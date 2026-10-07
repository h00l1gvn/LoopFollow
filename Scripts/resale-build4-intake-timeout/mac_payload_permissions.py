"""Copy-only signed Mac payload staging and read-only stored CPIO/BOM guards."""
from __future__ import annotations
import contextlib, hashlib, os, pathlib, stat, struct, xml.etree.ElementTree as ET, zlib
import validate_resale_export as validation

APP = 'ResaleBurrowMac.app'
EXECUTABLES = frozenset({'Contents/MacOS/ResaleBurrowMac', 'Contents/PlugIns/ResaleBurrowMacWidgets.appex/Contents/MacOS/ResaleBurrowMacWidgets'})
MAX_BYTES = 500 * 1024 * 1024

def check(condition, code):
    validation.require(condition, code)

def safe_name(name, allow_root=False):
    check(isinstance(name, str) and '\\' not in name and '\x00' not in name, 'payload_path_invalid')
    if allow_root and name in ('.', './'): return '.'
    if name.startswith('./'): name = name[2:]
    p = pathlib.PurePosixPath(name)
    check(bool(name) and not p.is_absolute() and '..' not in p.parts and str(p) == name and name != '.', 'payload_path_invalid')
    return name

def sha(raw): return hashlib.sha256(raw).hexdigest()

def tree_snapshot(root):
    root = pathlib.Path(root)
    check(root.is_dir() and not root.is_symlink(), 'payload_root_invalid')
    result = {}
    for p in [root] + sorted(root.rglob('*')):
        s = p.lstat(); rel = '.' if p == root else str(p.relative_to(root))
        check(not stat.S_ISLNK(s.st_mode) and (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)), 'payload_nonregular_member')
        check(s.st_mode & 0o7000 == 0, 'payload_special_mode')
        result[rel] = {'kind': 'directory' if p.is_dir() else 'file', 'mode': stat.S_IMODE(s.st_mode)}
        if p.is_file(): result[rel]['sha256'] = sha(p.read_bytes())
    return result

def pinned_input(snapshot, repair):
    hashes = repair.get('source_file_sha256', {}); dirs = repair.get('source_directories', [])
    check(isinstance(hashes, dict) and 0 < len(hashes) <= 25000 and isinstance(dirs, list) and 0 < len(dirs) <= 10000 and len(set(dirs)) == len(dirs) and '.' in dirs, 'payload_scope_shape_invalid')
    check(set(repair.get('exact_executables', [])) == EXECUTABLES, 'payload_executable_scope_invalid')
    files = {k: v for k, v in snapshot.items() if v['kind'] == 'file'}
    check(set(files) == set(hashes) and {k for k, v in snapshot.items() if v['kind'] == 'directory'} == set(dirs), 'payload_member_set_changed')
    for k, row in files.items():
        safe_name(k)
        check(row['sha256'] == hashes[k], 'payload_signed_bytes_changed')
        check(bool(row['mode'] & 0o111) == (k in EXECUTABLES), 'payload_unexpected_executable')
    return hashes

def stage_copy(primary, container, repair):
    """Leaves the authenticated source untouched; only new app copy gets public modes."""
    primary = pathlib.Path(primary); container = pathlib.Path(container)
    check(not container.exists() and not container.is_symlink(), 'payload_stage_collision')
    source = tree_snapshot(primary); pinned_input(source, repair)
    container.mkdir(mode=0o700); os.chmod(container, 0o700)
    payload_root = container / 'payload-root'; payload_root.mkdir(mode=0o755); os.chmod(payload_root, 0o755)
    staged = payload_root / APP
    for rel, row in sorted(source.items(), key=lambda kv: (len(pathlib.PurePosixPath(kv[0]).parts), kv[0])):
        target = staged if rel == '.' else staged / rel
        if row['kind'] == 'directory':
            target.mkdir(mode=0o755); os.chmod(target, 0o755)
        else:
            raw = (primary / rel).read_bytes()
            with target.open('xb') as handle: handle.write(raw)
            os.chmod(target, 0o755 if rel in EXECUTABLES else 0o644)
    check(tree_snapshot(primary) == source, 'original_payload_changed')
    copied = tree_snapshot(staged); pinned_input(copied, repair)
    for rel, row in copied.items():
        expected = 0o755 if row['kind'] == 'directory' or rel in EXECUTABLES else 0o644
        check(row['mode'] == expected, 'staged_payload_mode_invalid')
    check(stat.S_IMODE(container.stat().st_mode) == 0o700, 'private_outer_mode_changed')
    return staged, source, copied

@contextlib.contextmanager
def productbuild_creation_context(private_temp):
    """Only the packaging subprocess inherits 022; enclosing work remains private."""
    private_temp = pathlib.Path(private_temp)
    check(not private_temp.exists(), 'productbuild_temp_collision')
    private_temp.mkdir(mode=0o700); os.chmod(private_temp, 0o700)
    previous_umask = os.umask(0o022); previous_tmp = os.environ.get('TMPDIR')
    os.environ['TMPDIR'] = str(private_temp)
    try: yield
    finally:
        os.umask(previous_umask)
        if previous_tmp is None: os.environ.pop('TMPDIR', None)
        else: os.environ['TMPDIR'] = previous_tmp
        check(stat.S_IMODE(private_temp.stat().st_mode) == 0o700, 'private_productbuild_temp_mode_changed')

def bounded_decompress(raw, limit, gzip=False):
    d = zlib.decompressobj(16 + zlib.MAX_WBITS if gzip else zlib.MAX_WBITS)
    try: expanded = d.decompress(raw, limit + 1)
    except zlib.error: raise validation.ValidationError('payload_compression_invalid') from None
    check(len(expanded) <= limit and d.eof and not d.unused_data and not d.unconsumed_tail, 'payload_compression_limit_or_trailing')
    return expanded

def xar_components(raw):
    check(28 <= len(raw) <= MAX_BYTES, 'package_size_invalid')
    magic, header, version, compressed, expanded, algorithm = struct.unpack('>4sHHQQI', raw[:28])
    check(magic == b'xar!' and header == 28 and version == 1 and algorithm in (1, 3) and 0 < compressed <= 10 * 1024**2 and header + compressed <= len(raw), 'package_xar_header_invalid')
    xml = bounded_decompress(raw[header:header + compressed], 10 * 1024**2)
    check(len(xml) == expanded and b'<!DOCTYPE' not in xml and b'<!ENTITY' not in xml, 'package_xar_xml_invalid')
    try: root = ET.fromstring(xml)
    except ET.ParseError: raise validation.ValidationError('package_xar_xml_invalid') from None
    files = {}; heap = header + compressed
    def visit(nodes, parent=''):
        for node in nodes:
            name = node.findtext('name'); check(isinstance(name, str) and '/' not in name, 'package_xar_path_invalid')
            path = safe_name((parent + '/' if parent else '') + name)
            check(path not in files, 'package_xar_duplicate_member')
            kind = node.findtext('type')
            check(kind in ('file', 'directory'), 'package_xar_nonregular_member')
            if kind == 'directory':
                files[path] = None; visit(node.findall('file'), path)
            else:
                data = node.find('data'); check(data is not None, 'package_xar_data_missing')
                try: offset = int(data.findtext('offset')); length = int(data.findtext('length')); size = int(data.findtext('size'))
                except (TypeError, ValueError): raise validation.ValidationError('package_xar_data_invalid') from None
                check(offset >= 0 and 0 <= length <= MAX_BYTES and heap + offset + length <= len(raw), 'package_xar_data_invalid')
                encoded = raw[heap + offset:heap + offset + length]
                encoding = data.find('encoding'); check(encoding is not None, 'package_xar_encoding_missing')
                style = encoding.get('style')
                check(style in ('application/octet-stream', 'application/x-gzip'), 'package_xar_encoding_invalid')
                decoded = bounded_decompress(encoded, MAX_BYTES) if style == 'application/x-gzip' else encoded
                check(len(decoded) == size, 'package_xar_size_mismatch')
                for tag, value in [('archived-checksum', encoded), ('extracted-checksum', decoded)]:
                    digest = data.find(tag); check(digest is not None and digest.get('style') in ('sha1', 'sha256'), 'package_xar_checksum_missing')
                    check(hashlib.new(digest.get('style'), value).hexdigest() == digest.text, 'package_xar_checksum_mismatch')
                files[path] = decoded
    toc = root.find('toc'); check(toc is not None, 'package_xar_toc_missing')
    visit(toc.findall('file'))
    expected = {'com.julienbell.ResaleBurrow.mac.pkg', 'com.julienbell.ResaleBurrow.mac.pkg/Bom', 'com.julienbell.ResaleBurrow.mac.pkg/Payload', 'com.julienbell.ResaleBurrow.mac.pkg/PackageInfo', 'Distribution'}
    check(set(files) == expected, 'package_component_set_invalid')
    return files

def parse_odc(raw):
    """Parse stored odc CPIO in memory; never infer shipped modes from extracted files."""
    check(0 < len(raw) <= MAX_BYTES, 'cpio_size_invalid')
    offset = 0; rows = {}; trailer = False
    while offset < len(raw):
        check(len(rows) <= 35000 and offset + 76 <= len(raw), 'cpio_header_truncated')
        h = raw[offset:offset + 76]; check(h[:6] == b'070707', 'cpio_format_invalid')
        fields = []; pos = 6
        for width in (6, 6, 6, 6, 6, 6, 6, 11, 6, 11):
            value = h[pos:pos + width]; check(all(48 <= c <= 55 for c in value), 'cpio_integer_invalid')
            fields.append(int(value, 8)); pos += width
        dev, ino, mode, uid, gid, nlink, rdev, mtime, namesize, size = fields
        check(0 < namesize <= 4096 and size <= MAX_BYTES and offset + 76 + namesize + size <= len(raw), 'cpio_entry_bounds_invalid')
        namebytes = raw[offset + 76:offset + 76 + namesize]
        check(namebytes.endswith(b'\0') and b'\0' not in namebytes[:-1], 'cpio_name_invalid')
        try: name = namebytes[:-1].decode('utf-8')
        except UnicodeDecodeError: raise validation.ValidationError('cpio_name_invalid') from None
        start = offset + 76 + namesize; contents = raw[start:start + size]; offset = start + size
        if name == 'TRAILER!!!':
            check(size == 0 and all(b == 0 for b in raw[offset:]), 'cpio_trailer_invalid'); trailer = True; break
        name = safe_name(name, allow_root=True)
        check(name not in rows, 'cpio_duplicate_member')
        check(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'cpio_nonregular_member')
        check(mode & 0o7000 == 0 and not (stat.S_ISREG(mode) and nlink != 1) and not (stat.S_ISDIR(mode) and size != 0), 'cpio_special_or_linked_member')
        rows[name] = {'kind': 'directory' if stat.S_ISDIR(mode) else 'file', 'mode': stat.S_IMODE(mode), 'uid': uid, 'gid': gid}
        if stat.S_ISREG(mode): rows[name]['sha256'] = sha(contents)
    check(trailer, 'cpio_trailer_missing')
    return rows

def check_cpio(rows, repair):
    expected_files = {APP + '/' + k: v for k, v in repair['source_file_sha256'].items()}
    expected_dirs = {'.', APP} | {APP + '/' + k for k in repair['source_directories'] if k != '.'}
    check(set(rows) == set(expected_files) | expected_dirs, 'stored_payload_member_set_changed')
    for name, row in rows.items():
        check(row.get('kind') == ('directory' if name in expected_dirs else 'file'), 'stored_payload_member_type_changed')
        check(row['uid'] == row['gid'] == 0, 'stored_payload_owner_not_root')
        executable = name.startswith(APP + '/') and name[len(APP) + 1:] in EXECUTABLES
        wanted = 0o755 if name in expected_dirs or executable else 0o644
        check(row['mode'] == wanted, 'stored_payload_world_read_or_traverse_invalid')
        if name in expected_files: check(row.get('sha256') == expected_files[name], 'stored_payload_signed_bytes_changed')
    return {'stored_directories': len(expected_dirs), 'stored_regular_files': len(expected_files), 'world_read_traverse_verified': True, 'root_ownership_verified': True, 'group_other_write_absent': True, 'signed_file_hashes_match': True}

def check_bom(raw, cpio):
    check(len(raw) < 1024 * 1024, 'bom_output_invalid')
    try: lines = raw.decode('utf-8').splitlines()
    except UnicodeDecodeError: raise validation.ValidationError('bom_output_invalid') from None
    found = {}
    for line in lines:
        parts = line.split('\t'); check(len(parts) == 4, 'bom_record_invalid')
        name = safe_name(parts[0], allow_root=True); check(name not in found and name in cpio, 'bom_member_set_invalid')
        check(all(s and all(c in '01234567' for c in s) for s in parts[1:2]) and all(s.isdecimal() for s in parts[2:]), 'bom_integer_invalid')
        mode, uid, gid = int(parts[1], 8), int(parts[2]), int(parts[3]); row = cpio[name]
        # lsbom reports mode 0 for the synthetic component root; CPIO is authoritative there.
        check((name == '.' and mode == 0) or (stat.S_ISDIR(mode) if row['kind'] == 'directory' else stat.S_ISREG(mode)), 'bom_type_mismatch')
        check((name == '.' and mode == 0) or stat.S_IMODE(mode) == row['mode'], 'bom_cpio_mode_mismatch')
        check(uid == row['uid'] and gid == row['gid'], 'bom_cpio_owner_mismatch')
        found[name] = True
    check(set(found) == set(cpio), 'bom_member_set_invalid')

def check_package(package, repair, runner, private_dir):
    members = xar_components(pathlib.Path(package).read_bytes())
    prefix = 'com.julienbell.ResaleBurrow.mac.pkg/'
    payload = bounded_decompress(members[prefix + 'Payload'], MAX_BYTES, gzip=True)
    rows = parse_odc(payload); result = check_cpio(rows, repair)
    bom = pathlib.Path(private_dir) / 'stored-payload.bom'
    with bom.open('xb') as handle: handle.write(members[prefix + 'Bom'])
    os.chmod(bom, 0o600)
    raw = runner.run(['/usr/bin/lsbom', '-p', 'fmug', bom], 'stored-payload-bom')
    check_bom(raw, rows); result['bom_cpio_exact_modes_and_owners_agree'] = True
    return result
