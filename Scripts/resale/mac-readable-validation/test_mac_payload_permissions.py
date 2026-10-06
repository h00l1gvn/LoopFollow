import contextlib, copy, hashlib, json, os, pathlib, stat, tempfile, unittest, struct, zlib, xml.etree.ElementTree as ET
import mac_payload_permissions as p
import validate_resale_export as v

def fixture():
    scope=json.loads((pathlib.Path(__file__).parent/'mac-readable-package-scope.json').read_text())['permission_repair']
    repair=copy.deepcopy(scope)
    repair['source_file_sha256']={k:hashlib.sha256(k.encode()).hexdigest() for k in repair['source_file_sha256']}
    return repair

def make_tree(root,repair):
    root.mkdir(mode=0o700)
    for d in sorted(repair['source_directories'],key=lambda x:(len(pathlib.PurePosixPath(x).parts),x)):
        if d!='.':(root/d).mkdir(mode=0o700)
    for f in repair['source_file_sha256']:
        (root/f).write_bytes(f.encode());os.chmod(root/f,0o700 if f in p.EXECUTABLES else 0o600)

def rows(repair):
    result={'.':{'kind':'directory','mode':0o755,'uid':0,'gid':0}}
    for d in repair['source_directories']:
        result[p.APP+('/'+d if d!='.' else '')]={'kind':'directory','mode':0o755,'uid':0,'gid':0}
    for f,h in repair['source_file_sha256'].items():
        result[p.APP+'/'+f]={'kind':'file','mode':0o755 if f in p.EXECUTABLES else 0o644,'uid':0,'gid':0,'sha256':h}
    return result

def odc_entry(name,mode,raw=b'',uid=0,gid=0,nlink=1):
    values=[(0,6),(1,6),(mode,6),(uid,6),(gid,6),(nlink,6),(0,6),(0,11),(len(name.encode())+1,6),(len(raw),11)]
    return b'070707'+b''.join(format(n,'0'+str(width)+'o').encode() for n,width in values)+name.encode()+b'\0'+raw

def bom_from(rows):
    return ''.join('./'+k+'\t'+format((stat.S_IFDIR if r['kind']=='directory' else stat.S_IFREG)|r['mode'],'o')+'\t'+str(r['uid'])+'\t'+str(r['gid'])+'\n' if k!='.' else '.\t0\t0\t0\n' for k,r in rows.items()).encode()

def synthetic_xar(change=None):
    root=ET.Element('xar');toc=ET.SubElement(root,'toc');directory=ET.SubElement(toc,'file');ET.SubElement(directory,'name').text='com.julienbell.ResaleBurrow.mac.pkg';ET.SubElement(directory,'type').text='directory'
    heap=b''
    for parent,name,body in [(directory,'Bom',b'BOMStore'),(directory,'Payload',b'payload'),(directory,'PackageInfo',b'<pkg-info/>'),(toc,'Distribution',b'<installer-gui-script/>')]:
        node=ET.SubElement(parent,'file');ET.SubElement(node,'name').text=name;ET.SubElement(node,'type').text='file';data=ET.SubElement(node,'data')
        for tag,value in [('offset',len(heap)),('length',len(body)),('size',len(body))]:ET.SubElement(data,tag).text=str(value)
        ET.SubElement(data,'encoding',style='application/octet-stream')
        for tag in ('archived-checksum','extracted-checksum'):ET.SubElement(data,tag,style='sha256').text=hashlib.sha256(body).hexdigest()
        heap+=body
    if change:change(root)
    xml=ET.tostring(root);compressed=zlib.compress(xml)
    return struct.pack('>4sHHQQI',b'xar!',28,1,len(compressed),len(xml),1)+compressed+heap

class PermissionGuards(unittest.TestCase):
    def setUp(self):self.repair=fixture()
    def assertRejected(self,fn,*args):
        with self.assertRaises(v.ValidationError):fn(*args)
    def test_copy_changes_only_modes_and_keeps_private_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)/'original';make_tree(root,self.repair);before=p.tree_snapshot(root)
            staged,source,copied=p.stage_copy(root,pathlib.Path(tmp)/'private',self.repair)
            self.assertEqual(before,p.tree_snapshot(root));self.assertEqual(source,before)
            self.assertEqual(sum(r['kind']=='file' for r in copied.values()),15)
            self.assertEqual(sum(r['kind']=='directory' for r in copied.values()),12)
            self.assertEqual(stat.S_IMODE(staged.parent.parent.stat().st_mode),0o700)
            self.assertEqual({r['mode'] for k,r in copied.items() if r['kind']=='file' and k not in p.EXECUTABLES},{0o644})
    def test_destination_collision_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)/'original';make_tree(root,self.repair);dest=pathlib.Path(tmp)/'exists';dest.mkdir()
            self.assertRejected(p.stage_copy,root,dest,self.repair)
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)/'original';make_tree(root,self.repair);(root/'extra').symlink_to(root/'Contents/Info.plist')
            self.assertRejected(p.stage_copy,root,pathlib.Path(tmp)/'copy',self.repair)
    def test_signed_bytes_change_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)/'original';make_tree(root,self.repair);(root/'Contents/Info.plist').write_bytes(b'changed')
            self.assertRejected(p.stage_copy,root,pathlib.Path(tmp)/'copy',self.repair)
    def test_extra_executable_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)/'original';make_tree(root,self.repair);os.chmod(root/'Contents/Info.plist',0o700)
            self.assertRejected(p.stage_copy,root,pathlib.Path(tmp)/'copy',self.repair)
    def test_missing_executable_bit_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)/'original';make_tree(root,self.repair);os.chmod(root/next(iter(p.EXECUTABLES)),0o600)
            self.assertRejected(p.stage_copy,root,pathlib.Path(tmp)/'copy',self.repair)
    def test_special_bits_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)/'original';make_tree(root,self.repair);os.chmod(root/'Contents/Info.plist',0o4600)
            self.assertRejected(p.stage_copy,root,pathlib.Path(tmp)/'copy',self.repair)
    def test_umask_tmpdir_restored_after_exception(self):
        old=os.umask(0o077);os.umask(old);previous=os.environ.get('TMPDIR')
        with tempfile.TemporaryDirectory() as tmp:
            try:
                with p.productbuild_creation_context(pathlib.Path(tmp)/'private'):
                    current=os.umask(0o022);os.umask(current);self.assertEqual(current,0o022)
                    self.assertEqual(stat.S_IMODE((pathlib.Path(tmp)/'private').stat().st_mode),0o700)
                    raise RuntimeError('fixture')
            except RuntimeError:pass
        current=os.umask(old);self.assertEqual(current,old);self.assertEqual(os.environ.get('TMPDIR'),previous)
    def test_stored_readable_modes_pass(self):self.assertTrue(p.check_cpio(rows(self.repair),self.repair)['world_read_traverse_verified'])
    def test_root_only_resources_rejected(self):
        r=rows(self.repair);r[p.APP+'/Contents/Info.plist']['mode']=0o600;self.assertRejected(p.check_cpio,r,self.repair)
    def test_root_only_parent_rejected(self):
        r=rows(self.repair);r[p.APP+'/Contents']['mode']=0o700;self.assertRejected(p.check_cpio,r,self.repair)
    def test_synthetic_cpio_root_traverse_required(self):
        r=rows(self.repair);r['.']['mode']=0o700;self.assertRejected(p.check_cpio,r,self.repair)
    def test_expected_directory_cannot_be_regular_file(self):
        r=rows(self.repair);r[p.APP+'/Contents']['kind']='file';r[p.APP+'/Contents']['sha256']='0'*64;self.assertRejected(p.check_cpio,r,self.repair)
    def test_synthetic_root_cannot_be_regular_file(self):
        r=rows(self.repair);r['.']['kind']='file';r['.']['sha256']='0'*64;self.assertRejected(p.check_cpio,r,self.repair)
    def test_expected_regular_file_cannot_be_directory(self):
        r=rows(self.repair);r[p.APP+'/Contents/Info.plist']['kind']='directory';self.assertRejected(p.check_cpio,r,self.repair)
    def test_world_write_rejected(self):
        r=rows(self.repair);r[p.APP+'/Contents']['mode']=0o777;self.assertRejected(p.check_cpio,r,self.repair)
    def test_nonroot_owner_rejected(self):
        r=rows(self.repair);r[p.APP]['uid']=501;self.assertRejected(p.check_cpio,r,self.repair)
    def test_cpio_bytes_mismatch_rejected(self):
        r=rows(self.repair);r[p.APP+'/Contents/Info.plist']['sha256']='0'*64;self.assertRejected(p.check_cpio,r,self.repair)
    def test_odc_parser_and_exact_body_hash(self):
        raw=odc_entry('.',stat.S_IFDIR|0o755,nlink=2)+odc_entry('file',stat.S_IFREG|0o644,b'abc')+odc_entry('TRAILER!!!',0)
        r=p.parse_odc(raw);self.assertEqual(r['file']['sha256'],hashlib.sha256(b'abc').hexdigest());self.assertEqual(r['.']['mode'],0o755)
    def test_cpio_traversal_rejected(self):self.assertRejected(p.parse_odc,odc_entry('../escape',stat.S_IFREG|0o644)+odc_entry('TRAILER!!!',0))
    def test_cpio_duplicate_rejected(self):self.assertRejected(p.parse_odc,odc_entry('file',stat.S_IFREG|0o644)*2+odc_entry('TRAILER!!!',0))
    def test_cpio_symlink_rejected(self):self.assertRejected(p.parse_odc,odc_entry('link',stat.S_IFLNK|0o777,b'outside')+odc_entry('TRAILER!!!',0))
    def test_cpio_truncated_rejected(self):self.assertRejected(p.parse_odc,odc_entry('file',stat.S_IFREG|0o644,b'abc')[:-1])
    def test_cpio_no_trailer_rejected(self):self.assertRejected(p.parse_odc,odc_entry('file',stat.S_IFREG|0o644,b'abc'))
    def test_cpio_hardlink_rejected(self):self.assertRejected(p.parse_odc,odc_entry('file',stat.S_IFREG|0o644,b'abc',nlink=2)+odc_entry('TRAILER!!!',0))
    def test_bom_cpio_agree(self):p.check_bom(bom_from(rows(self.repair)),rows(self.repair))
    def test_bom_cpio_permission_mismatch_rejected(self):
        raw=bom_from(rows(self.repair)).replace(b'100644',b'100600',1);self.assertRejected(p.check_bom,raw,rows(self.repair))
    def test_bom_unknown_record_rejected(self):self.assertRejected(p.check_bom,bom_from(rows(self.repair))+b'./other\t100644\t0\t0\n',rows(self.repair))
    def test_bom_owner_mismatch_rejected(self):self.assertRejected(p.check_bom,bom_from(rows(self.repair)).replace(b'\t0\t0\n',b'\t501\t0\n',1),rows(self.repair))
    def test_xar_header_rejected(self):self.assertRejected(p.xar_components,b'not a xar file'*10)
    def test_xar_exact_component_and_checksums_pass(self):self.assertEqual(p.xar_components(synthetic_xar())['com.julienbell.ResaleBurrow.mac.pkg/Payload'],b'payload')
    def test_xar_checksum_mismatch_rejected(self):
        self.assertRejected(p.xar_components,synthetic_xar(lambda r:setattr(r.find('.//data/extracted-checksum'),'text','0'*64)))
    def test_xar_traversal_rejected(self):
        self.assertRejected(p.xar_components,synthetic_xar(lambda r:setattr(r.find('.//file/name'),'text','../escape')))
    def test_xar_symlink_rejected(self):
        self.assertRejected(p.xar_components,synthetic_xar(lambda r:setattr(r.find('.//file/file/type'),'text','symlink')))
    def test_xar_duplicate_rejected(self):
        self.assertRejected(p.xar_components,synthetic_xar(lambda r:r.find('toc').append(copy.deepcopy(r.find('toc/file')))))
    def test_bounded_gzip_rejects_overflow_and_trailing(self):
        import gzip
        self.assertRejected(p.bounded_decompress,gzip.compress(b'a'*50),10,True)
        self.assertRejected(p.bounded_decompress,gzip.compress(b'a')+b'extra',10,True)

if __name__=='__main__':unittest.main()
