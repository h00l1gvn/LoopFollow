#!/usr/bin/env python3
"""Single readable component package from a signed-copy-only staged app; no build, resign or upload."""
import argparse, datetime, hashlib, json, os, pathlib, re, secrets, shlex, tarfile, xml.etree.ElementTree as ET
import validate_resale_export as validation
import mac_payload_permissions as permissions
import resale_scoped_profiles as profiles
from export_resale_family import PrivateRunner

SOURCE='1162d8a1f4fdda1c2678220c9102f9c03ab48c33'
ARCHIVE_SHA='ce610ab71d3282aec86aa70085abe6f32cf80bf9c1ff76f6d323d5ce5fd3234a'
INSTALLER_SHA1='bf0ca3700e6436ad40baf5e65474fc8b8dfc00ce'

def extract_archive(path,destination):
    path=pathlib.Path(path);destination=pathlib.Path(destination)
    validation.require(validation.digest(path)==ARCHIVE_SHA,'archive_transport_hash_mismatch')
    validation.require(not destination.exists(),'archive_extract_destination_exists')
    with tarfile.open(path) as t:
        rows=t.getmembers();validation.require(0<len(rows)<=10000 and sum(r.size for r in rows)<=500*1024**2,'archive_transport_size_invalid')
        for row in rows:
            p=pathlib.PurePosixPath(row.name)
            validation.require(not p.is_absolute() and '..' not in p.parts and '\\' not in row.name and p.parts[0]=='ResaleBurrow.xcarchive' and (row.isdir() or row.isfile()) and not row.issym() and not row.islnk(),'archive_transport_member_invalid')
        validation.require(len({r.name for r in rows})==len(rows),'archive_transport_duplicate_member')
        destination.mkdir(parents=True,mode=0o700)
        for row in rows:
            target=destination/row.name
            if row.isdir():target.mkdir(parents=True,exist_ok=True,mode=0o700)
            else:
                target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                with target.open('xb') as f:f.write(t.extractfile(row).read())
                os.chmod(target,0o700 if row.mode&0o111 else 0o600)
    return destination/'ResaleBurrow.xcarchive'

def archive_primary(archive,scope,runner,now):
    expected=validation.scope_check(scope,'macos');props=validation.load_plist(archive/'Info.plist').get('ApplicationProperties',{})
    validation.require(props.get('CFBundleIdentifier')==validation.BASE+'.mac','archive_primary_identifier_mismatch')
    p=pathlib.PurePosixPath(props.get('ApplicationPath',''))
    validation.require(not p.is_absolute() and '..' not in p.parts and bool(p.parts),'archive_primary_path_invalid')
    primary=archive/'Products'/p
    validation.require(primary.resolve().is_relative_to((archive/'Products/Applications').resolve()) and list((archive/'Products/Applications').glob('*.app'))==[primary] and {x.name for x in (archive/'Products').iterdir()}=={'Applications'},'archive_not_single_top_level_app')
    rows=validation.bundle_set(primary,expected,runner,now)
    architectures=[]
    for bundle in [primary]+[x for x in primary.rglob('*.appex') if x.is_dir()]:
        info=validation.load_plist(validation.info_path(bundle));binary=bundle/'Contents/MacOS'/info['CFBundleExecutable']
        raw,_=runner.run(['/usr/bin/lipo','-archs',binary],'architecture')
        arch=raw.decode().strip().split();validation.require(set(arch)=={'x86_64','arm64'},'archive_not_verified_universal')
        architectures.append({'bundle_id':info['CFBundleIdentifier'],'architectures':arch})
    return primary,rows,architectures

def component_command(primary,keychain,package,verified_identity_name):
    validation.require(isinstance(verified_identity_name,str) and verified_identity_name.startswith('3rd Party Mac Developer Installer:') and verified_identity_name.endswith('('+profiles.TEAM+')'),'installer_identity_name_invalid')
    # Apple's productbuild manual specifies the certificate Common Name.
    # Resolve it privately from the separately fingerprint-pinned identity.
    return ['/usr/bin/productbuild','--sign',verified_identity_name,'--keychain',str(keychain),'--component',str(primary),'/Applications',str(package)]

def installer_leaf_from_toc(raw):
    validation.require(len(raw)<=5*1024**2 and b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw,'package_toc_invalid')
    try:
        import base64
        root=ET.fromstring(raw);signatures=[x for x in root.iter() if x.tag.split('}')[-1]=='signature']
        validation.require(len(signatures)==1,'package_signature_set_invalid')
        certs=[x for x in signatures[0].iter() if x.tag.split('}')[-1]=='X509Certificate']
        validation.require(bool(certs),'package_installer_certificate_absent')
        return hashlib.sha256(base64.b64decode(''.join((certs[0].text or '').split()),validate=True)).hexdigest()
    except (ValueError,ET.ParseError):raise validation.ValidationError('package_toc_invalid') from None

def package(scope,archive_tar,manifest,material,work,password_file):
    validation.require(os.environ.get('GITHUB_ACTIONS')=='true','package_requires_reviewed_ci')
    validation.require(scope.get('signing_delivery')=='signed-archive-readable-component-package-only' and scope.get('permission_repair',{}).get('no_upload') is True,'permission_repair_scope_missing')
    validation.require(scope.get('source_sha')==SOURCE and scope.get('recovery',{}).get('archive_sha256')==ARCHIVE_SHA and scope['recovery'].get('trusted_run_id')==37442839374 and scope['recovery'].get('trusted_job_id')==112200481325,'recovery_scope_mismatch')
    validation.require(scope.get('match_material_commit')=='d001564051efa319ea96060b6d23c285d03959f6','installer_match_scope_mismatch')
    temp=pathlib.Path(os.environ['RUNNER_TEMP']).resolve();work=pathlib.Path(work).resolve();material=pathlib.Path(material).resolve();archive_tar=pathlib.Path(archive_tar).resolve()
    validation.require(work.is_relative_to(temp) and material.is_relative_to(temp) and archive_tar.is_relative_to(temp) and not work.exists(),'private_runner_paths_invalid')
    identity=manifest.get('installer_certificate',{});p12=pathlib.Path(identity.get('p12_file',''))
    validation.require(manifest.get('source_sha')==SOURCE and manifest.get('family')=='macos' and manifest.get('team')==profiles.TEAM and manifest.get('match_commit')==scope['match_material_commit'],'installer_manifest_mismatch')
    validation.require(identity.get('verified') is True and identity.get('certificate_id')==profiles.INSTALLER_ID and identity.get('sha256')==profiles.INSTALLER_SHA and identity.get('sha1')==INSTALLER_SHA1 and identity.get('type')=='MAC_INSTALLER_DISTRIBUTION','installer_identity_mismatch')
    validation.require(p12.is_file() and not p12.is_symlink() and p12.resolve().is_relative_to(material) and validation.digest(p12)==identity.get('p12_file_sha256'),'installer_private_container_mismatch')
    password_file=pathlib.Path(password_file);validation.require(password_file.is_file() and not password_file.is_symlink() and password_file.stat().st_mode&0o077==0,'password_file_not_private')
    password=password_file.read_text().strip();validation.require(len(password)>=32,'password_file_invalid')
    private=PrivateRunner(work);keychain=material/'package-only.keychain-db';key_password=secrets.token_urlsafe(48);original=None;created=False
    try:
        xcode=private.run(['/usr/bin/xcodebuild','-version'],'xcode-version').decode();validation.require(re.search(r'^Xcode 26[.]2$',xcode,re.M),'reviewed_xcode_missing')
        archive=extract_archive(archive_tar,work/'input');v=validation.Runner(work/'archive-validation-private');primary,rows,architectures=archive_primary(archive,scope,v,datetime.datetime.now(datetime.timezone.utc))
        before=permissions.tree_snapshot(archive)
        staged,source_snapshot,staged_snapshot=permissions.stage_copy(primary,work/'staged-private',scope['permission_repair'])
        staged_rows=validation.bundle_set(staged,validation.scope_check(scope,'macos'),v,datetime.datetime.now(datetime.timezone.utc))
        validation.require(all(r['certificate_sha256']==profiles.CERT_SHA for r in rows+staged_rows),'archive_or_staged_signer_fingerprint_mismatch')
        validation.require(permissions.tree_snapshot(primary)==source_snapshot,'original_payload_changed')
        original=shlex.split(private.run(['/usr/bin/security','list-keychains','-d','user'],'original-search-list').decode())
        private.run(['/usr/bin/security','create-keychain','-p',key_password,keychain],'keychain-create');created=True
        private.run(['/usr/bin/security','set-keychain-settings','-lut','3600',keychain],'keychain-timeout')
        private.run(['/usr/bin/security','unlock-keychain','-p',key_password,keychain],'keychain-unlock')
        private.run(['/usr/bin/security','list-keychains','-d','user','-s',keychain,*original],'keychain-search-list')
        private.run(['/usr/bin/security','import',p12,'-k',keychain,'-P',password,'-T','/usr/bin/productbuild','-T','/usr/bin/productsign','-T','/usr/bin/security'],'import-installer')
        private.run(['/usr/bin/security','set-key-partition-list','-S','apple-tool:,apple:','-s','-k',key_password,keychain],'installer-partition')
        found=private.run(['/usr/bin/security','find-identity','-v',keychain],'exact-installer-identity').decode()
        matching=[x for x in found.splitlines() if INSTALLER_SHA1 in x.lower()]
        validation.require(len(matching)==1 and '3rd Party Mac Developer Installer:' in matching[0] and '('+profiles.TEAM+')' in matching[0],'installer_keychain_identity_not_verified')
        names=re.findall(r'"([^"\n]+)"',matching[0]);validation.require(len(names)==1,'installer_common_name_ambiguous')
        export=work/'export';export.mkdir(mode=0o700);pkg=export/'ResaleBurrowMac.pkg'
        try:
            with permissions.productbuild_creation_context(work/'productbuild-private-temp'):
                private.run(component_command(staged,keychain,pkg,names[0]),'single-productbuild',timeout=600)
        finally:
            if pkg.is_file():os.chmod(pkg,0o600)
        validation.require(permissions.tree_snapshot(staged)==staged_snapshot,'staged_signed_payload_changed')
        staged_after_rows=validation.bundle_set(staged,validation.scope_check(scope,'macos'),v,datetime.datetime.now(datetime.timezone.utc))
        validation.require(all(r['certificate_sha256']==profiles.CERT_SHA for r in staged_after_rows),'staged_after_signer_fingerprint_mismatch')
        toc=work/'private-package-toc.xml';private.run(['/usr/bin/xar','--dump-toc='+str(toc),'-f',pkg],'package-certificate-toc')
        validation.require(installer_leaf_from_toc(toc.read_bytes())==profiles.INSTALLER_SHA,'package_installer_leaf_mismatch')
        checked=validation.validate('macos',archive,export,scope,work/'signed-validation.json')
        validation.require(checked.get('status')=='passed','strict_package_validation_failed')
        validation.require(all(r['certificate_sha256']==profiles.CERT_SHA for r in checked['archive_bundles']+checked['export_bundles']),'exported_signer_fingerprint_mismatch')
        stored_permissions=permissions.check_package(pkg,scope['permission_repair'],private,work)
        after=permissions.tree_snapshot(archive)
        validation.require(before==after,'signed_archive_bytes_or_modes_changed_by_packaging')
        validation.require(permissions.tree_snapshot(staged)==staged_snapshot,'staged_signed_payload_changed')
        profiles.private_write(work/'package-provenance.json',{'schema':1,'source_sha':SOURCE,'run_id':os.environ.get('GITHUB_RUN_ID'),'family':'macos','archive_input_sha256':ARCHIVE_SHA,'original_archive_run':37442839374,'original_archive_job':112200481325,'archive_bundles':rows,'architectures':architectures,'original_archive_files_and_modes_unchanged':True,'signed_app_copy_bytes_unchanged':True,'signed_file_count':15,'app_directory_count':12,'stored_permissions':stored_permissions,'staged_bundles':staged_rows,'permission_changes_only':True,'package_sha256':validation.digest(pkg),'installer_sha256':profiles.INSTALLER_SHA,'strict_package_validation_passed':True,'no_source_checkout_or_rebuild':True,'no_application_resigning':True,'uploaded':False,'installed':False})
    finally:
        if original is not None:
            try:private.run(['/usr/bin/security','list-keychains','-d','user','-s',*original],'restore-search-list')
            except Exception:pass
        if created:
            try:private.run(['/usr/bin/security','delete-keychain',keychain],'keychain-delete')
            except Exception:pass
        profiles.private_write(work/'package-step-receipt.json',{'steps':private.steps,'keychain_created':created,'source_rebuilt':False,'application_resigned':False,'network_writes':False,'xcode_distribution_logs_from_prior_run_unavailable':True})

def main():
    p=argparse.ArgumentParser();p.add_argument('--scope',type=pathlib.Path,required=True);p.add_argument('--archive-tar',type=pathlib.Path,required=True);p.add_argument('--manifest',type=pathlib.Path,required=True);p.add_argument('--material-dir',type=pathlib.Path,required=True);p.add_argument('--work-dir',type=pathlib.Path,required=True);p.add_argument('--p12-password-file',type=pathlib.Path,required=True);a=p.parse_args()
    try:
        package(json.loads(a.scope.read_text()),a.archive_tar,json.loads(a.manifest.read_text()),a.material_dir,a.work_dir,a.p12_password_file)
        print('Exact signed Mac archive packaged and strictly validated; no build, resign or upload.');return 0
    except Exception:
        print('Package-only recovery stopped; protected private diagnostics required before another attempt.');return 1
if __name__=='__main__':raise SystemExit(main())
