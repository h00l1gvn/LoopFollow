#!/usr/bin/env python3
"""Ephemeral CI manual archive/export only. Raw output stays private; no Apple upload."""
from __future__ import annotations
import argparse,hashlib,json,os,re,secrets,shlex,subprocess,sys
from pathlib import Path
import build3_contract as c
import validate_resale_export as validation
import restore_build3_material as restore
import mac_payload_permissions as payload
import datetime
DESTINATIONS={'ios':('ResaleBurrowIOS','generic/platform=iOS'),'macos':('ResaleBurrowMac','generic/platform=macOS'),'tvos':('ResaleBurrowTV','generic/platform=tvOS')}

def private_write(path,value):
    restore.private_bytes(path,(json.dumps(value,indent=2)+'\n').encode())

def plan(scope,manifest,family,material,source,work):
    validation.scope_check(scope,family)
    c.require(os.environ.get('GITHUB_ACTIONS')=='true','Archive/export is restricted to an ephemeral reviewed CI runner.')
    c.require(scope.get('source_frozen') is True and scope.get('final_artwork_owner_approved') is True and manifest.get('source_sha')==scope.get('source_sha'),'Frozen private source differs.')
    c.require(family in DESTINATIONS and manifest.get('family')==family and manifest.get('team')==c.TEAM and manifest.get('group')==c.GROUP,'Restore family/identity differs.')
    material=Path(material).resolve();source=Path(source).resolve();work=Path(work).resolve();runner=Path(os.environ['RUNNER_TEMP']).resolve();workspace=Path(os.environ['GITHUB_WORKSPACE']).resolve()
    c.require(material.is_relative_to(runner) and work.is_relative_to(runner) and source.is_relative_to(workspace) and not work.is_relative_to(source),'Paths are outside the private runner scope.')
    wanted=[t for t in scope['targets'] if t['family']==family];rows=manifest.get('profiles',[])
    c.require(len(rows)==len(wanted) and {r.get('bundle_id') for r in rows}=={t['bundle_id'] for t in wanted},'Restore profile set differs.')
    for row in rows:
        c.require(row.get('verified') is True and row.get('native_readback_verified') is True and row.get('certificate_sha256')==c.CERT_SHA,'Profile verification is incomplete.')
        path=Path(row.get('private_profile_file',''))
        c.require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(material) and hashlib.sha256(path.read_bytes()).hexdigest()==row.get('sha256'),'Private profile path/hash differs.')
    for key in ['signing_certificate']+(['installer_certificate'] if family=='macos' else []):
        value=manifest.get(key,{}) or {};path=Path(value.get('p12_file',''))
        expected=c.CERT_SHA if key=='signing_certificate' else restore.INSTALLER_SHA
        c.require(value.get('verified') is True and value.get('sha256')==expected and path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(material) and hashlib.sha256(path.read_bytes()).hexdigest()==value.get('p12_file_sha256'),'Existing identity material is missing or changed.')
    return wanted,DESTINATIONS[family]

class PrivateRunner:
    def __init__(self,work):self.work=Path(work);self.work.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(self.work,0o700);self.steps=[]
    def run(self,args,label,cwd=None,timeout=180):
        index=len(self.steps)+1;out=self.work/(f'{index:02d}-{label}-stdout.log');err=self.work/(f'{index:02d}-{label}-stderr.log')
        with out.open('wb') as stdout,err.open('wb') as stderr:
            os.chmod(out,0o600);os.chmod(err,0o600)
            try:r=subprocess.run([str(v) for v in args],stdout=stdout,stderr=stderr,cwd=cwd,timeout=timeout)
            except (OSError,subprocess.TimeoutExpired):raise c.GateError('A private runner step was unavailable or timed out: '+label) from None
        self.steps.append({'step':label,'returncode':r.returncode})
        c.require(r.returncode==0,'A private runner step failed: '+label)
        return out.read_bytes()

def build(scope,scope_file,manifest,material,source,work,p12_password_file,bundle_gemfile):
    family=manifest['family'];wanted,(scheme,destination)=plan(scope,manifest,family,material,source,work)
    scripts=Path(__file__).parent.resolve();source=Path(source).resolve();material=Path(material).resolve();work=Path(work).resolve();runner=PrivateRunner(work)
    head=runner.run(['git','-C',source,'rev-parse','HEAD'],'source-sha').decode().strip();c.require(head==scope['source_sha'],'Private checkout SHA differs.')
    c.require(not runner.run(['git','-C',source,'status','--porcelain'],'source-clean'),'Private checkout is not clean before runner-only signing configuration.')
    version=runner.run(['/usr/bin/xcodebuild','-version'],'xcode-version').decode();c.require(re.search(r'^Xcode 26[.]2$',version,re.M),'Reviewed Xcode 26.2 is not active.')
    c.require(Path(bundle_gemfile).is_file(),'Pinned delivery Gemfile is missing.')
    os.environ['BUNDLE_GEMFILE']=str(Path(bundle_gemfile).resolve())
    password_file=Path(p12_password_file);c.require(password_file.is_file() and not password_file.is_symlink() and password_file.stat().st_mode&0o077==0,'Private ephemeral p12 password file invalid.')
    p12_password=password_file.read_text().strip();c.require(len(p12_password)>=32,'Private ephemeral p12 password too short.')
    keychain=material/'resale-ephemeral.keychain-db';keychain_password=secrets.token_urlsafe(48);original=None;installed=[];created=False;cleanup_errors=[]
    try:
        original=shlex.split(runner.run(['/usr/bin/security','list-keychains','-d','user'],'original-search-list').decode())
        runner.run(['/usr/bin/security','create-keychain','-p',keychain_password,keychain],'keychain-create');created=True
        runner.run(['/usr/bin/security','set-keychain-settings','-lut','21600',keychain],'keychain-timeout')
        runner.run(['/usr/bin/security','unlock-keychain','-p',keychain_password,keychain],'keychain-unlock')
        runner.run(['/usr/bin/security','list-keychains','-d','user','-s',keychain,*original],'keychain-search-list')
        for key in ['signing_certificate']+(['installer_certificate'] if family=='macos' else []):
            runner.run(['/usr/bin/security','import',manifest[key]['p12_file'],'-k',keychain,'-P',p12_password,'-T','/usr/bin/codesign','-T','/usr/bin/security','-T','/usr/bin/productbuild'],'import-'+key)
        runner.run(['/usr/bin/security','set-key-partition-list','-S','apple-tool:,apple:,codesign:','-s','-k',keychain_password,keychain],'keychain-partition')
        for row in manifest['profiles']:
            raw=Path(row['private_profile_file']).read_bytes()
            for folder in [Path.home()/'Library/MobileDevice/Provisioning Profiles',Path.home()/'Library/Developer/Xcode/UserData/Provisioning Profiles']:
                folder.mkdir(parents=True,exist_ok=True);dest=folder/Path(row['private_profile_file']).name
                if dest.exists():c.require(not dest.is_symlink() and dest.read_bytes()==raw,'Existing runner profile collision; refuse overwrite.')
                else:
                    with dest.open('xb') as handle:handle.write(raw)
                    os.chmod(dest,0o600);installed.append(dest)
        project=source/'apple/ResaleBurrow.xcodeproj';export_options=work/'ExportOptions.plist'
        runner.run(['bundle','exec','ruby',scripts/'configure_build3_signing.rb','--family',family,'--checkout',source,'--project',project,'--scope',scope_file,'--manifest',material/'restore-manifest.json','--export-options',export_options,'--report',work/'manual-signing-config.json'],'manual-configure',cwd=source,timeout=120)
        archive=work/'ResaleBurrow.xcarchive';export=work/'export'
        runner.run(['/usr/bin/xcodebuild','-project',project,'-scheme',scheme,'-configuration','Release','-destination',destination,'-archivePath',archive,'archive',*(['ARCHS=x86_64 arm64','ONLY_ACTIVE_ARCH=NO'] if family=='macos' else [])],'archive',cwd=source,timeout=3600)
        if family=='macos':
            primary=archive/'Products/Applications/ResaleBurrowMac.app'
            checked=validation.bundle_set(primary,validation.scope_check(scope,family),validation.Runner(work/'archive-validation-private'),datetime.datetime.now(datetime.timezone.utc))
            snapshot=payload.tree_snapshot(primary);repair=c.source_payload_scope(snapshot,checked)
            staged,before,copied=payload.stage_copy(primary,work/'staged-component',repair)
            validation.bundle_set(staged,validation.scope_check(scope,family),validation.Runner(work/'staged-validation-private'),datetime.datetime.now(datetime.timezone.utc))
            for relative in repair['exact_executables']:
                arches=runner.run(['/usr/bin/lipo','-archs',staged/relative],'universal-architecture-'+str(len(runner.steps))).decode().split()
                c.require(set(arches)=={'x86_64','arm64'},'mac_universal_architectures_missing')
            installer=manifest['installer_certificate'];identities=runner.run(['/usr/bin/security','find-identity','-v',keychain],'installer-identity').decode()
            matches=re.findall(r'(?m)^\s*\d+\)\s+'+re.escape(installer['sha1'].upper())+r'\s+"([^"\r\n]+)"\s*$',identities)
            c.require(len(matches)==1 and matches[0].startswith('3rd Party Mac Developer Installer:') and matches[0].endswith('('+c.TEAM+')'),'installer_exact_common_name_missing')
            export.mkdir(mode=0o700);package=export/'ResaleBurrowMac.pkg'
            with payload.productbuild_creation_context(work/'productbuild-private-temp'):
                runner.run(['/usr/bin/productbuild','--component',staged,'/Applications','--sign',matches[0],'--keychain',keychain,package],'component-package',timeout=600)
            os.chmod(package,0o600)
            c.require(payload.tree_snapshot(primary)==snapshot and payload.tree_snapshot(staged)==copied,'signed_archive_or_staged_bytes_modes_changed')
            details=payload.check_package(package,repair,runner,work)
            private_write(work/'stored-payload-permissions.json',{'source_sha':scope['source_sha'],'build':'3','substantive_archive_unchanged':True,'signed_staged_bytes_unchanged':True,'package_sha256':hashlib.sha256(package.read_bytes()).hexdigest(),**details})
        else:
            runner.run(['/usr/bin/xcodebuild','-exportArchive','-archivePath',archive,'-exportPath',export,'-exportOptionsPlist',export_options],'export',cwd=source,timeout=1200)
        runner.run([sys.executable,scripts/'validate_resale_export.py','--family',family,'--archive',archive,'--export-dir',export,'--scope',scope_file,'--report',work/'signed-validation.json'],'signed-validation',timeout=600)
        private_write(work/'export-provenance.json',{'schema':1,'source_sha':scope['source_sha'],'tooling_sha':scope['tooling_sha'],'delivery_sha':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'family':family,'team':c.TEAM,'group':c.GROUP,'match_commit':manifest['match_commit'],'exact_bundle_ids':[t['bundle_id'] for t in wanted],'archived':True,'exported':True,'signed_validation_passed':True,'uploaded':False,'profile_or_certificate_created_by_export':False,'app_intents_release_diagnostics_preserved_privately':True})
    finally:
        if original is not None:
            try:runner.run(['/usr/bin/security','list-keychains','-d','user','-s',*original],'restore-search-list')
            except Exception:cleanup_errors.append('search_list_restore_failed')
        if created:
            try:runner.run(['/usr/bin/security','delete-keychain',keychain],'keychain-delete')
            except Exception:cleanup_errors.append('ephemeral_keychain_delete_failed')
        for dest in installed:
            try:dest.unlink()
            except FileNotFoundError:pass
        private_write(work/'runner-step-receipt.json',{'steps':runner.steps,'ephemeral_keychain_created':created,'canonical_source_untouched':True,'runner_only_project_signing_configuration':True,'no_upload_path':True,'ephemeral_cleanup_verified':not cleanup_errors,'cleanup_failures':cleanup_errors})
        c.require(not cleanup_errors,'Ephemeral keychain cleanup did not complete; protected diagnostics preserved.')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scope',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--material-dir',type=Path,required=True);p.add_argument('--source-dir',type=Path,required=True);p.add_argument('--work-dir',type=Path,required=True);p.add_argument('--p12-password-file',type=Path,required=True);p.add_argument('--bundle-gemfile',type=Path,required=True);p.add_argument('--release-review',type=Path,required=True);p.add_argument('--source-manifest',type=Path,required=True);a=p.parse_args()
    try:
        c.validate_freeze(json.loads(a.release_review.read_text()),json.loads(a.source_manifest.read_text()),a.source_dir)
        build(json.loads(a.scope.read_text()),a.scope.resolve(),json.loads(a.manifest.read_text()),a.material_dir,a.source_dir,a.work_dir,a.p12_password_file,a.bundle_gemfile)
        print('Exact family signed archive/export validated. No App Store upload or device delivery performed.');return 0
    except c.GateError as error:print('Protected archive/export stopped: '+str(error));return 1
    except Exception:print('Protected archive/export stopped; private diagnostics remain protected.');return 1
if __name__=='__main__':raise SystemExit(main())
