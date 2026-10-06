#!/usr/bin/env python3
"""Fresh frozen Bryan ad-hoc archive/export only. Private runtime; no upload or device query."""
from __future__ import annotations
import argparse,hashlib,json,os,re,secrets,shlex,subprocess,sys
from pathlib import Path
import resale_scoped_profiles as profiles
import validate_resale_adhoc_export as adhoc
SOURCE='1162d8a1f4fdda1c2678220c9102f9c03ab48c33'
DESTINATIONS={'ios':('ResaleBurrowIOS','generic/platform=iOS'),'macos':('ResaleBurrowMac','generic/platform=macOS'),'tvos':('ResaleBurrowTV','generic/platform=tvOS')}

def base_plan(scope,manifest,family,material,source,work):
    profiles.validate_scope(scope)
    profiles.require(os.environ.get('GITHUB_ACTIONS')=='true','Archive/export is restricted to an ephemeral reviewed CI runner.')
    profiles.require(scope.get('source_sha')==SOURCE and manifest.get('source_sha')==SOURCE,'Frozen private source differs.')
    profiles.require(family in DESTINATIONS and manifest.get('family')==family and manifest.get('team')==profiles.TEAM and manifest.get('group')==profiles.GROUP,'Restore family/identity differs.')
    material=Path(material).resolve();source=Path(source).resolve();work=Path(work).resolve();runner=Path(os.environ['RUNNER_TEMP']).resolve();workspace=Path(os.environ['GITHUB_WORKSPACE']).resolve()
    profiles.require(material.is_relative_to(runner) and work.is_relative_to(runner) and source.is_relative_to(workspace) and not work.is_relative_to(source),'Paths are outside the private runner scope.')
    wanted=[t for t in scope['targets'] if t['family']==family];rows=manifest.get('profiles',[])
    profiles.require(len(rows)==len(wanted) and {r.get('bundle_id') for r in rows}=={t['bundle_id'] for t in wanted},'Restore profile set differs.')
    for row in rows:
        profiles.require(row.get('verified') is True and row.get('native_readback_verified') is True and row.get('certificate_sha256')==profiles.CERT_SHA,'Profile verification is incomplete.')
        path=Path(row.get('private_profile_file',''))
        profiles.require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(material) and hashlib.sha256(path.read_bytes()).hexdigest()==row.get('sha256'),'Private profile path/hash differs.')
    for key in ['signing_certificate']+(['installer_certificate'] if family=='macos' else []):
        value=manifest.get(key,{}) or {};path=Path(value.get('p12_file',''))
        expected=profiles.CERT_SHA if key=='signing_certificate' else profiles.INSTALLER_SHA
        profiles.require(value.get('verified') is True and value.get('sha256')==expected and path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(material) and hashlib.sha256(path.read_bytes()).hexdigest()==value.get('p12_file_sha256'),'Existing identity material is missing or changed.')
    return wanted,DESTINATIONS[family]

def plan(scope,manifest,family,material,source,work):
    wanted,destination=base_plan(scope,manifest,family,material,source,work)
    profiles.require(family=='ios' and manifest.get('distribution')=='ad-hoc','Bryan export requires an iOS ad-hoc restore.')
    _,pins=adhoc.scope_check(scope)
    profiles.require(manifest.get('match_commit')=='4d7f92fe5c81c32823e8ace5aca316ee98c8a53e' and scope.get('match_material_commit')==manifest['match_commit'],'Immutable existing key material commit differs.')
    for row in manifest['profiles']:
        pin=pins[row['bundle_id']]
        profiles.require(row.get('profile_type')=='IOS_APP_ADHOC' and all(row.get(k)==pin[k] for k in ['native_profile_id','name','uuid','sha256']) and row.get('owner_private_phone_membership_verified_by_exact_cms_hash') is True,'Bryan restored profile differs from exact approved native CMS pins.')
    return wanted,destination

class PrivateRunner:
    def __init__(self,work):self.work=Path(work);self.work.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(self.work,0o700);self.steps=[]
    def run(self,args,label,cwd=None,timeout=180):
        index=len(self.steps)+1;out=self.work/(f'{index:02d}-{label}-stdout.log');err=self.work/(f'{index:02d}-{label}-stderr.log')
        with out.open('wb') as stdout,err.open('wb') as stderr:
            os.chmod(out,0o600);os.chmod(err,0o600)
            try:r=subprocess.run([str(v) for v in args],stdout=stdout,stderr=stderr,cwd=cwd,timeout=timeout)
            except (OSError,subprocess.TimeoutExpired):raise profiles.audit.AuditError('A private runner step was unavailable or timed out: '+label) from None
        self.steps.append({'step':label,'returncode':r.returncode})
        profiles.require(r.returncode==0,'A private runner step failed: '+label)
        return out.read_bytes()

def build(scope,scope_file,manifest,material,source,work,p12_password_file,bundle_gemfile):
    family=manifest['family'];wanted,(scheme,destination)=plan(scope,manifest,family,material,source,work)
    scripts=Path(__file__).parent.resolve();source=Path(source).resolve();material=Path(material).resolve();work=Path(work).resolve();runner=PrivateRunner(work)
    head=runner.run(['git','-C',source,'rev-parse','HEAD'],'source-sha').decode().strip();profiles.require(head==SOURCE,'Private checkout SHA differs.')
    profiles.require(not runner.run(['git','-C',source,'status','--porcelain'],'source-clean'),'Private checkout is not clean before runner-only signing configuration.')
    version=runner.run(['/usr/bin/xcodebuild','-version'],'xcode-version').decode();profiles.require(re.search(r'^Xcode 26[.]2$',version,re.M),'Reviewed Xcode 26.2 is not active.')
    profiles.require(Path(bundle_gemfile).is_file(),'Pinned delivery Gemfile is missing.')
    os.environ['BUNDLE_GEMFILE']=str(Path(bundle_gemfile).resolve())
    password_file=Path(p12_password_file);profiles.require(password_file.is_file() and not password_file.is_symlink() and password_file.stat().st_mode&0o077==0,'Private ephemeral p12 password file invalid.')
    p12_password=password_file.read_text().strip();profiles.require(len(p12_password)>=32,'Private ephemeral p12 password too short.')
    keychain=material/'resale-ephemeral.keychain-db';keychain_password=secrets.token_urlsafe(48);original=None;installed=[];created=False
    try:
        original=shlex.split(runner.run(['/usr/bin/security','list-keychains','-d','user'],'original-search-list').decode())
        runner.run(['/usr/bin/security','create-keychain','-p',keychain_password,keychain],'keychain-create');created=True
        runner.run(['/usr/bin/security','set-keychain-settings','-lut','21600',keychain],'keychain-timeout')
        runner.run(['/usr/bin/security','unlock-keychain','-p',keychain_password,keychain],'keychain-unlock')
        runner.run(['/usr/bin/security','list-keychains','-d','user','-s',keychain,*original],'keychain-search-list')
        for key in ['signing_certificate']+(['installer_certificate'] if family=='macos' else []):
            runner.run(['/usr/bin/security','import',manifest[key]['p12_file'],'-k',keychain,'-P',p12_password,'-T','/usr/bin/codesign','-T','/usr/bin/security'],'import-'+key)
        runner.run(['/usr/bin/security','set-key-partition-list','-S','apple-tool:,apple:,codesign:','-s','-k',keychain_password,keychain],'keychain-partition')
        for row in manifest['profiles']:
            raw=Path(row['private_profile_file']).read_bytes()
            for folder in [Path.home()/'Library/MobileDevice/Provisioning Profiles',Path.home()/'Library/Developer/Xcode/UserData/Provisioning Profiles']:
                folder.mkdir(parents=True,exist_ok=True);dest=folder/Path(row['private_profile_file']).name
                if dest.exists():profiles.require(not dest.is_symlink() and dest.read_bytes()==raw,'Existing runner profile collision; refuse overwrite.')
                else:
                    with dest.open('xb') as handle:handle.write(raw)
                    os.chmod(dest,0o600);installed.append(dest)
        project=source/'apple/ResaleBurrow.xcodeproj';export_options=work/'ExportOptions.plist'
        runner.run(['bundle','exec','ruby',scripts/'configure_resale_signing.rb','--distribution','ad-hoc','--family',family,'--checkout',source,'--project',project,'--scope',scope_file,'--manifest',material/'restore-manifest.json','--export-options',export_options,'--report',work/'manual-signing-config.json'],'manual-configure',cwd=source,timeout=120)
        archive=work/'ResaleBurrow.xcarchive';export=work/'export'
        runner.run(['/usr/bin/xcodebuild','-project',project,'-scheme',scheme,'-configuration','Release','-destination',destination,'-archivePath',archive,'archive'],'archive',cwd=source,timeout=3600)
        runner.run(['/usr/bin/xcodebuild','-exportArchive','-archivePath',archive,'-exportPath',export,'-exportOptionsPlist',export_options],'export',cwd=source,timeout=1200)
        runner.run([sys.executable,scripts/'validate_resale_adhoc_export.py','--archive',archive,'--export-dir',export,'--scope',scope_file,'--report',work/'signed-validation.json'],'signed-validation',timeout=600)
        ipas=list(export.glob('*.ipa'));profiles.require(len(ipas)==1 and ipas[0].is_file() and not ipas[0].is_symlink(),'Exact validated Bryan IPA required.')
        final=export/'ResaleBurrow-Bryan.ipa'
        if ipas[0]!=final:
            profiles.require(not final.exists(),'Bryan result filename collision.');ipas[0].rename(final)
        profiles.private_write(work/'export-provenance.json',{'schema':1,'source_sha':SOURCE,'tooling_sha':scope['tooling_sha'],'run_id':os.environ.get('GITHUB_RUN_ID'),'family':family,'distribution':'ad-hoc','delivery_lane':'bryan-ad-hoc','watch_hardware_eligibility_verified':False,'phone_queries':0,'team':profiles.TEAM,'group':profiles.GROUP,'match_commit':manifest['match_commit'],'exact_bundle_ids':[t['bundle_id'] for t in wanted],'archived':True,'exported':True,'signed_validation_passed':True,'uploaded':False,'profile_or_certificate_created_by_export':False,'app_intents_release_diagnostics_preserved_privately':True})
    finally:
        if original is not None:
            try:runner.run(['/usr/bin/security','list-keychains','-d','user','-s',*original],'restore-search-list')
            except Exception:pass
        if created:
            try:runner.run(['/usr/bin/security','delete-keychain',keychain],'keychain-delete')
            except Exception:pass
        for dest in installed:
            try:dest.unlink()
            except FileNotFoundError:pass
        profiles.private_write(work/'runner-step-receipt.json',{'steps':runner.steps,'ephemeral_keychain_created':created,'canonical_source_untouched':True,'no_upload_path':True})

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scope',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--material-dir',type=Path,required=True);p.add_argument('--source-dir',type=Path,required=True);p.add_argument('--work-dir',type=Path,required=True);p.add_argument('--p12-password-file',type=Path,required=True);p.add_argument('--bundle-gemfile',type=Path,required=True);a=p.parse_args()
    try:
        build(json.loads(a.scope.read_text()),a.scope.resolve(),json.loads(a.manifest.read_text()),a.material_dir,a.source_dir,a.work_dir,a.p12_password_file,a.bundle_gemfile)
        print('Exact family signed archive/export validated. No App Store upload or device delivery performed.');return 0
    except profiles.audit.AuditError as error:print('Protected archive/export stopped: '+str(error));return 1
    except Exception:print('Protected archive/export stopped; private diagnostics remain protected.');return 1
if __name__=='__main__':raise SystemExit(main())
