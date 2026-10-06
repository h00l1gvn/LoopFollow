#!/usr/bin/env python3
"""Exact-family, read-only local archive/export validation. No signing, keychain import or upload.

Only platform tools read supplied artifacts. Raw tool output is written privately next to
--report; stdout and the report contain fixed diagnostics, never tool bodies/profile data.
The result is local artifact validation, not App Store acceptance or device installation.
"""
from __future__ import annotations
import argparse, datetime, hashlib, json, os, pathlib, plistlib, re, shutil, stat, subprocess, tempfile, zipfile

TEAM='N8K8G6QA36'
GROUP='group.com.julienbell.ResaleBurrow'
BASE='com.julienbell.ResaleBurrow'
EXACT={
 'ios':{BASE:('iOS','17.0'),BASE+'.widgets':('iOS','17.0'),BASE+'.watch':('watchOS','10.0'),BASE+'.watch.widgets':('watchOS','10.0')},
 'macos':{BASE+'.mac':('macOS','13.0'),BASE+'.mac.widgets':('macOS','13.0')},
 'tvos':{BASE+'.tv':('tvOS','17.0')},
}
PLATFORMS={'iOS':'iPhoneOS','watchOS':'WatchOS','macOS':'MacOSX','tvOS':'AppleTVOS'}
DEFAULT_REASONS={'CA92.1','1C8F.1'}

class ValidationError(Exception):
    def __init__(self, code:str): super().__init__(code); self.code=code

def require(value, code):
    if not value: raise ValidationError(code)

def digest(path): return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def private_write(path, content):
    path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    require(not path.is_symlink(),'unsafe_report_destination')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as handle: handle.write(content if isinstance(content,bytes) else content.encode())
    except BaseException:
        try:os.close(fd)
        except OSError:pass
        raise

def load_plist(path):
    try:
        value=plistlib.loads(pathlib.Path(path).read_bytes())
        require(isinstance(value,dict),'invalid_plist')
        return value
    except (OSError,ValueError,plistlib.InvalidFileException):raise ValidationError('invalid_plist') from None

def scope_check(scope, family):
    require(family in EXACT,'unsupported_family')
    require(scope.get('team')==TEAM and scope.get('group')==GROUP,'scope_identity_mismatch')
    require(scope.get('version')=='0.1.0' and str(scope.get('build'))=='1','scope_version_mismatch')
    require(isinstance(scope.get('source_sha'),str) and re.fullmatch(r'[0-9a-f]{40}',scope['source_sha']),'scope_source_unfrozen')
    rows=scope.get('targets');require(isinstance(rows,list) and len(rows)==7,'scope_bundle_set_mismatch')
    all_expected={i:(f,p,m) for f,rows in EXACT.items() for i,(p,m) in rows.items()}
    require(len({r.get('bundle_id') for r in rows})==7 and {r.get('bundle_id') for r in rows}==set(all_expected),'scope_bundle_set_mismatch')
    for row in rows:
        fam,platform,minimum=all_expected[row['bundle_id']]
        require((row.get('family'),row.get('platform'),row.get('minimum_os'))==(fam,platform,minimum),'scope_platform_mismatch')
    return {r['bundle_id']:r for r in rows if r['family']==family}

class Runner:
    """Platform commands only. No command mutates signing material, accounts or artifacts."""
    def __init__(self, private_dir):
        self.private_dir=pathlib.Path(private_dir);self.private_dir.mkdir(parents=True,exist_ok=True);os.chmod(self.private_dir,0o700);self.sequence=0
    def run(self, args, label, timeout=120):
        self.sequence+=1
        try:
            result=subprocess.run([str(x) for x in args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,env={**os.environ,'LC_ALL':'C'})
        except (OSError,subprocess.TimeoutExpired):raise ValidationError('platform_tool_unavailable_or_timed_out') from None
        prefix=f'{self.sequence:03d}-{label}'
        private_write(self.private_dir/(prefix+'-stdout.bin'),result.stdout)
        private_write(self.private_dir/(prefix+'-stderr.bin'),result.stderr)
        private_write(self.private_dir/(prefix+'-command.json'),json.dumps({'args':[str(x) for x in args],'returncode':result.returncode,'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
        require(result.returncode==0,'platform_validation_command_failed')
        return result.stdout,result.stderr
    def signature(self, bundle):
        self.run(['/usr/bin/codesign','--verify','--deep','--strict','--verbose=2',bundle],'codesign-verify')
        stdout,stderr=self.run(['/usr/bin/codesign','--display','--verbose=4',bundle],'codesign-display')
        details=(stdout+b'\n'+stderr).decode('utf-8',errors='replace')
        entitlements,_=self.run(['/usr/bin/codesign','--display','--entitlements',':-',bundle],'codesign-entitlements')
        try:
            marker=entitlements.find(b'<?xml');parsed=plistlib.loads(entitlements[marker:] if marker>=0 else entitlements)
        except (ValueError,plistlib.InvalidFileException):raise ValidationError('signed_entitlements_unreadable') from None
        prefix=self.private_dir/f'certificate-{self.sequence:03d}-'
        self.run(['/usr/bin/codesign','--display','--extract-certificates',prefix,bundle],'codesign-extract-certificates')
        certs=sorted(prefix.parent.glob(prefix.name+'*'))
        require(bool(certs) and pathlib.Path(str(prefix)+'0').is_file(),'signing_certificate_absent')
        for cert in certs:os.chmod(cert,0o600)
        self.run(['/usr/bin/security','verify-cert',*[x for cert in certs for x in ('-c',cert)],'-p','codeSign'],'certificate-trust')
        return {'team':re.search(r'^TeamIdentifier=(.+)$',details,re.M).group(1).strip() if re.search(r'^TeamIdentifier=(.+)$',details,re.M) else None,'identifier':re.search(r'^Identifier=(.+)$',details,re.M).group(1).strip() if re.search(r'^Identifier=(.+)$',details,re.M) else None,'authorities':re.findall(r'^Authority=(.+)$',details,re.M),'entitlements':parsed,'leaf_der':pathlib.Path(str(prefix)+'0').read_bytes()}
    def profile(self, path):
        stdout,_=self.run(['/usr/bin/security','cms','-D','-i',path],'profile-decode')
        try:return plistlib.loads(stdout)
        except (ValueError,plistlib.InvalidFileException):raise ValidationError('provisioning_profile_unreadable') from None
    def package(self, path, destination):
        stdout,stderr=self.run(['/usr/sbin/pkgutil','--check-signature',path],'pkg-signature')
        text=(stdout+b'\n'+stderr).decode('utf-8',errors='replace')
        require(bool(re.search(r'Status: signed by a certificate trusted by',text,re.I)),'installer_signature_untrusted')
        require(bool(re.search(r'3rd Party Mac Developer Installer:[^\n]*\('+re.escape(TEAM)+r'\)',text)),'installer_certificate_not_mac_app_store_team')
        require('Developer ID Installer:' not in text,'installer_certificate_not_mac_app_store_team')
        self.run(['/usr/sbin/pkgutil','--expand-full',path,destination],'pkg-expand',timeout=240)


def info_path(bundle):
    return bundle/'Contents/Info.plist' if (bundle/'Contents/Info.plist').is_file() else bundle/'Info.plist'

def resources_path(bundle, platform): return bundle/'Contents/Resources' if platform=='macOS' else bundle

def identifier_entitlement(entitlements, identifier):
    values=[entitlements[k] for k in ('application-identifier','com.apple.application-identifier') if k in entitlements]
    return bool(values) and all(v==TEAM+'.'+identifier for v in values)

def version_tuple(value):
    require(isinstance(value,str) and re.fullmatch(r'\d+(?:\.\d+){0,3}',value),'invalid_minimum_os')
    parts=tuple(int(p) for p in value.split('.'))
    return parts+(0,)*(4-len(parts))

def manifest_check(path, platform, widget):
    require(path.is_file(),'privacy_manifest_missing');privacy=load_plist(path)
    require(privacy.get('NSPrivacyTracking') is False and privacy.get('NSPrivacyTrackingDomains')==[],'unexpected_privacy_tracking')
    required=privacy.get('NSPrivacyAccessedAPITypes',[])
    require(any(r.get('NSPrivacyAccessedAPIType')=='NSPrivacyAccessedAPICategoryUserDefaults' and set(r.get('NSPrivacyAccessedAPITypeReasons',[]))==DEFAULT_REASONS for r in required),'privacy_defaults_reasons_missing')
    records=privacy.get('NSPrivacyCollectedDataTypes');require(isinstance(records,list),'privacy_collection_schema_invalid')
    expected=set() if widget else {'NSPrivacyCollectedDataTypeUserID','NSPrivacyCollectedDataTypeName','NSPrivacyCollectedDataTypeDeviceID','NSPrivacyCollectedDataTypeOtherUserContent'}
    if not widget and platform in ('iOS','macOS'):expected|={'NSPrivacyCollectedDataTypePhotosorVideos','NSPrivacyCollectedDataTypeOtherFinancialInfo'}
    require({r.get('NSPrivacyCollectedDataType') for r in records}==expected,'privacy_collection_types_mismatch')
    for r in records:require(r.get('NSPrivacyCollectedDataTypeLinked') is True and r.get('NSPrivacyCollectedDataTypeTracking') is False and r.get('NSPrivacyCollectedDataTypePurposes')==['NSPrivacyCollectedDataTypePurposeAppFunctionality'],'privacy_collection_purpose_mismatch')

def profile_check(profile, signature, identifier, now):
    require(profile.get('TeamIdentifier')==[TEAM],'profile_team_mismatch')
    require(profile.get('ApplicationIdentifierPrefix')==[TEAM],'profile_prefix_mismatch')
    expiry=profile.get('ExpirationDate');created=profile.get('CreationDate')
    require(isinstance(expiry,datetime.datetime),'profile_expiry_missing')
    expiry=expiry.replace(tzinfo=datetime.timezone.utc) if expiry.tzinfo is None else expiry
    require(expiry>now,'profile_expired')
    if isinstance(created,datetime.datetime):
        created=created.replace(tzinfo=datetime.timezone.utc) if created.tzinfo is None else created
        require(created<=now,'profile_not_yet_valid')
    require('ProvisionedDevices' not in profile and not profile.get('ProvisionsAllDevices',False),'profile_not_app_store_distribution')
    ent=profile.get('Entitlements',{});require(isinstance(ent,dict),'profile_entitlements_invalid')
    require(ent.get('get-task-allow',False) is False,'profile_development_enabled')
    require(identifier_entitlement(ent,identifier),'profile_explicit_identifier_mismatch')
    require(ent.get('com.apple.developer.team-identifier')==TEAM,'profile_entitlement_team_mismatch')
    require(ent.get('com.apple.security.application-groups')==[GROUP],'profile_app_group_mismatch')
    certs=profile.get('DeveloperCertificates',[])
    require(isinstance(certs,list) and signature['leaf_der'] in certs,'signer_not_in_embedded_profile')
    return {'expires_at':expiry.isoformat(),'certificate_sha256':hashlib.sha256(signature['leaf_der']).hexdigest()}

def bundle_check(bundle, target, runner, now):
    identifier=target['bundle_id'];platform=target['platform'];widget=identifier.endswith('.widgets');info=load_plist(info_path(bundle))
    require(info.get('CFBundleIdentifier')==identifier,'bundle_identifier_mismatch')
    require(info.get('CFBundleShortVersionString')=='0.1.0' and str(info.get('CFBundleVersion'))=='1','bundle_version_mismatch')
    require(info.get('CFBundlePackageType')==('XPC!' if widget else 'APPL'),'bundle_package_type_mismatch')
    require(info.get('ITSAppUsesNonExemptEncryption') is False,'export_encryption_metadata_missing')
    minimum=info.get('LSMinimumSystemVersion' if platform=='macOS' else 'MinimumOSVersion')
    require(version_tuple(minimum)==version_tuple(target['minimum_os']),'bundle_minimum_os_mismatch')
    require(info.get('CFBundleSupportedPlatforms')==[PLATFORMS[platform]],'compiled_platform_mismatch')
    executable=info.get('CFBundleExecutable');require(isinstance(executable,str) and executable not in ('','.', '..') and '/' not in executable,'executable_metadata_invalid')
    require((bundle/('Contents/MacOS/'+executable if platform=='macOS' else executable)).is_file(),'executable_missing')
    if widget:
        require(info.get('NSExtension',{}).get('NSExtensionPointIdentifier')=='com.apple.widgetkit-extension','widget_relationship_invalid')
    if platform=='watchOS' and not widget:
        require(info.get('WKApplication') is True and info.get('WKCompanionAppBundleIdentifier')==BASE and not info.get('WKWatchOnly',False),'watch_companion_relationship_invalid')
    if platform=='iOS' and not widget:
        require(set(info.get('UISupportedInterfaceOrientations~ipad',[]))=={'UIInterfaceOrientationPortrait','UIInterfaceOrientationPortraitUpsideDown','UIInterfaceOrientationLandscapeLeft','UIInterfaceOrientationLandscapeRight'},'ipad_orientations_incomplete')
    if platform=='tvOS':
        require(bool(info.get('CFBundleIcons',{}).get('CFBundlePrimaryIcon')),'compiled_tv_primary_icon_missing')
        require(bool(info.get('TVTopShelfImage',{}).get('TVTopShelfPrimaryImageWide')),'compiled_tv_wide_top_shelf_missing')
    manifest_check(resources_path(bundle,platform)/'PrivacyInfo.xcprivacy',platform,widget)
    signature=runner.signature(bundle)
    require(signature.get('team')==TEAM and signature.get('identifier')==identifier,'signature_identity_mismatch')
    require(any(a.startswith(('Apple Distribution:','3rd Party Mac Developer Application:')) for a in signature.get('authorities',[])),'signature_not_app_store_distribution')
    require(not any(a.startswith(('Apple Development:','iPhone Developer:','Mac Developer:','Developer ID Application:')) for a in signature.get('authorities',[])),'signature_not_app_store_distribution')
    ent=signature.get('entitlements',{});require(isinstance(ent,dict),'signature_entitlements_invalid')
    require(identifier_entitlement(ent,identifier),'signature_explicit_identifier_mismatch')
    require(ent.get('com.apple.developer.team-identifier')==TEAM,'signature_entitlement_team_mismatch')
    require(ent.get('com.apple.security.application-groups')==[GROUP],'signature_app_group_mismatch')
    require(ent.get('get-task-allow',False) is False,'signature_development_enabled')
    if platform=='macOS':require(ent.get('com.apple.security.app-sandbox') is True,'mac_sandbox_missing')
    profile_path=bundle/'Contents/embedded.provisionprofile' if platform=='macOS' else bundle/'embedded.mobileprovision'
    require(profile_path.is_file(),'embedded_profile_missing');profile=runner.profile(profile_path)
    profile_details=profile_check(profile,signature,identifier,now)
    return {'bundle_id':identifier,'platform':platform,'version':'0.1.0','build':'1','minimum_os':minimum,'privacy_manifest_sha256':digest(resources_path(bundle,platform)/'PrivacyInfo.xcprivacy'),'signature_verified':True,'profile_verified':True,**profile_details}

def bundle_set(primary, expected, runner, now):
    require(primary.is_dir() and primary.suffix=='.app','primary_app_missing')
    bundles=[primary]+[p for p in primary.rglob('*') if p.is_dir() and p.suffix in ('.app','.appex')]
    found={}
    for bundle in bundles:
        require(bundle.resolve().is_relative_to(primary.resolve()),'embedded_bundle_escaped_primary')
        identifier=load_plist(info_path(bundle)).get('CFBundleIdentifier')
        require(identifier in expected and identifier not in found,'unexpected_or_duplicate_bundle')
        found[identifier]=bundle
    require(set(found)==set(expected),'bundle_set_incomplete')
    for identifier,bundle in found.items():
        if identifier==BASE+'.watch':require(bundle.parent==primary/'Watch','watch_embedding_path_invalid')
        elif identifier.endswith('.widgets'):
            parent_id=identifier[:-len('.widgets')];host=found.get(parent_id)
            require(host is not None,'widget_host_missing')
            plugin=host/'Contents/PlugIns' if expected[identifier]['platform']=='macOS' else host/'PlugIns'
            require(bundle.parent==plugin,'widget_embedding_path_invalid')
    return [bundle_check(found[identifier],target,runner,now) for identifier,target in expected.items()]

def extract_ipa(path, destination):
    try:
        with zipfile.ZipFile(path) as handle:
            require(sum(r.file_size for r in handle.infolist())<=2*1024**3,'ipa_too_large')
            for row in handle.infolist():
                p=pathlib.PurePosixPath(row.filename);mode=row.external_attr>>16
                require(not p.is_absolute() and '..' not in p.parts and '\\' not in row.filename and not stat.S_ISLNK(mode),'unsafe_ipa_member')
            handle.extractall(destination)
            for row in handle.infolist():
                target=destination/row.filename;mode=(row.external_attr>>16)&0o777
                if mode and target.exists():os.chmod(target,mode)
    except (OSError,zipfile.BadZipFile):raise ValidationError('ipa_unreadable') from None
    apps=list((destination/'Payload').glob('*.app'));require(len(apps)==1,'export_payload_primary_set_invalid');return apps[0]

def validate(family, archive, export_dir, scope, report, runner=None, now=None):
    archive=pathlib.Path(archive).resolve();export_dir=pathlib.Path(export_dir).resolve();report=pathlib.Path(report).resolve()
    result={'schema':'ResaleBurrow-exact-family-export-validation-1','family':family,'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'failed','signed_local_artifacts_verified':False,'store_accepted':False,'uploaded':False,'installed':False,'source_sha_basis':scope.get('source_sha'),'source_sha_embedded_in_binary_verified':False}
    stage='scope'
    try:
        expected=scope_check(scope,family);runner=runner or Runner(report.parent/(report.stem+'-private'))
        now=now or datetime.datetime.now(datetime.timezone.utc)
        stage='archive';require(archive.is_dir() and archive.suffix=='.xcarchive','archive_missing')
        archive_info=load_plist(archive/'Info.plist');properties=archive_info.get('ApplicationProperties',{})
        primary_id=next(k for k in expected if k in (BASE,BASE+'.mac',BASE+'.tv'))
        require(properties.get('CFBundleIdentifier')==primary_id,'archive_primary_identifier_mismatch')
        app_path=properties.get('ApplicationPath');require(isinstance(app_path,str),'archive_primary_path_missing')
        path=pathlib.PurePosixPath(app_path);require(not path.is_absolute() and '..' not in path.parts,'archive_primary_path_invalid')
        primary=archive/'Products'/path
        require(primary.resolve().is_relative_to((archive/'Products/Applications').resolve()),'archive_not_single_top_level_app')
        apps=list((archive/'Products/Applications').glob('*.app'));require(apps==[primary] and {p.name for p in (archive/'Products').iterdir()}=={'Applications'},'archive_not_single_top_level_app')
        result['archive_bundles']=bundle_set(primary,expected,runner,now)
        stage='export';require(export_dir.is_dir(),'export_directory_missing')
        suffix='.pkg' if family=='macos' else '.ipa';exports=list(export_dir.glob('*'+suffix));require(len(exports)==1,'export_artifact_set_invalid')
        with tempfile.TemporaryDirectory(prefix='resale-export-validation-',dir=report.parent) as temporary:
            destination=pathlib.Path(temporary)/'expanded'
            if family=='macos':
                runner.package(exports[0],destination)
                roots=[p for p in destination.rglob('*.app') if (p/'Contents/Info.plist').is_file() and load_plist(p/'Contents/Info.plist').get('CFBundleIdentifier')==primary_id]
                require(len(roots)==1,'installer_payload_primary_set_invalid');export_primary=roots[0]
                require(not any(p.suffix in ('.app','.appex') and p!=export_primary and not p.is_relative_to(export_primary) for p in destination.rglob('*') if p.is_dir()),'installer_payload_unexpected_bundle')
                result['installer_signature_verified']=True
            else:destination.mkdir();export_primary=extract_ipa(exports[0],destination)
            result['export_bundles']=bundle_set(export_primary,expected,runner,now)
        result.update(status='passed',signed_local_artifacts_verified=True,export_artifact_sha256=digest(exports[0]),exact_bundle_count=len(expected),team=TEAM,group=GROUP)
    except ValidationError as error:result.update(error_code=error.code,failed_stage=stage)
    except (OSError,ValueError,TypeError,KeyError,AttributeError):result.update(error_code='artifact_or_scope_unreadable',failed_stage=stage)
    private_write(report,json.dumps(result,indent=2)+'\n');return result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--family',choices=tuple(EXACT),required=True);parser.add_argument('--archive',type=pathlib.Path,required=True);parser.add_argument('--export-dir',type=pathlib.Path,required=True);parser.add_argument('--scope',type=pathlib.Path,required=True);parser.add_argument('--report',type=pathlib.Path,required=True);args=parser.parse_args()
    args.report.parent.mkdir(parents=True,exist_ok=True)
    try:scope=json.loads(args.scope.read_text())
    except (OSError,ValueError):
        private_write(args.report,json.dumps({'status':'failed','error_code':'scope_unreadable'})+'\n');print(json.dumps({'status':'failed','error_code':'scope_unreadable'}));return 1
    result=validate(args.family,args.archive,args.export_dir,scope,args.report)
    print(json.dumps({k:result[k] for k in ('status','family','error_code','failed_stage','exact_bundle_count','signed_local_artifacts_verified') if k in result}))
    return 0 if result['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
