#!/usr/bin/env python3
"""Synthetic fixtures only; no actual codesign/security/pkgutil/signing/account calls."""
import copy,datetime,importlib.util,json,pathlib,plistlib,shutil,tempfile,unittest,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('resale_export_validator',ROOT/'validate_resale_export.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
SCOPE=json.loads((ROOT/'signing-export-scope.json').read_text());NOW=datetime.datetime(2026,10,6,8,tzinfo=datetime.timezone.utc)
CERT=b'SYNTHETIC TEST CERTIFICATE; NOT A SIGNED ARTIFACT'
class SyntheticReader:
    def __init__(self):self.entitlement_override={};self.profile_override={};self.leaf=CERT;self.payload=None;self.package_calls=0
    def signature(self,bundle):
        identifier=v.load_plist(v.info_path(bundle))['CFBundleIdentifier'];ent={'application-identifier':v.TEAM+'.'+identifier,'com.apple.developer.team-identifier':v.TEAM,'com.apple.security.application-groups':[v.GROUP],'get-task-allow':False}
        if '.mac' in identifier:ent['com.apple.security.app-sandbox']=True
        ent.update(self.entitlement_override)
        return {'team':v.TEAM,'identifier':identifier,'authorities':['Apple Distribution: Synthetic Fixture ('+v.TEAM+')'],'entitlements':ent,'leaf_der':self.leaf}
    def profile(self,path):
        bundle=path.parent.parent if path.parent.name=='Contents' else path.parent
        identifier=v.load_plist(v.info_path(bundle))['CFBundleIdentifier']
        ent={'application-identifier':v.TEAM+'.'+identifier,'com.apple.developer.team-identifier':v.TEAM,'com.apple.security.application-groups':[v.GROUP],'get-task-allow':False}
        result={'TeamIdentifier':[v.TEAM],'ApplicationIdentifierPrefix':[v.TEAM],'ExpirationDate':NOW+datetime.timedelta(days=30),'CreationDate':NOW-datetime.timedelta(days=1),'Entitlements':ent,'DeveloperCertificates':[CERT]}
        result.update(self.profile_override);return result
    def package(self,path,destination):
        self.package_calls+=1;shutil.copytree(self.payload,destination/'Payload')

def write_plist(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(plistlib.dumps(value))
def make_bundle(path,target):
    platform=target['platform'];identifier=target['bundle_id'];widget=identifier.endswith('.widgets');name=target['target']
    info={'CFBundleIdentifier':identifier,'CFBundleShortVersionString':'0.1.0','CFBundleVersion':'1','CFBundlePackageType':'XPC!' if widget else 'APPL','CFBundleExecutable':name,'ITSAppUsesNonExemptEncryption':False,'CFBundleSupportedPlatforms':[v.PLATFORMS[platform]],'LSMinimumSystemVersion' if platform=='macOS' else 'MinimumOSVersion':target['minimum_os']}
    if widget:info['NSExtension']={'NSExtensionPointIdentifier':'com.apple.widgetkit-extension'}
    if platform=='watchOS' and not widget:info.update(WKApplication=True,WKCompanionAppBundleIdentifier=v.BASE)
    if platform=='iOS' and not widget:info['UISupportedInterfaceOrientations~ipad']=['UIInterfaceOrientationPortrait','UIInterfaceOrientationPortraitUpsideDown','UIInterfaceOrientationLandscapeLeft','UIInterfaceOrientationLandscapeRight']
    if platform=='tvOS':info.update(CFBundleIcons={'CFBundlePrimaryIcon':'fixture-icon'},TVTopShelfImage={'TVTopShelfPrimaryImageWide':'fixture-wide'})
    write_plist(path/'Contents/Info.plist' if platform=='macOS' else path/'Info.plist',info)
    exe=path/('Contents/MacOS/'+name if platform=='macOS' else name);exe.parent.mkdir(parents=True,exist_ok=True);exe.write_bytes(b'SYNTHETIC UNSIGNED MACHO PLACEHOLDER')
    profile=path/('Contents/embedded.provisionprofile' if platform=='macOS' else 'embedded.mobileprovision');profile.write_bytes(b'SYNTHETIC CMS PLACEHOLDER')
    types=[] if widget else ['NSPrivacyCollectedDataTypeUserID','NSPrivacyCollectedDataTypeName','NSPrivacyCollectedDataTypeDeviceID','NSPrivacyCollectedDataTypeOtherUserContent']
    if not widget and platform in ('iOS','macOS'):types+=['NSPrivacyCollectedDataTypePhotosorVideos','NSPrivacyCollectedDataTypeOtherFinancialInfo']
    privacy={'NSPrivacyTracking':False,'NSPrivacyTrackingDomains':[],'NSPrivacyAccessedAPITypes':[{'NSPrivacyAccessedAPIType':'NSPrivacyAccessedAPICategoryUserDefaults','NSPrivacyAccessedAPITypeReasons':['CA92.1','1C8F.1']}],'NSPrivacyCollectedDataTypes':[{'NSPrivacyCollectedDataType':t,'NSPrivacyCollectedDataTypeLinked':True,'NSPrivacyCollectedDataTypeTracking':False,'NSPrivacyCollectedDataTypePurposes':['NSPrivacyCollectedDataTypePurposeAppFunctionality']} for t in types]}
    write_plist(v.resources_path(path,platform)/'PrivacyInfo.xcprivacy',privacy)

class Validation(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name);self.reader=SyntheticReader()
    def tearDown(self):self.temp.cleanup()
    def fixtures(self,family):
        expected=v.scope_check(SCOPE,family);archive=self.root/(family+'.xcarchive');primary_id=next(i for i in expected if i in (v.BASE,v.BASE+'.mac',v.BASE+'.tv'));main=archive/'Products/Applications'/ (expected[primary_id]['target']+'.app')
        paths={primary_id:main}
        for identifier,target in expected.items():
            if identifier==primary_id:continue
            if identifier.endswith('.watch'):paths[identifier]=main/'Watch'/(target['target']+'.app')
        for identifier,target in expected.items():
            if identifier.endswith('.widgets'):
                host=paths[identifier[:-len('.widgets')]];paths[identifier]=host/('Contents/PlugIns' if target['platform']=='macOS' else 'PlugIns')/(target['target']+'.appex')
        for identifier,path in paths.items():make_bundle(path,expected[identifier])
        write_plist(archive/'Info.plist',{'ApplicationProperties':{'ApplicationPath':main.relative_to(archive/'Products').as_posix(),'CFBundleIdentifier':primary_id}})
        exports=self.root/('export-'+family);exports.mkdir();payload=self.root/('payload-'+family);payload.mkdir();shutil.copytree(main,payload/main.name)
        if family=='macos':(exports/'ResaleBurrow.pkg').write_bytes(b'SYNTHETIC PKG');self.reader.payload=payload
        else:
            with zipfile.ZipFile(exports/'ResaleBurrow.ipa','w') as handle:
                for path in payload.rglob('*'):
                    if path.is_file():handle.write(path,('Payload/'+path.relative_to(payload).as_posix()))
        return archive,exports,paths
    def run_family(self,family):
        archive,exports,_=self.fixtures(family)
        return v.validate(family,archive,exports,SCOPE,self.root/(family+'-report.json'),self.reader,NOW)
    def test_exact_ios_embedded_watch_and_widgets_pass_synthetic_checks(self):
        result=self.run_family('ios');self.assertEqual(result['status'],'passed');self.assertEqual(result['exact_bundle_count'],4)
    def test_exact_mac_archive_and_export_package_payload_pass_synthetic_checks(self):
        result=self.run_family('macos');self.assertEqual(result['status'],'passed');self.assertTrue(result['installer_signature_verified']);self.assertEqual(self.reader.package_calls,1)
    def test_exact_tv_compiled_metadata_pass_synthetic_checks(self):self.assertEqual(self.run_family('tvos')['status'],'passed')
    def test_missing_embedded_watch_widget_fails(self):
        archive,exports,paths=self.fixtures('ios');shutil.rmtree(paths[v.BASE+'.watch.widgets'])
        result=v.validate('ios',archive,exports,SCOPE,self.root/'r.json',self.reader,NOW);self.assertEqual(result['error_code'],'bundle_set_incomplete')
    def test_signed_group_mismatch_fails_without_raw_values_in_report(self):
        self.reader.entitlement_override={'com.apple.security.application-groups':['private contact fixture must never escape']}
        result=self.run_family('tvos');self.assertEqual(result['error_code'],'signature_app_group_mismatch');self.assertNotIn('private contact',json.dumps(result))
    def test_signer_certificate_not_in_embedded_profile_fails(self):
        self.reader.leaf=b'WRONG SYNTHETIC CERT';result=self.run_family('tvos');self.assertEqual(result['error_code'],'signer_not_in_embedded_profile')
    def test_expired_profile_fails(self):
        self.reader.profile_override={'ExpirationDate':NOW-datetime.timedelta(seconds=1)};self.assertEqual(self.run_family('tvos')['error_code'],'profile_expired')
    def test_ad_hoc_profile_not_store_distribution_fails(self):
        self.reader.profile_override={'ProvisionedDevices':['PRIVATE-DEVICE-NOT-OUTPUT']};result=self.run_family('tvos');self.assertEqual(result['error_code'],'profile_not_app_store_distribution');self.assertNotIn('PRIVATE-DEVICE',json.dumps(result))
    def test_missing_compiled_tv_wide_key_fails_even_with_source_assets(self):
        archive,exports,paths=self.fixtures('tvos');p=paths[v.BASE+'.tv']/'Info.plist';info=v.load_plist(p);del info['TVTopShelfImage'];write_plist(p,info)
        result=v.validate('tvos',archive,exports,SCOPE,self.root/'r.json',self.reader,NOW);self.assertEqual(result['error_code'],'compiled_tv_wide_top_shelf_missing')
    def test_missing_manifest_fails_in_embedded_extension(self):
        archive,exports,paths=self.fixtures('macos');(paths[v.BASE+'.mac.widgets']/'Contents/Resources/PrivacyInfo.xcprivacy').unlink()
        result=v.validate('macos',archive,exports,SCOPE,self.root/'r.json',self.reader,NOW);self.assertEqual(result['error_code'],'privacy_manifest_missing')
    def test_export_is_independently_checked_and_cannot_change_owner_bundle_set(self):
        archive,exports,paths=self.fixtures('macos');p=self.reader.payload/paths[v.BASE+'.mac'].name/'Contents/PlugIns/ResaleBurrowMacWidgets.appex/Contents/Info.plist';info=v.load_plist(p);info['CFBundleIdentifier']='unrelated.private.bundle';write_plist(p,info)
        result=v.validate('macos',archive,exports,SCOPE,self.root/'r.json',self.reader,NOW);self.assertEqual(result['failed_stage'],'export');self.assertEqual(result['error_code'],'unexpected_or_duplicate_bundle')
    def test_zip_path_traversal_rejected(self):
        p=self.root/'unsafe.ipa'
        with zipfile.ZipFile(p,'w') as h:h.writestr('../../private-account.txt','unreadable fixture')
        with self.assertRaisesRegex(v.ValidationError,'unsafe_ipa_member'):v.extract_ipa(p,self.root/'out')
    def test_wildcard_profile_identifier_rejected(self):
        profile={'TeamIdentifier':[v.TEAM],'ApplicationIdentifierPrefix':[v.TEAM],'ExpirationDate':NOW+datetime.timedelta(days=1),'Entitlements':{'application-identifier':v.TEAM+'.*','com.apple.developer.team-identifier':v.TEAM,'com.apple.security.application-groups':[v.GROUP]},'DeveloperCertificates':[CERT]}
        with self.assertRaisesRegex(v.ValidationError,'profile_explicit_identifier_mismatch'):v.profile_check(profile,{'leaf_der':CERT},v.BASE,NOW)
    def test_second_top_level_archive_product_rejected(self):
        archive,exports,_=self.fixtures('ios');(archive/'Products/usr/local/lib').mkdir(parents=True)
        result=v.validate('ios',archive,exports,SCOPE,self.root/'r.json',self.reader,NOW);self.assertEqual(result['error_code'],'archive_not_single_top_level_app')
    def test_development_entitlement_rejected(self):
        self.reader.entitlement_override={'get-task-allow':True};self.assertEqual(self.run_family('ios')['error_code'],'signature_development_enabled')
    def test_private_raw_tool_logs_and_generic_error(self):
        import unittest.mock
        runner=v.Runner(self.root/'raw-private')
        fake=__import__('subprocess').CompletedProcess(['fixture'],1,stdout=b'PRIVATE-TEAM-CONTACT',stderr=b'PRIVATE-PROFILE-BODY')
        with unittest.mock.patch.object(v.subprocess,'run',return_value=fake):
            with self.assertRaisesRegex(v.ValidationError,'^platform_validation_command_failed$'):runner.run(['/usr/bin/codesign','--display','fixture'],'fixture')
        self.assertEqual((self.root/'raw-private').stat().st_mode&0o777,0o700)
        self.assertTrue(all(p.stat().st_mode&0o777==0o600 for p in (self.root/'raw-private').iterdir()))
        self.assertEqual((self.root/'raw-private/001-fixture-stdout.bin').read_bytes(),b'PRIVATE-TEAM-CONTACT')
    def test_scope_extra_identity_rejected(self):
        scope=copy.deepcopy(SCOPE);scope['targets'][0]['bundle_id']='another.bundle'
        with self.assertRaisesRegex(v.ValidationError,'scope_bundle_set_mismatch'):v.scope_check(scope,'ios')
    def test_report_is_private_and_never_claims_upload_or_store_acceptance(self):
        result=self.run_family('tvos');report=self.root/'tvos-report.json';self.assertEqual(report.stat().st_mode&0o777,0o600);self.assertFalse(result['uploaded']);self.assertFalse(result['store_accepted']);self.assertFalse(result['installed']);self.assertFalse(result['source_sha_embedded_in_binary_verified'])
    def profile_group_fixture(self, identifier, groups):
        return {'TeamIdentifier':[v.TEAM],'ApplicationIdentifierPrefix':[v.TEAM],
            'ExpirationDate':NOW+datetime.timedelta(days=1),
            'Entitlements':{'com.apple.application-identifier' if '.mac' in identifier else 'application-identifier':v.TEAM+'.'+identifier,
                'com.apple.developer.team-identifier':v.TEAM,'com.apple.security.application-groups':groups},
            'DeveloperCertificates':[CERT]}
    def test_observed_mac_literal_plus_team_wildcard_profile_grant_is_allowed(self):
        for identifier in [v.BASE+'.mac',v.BASE+'.mac.widgets']:
            for groups in [[v.GROUP],[v.GROUP,v.TEAM+'.*'],[v.TEAM+'.*',v.GROUP]]:
                v.profile_check(self.profile_group_fixture(identifier,groups),{'leaf_der':CERT},identifier,NOW)
    def test_ios_or_tv_profile_never_gets_mac_wildcard_exception(self):
        for identifier in [v.BASE,v.BASE+'.widgets',v.BASE+'.tv',v.BASE+'.watch']:
            with self.subTest(identifier=identifier),self.assertRaisesRegex(v.ValidationError,'profile_app_group_mismatch'):
                v.profile_check(self.profile_group_fixture(identifier,[v.GROUP,v.TEAM+'.*']),{'leaf_der':CERT},identifier,NOW)
    def test_mac_profile_extra_unrelated_missing_literal_or_duplicate_grant_rejected(self):
        for groups in [[v.GROUP,'OTHERTEAM.*'],[v.TEAM+'.*'],[v.GROUP,v.TEAM+'.*','other.group'],[v.GROUP,v.GROUP]]:
            with self.subTest(groups=groups),self.assertRaisesRegex(v.ValidationError,'profile_app_group_mismatch'):
                v.profile_check(self.profile_group_fixture(v.BASE+'.mac',groups),{'leaf_der':CERT},v.BASE+'.mac',NOW)
    def test_mac_signed_binary_wildcard_is_rejected_even_with_valid_profile(self):
        self.reader.entitlement_override={'com.apple.security.application-groups':[v.GROUP,v.TEAM+'.*']}
        result=self.run_family('macos');self.assertEqual(result['error_code'],'signature_app_group_mismatch')
    def test_codesign_certificate_optional_argument_is_single_equals_token(self):
        import subprocess,unittest.mock
        calls=[]
        def fake_run(args,**kwargs):
            calls.append(args);stdout=b''
            if '--verbose=4' in args:
                stdout=('TeamIdentifier='+v.TEAM+'\nIdentifier='+v.BASE+'\nAuthority=Apple Distribution: Synthetic Fixture\n').encode()
            if '--entitlements' in args:
                stdout=plistlib.dumps({'application-identifier':v.TEAM+'.'+v.BASE})
            for argument in args:
                if argument.startswith('--extract-certificates='):
                    pathlib.Path(argument.split('=',1)[1]+'0').write_bytes(CERT)
            return subprocess.CompletedProcess(args,0,stdout=stdout,stderr=b'')
        runner=v.Runner(self.root/'private-tools')
        with unittest.mock.patch.object(v.subprocess,'run',side_effect=fake_run):
            self.assertEqual(runner.signature(self.root/'synthetic.app')['leaf_der'],CERT)
        extraction=next(args for args in calls if any(a.startswith('--extract-certificates=') for a in args))
        self.assertEqual(len(extraction),4)
        self.assertNotIn('--extract-certificates',extraction)
if __name__=='__main__':unittest.main(verbosity=2)
