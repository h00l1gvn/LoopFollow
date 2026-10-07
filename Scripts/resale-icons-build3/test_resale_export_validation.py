#!/usr/bin/env python3
"""Synthetic fixtures only; no actual codesign/security/pkgutil/signing/account calls."""
import base64,copy,datetime,hashlib,importlib.util,json,pathlib,plistlib,shutil,tempfile,unittest,zipfile,unittest.mock
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('resale_export_validator',ROOT/'validate_resale_export.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
SCOPE=json.loads((ROOT/'signing-export-scope.json').read_text());SCOPE['source_sha']='a'*40;NOW=datetime.datetime(2026,10,6,8,tzinfo=datetime.timezone.utc)
CERT=b'SYNTHETIC TEST CERTIFICATE; NOT A SIGNED ARTIFACT'

def synthetic_installer_chain(*,eku='1.2.840.113635.100.4.9',marker='1.2.840.113635.100.6.1.8',team=v.TEAM,expired=False,digital_signature=True):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    keys=[rsa.generate_private_key(public_exponent=65537,key_size=2048) for _ in range(3)]
    names=[x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'3rd Party Mac Developer Installer: SYNTHETIC ('+team+')'),x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME,team)]),x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'SYNTHETIC WWDR')]),x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'SYNTHETIC ROOT')])]
    certs=[]
    for i in range(3):
        parent=min(i+1,2)
        b=x509.CertificateBuilder().subject_name(names[i]).issuer_name(names[parent]).public_key(keys[i].public_key()).serial_number(i+1).not_valid_before(NOW-datetime.timedelta(days=2)).not_valid_after(NOW-datetime.timedelta(days=1) if expired and i==0 else NOW+datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=i>0,path_length=None),critical=True)
        if i==0:
            b=b.add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier(eku)]),critical=True).add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(marker),b'\x05\x00'),critical=True).add_extension(x509.KeyUsage(digital_signature=digital_signature,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True)
        certs.append(b.sign(keys[parent],hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    return certs

def synthetic_toc(chain,additional=None):
    def sig(name,values):return '<'+name+'><KeyInfo>'+''.join('<X509Certificate>'+base64.b64encode(c).decode()+'</X509Certificate>' for c in values)+'</KeyInfo></'+name+'>'
    return ('<xar><toc>'+sig('signature',chain)+(sig('x-signature',additional) if additional is not None else '')+'</toc></xar>').encode()
class SyntheticReader:
    def __init__(self):self.entitlement_override={};self.profile_override={};self.leaf=CERT;self.payload=None;self.package_calls=0
    def signature(self,bundle):
        identifier=v.load_plist(v.info_path(bundle))['CFBundleIdentifier'];ent={'application-identifier':v.TEAM+'.'+identifier,'com.apple.developer.team-identifier':v.TEAM,'com.apple.security.application-groups':[v.GROUP],'get-task-allow':False}
        if '.mac' in identifier:ent['com.apple.security.app-sandbox']=True
        if identifier in v.contract.PUSH:ent[v.contract.PUSH[identifier]]='production'
        ent.update(self.entitlement_override)
        return {'team':v.TEAM,'identifier':identifier,'authorities':['Apple Distribution: Synthetic Fixture ('+v.TEAM+')'],'entitlements':ent,'leaf_der':self.leaf}
    def profile(self,path):
        bundle=path.parent.parent if path.parent.name=='Contents' else path.parent
        identifier=v.load_plist(v.info_path(bundle))['CFBundleIdentifier']
        ent={'application-identifier':v.TEAM+'.'+identifier,'com.apple.developer.team-identifier':v.TEAM,'com.apple.security.application-groups':[v.GROUP],'get-task-allow':False}
        if identifier in v.contract.PUSH:ent[v.contract.PUSH[identifier]]='production'
        ent.update(getattr(self,'profile_entitlement_override',{}))
        result={'TeamIdentifier':[v.TEAM],'ApplicationIdentifierPrefix':[v.TEAM],'ExpirationDate':NOW+datetime.timedelta(days=30),'CreationDate':NOW-datetime.timedelta(days=1),'Entitlements':ent,'DeveloperCertificates':[CERT]}
        result.update(self.profile_override);return result
    def package(self,path,destination):
        self.package_calls+=1;shutil.copytree(self.payload,destination/'Payload')

def write_plist(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(plistlib.dumps(value))
def make_bundle(path,target):
    platform=target['platform'];identifier=target['bundle_id'];widget=identifier.endswith('.widgets');name=target['target']
    info={'CFBundleIdentifier':identifier,'CFBundleShortVersionString':'0.1.0','CFBundleVersion':'3','CFBundleDisplayName':'Re$Burrow','CFBundlePackageType':'XPC!' if widget else 'APPL','CFBundleExecutable':name,'ITSAppUsesNonExemptEncryption':False,'CFBundleSupportedPlatforms':[v.PLATFORMS[platform]],'LSMinimumSystemVersion' if platform=='macOS' else 'MinimumOSVersion':target['minimum_os']}
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
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name);self.reader=SyntheticReader()
        patch=unittest.mock.patch.object(v.contract,'CERT_SHA',hashlib.sha256(CERT).hexdigest());patch.start();self.addCleanup(patch.stop)
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
        self.reader.leaf=b'WRONG SYNTHETIC CERT'
        with unittest.mock.patch.object(v.contract,'CERT_SHA',hashlib.sha256(self.reader.leaf).hexdigest()):result=self.run_family('tvos')
        self.assertEqual(result['error_code'],'signer_not_in_embedded_profile')
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

    def test_build1_binary_is_not_build2(self):
        archive,exports,paths=self.fixtures('ios');p=paths[v.BASE]/'Info.plist';info=v.load_plist(p);info['CFBundleVersion']='1';write_plist(p,info)
        self.assertEqual(v.validate('ios',archive,exports,SCOPE,self.root/'r.json',self.reader,NOW)['error_code'],'bundle_version_mismatch')
    def test_unsigned_source_aps_does_not_substitute_profile_permission(self):
        self.reader.profile_entitlement_override={'aps-environment':None}
        self.assertEqual(self.run_family('ios')['error_code'],'production_push_grant_missing')
    def test_binary_must_use_production_not_development_push(self):
        self.reader.entitlement_override={'aps-environment':'development'}
        self.assertEqual(self.run_family('ios')['error_code'],'production_push_grant_missing')
    def test_mac_requires_correct_platform_push_key(self):
        self.reader.profile_entitlement_override={'com.apple.developer.aps-environment':None}
        self.assertEqual(self.run_family('macos')['error_code'],'production_push_grant_missing')
    def test_widget_and_tv_do_not_gain_unapproved_push(self):
        self.reader.entitlement_override={'aps-environment':'production'}
        self.assertEqual(self.run_family('tvos')['error_code'],'unexpected_widget_or_tv_push')
    def test_other_valid_distribution_signer_still_rejected(self):
        self.reader.leaf=b'OTHER CURRENT VALID FIXTURE'
        self.assertEqual(self.run_family('tvos')['error_code'],'approved_signer_fingerprint_mismatch')
    def test_old_immutable_source_not_reused_as_build2(self):
        with self.assertRaisesRegex(v.ValidationError,'historical_source_not_build2'):v.scope_check({**SCOPE,'source_sha':v.contract.OLD_SOURCE},'ios')

class InstallerGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.chain=synthetic_installer_chain()
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def check(self,chain,now=NOW):
        with unittest.mock.patch.object(v,'INSTALLER_CHAIN_SHA256',tuple(hashlib.sha256(c).hexdigest() for c in chain)):
            return v.installer_chain_check(chain,now)
    def test_exact_synthetic_submission_purpose_dates_and_chain_pass(self):
        self.assertTrue(self.check(self.chain)['installer_submission_purpose_verified'])
    def test_every_chain_der_is_pinned_not_only_leaf(self):
        pins=tuple(hashlib.sha256(c).hexdigest() for c in self.chain)
        for i in range(3):
            changed=list(self.chain);changed[i]=changed[i]+b'changed'
            with self.subTest(i=i),unittest.mock.patch.object(v,'INSTALLER_CHAIN_SHA256',pins),self.assertRaisesRegex(v.ValidationError,'installer_chain_fingerprint_mismatch'):v.installer_chain_check(changed,NOW)
    def test_expiry_cannot_be_overridden_by_signed_pkgutil_wording(self):
        with self.assertRaisesRegex(v.ValidationError,'installer_certificate_not_current'):self.check(self.chain,NOW+datetime.timedelta(days=31))
    def test_future_certificate_rejected(self):
        with self.assertRaisesRegex(v.ValidationError,'installer_certificate_not_current'):self.check(self.chain,NOW-datetime.timedelta(days=3))
    def test_wrong_purpose_developer_id_or_missing_submission_marker_rejected(self):
        for options in [{'eku':'1.2.840.113635.100.4.13'},{'marker':'1.2.840.113635.100.6.1.14'},{'digital_signature':False}]:
            with self.subTest(options=options),self.assertRaisesRegex(v.ValidationError,'installer_certificate_purpose_invalid'):self.check(synthetic_installer_chain(**options))
    def test_wrong_team_cannot_pass_by_status_text(self):
        with self.assertRaisesRegex(v.ValidationError,'installer_certificate_not_mac_app_store_team'):self.check(synthetic_installer_chain(team='OTHERTEAM1'))
    def test_toc_alternate_signature_must_have_identical_three_certificate_chain(self):
        self.assertEqual(v.installer_chain_from_toc(synthetic_toc(self.chain,self.chain)),self.chain)
        changed=list(self.chain);changed[-1]=b'OTHER ROOT'
        with self.assertRaisesRegex(v.ValidationError,'installer_signature_chain_mismatch'):v.installer_chain_from_toc(synthetic_toc(self.chain,changed))
        with self.assertRaisesRegex(v.ValidationError,'installer_chain_set_invalid'):v.installer_chain_from_toc(synthetic_toc(self.chain[:2]))
    def test_toc_external_entity_rejected(self):
        with self.assertRaisesRegex(v.ValidationError,'installer_toc_invalid'):v.installer_chain_from_toc(b'<!DOCTYPE xar [<!ENTITY data SYSTEM "file:///private">]><xar/>')
    def package_reader(self,status='Status: signed by a developer certificate issued by Apple (Development)',fail_trust=False):
        reader=v.Runner(self.root/'private-tools');calls=[]
        def run(args,label,timeout=120):
            calls.append((args,label));reader.sequence+=1
            if label=='pkg-signature':return (status+'\n1. 3rd Party Mac Developer Installer: SYNTHETIC ('+v.TEAM+')\n').encode(),b''
            if label=='installer-toc':pathlib.Path(str(args[1]).split('=',1)[1]).write_bytes(synthetic_toc(self.chain,self.chain))
            if label=='installer-chain-trust' and fail_trust:raise v.ValidationError('platform_validation_command_failed')
            return b'',b''
        reader.run=run;return reader,calls
    def test_observed_wording_never_skips_independent_chain_trust(self):
        reader,calls=self.package_reader();pins=tuple(hashlib.sha256(c).hexdigest() for c in self.chain)
        with unittest.mock.patch.object(v,'INSTALLER_CHAIN_SHA256',pins),unittest.mock.patch.object(v.datetime,'datetime',wraps=datetime.datetime) as dt:
            dt.now.return_value=NOW;result=reader.package(self.root/'synthetic.pkg',self.root/'expanded')
        self.assertTrue(result['installer_chain_trust_verified'])
        args=next(args for args,label in calls if label=='installer-chain-trust')
        self.assertEqual(args.count('-c'),3);self.assertIn('-r',args);self.assertEqual(args[-5:],['-p','basic','-L','-R','offline'])
        self.assertEqual(calls[-1][1],'pkg-expand')
    def test_trust_failure_does_not_expand_or_approve_package(self):
        reader,calls=self.package_reader(fail_trust=True);pins=tuple(hashlib.sha256(c).hexdigest() for c in self.chain)
        with unittest.mock.patch.object(v,'INSTALLER_CHAIN_SHA256',pins),unittest.mock.patch.object(v.datetime,'datetime',wraps=datetime.datetime) as dt:
            dt.now.return_value=NOW
            with self.assertRaisesRegex(v.ValidationError,'platform_validation_command_failed'):reader.package(self.root/'synthetic.pkg',self.root/'expanded')
        self.assertNotIn('pkg-expand',[label for args,label in calls])
    def test_untrusted_unsigned_or_ambiguous_status_rejected(self):
        for status in ['Status: no signature','Status: signed by an untrusted certificate','Status: signed by a developer certificate issued by Apple (Development)\nStatus: no signature']:
            reader,calls=self.package_reader(status)
            with self.subTest(status=status),self.assertRaisesRegex(v.ValidationError,'installer_signature_untrusted'):reader.package(self.root/'synthetic.pkg',self.root/'expanded')
            self.assertEqual(len(calls),1)

if __name__=='__main__':unittest.main(verbosity=2)
