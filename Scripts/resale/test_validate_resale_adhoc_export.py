"""Synthetic ad-hoc export fixtures; no real signing/profile/device/account calls."""
import copy
import datetime
import hashlib
import json
import pathlib
import plistlib
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import validate_resale_export as base
import validate_resale_adhoc_export as adhoc
import test_resale_export_validation as fixture


class AdhocExportGuards(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
        self.cert=b'SYNTHETIC ADHOC LEAF; NOT A CERTIFICATE'
        self.cert_hash=hashlib.sha256(self.cert).hexdigest()
        self.expected={}
        self.scope=copy.deepcopy(fixture.SCOPE);self.scope['source_sha']=adhoc.SOURCE
        self.scope['adhoc_native_profiles']=[]
        self.profile_values={}
        for i,(identifier,(native,name,_)) in enumerate(adhoc.EXPECTED.items()):
            raw=('SYNTHETIC CMS '+identifier).encode();sha=hashlib.sha256(raw).hexdigest()
            uuid=f'00000000-0000-0000-0000-{i+1:012d}'
            self.expected[identifier]=(native,name,sha)
            self.scope['adhoc_native_profiles'].append({'bundle_id':identifier,'native_profile_id':native,
                'name':name,'sha256':sha,'uuid':uuid,'profile_type':'IOS_APP_ADHOC',
                'owner_private_phone_membership_verified_by_exact_cms_hash':True})
            self.profile_values[identifier]={'Name':name,'UUID':uuid,'TeamIdentifier':[base.TEAM],
                'ApplicationIdentifierPrefix':[base.TEAM],
                'CreationDate':fixture.NOW-datetime.timedelta(hours=1),
                'ExpirationDate':fixture.NOW+datetime.timedelta(days=30),
                'Entitlements':{'application-identifier':base.TEAM+'.'+identifier,
                    'com.apple.developer.team-identifier':base.TEAM,
                    'com.apple.security.application-groups':[base.GROUP],'get-task-allow':False},
                'ProvisionedDevices':['synthetic-phone-do-not-report'],
                'DeveloperCertificates':[self.cert]}
        self.fixture_case=fixture.Validation();self.fixture_case.root=self.root;self.fixture_case.reader=fixture.SyntheticReader()
        self.archive,self.exports,self.paths=self.fixture_case.fixtures('ios')
        for identifier,path in self.paths.items():
            (path/'embedded.mobileprovision').write_bytes(('SYNTHETIC CMS '+identifier).encode())
        self.repack()
        owner=self
        class Reader(fixture.SyntheticReader):
            def __init__(self):super().__init__();self.leaf=owner.cert;self.profile_changes={}
            def profile(self,path):
                identifier=base.load_plist(path.parent/'Info.plist')['CFBundleIdentifier']
                value=copy.deepcopy(owner.profile_values[identifier])
                value.update(self.profile_changes.get(identifier,{}))
                return value
        self.reader=Reader()
        self.expected_patch=patch.object(adhoc,'EXPECTED',self.expected);self.expected_patch.start()
        self.cert_patch=patch.object(adhoc,'CERT',self.cert_hash);self.cert_patch.start()
    def tearDown(self):
        self.expected_patch.stop();self.cert_patch.stop();self.temp.cleanup()
    def repack(self):
        for p in self.exports.glob('*.ipa'):p.unlink()
        primary=self.paths[base.BASE]
        with zipfile.ZipFile(self.exports/'ResaleBurrow-Bryan.ipa','w') as z:
            for p in primary.rglob('*'):
                if p.is_file():z.write(p,'Payload/'+primary.name+'/'+p.relative_to(primary).as_posix())
    def validate(self):return adhoc.validate(self.exports,self.scope,self.root/'report.json',self.reader,fixture.NOW)
    def test_exact_four_export_bundles_pass_without_hardware_data_in_report(self):
        value=self.validate();self.assertEqual(value['status'],'passed');self.assertEqual(value['exact_bundle_count'],4)
        self.assertFalse(value['archive_checked_here']);self.assertFalse(value['uploaded']);self.assertFalse(value['installed'])
        self.assertFalse(value['watch_hardware_eligibility_verified'])
        self.assertNotIn('synthetic-phone',json.dumps(value))
        self.assertEqual((self.root/'report.json').stat().st_mode&0o777,0o600)
    def test_store_default_still_rejects_adhoc_profiles(self):
        value=base.validate('ios',self.archive,self.exports,self.scope,self.root/'store-report.json',self.reader,fixture.NOW)
        self.assertEqual(value['error_code'],'profile_not_app_store_distribution')
    def test_scope_exact_native_name_hash_uuid_release_required(self):
        for key,value in [('native_profile_id','OTHER'),('name','other'),('sha256','a'*64),
                          ('uuid','unknown'),('profile_type','IOS_APP_STORE')]:
            scope=copy.deepcopy(self.scope);scope['adhoc_native_profiles'][0][key]=value
            with self.subTest(key=key),self.assertRaises(base.ValidationError):adhoc.scope_check(scope)
    def test_private_device_fields_are_not_accepted_in_public_scope(self):
        self.scope['adhoc_native_profiles'][0]['hardware_identifier']='synthetic-phone-do-not-report'
        value=self.validate();self.assertEqual(value['error_code'],'adhoc_profile_scope_has_unexpected_private_fields')
        self.assertNotIn('synthetic-phone',json.dumps(value))
    def test_private_phone_membership_attestation_missing_or_false_is_not_ready(self):
        for value in [None,False]:
            scope=copy.deepcopy(self.scope)
            scope['adhoc_native_profiles'][0]['owner_private_phone_membership_verified_by_exact_cms_hash']=value
            with self.subTest(value=value),self.assertRaises(base.ValidationError):adhoc.scope_check(scope)
    def test_other_source_and_duplicate_uuid_rejected(self):
        scope=copy.deepcopy(self.scope);scope['source_sha']='a'*40
        with self.assertRaises(base.ValidationError):adhoc.scope_check(scope)
        scope=copy.deepcopy(self.scope);scope['adhoc_native_profiles'][1]['uuid']=scope['adhoc_native_profiles'][0]['uuid']
        with self.assertRaises(base.ValidationError):adhoc.scope_check(scope)
    def test_other_embedded_cms_bytes_rejected_before_decoded_claims(self):
        (self.paths[base.BASE]/'embedded.mobileprovision').write_bytes(b'different signed profile')
        self.repack();self.assertEqual(self.validate()['error_code'],'adhoc_embedded_cms_bytes_mismatch')
    def test_other_name_uuid_or_team_rejected(self):
        for key,value in [('Name','other'),('UUID','00000000-0000-0000-0000-000000000099'),('TeamIdentifier',['OTHER'])]:
            self.reader.profile_changes={base.BASE:{key:value}}
            with self.subTest(key=key):self.assertEqual(self.validate()['status'],'failed')
    def test_store_enterprise_development_or_extra_phone_profile_rejected(self):
        for key,value in [('ProvisionedDevices',None),('ProvisionsAllDevices',True),
                          ('ProvisionedDevices',['synthetic-phone-do-not-report','other-phone'])]:
            self.reader.profile_changes={base.BASE:{key:value}}
            with self.subTest(key=key):self.assertEqual(self.validate()['status'],'failed')
        ent=copy.deepcopy(self.profile_values[base.BASE]['Entitlements']);ent['get-task-allow']=True
        self.reader.profile_changes={base.BASE:{'Entitlements':ent}}
        self.assertEqual(self.validate()['error_code'],'adhoc_release_profile_required')
    def test_unequal_single_selected_phone_across_embedded_profiles_rejected_privately(self):
        self.reader.profile_changes={base.BASE+'.watch':{'ProvisionedDevices':['different-synthetic-phone']}}
        value=self.validate();self.assertEqual(value['error_code'],'adhoc_profiles_selected_phone_mismatch')
        self.assertNotIn('synthetic-phone',json.dumps(value))
    def test_profile_expired_future_created_or_beyond_approved_certificate_rejected(self):
        for key,value in [('ExpirationDate',fixture.NOW-datetime.timedelta(seconds=1)),
                          ('CreationDate',fixture.NOW+datetime.timedelta(seconds=1)),
                          ('ExpirationDate',adhoc.CERT_EXPIRES+datetime.timedelta(seconds=1))]:
            self.reader.profile_changes={base.BASE:{key:value}}
            with self.subTest(key=key):self.assertEqual(self.validate()['status'],'failed')
    def test_same_team_but_other_leaf_certificate_rejected(self):
        self.reader.leaf=b'ANOTHER SAME-TEAM SYNTHETIC LEAF'
        self.assertEqual(self.validate()['error_code'],'adhoc_approved_distribution_leaf_mismatch')
    def test_extra_certificate_or_profile_literal_group_mismatch_rejected(self):
        self.reader.profile_changes={base.BASE:{'DeveloperCertificates':[self.cert,b'other']}}
        self.assertEqual(self.validate()['error_code'],'adhoc_profile_certificate_binding_mismatch')
        ent=copy.deepcopy(self.profile_values[base.BASE]['Entitlements']);ent['com.apple.security.application-groups']=[base.GROUP,base.TEAM+'.*']
        self.reader.profile_changes={base.BASE:{'Entitlements':ent}}
        self.assertEqual(self.validate()['error_code'],'adhoc_profile_literal_group_mismatch')
    def test_signed_binary_literal_group_debug_minimum_and_privacy_remain_enforced(self):
        self.reader.entitlement_override={'com.apple.security.application-groups':[base.GROUP,base.TEAM+'.*']}
        self.assertEqual(self.validate()['error_code'],'signature_app_group_mismatch')
        self.reader.entitlement_override={'get-task-allow':True}
        self.assertEqual(self.validate()['error_code'],'signature_development_enabled')
        self.reader.entitlement_override={}
        info=self.paths[base.BASE]/'Info.plist';value=base.load_plist(info);value['MinimumOSVersion']='16.0';fixture.write_plist(info,value)
        self.repack();self.assertEqual(self.validate()['error_code'],'bundle_minimum_os_mismatch')
    def test_missing_widget_privacy_manifest_fails(self):
        (self.paths[base.BASE+'.widgets']/'PrivacyInfo.xcprivacy').unlink();self.repack()
        self.assertEqual(self.validate()['error_code'],'privacy_manifest_missing')
    def test_unexpected_or_missing_bundle_and_watch_relation_fail(self):
        shutil.rmtree(self.paths[base.BASE+'.watch.widgets']);self.repack()
        self.assertEqual(self.validate()['error_code'],'bundle_set_incomplete')
    def test_wrong_watch_companion_fails(self):
        info=self.paths[base.BASE+'.watch']/'Info.plist';v=base.load_plist(info);v['WKCompanionAppBundleIdentifier']='wrong.app';fixture.write_plist(info,v);self.repack()
        self.assertEqual(self.validate()['error_code'],'watch_companion_relationship_invalid')
    def test_extra_export_ipa_fails(self):
        (self.exports/'extra.ipa').write_bytes(b'fixture')
        self.assertEqual(self.validate()['error_code'],'adhoc_exact_one_export_ipa_required')
    def test_optional_fresh_adhoc_archive_is_independently_validated(self):
        result=adhoc.validate(self.exports,self.scope,self.root/'report.json',self.reader,fixture.NOW,archive=self.archive)
        self.assertEqual(result['status'],'passed');self.assertTrue(result['archive_checked_here'])
        self.assertEqual(len(result['archive_bundles']),4);self.assertEqual(len(result['export_bundles']),4)
        self.assertNotIn('synthetic-phone',json.dumps(result))
    def test_optional_archive_extra_products_and_wrong_primary_fail_at_archive_stage(self):
        (self.archive/'Products/usr/local').mkdir(parents=True)
        result=adhoc.validate(self.exports,self.scope,self.root/'report.json',self.reader,fixture.NOW,archive=self.archive)
        self.assertEqual(result['failed_stage'],'archive')
        self.assertEqual(result['error_code'],'adhoc_archive_not_single_top_level_app')
        shutil.rmtree(self.archive/'Products/usr')
        p=self.archive/'Info.plist';v=base.load_plist(p);v['ApplicationProperties']['CFBundleIdentifier']='another.app';fixture.write_plist(p,v)
        result=adhoc.validate(self.exports,self.scope,self.root/'report.json',self.reader,fixture.NOW,archive=self.archive)
        self.assertEqual(result['failed_stage'],'archive')
        self.assertEqual(result['error_code'],'adhoc_archive_primary_identifier_mismatch')
    def test_zip_duplicate_traversal_and_symlink_rejected(self):
        for mode,name in [('duplicate','same'),('traversal','../../private'),('symlink','link')]:
            p=self.root/(mode+'.ipa')
            with zipfile.ZipFile(p,'w') as z:
                if mode=='symlink':
                    row=zipfile.ZipInfo(name);row.external_attr=(0o120777<<16);z.writestr(row,'target')
                else:
                    z.writestr(name,'fixture')
                    if mode=='duplicate':
                        import warnings
                        with warnings.catch_warnings():warnings.simplefilter('ignore');z.writestr(name,'other')
            with self.subTest(mode=mode),self.assertRaises(base.ValidationError):adhoc.zip_preflight(p)


if __name__=='__main__':unittest.main(verbosity=2)
