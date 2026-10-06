"""Synthetic metadata/privacy guards. No portal, phone or actual CMS inputs."""
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import validate_adhoc_profiles as v

NOW=datetime(2026,10,6,10,tzinfo=timezone.utc)
CERT=b'synthetic-existing-certificate'
DEVICE='synthetic-private-phone'

def profile(ident=v.BASE):
    return {'Name':v.EXPECTED[ident][1],'UUID':'12345678-1234-1234-1234-123456789abc',
     'TeamIdentifier':[v.TEAM],'ApplicationIdentifierPrefix':[v.TEAM],
     'Entitlements':{'application-identifier':v.TEAM+'.'+ident,'com.apple.developer.team-identifier':v.TEAM,
       'com.apple.security.application-groups':[v.GROUP],'get-task-allow':False},
     'CreationDate':NOW-timedelta(hours=1),'ExpirationDate':NOW+timedelta(days=90),
     'ProvisionedDevices':[DEVICE],'DeveloperCertificates':[CERT]}

def manifest():
    return {'complete':True,'authenticated_exact_profile_get':True,'team':v.TEAM,'group':v.GROUP,
      'source_sha':'a'*40,'delivery_sha':'b'*40,'profiles':[
      {'bundle_id':i,'native_profile_id':r[0],'name':r[1],'path':'profiles/'+r[0]+'.mobileprovision','sha256':'c'*64}
      for i,r in v.EXPECTED.items()]}

class Guards(unittest.TestCase):
    def setUp(self): self.pin=patch.object(v,'CERT_SHA',hashlib.sha256(CERT).hexdigest()); self.pin.start()
    def tearDown(self): self.pin.stop()

    def test_exact_four_manifest(self):
        self.assertEqual(len(v.validate_manifest(manifest(),'a'*40,'b'*40)),4)

    def test_native_ids_and_names_are_pinned(self):
        for key,value in [('native_profile_id','OTHER'),('name','Unrelated app')]:
            m=manifest();m['profiles'][0][key]=value
            with self.subTest(key=key),self.assertRaises(v.Invalid):v.validate_manifest(m,'a'*40,'b'*40)

    def test_authentication_provenance_and_complete_required(self):
        for key,value in [('authenticated_exact_profile_get',False),('complete',False),('source_sha','d'*40),('delivery_sha','e'*40)]:
            m=manifest();m[key]=value
            with self.subTest(key=key),self.assertRaises(v.Invalid):v.validate_manifest(m,'a'*40,'b'*40)

    def test_duplicates_and_extra_bundle_rejected(self):
        m=manifest();m['profiles'][1]=copy.deepcopy(m['profiles'][0])
        with self.assertRaises(v.Invalid):v.validate_manifest(m,'a'*40,'b'*40)
        m=manifest();m['profiles'].append(copy.deepcopy(m['profiles'][0]))
        with self.assertRaises(v.Invalid):v.validate_manifest(m,'a'*40,'b'*40)

    def test_all_four_private_membership_without_watch_claim(self):
        for ident in v.EXPECTED:
            r=v.validate_profile(profile(ident),ident,device=DEVICE,now=NOW)
            self.assertTrue(r['private_phone_membership_verified']);self.assertFalse(r['watch_hardware_eligibility_verified'])
            self.assertNotIn(DEVICE,json.dumps(r))

    def test_no_membership_inference_when_record_omitted(self):
        self.assertFalse(v.validate_profile(profile(),v.BASE,now=NOW)['private_phone_membership_verified'])

    def test_wrong_team_app_group_rejected(self):
        for key,value in [('application-identifier',v.TEAM+'.wrong'),('com.apple.developer.team-identifier','OTHERTEAM'),('com.apple.security.application-groups',[v.GROUP,'other'])]:
            p=profile();p['Entitlements'][key]=value
            with self.subTest(key=key),self.assertRaises(v.Invalid):v.validate_profile(p,v.BASE,device=DEVICE,now=NOW)

    def test_not_store_enterprise_or_debug(self):
        for mode in ('store','enterprise','debug'):
            p=profile()
            if mode=='store':p.pop('ProvisionedDevices')
            elif mode=='enterprise':p['ProvisionsAllDevices']=True
            else:p['Entitlements']['get-task-allow']=True
            with self.subTest(mode=mode),self.assertRaises(v.Invalid):v.validate_profile(p,v.BASE,now=NOW)

    def test_only_single_exact_phone_no_watch_substitution(self):
        for devices in ([],[DEVICE,'synthetic-watch'],['other-phone'],['synthetic-watch']):
            p=profile();p['ProvisionedDevices']=devices
            with self.subTest(count=len(devices)),self.assertRaises(v.Invalid):v.validate_profile(p,v.BASE,device=DEVICE,now=NOW)

    def test_certificate_pin_and_one_certificate(self):
        for certs in ([b'wrong'],[CERT,b'extra'],[]):
            p=profile();p['DeveloperCertificates']=certs
            with self.subTest(count=len(certs)),self.assertRaises(v.Invalid):v.validate_profile(p,v.BASE,now=NOW)

    def test_dates_current_creation_and_cert_expiry_bounds(self):
        for key,value in [('CreationDate',NOW+timedelta(minutes=6)),('CreationDate',NOW-timedelta(days=2)),('ExpirationDate',NOW-timedelta(seconds=1)),('ExpirationDate',datetime(2028,1,1,tzinfo=timezone.utc))]:
            p=profile();p[key]=value
            with self.subTest(key=key),self.assertRaises(v.Invalid):v.validate_profile(p,v.BASE,now=NOW)

    def test_no_raw_device_error_text(self):
        with self.assertRaises(v.Invalid) as ctx:v.validate_profile(profile(),v.BASE,device='different-secret',now=NOW)
        self.assertNotIn(DEVICE,str(ctx.exception));self.assertNotIn('different-secret',str(ctx.exception))

    def test_private_file_and_symlink_guard(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'record';p.write_text('synthetic');p.chmod(0o600)
            self.assertEqual(v.private_read(p),b'synthetic')
            p.chmod(0o644)
            with self.assertRaises(v.Invalid):v.private_read(p)
            p.chmod(0o600);alias=Path(d)/'alias';alias.symlink_to(p)
            with self.assertRaises(v.Invalid):v.private_read(alias)

    def test_only_portable_exact_relative_paths(self):
        for path in ('/tmp/profiles/DMWQ2F9XCQ.mobileprovision','../profiles/DMWQ2F9XCQ.mobileprovision','profiles/OTHER.mobileprovision','profiles\\DMWQ2F9XCQ.mobileprovision'):
            m=manifest();m['profiles'][0]['path']=path
            with self.subTest(path=path),self.assertRaises(v.Invalid):v.validate_manifest(m,'a'*40,'b'*40)

    def test_profile_relative_resolution_and_symlink_parent(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);m=root/'manifest.json';m.write_text('{}');folder=root/'profiles';folder.mkdir()
            row=manifest()['profiles'][0];p=folder/'DMWQ2F9XCQ.mobileprovision';p.write_bytes(b'synthetic')
            self.assertEqual(v.resolved_profile_path(m,row),p.resolve())
            p.unlink();folder.rmdir();folder.symlink_to(root)
            with self.assertRaises(v.Invalid):v.resolved_profile_path(m,row)

if __name__=='__main__':unittest.main()
