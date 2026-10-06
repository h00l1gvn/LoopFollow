"""Synthetic guards only: no SDK, signing, account, device or network calls."""
import copy,datetime,hashlib,json,os,pathlib,plistlib,subprocess,sys,tempfile,unittest,zipfile
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import export_bryan_build2 as b
NOW=datetime.datetime(2026,10,6,20,tzinfo=datetime.timezone.utc)
CERT=b'synthetic-distribution-cert'

def scope():
    s=json.loads((pathlib.Path(b.__file__).parent.parent/'signing-export-scope.json').read_text())
    s.update(distribution='ad-hoc',delivery_lane='bryan-ad-hoc',profile_material_mode='native-adhoc-get-with-immutable-match-certificates')
    s['adhoc_native_profiles']=[]
    for i,identifier in enumerate(sorted(b.EXACT)):
        raw=('synthetic-cms-'+identifier).encode()
        s['adhoc_native_profiles'].append({'bundle_id':identifier,'native_profile_id':'NEWPIN'+str(i),'name':'Reviewed synthetic '+identifier,
          'uuid':f'{i+1:08x}-1234-1234-1234-123456789abc','sha256':hashlib.sha256(raw).hexdigest(),'profile_type':'IOS_APP_ADHOC',
          'native_readback_verified':True,'owner_private_phone_membership_verified_by_exact_cms_hash':True})
    return s

def profile(pin,phone='PRIVATE-SYNTHETIC-PHONE'):
    identifier=pin['bundle_id'];ent={'application-identifier':b.contract.TEAM+'.'+identifier,
      'com.apple.developer.team-identifier':b.contract.TEAM,'com.apple.security.application-groups':[b.contract.GROUP],'get-task-allow':False}
    if identifier in b.contract.PUSH:ent[b.contract.PUSH[identifier]]='production'
    return {'Name':pin['name'],'UUID':pin['uuid'],'TeamIdentifier':[b.contract.TEAM],'ApplicationIdentifierPrefix':[b.contract.TEAM],
      'Entitlements':ent,'CreationDate':NOW-datetime.timedelta(days=1),'ExpirationDate':NOW+datetime.timedelta(days=100),
      'DeveloperCertificates':[CERT],'ProvisionedDevices':[phone]}

class Guards(unittest.TestCase):
    def test_exact_build2_approved_four_scope(self):
        targets,pins=b.scope_check(scope());self.assertEqual(set(targets),b.EXACT);self.assertEqual(len(pins),4)
    def test_stale_source_or_unapproved_art_is_blocked(self):
        for key,value in [('source_sha',b.contract.OLD_SOURCE),('source_frozen',False),('final_artwork_owner_approved',False),('build','1')]:
            s=scope();s[key]=value
            with self.assertRaises(b.Error):b.scope_check(s)
    def test_store_mode_or_unpinned_profile_is_blocked(self):
        for key,value in [('distribution','app-store'),('delivery_lane','ordinary'),('match_material_commit','0'*40)]:
            s=scope();s[key]=value
            with self.assertRaises(b.Error):b.scope_check(s)
        s=scope();s.pop('adhoc_native_profiles')
        with self.assertRaises(b.Error):b.scope_check(s)
    def test_private_identifiers_are_not_scope_fields(self):
        s=scope();s['adhoc_native_profiles'][0]['device_identifier']='do-not-retain'
        with self.assertRaises(b.Error):b.scope_check(s)
    def test_missing_owner_cms_membership_or_duplicate_uuid_rejected(self):
        s=scope();s['adhoc_native_profiles'][0]['owner_private_phone_membership_verified_by_exact_cms_hash']=False
        with self.assertRaises(b.Error):b.scope_check(s)
        s=scope();s['adhoc_native_profiles'][0]['uuid']=s['adhoc_native_profiles'][1]['uuid']
        with self.assertRaises(b.Error):b.scope_check(s)
    def test_profiles_require_two_production_aps_and_two_nonreceivers(self):
        s=scope();_,pins=b.scope_check(s);checker=b.AdhocProfiles(pins)
        with patch.object(b.contract,'CERT_SHA',hashlib.sha256(CERT).hexdigest()):
            for identifier,pin in pins.items():
                p=profile(pin);r=checker.check_raw(p,{'leaf_der':CERT,'entitlements':p['Entitlements']},identifier,NOW,('synthetic-cms-'+identifier).encode())
                self.assertTrue(r['same_single_selected_phone_verified']);self.assertNotIn('PRIVATE',json.dumps(r))
    def test_old_missing_aps_and_widget_aps_are_rejected(self):
        _,pins=b.scope_check(scope())
        for identifier in [b.PHONE,b.PHONE+'.watch',b.PHONE+'.widgets']:
            pin=pins[identifier];p=profile(pin)
            if identifier in b.contract.PUSH:p['Entitlements'].pop('aps-environment')
            else:p['Entitlements']['aps-environment']='production'
            with patch.object(b.contract,'CERT_SHA',hashlib.sha256(CERT).hexdigest()),self.assertRaises(b.contract.GateError):
                b.AdhocProfiles(pins).check_raw(p,{'leaf_der':CERT,'entitlements':p['Entitlements']},identifier,NOW,('synthetic-cms-'+identifier).encode())
    def test_store_profiles_or_second_phone_not_accepted(self):
        _,pins=b.scope_check(scope());checker=b.AdhocProfiles(pins);ids=list(pins)
        with patch.object(b.contract,'CERT_SHA',hashlib.sha256(CERT).hexdigest()):
            for index,identifier in enumerate(ids[:2]):
                pin=pins[identifier];p=profile(pin,phone='PRIVATE-PHONE-A' if index==0 else 'PRIVATE-PHONE-B')
                if index==0:checker.check_raw(p,{'leaf_der':CERT,'entitlements':p['Entitlements']},identifier,NOW,('synthetic-cms-'+identifier).encode())
                else:
                    with self.assertRaises(b.Error):checker.check_raw(p,{'leaf_der':CERT,'entitlements':p['Entitlements']},identifier,NOW,('synthetic-cms-'+identifier).encode())
            identifier=ids[0];pin=pins[identifier];p=profile(pin);p.pop('ProvisionedDevices')
            with self.assertRaises(b.Error):b.AdhocProfiles(pins).check_raw(p,{'leaf_der':CERT,'entitlements':p['Entitlements']},identifier,NOW,('synthetic-cms-'+identifier).encode())
    def test_changed_cms_cert_group_dates_block(self):
        _,pins=b.scope_check(scope());identifier=b.PHONE;pin=pins[identifier]
        for kind in ['bytes','certificate','group','date','development']:
            p=profile(pin);raw=('synthetic-cms-'+identifier).encode();leaf=CERT
            if kind=='bytes':raw+=b'changed'
            if kind=='certificate':leaf=b'wrong'
            if kind=='group':p['Entitlements']['com.apple.security.application-groups']=['wrong']
            if kind=='date':p['ExpirationDate']=NOW
            if kind=='development':p['Entitlements']['get-task-allow']=True
            with patch.object(b.contract,'CERT_SHA',hashlib.sha256(CERT).hexdigest()),self.assertRaises(b.Error):
                b.AdhocProfiles(pins).check_raw(p,{'leaf_der':leaf,'entitlements':p['Entitlements']},identifier,NOW,raw)
    def fixture_plan(self,root):
        s=scope();material=root/'temp/material';material.mkdir(parents=True);source=root/'workspace/native-source';source.mkdir(parents=True);work=root/'temp/adhoc-work'
        _,pins=b.scope_check(s);certpath=material/'signing_certificate.p12';certpath.write_bytes(b'synthetic-p12');rows=[]
        for identifier,pin in pins.items():
            path=material/(pin['uuid']+'.mobileprovision');path.write_bytes(('synthetic-cms-'+identifier).encode())
            target=next(t for t in s['targets'] if t['bundle_id']==identifier)
            rows.append({**pin,'target':target['target'],'verified':True,'certificate_sha256':b.contract.CERT_SHA,'private_profile_file':str(path)})
        m={'schema':1,'source_sha':b.SOURCE,'family':'ios','distribution':'ad-hoc','team':b.contract.TEAM,'group':b.contract.GROUP,'match_commit':b.MATCH,
          'profiles':rows,'installer_certificate':None,'signing_certificate':{'verified':True,'type':'DISTRIBUTION','sha256':b.contract.CERT_SHA,'sha1':'a'*40,'p12_file':str(certpath),'p12_file_sha256':b.base.digest(certpath)}}
        return s,m,material,source,work
    def test_export_exact_profile_mapping_and_private_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td);s,m,mat,src,work=self.fixture_plan(root)
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','GITHUB_RUN_ATTEMPT':'1','RUNNER_TEMP':str(root/'temp'),'GITHUB_WORKSPACE':str(root/'workspace')}):
                p=b.export_plan(s,m,mat,src,work);self.assertEqual(len(p['mapping']),4)
                with self.assertRaises(b.Error):b.export_plan(s,m,mat,src,mat/'work')
    def test_export_rejects_changed_profile_or_identity_and_rerun(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td);s,m,mat,src,work=self.fixture_plan(root)
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','GITHUB_RUN_ATTEMPT':'1','RUNNER_TEMP':str(root/'temp'),'GITHUB_WORKSPACE':str(root/'workspace')}):
                wrong=copy.deepcopy(m);wrong['profiles'][0]['uuid']='00000000-1234-1234-1234-123456789abc'
                with self.assertRaises(b.Error):b.export_plan(s,wrong,mat,src,work)
                wrong=copy.deepcopy(m);wrong['signing_certificate']['sha256']='0'*64
                with self.assertRaises(b.Error):b.export_plan(s,wrong,mat,src,work)
                with patch.dict(os.environ,{'GITHUB_RUN_ATTEMPT':'2'}),self.assertRaises(b.Error):b.export_plan(s,m,mat,src,work)
    def test_workflow_scope_and_no_upload_or_device_commands(self):
        text=(pathlib.Path(b.__file__).parent/'resale-build2-bryan-protected-export.yml').read_text()
        self.assertIn(b.SOURCE,text);self.assertIn('github.run_attempt == 1',text);self.assertIn('family: [ios]',text)
        self.assertIn('--mode restore',text);self.assertIn('--mode export',text)
        self.assertIn('adhoc-export-work',text);self.assertIn('bryan-signing-export-scope.json',text)
        for forbidden in ['upload_to_testflight','--upload-app','devicectl','idevice','MATCH_FORCE','export_build2_family.py --']:
            self.assertNotIn(forbidden,text)
        self.assertNotIn('xcodegen',b.RUBY_CONFIG)
    def test_embedded_ruby_is_valid_syntax_without_execution(self):
        r=subprocess.run(['ruby','-c'],input=b.RUBY_CONFIG.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.assertEqual(r.returncode,0);self.assertIn(b'Syntax OK',r.stdout)
    def test_ruby_configuration_is_four_only_export_and_preserves_others(self):
        self.assertIn('ResaleSigning.project_preflight(project,plan)',b.RUBY_CONFIG)
        self.assertIn("'method'=>'release-testing'",b.RUBY_CONFIG)
        self.assertIn("'destination'=>'export'",b.RUBY_CONFIG)
        self.assertIn("'uploadSymbols'=>false",b.RUBY_CONFIG)
        self.assertIn("'unselected_targets_changed'",b.RUBY_CONFIG)

if __name__=='__main__':unittest.main()
