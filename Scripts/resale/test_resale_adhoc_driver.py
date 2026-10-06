import copy,hashlib,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import resale_apple_audit as audit
import resale_scoped_profiles as profiles
import restore_resale_adhoc_material as restore
import export_resale_adhoc as export
import test_resale_apple_audit as fixtures
SCOPE=json.loads(Path(__file__).with_name('bryan-direct-signing-export-scope.json').read_text())
class Guards(unittest.TestCase):
    def test_plan_exact_source_profile_type_and_immutable_certificate_tree(self):
        self.assertEqual(len(restore.plan(SCOPE,restore.MATCH)),4)
        for key,value in [('match_material_commit','a'*40),('source_sha','b'*40),('profile_material_mode','immutable-match')]:
            x=copy.deepcopy(SCOPE);x[key]=value
            with self.assertRaises((audit.AuditError,export.adhoc.Error)):restore.plan(x,restore.MATCH)
        x=copy.deepcopy(SCOPE);x['adhoc_native_profiles'][0]['sha256']='0'*64
        with self.assertRaises(export.adhoc.Error):restore.plan(x,restore.MATCH)
    def test_restore_only_get_two_existing_certificate_blobs_then_four_pinned_profiles(self):
        key,cert=fixtures.Guards.material();downloads=[];calls=[]
        class Git:
            def request(self,method,path):
                calls.append((method,path))
                if '/git/commits/' in path:return {'sha':restore.MATCH,'tree':{'sha':'b'*40}}
                if '/git/trees/' in path:return {'truncated':False,'tree':[{'path':'certs/distribution/'+profiles.CERT_ID+ext,'mode':'100644','type':'blob','sha':str(i)*40} for i,ext in [(1,'.cer'),(2,'.p12')]]+[{'path':'profiles/unrelated.mobileprovision','type':'blob','sha':'c'*40}]}
                raise AssertionError('Unexpected request')
        def retrieve(client,output,delivery,pins):
            output.mkdir(mode=0o700);(output/'profiles').mkdir();rows=[]
            for pin in pins:
                path=output/'profiles'/(pin['native_profile_id']+'.mobileprovision');path.write_bytes(b'synthetic')
                rows.append({**pin,'path':str(path.relative_to(output)),'profile_type':'IOS_APP_ADHOC','certificate_sha256':profiles.CERT_SHA,'native_readback_verified':True})
            return {'profiles':rows}
        def decrypt(client,row,password):downloads.append(row['path']);return [b'fixture']
        with tempfile.TemporaryDirectory() as t,patch.object(profiles,'verified_certificate',return_value=b'der'),patch.object(restore.material,'decrypt_entry',side_effect=decrypt),patch.object(restore.material,'key_pair',return_value=(key,cert,{'verified':True,'sha256':profiles.CERT_SHA,'sha1':'a'*40})),patch.object(restore.native,'retrieve',side_effect=retrieve):
            r=restore.restore(Git(),object(),SCOPE,restore.MATCH,Path(t)/'private','synthetic','p'*48,'d'*40)
            self.assertEqual(r['distribution'],'ad-hoc');self.assertEqual(len(r['profiles']),4);self.assertTrue(all(m=='GET' for m,_ in calls));self.assertEqual(set(downloads),{'certs/distribution/'+profiles.CERT_ID+'.p12','certs/distribution/'+profiles.CERT_ID+'.cer'});self.assertFalse(r['network_mutations']);self.assertFalse(r['watch_hardware_eligibility_verified'])
    def fixture(self,root):
        runner=root/'runner';runner.mkdir();workspace=root/'workspace';workspace.mkdir();material=runner/'material';material.mkdir();source=workspace/'source';source.mkdir();work=runner/'work';work.mkdir();(source/'apple/ResaleBurrow.xcodeproj').mkdir(parents=True)
        rows=[]
        for pin in SCOPE['adhoc_native_profiles']:
            path=material/(pin['native_profile_id']+'.mobileprovision');path.write_bytes(b'synthetic');rows.append({**pin,'profile_type':'IOS_APP_ADHOC','sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'verified':True,'native_readback_verified':True,'certificate_sha256':profiles.CERT_SHA,'private_profile_file':str(path)})
        scope=copy.deepcopy(SCOPE)
        # Synthetic path hashes substitute only with scope checker mocked; production pins never change.
        key=material/'key.p12';key.write_bytes(b'fixture');manifest={'source_sha':export.SOURCE,'family':'ios','distribution':'ad-hoc','team':profiles.TEAM,'group':profiles.GROUP,'match_commit':restore.MATCH,'profiles':rows,'signing_certificate':{'verified':True,'sha256':profiles.CERT_SHA,'p12_file':str(key),'p12_file_sha256':hashlib.sha256(key.read_bytes()).hexdigest()}}
        pins={p['bundle_id']:p for p in rows};return runner,workspace,material,source,work,manifest,pins
    def test_driver_rejects_store_mode_or_mac_family_and_changed_profile(self):
        with tempfile.TemporaryDirectory() as t:
            runner,workspace,material,source,work,m,pins=self.fixture(Path(t))
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_TEMP':str(runner),'GITHUB_WORKSPACE':str(workspace)}),patch.object(export.adhoc,'scope_check',return_value=([],pins)):
                export.plan(SCOPE,m,'ios',material,source,work)
                bad=copy.deepcopy(m);bad['distribution']='app-store'
                with self.assertRaises(audit.AuditError):export.plan(SCOPE,bad,'ios',material,source,work)
                bad=copy.deepcopy(m);bad['profiles'][0]['native_profile_id']='OTHER'
                with self.assertRaises(audit.AuditError):export.plan(SCOPE,bad,'ios',material,source,work)
                with self.assertRaises(audit.AuditError):export.plan(SCOPE,m,'macos',material,source,work)
    def test_commands_bound_distribution_validator_cleanup_and_no_upload(self):
        text=Path(export.__file__).read_text();self.assertIn("'--distribution','ad-hoc'",text);self.assertIn("scripts/'validate_resale_adhoc_export.py','--archive'",text);self.assertIn("export/'ResaleBurrow-Bryan.ipa'",text);self.assertNotIn('allowProvisioningUpdates',text);self.assertNotIn('upload_to_testflight',text)
        with tempfile.TemporaryDirectory() as t:
            runner,workspace,material,source,work,m,pins=self.fixture(Path(t));password=runner/'password';password.write_text('p'*48);os.chmod(password,0o600);gem=Path(t)/'Gemfile';gem.write_text('fixture');scopefile=Path(t)/'scope.json';scopefile.write_text(json.dumps(SCOPE));home=Path(t)/'home';home.mkdir();commands=[]
            class Fake:
                def __init__(self,work):self.steps=[]
                def run(self,args,label,**kwargs):
                    commands.append([str(v) for v in args]);self.steps.append({'step':label,'returncode':0})
                    if label=='source-sha':return (export.SOURCE+'\n').encode()
                    if label=='source-clean':return b''
                    if label=='xcode-version':return b'Xcode 26.2\n'
                    if label=='original-search-list':return b'"/fixture/login.keychain"'
                    if label=='archive':raise audit.AuditError('fixture failure')
                    return b''
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_TEMP':str(runner),'GITHUB_WORKSPACE':str(workspace)}),patch.object(export.adhoc,'scope_check',return_value=([],pins)),patch.object(export,'PrivateRunner',Fake),patch.object(Path,'home',return_value=home):
                with self.assertRaises(audit.AuditError):export.build(SCOPE,scopefile,m,material,source,work,password,gem)
            self.assertTrue(any('delete-keychain' in c for c in commands));self.assertTrue(any(c[:5]==['/usr/bin/security','list-keychains','-d','user','-s'] and c[-1]=='/fixture/login.keychain' for c in commands));self.assertFalse(list(home.rglob('*.mobileprovision')))
if __name__=='__main__':unittest.main()
