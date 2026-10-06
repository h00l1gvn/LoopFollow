import base64,hashlib,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import resale_apple_audit as audit
import resale_scoped_profiles as profiles
import restore_resale_material as restore
import export_resale_family as export
import test_resale_apple_audit as fixtures
SCOPE=json.loads(Path(__file__).with_name('signing-export-scope.json').read_text())
class Guards(unittest.TestCase):
    def direct_scope(self):return json.loads(Path(__file__).with_name('ios-direct-signing-export-scope.json').read_text())
    def test_direct_profile_mode_rejects_other_family_and_identity_drift(self):
        scope=self.direct_scope();selected=[t for t in scope['targets'] if t['family']=='ios'];plan=restore.direct_profile_plan(scope,'ios',selected);self.assertEqual(len(plan),4)
        with self.assertRaises(audit.AuditError):restore.direct_profile_plan(scope,'macos',selected)
        scope['direct_native_profiles'][1]['native_profile_id']=scope['direct_native_profiles'][0]['native_profile_id']
        with self.assertRaises(audit.AuditError):restore.direct_profile_plan(scope,'ios',selected)
    def test_direct_restore_only_downloads_two_immutable_cert_blobs_and_pins_native_id_hash(self):
        scope=self.direct_scope();calls=[];targets=[t for t in scope['targets'] if t['family']=='ios'];reviewed={r['bundle_id']:r for r in scope['direct_native_profiles']};native={str(i):t for i,t in enumerate(targets)}
        key,cert=fixtures.Guards.material()
        class Git:
            def request(self,method,path):
                calls.append((method,path))
                if '/git/commits/' in path:return {'sha':scope['match_material_commit'],'tree':{'sha':'b'*40}}
                if '/git/trees/' in path:return {'tree':[{'path':'certs/distribution/'+profiles.CERT_ID+ext,'mode':'100644','type':'blob','sha':('c' if ext=='.cer' else 'd')*40} for ext in ('.cer','.p12')]+[{'path':'profiles/appstore/unrelated.mobileprovision','mode':'100644','type':'blob','sha':'e'*40}],'truncated':False}
                raise AssertionError('Unexpected Git request')
        class Apple:
            wrong=False
            def collection(self,path):
                calls.append(('GET',path))
                if path.startswith('/v1/bundleIds?'):
                    from urllib.parse import parse_qs,urlparse
                    bundle=parse_qs(urlparse(path).query)['filter[identifier]'][0];i=next(k for k,t in native.items() if t['bundle_id']==bundle);return [{'id':i,'attributes':{'identifier':bundle}}]
                target=native[path.split('/')[3]];r=reviewed[target['bundle_id']]
                return [{'id':'DIFFERENT' if self.wrong else r['native_profile_id'],'attributes':{'name':r['name']}}]
        downloaded=[]
        def decrypt(client,entry,password):downloaded.append(entry['path']);return [b'synthetic']
        def validate(resource,target,der):
            row=dict(reviewed[target['bundle_id']]);row['verified']=True;return row,b'profile fixture'
        apple=Apple()
        with tempfile.TemporaryDirectory() as tmp,patch.object(profiles,'verified_certificate',return_value=b'der'),patch.object(restore,'decrypt_entry',side_effect=decrypt),patch.object(restore,'key_pair',return_value=(key,cert,{'verified':True,'sha256':profiles.CERT_SHA,'sha1':'a'*40})),patch.object(profiles,'validate_profile',side_effect=validate):
            result=restore.restore(Git(),apple,scope,'ios',scope['match_material_commit'],Path(tmp)/'private','synthetic','p'*40)
            self.assertEqual(set(downloaded),{'certs/distribution/'+profiles.CERT_ID+'.cer','certs/distribution/'+profiles.CERT_ID+'.p12'});self.assertEqual(len(result['profiles']),4);self.assertTrue(result['authenticated_exact_profile_get']);self.assertTrue(all(method=='GET' for method,_ in calls))
            apple.wrong=True
            with self.assertRaises(audit.AuditError):restore.restore(Git(),apple,scope,'ios',scope['match_material_commit'],Path(tmp)/'wrong','synthetic','p'*40)
            apple.wrong=False
            with patch.object(profiles,'validate_profile',side_effect=lambda resource,target,der:({**reviewed[target['bundle_id']],'sha256':'0'*64},b'changed')):
                with self.assertRaises(audit.AuditError):restore.restore(Git(),apple,scope,'ios',scope['match_material_commit'],Path(tmp)/'changed','synthetic','p'*40)
    def test_restore_pem_pair_and_real_pkcs12_same_fingerprint(self):
        from cryptography.hazmat.primitives import serialization,hashes
        from cryptography.hazmat.primitives.serialization import pkcs12
        key,cert=fixtures.Guards.material();der=cert.public_bytes(serialization.Encoding.DER);fingerprint=cert.fingerprint(hashes.SHA256()).hex();pem=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
        for raw in (pem,pkcs12.serialize_key_and_certificates(b'synthetic',key,cert,None,serialization.NoEncryption())):
            _,_,info=restore.key_pair([raw],[der],profiles.TEAM,fingerprint);self.assertEqual(info['sha256'],fingerprint)
        with self.assertRaises(audit.AuditError):restore.key_pair([pem],[der],profiles.TEAM,'0'*64)
    def test_blob_exact_git_hash_before_decryption_and_only_get(self):
        encrypted=profiles.encrypt_profile(b'synthetic profile','synthetic-only');sha=hashlib.sha1(b'blob '+str(len(encrypted)).encode()+b'\0'+encrypted).hexdigest();calls=[]
        class Client:
            def request(self,method,path):calls.append((method,path));return {'encoding':'base64','content':base64.b64encode(encrypted).decode()}
        entry={'mode':'100644','type':'blob','sha':sha}
        self.assertEqual(restore.decrypt_entry(Client(),entry,'synthetic-only'),[b'synthetic profile']);self.assertEqual(calls[0][0],'GET')
        entry['sha']='0'*40
        with self.assertRaises(audit.AuditError):restore.decrypt_entry(Client(),entry,'synthetic-only')
    def fixture(self,tmp):
        root=Path(tmp);runner=root/'runner';workspace=root/'workspace';runner.mkdir();workspace.mkdir();material=runner/'material';material.mkdir();source=workspace/'source';source.mkdir();work=runner/'work';work.mkdir();(source/'apple/ResaleBurrow.xcodeproj').mkdir(parents=True)
        rows=[]
        for i,t in enumerate(t for t in SCOPE['targets'] if t['family']=='tvos'):
            raw=b'synthetic profile';path=material/'12345678-1234-1234-1234-123456789ABC.mobileprovision';path.write_bytes(raw)
            rows.append({'bundle_id':t['bundle_id'],'target':t['target'],'uuid':path.stem,'name':profiles.profile_name(t),'profile_type':t['profile_type'],'verified':True,'native_readback_verified':True,'certificate_sha256':profiles.CERT_SHA,'private_profile_file':str(path),'sha256':hashlib.sha256(raw).hexdigest()})
        key=material/'signing_certificate.p12';key.write_bytes(b'synthetic identity');cert={'verified':True,'sha256':profiles.CERT_SHA,'sha1':'a'*40,'type':'DISTRIBUTION','p12_file':str(key),'p12_file_sha256':hashlib.sha256(key.read_bytes()).hexdigest()}
        manifest={'schema':1,'source_sha':export.SOURCE,'family':'tvos','team':profiles.TEAM,'group':profiles.GROUP,'profiles':rows,'signing_certificate':cert,'installer_certificate':None,'match_commit':'a'*40}
        profiles.private_write(material/'restore-manifest.json',manifest);password=runner/'p12-password';password.write_text('x'*48);os.chmod(password,0o600);gemfile=root/'Gemfile';gemfile.write_text('synthetic fixture only');scopefile=root/'scope.json';scopefile.write_text(json.dumps(SCOPE))
        return runner,workspace,material,source,work,manifest,password,gemfile,scopefile
    def test_export_guard_rejects_local_paths_changed_identity_and_missing_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner,workspace,material,source,work,manifest,*_=self.fixture(tmp)
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_TEMP':str(runner),'GITHUB_WORKSPACE':str(workspace)}):
                export.plan(SCOPE,manifest,'tvos',material,source,work)
                with self.assertRaises(audit.AuditError):export.plan(SCOPE,manifest,'tvos',material,source,source/'unsafe')
                key=Path(manifest['signing_certificate']['p12_file']);key.write_bytes(b'tampered identity')
                with self.assertRaises(audit.AuditError):export.plan(SCOPE,manifest,'tvos',material,source,work)
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}):
                with self.assertRaises(audit.AuditError):export.plan(SCOPE,manifest,'tvos',material,source,work)
    def test_failed_archive_restores_search_list_deletes_own_keychain_profiles_no_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner,workspace,material,source,work,manifest,password,gemfile,scopefile=self.fixture(tmp);commands=[];home=Path(tmp)/'home';home.mkdir()
            class FakeRunner:
                def __init__(self,work):self.steps=[]
                def run(self,args,label,**kwargs):
                    commands.append([str(v) for v in args]);self.steps.append({'step':label,'returncode':0})
                    if label=='source-sha':return (export.SOURCE+'\n').encode()
                    if label=='source-clean':return b''
                    if label=='xcode-version':return b'Xcode 26.2\nBuild version synthetic\n'
                    if label=='original-search-list':return b'"/synthetic/login.keychain-db"\n'
                    if label=='archive':raise audit.AuditError('Synthetic archive failure')
                    return b''
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_TEMP':str(runner),'GITHUB_WORKSPACE':str(workspace)}),patch.object(export,'PrivateRunner',FakeRunner),patch.object(Path,'home',return_value=home):
                with self.assertRaises(audit.AuditError) as error:export.build(SCOPE,scopefile,manifest,material,source,work,password,gemfile)
            self.assertEqual(str(error.exception),'Synthetic archive failure')
            self.assertTrue(any(c[:3]==['/usr/bin/security','delete-keychain',str(material.resolve()/'resale-ephemeral.keychain-db')] for c in commands))
            self.assertIn(['/usr/bin/security','list-keychains','-d','user','-s','/synthetic/login.keychain-db'],commands)
            self.assertFalse(list(home.rglob('*.mobileprovision')))
            joined=json.dumps(commands).lower();self.assertNotIn('upload_to_testflight',joined);self.assertNotIn('altool',joined);self.assertNotIn('allowprovisioningupdates',joined)
if __name__=='__main__':unittest.main()
