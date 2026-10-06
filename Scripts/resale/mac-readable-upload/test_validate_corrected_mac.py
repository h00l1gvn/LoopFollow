import copy,json,pathlib,unittest
from unittest.mock import patch
import validate_corrected_mac as v
class Guards(unittest.TestCase):
    def setUp(self):self.scope=json.loads((pathlib.Path(__file__).parent/'corrected-package-scope.json').read_text())
    def test_only_validation_command(self):
        argv=v.command(pathlib.Path('/private/pkg'),'ABCDE12345','01234567-89ab-cdef-0123-456789abcdef')
        self.assertEqual(argv[:3],['/usr/bin/xcrun','altool','--validate-app']);self.assertNotIn('--upload-app',argv);self.assertEqual(argv[5:7],['-t','macos'])
    def test_key_argument_injection_rejected(self):
        for key in ['x --upload-app','../key','',None]:
            with self.assertRaises(v.Stop):v.command('/pkg',key,'01234567-89ab-cdef-0123-456789abcdef')
    def test_current_cli_help_required(self):
        with self.assertRaises(v.Stop):v.help_gate(b'--upload-app -f file')
        v.help_gate(b'--validate-app --apiKey --apiIssuer --output-format macos')
    def test_owner_gate_rejects_push_unrelated_actor_repo_branch(self):
        env={'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':'h00l1gvn/LoopFollow','GITHUB_ACTOR':'h00l1gvn','GITHUB_REF':'refs/heads/'+v.BRANCH,'GITHUB_SHA':'1'*40}
        v.owner_gate(env)
        for key,value in [('GITHUB_EVENT_NAME','push'),('GITHUB_ACTOR','other'),('GITHUB_REPOSITORY','public/other'),('GITHUB_REF','refs/heads/main'),('GITHUB_SHA','bad')]:
            test=dict(env);test[key]=value
            with self.subTest(key=key),self.assertRaises(v.Stop):v.owner_gate(test)
    def release(self):return {'id':2,'tag_name':self.scope['new_private_release_tag'],'draft':True,'prerelease':True,'target_commitish':self.scope['source_sha'],'assets':[{'name':self.scope['package_name']},{'name':self.scope['manifest_name']}]}
    def test_new_release_required_and_exact_assets(self):
        r=self.release();v.release_check(r,self.scope,2)
        for changes in [{'draft':False},{'tag_name':'resale-burrow-0.1.0-build-1-signed-cache'},{'target_commitish':'0'*40},{'id':3}]:
            bad=copy.deepcopy(r);bad.update(changes)
            with self.subTest(changes=changes),self.assertRaises(v.Stop):v.release_check(bad,self.scope,2)
    def test_prior_validation_intent_or_result_stops(self):
        for name in [v.INTENT,v.RESULT,'unrelated']:
            bad=self.release();bad['assets'].append({'name':name})
            with self.subTest(name=name),self.assertRaises(v.Stop):v.release_check(bad,self.scope,2)
    def test_manifest_exact_scope_not_old_pkg(self):
        row={**self.scope,'private_release_id':2,'package_asset_id':3,'Apple_validation_executed':False,'Apple_upload_executed':False};v.manifest_check(row,self.scope,2,3)
        for key,value in [('package_sha256',self.scope['old_package_sha256']),('package_run_id',37447312021),('Apple_upload_executed',True),('package_asset_id',9),('source_sha','0'*40)]:
            bad=copy.deepcopy(row);bad[key]=value
            with self.subTest(key=key),self.assertRaises(v.Stop):v.manifest_check(bad,self.scope,2,3)
    def test_Apple_GET_scope_no_external_or_unrelated_routes(self):
        class Opener:
            def open(self,*a,**kw):raise AssertionError('network')
        client=v.ASC('secret',Opener())
        for path in ['https://attacker.test/v1/apps/6819601423','/v1/apps/another','/v1/certificates','/v1/builds/unknown/preReleaseVersion','/v1/apps/6819601423?token=x','http://api.appstoreconnect.apple.com/v1/apps/6819601423','https://api.appstoreconnect.apple.com:444/v1/apps/6819601423']:
            with self.subTest(path=path),self.assertRaises(v.Stop):client.get(path)
    def test_GitHub_no_write_or_wrong_repo_route(self):
        client=v.GitHub(self.scope,2)
        for path in ['repos/other/project/releases/2','repos/h00l1gvn/resale-burrow-native/issues','repos/h00l1gvn/resale-burrow-native/releases/404532466']:
            with self.subTest(path=path),self.assertRaises(v.Stop):client.api(path)
    def test_journal_names_only_validation(self):
        with self.assertRaises(v.Stop):v.GitHub(self.scope,2).upload_journal(pathlib.Path('upload-intent-macos-0.1.0-1.json'))
    def fake(self,build=False,upload=False,state='FAILED'):
        class Client:
            builds=set()
            def get(self,p):
                if p.startswith('/v1/builds/'):
                    return {'data':{'type':'preReleaseVersions','attributes':{'platform':'MAC_OS','version':'0.1.0'}}}
                return {'data':{'id':'6819601423','type':'apps','attributes':{'bundleId':'com.julienbell.ResaleBurrow.mac'}}}
            def collection(self,p):
                if '/buildUploads' in p:return [{'type':'buildUploads','id':'u1','attributes':{'platform':'MAC_OS','cfBundleShortVersionString':'0.1.0','cfBundleVersion':'1','state':{'state':state}}}] if upload else []
                return [{'type':'builds','id':'b1','attributes':{'version':'1'}}] if build else []
        return Client()
    def test_fresh_exact_empty_outcome(self):self.assertTrue(v.fresh_collision(self.fake())['complete'])
    def test_existing_build_or_even_failed_upload_collision(self):
        for client in [self.fake(build=True),self.fake(upload=True),self.fake(upload=True,state='PROCESSING')]:
            with self.assertRaises(v.Stop):v.fresh_collision(client)
    def test_unknown_upload_state_stops(self):
        with self.assertRaises(v.Stop):v.fresh_collision(self.fake(upload=True,state=None))
if __name__=='__main__':unittest.main()
