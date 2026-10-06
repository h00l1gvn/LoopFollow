import copy,json,pathlib,unittest
import read_ios_build3 as m
from datetime import datetime,timezone

def rel(kind,id):return {'data':{'type':kind,'id':id}}
def fixtures(state='VALID'):
    return {
        '/v1/apps/'+m.APP:{'data':{'type':'apps','id':m.APP,'attributes':{'bundleId':m.BUNDLE}}},
        '/v1/builds':{'data':[{'type':'builds','id':'new-build3','attributes':{'version':'3','processingState':state,'expired':False,'expirationDate':'2026-12-31T00:00:00Z','uploadedDate':'2026-10-06T22:26:45Z','usesNonExemptEncryption':False},'relationships':{'app':rel('apps',m.APP),'preReleaseVersion':rel('preReleaseVersions','ios-version')}}],'included':[{'type':'preReleaseVersions','id':'ios-version','attributes':{'version':'0.1.0','platform':'IOS'}}]},
        '/v1/builds/new-build3/buildBetaDetail':{'data':{'type':'buildBetaDetails','id':'detail3','attributes':{'internalBuildState':'READY_FOR_BETA_TESTING'},'relationships':{'build':rel('builds','new-build3')}}},
        '/v1/betaGroups/'+m.GROUP:{'data':{'type':'betaGroups','id':m.GROUP,'attributes':{'isInternalGroup':True,'hasAccessToAllBuilds':False},'relationships':{'app':rel('apps',m.APP)}}},
        '/v1/betaGroups/'+m.GROUP+'/relationships/betaTesters':{'data':[{'type':'betaTesters','id':'private-member-resource','attributes':{'email':'do-not-retain@example.invalid'}}]},
        '/v1/betaGroups/'+m.GROUP+'/relationships/builds':{'data':[{'type':'builds','id':'existing-build2'}]}}
class Fake(m.ReadClient):
    def __init__(self,rows):super().__init__('fake-token');self.rows=rows;self.paths=[]
    def get(self,path):
        self.validate(path);self.request_count+=1;self.paths.append(path);return copy.deepcopy(self.rows[m.urlparse(path).path])
class Reader(unittest.TestCase):
    def test_real_transport_constructs_only_GET_and_frozen_scope_matches(self):
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):return None
            def read(self,n):return json.dumps(fixtures()['/v1/apps/'+m.APP]).encode()
        class Opener:
            def open(self,request,timeout):
                self.method=request.get_method();return Response()
        o=Opener();c=m.ReadClient('synthetic-token',o);c.get(m.route('/v1/apps/'+m.APP,m.APP_QUERY));self.assertEqual(o.method,'GET')
        s=json.loads((pathlib.Path(__file__).resolve().parent/'scope.json').read_text());self.assertEqual((s['source_sha'],s['app_id'],s['build'],s['beta_group_id']),(m.SOURCE,m.APP,m.BUILD,m.GROUP));self.assertTrue(s['GET_only']);self.assertFalse(s['assignment_authorized'])
    def test_exact_valid_build_group_counts_without_private_identifiers(self):
        c=Fake(fixtures());r=m.read(c);self.assertTrue(r['eligible_for_existing_internal_group']);self.assertEqual((r['tester_count'],r['assigned_build_count']),(1,1));self.assertFalse(r['exact_build_assigned']);self.assertNotIn('private-member-resource',json.dumps(r));self.assertNotIn('email',json.dumps(r).replace('emails',''))
    def test_processing_and_unknown_encryption_never_ready(self):
        for change in [{'processingState':'PROCESSING'},{'usesNonExemptEncryption':None},{'usesNonExemptEncryption':True},{'expired':True},{'expirationDate':None}]:
            rows=fixtures();rows['/v1/builds']['data'][0]['attributes'].update(change);self.assertFalse(m.read(Fake(rows))['eligible_for_existing_internal_group'])
    def test_old_build_other_app_and_platform_rejected(self):
        for changed in ['version','app','platform']:
            rows=fixtures()
            if changed=='version':rows['/v1/builds']['data'][0]['attributes']['version']='2'
            if changed=='app':rows['/v1/builds']['data'][0]['relationships']['app']=rel('apps','6819601423')
            if changed=='platform':rows['/v1/builds']['included'][0]['attributes']['platform']='MAC_OS'
            with self.assertRaises(m.Stop):m.read(Fake(rows))
    def test_absence_is_unobserved_no_retry_permission(self):
        rows=fixtures();rows['/v1/builds']={'data':[]};r=m.read(Fake(rows));self.assertFalse(r['build_observed']);self.assertIsNone(r['processing_state']);self.assertFalse(r['eligible_for_existing_internal_group'])
    def test_ambiguous_builds_rejected(self):
        rows=fixtures();rows['/v1/builds']['data']*=2
        with self.assertRaises(m.Stop):m.read(Fake(rows))
    def test_group_cannot_be_unrelated_or_external(self):
        for change in ['app','external']:
            rows=fixtures();g=rows['/v1/betaGroups/'+m.GROUP]['data']
            if change=='app':g['relationships']['app']=rel('apps','wrong-app')
            else:g['attributes']['isInternalGroup']=False
            with self.assertRaises(m.Stop):m.read(Fake(rows))
    def test_scope_rejects_other_apps_unfiltered_builds_names_and_redirects(self):
        c=m.ReadClient('fake')
        for p in ['/v1/apps/6819601423','/v1/builds','/v1/betaTesters','https://evil.invalid/v1/builds',m.route('/v1/builds',{**m.BUILD_QUERY,'filter[version]':'2'}),m.route('/v1/builds/new-build3/buildBetaDetail',m.DETAIL_QUERY)]:
            with self.assertRaises(m.Stop):c.validate(p)
    def test_pagination_scope_escape_rejected(self):
        rows=fixtures();rows['/v1/builds']['links']={'next':m.route('/v1/builds',{**m.BUILD_QUERY,'filter[app]':'wrong'})}
        with self.assertRaises(m.Stop):m.read(Fake(rows))
    def test_known_build_observation_survives_later_detail_failure(self):
        c=Fake(fixtures());c.rows['/v1/builds/new-build3/buildBetaDetail']={'data':None}
        with self.assertRaises(m.Stop):m.read(c)
        self.assertTrue(c.observation['build_observed']);self.assertEqual(c.observation['processing_state'],'VALID');self.assertFalse(c.observation['eligible_for_existing_internal_group'])
    def test_push_reentry_and_other_owner_cannot_execute(self):
        env={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'h00l1gvn/LoopFollow','GITHUB_ACTOR':'h00l1gvn','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':'refs/heads/'+m.BRANCH,'GITHUB_RUN_ATTEMPT':'1'};m.owner_gate(env)
        for bad in [{'GITHUB_EVENT_NAME':'push'},{'GITHUB_RUN_ATTEMPT':'2'},{'GITHUB_ACTOR':'other'}]:
            with self.assertRaises(m.Stop):m.owner_gate({**env,**bad})
    def test_workflow_registration_skip_and_no_assignment_or_upload(self):
        root=pathlib.Path(__file__).resolve().parent;local=root/'resale-build3-ios-processing-read.yml';p=local if local.exists() else root.parents[1]/'.github/workflows/resale-build3-ios-processing-read.yml';t=p.read_text();self.assertIn("github.event_name == 'workflow_dispatch'",t);self.assertIn('--execute-read-only',t);self.assertNotIn('altool',t);self.assertNotIn('MATCH_PASSWORD',t);self.assertNotIn('GH_PAT',t)
if __name__=='__main__':unittest.main()
