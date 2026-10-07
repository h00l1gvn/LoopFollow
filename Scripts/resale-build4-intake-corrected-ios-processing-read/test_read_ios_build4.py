import copy,json,pathlib,subprocess,sys,tempfile,unittest
from urllib.parse import urlparse
import read_ios_build4 as m

FAKE_BUILD='44444444-4444-4444-4444-444444444444'
def rel(kind,identity):return {'data':{'type':kind,'id':identity}}
def fixtures():
    app={'type':'apps','id':m.APP,'attributes':{'bundleId':m.BUNDLE}}
    return {
      '/v1/apps/'+m.APP:{'data':app},
      '/v1/builds':{'data':[{'type':'builds','id':FAKE_BUILD,'attributes':{'version':'4','processingState':'VALID','expired':False,'expirationDate':'2027-01-01T00:00:00Z','uploadedDate':'2026-10-07T05:00:00Z','usesNonExemptEncryption':False},'relationships':{'app':rel('apps',m.APP),'preReleaseVersion':rel('preReleaseVersions','pre4')}}],'included':[app,{'type':'preReleaseVersions','id':'pre4','attributes':{'version':'0.1.0','platform':'IOS'}}]},
      '/v1/builds/'+FAKE_BUILD+'/buildBetaDetail':{'data':{'type':'buildBetaDetails','id':'opaque/detail=id:never-in-a-path','attributes':{'internalBuildState':'READY_FOR_BETA_TESTING'},'relationships':{'build':{'data':None}}}},
      '/v1/betaGroups/'+m.GROUP:{'data':{'type':'betaGroups','id':m.GROUP,'attributes':{'isInternalGroup':True,'hasAccessToAllBuilds':False},'relationships':{'app':{'data':None}}}},
      '/v1/betaGroups/'+m.GROUP+'/app':{'data':copy.deepcopy(app)},
      '/v1/betaGroups/'+m.GROUP+'/relationships/betaTesters':{'data':[{'type':'betaTesters','id':'private-existing-tester','attributes':{'email':'never-retain@example.invalid'}}]},
      '/v1/betaGroups/'+m.GROUP+'/relationships/builds':{'data':[{'type':'builds','id':'old-build1'},{'type':'builds','id':'old-build2'},{'type':'builds','id':'old-build3'}]}}
class Fake(m.ReadClient):
    def __init__(self,rows=None):super().__init__('synthetic-token');self.rows=rows or fixtures();self.paths=[]
    def get(self,path):self.validate(path);self.request_count+=1;self.paths.append(path);return copy.deepcopy(self.rows[urlparse(path).path])
class Build4Read(unittest.TestCase):
    def test_discovery_uses_corrected_parent_binding_and_group_fallback(self):
        c=Fake();r=m.read(c);self.assertEqual(r['build_id'],FAKE_BUILD);self.assertTrue(r['eligible_for_existing_internal_group']);self.assertEqual(r['detail_binding_basis'],'exact_owned_parent_endpoint');self.assertEqual(r['group_app_binding_basis'],'exact_group_app_endpoint');self.assertEqual((r['tester_count'],r['assigned_build_count']),(1,3));self.assertFalse(r['exact_build_assigned']);self.assertEqual(r['account_mutations'],0)
        for private in ['private-existing-tester','never-retain','opaque/detail'] :self.assertNotIn(private,json.dumps(r))
        self.assertTrue(all('opaque' not in path for path in c.paths));self.assertFalse(hasattr(c,'add_exact_build_once'))
    def test_missing_build_is_not_a_failed_upload_or_assignment_permission(self):
        c=Fake();c.rows['/v1/builds']['data']=[];r=m.read(c);self.assertEqual(r['status'],'complete_read_only');self.assertIsNone(r['build_id']);self.assertFalse(r['build_observed']);self.assertFalse(r['eligible_for_existing_internal_group']);self.assertFalse(any('buildBetaDetail' in p for p in c.paths));self.assertFalse(r['uploaded'])
    def test_processing_and_export_compliance_stay_distinct_noneligible_states(self):
        for processing,internal,encryption in [('PROCESSING','PROCESSING',None),('VALID','MISSING_EXPORT_COMPLIANCE',None),('INVALID','PROCESSING_EXCEPTION',False),('FAILED','PROCESSING_EXCEPTION',False)]:
            c=Fake();c.rows['/v1/builds']['data'][0]['attributes'].update(processingState=processing,usesNonExemptEncryption=encryption);c.rows['/v1/builds/'+FAKE_BUILD+'/buildBetaDetail']['data']['attributes']['internalBuildState']=internal;r=m.read(c);self.assertEqual(r['processing_state'],processing);self.assertEqual(r['internal_build_state'],internal);self.assertFalse(r['eligible_for_existing_internal_group'])
    def test_actual_pinned_id_conflicting_app_platform_number_or_ambiguity_stops(self):
        for delta in ['pinned','app','platform','number','ambiguous']:
            c=Fake()
            if delta=='pinned':c.expected_build_id='55555555-5555-5555-5555-555555555555'
            if delta=='app':c.rows['/v1/builds']['data'][0]['relationships']['app']=rel('apps','other-app')
            if delta=='platform':c.rows['/v1/builds']['included'][1]['attributes']['platform']='MAC_OS'
            if delta=='number':c.rows['/v1/builds']['data'][0]['attributes']['version']='3'
            if delta=='ambiguous':c.rows['/v1/builds']['data']*=2
            with self.assertRaises(m.Stop):m.read(c)
    def test_optional_representations_cannot_contradict_parent_evidence(self):
        for delta in ['detail-link','detail-included','detail-duplicate','group-link','group-included','group-fallback']:
            c=Fake();detail=c.rows['/v1/builds/'+FAKE_BUILD+'/buildBetaDetail'];group=c.rows['/v1/betaGroups/'+m.GROUP]
            if delta=='detail-link':detail['data']['relationships']['build']=rel('builds','other-build')
            if delta=='detail-included':detail['included']=[{'type':'builds','id':'other-build'}]
            if delta=='detail-duplicate':detail['included']=[{'type':'builds','id':FAKE_BUILD}]*2
            if delta=='group-link':group['data']['relationships']['app']=rel('apps','other-app')
            if delta=='group-included':group['included']=[{'type':'apps','id':m.APP,'attributes':{'bundleId':'other.bundle'}}]
            if delta=='group-fallback':c.rows['/v1/betaGroups/'+m.GROUP+'/app']['data']['id']='other-app'
            with self.assertRaises(m.Stop):m.read(c)
            self.assertEqual(c.observation['build_id'],FAKE_BUILD)
    def test_links_only_or_null_relationships_use_documented_fallback_not_returned_urls(self):
        for value in [None,{'data':None},{'links':{'related':'https://unrelated.invalid/ignored'}}]:
            c=Fake();c.rows['/v1/builds/'+FAKE_BUILD+'/buildBetaDetail']['data']['relationships']['build']=value;c.rows['/v1/betaGroups/'+m.GROUP]['data']['relationships']['app']=value;r=m.read(c);self.assertTrue(r['eligible_for_existing_internal_group']);self.assertFalse(any('unrelated' in p for p in c.paths))
    def test_changed_group_count_does_not_become_assignment_eligible(self):
        for change in ['tester','prior','automatic']:
            c=Fake()
            if change=='tester':c.rows['/v1/betaGroups/'+m.GROUP+'/relationships/betaTesters']['data'].append({'type':'betaTesters','id':'other-tester'})
            if change=='prior':c.rows['/v1/betaGroups/'+m.GROUP+'/relationships/builds']['data'].pop()
            if change=='automatic':c.rows['/v1/betaGroups/'+m.GROUP]['data']['attributes']['hasAccessToAllBuilds']=True
            self.assertFalse(m.read(c)['eligible_for_existing_internal_group'])
    def test_exact_routes_and_pagination_cannot_escape(self):
        c=m.ReadClient('fake')
        for p in ['/v1/builds','/v1/betaTesters','/v1/profiles',m.route('/v1/builds/'+FAKE_BUILD+'/buildBetaDetail',m.DETAIL_QUERY),m.route('/v1/betaGroups/'+m.GROUP+'/app',m.APP_QUERY),'https://unrelated.invalid'+m.route('/v1/builds',m.BUILD_QUERY),m.route('/v1/builds',{**m.BUILD_QUERY,'filter[version]':'3'})]:
            with self.assertRaises(m.Stop):c.validate(p)
        c=Fake();c.rows['/v1/builds']['links']={'next':m.route('/v1/builds',{**m.BUILD_QUERY,'filter[app]':'other-app'})}
        with self.assertRaises(m.Stop):m.read(c)
    def test_scope_remains_held_until_actual_upload_and_build_id_unset(self):
        root=pathlib.Path(__file__).resolve().parent;scope={**json.loads((root/'scope.json').read_text()),'build_id':None,'dispatchable':False,'store_upload_confirmed':False,'store_upload_receipt_sha256':None};self.assertIsNone(scope['build_id']);self.assertFalse(scope['dispatchable'])
        with self.assertRaises(m.Stop):m.scope_gate(scope)
        ready={**scope,'dispatchable':True,'store_upload_confirmed':True,'store_upload_receipt_sha256':'a'*64};m.scope_gate(ready)
        for delta in [{'source_sha':'a'*40},{'build':'3'},{'app_id':'other'},{'assignment_authorized':True},{'store_upload_receipt_sha256':None},{'build_id':'not-an-observed-uuid'}]:
            with self.assertRaises(m.Stop):m.scope_gate({**ready,**delta})
    def test_real_cli_held_scope_stops_before_credentials(self):
        root=pathlib.Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as folder:
            held=pathlib.Path(folder)/'held.json';held.write_text(json.dumps({**json.loads((root/'scope.json').read_text()),'dispatchable':False,'store_upload_confirmed':False,'store_upload_receipt_sha256':None}));held.chmod(0o600)
            report=pathlib.Path(folder)/'report.json';call=subprocess.run([sys.executable,str(root/'read_ios_build4.py'),'--execute-read-only','--scope',str(held),'--report',str(report)],capture_output=True,text=True,env={'PYTHONDONTWRITEBYTECODE':'1'});self.assertEqual(call.returncode,2);data=json.loads(report.read_text());self.assertEqual(data['error_code'],'read_scope_held_until_store_upload');self.assertEqual(data['account_mutations'],0);self.assertEqual(report.stat().st_mode&0o777,0o600)
    def test_workflow_owner_branch_attempt_guard(self):
        root=pathlib.Path(__file__).resolve().parent;name='resale-build4-intake-corrected-ios-processing-read.yml';workflow=root/name
        if not workflow.exists():workflow=root.parents[1]/'.github/workflows'/name
        text=workflow.read_text();self.assertIn('branches: ['+m.BRANCH+']',text);self.assertIn('--scope Scripts/resale-build4-intake-corrected-ios-processing-read/scope.json',text)
        e={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'h00l1gvn/LoopFollow','GITHUB_ACTOR':'h00l1gvn','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':'refs/heads/'+m.BRANCH,'GITHUB_RUN_ATTEMPT':'1'};m.owner_gate(e)
        for delta in [{'GITHUB_EVENT_NAME':'push'},{'GITHUB_RUN_ATTEMPT':'2'},{'GITHUB_REF':'refs/heads/main'}]:
            with self.assertRaises(m.Stop):m.owner_gate({**e,**delta})
if __name__=='__main__':unittest.main()
