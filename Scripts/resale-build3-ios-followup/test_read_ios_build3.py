import copy,json,pathlib,unittest
import read_ios_build3 as m

def rel(kind,id):return {'data':{'type':kind,'id':id}}
def fixtures():
    build={'type':'builds','id':m.KNOWN_BUILD,'attributes':{'version':'3','processingState':'VALID','expired':False,'expirationDate':'2027-01-04T22:28:54Z','uploadedDate':'2026-10-06T22:28:54Z','usesNonExemptEncryption':False},'relationships':{'app':rel('apps',m.APP),'preReleaseVersion':rel('preReleaseVersions','prerelease3')}}
    app={'type':'apps','id':m.APP,'attributes':{'bundleId':m.BUNDLE}}
    return {
      '/v1/builds/'+m.KNOWN_BUILD:{'data':build,'included':[app,{'type':'preReleaseVersions','id':'prerelease3','attributes':{'version':'0.1.0','platform':'IOS'}}]},
      '/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail':{'data':{'type':'buildBetaDetails','id':'opaque:detail/value=not-for-a-path','attributes':{'internalBuildState':'READY_FOR_BETA_TESTING'}},'included':[{'type':'builds','id':m.KNOWN_BUILD,'attributes':{'version':'3'}}]},
      '/v1/betaGroups/'+m.GROUP:{'data':{'type':'betaGroups','id':m.GROUP,'attributes':{'isInternalGroup':True,'hasAccessToAllBuilds':False}},'included':[app]},
      '/v1/betaGroups/'+m.GROUP+'/relationships/betaTesters':{'data':[{'type':'betaTesters','id':'private-tester-id'}]},
      '/v1/betaGroups/'+m.GROUP+'/relationships/builds':{'data':[{'type':'builds','id':'build2-existing'}]}}
class Fake(m.ReadClient):
    def __init__(self,rows):super().__init__('fake');self.rows=rows;self.paths=[]
    def get(self,path):self.validate(path);self.request_count+=1;self.paths.append(path);return copy.deepcopy(self.rows[m.urlparse(path).path])
class ReadFollowup(unittest.TestCase):
    def test_optional_linkage_and_opaque_detail_id_with_exact_included_binding(self):
        c=Fake(fixtures());r=m.read(c);self.assertTrue(r['eligible_for_existing_internal_group']);self.assertEqual((r['tester_count'],r['assigned_build_count']),(1,1));self.assertEqual(len(c.paths),5);self.assertNotIn('private-tester-id',json.dumps(r));self.assertNotIn('opaque:detail/value',json.dumps(r));self.assertIn('include=build',c.paths[1])
    def test_present_linkage_must_match_and_included_build_required(self):
        for changed in ['mismatch','missing','present_wrong']:
            rows=fixtures();d=rows['/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail']
            if changed=='mismatch':d['included'][0]['id']='wrong-build'
            elif changed=='missing':d.pop('included')
            else:d['data']['relationships']={'build':rel('builds','wrong-build')}
            with self.assertRaises(m.Stop):m.read(Fake(rows))
    def test_opaque_id_bounds_type_and_control_characters(self):
        for v in ['',None,'a'*513,'private\nvalue']:
            rows=fixtures();rows['/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail']['data']['id']=v
            with self.assertRaises(m.Stop):m.read(Fake(rows))
        rows=fixtures();rows['/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail']['data']['type']='apps'
        with self.assertRaises(m.Stop):m.read(Fake(rows))
    def test_exact_build_app_version_platform_binding(self):
        for bad in ['id','app','version','platform']:
            rows=fixtures();b=rows['/v1/builds/'+m.KNOWN_BUILD]
            if bad=='id':b['data']['id']='wrong-build'
            elif bad=='app':b['included'][0]['id']='6819601423'
            elif bad=='version':b['data']['attributes']['version']='2'
            else:b['included'][1]['attributes']['platform']='MAC_OS'
            with self.assertRaises(m.Stop):m.read(Fake(rows))
    def test_late_partial_preserves_actual_valid_build_and_state_never_eligible(self):
        rows=fixtures();rows['/v1/betaGroups/'+m.GROUP]['data']['id']='wrong-group';c=Fake(rows)
        with self.assertRaises(m.Stop):m.read(c)
        r=c.observation;self.assertEqual(r['processing_state'],'VALID');self.assertEqual(r['internal_build_state'],'READY_FOR_BETA_TESTING');self.assertFalse(r['eligible_for_existing_internal_group']);self.assertEqual(r['stage'],'exact_existing_group')
    def test_unknown_encryption_processing_internalstate_or_no_testers_not_ready(self):
        for change in ['encryption','processing','internal','testers']:
            rows=fixtures()
            if change=='encryption':rows['/v1/builds/'+m.KNOWN_BUILD]['data']['attributes']['usesNonExemptEncryption']=None
            elif change=='processing':rows['/v1/builds/'+m.KNOWN_BUILD]['data']['attributes']['processingState']='PROCESSING'
            elif change=='internal':rows['/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail']['data']['attributes']['internalBuildState']='PROCESSING'
            else:rows['/v1/betaGroups/'+m.GROUP+'/relationships/betaTesters']['data']=[]
            self.assertFalse(m.read(Fake(rows))['eligible_for_existing_internal_group'])
    def test_only_known_build_detail_and_group_routes_no_list_or_old_build(self):
        c=m.ReadClient('fake')
        for p in [m.route('/v1/builds',m.BUILD_QUERY),m.route('/v1/builds/old-build2',m.BUILD_QUERY),'/v1/betaTesters',m.route('/v1/apps/'+m.APP,m.APP_QUERY),m.route('/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail',m.DETAIL_QUERY)]:
            with self.assertRaises(m.Stop):c.validate(p)
        c.owned_build=m.KNOWN_BUILD;c.validate(m.route('/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail',m.DETAIL_QUERY))
        with self.assertRaises(m.Stop):c.validate(m.route('/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail',{**m.DETAIL_QUERY,'include':'app'}))
    def test_sanitized_failure_shape_never_retains_id_keys_attributes_or_bodies(self):
        value={'data':{'type':'buildBetaDetails','id':'opaque/private:secret','attributes':{'buyer':'do-not-save'},'relationships':{'build':{'links':{'related':'private-url'}}}},'included':[]};d=m.diagnostic(value);self.assertEqual(d['id_format'],'bounded_opaque');self.assertFalse(d['build_linkage_data_present']);self.assertNotIn('secret',json.dumps(d));self.assertNotIn('buyer',json.dumps(d));self.assertNotIn('private-url',json.dumps(d))
    def test_push_reentry_wrong_owner_and_scope_guard(self):
        env={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'h00l1gvn/LoopFollow','GITHUB_ACTOR':'h00l1gvn','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':'refs/heads/'+m.BRANCH,'GITHUB_RUN_ATTEMPT':'1'};m.owner_gate(env)
        for bad in [{'GITHUB_EVENT_NAME':'push'},{'GITHUB_RUN_ATTEMPT':'2'},{'GITHUB_ACTOR':'other'}]:
            with self.assertRaises(m.Stop):m.owner_gate({**env,**bad})
        s=json.loads((pathlib.Path(__file__).parent/'scope.json').read_text());self.assertEqual(s['build_id'],m.KNOWN_BUILD);self.assertTrue(s['GET_only']);self.assertFalse(s['assignment_authorized'])
    def test_workflow_ci_shape_path_skip_no_upload_or_mutation(self):
        root=pathlib.Path(__file__).resolve().parent;n='resale-build3-ios-processing-followup.yml';p=root/n
        if not p.exists():p=root.parents[1]/'.github/workflows'/n
        t=p.read_text();self.assertIn('branches: ['+m.BRANCH+']',t);self.assertIn("github.ref == 'refs/heads/"+m.BRANCH+"'",t);self.assertIn("github.event_name == 'workflow_dispatch'",t);self.assertNotIn('altool',t);self.assertNotIn('GH_PAT',t);self.assertNotIn('MATCH_PASSWORD',t)
if __name__=='__main__':unittest.main()
