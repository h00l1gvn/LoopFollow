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
      '/v1/betaGroups/'+m.GROUP+'/app':{'data':copy.deepcopy(app)},
      '/v1/betaGroups/'+m.GROUP+'/relationships/betaTesters':{'data':[{'type':'betaTesters','id':'private-tester-id'}]},
      '/v1/betaGroups/'+m.GROUP+'/relationships/builds':{'data':[{'type':'builds','id':'build2-existing'}]}}
class Fake(m.ReadClient):
    def __init__(self,rows):super().__init__('fake');self.rows=rows;self.paths=[]
    def get(self,path):self.validate(path);self.request_count+=1;self.paths.append(path);return copy.deepcopy(self.rows[m.urlparse(path).path])
class ParentRead(unittest.TestCase):
    def test_null_linkage_absent_included_uses_authoritative_parent_and_group_app(self):
        rows=fixtures();detail=rows['/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail'];detail['included']=[];detail['data']['relationships']={'build':{'data':None}};group=rows['/v1/betaGroups/'+m.GROUP];group['included']=[];group['data']['relationships']={'app':{'data':None}};c=Fake(rows);r=m.read(c);self.assertTrue(r['eligible_for_existing_internal_group']);self.assertEqual(r['detail_binding_basis'],'exact_owned_parent_endpoint');self.assertEqual(r['group_app_binding_basis'],'exact_group_app_endpoint');self.assertEqual(len(c.paths),6);self.assertNotIn('private-tester-id',json.dumps(r))
    def test_absent_linkage_and_included_does_not_block_owned_detail_or_group(self):
        rows=fixtures();rows['/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail'].pop('included');rows['/v1/betaGroups/'+m.GROUP].pop('included');r=m.read(Fake(rows));self.assertEqual(r['internal_build_state'],'READY_FOR_BETA_TESTING');self.assertTrue(r['eligible_for_existing_internal_group'])
    def test_nonnull_contradictory_proof_and_fallback_wrong_app_rejected(self):
        for resource in ['detail','group']:
            for bad in ['link','included','duplicate']:
                rows=fixtures();key='/v1/builds/'+m.KNOWN_BUILD+'/buildBetaDetail' if resource=='detail' else '/v1/betaGroups/'+m.GROUP;r=rows[key];kind='builds' if resource=='detail' else 'apps';linkkey='build' if resource=='detail' else 'app'
                if bad=='link':r['data']['relationships']={linkkey:rel(kind,'wrong-resource')}
                elif bad=='included':r['included'][0]['id']='wrong-resource'
                else:r['included']*=2
                with self.assertRaises(m.Stop):m.read(Fake(rows))
        rows=fixtures();rows['/v1/betaGroups/'+m.GROUP]['included']=[];rows['/v1/betaGroups/'+m.GROUP+'/app']['data']['id']='wrong-app';c=Fake(rows)
        with self.assertRaises(m.Stop):m.read(c)
        self.assertEqual(c.observation['internal_build_state'],'READY_FOR_BETA_TESTING');self.assertFalse(c.observation['eligible_for_existing_internal_group'])
    def test_branch_gate_scope_and_staged_workflow_binding(self):
        root=pathlib.Path(__file__).resolve().parent;n='resale-build3-ios-parent-read.yml';p=root/n
        if not p.exists():p=root.parents[1]/'.github/workflows'/n
        t=p.read_text();self.assertIn('branches: ['+m.BRANCH+']',t);self.assertIn("github.ref == 'refs/heads/"+m.BRANCH+"'",t)
        e={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'h00l1gvn/LoopFollow','GITHUB_ACTOR':'h00l1gvn','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':'refs/heads/'+m.BRANCH,'GITHUB_RUN_ATTEMPT':'1'};m.owner_gate(e)
        with self.assertRaises(m.Stop):m.owner_gate({**e,'GITHUB_EVENT_NAME':'push'})
        c=m.ReadClient('fake')
        with self.assertRaises(m.Stop):c.validate(m.route('/v1/betaGroups/'+m.GROUP+'/app',m.GROUP_APP_QUERY))
        c.owned_group=True;c.validate(m.route('/v1/betaGroups/'+m.GROUP+'/app',m.GROUP_APP_QUERY))
        with self.assertRaises(m.Stop):c.validate(m.route('/v1/betaGroups/wrong/app',m.GROUP_APP_QUERY))
if __name__=='__main__':unittest.main()
