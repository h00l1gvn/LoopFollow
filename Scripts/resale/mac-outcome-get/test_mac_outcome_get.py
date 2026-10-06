import copy, unittest, tempfile, subprocess
from pathlib import Path
from unittest.mock import patch
import mac_outcome_get as probe
import cached_upload as reviewed

APP = probe.APP
BASE = 'https://api.appstoreconnect.apple.com'
class Fixture:
    def __init__(self, builds=None, uploads=None):
        self.calls = []
        self.responses = {
            BASE+'/v1/apps/'+APP['asc_id']: {'data': {'type':'apps','id':APP['asc_id'],
                'attributes':{'bundleId':APP['bundle_id']}}},
            BASE+'/v1/apps/'+APP['asc_id']+'/builds?limit=200': {'data': builds or []},
            BASE+'/v1/apps/'+APP['asc_id']+'/buildUploads?limit=200': {'data': uploads or []},
        }
    def json(self, url, **kwargs):
        self.calls.append((url,kwargs))
        return copy.deepcopy(self.responses[url])
def upload(state='PROCESSING', version='0.1.0', build='1'):
    return {'type':'buildUploads','id':'observed-upload-1','attributes':{
        'cfBundleShortVersionString':version,'cfBundleVersion':build,
        'platform':'MAC_OS','state':{'state':state}}}
class Tests(unittest.TestCase):
    def result(self, fixture): return probe.exact_outcome(probe.MacOnlyApple('SYNTHETIC_NOT_A_TOKEN', fixture))
    def test_empty_complete_is_not_automatic_retry_permission(self):
        f=Fixture(); r=self.result(f); self.assertTrue(r['exact_current_records_absent'])
        self.assertFalse(r['retry_authorized']); self.assertFalse(r['resolution_record_created'])
        self.assertEqual(len(f.calls),3); self.assertTrue(all('method' not in kw for _,kw in f.calls))
    def test_processing_upload_blocks(self):
        r=self.result(Fixture(uploads=[upload()]));self.assertTrue(r['collision_hold'])
    def test_failed_upload_still_blocks(self):
        r=self.result(Fixture(uploads=[upload('FAILED')]));self.assertTrue(r['collision_hold'])
        self.assertEqual(r['exact_build_uploads'][0]['state'],'FAILED')
    def test_unknown_upload_state_shape_blocks(self):
        row=upload();row['attributes']['state']='FAILED'
        with self.assertRaises(reviewed.Invalid):self.result(Fixture(uploads=[row]))
    def test_exact_build_any_status_blocks(self):
        row={'type':'builds','id':'build-1','attributes':{'version':'1'}};f=Fixture(builds=[row])
        f.responses[BASE+'/v1/builds/build-1/preReleaseVersion']={'data':{
            'type':'preReleaseVersions','id':'pr-1','attributes':{'version':'0.1.0','platform':'MAC_OS'}}}
        self.assertTrue(self.result(f)['collision_hold'])
    def test_other_version_is_not_this_collision(self):
        r=self.result(Fixture(uploads=[upload(version='0.2.0')]));self.assertFalse(r['collision_hold'])
    def test_unresolved_existing_version_stops(self):
        row=upload();del row['attributes']['cfBundleVersion']
        with self.assertRaises(reviewed.Invalid):self.result(Fixture(uploads=[row]))
    def test_other_owned_app_cannot_be_read(self):
        f=Fixture();client=probe.MacOnlyApple('SYNTHETIC',f)
        for route in ['/v1/apps/6819601040','/v1/apps/6819601651/builds?limit=200']:
            with self.assertRaises(reviewed.Invalid):client.get(route)
        self.assertFalse(f.calls)
    def test_unowned_prerelease_and_write_routes_block(self):
        f=Fixture();c=probe.MacOnlyApple('SYNTHETIC',f)
        for path in ['/v1/builds/unknown/preReleaseVersion','/v1/apps/6819601423/betaGroups','/v1/buildUploads/ab4e768a-7a43-42bd-9cdf-d1c12aa99fd0']:
            with self.assertRaises(reviewed.Invalid):c.get(path)
        self.assertFalse(f.calls)
    def test_changed_app_bundle_stops(self):
        f=Fixture();f.responses[BASE+'/v1/apps/'+APP['asc_id']]['data']['attributes']['bundleId']='com.other'
        with self.assertRaises(reviewed.Invalid):self.result(f)
    def test_pagination_must_be_same_collection(self):
        f=Fixture();f.responses[BASE+'/v1/apps/'+APP['asc_id']+'/builds?limit=200']['links']={'next':'https://untrusted.test/v1/apps/6819601423/builds?limit=200'}
        with self.assertRaises(reviewed.Invalid):self.result(f)
    def test_push_or_other_actor_never_reaches_credentials(self):
        env={'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':'h00l1gvn/LoopFollow','GITHUB_ACTOR':'h00l1gvn','GITHUB_REF':'refs/heads/'+probe.BRANCH,'GITHUB_SHA':'a'*40}
        probe.owner_gate(env)
        for key,value in [('GITHUB_EVENT_NAME','push'),('GITHUB_ACTOR','other'),('GITHUB_REF','refs/heads/main')]:
            bad=dict(env);bad[key]=value
            with self.assertRaises(reviewed.Invalid):probe.owner_gate(bad)
    def test_no_account_contact_fields_copied(self):
        row=upload();row['attributes']['email']='PRIVATE';row['attributes']['errors']=[{'message':'PRIVATE'}]
        r=self.result(Fixture(uploads=[row]));self.assertNotIn('PRIVATE',str(r))
        self.assertFalse(r['upload_executed']);self.assertFalse(r['prior_unknown_journals_modified'])
    def test_modified_reviewed_helper_rejected_before_key_read(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in probe.HELPERS:(root/name).write_bytes((Path(probe.__file__).parent/name).read_bytes())
            probe.verify_sources(root)
            (root/'cached_upload.py').write_text('changed')
            with self.assertRaises(reviewed.Invalid):probe.verify_sources(root)
    def test_workflow_has_only_owner_dispatch_account_step(self):
        root=Path(probe.__file__).resolve().parent
        candidates=[root/'resale-mac-outcome-get.yml',root.parents[2]/'.github/workflows/resale-mac-outcome-get.yml']
        text=next(p.read_text() for p in candidates if p.is_file())
        self.assertIn("github.event_name == 'workflow_dispatch'",text)
        self.assertIn("github.actor == 'h00l1gvn'",text)
        self.assertIn("github.ref == 'refs/heads/"+probe.BRANCH+"'",text)
        for forbidden in ['GH_PAT','MATCH_PASSWORD','fastlane ','--execute-reviewed-upload','workflow_dispatch:\n    inputs:']:
            self.assertNotIn(forbidden,text)
        self.assertIn('Protect exact private GET snapshot and diagnostics',text)
        self.assertIn('persist-credentials: false',text)
    def test_entire_workflow_parses_as_YAML(self):
        root=Path(probe.__file__).resolve().parent
        candidates=[root/'resale-mac-outcome-get.yml',root.parents[2]/'.github/workflows/resale-mac-outcome-get.yml']
        path=next(p for p in candidates if p.is_file())
        result=subprocess.run(['ruby','-rpsych','-e','Psych.parse_file(ARGV[0])',str(path)],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.assertEqual(result.returncode,0,'Entire workflow must parse; shell colons require a block scalar.')
    def test_all_run_steps_are_nonempty_strings(self):
        root=Path(probe.__file__).resolve().parent
        path=next(p for p in [root/'resale-mac-outcome-get.yml',root.parents[2]/'.github/workflows/resale-mac-outcome-get.yml'] if p.is_file())
        ruby="doc=Psych.safe_load(File.read(ARGV[0])); raise unless doc['jobs'].keys == ['outcome']; steps=doc['jobs']['outcome']['steps']; raise unless steps.is_a?(Array); runs=steps.select{|s| s.key?('run')}; raise unless runs.length == 6 && runs.all?{|s| s['run'].is_a?(String) && !s['run'].strip.empty?}; raise unless runs.find{|s| s['name'] == 'Install pinned read-only authentication dependencies'}['run'].include?('--only-binary=:all:')"
        result=subprocess.run(['ruby','-rpsych','-e',ruby,str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.assertEqual(result.returncode,0,'Every native run step must parse into the intended shell string.')
        # The previously rejected scalar must actually fail, so this guard
        # proves it covers the registration failure rather than mirroring text.
        old=path.read_text().replace('run: |\n          python -m pip install','run: python -m pip install',1)
        with tempfile.TemporaryDirectory() as folder:
            broken=Path(folder)/'broken.yml';broken.write_text(old)
            result=subprocess.run(['ruby','-rpsych','-e','Psych.parse_file(ARGV[0])',str(broken)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertNotEqual(result.returncode,0)
if __name__=='__main__':unittest.main()
