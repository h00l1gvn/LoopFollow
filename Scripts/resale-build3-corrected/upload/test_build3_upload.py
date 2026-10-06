"""Focused no-network upload/journal/collision and future-coordinate guards."""
import copy, json, pathlib, sys, tempfile, unittest, subprocess, shutil
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import build3_upload as u
ROOT=pathlib.Path(__file__).resolve().parent.parent

def workflow_text():
    name='resale-build3-corrected-upload-cached.yml'
    local=ROOT/'upload'/name
    if local.is_file():return local.read_text()
    return (ROOT.parents[1]/'.github/workflows'/name).read_text()

class Build3Upload(unittest.TestCase):
    def setUp(self):
        self.scope=json.loads((ROOT/'scope.json').read_text())
        self.scope.update(source_sha='a'*40, source_frozen=True, final_artwork_owner_approved=True)
        self.coordinates=json.loads((ROOT/'export-coordinates.json').read_text())
        self.coordinates.update(source_sha='a'*40,export_head_sha='b'*40,export_run_id=101,export_job_id=102,authenticated_successful_run_observed=True)
        u.bind_release(self.scope,self.coordinates)
    def pins(self):
        return {'family':'ios','package_name':'ReBurrow.ipa','manifest_name':'manifest.json','release_id':7,'release_tag':'resale-burrow-0.1.0-build-3-ios-'+u.SOURCE[:12],'package_sha256':'c'*64,'package_bytes':10}
    def manifest(self):
        p=self.pins()
        return {'schema':'ReBurrow-build3-cached-export-1','source_sha':u.SOURCE,'version':'0.1.0','build':'3','family':'ios','package_name':p['package_name'],'package_sha256':p['package_sha256'],'package_bytes':10,'export_run_id':u.EXPORT_RUN,'export_job_id':u.APPS['ios'][4],'export_head_sha':u.EXPORT_HEAD,'strict_validation_passed':True,'ephemeral_cleanup_verified':True,'recipient_context_authenticated':True}
    def test_absent_unverified_or_foreign_future_coordinates_are_blocked(self):
        for changes in [{'export_run_id':None},{'export_head_sha':None},{'authenticated_successful_run_observed':False},{'source_sha':'d'*40},{'event':'push'},{'workflow':'.github/workflows/resale-build2-protected-export.yml'}]:
            v={**self.coordinates,**changes}
            with self.assertRaises(u.Stop):u.bind_release(self.scope,v)
    def test_exact_new_manifest_rejects_old_build_or_changed_package(self):
        u.package_manifest(self.manifest(),self.pins())
        for changes in [{'build':'2'},{'source_sha':u.c.OLD_SOURCE},{'package_sha256':'d'*64},{'strict_validation_passed':False}]:
            with self.assertRaises(u.Stop):u.package_manifest({**self.manifest(),**changes},self.pins())
    def test_exact_successful_new_export_job_only(self):
        run={'id':101,'head_sha':'b'*40,'run_attempt':1,'event':'workflow_dispatch','path':'.github/workflows/resale-build3-corrected-export.yml','actor':{'login':'h00l1gvn'},'status':'completed','conclusion':'success'}
        job={'id':102,'run_id':101,'head_sha':'b'*40,'run_attempt':1,'name':'export (ios)','status':'completed','conclusion':'success'}
        u.ci_gate(run,job,'ios')
        for changes in [{'conclusion':'failure'},{'status':'in_progress'},{'id':37509737158},{'event':'push'}]:
            with self.assertRaises(u.Stop):u.ci_gate({**run,**changes},job,'ios')
    def test_build3_journal_requires_empty_exact_new_cache(self):
        pins=self.pins();base=[pins['package_name'],pins['manifest_name']]
        u.stage_gate(base,pins)
        for extras in [['upload-intent-ios-0.1.0-3.json'],['upload-result-ios-0.1.0-2.json'],[pins['manifest_name']]]:
            with self.assertRaises(u.Stop):u.stage_gate(base+extras,pins)
    def test_unknown_transport_calls_once_and_cleans_ephemeral_api_key(self):
        with tempfile.TemporaryDirectory() as folder:
            calls=[];work=pathlib.Path(folder)
            env={'FASTLANE_KEY_ID':'ABC1234567','FASTLANE_ISSUER_ID':'11111111-1111-1111-1111-111111111111','FASTLANE_KEY':'SYNTHETIC-NOT-A-KEY'}
            def runner(*args):calls.append(args);raise subprocess.TimeoutExpired(args[0],1)
            self.assertEqual(u.once(work/'package.ipa','ios',work,env,runner,'upload'),('outcome_unknown_stop_no_retry',None))
            self.assertEqual(len(calls),1);self.assertEqual(list(work.iterdir()),[])
    def test_only_new_build3_collision_blocks_with_no_inferred_retry_permission(self):
        a=u.Apple('SYNTHETIC','ios')
        a.get=lambda path: {'data':{'id':'6819601040','attributes':{'bundleId':u.c.BASE}}} if '/apps/' in path else {'data':{'type':'preReleaseVersions','attributes':{'platform':'IOS','version':'0.1.0'}}}
        a.collection=lambda path:[{'type':'builds','id':'one','attributes':{'version':'3'}}] if '/builds?' in path else []
        with self.assertRaises(u.Stop):a.collision()
        a.collection=lambda path:[{'type':'builds','id':'old','attributes':{'version':'2'}}] if '/builds?' in path else []
        self.assertTrue(a.collision()['complete'])
    def test_upload_workflow_registration_does_not_touch_secrets(self):
        text=workflow_text()
        self.assertIn("github.event_name == 'workflow_dispatch'",text)
        self.assertIn('options: [ios]',text)
        self.assertIn('--coordinates Scripts/resale-build3-corrected/export-coordinates.json',text)

    def test_actual_staged_upload_layout_can_read_only_root_workflow(self):
        with tempfile.TemporaryDirectory() as folder:
            repo=pathlib.Path(folder);scripts=repo/'Scripts/resale-build3-corrected';upload=scripts/'upload';upload.mkdir(parents=True)
            workflow=repo/'.github/workflows';workflow.mkdir(parents=True)
            for name in ['build3_contract.py','validate_resale_export.py','mac_payload_permissions.py','scope.json','export-coordinates.json']:
                shutil.copyfile(ROOT/name,scripts/name)
            for name in ['build3_upload.py','test_build3_upload.py']:
                shutil.copyfile(ROOT/'upload'/name,upload/name)
            (workflow/'resale-build3-corrected-upload-cached.yml').write_text(workflow_text())
            self.assertFalse((upload/'resale-build3-corrected-upload-cached.yml').exists())
            result=subprocess.run([sys.executable,'-m','unittest','test_build3_upload.Build3Upload.test_upload_workflow_registration_does_not_touch_secrets'],cwd=upload,capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())

if __name__=='__main__':unittest.main()
