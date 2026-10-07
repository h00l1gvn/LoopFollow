"""Focused offline regression guards for the new source/version/workflow boundaries."""
import copy, json, pathlib, unittest, tempfile, shutil, subprocess, sys
import build5_contract as c
import restore_build5_material as restore
import validate_resale_export as strict

ROOT=pathlib.Path(__file__).resolve().parent

def workflow_text():
    name='resale-build5-approved-posting-export.yml'
    local=ROOT/name
    if local.is_file():return local.read_text()
    # stage_build5_tooling places helpers in Scripts/resale-build5-approved-posting and the
    # one exact workflow at the repository root's .github/workflows.
    return (ROOT.parents[1]/'.github/workflows'/name).read_text()

def fixture_scope():
    value=json.loads((ROOT/'scope.json').read_text())
    value.update(source_sha='a'*40, source_frozen=True, final_artwork_owner_approved=True)
    return value

class Build5Preparation(unittest.TestCase):
    def test_new_build5_reuses_exact_existing_store_profile_names_and_four_ios_bundles(self):
        expected,pins=restore.plan(fixture_scope(),'ios')
        self.assertEqual(set(expected), {c.BASE,c.BASE+'.widgets',c.BASE+'.watch',c.BASE+'.watch.widgets'})
        self.assertEqual({p['native_profile_id'] for p in pins.values()}, {'PJS3KH7KD8','DDY3DKMS86','F6Q3BN946G','P95TG8C7Z7'})
        self.assertTrue(pins[c.BASE]['name'].startswith('ResaleBurrow Build2 AppStore '))

    def test_historical_build2_source_and_number_are_rejected(self):
        for change in [{'build':'2'},{'build':'3'},{'source_sha':c.OLD_SOURCE},{'source_sha':c.TIMEOUT_SUPERSEDED_SOURCE},{'source_sha':'1162d8a1f4fdda1c2678220c9102f9c03ab48c33'}]:
            scope=fixture_scope();scope.update(change)
            with self.assertRaises(Exception):strict.scope_check(scope,'ios')

    def test_future_unfrozen_scope_is_not_restorable(self):
        for change in [{'source_sha':None},{'source_frozen':False},{'final_artwork_owner_approved':False}]:
            scope=fixture_scope();scope.update(change)
            with self.assertRaises(Exception):restore.plan(scope,'ios')

    def test_changed_existing_cms_or_unrelated_profile_cannot_be_substituted(self):
        scope=fixture_scope();scope['native_profiles'][0]['native_readback_verified']=False
        with self.assertRaises(Exception):restore.plan(scope,'ios')
        scope=fixture_scope();scope['native_profiles'][0]['name']='ResaleBurrow Build5 created without review'
        with self.assertRaises(Exception):restore.plan(scope,'ios')

    def test_workflow_only_ios_first_manual_owner_attempt_and_unsigned_before_material(self):
        text=workflow_text()
        self.assertIn("github.event_name == 'workflow_dispatch'",text)
        self.assertIn("github.actor == 'h00l1gvn'",text)
        self.assertIn('github.run_attempt == 1',text)
        self.assertIn('family: [ios]',text)
        self.assertNotIn('family: [ios, macos, tvos]',text)
        self.assertLess(text.index('swift test --parallel'),text.index('name: GET-only scoped material restore'))
        self.assertIn('CODE_SIGNING_ALLOWED=NO build',text)
        self.assertNotIn('--upload-app',text)
        self.assertNotIn('prepare_three_push_profiles',text)

    def test_ci_shaped_layout_runs_exact_workflow_guard_before_material(self):
        with tempfile.TemporaryDirectory() as folder:
            repo=pathlib.Path(folder)
            scripts=repo/'Scripts/resale-build5-approved-posting';scripts.mkdir(parents=True)
            workflows=repo/'.github/workflows';workflows.mkdir(parents=True)
            # The CI layout deliberately has no helper-adjacent YAML copy.
            for name in ['test_build5_preparation.py','build5_contract.py','restore_build5_material.py','build5_profile_audit.py','resale_apple_audit.py','validate_resale_export.py','scope.json']:
                shutil.copyfile(ROOT/name,scripts/name)
            (workflows/'resale-build5-approved-posting-export.yml').write_text(workflow_text())
            self.assertFalse((scripts/'resale-build5-approved-posting-export.yml').exists())
            result=subprocess.run([sys.executable,'-m','unittest','test_build5_preparation.Build5Preparation.test_workflow_only_ios_first_manual_owner_attempt_and_unsigned_before_material'],cwd=scripts,capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())

if __name__=='__main__':unittest.main()
