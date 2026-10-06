"""Synthetic offline upload guards; no network, key, build or upload calls."""
import copy
from datetime import datetime, timezone, timedelta
import hashlib
from pathlib import Path
import tempfile
import unittest
import plan_cached_upload as v

NOW=datetime(2026,10,6,10,tzinfo=timezone.utc)
def check(family='ios'):
    app=v.APPS[family]
    return {'authenticated_get_only':True,'complete':True,'asc_id':app['asc_id'],
      'bundle_id':app['bundle_id'],'platform':app['platform'],'checked_at':NOW.isoformat(),
      'unknown_previous_upload':False,'pagination_complete':True,'builds':[],'build_uploads':[]}

def export(path,family='ios'):
    sha=hashlib.sha256(path.read_bytes()).hexdigest()
    return {'family':family,'distribution':'app-store','version':'0.1.0','build':'1',
      'source_sha':'a'*40,'delivery_sha':'b'*40,'authenticated_recovery_verified':True,
      'path':str(path),'sha256':sha,'validation':{'status':'passed','signed_local_artifacts_verified':True,
      'export_artifact_sha256':sha,'family':family,'team':v.TEAM,'group':v.GROUP,
      'exact_bundle_count':v.APPS[family]['count'],'source_sha_basis':'a'*40,'uploaded':False}}

class Guards(unittest.TestCase):
    def test_fresh_complete_exact_collision_precheck(self):
        self.assertTrue(v.collision_precheck(check(),'ios',now=NOW))

    def test_existing_build_or_upload_blocks_any_processing_state(self):
        for collection in ('builds','build_uploads'):
            c=check();c[collection]=[{'identity_resolved':True,'version':'0.1.0','build':'1','platform':'IOS','state':'PROCESSING'}]
            with self.subTest(collection=collection),self.assertRaises(v.Invalid):v.collision_precheck(c,'ios',now=NOW)

    def test_unknown_and_incomplete_precheck_blocks(self):
        for key,value in [('authenticated_get_only',False),('complete',False),('unknown_previous_upload',True),('pagination_complete',False),('asc_id','OTHER')]:
            c=check();c[key]=value
            with self.subTest(key=key),self.assertRaises(v.Invalid):v.collision_precheck(c,'ios',now=NOW)

    def test_stale_and_future_prechecks_block(self):
        for date in (NOW-timedelta(minutes=11),NOW+timedelta(seconds=1)):
            c=check();c['checked_at']=date.isoformat()
            with self.assertRaises(v.Invalid):v.collision_precheck(c,'ios',now=NOW)

    def test_unresolved_existing_upload_blocks(self):
        c=check();c['build_uploads']=[{'identity_resolved':False}]
        with self.assertRaises(v.Invalid):v.collision_precheck(c,'ios',now=NOW)

    def test_all_exact_export_families(self):
        with tempfile.TemporaryDirectory() as d:
            for family,a in v.APPS.items():
                p=Path(d)/('synthetic-'+family+a['suffix']);p.write_bytes(b'synthetic signed test fixture')
                r=v.validate_export(export(p,family),'a'*40,'b'*40)
                self.assertEqual(r['asc_id'],a['asc_id'])

    def test_adhoc_or_untrusted_recovery_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'synthetic.ipa';p.write_bytes(b'synthetic')
            for key,value in [('distribution','ad-hoc'),('authenticated_recovery_verified',False),('version','0.2.0'),('build','2'),('source_sha','c'*40)]:
                r=export(p);r[key]=value
                with self.subTest(key=key),self.assertRaises(v.Invalid):v.validate_export(r,'a'*40,'b'*40)

    def test_wrong_digest_or_other_validation_does_not_pass(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'synthetic.ipa';p.write_bytes(b'synthetic')
            for key,value in [('exact_bundle_count',1),('team','OTHER'),('export_artifact_sha256','d'*64),('uploaded',True),('source_sha_basis','d'*40)]:
                r=export(p);r['validation'][key]=value
                with self.subTest(key=key),self.assertRaises(v.Invalid):v.validate_export(r,'a'*40,'b'*40)
            r=export(p);p.write_bytes(b'changed')
            with self.assertRaises(v.Invalid):v.validate_export(r,'a'*40,'b'*40)

    def test_public_other_repo_and_duplicate_families_rejected(self):
        rows=[{'family':f,'path':'/synthetic/'+f+v.APPS[f]['suffix'],'sha256':'c'*64} for f in v.APPS]
        for repo in ({'full_name':v.REPO,'private':False},{'full_name':'other/repo','private':True}):
            with self.assertRaises(v.Invalid):v.private_cache_plan(repo,rows)
        rows[1]=rows[0]
        with self.assertRaises(v.Invalid):v.private_cache_plan({'full_name':v.REPO,'private':True},rows)

    def test_draft_cache_exact_assets_no_sensitive_attachments(self):
        rows=[{'family':f,'path':'/synthetic/'+f+v.APPS[f]['suffix'],'sha256':'c'*64} for f in v.APPS]
        r=v.private_cache_plan({'full_name':v.REPO,'private':True},rows)
        self.assertTrue(r['draft']);self.assertEqual(len(r['assets']),3)
        self.assertEqual(r['additional_allowed_asset'],'signed-export-cache-manifest.json')

    def test_upload_only_exact_app_and_platform_options(self):
        for family,app in v.APPS.items():
            r=v.fastlane_options({'family':family,'path':'/owned/'+family+app['suffix']})
            self.assertEqual(r['apple_id'],app['asc_id']);self.assertEqual(r['app_platform'],app['fastlane_platform'])
            self.assertTrue(r['skip_submission']);self.assertTrue(r['skip_waiting_for_build_processing'])
            self.assertFalse(r['distribute_external']);self.assertFalse(r['notify_external_testers'])
            self.assertNotIn('api_key',r);self.assertNotIn('groups',r);self.assertNotIn('changelog',r)

    def test_durable_local_unknown_attempt_cannot_repeat(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'attempt.json';v.reserve_local_attempt(p,'ios','c'*64)
            with self.assertRaises(FileExistsError):v.reserve_local_attempt(p,'ios','c'*64)

if __name__=='__main__':unittest.main()
