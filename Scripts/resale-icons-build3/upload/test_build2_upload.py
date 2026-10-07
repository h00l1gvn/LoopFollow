import copy,io,json,pathlib,sys,tempfile,unittest,subprocess,time
from unittest.mock import patch,Mock
import types
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import build2_upload as u
class Test(unittest.TestCase):
 def pins(self,f='tvos'):return {'family':f,'package_name':'ReBurrow.ipa','manifest_name':'manifest.json','release_id':7,'release_tag':'resale-burrow-0.1.0-build-3-'+f+'-'+u.SOURCE[:12],'package_sha256':'a'*64,'package_bytes':10}
 def manifest(self):
  p=self.pins();return {'schema':'ReBurrow-icons-build3-cached-export-1','source_sha':u.SOURCE,'version':'0.1.0','build':'3','family':'tvos','package_sha256':p['package_sha256'],'package_bytes':10,'package_name':'ReBurrow.ipa','export_run_id':u.EXPORT_RUN,'export_job_id':u.APPS['tvos'][4],'export_head_sha':u.EXPORT_HEAD,'strict_validation_passed':True,'ephemeral_cleanup_verified':True,'recipient_context_authenticated':True}
 def test_upload_platforms_are_exactly_mac_tv(self):
  self.assertEqual(set(u.APPS),{'macos','tvos'})
  with self.assertRaises(u.Stop):u.command('x.ipa','ios','ABC1234567','a'*8+'-'+ 'a'*4+'-'+ 'a'*4+'-'+ 'a'*4+'-'+ 'a'*12,'upload')
 def test_manifest(self):u.package_manifest(self.manifest(),self.pins())
 def test_reject_historical(self):
  for k,v in [('source_sha','1162d8a1f4fdda1c2678220c9102f9c03ab48c33'),('build','1'),('export_job_id',8),('ephemeral_cleanup_verified',False),('strict_validation_passed',False),('package_sha256','b'*64)]:
   x=self.manifest();x[k]=v
   with self.assertRaises(u.Stop):u.package_manifest(x,self.pins())
 def test_exact_stages(self):
  for family in u.APPS:
   p=self.pins(family);names=['ReBurrow.ipa','manifest.json'];u.stage_gate(names,p)
   for marker in u.marker_names(family):u.stage_gate(names,p,marker);names.append(marker)
 def test_unexpected_result_before_intent(self):
  p=self.pins()
  with self.assertRaises(u.Stop):u.stage_gate(['ReBurrow.ipa','manifest.json','upload-result-tvos-0.1.0-3.json'],p,'upload-intent-tvos-0.1.0-3.json')
 def test_duplicate_names(self):
  with self.assertRaises(u.Stop):u.stage_gate(['ReBurrow.ipa','manifest.json','manifest.json'],self.pins())
 def test_mac_validation_before_upload(self):
  p=self.pins('macos')
  with self.assertRaises(u.Stop):u.stage_gate(['ReBurrow.ipa','manifest.json'],p,'upload-intent-macos-0.1.0-3.json')
 def test_single_timeout_cleanup(self):
  with tempfile.TemporaryDirectory() as t:
   calls=[];env={'FASTLANE_KEY_ID':'ABC1234567','FASTLANE_ISSUER_ID':'a'*8+'-'+ 'a'*4+'-'+ 'a'*4+'-'+ 'a'*4+'-'+ 'a'*12,'FASTLANE_KEY':'synthetic-private','API_PRIVATE_KEYS_DIR':'original'}
   def run(*args):calls.append(args);raise subprocess.TimeoutExpired(args[0],1)
   result=u.once(pathlib.Path(t)/'file.ipa','tvos',pathlib.Path(t),env,run,'upload')
   self.assertEqual(result,('outcome_unknown_stop_no_retry',None));self.assertEqual(len(calls),1);self.assertEqual(list(pathlib.Path(t).iterdir()),[]);self.assertEqual(env['API_PRIVATE_KEYS_DIR'],'original')
 def test_upload_command(self):
  argv=u.command('x.pkg','macos','ABC1234567','a'*8+'-'+ 'a'*4+'-'+ 'a'*4+'-'+ 'a'*4+'-'+ 'a'*12,'upload');self.assertIn('--upload-app',argv);self.assertNotIn('--validate-app',argv)
 def test_disallowed_command(self):
  with self.assertRaises(u.Stop):u.command('x','tvos','bad/key','x','upload')
 def test_ci_exact_job(self):
  r={'id':u.EXPORT_RUN,'head_sha':u.EXPORT_HEAD,'run_attempt':1,'event':'workflow_dispatch','path':'.github/workflows/resale-icons-build3-protected-export.yml','actor':{'login':'h00l1gvn'},'status':'completed','conclusion':'success'}
  j={'id':u.APPS['tvos'][4],'run_id':u.EXPORT_RUN,'head_sha':u.EXPORT_HEAD,'run_attempt':1,'name':'export (tvos)','status':'completed','conclusion':'success'};u.ci_gate(r,j,'tvos')
  for k,v in [('id',12),('head_sha','0'*40),('conclusion','failure'),('run_attempt',2),('name','export (macos)')]:
   z={**j,k:v}
   with self.assertRaises(u.Stop):u.ci_gate(r,z,'tvos')
 def test_release_source(self):
  p=self.pins();r={'id':7,'tag_name':p['release_tag'],'target_commitish':u.SOURCE,'draft':True,'prerelease':True};u.release_gate(r,p)
  r['target_commitish']='main'
  with self.assertRaises(u.Stop):u.release_gate(r,p)
 def test_browser_not_CI(self):
  with self.assertRaises(u.Stop):u.owner_gate({})
 def test_apple_allowlist(self):
  a=u.Apple('secret','tvos')
  for path in ['/v1/apps/6819601423','https://evil.test/v1/apps/6819601040','/v1/apps/6819601040/builds?limit=200&limit=1','/v1/builds/unknown/preReleaseVersion']:
   with self.assertRaises(u.Stop):a.get(path)
 def test_each_action_uses_fresh_timestamp_and_collision(self):
  calls=[];env={'TEAMID':u.c.TEAM,'FASTLANE_KEY':'synthetic','FASTLANE_ISSUER_ID':'issuer','FASTLANE_KEY_ID':'KEYID'}
  class FakeApple:
   def __init__(self,token,family):self.family=family
   def collision(self):calls.append(self.family);return {'checked_at':str(len(calls)),'complete':True,'exact_records':[]}
  encode=Mock(return_value='synthetic-token')
  with patch.dict(sys.modules,{'jwt':types.SimpleNamespace(encode=encode)}):
   a=u.fresh_collision(env,'macos',FakeApple);b=u.fresh_collision(env,'macos',FakeApple)
   self.assertNotEqual(a['checked_at'],b['checked_at']);self.assertEqual(len(calls),2)
   for call in encode.call_args_list:
    payload=call.args[0];self.assertLess(abs(payload['iat']-int(time.time())),2);self.assertEqual(payload['exp']-payload['iat'],600)
 def test_collision_complete(self):
  a=u.Apple('secret','tvos');a.get=lambda path:{'data':{'id':'6819601651','attributes':{'bundleId':'com.julienbell.ResaleBurrow.tv'}}} if '/apps/' in path else {'data':{'type':'preReleaseVersions','attributes':{'platform':'TV_OS','version':'0.1.0'}}}
  a.collection=lambda path:[{'type':'builds','id':'one','attributes':{'version':'3'}}] if '/builds?' in path else []
  with self.assertRaises(u.Stop):a.collision()
if __name__=='__main__':unittest.main()
