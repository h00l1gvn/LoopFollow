"""Build2 material/runner plans; no API, keychain, build or export commands run."""
import copy,json,pathlib,tempfile,unittest,os,hashlib
from unittest.mock import patch
import build2_contract as c
import restore_build2_material as r
import export_build2_family as e
ROOT=pathlib.Path(__file__).parent

def scope():
 v=json.loads((ROOT/'scope.json').read_text());v.update(source_sha='2'*40,source_frozen=True,final_artwork_owner_approved=True,match_material_commit=r.MATCH_COMMIT)
 v['native_profiles']=[{'bundle_id':t['bundle_id'],'native_profile_id':'NATIVE'+str(i),'uuid':'00000000-1111-2222-3333-'+str(i).zfill(12),'profile_type':t['profile_type'],'name':('ResaleBurrow Build2 AppStore ' if t['bundle_id'] in c.PUSH else 'ResaleBurrow AppStore ')+t['target'],'sha256':'a'*64,'native_readback_verified':True} for i,t in enumerate(v['targets'])];return v

class Plans(unittest.TestCase):
 def test_exact_selected_family_native_hash_pins(self):
  for fam,count in [('ios',4),('macos',2),('tvos',1)]:
   expected,pins=r.plan(scope(),fam);self.assertEqual(len(expected),count);self.assertEqual(set(expected),set(pins))
 def test_unfrozen_old_build_or_unapproved_art_blocked(self):
  for change in [{'source_sha':c.OLD_SOURCE},{'source_frozen':False},{'build':'1'},{'final_artwork_owner_approved':False},{'match_material_commit':'f'*40}]:
   v=scope();v.update(change)
   with self.assertRaises(Exception):r.plan(v,'ios')
 def test_changed_native_name_duplicate_uuid_unverified_or_type_blocked(self):
  for field,value in [('name','Other'),('native_readback_verified',False),('profile_type','IOS_APP_ADHOC'),('sha256','bad'),('uuid','bad')]:
   v=scope();v['native_profiles'][0][field]=value
   with self.assertRaises(c.GateError):r.plan(v,'ios')
  v=scope();v['native_profiles'][1]['uuid']=v['native_profiles'][0]['uuid']
  with self.assertRaises(c.GateError):r.plan(v,'ios')
 def test_read_clients_reject_unrelated_endpoints_before_transport(self):
  class NoneAllowed:
   def open(self,*a,**k):raise AssertionError('No network')
  a=r.CertificateReadClient('SYNTHETIC',NoneAllowed());b=r.ProfileReadClient('SYNTHETIC',scope(),NoneAllowed())
  for cli,path in [(a,'/repos/h00l1gvn/Match-Secrets/git/commits/'+'e'*40),(a,'/repos/OTHER/git/blobs/'+'e'*40),(a,'/repos/h00l1gvn/Match-Secrets/git/ref/heads/master'),(b,'/v1/profiles/OTHER'),(b,'/v1/devices'),(b,'https://evil.invalid/')]:
   with self.assertRaises(c.GateError):cli.get(path)
 def test_no_overwrite_private_restore_output(self):
  with tempfile.TemporaryDirectory() as d:
   f=pathlib.Path(d)/'secret';r.private_bytes(f,b'SYNTHETIC');self.assertEqual(f.stat().st_mode&0o777,0o600)
   with self.assertRaises(c.GateError):r.private_bytes(f,b'OTHER')
   self.assertEqual(f.read_bytes(),b'SYNTHETIC')
 def test_plan_requires_frozen_family_and_private_material_hashes(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);work=root/'work';material=root/'material';source=root/'workspace/source';material.mkdir();source.mkdir(parents=True)
   v=scope();rows=[]
   for t in [t for t in v['targets'] if t['family']=='ios']:
    f=material/(t['target']+'.mobileprovision');f.write_bytes(b'SYNTHETIC '+t['bundle_id'].encode());rows.append({'bundle_id':t['bundle_id'],'verified':True,'native_readback_verified':True,'certificate_sha256':c.CERT_SHA,'private_profile_file':str(f),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
   f=material/'sign.p12';f.write_bytes(b'SYNTHETIC PRIVATE');manifest={'source_sha':v['source_sha'],'family':'ios','team':c.TEAM,'group':c.GROUP,'profiles':rows,'signing_certificate':{'verified':True,'sha256':c.CERT_SHA,'p12_file':str(f),'p12_file_sha256':hashlib.sha256(f.read_bytes()).hexdigest()}}
   with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_TEMP':str(root),'GITHUB_WORKSPACE':str(root/'workspace')}):
    self.assertEqual(len(e.plan(v,manifest,'ios',material,source,work)[0]),4)
    f.write_bytes(b'CHANGED')
    with self.assertRaises(c.GateError):e.plan(v,manifest,'ios',material,source,work)
 def test_local_driver_plan_rejected_before_keychain_or_build(self):
  with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}):
   with self.assertRaises(c.GateError):e.plan(scope(),{},'ios','/tmp','/tmp','/tmp')
 def test_unrecognized_source_family_rejected(self):
  with self.assertRaises(Exception):r.plan(scope(),'watchStandalone')
if __name__=='__main__':unittest.main()
