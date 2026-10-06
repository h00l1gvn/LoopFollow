import base64,copy,datetime,json,pathlib,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import prepare_julien_profiles as p
NOW=datetime.datetime(2026,10,6,20,tzinfo=datetime.timezone.utc)
CERT=b'fixture';MEMBERS={'phone':'PRIVATE-PHONE','ipad':'PRIVATE-IPAD','watch':'PRIVATE-WATCH'}
def scope():return json.loads((pathlib.Path(p.__file__).parent/'julien-profile-preparation-scope.json').read_text())
def doc(row):
 ent={'application-identifier':p.c.TEAM+'.'+row['bundle_id'],'com.apple.developer.team-identifier':p.c.TEAM,'com.apple.security.application-groups':[p.c.GROUP],'get-task-allow':False}
 if row['bundle_id'] in p.c.PUSH:ent['aps-environment']='production'
 return {'Name':row['name'],'UUID':'12345678-1234-1234-1234-123456789abc','TeamIdentifier':[p.c.TEAM],'ApplicationIdentifierPrefix':[p.c.TEAM],'Entitlements':ent,'CreationDate':NOW,'ExpirationDate':NOW+datetime.timedelta(days=100),'DeveloperCertificates':[CERT],'ProvisionedDevices':[MEMBERS[k] for k in row['device_roles']]}
def resource(row):return {'type':'profiles','id':'FIXTUREID','attributes':{'name':row['name'],'profileType':'IOS_APP_ADHOC','profileState':'ACTIVE','profileContent':base64.b64encode(b'fixture-cms').decode()}}
class Guards(unittest.TestCase):
 def test_exact_four_scope(self):self.assertEqual(len(p.validate_scope(scope())),4)
 def test_no_extra_target_or_stale_source(self):
  for field,value in [('source_sha','0'*40),('build','1'),('certificate_sha256','0'*64)]:
   s=scope();s[field]=value
   with self.assertRaises(p.c.GateError):p.validate_scope(s)
 def test_role_scope_cannot_expand(self):
  s=scope();s['new_profiles'][0]['device_roles'].append('watch')
  with self.assertRaises(p.c.GateError):p.validate_scope(s)
 def test_get_rejects_unrelated_or_mutation_routes(self):
  client=p.JulienClient('fixture',scope());client.private_devices=MEMBERS
  self.assertTrue(client.get_allowed('/v1/devices?filter%5Budid%5D=PRIVATE-PHONE&limit=50'))
  for path in ['/v1/devices','/v1/devices?filter%5Budid%5D=OTHER','/v1/certificates','/v1/profiles/UNOWNED','/v1/bundleIds/OTHER/profiles','https://attacker.example/v1/devices']:self.assertFalse(client.get_allowed(path))
 def test_no_post_without_private_binding(self):
  client=p.JulienClient('fixture',scope())
  with self.assertRaises(p.c.GateError):client.create_profile(scope()['new_profiles'][0])
 def test_profile_requests_exact_role_devices(self):
  ids={k:'API'+k.upper() for k in MEMBERS}
  for row in scope()['new_profiles']:
   request=p.request(row,ids)['data'];self.assertEqual(request['relationships']['devices']['data'],[{'type':'devices','id':ids[k]} for k in row['device_roles']]);self.assertEqual(request['relationships']['certificates']['data'],[{'type':'certificates','id':p.ap.CERT_ID}])
 def test_valid_current_membership_aps_and_no_hardware_result(self):
  for row in scope()['new_profiles']:
   d=doc(row);r,_=p.checked_profile(resource(row),row,CERT,NOW,lambda _:d,MEMBERS)
   self.assertNotIn('PRIVATE',json.dumps(r));self.assertEqual(r['device_roles'],row['device_roles'])
 def test_profile_wrong_device_development_or_same_team_wrong_cert(self):
  row=scope()['new_profiles'][0]
  for kind in ['device','development','certificate','inactive','group','expiry']:
   d=doc(row);r=resource(row)
   if kind=='device':d['ProvisionedDevices'][0]='PRIVATE-OTHER'
   if kind=='development':d['Entitlements']['get-task-allow']=True
   if kind=='certificate':d['DeveloperCertificates']=[b'other']
   if kind=='inactive':r['attributes']['profileState']='INVALID'
   if kind=='group':d['Entitlements']['com.apple.security.application-groups']=['other']
   if kind=='expiry':d['ExpirationDate']=NOW
   with self.assertRaises(p.c.GateError):p.checked_profile(r,row,CERT,NOW,lambda _:d,MEMBERS)
 def test_receiver_missing_push_and_widget_unexpected_push(self):
  for row in scope()['new_profiles']:
   d=doc(row)
   if row['bundle_id'] in p.c.PUSH:d['Entitlements'].pop('aps-environment')
   else:d['Entitlements']['aps-environment']='production'
   with self.assertRaises(p.c.GateError):p.checked_profile(resource(row),row,CERT,NOW,lambda _:d,MEMBERS)
 def test_unknown_post_stops_no_retry(self):
  class Opener:
   def __init__(self):self.calls=0
   def open(self,*a,**kw):self.calls+=1;raise TimeoutError()
  o=Opener();client=p.JulienClient('fixture',scope(),o);client.bindings={k:'API'+k.upper() for k in MEMBERS}
  with self.assertRaisesRegex(p.c.GateError,'unknown_stop_no_retry'):client.create_profile(scope()['new_profiles'][0])
  self.assertEqual(o.calls,1)
if __name__=='__main__':unittest.main()
