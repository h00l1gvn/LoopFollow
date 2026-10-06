"""Scope/unknown-outcome/reuse/profile assertions with fake APIs only."""
import base64,copy,datetime,json,pathlib,tempfile,unittest
from unittest.mock import patch
from urllib.parse import parse_qs,urlparse
import prepare_three_push_profiles as p
from test_build2_profile_audit import CERT,NOW,fixture
SCOPE=json.loads((pathlib.Path(__file__).parent/'three-push-profile-scope.json').read_text())

class Fake:
    def __init__(self,reuse=False):
        self.calls=[];self.post_calls=[];self.scope=SCOPE;self.caps={};self.profiles={};self.cms={};self.fail_cap=False;self.fail_profile=False;self.no_cap_readback=False;self.no_profile_readback=False;self.current_bundle_changed=False
        if reuse:
            for r in SCOPE['targets']:self.enable_push(r);self.create_profile(r)
            self.post_calls=[]
    def collection(self,path):
        self.calls.append(path)
        if path.startswith('/v1/bundleIds?'):
            identifier=parse_qs(urlparse(path).query)['filter[identifier]'][0];r=next(r for r in SCOPE['targets'] if r['bundle_id']==identifier)
            return [{'id':'DIFFERENT' if self.current_bundle_changed else r['native_bundle_resource_id'],'attributes':{'identifier':identifier}}]
        native=path.split('/')[3]
        if '/bundleIdCapabilities?' in path:return [] if self.no_cap_readback else self.caps.get(native,[])
        return [] if self.no_profile_readback else self.profiles.get(native,[])
    def enable_push(self,row):
        self.post_calls.append(('capability',row['bundle_id']))
        if self.fail_cap:raise p.c.GateError('grant_post_unknown_stop_no_retry')
        v={'id':'CAP'+str(list(p.EXACT).index(row['bundle_id'])),'attributes':{'capabilityType':'PUSH_NOTIFICATIONS'}};self.caps[row['native_bundle_resource_id']]=[v];return v
    def create_profile(self,row):
        self.post_calls.append(('profile',row['bundle_id']))
        if self.fail_profile:raise p.c.GateError('grant_post_unknown_stop_no_retry')
        r,cms=fixture(row['bundle_id']);r['id']='PROFILE'+str(list(p.EXACT).index(row['bundle_id']));r['attributes']['name']=row['profile_name'];cms['Name']=row['profile_name'];cms['UUID']='00000000-1111-2222-3333-'+str(list(p.EXACT).index(row['bundle_id'])).zfill(12)
        raw=(row['bundle_id']+' SYNTHETIC PRIVATE PROFILE').encode();encoded=base64.b64encode(raw).decode();r['attributes']['profileContent']=encoded;self.cms[encoded]=cms;self.profiles[row['native_bundle_resource_id']]=[r];return r
    def decode(self,raw):return self.cms[raw]

class Guards(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name)
    def run_prepared(self,client,scope=SCOPE):
        with patch.object(p.audit2,'certificate',return_value=CERT):return p.prepare(client,scope,self.root/'profiles',NOW,client.decode)
    def test_exact_three_new_grants_get_readback_and_private_bytes(self):
        client=Fake();result=self.run_prepared(client);self.assertTrue(result['complete']);self.assertEqual(len(client.post_calls),6)
        self.assertEqual(set(result['exact_push_receiving_bundle_ids']),set(p.EXACT));self.assertFalse(result['app_built_or_uploaded']);self.assertFalse(result['old_profiles_deleted_or_overwritten'])
        for r in result['profiles']:
            f=self.root/'profiles'/r['path'];self.assertEqual(f.stat().st_mode&0o777,0o600);self.assertEqual(p.hashlib.sha256(f.read_bytes()).hexdigest(),r['sha256']);self.assertTrue(r['production_push_grant_verified'])
    def test_creation_response_state_is_not_reused_as_authoritative_get_state(self):
        client=Fake();original=client.create_profile
        def create(row):
            resource=original(row);post=copy.deepcopy(resource);post['attributes']['profileState']='INVALID';return post
        client.create_profile=create;result=self.run_prepared(client)
        self.assertTrue(result['complete']);self.assertTrue(all(r['native_readback_verified'] for r in result['profiles']));self.assertEqual(len(client.post_calls),6)
    def test_created_profile_grants_settle_using_get_only_no_second_post(self):
        client=Fake();original=client.collection;counts={}
        def read(path):
            rows=original(path)
            if '/profiles?' in path and rows:
                counts[path]=counts.get(path,0)+1
                if counts[path]==1:
                    rows=copy.deepcopy(rows);rows[0]['attributes']['profileState']='INVALID'
            return rows
        client.collection=read
        with patch.object(p.time,'sleep') as delay:result=self.run_prepared(client)
        self.assertTrue(result['complete']);self.assertEqual(len(client.post_calls),6);self.assertEqual(delay.call_count,3)
    def test_unsettled_created_profile_stops_after_bounded_gets_without_repost(self):
        client=Fake();original=client.create_profile
        def create(row):
            resource=original(row);resource['attributes']['profileState']='INVALID';return resource
        client.create_profile=create
        with patch.object(p.time,'sleep') as delay:
            with self.assertRaisesRegex(p.c.GateError,'required_grants'):self.run_prepared(client)
        self.assertEqual(len(client.post_calls),2);self.assertEqual(delay.call_count,3)
    def test_current_exact_names_reuse_without_any_posts(self):
        client=Fake(True);self.run_prepared(client);self.assertEqual(client.post_calls,[])
    def test_unknown_capability_post_stops_once_keeps_intent(self):
        client=Fake();client.fail_cap=True
        with self.assertRaisesRegex(p.c.GateError,'unknown_stop'):self.run_prepared(client)
        self.assertEqual(len(client.post_calls),1);self.assertTrue(list((self.root/'profiles').glob('*capability-intent.json')));self.assertFalse(list((self.root/'profiles').glob('*profile-intent.json')))
    def test_unknown_profile_post_never_repeats_or_advances(self):
        client=Fake();client.fail_profile=True
        with self.assertRaisesRegex(p.c.GateError,'unknown_stop'):self.run_prepared(client)
        self.assertEqual(len(client.post_calls),2);self.assertTrue(list((self.root/'profiles').glob('*profile-intent.json')));self.assertFalse((self.root/'profiles'/'three-push-profile-manifest.json').exists())
    def test_capability_absent_on_readback_cannot_be_success(self):
        client=Fake();client.no_cap_readback=True
        with self.assertRaisesRegex(p.c.GateError,'readback'):self.run_prepared(client)
        self.assertEqual(len(client.post_calls),1)
    def test_profile_absent_on_readback_stops_without_second_post(self):
        client=Fake();client.no_profile_readback=True
        with self.assertRaisesRegex(p.c.GateError,'readback'):self.run_prepared(client)
        self.assertEqual(len(client.post_calls),2)
    def test_native_bundle_identity_reconfirmed_before_account_write(self):
        client=Fake();client.current_bundle_changed=True
        with self.assertRaisesRegex(p.c.GateError,'owned_bundle_current_resource_mismatch'):self.run_prepared(client)
        self.assertEqual(client.post_calls,[])
    def test_unrelated_bundle_certificate_type_and_duplicate_native_id_rejected(self):
        for fn in [lambda s:s['targets'][0].update(bundle_id=p.c.BASE+'.tv'),lambda s:s.update(certificate_id='OTHER'),lambda s:s['targets'][0].update(profile_type='IOS_APP_ADHOC'),lambda s:s['targets'][1].update(native_bundle_resource_id=s['targets'][0]['native_bundle_resource_id'])]:
            s=copy.deepcopy(SCOPE);fn(s)
            with self.assertRaises(p.c.GateError):p.validate_scope(s)
    def test_invalid_existing_profile_never_overwritten_or_recreated(self):
        client=Fake(True);first=SCOPE['targets'][0];cms=next(v for v in client.cms.values() if v['Name']==first['profile_name']);cms['Entitlements']['aps-environment']='development'
        with self.assertRaisesRegex(p.c.GateError,'required_grants'):self.run_prepared(client)
        self.assertEqual(client.post_calls,[])
    def test_post_class_rejects_other_api_paths_and_body_variants_before_transport(self):
        class NoNetwork:
            def open(self,*a,**k):raise AssertionError('No request may execute')
        client=p.ThreeGrantClient('SYNTHETIC',SCOPE,NoNetwork());r=SCOPE['targets'][0]
        for endpoint,body in [('/v1/certificates',{}),('/v1/profiles',p.capability_request(r)),('/v1/bundleIdCapabilities',{**p.capability_request(r),'unexpected':True})]:
            with self.assertRaisesRegex(p.c.GateError,'unapproved_three_grant_post'):client._post(endpoint,body)
    def test_output_collision_stops_before_any_mutation(self):
        client=Fake();(self.root/'profiles').mkdir()
        with self.assertRaisesRegex(p.c.GateError,'collision'):self.run_prepared(client)
        self.assertEqual(client.post_calls,[])
    def test_existing_other_profile_names_remain_untouched(self):
        client=Fake();first=SCOPE['targets'][0];client.profiles[first['native_bundle_resource_id']]=[{'id':'OLD','attributes':{'name':'Historical Build1 Profile'}}]
        # Fake service appends its new profile while retaining history.
        original=client.create_profile
        def create(r):
            old=copy.deepcopy(client.profiles.get(r['native_bundle_resource_id'],[]));v=original(r);client.profiles[r['native_bundle_resource_id']]=old+[v];return v
        client.create_profile=create;self.run_prepared(client);self.assertEqual(client.profiles[first['native_bundle_resource_id']][0]['id'],'OLD')

if __name__=='__main__':unittest.main()
