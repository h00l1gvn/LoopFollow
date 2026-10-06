"""Synthetic account-boundary/CMS fixtures; never imports credentials or transport."""
import base64,copy,datetime,hashlib,json,pathlib,sys,tempfile,unittest
from unittest.mock import patch
from urllib.error import URLError
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import prepare_bryan_push_profiles as p

NOW=datetime.datetime(2026,10,6,22,tzinfo=datetime.timezone.utc)
CERT=b'synthetic-approved-cert'
PHONE='SYNTHETIC-NON-HARDWARE-PHONE'
DEVICE='SYNTHETIC-DEVICE-RESOURCE'

def scope():return json.loads((pathlib.Path(__file__).parent/'bryan-profile-preparation-scope.json').read_text())

def fixture(ident,name,native,index,*,push=False):
    row={'Name':name,'UUID':f'00000000-0000-0000-0000-{index:012d}','TeamIdentifier':[p.c.TEAM],'ApplicationIdentifierPrefix':[p.c.TEAM],
      'Entitlements':{'application-identifier':p.c.TEAM+'.'+ident,'com.apple.developer.team-identifier':p.c.TEAM,'com.apple.security.application-groups':[p.c.GROUP],'get-task-allow':False},
      'CreationDate':NOW-datetime.timedelta(hours=1),'ExpirationDate':datetime.datetime(2027,1,1,tzinfo=datetime.timezone.utc),'DeveloperCertificates':[CERT],'ProvisionedDevices':[PHONE]}
    if push:row['Entitlements']['aps-environment']='production'
    raw=('synthetic-cms:'+ident+':'+name).encode()
    resource={'type':'profiles','id':native,'attributes':{'name':name,'profileType':'IOS_APP_ADHOC','profileState':'ACTIVE','profileContent':base64.b64encode(raw).decode()}}
    return resource,raw,row

class FakeClient:
    def __init__(self):
        self.calls=[];self.posts=[];self.named={};self.resources={};self.decoded={};self.binds=[];self.device=None;self.fail_post=False;self.missing_readback=False
        self.old={}
        for i,(ident,(native,name,_,_)) in enumerate(p.OLD.items(),1):
            resource,raw,parsed=fixture(ident,name,native,i);self.resources[native]=resource;self.decoded[raw]=parsed
            self.old[ident]=(native,name,hashlib.sha256(raw).hexdigest(),parsed['UUID'])
        self.relationships={v[0]:[{'type':'devices','id':DEVICE,'attributes':{'udid':PHONE,'status':'ENABLED','platform':'IOS'}}] for k,v in p.OLD.items() if k in p.NEW}
        self.bundle_mismatch=False;self.no_push=False
    def decoder(self,raw):return copy.deepcopy(self.decoded[raw])
    def get(self,path):
        self.calls.append(('GET',path));return {'data':copy.deepcopy(self.resources[path.split('/')[-1]])}
    def collection(self,path):
        self.calls.append(('GET',path))
        if path.startswith('/v1/profiles/'):
            return copy.deepcopy(self.relationships[path.split('/')[3]])
        if path.startswith('/v1/bundleIds?'):
            ident=__import__('urllib.parse',fromlist=['parse_qs','urlsplit']).parse_qs(__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(path).query)['filter[identifier]'][0]
            return [{'id':'WRONG' if self.bundle_mismatch else p.NEW[ident][0],'attributes':{'identifier':ident}}]
        native=path.split('/')[3]
        if '/bundleIdCapabilities?' in path:return [] if self.no_push else [{'attributes':{'capabilityType':'PUSH_NOTIFICATIONS'}}]
        return copy.deepcopy(self.named.get(native,[]))
    def bind_approved_device(self,v):self.binds.append(v);self.device=v
    def create_profile(self,row):
        self.posts.append(p.request(row,self.device))
        if self.fail_post:raise p.c.GateError('profile_post_unknown_stop_no_retry')
        native='SYNTHETICNEW'+str(len(self.posts));r,raw,d=fixture(row['bundle_id'],row['name'],native,10+len(self.posts),push=True)
        self.resources[native]=r;self.decoded[raw]=d
        if not self.missing_readback:self.named[row['native_bundle_resource_id']]=[r]
        return copy.deepcopy(r)
    def valid_existing(self,which=0):
        row=scope()['new_profiles'][which];r,raw,d=fixture(row['bundle_id'],row['name'],'EXISTINGNEW'+str(which),20+which,push=True)
        self.resources[r['id']]=r;self.decoded[raw]=d;self.named[row['native_bundle_resource_id']]=[r];return d

class Guards(unittest.TestCase):
    def execute(self,client=None,mutate=None,exist_output=False):
        client=client or FakeClient();s=scope();s['old_profiles']=[dict(bundle_id=k,native_profile_id=v[0],name=v[1],sha256=v[2],uuid=v[3],owner_private_phone_membership_verified_by_exact_cms_hash=True) for k,v in client.old.items()]
        if mutate:mutate(s)
        with tempfile.TemporaryDirectory() as t,patch.object(p,'OLD',client.old),patch.object(p.time,'sleep'):
            out=pathlib.Path(t)/'output'
            if exist_output:out.mkdir()
            result=p.prepare(client,s,out,NOW,client.decoder,lambda *_:CERT)
            emitted=json.loads((out/'bryan-signing-export-scope.json').read_text())
            self.assertEqual((out/'bryan-build2-profile-manifest.json').stat().st_mode&0o777,0o600)
            return result,emitted,client
    def failure(self,client,code):
        with self.assertRaisesRegex(p.c.GateError,code):self.execute(client)
    def test_exact_two_profile_posts_and_two_widgets_reused(self):
        r,e,f=self.execute();self.assertEqual(len(f.posts),2);self.assertEqual(r['reused_widget_count'],2);self.assertEqual(len(e['adhoc_native_profiles']),4)
        self.assertEqual({v['attributes']['name'] for b in f.posts for v in [b['data']]},{x[1] for x in p.NEW.values()})
        self.assertTrue(all(b['data']['relationships']['devices']['data']==[{'type':'devices','id':DEVICE}] for b in f.posts))
        self.assertNotIn(PHONE,json.dumps(r)+json.dumps(e));self.assertNotIn(DEVICE,json.dumps(r)+json.dumps(e));self.assertFalse(e['watch_hardware_eligibility_verified'])
        keys={'bundle_id','native_profile_id','name','sha256','uuid','profile_type','owner_private_phone_membership_verified_by_exact_cms_hash','native_readback_verified'}
        self.assertTrue(all(set(x)==keys for x in e['adhoc_native_profiles']));self.assertEqual(e['signing_delivery'],'bryan-ad-hoc-export-only')
    def test_all_old_membership_checks_precede_first_post(self):
        r,e,f=self.execute();self.assertEqual(len(f.binds),1);self.assertEqual(f.binds[0],DEVICE)
        self.assertEqual({x[1] for x in f.calls if x[1].startswith('/v1/profiles/') and x[1].endswith('/devices?limit=50')},{'/v1/profiles/'+p.OLD[k][0]+'/devices?limit=50' for k in p.NEW})
    def test_valid_named_profile_reused(self):
        f=FakeClient();f.valid_existing();r,e,f=self.execute(f);self.assertEqual(len(f.posts),1);self.assertEqual(r['new_profile_count'],1)
    def test_invalid_existing_named_profile_no_replacement(self):
        f=FakeClient();d=f.valid_existing();d['Entitlements']['aps-environment']='development';self.failure(f,'production_aps_missing');self.assertEqual(f.posts,[])
    def test_ambiguous_name_stops(self):
        f=FakeClient();f.valid_existing();k=next(iter(f.named));f.named[k]*=2;self.failure(f,'name_ambiguous');self.assertEqual(f.posts,[])
    def test_unknown_post_once_no_retry(self):
        f=FakeClient();f.fail_post=True;self.failure(f,'unknown_stop');self.assertEqual(len(f.posts),1)
    def test_missing_readback_once_no_retry(self):
        f=FakeClient();f.missing_readback=True;self.failure(f,'readback_missing');self.assertEqual(len(f.posts),1)
    def test_get_settles_empty_first_three_exact_fourth_no_second_post(self):
        f=FakeClient();original=f.collection;reads={}
        def lag(path):
            result=original(path)
            if '/profiles?' in path and result and path.split('/')[3] in f.named:
                native=path.split('/')[3];reads[native]=reads.get(native,0)+1
                if reads[native]<=3:return []
            return result
        f.collection=lag;r,e,f=self.execute(f);self.assertEqual(len(f.posts),2);self.assertEqual(set(reads.values()),{4});self.assertTrue(r['complete'])
    def test_all_four_empty_reads_stop_and_keep_known_post_id(self):
        f=FakeClient();f.missing_readback=True;s=scope();s['old_profiles']=[dict(bundle_id=k,native_profile_id=v[0],name=v[1],sha256=v[2],uuid=v[3],owner_private_phone_membership_verified_by_exact_cms_hash=True) for k,v in f.old.items()]
        with tempfile.TemporaryDirectory() as t,patch.object(p,'OLD',f.old),patch.object(p.time,'sleep') as wait:
            out=pathlib.Path(t)/'out'
            with self.assertRaisesRegex(p.c.GateError,'readback_missing'):p.prepare(f,s,out,NOW,f.decoder,lambda *_:CERT)
            self.assertEqual(wait.call_count,3);self.assertEqual(len(f.posts),1)
            actual=json.loads(next(out.glob('*-post-confirmed-private.json')).read_text());self.assertEqual(actual['native_profile_id'],'SYNTHETICNEW1');self.assertFalse(actual['post_retry_allowed'])
    def test_old_wrong_cms_hash_stops(self):
        f=FakeClient();f.resources[next(iter(f.resources))]['attributes']['profileContent']=base64.b64encode(b'wrong').decode();self.failure(f,'old_profile_content_pin_changed');self.assertEqual(f.posts,[])
    def test_old_profile_private_phone_mismatch(self):
        f=FakeClient();last=next(reversed(f.decoded));f.decoded[last]['ProvisionedDevices']=['OTHER-SYNTHETIC-PHONE'];self.failure(f,'private_phone_membership_changed');self.assertEqual(f.posts,[])
    def test_old_profile_multiple_devices(self):
        f=FakeClient();next(iter(f.decoded.values()))['ProvisionedDevices'].append('OTHER-SYNTHETIC-PHONE');self.failure(f,'single_private_phone');self.assertEqual(f.posts,[])
    def test_relationship_hardware_mismatch(self):
        f=FakeClient();next(iter(f.relationships.values()))[0]['attributes']['udid']='OTHER';self.failure(f,'membership_changed');self.assertEqual(f.posts,[])
    def test_relationship_device_resources_disagree(self):
        f=FakeClient();list(f.relationships.values())[1][0]['id']='OTHER';self.failure(f,'relationships_disagree');self.assertEqual(f.posts,[])
    def test_disabled_device_stops(self):
        f=FakeClient();next(iter(f.relationships.values()))[0]['attributes']['status']='DISABLED';self.failure(f,'membership_changed');self.assertEqual(f.posts,[])
    def test_multi_api_devices_stops(self):
        f=FakeClient();next(iter(f.relationships.values())).append({'type':'devices'});self.failure(f,'single_device_relationship');self.assertEqual(f.posts,[])
    def test_owned_bundle_id_changed(self):
        f=FakeClient();f.bundle_mismatch=True;self.failure(f,'owned_bundle_resource_changed');self.assertEqual(f.posts,[])
    def test_push_capability_missing_no_mutation(self):
        f=FakeClient();f.no_push=True;self.failure(f,'existing_push_capability_required');self.assertEqual(f.posts,[])
    def test_wrong_certificate_in_cms(self):
        f=FakeClient();next(iter(f.decoded.values()))['DeveloperCertificates']=[b'wrong'];self.failure(f,'certificate_changed');self.assertEqual(f.posts,[])
    def test_wrong_group(self):
        f=FakeClient();next(iter(f.decoded.values()))['Entitlements']['com.apple.security.application-groups']=['WRONG'];self.failure(f,'group_release');self.assertEqual(f.posts,[])
    def test_debug_profile(self):
        f=FakeClient();next(iter(f.decoded.values()))['Entitlements']['get-task-allow']=True;self.failure(f,'group_release');self.assertEqual(f.posts,[])
    def test_wrong_profile_type(self):
        f=FakeClient();next(iter(f.resources.values()))['attributes']['profileType']='IOS_APP_STORE';self.failure(f,'resource_identity');self.assertEqual(f.posts,[])
    def test_invalid_old_receivers_are_provenance_only_not_exported(self):
        f=FakeClient()
        for ident in p.NEW:f.resources[f.old[ident][0]]['attributes']['profileState']='INVALID'
        r,e,f=self.execute(f);self.assertTrue(r['complete']);self.assertEqual(len(f.posts),2)
        self.assertTrue(all(x['native_profile_state']=='ACTIVE' for x in r['profiles']))
        self.assertFalse({f.old[k][0] for k in p.NEW}&{x['native_profile_id'] for x in e['adhoc_native_profiles']})
    def test_invalid_old_widget_rejected_before_post(self):
        f=FakeClient();f.resources[f.old[p.c.BASE+'.widgets'][0]]['attributes']['profileState']='INVALID';self.failure(f,'state_not_authorized');self.assertEqual(f.posts,[])
    def test_invalid_new_profile_rejected(self):
        f=FakeClient();f.valid_existing();next(iter(f.named.values()))[0]['attributes']['profileState']='INVALID';self.failure(f,'state_not_authorized');self.assertEqual(f.posts,[])
    def test_invalid_created_profile_stops_without_second_post(self):
        f=FakeClient();original=f.create_profile
        def invalid(row):
            result=original(row);next(iter(f.named.values()))[0]['attributes']['profileState']='INVALID';return result
        f.create_profile=invalid;self.failure(f,'state_not_authorized');self.assertEqual(len(f.posts),1)
    def test_invalid_old_receiver_still_requires_exact_cms_pin(self):
        f=FakeClient();resource=f.resources[f.old[p.c.BASE][0]];resource['attributes'].update(profileState='INVALID',profileContent=base64.b64encode(b'changed').decode());self.failure(f,'content_pin_changed');self.assertEqual(f.posts,[])
    def test_unknown_old_state_rejected(self):
        f=FakeClient();f.resources[f.old[p.c.BASE][0]]['attributes']['profileState']='EXPIRED';self.failure(f,'state_not_authorized');self.assertEqual(f.posts,[])
    def test_old_metadata_recorded_privately_without_hardware(self):
        f=FakeClient();f.resources[f.old[p.c.BASE][0]]['attributes']['profileState']='INVALID';s=scope();s['old_profiles']=[dict(bundle_id=k,native_profile_id=v[0],name=v[1],sha256=v[2],uuid=v[3],owner_private_phone_membership_verified_by_exact_cms_hash=True) for k,v in f.old.items()]
        with tempfile.TemporaryDirectory() as t,patch.object(p,'OLD',f.old),patch.object(p.time,'sleep'):
            out=pathlib.Path(t)/'out';p.prepare(f,s,out,NOW,f.decoder,lambda *_:CERT);file=out/(f.old[p.c.BASE][0]+'-old-observation-private.json');r=json.loads(file.read_text())
            self.assertEqual(r['observed_state'],'INVALID');self.assertTrue(r['cms_matches_reviewed_pin']);self.assertEqual(file.stat().st_mode&0o777,0o600);self.assertNotIn(PHONE,file.read_text());self.assertNotIn(DEVICE,file.read_text())
    def test_scope_source_stale(self):
        with self.assertRaisesRegex(p.c.GateError,'source_required'):self.execute(mutate=lambda s:s.update(source_sha=p.c.OLD_SOURCE))
    def test_scope_private_membership_unverified(self):
        with self.assertRaisesRegex(p.c.GateError,'membership_required'):self.execute(mutate=lambda s:s.update(old_four_private_phone_membership_verified=False))
    def test_scope_unapproved_certificate(self):
        with self.assertRaisesRegex(p.c.GateError,'certificate_pin'):self.execute(mutate=lambda s:s.update(certificate_id='OTHER'))
    def test_output_collision_no_post(self):
        f=FakeClient()
        with self.assertRaisesRegex(p.c.GateError,'output_collision'):self.execute(f,exist_output=True)
        self.assertEqual(f.posts,[])
    def test_new_wrong_phone_after_post_stops(self):
        f=FakeClient();old=f.create_profile
        def bad(r):
            value=old(r);raw=base64.b64decode(value['attributes']['profileContent']);f.decoded[raw]['ProvisionedDevices']=['OTHER'];return value
        f.create_profile=bad;self.failure(f,'membership_changed');self.assertEqual(len(f.posts),1)
    def test_new_aps_wrong_platform_stops(self):
        f=FakeClient();old=f.create_profile
        def bad(r):
            value=old(r);d=f.decoded[base64.b64decode(value['attributes']['profileContent'])];d['Entitlements']['com.apple.developer.aps-environment']='production';return value
        f.create_profile=bad;self.failure(f,'unapproved_sensitive');self.assertEqual(len(f.posts),1)
    def test_transport_get_boundary(self):
        client=p.BryanClient('synthetic-no-secret',scope())
        for value in ['/v1/devices','/v1/profiles/UNRELATED','/v1/certificates/OTHER','https://evil.test/v1/profiles/DMWQ2F9XCQ','/v1/profiles/DMWQ2F9XCQ/devices?filter[udid]=X','/v1/bundleIds?filter[identifier]=com.unrelated']:
            self.assertFalse(client.get_allowed(value),value)
        self.assertTrue(client.get_allowed('/v1/profiles/DMWQ2F9XCQ/devices?limit=50'))
    def test_no_post_before_device_binding(self):
        client=p.BryanClient('synthetic-no-secret',scope())
        with self.assertRaisesRegex(p.c.GateError,'private_binding'):client.create_profile(scope()['new_profiles'][0])
    def test_unapproved_post_row(self):
        client=p.BryanClient('synthetic-no-secret',scope());client.bind_approved_device(DEVICE);r=scope()['new_profiles'][0];r['name']='WRONG'
        with self.assertRaisesRegex(p.c.GateError,'private_binding'):client.create_profile(r)
    def test_mutable_source_scope_does_not_broaden_client(self):
        s=scope();client=p.BryanClient('synthetic-no-secret',s);client.bind_approved_device(DEVICE);s['new_profiles'][0]['name']='WRONG'
        with self.assertRaisesRegex(p.c.GateError,'private_binding'):client.create_profile(s['new_profiles'][0])
    def test_expired_profile_stops(self):
        f=FakeClient();next(iter(f.decoded.values()))['ExpirationDate']=NOW-datetime.timedelta(days=1);self.failure(f,'profile_dates_invalid');self.assertEqual(f.posts,[])
    def test_widget_push_not_added(self):
        f=FakeClient();ident=p.c.BASE+'.widgets';raw=base64.b64decode(f.resources[f.old[ident][0]]['attributes']['profileContent']);f.decoded[raw]['Entitlements']['aps-environment']='production';self.failure(f,'old_or_widget_push_changed');self.assertEqual(f.posts,[])
    def test_protected_recipient_required(self):
        with self.assertRaisesRegex(p.c.GateError,'recipient_pin'):self.execute(mutate=lambda s:s.pop('recipient_spki_sha256'))
    def test_export_target_metadata_unchanged(self):
        with self.assertRaisesRegex(p.c.GateError,'minimum_os_changed'):self.execute(mutate=lambda s:s['export_scope']['targets'][0].update(minimum_os='1.0'))
    def test_workflow_owner_dispatch_only_no_raw_upload(self):
        import subprocess
        file=pathlib.Path(__file__).parent/'resale-build2-bryan-push-profiles.yml';text=file.read_text()
        parsed=subprocess.run(['/usr/bin/ruby','-rjson','-ryaml','-e','puts JSON.generate(YAML.safe_load(File.read(ARGV.fetch(0))))',str(file)],check=True,capture_output=True,text=True)
        doc=json.loads(parsed.stdout);job=doc['jobs']['profiles']
        self.assertIn("github.event_name == 'workflow_dispatch'",job['if']);self.assertIn("github.actor == 'h00l1gvn'",job['if']);self.assertIn('github.run_attempt == 1',job['if'])
        self.assertEqual(doc['permissions'],{'contents':'read'})
        uploads=[s for s in job['steps'] if str(s.get('uses','')).startswith('actions/upload-artifact@')];self.assertEqual(len(uploads),1);self.assertIn('-encrypted/',uploads[0]['with']['path'])
        for s in job['steps']:
            if 'run' in s:self.assertIsInstance(s['run'],str)
        self.assertNotIn('MATCH_PASSWORD',text);self.assertNotIn('GH_PAT',text);self.assertNotIn('xcodebuild',text)
    def test_actual_post_transport_unknown_is_one_exact_call(self):
        class Stop:
            def __init__(self):self.calls=[]
            def open(self,req,timeout):self.calls.append(req);raise URLError('synthetic-no-network')
        op=Stop();client=p.BryanClient('synthetic-no-secret',scope(),op);client.bind_approved_device(DEVICE)
        with self.assertRaisesRegex(p.c.GateError,'unknown_stop_no_retry'):client.create_profile(scope()['new_profiles'][0])
        self.assertEqual(len(op.calls),1);self.assertEqual(op.calls[0].get_method(),'POST');self.assertEqual(op.calls[0].full_url,'https://api.appstoreconnect.apple.com/v1/profiles')
        self.assertEqual(json.loads(op.calls[0].data),p.request(scope()['new_profiles'][0],DEVICE))

if __name__=='__main__':unittest.main()
