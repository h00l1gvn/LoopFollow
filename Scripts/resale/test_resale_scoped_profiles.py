import base64, copy, importlib.util, json, os, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError
import resale_scoped_profiles as profiles
import resale_apple_audit as audit

SCOPE=json.loads(Path(__file__).with_name('signing-export-scope.json').read_text())
class FakeClient:
    def __init__(self,reuse=False): self.calls=[];self.reuse=reuse;self.created=set()
    def collection(self,path):
        self.calls.append(('GET',path))
        if '/profiles?' in path:
            identifier=path.split('/')[3]
            target=next(t for t in SCOPE['targets'] if t['target']==identifier)
            return [resource(target)] if self.reuse or target['target'] in self.created else []
        from urllib.parse import parse_qs,urlparse
        identifier=parse_qs(urlparse(path).query)['filter[identifier]'][0]
        target=next(t for t in SCOPE['targets'] if t['bundle_id']==identifier)
        return [{'id':target['target'],'attributes':{'identifier':identifier}}]
    def create_profile(self,target,native_id):
        self.calls.append(('POST',profiles.create_request(target,native_id)))
        self.created.add(target['target'])
        return resource(target)
def resource(target):
    return {'id':target['target'],'attributes':{'name':profiles.profile_name(target),'profileType':target['profile_type'],'profileState':'ACTIVE','expirationDate':'2027-01-01T00:00:00Z','profileContent':base64.b64encode(target['target'].encode()).decode()}}
def decode(content):
    name=base64.b64decode(content).decode();target=next(t for t in SCOPE['targets'] if t['target']==name)
    return {'UUID':'12345678-1234-1234-1234-123456789ABC','Name':profiles.profile_name(target),'TeamIdentifier':[profiles.TEAM],'ApplicationIdentifierPrefix':[profiles.TEAM],'ExpirationDate':datetime.now(timezone.utc)+timedelta(days=2),'DeveloperCertificates':[b'synthetic DER'],'Entitlements':{'application-identifier':profiles.TEAM+'.'+target['bundle_id'],'com.apple.developer.team-identifier':profiles.TEAM,'com.apple.security.application-groups':[profiles.GROUP],'get-task-allow':False}}
class Guards(unittest.TestCase):
    def test_exact_observed_mac_permission_superset_only_and_ios_remains_literal(self):
        target=next(t for t in SCOPE['targets'] if t['target']=='ResaleBurrowMac');r=resource(target);v=decode(r['attributes']['profileContent']);v['Entitlements'].pop('application-identifier');v['Entitlements']['com.apple.application-identifier']=profiles.TEAM+'.'+target['bundle_id'];v['Entitlements']['com.apple.security.application-groups']=[profiles.GROUP,profiles.TEAM+'.*']
        row,_=profiles.validate_profile(r,target,b'synthetic DER',lambda _:v);self.assertTrue(row['verified'])
        for groups in ([profiles.TEAM+'.*'],[profiles.GROUP,'OTHERTEAM.*'],[profiles.GROUP,profiles.TEAM+'.*','group.other'],[profiles.GROUP,profiles.GROUP]):
            v['Entitlements']['com.apple.security.application-groups']=groups
            with self.assertRaises(audit.AuditError):profiles.validate_profile(r,target,b'synthetic DER',lambda _:v)
        ios=SCOPE['targets'][0];v=decode(resource(ios)['attributes']['profileContent']);v['Entitlements']['com.apple.security.application-groups']=[profiles.GROUP,profiles.TEAM+'.*']
        with self.assertRaises(audit.AuditError):profiles.validate_profile(resource(ios),ios,b'synthetic DER',lambda _:v)
    def test_scope_cannot_add_target_change_certificate_or_profile_type(self):
        for mutate in (lambda s:s['targets'].append(dict(s['targets'][0])),lambda s:s['targets'][0].update(profile_type='IOS_APP_ADHOC'),lambda s:s['certificates']['distribution'].update(certificate_id='OTHER'),lambda s:s['targets'][0].update(target='../unrelated')):
            changed=copy.deepcopy(SCOPE);mutate(changed)
            with self.assertRaises(audit.AuditError):profiles.validate_scope(changed)
    def test_requests_exact_seven_ids_one_existing_cert_and_no_devices(self):
        profiles.validate_scope(SCOPE)
        for target in SCOPE['targets']:
            body=profiles.create_request(target,'NATIVE_RESOURCE')
            self.assertEqual(body['data']['type'],'profiles')
            self.assertEqual(body['data']['relationships']['certificates']['data'],[{'type':'certificates','id':profiles.CERT_ID}])
            self.assertNotIn('devices',body['data']['relationships'])
            self.assertEqual(body['data']['attributes']['profileType'],profiles.EXPECTED[target['bundle_id']])
        with self.assertRaises(audit.AuditError):profiles.create_request({'bundle_id':'com.other.app','profile_type':'IOS_APP_STORE'},'ID')
    def test_create_only_seven_and_encrypted_bytes_roundtrip(self):
        client=FakeClient()
        with tempfile.TemporaryDirectory() as tmp,patch.object(profiles,'verified_certificate',return_value=b'synthetic DER'):
            output=Path(tmp)/'profiles';result=profiles.prepare_profiles(client,SCOPE,output,'synthetic-only',decode)
            self.assertEqual(result['profile_count'],7)
            self.assertEqual(sum(method=='POST' for method,_ in client.calls),7)
            self.assertTrue(all(row['action']=='created' for row in result['profiles']))
            for row in result['profiles']:
                raw=(output/row['path']).read_bytes()
                self.assertEqual(list(audit.decrypt_match_candidates(raw,'synthetic-only')),[row['target'].encode()])
                self.assertEqual((output/row['path']).stat().st_mode&0o777,0o600)
            self.assertFalse(result['match_write_performed']);self.assertFalse(result['certificate_created'])
    def test_reuse_has_no_post_and_invalid_named_profile_never_replaced(self):
        client=FakeClient(reuse=True)
        with tempfile.TemporaryDirectory() as tmp,patch.object(profiles,'verified_certificate',return_value=b'synthetic DER'):
            result=profiles.prepare_profiles(client,SCOPE,Path(tmp)/'profiles','synthetic-only',decode)
        self.assertFalse(any(method=='POST' for method,_ in client.calls));self.assertTrue(all(r['action']=='reused' for r in result['profiles']))
        def invalid(content):
            value=decode(content);value['Entitlements']['com.apple.security.application-groups']=['group.unrelated'];return value
        client=FakeClient(reuse=True)
        with tempfile.TemporaryDirectory() as tmp,patch.object(profiles,'verified_certificate',return_value=b'synthetic DER'):
            with self.assertRaises(audit.AuditError):profiles.prepare_profiles(client,SCOPE,Path(tmp)/'profiles','synthetic-only',invalid)
        self.assertFalse(any(method=='POST' for method,_ in client.calls))
    def test_wrong_cert_and_devices_or_extra_group_are_rejected(self):
        target=SCOPE['targets'][0]
        for change in (lambda v:v.update(DeveloperCertificates=[b'other DER']),lambda v:v.update(ProvisionedDevices=['synthetic UDID']),lambda v:v['Entitlements'].update({'com.apple.security.application-groups':[profiles.GROUP,'group.other']})):
            value=decode(resource(target)['attributes']['profileContent']);change(value)
            with self.assertRaises(audit.AuditError):profiles.validate_profile(resource(target),target,b'synthetic DER',lambda _:value)
    def test_unknown_create_outcome_not_retried_or_body_leaked(self):
        class Opener:
            def __init__(self):self.calls=[]
            def open(self,request,timeout):self.calls.append(request);raise URLError('synthetic-secret-body')
        opener=Opener();client=profiles.ProfileClient('https://api.appstoreconnect.apple.com','synthetic-only',opener)
        with self.assertRaises(audit.AuditError) as err:client.create_profile(SCOPE['targets'][0],'NATIVE_RESOURCE')
        self.assertEqual(len(opener.calls),1);self.assertEqual(opener.calls[0].get_method(),'POST')
        self.assertNotIn('synthetic-secret-body',str(err.exception))
if __name__=='__main__':unittest.main()
