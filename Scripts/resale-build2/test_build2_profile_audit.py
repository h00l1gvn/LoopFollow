"""Owned-scope/privacy/GET guards. No actual certificate or account operation."""
import base64,copy,datetime,hashlib,json,unittest
from unittest.mock import patch
import build2_profile_audit as p
NOW=datetime.datetime(2026,10,6,17,tzinfo=datetime.timezone.utc)
CERT=b'ONLY SYNTHETIC PROFILE TEST CERTIFICATE'

def fixture(identifier):
    e={'application-identifier':p.c.TEAM+'.'+identifier,'com.apple.developer.team-identifier':p.c.TEAM,'com.apple.security.application-groups':[p.c.GROUP]}
    if identifier in p.c.PUSH:e[p.c.PUSH[identifier]]='production'
    cms={'TeamIdentifier':[p.c.TEAM],'ApplicationIdentifierPrefix':[p.c.TEAM],'CreationDate':NOW-datetime.timedelta(days=1),'ExpirationDate':NOW+datetime.timedelta(days=30),'Entitlements':e,'DeveloperCertificates':[CERT],'UUID':'00000000-1111-2222-3333-444444444444'}
    resource={'id':'NATIVEPROFILE','attributes':{'profileContent':base64.b64encode(b'SYNTHETIC CMS').decode(),'profileType':p.EXPECTED[identifier],'profileState':'ACTIVE','name':'PRIVATE SOURCE NAME NOT RETAINED'}}
    return resource,cms

class Client:
    def __init__(self):self.paths=[];self.missing_cap=False;self.cms={}
    def collection(self,path):
        self.paths.append(path)
        if path.startswith('/v1/bundleIds?'):
            from urllib.parse import parse_qs,urlparse
            i=parse_qs(urlparse(path).query)['filter[identifier]'][0];return [{'id':'ID'+str(list(p.EXPECTED).index(i)),'attributes':{'identifier':i}}]
        ident=list(p.EXPECTED)[int(path.split('/')[3][2:])]
        if '/bundleIdCapabilities?' in path:return [{'attributes':{'capabilityType':v}} for v in ['APP_GROUPS']+([] if self.missing_cap else ['PUSH_NOTIFICATIONS'])]
        r,cms=fixture(ident);r['id']='PROFILE'+str(list(p.EXPECTED).index(ident));r['attributes']['profileContent']=base64.b64encode(ident.encode()).decode();self.cms[r['attributes']['profileContent']]=cms
        # An ad-hoc profile/hardware payload is intentionally never decoded.
        return [r,{'id':'ADHOC','attributes':{'profileType':'IOS_APP_ADHOC','profileContent':'DO NOT READ PRIVATE HARDWARE'}}]

class ProfileAudit(unittest.TestCase):
    def certificate_resource(self,team=p.c.TEAM,expired=False):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'SYNTHETIC TEST'),x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME,team)])
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(NOW-datetime.timedelta(days=2)).not_valid_after(NOW-datetime.timedelta(seconds=1) if expired else NOW+datetime.timedelta(days=30)).sign(key,hashes.SHA256())
        raw=cert.public_bytes(serialization.Encoding.DER)
        return {'id':p.CERT_ID,'attributes':{'certificateType':'DISTRIBUTION','certificateContent':base64.b64encode(raw).decode()}},raw
    def test_certificate_identity_fingerprint_team_and_current_date_required(self):
        class CertClient:
            def get(self,path):self.path=path;return {'data':self.resource}
        client=CertClient();client.resource,raw=self.certificate_resource()
        with patch.object(p.c,'CERT_SHA',hashlib.sha256(raw).hexdigest()):self.assertEqual(p.certificate(client,NOW),raw)
        self.assertEqual(client.path,'/v1/certificates/'+p.CERT_ID)
        with self.assertRaisesRegex(p.c.GateError,'approved_certificate_fingerprint_mismatch'):p.certificate(client,NOW)
        for team,expired in [('OTHER',False),(p.c.TEAM,True)]:
            client.resource,raw=self.certificate_resource(team,expired)
            with patch.object(p.c,'CERT_SHA',hashlib.sha256(raw).hexdigest()):
                with self.assertRaisesRegex(p.c.GateError,'certificate_team_or_validity_mismatch'):p.certificate(client,NOW)
    def test_unexpected_certificate_type_resource_or_content_rejected(self):
        class CertClient:
            def get(self,path):return {'data':self.resource}
        client=CertClient();r,_=self.certificate_resource()
        for value in [{**r,'id':'OTHER'},{**r,'attributes':{**r['attributes'],'certificateType':'DEVELOPMENT'}},{**r,'attributes':{**r['attributes'],'certificateContent':'BAD'}}]:
            client.resource=value
            with self.assertRaises(p.c.GateError):p.certificate(client,NOW)
    def test_exact_get_scope_and_no_private_profile_or_device_values_retained(self):
        client=Client()
        with patch.object(p,'certificate',return_value=CERT):r=p.run(client,NOW,lambda raw:client.cms[raw])
        self.assertEqual(len(r['exact_targets']),7);self.assertTrue(r['all_profile_ready']);self.assertEqual(r['account_mutations'],0)
        self.assertEqual(len(client.paths),21);self.assertTrue(all(s.startswith('/v1/bundleIds') for s in client.paths))
        raw=json.dumps(r);self.assertNotIn('PRIVATE SOURCE NAME',raw);self.assertNotIn('Hardware',raw);self.assertNotIn('DO NOT READ',raw);self.assertNotIn(base64.b64encode(CERT).decode(),raw)
    def test_missing_capability_is_not_ready_even_with_production_profile(self):
        client=Client();client.missing_cap=True
        with patch.object(p,'certificate',return_value=CERT):r=p.run(client,NOW,lambda raw:client.cms[raw])
        self.assertFalse(r['all_receiving_push_capability_ready']);self.assertTrue(r['all_profile_ready'])
    def test_missing_and_development_push_never_reuses_profile(self):
        for v in [None,'development']:
            r,cms=fixture(p.c.BASE);cms['Entitlements']['aps-environment']=v
            self.assertFalse(p.profile_evidence(r,p.c.BASE,CERT,NOW,lambda _:cms)['reusable_for_build2'])
    def test_wrong_owner_certificate_expiry_and_hardware_profiles_not_reused(self):
        r,cms=fixture(p.c.BASE)
        for key,value in [('DeveloperCertificates',[b'OTHER']),('ProvisionedDevices',['PRIVATE-HARDWARE']),('TeamIdentifier',['OTHER']),('ExpirationDate',NOW-datetime.timedelta(seconds=1))]:
            d={**cms,key:value};self.assertFalse(p.profile_evidence(r,p.c.BASE,CERT,NOW,lambda _:d)['reusable_for_build2'])
    def test_mac_permission_shape_preserved_binary_group_not_widened(self):
        r,cms=fixture(p.c.BASE+'.mac');cms['Entitlements']['com.apple.security.application-groups']=[p.c.GROUP,p.c.TEAM+'.*']
        self.assertTrue(p.profile_evidence(r,p.c.BASE+'.mac',CERT,NOW,lambda _:cms)['reusable_for_build2'])
        cms['Entitlements']['com.apple.security.application-groups'].append('group.unrelated');self.assertFalse(p.profile_evidence(r,p.c.BASE+'.mac',CERT,NOW,lambda _:cms)['reusable_for_build2'])
    def test_decode_failure_cannot_be_empty_success(self):
        r,_=fixture(p.c.BASE)
        with self.assertRaisesRegex(p.c.GateError,'profile_cms_decode_failed'):p.profile_evidence(r,p.c.BASE,CERT,NOW,lambda _:None)
    def test_get_transport_rejects_unowned_origin_route_and_method_capability(self):
        client=p.audit.ReadClient('https://api.appstoreconnect.apple.com','SYNTHETIC TOKEN')
        for path in ['https://other.example/v1/certificates/9K5USY2222','/v1/users','/v1/profiles/PRIVATE']:
            with self.assertRaises(p.audit.AuditError):client.get(path)
        self.assertFalse(hasattr(client,'create_profile'));self.assertFalse(hasattr(client,'post'));self.assertFalse(hasattr(client,'delete'))

if __name__=='__main__':unittest.main()
