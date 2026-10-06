import base64
import importlib.util
import json
import os
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('audit', Path(__file__).with_name('resale_apple_audit.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

class Response:
    def __init__(self, value): self.value = value
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, limit): return json.dumps(self.value).encode()

class Opener:
    def __init__(self, values): self.values, self.requests = iter(values), []
    def open(self, request, timeout):
        self.requests.append(request)
        return Response(next(self.values))

class Guards(unittest.TestCase):
    def test_workflow_yaml_syntax_and_only_owned_audit_branch(self):
        workflow=Path(__file__).with_name('resale-get-only-preflight.yml')
        if not workflow.exists(): workflow=Path(__file__).parents[2]/'.github/workflows/resale-get-only-preflight.yml'
        result=subprocess.run(['ruby','-ryaml','-rjson','-e','puts JSON.generate(YAML.load(File.read(ARGV[0])))',str(workflow)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,'Workflow YAML must parse before a push')
        data=json.loads(result.stdout)
        triggers=data.get('on') or data.get('true')
        self.assertEqual(triggers['push']['branches'],['codex/resale-burrow-get-only-preflight'])
        self.assertEqual(data['permissions'],{'contents':'read'})
        self.assertEqual(list(data['jobs']),['audit'])
        self.assertNotIn('pull_request',triggers)
        self.assertNotIn('pull_request_target',triggers)

    def test_only_get_and_owned_host(self):
        opener = Opener([{'data':[]}])
        client = audit.ReadClient('https://api.appstoreconnect.apple.com', 'synthetic', opener)
        client.get('/v1/bundleIds?filter%5Bidentifier%5D=com.julienbell.ResaleBurrow')
        self.assertEqual(opener.requests[0].get_method(), 'GET')
        for url in ['https://evil.invalid/v1/bundleIds', '/v1/users', '/v1/profiles', '/v1/bundleIds?filter%5Bidentifier%5D=com.other.app']:
            with self.assertRaises(audit.AuditError): client.get(url)
        self.assertEqual(len(opener.requests), 1)

    def test_pagination_cannot_escape_target(self):
        opener = Opener([{'data':[], 'links':{'next':'/v1/bundleIds/UNRELATED/profiles'}}])
        client = audit.ReadClient('https://api.appstoreconnect.apple.com', 'synthetic', opener)
        with self.assertRaises(audit.AuditError):
            client.collection('/v1/bundleIds?filter%5Bidentifier%5D=com.julienbell.ResaleBurrow')
        self.assertEqual(len(opener.requests),1)

    def test_mac_exact_team_type_and_group(self):
        item = next(t for t in audit.CONFIG['targets'] if t['target']=='ResaleBurrowMac')
        profile = {'TeamIdentifier':[audit.CONFIG['team']], 'ExpirationDate':datetime.now(timezone.utc)+timedelta(days=2), 'Entitlements':{'com.apple.application-identifier':audit.CONFIG['team']+'.'+item['bundle_id'], 'get-task-allow':False, 'com.apple.security.application-groups':[audit.GROUP]}}
        resource={'attributes':{'profileType':'MAC_APP_STORE','profileState':'ACTIVE','profileContent':'synthetic'}}
        requirements=audit.TARGETS['ResaleBurrowMac']
        result=audit.profile_summary(resource,item['bundle_id'],requirements,audit.CONFIG['team'],lambda _:profile)
        self.assertTrue(result['productionRequirementsMet'])
        resource['attributes']['profileType']='IOS_APP_STORE'
        self.assertFalse(audit.profile_summary(resource,item['bundle_id'],requirements,audit.CONFIG['team'],lambda _:profile)['productionRequirementsMet'])
        resource['attributes']['profileType']='MAC_APP_STORE'
        profile['Entitlements'].pop('com.apple.security.application-groups')
        self.assertFalse(audit.profile_summary(resource,item['bundle_id'],requirements,audit.CONFIG['team'],lambda _:profile)['productionRequirementsMet'])

    def test_match_master_mac_extension_no_profile_blob(self):
        class Client:
            calls=[]
            def get(self,path):
                self.calls.append(path)
                if '/git/trees/' in path:
                    return {'tree':[{'path':'profiles/appstore/AppStore_com.julienbell.ResaleBurrow.mac.provisionprofile','type':'blob','sha':'a'*40}]}
                return {'private':True,'default_branch':'main'}
        client=Client()
        with patch.dict(os.environ,{},clear=True): result=audit.match_metadata(client,'h00l1gvn')
        self.assertEqual(result['encryptedProfileCounts']['ResaleBurrowMac']['appStore'],1)
        self.assertTrue(any('/git/trees/master?' in p for p in client.calls))
        self.assertFalse(any('/git/blobs/' in p for p in client.calls))

    def test_match_v2_authentication_and_wrong_password(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import hashlib
        salt=b'12345678'; password='synthetic-only'
        keyiv=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,10000,68)
        ciphertext=AESGCM(keyiv[:32]).encrypt(keyiv[32:44],b'synthetic private material',keyiv[44:])
        encoded=base64.b64encode(b'match_encrypted_v2__'+salt+ciphertext[-16:]+ciphertext[:-16])
        self.assertEqual(list(audit.decrypt_match_candidates(encoded,password)),[b'synthetic private material'])
        with self.assertRaises(Exception): list(audit.decrypt_match_candidates(encoded,'incorrect'))

    def test_certificate_types_do_not_widen_to_development(self):
        self.assertEqual(audit.eligible_certificate_classes('DISTRIBUTION'),('distribution','mac_app_distribution'))
        self.assertEqual(audit.eligible_certificate_classes('IOS_DISTRIBUTION'),('distribution',))
        self.assertEqual(audit.eligible_certificate_classes('MAC_INSTALLER_DISTRIBUTION'),('mac_installer_distribution',))
        self.assertEqual(audit.eligible_certificate_classes('DEVELOPMENT'),())

    def test_certificate_private_key_team_and_expiry(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import NameOID
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic only'),x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,audit.CONFIG['team'])])
        now=datetime.now(timezone.utc)
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=2)).sign(key,hashes.SHA256())
        data=pkcs12.serialize_key_and_certificates(b'synthetic',key,cert,None,serialization.NoEncryption())
        self.assertTrue(audit.certificate_key_check(data,audit.CONFIG['team']))
        self.assertFalse(audit.certificate_key_check(data,'WRONGTEAM1'))
        class BlobClient:
            def get(self,path): return {'encoding':'base64','content':base64.b64encode(b'encrypted synthetic input').decode()}
        class AppleClient:
            native_type='DEVELOPMENT'
            def get(self,path):
                return {'data':{'id':'SYNTHETIC','attributes':{'certificateContent':base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),'certificateType':self.native_type}}}
        apple=AppleClient()
        entries=[{'path':'certs/distribution/SYNTHETIC.p12','sha':'b'*40}]
        with patch.dict(os.environ,{'MATCH_PASSWORD':'synthetic-only'}), patch.object(audit,'decrypt_match_candidates',lambda *_:iter([data])):
            rejected=audit.audit_existing_certificate_keys(BlobClient(),entries,apple)
            self.assertEqual(rejected['selected'],{})
            apple.native_type='DISTRIBUTION'
            accepted=audit.audit_existing_certificate_keys(BlobClient(),entries,apple)
        self.assertEqual(accepted['selected']['distribution']['certificate_id'],'SYNTHETIC')
        self.assertEqual(set(accepted['selected']['distribution']),{'certificate_id','sha256','type','expires_at','existing_private_key_challenge_verified','exact_current_apple_certificate_verified'})
        self.assertNotIn('PRIVATE KEY',json.dumps(accepted))
        self.assertNotIn('synthetic only',json.dumps(accepted))
        expired=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(2).not_valid_before(now-timedelta(days=3)).not_valid_after(now-timedelta(days=1)).sign(key,hashes.SHA256())
        expired_data=pkcs12.serialize_key_and_certificates(b'synthetic',key,expired,None,serialization.NoEncryption())
        self.assertFalse(audit.certificate_key_check(expired_data,audit.CONFIG['team']))

    @staticmethod
    def material(team=None, expired=False):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic-contact-must-not-escape'),x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,team or audit.CONFIG['team'])])
        now=datetime.now(timezone.utc)
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=3)).not_valid_after(now+timedelta(days=-1 if expired else 2)).sign(key,hashes.SHA256())
        return key,cert

    @staticmethod
    def encrypted_material(raw, password='synthetic-only'):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import hashlib
        salt=b'12345678'
        keyiv=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,10000,68)
        value=AESGCM(keyiv[:32]).encrypt(keyiv[32:44],raw,keyiv[44:])
        return base64.b64encode(b'match_encrypted_v2__'+salt+value[-16:]+value[:-16])

    def pem_pair_fixture(self, certificate_override=None, paired_path='certs/distribution/SYNTHETIC.cer', apple_id='SYNTHETIC'):
        from cryptography.hazmat.primitives import serialization
        key,cert=self.material()
        pem=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
        der=(certificate_override or cert).public_bytes(serialization.Encoding.DER)
        blobs={'a'*40:self.encrypted_material(pem),'b'*40:self.encrypted_material(der)}
        entries=[{'path':'certs/distribution/SYNTHETIC.p12','sha':'a'*40},{'path':paired_path,'sha':'b'*40}]
        calls=[]
        class BlobClient:
            def get(self,path):
                calls.append(path)
                raw=blobs[path.rsplit('/',1)[-1]]
                return {'encoding':'base64','content':base64.b64encode(raw).decode()}
        class AppleClient:
            def get(self,path):
                calls.append(path)
                return {'data':{'id':apple_id,'attributes':{'certificateContent':base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),'certificateType':'DISTRIBUTION'}}}
        return BlobClient(),entries,AppleClient(),calls

    def test_fastlane_pem_p12_exact_sibling_der_and_safe_stage_counts(self):
        client,entries,apple,calls=self.pem_pair_fixture()
        with patch.dict(os.environ,{'MATCH_PASSWORD':'synthetic-only'}):
            result=audit.audit_existing_certificate_keys(client,entries,apple)
        self.assertTrue(result['distribution'])
        self.assertTrue(result['mac_app_distribution'])
        self.assertEqual(result['selected']['distribution']['certificate_id'],'SYNTHETIC')
        self.assertEqual(result['stage_counts']['verified_pem_with_paired_certificate'],1)
        for stage in ('private_key_blob_get_succeeded','paired_certificate_blob_get_succeeded','private_key_decrypt_succeeded','paired_certificate_decrypt_succeeded','certificate_team_verified','certificate_dates_verified','private_key_certificate_match','private_key_challenge_verified','current_apple_certificate_fingerprint_verified'):
            self.assertEqual(result['stage_counts'][stage],1)
        self.assertEqual(result['failure_counts'],{})
        self.assertEqual(len(calls),3)
        rendered=json.dumps(result)
        for forbidden in ('synthetic-contact-must-not-escape','PRIVATE KEY','synthetic-only','BEGIN CERTIFICATE'):
            self.assertNotIn(forbidden,rendered)

    def test_pem_requires_exact_sibling_not_different_certificate_path(self):
        for path in ('certs/distribution/OTHER.cer','certs/mac_app_distribution/SYNTHETIC.cer'):
            client,entries,apple,calls=self.pem_pair_fixture(paired_path=path)
            with patch.dict(os.environ,{'MATCH_PASSWORD':'synthetic-only'}):
                result=audit.audit_existing_certificate_keys(client,entries,apple)
            self.assertEqual(result['selected'],{})
            self.assertEqual(result['failure_counts']['paired_certificate_missing'],1)
            self.assertEqual(len(calls),1)

    def test_pair_mismatch_wrong_team_and_expiry_have_bounded_reasons(self):
        from cryptography.hazmat.primitives import serialization
        key,cert=self.material()
        pem=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
        for reason,other in (('private_key_certificate_mismatch',self.material()[1]),('certificate_team_mismatch',self.material('WRONGTEAM1')[1]),('certificate_outside_validity',self.material(expired=True)[1])):
            diagnostics={}
            self.assertFalse(audit.certificate_key_check(pem,audit.CONFIG['team'],other.public_bytes(serialization.Encoding.DER),diagnostics))
            self.assertEqual(diagnostics['failure_counts'],{reason:1})
            self.assertNotIn('synthetic-contact-must-not-escape',json.dumps(diagnostics))

    def test_current_certificate_id_mismatch_and_decrypt_failure_are_not_invalid_key_claims(self):
        client,entries,apple,calls=self.pem_pair_fixture(apple_id='DIFFERENT')
        with patch.dict(os.environ,{'MATCH_PASSWORD':'synthetic-only'}):
            result=audit.audit_existing_certificate_keys(client,entries,apple)
        self.assertEqual(result['selected'],{})
        self.assertEqual(result['failure_counts']['current_apple_certificate_id_mismatch'],1)
        client,entries,apple,calls=self.pem_pair_fixture()
        with patch.dict(os.environ,{'MATCH_PASSWORD':'wrong-password'}):
            result=audit.audit_existing_certificate_keys(client,entries,apple)
        self.assertEqual(result['selected'],{})
        self.assertEqual(result['failure_counts']['private_key_decrypt_or_encoding_failed'],1)
        self.assertFalse(any('/v1/certificates/' in value for value in calls))
        self.assertNotIn('invalid key',json.dumps(result).lower())


if __name__=='__main__': unittest.main()
