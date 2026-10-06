import base64,hashlib,tempfile,unittest
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
import get_resale_adhoc_profiles as get
import validate_adhoc_profiles as a
import resale_apple_audit as audit

class Guards(unittest.TestCase):
    def fixture(self):
        native={str(i):(bundle,identifier,name) for i,(bundle,(identifier,name)) in enumerate(a.EXPECTED.items())};calls=[];wrong={'id':False,'device':False};profiles={}
        for index,(bundle,identifier,name) in native.items():
            raw=identifier.encode();profiles[identifier]={'Name':name,'UUID':'00000000-0000-0000-0000-'+str(index).zfill(12),'TeamIdentifier':[a.TEAM],'ApplicationIdentifierPrefix':[a.TEAM],'Entitlements':{'application-identifier':a.TEAM+'.'+bundle,'com.apple.developer.team-identifier':a.TEAM,'com.apple.security.application-groups':[a.GROUP],'get-task-allow':False},'CreationDate':datetime(2026,10,6,tzinfo=timezone.utc),'ExpirationDate':datetime(2027,9,15,tzinfo=timezone.utc),'DeveloperCertificates':[b'fixture certificate'],'ProvisionedDevices':['SYNTHETIC-PRIVATE-DEVICE']}
        class Client:
            def collection(self,path):
                calls.append(('GET',path))
                if path.startswith('/v1/bundleIds?'):
                    from urllib.parse import parse_qs,urlparse
                    bundle=parse_qs(urlparse(path).query)['filter[identifier]'][0];bid=next(i for i,t in native.items() if t[0]==bundle);return [{'id':bid,'attributes':{'identifier':bundle}}]
                bundle,identifier,name=native[path.split('/')[3]]
                if wrong['device'] and bundle.endswith('.widgets'):profiles[identifier]['ProvisionedDevices']=['DIFFERENT-PRIVATE-DEVICE']
                return [{'id':'WRONG' if wrong['id'] else identifier,'attributes':{'name':name,'profileType':'IOS_APP_ADHOC','profileState':'ACTIVE','profileContent':base64.b64encode(identifier.encode()).decode()}}]
        return Client(),profiles,calls,wrong
    def test_exact_four_get_only_private_manifest_does_not_retain_device(self):
        client,p,calls,_=self.fixture()
        with tempfile.TemporaryDirectory() as tmp,patch.object(get.profiles,'verified_certificate',return_value=b'fixture certificate'),patch.object(a,'CERT_SHA',hashlib.sha256(b'fixture certificate').hexdigest()):
            reviewed=[{'bundle_id':b,'native_profile_id':i,'name':n,'sha256':hashlib.sha256(i.encode()).hexdigest()} for b,(i,n) in a.EXPECTED.items()]
            out=Path(tmp)/'private';result=get.retrieve(client,out,'a'*40,reviewed,lambda text:p[base64.b64decode(text).decode()])
            self.assertEqual(len(result['profiles']),4);self.assertTrue(all(v['path'].startswith('profiles/') for v in result['profiles']));self.assertTrue(all(m=='GET' for m,_ in calls));self.assertNotIn('SYNTHETIC-PRIVATE-DEVICE',(out/'adhoc-profile-manifest.json').read_text());self.assertEqual((out/'adhoc-profile-manifest.json').stat().st_mode&0o777,0o600)
    def test_changed_resource_and_phone_or_nonfrozen_delivery_rejected(self):
        client,p,_,wrong=self.fixture()
        reviewed=[{'bundle_id':b,'native_profile_id':i,'name':n,'sha256':hashlib.sha256(i.encode()).hexdigest()} for b,(i,n) in a.EXPECTED.items()]
        with tempfile.TemporaryDirectory() as tmp,patch.object(get.profiles,'verified_certificate',return_value=b'fixture certificate'),patch.object(a,'CERT_SHA',hashlib.sha256(b'fixture certificate').hexdigest()):
            wrong['id']=True
            with self.assertRaises(audit.AuditError):get.retrieve(client,Path(tmp)/'wrong-id','a'*40,reviewed,lambda text:p[base64.b64decode(text).decode()])
            wrong['id']=False;wrong['device']=True
            with self.assertRaises(audit.AuditError):get.retrieve(client,Path(tmp)/'wrong-device','a'*40,reviewed,lambda text:p[base64.b64decode(text).decode()])
            with self.assertRaises(audit.AuditError):get.retrieve(client,Path(tmp)/'not-frozen','latest',reviewed,lambda _:None)
            wrong['device']=False
            reviewed[0]['sha256']='0'*64
            with self.assertRaises(audit.AuditError):get.retrieve(client,Path(tmp)/'changed-raw','a'*40,reviewed,lambda _:None)
if __name__=='__main__':unittest.main()
