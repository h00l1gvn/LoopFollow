#!/usr/bin/env python3
"""Read-only exact native Store profiles and immutable existing certificate restoration."""
from __future__ import annotations
import argparse,base64,datetime,hashlib,json,os,re
from urllib.request import Request,build_opener
from urllib.error import HTTPError,URLError
from pathlib import Path
import build2_contract as c
import build2_profile_audit as ap
import resale_apple_audit as audit
import validate_resale_export as validation
MATCH_COMMIT='4d7f92fe5c81c32823e8ace5aca316ee98c8a53e'
PREFIX='/repos/h00l1gvn/Match-Secrets'
INSTALLER_ID='WBR8H2GCGZ'
INSTALLER_SHA='99d5b88d90d30283082420947296a6afa8e784cd5df9781c9eade2f7720f4df2'

class MaterialReadClient:
    def __init__(self,origin,token,scope=None,opener=None):
        c.require(origin in ['https://api.github.com','https://api.appstoreconnect.apple.com'],'unapproved_material_origin');self.origin=origin;self.token=token;self.scope=scope;self.opener=opener or build_opener(audit.NoRedirect())
    def get(self,path):
        if self.origin=='https://api.github.com':
            permitted=(path==PREFIX+'/git/commits/'+MATCH_COMMIT or re.fullmatch(re.escape(PREFIX)+r'/git/(trees|blobs)/[0-9a-f]{40}(?:[?]recursive=1)?',path))
        else:
            permitted=path in {'/v1/certificates/'+ap.CERT_ID,'/v1/certificates/'+INSTALLER_ID}|{'/v1/profiles/'+r['native_profile_id'] for r in self.scope['native_profiles']}
        c.require(permitted,'unapproved_material_get')
        req=Request(self.origin+path,headers={'Authorization':'Bearer '+self.token,'Accept':'application/json','User-Agent':'ResaleBurrow-build2-exact-material-GET'},method='GET')
        try:
            with self.opener.open(req,timeout=45) as response:raw=response.read(16*1024**2+1)
            c.require(len(raw)<=16*1024**2,'material_response_bound');value=json.loads(raw);c.require(isinstance(value,dict),'material_response_shape');return value
        except HTTPError as e:raise c.GateError('material_get_http_'+str(e.code)) from None
        except (URLError,TimeoutError,OSError,ValueError):raise c.GateError('material_get_unavailable') from None

class CertificateReadClient(MaterialReadClient):
    def __init__(self,token,opener=None):super().__init__('https://api.github.com',token,opener=opener)

class ProfileReadClient(MaterialReadClient):
    def __init__(self,token,scope,opener=None):super().__init__('https://api.appstoreconnect.apple.com',token,scope,opener)


def private_bytes(path,raw):
    path=Path(path);c.require(not path.exists() and not path.is_symlink(),'private_material_collision')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as h:h.write(raw)

def plan(scope,family):
    expected=validation.scope_check(scope,family)
    c.require(scope.get('match_material_commit')==MATCH_COMMIT and scope.get('source_frozen') is True and scope.get('final_artwork_owner_approved') is True,'reviewed_build2_freeze_missing')
    rows=scope.get('native_profiles');c.require(isinstance(rows,list) and len(rows)==7 and {r.get('bundle_id') for r in rows}==set(c.TARGETS.values()),'exact_seven_profile_scope_missing')
    c.require(len({r.get('native_profile_id') for r in rows})==7 and len({r.get('uuid') for r in rows})==7,'profile_ids_or_uuid_ambiguous')
    for row in rows:
        c.require(row.get('native_readback_verified') is True and row.get('profile_type')==ap.EXPECTED[row['bundle_id']] and re.fullmatch('[A-Za-z0-9_-]{1,80}',row.get('native_profile_id','')) and re.fullmatch('[0-9a-f]{64}',row.get('sha256','')) and re.fullmatch('[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}',row.get('uuid','')),'native_profile_pins_invalid')
        target=next(t['target'] for t in scope['targets'] if t['bundle_id']==row['bundle_id'])
        name=('ResaleBurrow Build2 AppStore ' if row['bundle_id'] in c.PUSH else 'ResaleBurrow AppStore ')+target
        c.require(row.get('name')==name,'native_profile_exact_name_changed')
    return expected,{r['bundle_id']:r for r in rows if r['bundle_id'] in expected}

def decrypt_entry(client,entry,password):
    c.require(entry.get('type')=='blob' and entry.get('mode')=='100644' and re.fullmatch('[0-9a-f]{40}',entry.get('sha','')),'immutable_certificate_blob_invalid')
    blob=client.get(PREFIX+'/git/blobs/'+entry['sha']);c.require(blob.get('encoding')=='base64','certificate_blob_encoding_invalid')
    encoded=base64.b64decode(b''.join(blob.get('content','').encode().split()),validate=True)
    c.require(0<len(encoded)<=3*1024**2 and hashlib.sha1(b'blob '+str(len(encoded)).encode()+b'\0'+encoded).hexdigest()==entry['sha'],'immutable_certificate_blob_hash_changed')
    values=list(audit.decrypt_match_candidates(encoded,password));c.require(bool(values),'existing_material_decrypt_failed');return values

def key_pair(key_values,cert_values,team,fingerprint):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization,hashes
    from cryptography.hazmat.primitives.serialization import pkcs12
    for key_raw in key_values:
        for cert_raw in cert_values:
            try:
                check=audit.certificate_key_check(key_raw,team,cert_raw)
                if not check or check['fingerprint']!=fingerprint:continue
                try:key,cert,_=pkcs12.load_key_and_certificates(key_raw,b'')
                except ValueError:key=serialization.load_pem_private_key(key_raw,password=None);cert=x509.load_der_x509_certificate(cert_raw)
                if key is None or cert is None:continue
                return key,cert,{'verified':True,'sha256':fingerprint,'sha1':cert.fingerprint(hashes.SHA1()).hex()}
            except Exception:continue
    raise audit.AuditError('Exact existing private-key/certificate pair failed scoped verification.')

def macos_import_pkcs12(key,cert,password):
    """Ephemeral macOS-import format; outer protected artifact remains AES-GCM/RSA.

    cryptography documents that OpenSSL 3 defaults are unreadable by some
    macOS versions. PBESv1 3DES/SHA1 is only a keychain import compatibility
    container, never the at-rest/transport security boundary.
    """
    from cryptography.hazmat.primitives import serialization,hashes
    from cryptography.hazmat.primitives.serialization import pkcs12
    c.require(isinstance(password,str) and len(password)>=32,'Private ephemeral import password required.')
    encryption=(serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000).key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(password.encode()))
    raw=pkcs12.serialize_key_and_certificates(b'ResaleBurrow-existing-identity',key,cert,None,encryption)
    checked_key,checked_cert,cas=pkcs12.load_key_and_certificates(raw,password.encode())
    c.require(checked_key is not None and checked_cert is not None and not cas and checked_cert.public_bytes(serialization.Encoding.DER)==cert.public_bytes(serialization.Encoding.DER) and checked_key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)==key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo),'Ephemeral compatibility container round-trip differs.')
    return raw


def current_installer(apple,now):
    from cryptography import x509
    raw=base64.b64decode(apple.get('/v1/certificates/'+INSTALLER_ID).get('data',{}).get('attributes',{}).get('certificateContent',''),validate=True)
    cert=x509.load_der_x509_certificate(raw)
    c.require(hashlib.sha256(raw).hexdigest()==INSTALLER_SHA and [v.value for v in cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)]==[c.TEAM] and cert.not_valid_before_utc<=now<cert.not_valid_after_utc,'existing_installer_identity_or_date_changed');return raw

def restore(client,apple,scope,family,output,password,p12_password,now=None):
    c.require(family in {'macos','tvos'},'mac_tv_material_only')
    expected,pins=plan(scope,family);now=now or datetime.datetime.now(datetime.timezone.utc)
    c.require(password and len(p12_password)>=32,'private_restore_password_missing')
    current_cert=ap.certificate(apple,now)
    if family=='macos':current_installer(apple,now)
    commit=client.get(PREFIX+'/git/commits/'+MATCH_COMMIT);c.require(commit.get('sha')==MATCH_COMMIT and re.fullmatch('[0-9a-f]{40}',commit.get('tree',{}).get('sha','')),'immutable_match_commit_changed')
    tree=client.get(PREFIX+'/git/trees/'+commit['tree']['sha']+'?recursive=1');c.require(tree.get('truncated') is False and isinstance(tree.get('tree'),list),'immutable_match_tree_incomplete')
    identities=[('signing_certificate','distribution',ap.CERT_ID,c.CERT_SHA)]+([('installer_certificate','mac_installer_distribution',INSTALLER_ID,INSTALLER_SHA)] if family=='macos' else [])
    allowed={'certs/'+folder+'/'+identifier+ext for _,folder,identifier,_ in identities for ext in ['.p12','.cer']}
    entries={}
    for row in tree['tree']:
        if row.get('path') in allowed:c.require(row['path'] not in entries,'certificate_tree_path_ambiguous');entries[row['path']]=row
    c.require(set(entries)==allowed,'existing_certificate_material_missing')
    values={key:decrypt_entry(client,row,password) for key,row in entries.items()}
    output=Path(output);c.require(not output.exists() and not output.is_symlink(),'restore_output_collision');output.mkdir(parents=True,mode=0o700);output.chmod(0o700)
    metadata={}
    for kind,folder,identifier,fingerprint in identities:
        key,cert,info=key_pair(values['certs/'+folder+'/'+identifier+'.p12'],values['certs/'+folder+'/'+identifier+'.cer'],c.TEAM,fingerprint)
        path=output/(kind+'.p12');private_bytes(path,macos_import_pkcs12(key,cert,p12_password))
        info.update(type='MAC_INSTALLER_DISTRIBUTION' if kind=='installer_certificate' else 'DISTRIBUTION',certificate_id=identifier,p12_file=str(path),p12_file_sha256=hashlib.sha256(path.read_bytes()).hexdigest());metadata[kind]=info
    rows=[]
    for identifier,target in expected.items():
        pin=pins[identifier];resource=apple.get('/v1/profiles/'+pin['native_profile_id']).get('data',{})
        c.require(resource.get('id')==pin['native_profile_id'] and resource.get('attributes',{}).get('name')==pin['name'],'exact_native_profile_identity_changed')
        evidence=ap.profile_evidence(resource,identifier,current_cert,now)
        c.require(evidence['reusable_for_build2'] is True and evidence['sha256']==pin['sha256'] and evidence['uuid']==pin['uuid'],'exact_native_profile_grants_or_bytes_changed')
        raw=base64.b64decode(resource['attributes']['profileContent'],validate=True)
        path=output/(evidence['uuid']+('.provisionprofile' if family=='macos' else '.mobileprovision'));private_bytes(path,raw)
        name=next(t['target'] for t in scope['targets'] if t['bundle_id']==identifier)
        rows.append({**evidence,'bundle_id':identifier,'target':name,'name':pin['name'],'certificate_sha256':c.CERT_SHA,'verified':True,'native_readback_verified':True,'private_profile_file':str(path)})
    result={'schema':1,'source_sha':scope['source_sha'],'family':family,'team':c.TEAM,'group':c.GROUP,'match_commit':MATCH_COMMIT,'profiles':rows,**metadata,'installer_certificate':metadata.get('installer_certificate'),'restored_paths_only':sorted(allowed),'profile_material_mode':'exact-native-profile-GET-with-immutable-existing-certificates','authenticated_exact_profile_get':True,'network_mutations':False,'keychain_modified':False,'app_upload_performed':False}
    private_bytes(output/'restore-manifest.json',(json.dumps(result,indent=2)+'\n').encode());return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--scope',type=Path,required=True);p.add_argument('--family',choices=['macos','tvos'],required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--p12-password-file',type=Path,required=True);a=p.parse_args()
    try:
        c.require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('TEAMID')==c.TEAM,'reviewed_first_ci_restore_required')
        c.require(a.output.resolve().is_relative_to(Path(os.environ['RUNNER_TEMP']).resolve()),'restore_not_private_runner')
        c.require(a.p12_password_file.is_file() and not a.p12_password_file.is_symlink() and a.p12_password_file.stat().st_mode&0o077==0,'ephemeral_password_not_private')
        scope=json.loads(a.scope.read_text());plan(scope,a.family)
        restore(CertificateReadClient(os.environ['GH_PAT']),ProfileReadClient(audit.apple_token(os.environ),scope),scope,a.family,a.output,os.environ['MATCH_PASSWORD'],a.p12_password_file.read_text().strip())
        print(json.dumps({'status':'exact_existing_material_restored','family':a.family,'network_writes':0}));return 0
    except (c.GateError,audit.AuditError,validation.ValidationError) as e:print(json.dumps({'status':'stopped','code':str(e)}));return 1
    except Exception:print(json.dumps({'status':'stopped','code':'material_restore_unexpected_private_response'}));return 1
if __name__=='__main__':raise SystemExit(main())
