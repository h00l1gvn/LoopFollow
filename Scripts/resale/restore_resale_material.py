#!/usr/bin/env python3
"""GET-only exact-family material restore from an immutable Match commit, private runner."""
from __future__ import annotations
import argparse,base64,hashlib,json,os,re
from pathlib import Path
from urllib.parse import urlencode,quote
import resale_apple_audit as audit
import resale_scoped_profiles as profiles
import store_resale_profiles as store

def private_bytes(path,raw):
    path=Path(path);profiles.require(not path.exists() and not path.is_symlink(),'Refuse to replace existing private material.')
    with path.open('xb') as handle:handle.write(raw)
    os.chmod(path,0o600)

def decrypt_entry(client,entry,password):
    profiles.require(entry.get('type')=='blob' and entry.get('mode')=='100644','Material path is not a regular Git blob.')
    sha=store.checked_sha(entry.get('sha'));blob=client.request('GET',store.PREFIX+'/git/blobs/'+sha)
    profiles.require(blob.get('encoding')=='base64','Encrypted blob encoding invalid.')
    encoded=base64.b64decode(b''.join(blob.get('content','').encode().split()),validate=True)
    profiles.require(0<len(encoded)<=3*1024*1024,'Encrypted blob size invalid.')
    profiles.require(hashlib.sha1(b'blob '+str(len(encoded)).encode()+b'\0'+encoded).hexdigest()==sha,'Encrypted Git blob bytes differ from the immutable tree.')
    values=list(audit.decrypt_match_candidates(encoded,password));profiles.require(bool(values),'Encrypted material could not be read.');return values

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

def direct_profile_plan(scope,family,selected):
    """Reviewed exact iOS resources; never selects latest/name-only alternatives."""
    if scope.get('profile_material_mode')!='native-profile-get-with-immutable-match-certificates':return None
    profiles.require(family=='ios','Direct profile mode is reviewed for iOS only.')
    rows=scope.get('direct_native_profiles',[])
    profiles.require(isinstance(rows,list) and len(rows)==4 and {r.get('bundle_id') for r in rows}=={t['bundle_id'] for t in selected},'Direct native profile scope must contain exactly four iOS targets.')
    profiles.require(len({r.get('native_profile_id') for r in rows})==4,'Direct native profile resource IDs must be distinct.')
    for row in rows:
        target=next(t for t in selected if t['bundle_id']==row['bundle_id'])
        profiles.require(row.get('name')==profiles.profile_name(target) and row.get('profile_type')==target['profile_type'] and row.get('native_readback_verified') is True,'Direct native profile prior verification differs.')
        profiles.require(re.fullmatch(r'[A-Za-z0-9_-]{1,80}',row.get('native_profile_id','')) and re.fullmatch(r'[0-9a-f]{64}',row.get('sha256','')) and re.fullmatch(r'[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}',row.get('uuid','')),'Direct native profile identity/hash invalid.')
    return {r['bundle_id']:r for r in rows}

def restore(client,apple,scope,family,match_commit,output,password,p12_password):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    targets=profiles.validate_scope(scope);selected=[t for t in targets if t['family']==family]
    profiles.require(family in ('ios','macos','tvos') and bool(selected),'Unapproved export family.')
    store.checked_sha(match_commit)
    profiles.require(scope.get('match_material_commit')==match_commit,'Immutable Match material commit has not been reviewed into the export scope.')
    profiles.require(password and len(p12_password)>=32,'Private ephemeral material passwords are required.')
    current_cert=profiles.verified_certificate(apple,profiles.CERT_ID,profiles.CERT_SHA,{'DISTRIBUTION'})
    if family=='macos':profiles.verified_certificate(apple,profiles.INSTALLER_ID,profiles.INSTALLER_SHA,{'MAC_INSTALLER_DISTRIBUTION'})
    commit=client.request('GET',store.PREFIX+'/git/commits/'+match_commit);profiles.require(commit.get('sha')==match_commit,'Immutable Match commit lookup differs.')
    tree=client.request('GET',store.PREFIX+'/git/trees/'+store.checked_sha(commit.get('tree',{}).get('sha'))+'?recursive=1')
    profiles.require(not tree.get('truncated') and isinstance(tree.get('tree'),list),'Immutable Match tree incomplete.')
    direct=direct_profile_plan(scope,family,selected)
    allowed=({'certs/distribution/'+profiles.CERT_ID+'.p12','certs/distribution/'+profiles.CERT_ID+'.cer'} if direct else {profiles.profile_path(t) for t in selected}|{'certs/distribution/'+profiles.CERT_ID+'.p12','certs/distribution/'+profiles.CERT_ID+'.cer'})
    if family=='macos':allowed|={'certs/mac_installer_distribution/'+profiles.INSTALLER_ID+'.p12','certs/mac_installer_distribution/'+profiles.INSTALLER_ID+'.cer'}
    entries={}
    for e in tree['tree']:
        if e.get('path') in allowed:
            profiles.require(e['path'] not in entries,'Scoped material path is ambiguous.');entries[e['path']]=e
    profiles.require(set(entries)==allowed,'An exact scoped profile/certificate path is missing.')
    # No unrelated profile, device or signing blob is downloaded.
    values={p:decrypt_entry(client,e,password) for p,e in entries.items()}
    output=Path(output);profiles.require(not output.exists(),'Refuse to replace a previous private restore.');output.mkdir(parents=True,mode=0o700);os.chmod(output,0o700)
    restored={};metadata={}
    for kind,folder,identifier,fingerprint in [('signing_certificate','distribution',profiles.CERT_ID,profiles.CERT_SHA)]+([('installer_certificate','mac_installer_distribution',profiles.INSTALLER_ID,profiles.INSTALLER_SHA)] if family=='macos' else []):
        key,cert,info=key_pair(values['certs/'+folder+'/'+identifier+'.p12'],values['certs/'+folder+'/'+identifier+'.cer'],profiles.TEAM,fingerprint)
        info.update(type='DISTRIBUTION' if kind=='signing_certificate' else 'MAC_INSTALLER_DISTRIBUTION',certificate_id=identifier)
        path=output/(kind+'.p12');private_bytes(path,pkcs12.serialize_key_and_certificates(b'ResaleBurrow-existing-identity',key,cert,None,serialization.BestAvailableEncryption(p12_password.encode())))
        info['p12_file']=str(path);info['p12_file_sha256']=hashlib.sha256(path.read_bytes()).hexdigest();metadata[kind]=info
    rows=[]
    for target in selected:
        bundles=apple.collection('/v1/bundleIds?'+urlencode({'filter[identifier]':target['bundle_id'],'limit':50}))
        exact=[r for r in bundles if r.get('attributes',{}).get('identifier')==target['bundle_id']];profiles.require(len(exact)==1,'Exact native bundle missing or ambiguous at restore.')
        native=apple.collection('/v1/bundleIds/'+quote(exact[0]['id'],safe='')+'/profiles?limit=50')
        exact_profiles=[r for r in native if r.get('attributes',{}).get('name')==profiles.profile_name(target) and (not direct or r.get('id')==direct[target['bundle_id']]['native_profile_id'])];profiles.require(len(exact_profiles)==1,'Exact current native profile missing or ambiguous at restore.')
        row,raw=profiles.validate_profile(exact_profiles[0],target,current_cert)
        if direct:
            reviewed=direct[target['bundle_id']]
            profiles.require(row['sha256']==reviewed['sha256'] and row['uuid']==reviewed['uuid'],'Current exact native profile differs from the reviewed authenticated creation/readback.')
        else:profiles.require(any(value==raw for value in values[profiles.profile_path(target)]),'Immutable Match profile differs from current signed native content.')
        path=output/(row['uuid']+('.provisionprofile' if family=='macos' else '.mobileprovision'));private_bytes(path,raw);row['private_profile_file']=str(path);row['native_profile_id']=exact_profiles[0]['id'];row['native_readback_verified']=True;rows.append(row)
    result={'schema':1,'source_sha':scope['source_sha'],'family':family,'team':profiles.TEAM,'group':profiles.GROUP,'match_commit':match_commit,'profiles':rows,'signing_certificate':metadata['signing_certificate'],'installer_certificate':metadata.get('installer_certificate'),'restored_paths_only':sorted(allowed),'profile_material_mode':'native-profile-get-with-immutable-match-certificates' if direct else 'immutable-match-profile-and-certificate','authenticated_exact_profile_get':True,'network_mutations':False,'keychain_modified':False,'app_upload_performed':False}
    profiles.private_write(output/'restore-manifest.json',result);return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scope',type=Path,required=True);p.add_argument('--family',choices=['ios','macos','tvos'],required=True);p.add_argument('--match-commit',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--p12-password-file',type=Path,required=True);a=p.parse_args()
    try:
        profiles.require(os.environ.get('GITHUB_ACTIONS')=='true','Material restoration is restricted to the reviewed ephemeral CI runner.')
        profiles.require(not a.p12_password_file.is_symlink() and a.p12_password_file.stat().st_mode&0o077==0,'Ephemeral password file is not private.')
        scope=json.loads(a.scope.read_text());apple=profiles.ProfileClient('https://api.appstoreconnect.apple.com',audit.apple_token(os.environ));client=store.StoreClient(os.environ.get('GH_PAT',''))
        restore(client,apple,scope,a.family,a.match_commit,a.output,os.environ.get('MATCH_PASSWORD',''),a.p12_password_file.read_text().strip())
        print('Exact family existing material restored privately and revalidated. No network writes or keychain changes.');return 0
    except audit.AuditError as error:print('Scoped material restore stopped: '+str(error));return 1
    except Exception:print('Scoped material restore stopped; no private data or upstream bodies printed.');return 1
if __name__=='__main__':raise SystemExit(main())
