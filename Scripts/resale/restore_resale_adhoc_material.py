#!/usr/bin/env python3
"""GET-only Bryan restore: exact four native CMS files and immutable existing key pair."""
from __future__ import annotations
import argparse,hashlib,json,os
from pathlib import Path
import resale_apple_audit as audit
import resale_scoped_profiles as profiles
import store_resale_profiles as store
import restore_resale_material as material
import get_resale_adhoc_profiles as native
import validate_resale_adhoc_export as validator
MATCH='4d7f92fe5c81c32823e8ace5aca316ee98c8a53e'

def plan(scope,match_commit):
    profiles.validate_scope(scope);validator.scope_check(scope)
    profiles.require(scope.get('match_material_commit')==MATCH and match_commit==MATCH,'Bryan existing certificate storage must use the exact reviewed immutable commit.')
    profiles.require(scope.get('profile_material_mode')=='native-adhoc-get-with-immutable-match-certificates','Bryan direct native profile mode required.')
    return [t for t in scope['targets'] if t['family']=='ios']

def restore(client,apple,scope,match_commit,output,password,p12_password,delivery_sha):
    selected=plan(scope,match_commit)
    profiles.require(password and len(p12_password)>=32,'Private ephemeral material passwords are required.')
    profiles.verified_certificate(apple,profiles.CERT_ID,profiles.CERT_SHA,{'DISTRIBUTION'})
    commit=client.request('GET',store.PREFIX+'/git/commits/'+MATCH);profiles.require(commit.get('sha')==MATCH,'Immutable Match commit lookup differs.')
    tree=client.request('GET',store.PREFIX+'/git/trees/'+store.checked_sha(commit.get('tree',{}).get('sha'))+'?recursive=1')
    profiles.require(not tree.get('truncated') and isinstance(tree.get('tree'),list),'Immutable Match tree incomplete.')
    allowed={'certs/distribution/'+profiles.CERT_ID+'.p12','certs/distribution/'+profiles.CERT_ID+'.cer'};entries={}
    for row in tree['tree']:
        if row.get('path') in allowed:
            profiles.require(row['path'] not in entries,'Scoped certificate path is ambiguous.');entries[row['path']]=row
    profiles.require(set(entries)==allowed,'Exact existing certificate pair paths missing.')
    values={p:material.decrypt_entry(client,row,password) for p,row in entries.items()}
    key,cert,info=material.key_pair(values['certs/distribution/'+profiles.CERT_ID+'.p12'],values['certs/distribution/'+profiles.CERT_ID+'.cer'],profiles.TEAM,profiles.CERT_SHA)
    output=Path(output);profiles.require(not output.exists() and not output.is_symlink(),'Refuse to replace a previous private restore.');output.mkdir(mode=0o700);os.chmod(output,0o700)
    path=output/'signing_certificate.p12';material.private_bytes(path,material.macos_import_pkcs12(key,cert,p12_password))
    info.update(verified=True,type='DISTRIBUTION',certificate_id=profiles.CERT_ID,p12_file=str(path.resolve()),p12_file_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    retrieved=native.retrieve(apple,output/'native-adhoc',delivery_sha,scope['adhoc_native_profiles'])
    rows=[];reviewed={r['bundle_id']:r for r in scope['adhoc_native_profiles']}
    for row in retrieved['profiles']:
        target=next(t for t in selected if t['bundle_id']==row['bundle_id']);pin=reviewed[row['bundle_id']]
        profiles.require((row['native_profile_id'],row['name'],row['uuid'],row['sha256'])==(pin['native_profile_id'],pin['name'],pin['uuid'],pin['sha256']),'Actual retrieved profile differs from approved Bryan CMS pins.')
        profiles.require(pin['owner_private_phone_membership_verified_by_exact_cms_hash'] is True,'Prior private-phone membership proof missing.')
        profile_path=output/'native-adhoc'/row['path']
        rows.append({**row,'target':target['target'],'verified':True,'private_profile_file':str(profile_path.resolve()),'owner_private_phone_membership_verified_by_exact_cms_hash':True})
    result={'schema':1,'source_sha':scope['source_sha'],'family':'ios','distribution':'ad-hoc','team':profiles.TEAM,'group':profiles.GROUP,'match_commit':MATCH,'profiles':rows,'signing_certificate':info,'installer_certificate':None,'restored_paths_only':sorted(allowed),'profile_material_mode':scope['profile_material_mode'],'authenticated_exact_profile_get':True,'same_single_phone_across_four_profiles':True,'private_owner_phone_membership_verified_by_exact_cms_hash':True,'watch_hardware_eligibility_verified':False,'network_mutations':False,'keychain_modified':False,'app_upload_performed':False}
    profiles.private_write(output/'restore-manifest.json',result);return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scope',type=Path,required=True);p.add_argument('--match-commit',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--p12-password-file',type=Path,required=True);p.add_argument('--delivery-sha',required=True);a=p.parse_args()
    try:
        profiles.require(os.environ.get('GITHUB_ACTIONS')=='true','Restoration restricted to ephemeral reviewed CI.')
        profiles.require(a.p12_password_file.is_file() and not a.p12_password_file.is_symlink() and a.p12_password_file.stat().st_mode&0o077==0,'Ephemeral password file is not private.')
        apple=profiles.ProfileClient('https://api.appstoreconnect.apple.com',audit.apple_token(os.environ));client=store.StoreClient(os.environ.get('GH_PAT',''))
        restore(client,apple,json.loads(a.scope.read_text()),a.match_commit,a.output,os.environ.get('MATCH_PASSWORD',''),a.p12_password_file.read_text().strip(),a.delivery_sha)
        print('Four pinned Bryan profiles and existing identity restored privately; no network writes.');return 0
    except (audit.AuditError,validator.Error) as error:print('Bryan private restore stopped: '+str(error));return 1
    except Exception:print('Bryan private restore stopped; private diagnostics protected.');return 1
if __name__=='__main__':raise SystemExit(main())
