#!/usr/bin/env python3
"""GET-only existing Mac installer pair restore. No profiles, application key or writes."""
import argparse, hashlib, json, os
from pathlib import Path
import resale_apple_audit as audit
import resale_scoped_profiles as profiles
import store_resale_profiles as store
import restore_resale_material as material

MATCH='d001564051efa319ea96060b6d23c285d03959f6'
PATHS={'certs/mac_installer_distribution/WBR8H2GCGZ.cer','certs/mac_installer_distribution/WBR8H2GCGZ.p12'}

class InstallerStoreGetOnly(store.StoreClient):
    def request(self,method,path,body=None):
        profiles.require(method=='GET','Installer restore permits GET only.')
        return super().request(method,path,body)

def restore(client, apple, scope, output, password, import_password):
    profiles.validate_scope(scope)
    profiles.require(scope.get('match_material_commit')==MATCH,'Reviewed immutable Match commit differs.')
    profiles.verified_certificate(apple,profiles.INSTALLER_ID,profiles.INSTALLER_SHA,{'MAC_INSTALLER_DISTRIBUTION'})
    commit=client.request('GET',store.PREFIX+'/git/commits/'+MATCH)
    profiles.require(commit.get('sha')==MATCH,'Immutable Match lookup differs.')
    tree=client.request('GET',store.PREFIX+'/git/trees/'+store.checked_sha(commit.get('tree',{}).get('sha'))+'?recursive=1')
    profiles.require(not tree.get('truncated') and isinstance(tree.get('tree'),list),'Match tree incomplete.')
    selected=[r for r in tree['tree'] if r.get('path') in PATHS]
    profiles.require(len(selected)==2 and {r.get('path') for r in selected}==PATHS,'Exact installer blob set differs.')
    values={r['path']:material.decrypt_entry(client,r,password) for r in selected}
    key,cert,info=material.key_pair(values['certs/mac_installer_distribution/WBR8H2GCGZ.p12'],values['certs/mac_installer_distribution/WBR8H2GCGZ.cer'],profiles.TEAM,profiles.INSTALLER_SHA)
    output=Path(output);profiles.require(not output.exists(),'Private restore destination exists.')
    output.mkdir(parents=True,mode=0o700)
    p12=output/'installer.p12';material.private_bytes(p12,material.macos_import_pkcs12(key,cert,import_password))
    info.update(certificate_id=profiles.INSTALLER_ID,type='MAC_INSTALLER_DISTRIBUTION',p12_file=str(p12),p12_file_sha256=hashlib.sha256(p12.read_bytes()).hexdigest())
    result={'schema':1,'source_sha':scope['source_sha'],'family':'macos','team':profiles.TEAM,'group':profiles.GROUP,'match_commit':MATCH,'installer_certificate':info,'restored_paths_only':sorted(PATHS),'network_mutations':False,'profiles_restored':False,'application_key_restored':False}
    profiles.private_write(output/'installer-manifest.json',result);return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--scope',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--p12-password-file',type=Path,required=True);a=p.parse_args()
    try:
        profiles.require(os.environ.get('GITHUB_ACTIONS')=='true','Restore is restricted to reviewed ephemeral CI.')
        profiles.require(not a.p12_password_file.is_symlink() and a.p12_password_file.stat().st_mode&0o077==0,'Password file not private.')
        restore(InstallerStoreGetOnly(os.environ.get('GH_PAT','')),audit.ReadClient('https://api.appstoreconnect.apple.com',audit.apple_token(os.environ)),json.loads(a.scope.read_text()),a.output,os.environ.get('MATCH_PASSWORD',''),a.p12_password_file.read_text().strip())
        print('Existing exact Mac installer restored privately; no profile or network writes.');return 0
    except Exception:
        print('Installer-only restore stopped; raw material remains private.');return 1
if __name__=='__main__':raise SystemExit(main())
