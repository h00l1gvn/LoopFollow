#!/usr/bin/env python3
"""Add only verified Match-encrypted Resale profiles; master CAS, no overwrite/delete."""
from __future__ import annotations
import argparse,base64,hashlib,json,os,re
from pathlib import Path
from urllib.error import HTTPError,URLError
from urllib.request import Request,build_opener
import resale_apple_audit as audit
import resale_scoped_profiles as profiles
REPO='h00l1gvn/Match-Secrets';PREFIX='/repos/'+REPO

class StoreClient:
    def __init__(self,token,opener=None):self.token=token;self.opener=opener or build_opener(audit.NoRedirect())
    def request(self,method,path,body=None):
        approved=(method=='GET' and (path in (PREFIX,PREFIX+'/git/ref/heads/master') or re.fullmatch(re.escape(PREFIX)+r'/git/(commits|trees|blobs)/[0-9a-f]{40}(?:[?]recursive=1)?',path))) or (method=='POST' and path in (PREFIX+'/git/trees',PREFIX+'/git/commits')) or (method=='PATCH' and path==PREFIX+'/git/refs/heads/master')
        profiles.require(approved,'Store route/method is outside the reviewed narrow Git Data API scope.')
        request=Request('https://api.github.com'+path,data=None if body is None else json.dumps(body,separators=(',',':')).encode(),headers={'Authorization':'Bearer '+self.token,'Accept':'application/vnd.github+json','Content-Type':'application/json','User-Agent':'ResaleBurrow-encrypted-seven-profile-store'},method=method)
        try:
            with self.opener.open(request,timeout=45) as response:raw=response.read(16*1024*1024+1)
            profiles.require(len(raw)<=16*1024*1024,'Store response exceeded the bound.')
            value=json.loads(raw);profiles.require(isinstance(value,dict),'Store response shape was invalid.');return value
        except HTTPError as error:raise audit.AuditError('Encrypted profile store request failed; no automatic mutation retry.',http_status=error.code) from None
        except (OSError,URLError,TimeoutError,ValueError):raise audit.AuditError('Encrypted profile store outcome is unknown; use fresh GETs before any mutation retry.') from None

def checked_sha(value):
    profiles.require(isinstance(value,str) and re.fullmatch(r'[0-9a-f]{40}',value),'Store Git object SHA invalid.');return value

def validate_manifest(scope,manifest,folder):
    targets=profiles.validate_scope(scope);wanted={t['bundle_id']:t for t in targets};rows=manifest.get('profiles',[])
    profiles.require(manifest.get('complete') is True and manifest.get('profile_count')==7 and manifest.get('team')==profiles.TEAM and manifest.get('group')==profiles.GROUP and manifest.get('source_sha')==scope['source_sha'],'Profile manifest is not the reviewed complete exact set.')
    profiles.require(len(rows)==7 and len({r.get('bundle_id') for r in rows})==7 and {r.get('bundle_id') for r in rows}==set(wanted),'Profile store scope mismatch.')
    result={}
    for row in rows:
        target=wanted[row['bundle_id']];expected=profiles.profile_path(target)
        profiles.require(row.get('path')==expected and row.get('target')==target['target'] and row.get('profile_type')==target['profile_type'] and row.get('verified') is True and row.get('native_readback_verified') is True and re.fullmatch(r'[A-Za-z0-9_-]{1,80}',row.get('native_profile_id','')) and row.get('certificate_sha256')==profiles.CERT_SHA,'Profile store row failed provenance checks.')
        path=Path(folder)/expected
        profiles.require(path.is_file() and not path.is_symlink() and path.stat().st_size<=3*1024*1024,'Encrypted profile file missing/unsafe.')
        raw=path.read_bytes();profiles.require(hashlib.sha256(raw).hexdigest()==row.get('encrypted_sha256'),'Encrypted profile file hash changed.')
        decoded=base64.b64decode(b''.join(raw.split()),validate=True);profiles.require(decoded.startswith(b'match_encrypted_v2__'),'Only authenticated Match V2 profile bytes may enter the store.')
        profiles.require(re.fullmatch(r'[0-9a-f]{64}',row.get('sha256','')),'Original profile hash invalid.')
        result[expected]=(row,raw)
    return result

def store_profiles(client,scope,manifest,folder,expected_head,password):
    checked_sha(expected_head);files=validate_manifest(scope,manifest,folder)
    profiles.require(client.request('GET',PREFIX).get('private') is True,'Signing store is not private.')
    current=checked_sha(client.request('GET',PREFIX+'/git/ref/heads/master').get('object',{}).get('sha'))
    profiles.require(current==expected_head,'Match master changed; refuse a stale write and require a fresh reviewed head.')
    commit=client.request('GET',PREFIX+'/git/commits/'+current);profiles.require(commit.get('sha')==current,'Match commit lookup mismatch.')
    tree_sha=checked_sha(commit.get('tree',{}).get('sha'));tree=client.request('GET',PREFIX+'/git/trees/'+tree_sha+'?recursive=1')
    profiles.require(not tree.get('truncated') and isinstance(tree.get('tree'),list),'Match tree was incomplete.')
    entries={}
    for e in tree['tree']:
        if e.get('path') in files:
            profiles.require(e['path'] not in entries,'Match profile path is ambiguous.');entries[e['path']]=e
    additions=[]
    for path,(row,raw) in files.items():
        if path in entries:
            e=entries[path];profiles.require(e.get('mode')=='100644' and e.get('type')=='blob','Existing owned Match profile path is not a regular blob.')
            blob=client.request('GET',PREFIX+'/git/blobs/'+checked_sha(e.get('sha')))
            profiles.require(blob.get('encoding')=='base64','Existing owned Match blob encoding invalid.')
            encrypted=base64.b64decode(b''.join(blob.get('content','').encode().split()),validate=True)
            values=list(audit.decrypt_match_candidates(encrypted,password))
            profiles.require(any(hashlib.sha256(v).hexdigest()==row['sha256'] for v in values),'An existing owned profile differs; no overwrite/renewal is permitted by this additive job.')
        else:additions.append({'path':path,'mode':'100644','type':'blob','content':raw.decode('ascii')})
    if not additions:return {'schema':1,'match_commit':current,'replayed':True,'added_paths':[],'existing_paths_preserved':sorted(files),'no_other_paths_modified':True}
    # Three fixed writes. Non-force ref update is the final compare-and-swap.
    newtree=checked_sha(client.request('POST',PREFIX+'/git/trees',{'base_tree':tree_sha,'tree':additions}).get('sha'))
    newcommit=checked_sha(client.request('POST',PREFIX+'/git/commits',{'message':'Add verified ResaleBurrow App Store profiles only','tree':newtree,'parents':[current]}).get('sha'))
    # Re-read exact ref before updating. A concurrent unrelated commit causes a stop.
    profiles.require(client.request('GET',PREFIX+'/git/ref/heads/master').get('object',{}).get('sha')==current,'Match master changed before save; no ref update attempted.')
    saved=client.request('PATCH',PREFIX+'/git/refs/heads/master',{'sha':newcommit,'force':False})
    profiles.require(saved.get('object',{}).get('sha')==newcommit,'Match ref save outcome needs fresh GET confirmation.')
    profiles.require(client.request('GET',PREFIX+'/git/ref/heads/master').get('object',{}).get('sha')==newcommit,'Match ref readback needs fresh review.')
    readback=client.request('GET',PREFIX+'/git/trees/'+newtree+'?recursive=1')
    profiles.require(not readback.get('truncated') and isinstance(readback.get('tree'),list),'Saved Match tree readback incomplete.')
    def blobs(rows):
        values={}
        for row in rows:
            if row.get('type')=='tree':continue
            profiles.require(isinstance(row.get('path'),str) and row['path'] not in values,'Match tree path ambiguity.')
            values[row['path']]=(row.get('mode'),row.get('type'),row.get('sha'))
        return values
    before=blobs(tree['tree']);after=blobs(readback['tree'])
    profiles.require(all(after.get(p)==value for p,value in before.items()),'Existing Match entries changed in readback; stop for review.')
    profiles.require(set(after)-set(before)=={a['path'] for a in additions},'Saved Match additions exceeded the exact reviewed paths.')
    for addition in additions:
        content=addition['content'].encode();sha=hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        profiles.require(after[addition['path']]==('100644','blob',sha),'Saved encrypted profile bytes differ from the exact added content.')
    return {'schema':1,'match_commit':newcommit,'previous_match_commit':current,'replayed':False,'added_paths':[r['path'] for r in additions],'existing_paths_preserved':sorted(entries),'all_previous_tree_entries_preserved':True,'encrypted_bytes_readback_verified':True,'no_other_paths_modified':True}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scope',type=Path,required=True);p.add_argument('--profile-dir',type=Path,required=True);p.add_argument('--expected-head',required=True);p.add_argument('--execute-reviewed-profile-store-addition',action='store_true');a=p.parse_args()
    try:
        profiles.require(a.execute_reviewed_profile_store_addition,'Store addition is prepared only; explicit reviewed execution flag required.')
        scope=json.loads(a.scope.read_text());manifest=json.loads((a.profile_dir/'profile-manifest.json').read_text())
        profiles.require(os.environ.get('GH_PAT') and os.environ.get('MATCH_PASSWORD'),'Configured private store credentials are required.')
        result=store_profiles(StoreClient(os.environ['GH_PAT']),scope,manifest,a.profile_dir,a.expected_head,os.environ['MATCH_PASSWORD'])
        profiles.private_write(a.profile_dir/'store-receipt.json',result)
        print('Exact encrypted owned-profile addition saved and read back. No certificate/deletion/upload operation.');return 0
    except audit.AuditError as error:print('Scoped encrypted store stopped: '+str(error));return 1
    except Exception:print('Scoped encrypted store stopped; no upstream body or private contents printed.');return 1
if __name__=='__main__':raise SystemExit(main())
