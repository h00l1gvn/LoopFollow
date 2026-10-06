#!/usr/bin/env python3
"""Exact cached-export upload runner; executable only by explicit reviewed CI gate.

No rebuild, signing, keychain/profile changes, source checkout or device calls.
Private GitHub release assets provide a cross-run atomic intent and result journal.
No write or upload is retried, including ambiguous network outcomes.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler

import plan_cached_upload as plan

HERE=Path(__file__).resolve().parent
REPO=plan.REPO
TOOLING_REPO='h00l1gvn/LoopFollow'
TAG='resale-burrow-0.1.0-build-1-signed-cache'
MAX_PACKAGE=512*1024*1024
MANIFEST_NAME='signed-export-cache-manifest.json'
SOURCE='1162d8a1f4fdda1c2678220c9102f9c03ab48c33'
DEPENDENCIES={'Gemfile':'c4d7c24a57bd57e7b62143b3af29af6dfc42e407425685ae8b65464e51d91b1f','Gemfile.lock':'8c21e506e0687cc9e3f6cd02877d5d4f679ab82ffaaec9810c21b7312807625b'}
RECIPIENT='62d6dc6cd0253c7d427f63fbadd9953247a6312146df856689955371cd3e6358'

class Invalid(ValueError): pass
def require(value,code):
    if not value: raise Invalid(code)
def stamp():return datetime.now(timezone.utc).isoformat()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path=Path(path);require(not path.is_symlink(),'unsafe_output_path')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(value,f,indent=2);f.write('\n')
def numeric(value):return type(value) in (str,int) and re.fullmatch(r'[1-9][0-9]{0,24}',str(value)) is not None
def resource_id(value):return isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,100}',value) is not None

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

class HTTP:
    """One request per call. Never logs tokens, response bodies or redirect URLs."""
    def __init__(self,opener=None):self.opener=opener or build_opener(NoRedirect())
    def request(self,url,*,token=None,accept='application/json',data=None,method='GET',maximum=2*1024*1024,redirect_asset=False):
        p=urlparse(url);require(p.scheme=='https' and not p.username and not p.password and not p.fragment,'https_destination_required')
        headers={'Accept':accept,'User-Agent':'ResaleBurrow-exact-cached-upload'}
        if token:headers['Authorization']='Bearer '+token
        if data is not None:headers['Content-Type']='application/json'
        request=Request(url,headers=headers,data=data,method=method)
        try:
            response=self.opener.open(request,timeout=60)
        except HTTPError as e:
            if method=='GET' and redirect_asset and e.code in (301,302,303,307,308):
                location=e.headers.get('Location','');q=urlparse(location)
                require(q.scheme=='https' and q.hostname in ('release-assets.githubusercontent.com','objects.githubusercontent.com') and not q.username and not q.password and not q.fragment,'asset_redirect_outside_github')
                # A fresh request deliberately omits the GitHub credential.
                return self.request(location,accept='application/octet-stream',maximum=maximum)
            raise Invalid('metadata_http_error' if method=='GET' else 'write_outcome_unknown_no_retry') from None
        except (OSError,URLError,TimeoutError):raise Invalid('metadata_unavailable' if method=='GET' else 'write_outcome_unknown_no_retry') from None
        try:
            require(response.status==(200 if method=='GET' else 201),'unexpected_response_status')
            raw=response.read(maximum+1);require(len(raw)<=maximum,'response_exceeds_bound')
            return raw
        except (OSError,TimeoutError):raise Invalid('metadata_unavailable' if method=='GET' else 'write_outcome_unknown_no_retry') from None
        finally:response.close()
    def json(self,url,*,token=None,data=None,method='GET'):
        try:return json.loads(self.request(url,token=token,data=data,method=method))
        except (ValueError,UnicodeError):raise Invalid('metadata_shape_unreadable' if method=='GET' else 'write_outcome_unknown_no_retry') from None

class GitHub:
    def __init__(self,token,http=None):self.token=token;self.http=http or HTTP()
    def get(self,path):
        p=urlparse(path);pairs=parse_qsl(p.query);query=dict(pairs);require(len(pairs)==len(query),'duplicate_query_key');base='/repos/'+REPO
        if p.path==base:require(not query,'github_get_outside_scope')
        elif p.path==base+'/releases' or re.fullmatch(re.escape(base)+r'/releases/[1-9][0-9]*/assets',p.path):
            require(set(query)=={'per_page','page'} and query['per_page']=='100' and query['page'] in {str(n) for n in range(1,11)},'github_collection_query_outside_scope')
        elif re.fullmatch(re.escape(base)+r'/releases/[1-9][0-9]*',p.path) or re.fullmatch('/repos/'+re.escape(TOOLING_REPO)+r'/actions/runs/[1-9][0-9]*',p.path):require(not query,'github_get_outside_scope')
        else:raise Invalid('github_get_outside_scope')
        require(not p.scheme and not p.netloc and not p.fragment,'github_get_outside_scope')
        return self.http.json('https://api.github.com'+path,token=self.token)
    def collection(self,path):
        require(path in ('/repos/'+REPO+'/releases',) or re.fullmatch('/repos/'+re.escape(REPO)+r'/releases/[1-9][0-9]*/assets',path),'github_collection_outside_scope')
        rows=[]
        for page in range(1,11):
            value=self.get(path+'?'+urlencode({'per_page':100,'page':page}));require(isinstance(value,list),'github_collection_invalid')
            require(all(isinstance(v,dict) for v in value),'github_collection_invalid');rows.extend(value)
            if len(value)<100:return rows
        raise Invalid('github_collection_incomplete')
    def verify_private_release(self,release_id):
        require(numeric(release_id),'release_id_invalid')
        repo=self.get('/repos/'+REPO);require(repo.get('full_name')==REPO and repo.get('private') is True,'private_repository_not_verified')
        matches=[r for r in self.collection('/repos/'+REPO+'/releases') if r.get('tag_name')==TAG]
        require(len(matches)==1 and str(matches[0].get('id'))==str(release_id),'canonical_cache_release_not_unique')
        release=self.get('/repos/'+REPO+'/releases/'+str(release_id))
        require(str(release.get('id'))==str(release_id) and release.get('draft') is True and release.get('prerelease') is True and release.get('tag_name')==TAG,'owned_draft_cache_release_mismatch')
        return self.collection('/repos/'+REPO+'/releases/'+str(release_id)+'/assets')
    def download_asset(self,asset_id,expected_sha,expected_bytes):
        require(numeric(asset_id) and re.fullmatch(r'[a-f0-9]{64}',expected_sha) and isinstance(expected_bytes,int) and 0<expected_bytes<=MAX_PACKAGE,'asset_pin_invalid')
        raw=self.http.request('https://api.github.com/repos/'+REPO+'/releases/assets/'+str(asset_id),token=self.token,accept='application/octet-stream',maximum=expected_bytes,redirect_asset=True)
        require(len(raw)==expected_bytes and sha(raw)==expected_sha,'private_asset_bytes_or_hash_mismatch');return raw
    def upload_marker_once(self,release_id,name,value):
        require(numeric(release_id) and re.fullmatch(r'upload-(intent|result)-(ios|macos|tvos)-0[.]1[.]0-1[.]json',name),'marker_write_outside_scope')
        raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();require(len(raw)<65536,'marker_size_invalid')
        url='https://uploads.github.com/repos/'+REPO+'/releases/'+str(release_id)+'/assets?'+urlencode({'name':name})
        result=self.http.json(url,token=self.token,data=raw,method='POST')
        require(isinstance(result,dict) and numeric(result.get('id')) and result.get('name')==name and result.get('size')==len(raw) and result.get('state')=='uploaded','marker_write_outcome_unknown_no_retry')
        readback=self.download_asset(result['id'],sha(raw),len(raw));require(readback==raw,'marker_readback_failed')
        return {'asset_id':str(result['id']),'name':name,'sha256':sha(raw),'bytes':len(raw)}

class Apple:
    def __init__(self,token,http=None):self.token=token;self.http=http or HTTP();self.build_ids=set()
    def get(self,path):
        p=urlparse(path);pairs=parse_qsl(p.query);query=dict(pairs);require(len(pairs)==len(query),'duplicate_query_key')
        ids={v['asc_id'] for v in plan.APPS.values()}
        if any(p.path=='/v1/apps/'+i for i in ids):require(not query,'apple_app_query_outside_scope')
        elif any(p.path=='/v1/apps/'+i+'/builds' or p.path=='/v1/apps/'+i+'/buildUploads' for i in ids):
            require(set(query)<= {'limit','cursor'} and query.get('limit','200')=='200','apple_collection_query_outside_scope')
        else:
            m=re.fullmatch(r'/v1/builds/([A-Za-z0-9_-]{1,100})/preReleaseVersion',p.path)
            require(m is not None and m.group(1) in self.build_ids and not query,'apple_get_outside_owned_scope')
        require(not p.scheme and not p.netloc and not p.fragment,'apple_get_outside_owned_scope')
        value=self.http.json('https://api.appstoreconnect.apple.com'+path,token=self.token)
        require(isinstance(value,dict),'apple_metadata_invalid');return value
    def collection(self,path):
        root=urlparse(path).path;rows=[];seen=set()
        for _ in range(10):
            require(path not in seen,'apple_pagination_cycle');seen.add(path)
            value=self.get(path);data=value.get('data');require(isinstance(data,list) and all(isinstance(v,dict) for v in data),'apple_collection_invalid');rows.extend(data)
            nxt=(value.get('links') or {}).get('next')
            if not nxt:return rows
            require(isinstance(nxt,str),'apple_pagination_invalid');p=urlparse(nxt)
            require((not p.scheme and not p.netloc) or (p.scheme=='https' and p.netloc=='api.appstoreconnect.apple.com'),'apple_pagination_origin_changed')
            require(p.path==root and not p.fragment and not p.username and not p.password,'apple_pagination_scope_changed')
            path=p.path+('?' +p.query if p.query else '')
        raise Invalid('apple_collection_incomplete')
    def precheck(self,family):
        app=plan.APPS[family];ident=app['asc_id']
        value=self.get('/v1/apps/'+ident).get('data',{})
        require(value.get('type')=='apps' and value.get('id')==ident and value.get('attributes',{}).get('bundleId')==app['bundle_id'],'apple_exact_app_not_verified')
        builds=[]
        for row in self.collection('/v1/apps/'+ident+'/builds?limit=200'):
            require(row.get('type')=='builds' and resource_id(row.get('id')),'apple_build_identity_invalid')
            self.build_ids.add(row['id'])
            version=self.get('/v1/builds/'+row['id']+'/preReleaseVersion').get('data',{})
            a=version.get('attributes',{});build=row.get('attributes',{}).get('version')
            require(version.get('type')=='preReleaseVersions' and isinstance(a.get('version'),str) and a.get('platform')==app['platform'] and isinstance(build,str),'apple_existing_build_coordinates_unknown')
            builds.append({'id':row['id'],'identity_resolved':True,'version':a['version'],'build':build,'platform':a['platform']})
        uploads=[]
        for row in self.collection('/v1/apps/'+ident+'/buildUploads?limit=200'):
            a=row.get('attributes',{});state=a.get('state',{});state=state.get('state') if isinstance(state,dict) else None
            require(row.get('type')=='buildUploads' and resource_id(row.get('id')) and isinstance(a.get('cfBundleShortVersionString'),str) and isinstance(a.get('cfBundleVersion'),str) and a.get('platform')==app['platform'] and isinstance(state,str),'apple_existing_upload_coordinates_unknown')
            uploads.append({'id':row['id'],'identity_resolved':True,'version':a['cfBundleShortVersionString'],'build':a['cfBundleVersion'],'platform':a['platform'],'state':state})
        result={'authenticated_get_only':True,'complete':True,'asc_id':ident,'bundle_id':app['bundle_id'],'platform':app['platform'],'checked_at':stamp(),'unknown_previous_upload':False,'pagination_complete':True,'builds':builds,'build_uploads':uploads}
        plan.collision_precheck(result,family);return result

def validate_cache_manifest(value,*,source,family,delivery,run_id):
    require(isinstance(value,dict) and value.get('schema')=='ResaleBurrow-signed-cache-2' and value.get('complete') is True,'cache_manifest_schema_invalid')
    require(value.get('repository')==REPO and value.get('source_sha')==source==SOURCE,'cache_source_pin_mismatch')
    approved=value.get('approved_families');rows=value.get('exports')
    require(isinstance(approved,list) and approved and len(set(approved))==len(approved) and set(approved)<=set(plan.APPS) and family in approved,'approved_family_subset_required')
    require(isinstance(rows,list) and len(rows)==len(approved) and all(isinstance(r,dict) for r in rows) and {r.get('family') for r in rows}==set(approved),'exact_approved_export_subset_required')
    for row in rows:
        app=plan.APPS[row['family']]
        require(row.get('bundle_id')==app['bundle_id'] and row.get('asc_id')==app['asc_id'] and row.get('version')=='0.1.0' and str(row.get('build'))=='1' and row.get('distribution')=='app-store','cache_export_identity_mismatch')
        name='ResaleBurrow-'+row['family']+'-0.1.0-1'+app['suffix']
        require(row.get('name')==name and numeric(row.get('asset_id')) and type(row.get('bytes')) is int and 0<row['bytes']<=MAX_PACKAGE and re.fullmatch(r'[a-f0-9]{64}',row.get('sha256','')),'cache_asset_pin_invalid')
        ci=row.get('export_ci',{});recovery=row.get('recovery',{})
        require(ci.get('repository')==TOOLING_REPO and numeric(ci.get('run_id')) and re.fullmatch(r'[a-f0-9]{40}',ci.get('head_sha','')) and ci.get('status')=='completed' and ci.get('conclusion') in ('success','failure') and ci.get('event') in ('push','workflow_dispatch'),'per_family_actual_export_provenance_required')
        require(recovery.get('authenticated_recovery_verified') is True and recovery.get('archive_command_succeeded') is True and recovery.get('export_command_succeeded') is True and recovery.get('signed_local_validation_passed') is True and recovery.get('export_sha256')==row['sha256'],'authenticated_export_recovery_required')
        for k in ('recovery_receipt_sha256','local_validation_receipt_sha256'):
            require(re.fullmatch(r'[a-f0-9]{64}',recovery.get(k,'')),'pinned_recovery_and_validation_receipts_required')
        if ci['conclusion']=='failure':require(recovery.get('ci_failure_stage')=='post_export_validation' and recovery.get('validation_failure_resolved_locally') is True,'failed_export_run_not_explained_by_verified_recovery')
    require(len({str(r['asset_id']) for r in rows})==len(rows),'cache_asset_ids_not_unique')
    selected=next(r for r in rows if r['family']==family)
    require(selected['export_ci']['head_sha']==delivery and str(selected['export_ci']['run_id'])==str(run_id),'selected_family_export_pin_mismatch')
    return {r['family']:r for r in rows}

def verify_export_run(run,row):
    ci=row['export_ci']
    require(isinstance(run,dict) and str(run.get('id'))==str(ci['run_id']) and run.get('head_sha')==ci['head_sha'] and run.get('status')==ci['status'] and run.get('conclusion')==ci['conclusion'] and run.get('event')==ci['event'],'actual_family_export_run_not_verified')

def verify_assets(assets,manifest_asset_id,manifest_bytes,rows):
    expected={str(manifest_asset_id):(MANIFEST_NAME,manifest_bytes)}
    expected.update({str(r['asset_id']):(r['name'],r['bytes']) for r in rows.values()})
    require(len(expected)==1+len(rows),'cache_manifest_asset_conflict')
    for ident,(name,count) in expected.items():
        found=[r for r in assets if str(r.get('id'))==ident]
        require(len(found)==1 and found[0].get('name')==name and found[0].get('state')=='uploaded' and found[0].get('size')==count,'exact_private_release_asset_not_verified')
    allowed=set(n for n,_ in expected.values())
    # Never turn this cache into an archive, key, profile or diagnostic store.
    require(all(r.get('name') in allowed or re.fullmatch(r'upload-(intent|result)-(ios|macos|tvos)-0[.]1[.]0-1[.]json',r.get('name','')) for r in assets),'unexpected_private_cache_asset')

def strict_revalidate(path,family,work,expected_sha,source):
    """Reuse the frozen platform-tool validator on exported bytes only."""
    import strict_export_validator as strict
    require(plan.digest(path)==expected_sha,'received_export_hash_mismatch')
    expected={i:{'bundle_id':i,'platform':p,'minimum_os':m} for i,(p,m) in strict.EXACT[family].items()}
    runner=strict.Runner(work/'validation-private');destination=work/'expanded-private'
    try:
        if family=='macos':
            runner.package(path,destination)
            roots=[p for p in destination.rglob('*.app') if (p/'Contents/Info.plist').is_file() and strict.load_plist(p/'Contents/Info.plist').get('CFBundleIdentifier')==plan.APPS[family]['bundle_id']]
            require(len(roots)==1,'mac_installer_primary_missing');primary=roots[0]
            require(not any(p.suffix in ('.app','.appex') and p!=primary and not p.is_relative_to(primary) for p in destination.rglob('*') if p.is_dir()),'mac_installer_extra_bundle')
        else:
            destination.mkdir(mode=0o700);primary=strict.extract_ipa(path,destination)
        bundles=strict.bundle_set(primary,expected,runner,datetime.now(timezone.utc))
        require(plan.digest(path)==expected_sha,'export_changed_during_validation')
        return {'status':'passed','family':family,'signed_local_artifacts_verified':True,'export_artifact_sha256':expected_sha,'exact_bundle_count':len(bundles),'team':plan.TEAM,'group':plan.GROUP,'source_sha_basis':source,'uploaded':False,'export_bundles':bundles,'archive_rebuilt':False,'resigned':False}
    except strict.ValidationError as e:raise Invalid('strict_export_'+e.code) from None

def apple_token(environment):
    require(environment.get('TEAMID')==plan.TEAM,'credential_team_mismatch')
    for key in ('FASTLANE_KEY_ID','FASTLANE_ISSUER_ID','FASTLANE_KEY'):require(bool(environment.get(key)),'existing_ci_credentials_missing')
    key=environment['FASTLANE_KEY'].replace('\\n','\n').strip()
    if '-----BEGIN PRIVATE KEY-----' not in key:
        try:key=base64.b64decode(key,validate=True).decode()
        except (ValueError,UnicodeError):raise Invalid('existing_ci_key_format_invalid') from None
    import jwt
    current=int(datetime.now(timezone.utc).timestamp())
    try:return jwt.encode({'iss':environment['FASTLANE_ISSUER_ID'],'iat':current,'exp':current+600,'aud':'appstoreconnect-v1'},key,algorithm='ES256',headers={'kid':environment['FASTLANE_KEY_ID'],'typ':'JWT'})
    except Exception:raise Invalid('existing_ci_key_could_not_sign') from None

def fastlane_once(row,work,tooling):
    require(plan.digest(row['path'])==row['sha256'],'preupload_export_hash_changed')
    payload=plan.fastlane_options(row);input_path=work/'upload-options-private.json';save(input_path,payload)
    env=dict(os.environ,BUNDLE_GEMFILE=str((tooling/'Gemfile').resolve()),RESALE_UPLOAD_OPTIONS=str(input_path),RESALE_PACKAGE_SHA256=row['sha256'],RESALE_EXECUTE_REVIEWED_UPLOAD='true',FASTLANE_SKIP_UPDATE_CHECK='1',FASTLANE_HIDE_CHANGELOG='1',CI='true')
    env.pop('GH_PAT',None);env.pop('GITHUB_TOKEN',None)
    cwd=work/'fastlane-runner';(cwd/'fastlane').mkdir(parents=True,mode=0o700)
    (cwd/'fastlane/Fastfile').write_bytes((HERE/'UploadFastfile').read_bytes())
    out=work/'fastlane-private-stdout.log';err=work/'fastlane-private-stderr.log'
    with out.open('xb') as stdout,err.open('xb') as stderr:
        out.chmod(0o600);err.chmod(0o600)
        try:r=subprocess.run(['bundle','exec','fastlane','upload_resale_cached_once'],cwd=cwd,env=env,stdout=stdout,stderr=stderr,timeout=1800)
        except (OSError,subprocess.TimeoutExpired):raise Invalid('upload_transport_outcome_unknown_no_retry') from None
    require(r.returncode==0,'upload_transport_outcome_unknown_no_retry')
    # Action return means Transporter success, not processing or group assignment.
    return {'status':'transport_reported_success','uploaded':True,'processing_verified':False,'testflight_group_verified':False,'installed':False}

def execute_batch_stage(github,apple,row,release_id,work,*,uploader,source,delivery,execute=False):
    family=row['family'];app=plan.APPS[family]
    name='upload-intent-'+family+'-0.1.0-1.json';result_name='upload-result-'+family+'-0.1.0-1.json'
    assets=github.collection('/repos/'+REPO+'/releases/'+str(release_id)+'/assets')
    require(not any(r.get('name') in (name,result_name) for r in assets),'durable_prior_upload_intent_or_result_stop')
    precheck=apple.precheck(family);save(work/'precheck-private.json',precheck)
    if not execute:return {'status':'preflight_only','upload_attempts':0}
    intent={'schema':'ResaleBurrow-upload-intent-1','operation_id':secrets.token_hex(32),'family':family,'asc_id':app['asc_id'],'bundle_id':app['bundle_id'],'version':'0.1.0','build':'1','export_sha256':row['sha256'],'source_sha':source,'export_delivery_sha':delivery,'reserved_at':stamp(),'upload_ci_run':os.environ.get('GITHUB_RUN_ID'),'outcome':'unknown_until_result'}
    # Uploaded asset names are atomically unique in this canonical private release.
    # HTTP failure/timeout is uncertain and must never call Fastlane.
    reservation=github.upload_marker_once(release_id,name,intent);save(work/'intent-private.json',{'intent':intent,'reservation':reservation})
    result={'schema':'ResaleBurrow-upload-result-1','operation_id':intent['operation_id'],'family':family,'asc_id':app['asc_id'],'version':'0.1.0','build':'1','export_sha256':row['sha256'],'intent':reservation,'recorded_at':stamp(),'status':'unknown','upload_attempts':0}
    try:
        second=apple.precheck(family);save(work/'preupload-private.json',second)
        result['upload_attempts']=1
        outcome=uploader(row,work)
        require(isinstance(outcome,dict) and outcome.get('status')=='transport_reported_success' and outcome.get('uploaded') is True and outcome.get('processing_verified') is False and outcome.get('installed') is False,'upload_transport_outcome_unknown_no_retry')
        result.update(outcome)
    except Exception as error:
        result['status']='unknown_stop_no_retry'
        result['safe_error']=str(error) if isinstance(error,Invalid) else 'unexpected_private_failure'
    save(work/'result-private.json',result)
    # This result contains only fixed status and exact release coordinates.
    # If this write fails, the earlier intent still blocks every later run.
    marker=github.upload_marker_once(release_id,result_name,result);result['durable_result']=marker
    require(result['status']=='transport_reported_success','upload_not_proven_stop_no_retry')
    return result

def ci_gate(environment,tooling):
    require(environment.get('GITHUB_ACTIONS')=='true' and environment.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and environment.get('GITHUB_REPOSITORY')==TOOLING_REPO and environment.get('GITHUB_ACTOR')=='h00l1gvn','reviewed_owner_ci_dispatch_required')
    require(tooling.is_dir() and (tooling/'Gemfile').is_file() and (tooling/'Gemfile.lock').is_file(),'locked_tooling_bundle_missing')
    require(all(plan.digest(tooling/name)==digest for name,digest in DEPENDENCIES.items()),'locked_delivery_dependencies_mismatch')
    head=subprocess.run(['git','rev-parse','HEAD'],cwd=tooling,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    require(head.returncode==0 and head.stdout.decode().strip()==environment.get('GITHUB_SHA'),'reviewed_upload_checkout_mismatch')
    runner=Path(environment.get('RUNNER_TEMP','')).resolve();require(tooling.is_relative_to(Path(environment['GITHUB_WORKSPACE']).resolve()),'tooling_checkout_outside_workspace')
    return runner

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family',choices=tuple(plan.APPS),required=True)
    for key in ('release-id','manifest-asset-id','manifest-sha256','manifest-bytes','source','export-delivery','export-run','work-dir','tooling-dir'):parser.add_argument('--'+key,required=True)
    parser.add_argument('--execute-reviewed-upload',action='store_true');a=parser.parse_args(argv)
    require(numeric(a.release_id) and numeric(a.manifest_asset_id) and numeric(a.export_run) and re.fullmatch(r'[a-f0-9]{64}',a.manifest_sha256) and re.fullmatch(r'[a-f0-9]{40}',a.source) and re.fullmatch(r'[a-f0-9]{40}',a.export_delivery),'independent_exact_cache_pins_required')
    require(a.source==SOURCE and a.manifest_bytes.isdigit() and 0<int(a.manifest_bytes)<=65536,'reviewed_source_and_small_manifest_required')
    tooling=Path(a.tooling_dir).resolve();runner=ci_gate(os.environ,tooling);work=Path(a.work_dir).resolve()
    require(work.is_relative_to(runner) and not work.exists(),'new_ephemeral_private_work_required');work.mkdir(mode=0o700,parents=True)
    github=GitHub(os.environ.get('GH_PAT',''));require(bool(github.token),'existing_github_ci_credential_missing')
    assets=github.verify_private_release(a.release_id)
    manifest=github.download_asset(a.manifest_asset_id,a.manifest_sha256,int(a.manifest_bytes));save(work/'cache-manifest-private.json',json.loads(manifest))
    rows=validate_cache_manifest(json.loads(manifest),source=a.source,family=a.family,delivery=a.export_delivery,run_id=a.export_run)
    verify_assets(assets,a.manifest_asset_id,int(a.manifest_bytes),rows)
    run=github.get('/repos/'+TOOLING_REPO+'/actions/runs/'+a.export_run)
    verify_export_run(run,rows[a.family])
    row=rows[a.family];raw=github.download_asset(row['asset_id'],row['sha256'],row['bytes']);path=work/row['name'];path.write_bytes(raw);path.chmod(0o600);del raw
    validation=strict_revalidate(path,a.family,work,row['sha256'],a.source);save(work/'strict-validation-private.json',validation)
    verified=plan.validate_export({'family':a.family,'distribution':'app-store','version':'0.1.0','build':'1','source_sha':a.source,'delivery_sha':a.export_delivery,'authenticated_recovery_verified':True,'path':str(path),'sha256':row['sha256'],'validation':validation},a.source,a.export_delivery)
    apple=Apple(apple_token(os.environ))
    result=execute_batch_stage(github,apple,verified,a.release_id,work,uploader=lambda row,work:fastlane_once(row,work,tooling),source=a.source,delivery=a.export_delivery,execute=a.execute_reviewed_upload)
    save(work/'final-private.json',{'status':result['status'],'family':a.family,'source_sha':a.source,'export_delivery_sha':a.export_delivery,'cache_manifest_sha256':a.manifest_sha256,'package_sha256':row['sha256'],'result':result,'raw_diagnostics_private':True,'rebuilds':0,'resigns':0})
    print('Cached upload stage completed; exact package recorded privately. Processing and devices remain separate.')

if __name__=='__main__':
    try:main()
    except (Invalid,plan.Invalid) as e:print('Cached upload stopped: '+str(e));raise SystemExit(2)
    except Exception:print('Cached upload stopped; details stay private, no automatic retry.');raise SystemExit(2)
