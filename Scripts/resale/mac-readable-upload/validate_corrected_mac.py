#!/usr/bin/env python3
"""One reviewed Apple validation-only transmission of the corrected Mac PKG. NO UPLOAD."""
from __future__ import annotations
import argparse, datetime, hashlib, json, os, pathlib, re, subprocess, tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, build_opener, HTTPRedirectHandler
import mac_payload_permissions as permissions
import validate_resale_export as strict

SCOPE_SHA='946c9b9ab6615cefd7c7004119a1d37d57b60b38289f41c8c22957eb6e124af0'
BRANCH='codex/resale-burrow-mac-validate-readable'
INTENT='validation-intent-macos-readable-37491147579.json'
RESULT='validation-result-macos-readable-37491147579.json'
class Stop(ValueError):pass
def need(v,c):
    if not v:raise Stop(c)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(p,v):
    with pathlib.Path(p).open('x') as f:json.dump(v,f,indent=2);f.write('\n')
    pathlib.Path(p).chmod(0o600)
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def owner_gate(env):
    need(env.get('GITHUB_ACTIONS')=='true' and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and
         env.get('GITHUB_REPOSITORY')=='h00l1gvn/LoopFollow' and env.get('GITHUB_ACTOR')=='h00l1gvn' and
         env.get('GITHUB_REF')=='refs/heads/'+BRANCH and re.fullmatch(r'[0-9a-f]{40}',env.get('GITHUB_SHA','')),
         'owner_validation_dispatch_required')
def command(package,keyid,issuer):
    need(re.fullmatch(r'[A-Z0-9]{5,30}',keyid or '') and re.fullmatch(r'[0-9A-Fa-f-]{36}',issuer or ''),'existing_key_identifiers_invalid')
    return ['/usr/bin/xcrun','altool','--validate-app','-f',str(package),'-t','macos','--apiKey',keyid,'--apiIssuer',issuer,'--output-format','json']
def help_gate(raw):
    text=raw.decode('utf8',errors='replace')
    need(all(flag in text for flag in ['--validate-app','--apiKey','--apiIssuer','--output-format']) and
         ('macos' in text.lower() or 'osx' in text.lower()),'current_altool_validation_syntax_unavailable')
def manifest_check(value,scope,rid,aid):
    for key,v in scope.items():need(value.get(key)==v,'corrected_manifest_scope_mismatch')
    need(value.get('private_release_id')==rid and value.get('package_asset_id')==aid and
         value.get('Apple_validation_executed') is False and value.get('Apple_upload_executed') is False,
         'corrected_cache_identity_mismatch')
def release_check(row,scope,rid):
    need(row.get('id')==rid and row.get('tag_name')==scope['new_private_release_tag'] and row.get('draft') is True and
         row.get('prerelease') is True and row.get('target_commitish')==scope['source_sha'],'corrected_private_release_identity_mismatch')
    names={a['name'] for a in row['assets']}
    need(INTENT not in names and RESULT not in names,'prior_validation_attempt_stop_no_retry')
    need(names=={scope['package_name'],scope['manifest_name']},'unexpected_corrected_release_assets')

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
class ASC:
    """Credential-bound HTTPS GET allowlist; no Apple mutation method exists."""
    def __init__(self,token,opener=None):self.token=token;self.opener=opener or build_opener(NoRedirect());self.builds=set()
    def get(self,path):
        p=urlparse(path);query=parse_qs(p.query);base='/v1/apps/6819601423'
        allowed=p.path in {base,base+'/builds',base+'/buildUploads'} or bool(re.fullmatch(r'/v1/builds/([A-Za-z0-9_-]{1,100})/preReleaseVersion',p.path) and p.path.split('/')[3] in self.builds)
        need(allowed and not p.fragment and not p.username and not p.password and (not p.netloc or p.netloc=='api.appstoreconnect.apple.com') and (not p.scheme or p.scheme=='https') and set(query)<= {'limit','cursor'} and all(len(v)==1 for v in query.values()),'Apple_GET_outside_exact_scope')
        url=path if p.scheme else 'https://api.appstoreconnect.apple.com'+path
        try:
            with self.opener.open(Request(url,method='GET',headers={'Authorization':'Bearer '+self.token,'Accept':'application/json'}),timeout=60) as response:
                need(response.status==200,'Apple_GET_status_unknown');raw=response.read(2*1024*1024+1);need(len(raw)<=2*1024*1024,'Apple_GET_response_bound');return json.loads(raw)
        except (HTTPError,URLError,TimeoutError,OSError,ValueError):raise Stop('Apple_GET_unavailable_no_validation') from None
    def collection(self,path):
        seen=set();rows=[]
        for _ in range(10):
            need(path not in seen,'Apple_GET_pagination_loop');seen.add(path);value=self.get(path)
            need(isinstance(value.get('data'),list),'Apple_GET_collection_shape');rows.extend(value['data'])
            nextpage=value.get('links',{}).get('next')
            if not nextpage:return rows
            need(isinstance(nextpage,str),'Apple_GET_next_unknown');path=nextpage
        raise Stop('Apple_GET_collection_incomplete')
def fresh_collision(client):
    app=client.get('/v1/apps/6819601423')['data']
    need(app.get('type')=='apps' and app.get('id')=='6819601423' and app.get('attributes',{}).get('bundleId')=='com.julienbell.ResaleBurrow.mac','Apple_exact_app_mismatch')
    exact=[]
    for row in client.collection('/v1/apps/6819601423/builds?limit=200'):
        need(row.get('type')=='builds' and re.fullmatch(r'[A-Za-z0-9_-]{1,100}',row.get('id','')),'Apple_build_identity_unknown');client.builds.add(row['id'])
        version=client.get('/v1/builds/'+row['id']+'/preReleaseVersion')['data'];attrs=version.get('attributes',{})
        need(version.get('type')=='preReleaseVersions' and attrs.get('platform')=='MAC_OS' and isinstance(attrs.get('version'),str) and isinstance(row.get('attributes',{}).get('version'),str),'Apple_build_coordinates_unknown')
        if attrs['version']=='0.1.0' and row['attributes']['version']=='1':exact.append({'kind':'build','id':row['id']})
    for row in client.collection('/v1/apps/6819601423/buildUploads?limit=200'):
        attrs=row.get('attributes',{});state=attrs.get('state',{});state=state.get('state') if isinstance(state,dict) else None
        need(row.get('type')=='buildUploads' and re.fullmatch(r'[A-Za-z0-9_-]{1,100}',row.get('id','')) and attrs.get('platform')=='MAC_OS' and isinstance(attrs.get('cfBundleShortVersionString'),str) and isinstance(attrs.get('cfBundleVersion'),str) and isinstance(state,str),'Apple_upload_coordinates_unknown')
        if attrs['cfBundleShortVersionString']=='0.1.0' and attrs['cfBundleVersion']=='1':exact.append({'kind':'buildUpload','id':row['id'],'state':state})
    need(not exact,'existing_exact_Apple_build_or_upload_collision')
    return {'checked_at':stamp(),'complete':True,'exact_records':[],'absence_is_not_prior_upload_resolution':True}
class GitHub:
    def __init__(self,scope,rid):self.scope=scope;self.rid=rid
    def api(self,path,binary=False):
        base='repos/'+self.scope['private_repository']
        need(path==base or path==base+'/releases/'+str(self.rid) or bool(re.fullmatch(re.escape(base)+r'/releases/assets/[1-9][0-9]*',path)) or path==f'repos/{self.scope["tooling_repository"]}/actions/runs/{self.scope["package_run_id"]}' or path==f'repos/{self.scope["tooling_repository"]}/actions/jobs/{self.scope["package_job_id"]}', 'GitHub_GET_outside_scope')
        args=['gh','api',path]+(['--header','Accept: application/octet-stream'] if binary else [])
        r=subprocess.run(args,capture_output=True,timeout=120);need(r.returncode==0,'private_cache_GET_failed');return r.stdout if binary else json.loads(r.stdout)
    def upload_journal(self,path):
        need(path.name in {INTENT,RESULT},'validation_journal_name_forbidden')
        row=self.api('repos/'+self.scope['private_repository']+'/releases/'+str(self.rid))
        need(row['id']==self.rid and row['tag_name']==self.scope['new_private_release_tag'] and row['draft'] is True and row['prerelease'] is True and row['target_commitish']==self.scope['source_sha'],'private_validation_journal_release_changed')
        need(not any(a['name']==path.name for a in row['assets']),'prior_validation_journal_stop_no_retry')
        result=subprocess.run(['gh','release','upload',self.scope['new_private_release_tag'],str(path),'--repo',self.scope['private_repository']],capture_output=True,timeout=120)
        need(result.returncode==0,'validation_journal_write_unknown_stop_no_retry')
        row=self.api('repos/'+self.scope['private_repository']+'/releases/'+str(self.rid));matches=[a for a in row['assets'] if a['name']==path.name];need(len(matches)==1,'validation_journal_readback_unknown')
        raw=self.api('repos/'+self.scope['private_repository']+'/releases/assets/'+str(matches[0]['id']),binary=True);need(sha(raw)==sha(path.read_bytes()),'validation_journal_readback_mismatch')
        return {'id':matches[0]['id'],'sha256':sha(raw)}
def apple_token(env):
    import jwt
    need(env.get('TEAMID')=='N8K8G6QA36','existing_team_secret_mismatch')
    key=env.get('FASTLANE_KEY','').replace('\\n','\n').strip();need('PRIVATE KEY' in key,'existing_API_key_missing')
    now=int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    return jwt.encode({'iss':env['FASTLANE_ISSUER_ID'],'iat':now,'exp':now+600,'aud':'appstoreconnect-v1'},key,algorithm='ES256',headers={'kid':env['FASTLANE_KEY_ID'],'typ':'JWT'})

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--scope',type=pathlib.Path,required=True);parser.add_argument('--release-id',type=int,required=True);parser.add_argument('--manifest-asset-id',type=int,required=True);parser.add_argument('--manifest-sha256',required=True);parser.add_argument('--package-asset-id',type=int,required=True);parser.add_argument('--work-dir',type=pathlib.Path,required=True);a=parser.parse_args()
    owner_gate(os.environ);raw=a.scope.read_bytes();need(sha(raw)==SCOPE_SHA,'reviewed_scope_hash_mismatch');scope=json.loads(raw)
    for name,expected in [('validate_resale_export.py',scope['strict_validator_sha256']),('mac_payload_permissions.py',scope['permission_helper_sha256']),('permission-repair-scope.json','2895adf5ff55cd0ea58864169cf15af06be2138955d0e3c1bf19a868362768fb')]:
        need(sha((a.scope.parent/name).read_bytes())==expected,'reviewed_local_dependency_hash_mismatch')
    need(subprocess.check_output(['git','rev-parse','HEAD']).decode().strip()==os.environ['GITHUB_SHA'],'validation_checkout_head_mismatch')
    need(all(v>0 for v in [a.release_id,a.manifest_asset_id,a.package_asset_id]) and a.release_id!=scope['old_private_release_id'] and re.fullmatch(r'[0-9a-f]{64}',a.manifest_sha256),'exact_new_cache_inputs_required')
    work=a.work_dir.resolve();need(work.is_relative_to(pathlib.Path(os.environ['RUNNER_TEMP']).resolve()) and not work.exists(),'private_work_destination_required');work.mkdir(mode=0o700)
    def run(args,label,timeout=120):
        result=subprocess.run([str(x) for x in args],capture_output=True,timeout=timeout)
        for part,contents in [('stdout',result.stdout),('stderr',result.stderr)]:
            path=work/(label+'-'+part+'.bin');path.write_bytes(contents);path.chmod(0o600)
        save(work/(label+'-exit.json'),{'returncode':result.returncode,'observed_at':stamp()});return result
    xcode=run(['/usr/bin/xcodebuild','-version'],'xcode');need(xcode.returncode==0 and re.search(r'^Xcode 26\.2$',xcode.stdout.decode(),re.M),'current_Xcode26_2_required')
    help=run(['/usr/bin/xcrun','altool','--help'],'current-altool-help');need(help.returncode==0,'current_altool_help_failed');help_gate(help.stdout+help.stderr)
    client=GitHub(scope,a.release_id);base='repos/'+scope['private_repository'];need(client.api(base)['private'] is True,'private_cache_repository_required')
    release=client.api(base+'/releases/'+str(a.release_id));release_check(release,scope,a.release_id)
    def asset(aid,name,digest,size=None):
        meta=client.api(base+'/releases/assets/'+str(aid));need(meta['id']==aid and meta['name']==name and meta['state']=='uploaded' and (size is None or meta['size']==size) and any(x['id']==aid for x in release['assets']),'exact_cache_asset_metadata_mismatch')
        raw=client.api(base+'/releases/assets/'+str(aid),binary=True);need(len(raw)==meta['size'] and sha(raw)==digest,'exact_cache_asset_hash_mismatch');return raw
    manifest=json.loads(asset(a.manifest_asset_id,scope['manifest_name'],a.manifest_sha256));manifest_check(manifest,scope,a.release_id,a.package_asset_id)
    package=work/scope['package_name'];package.write_bytes(asset(a.package_asset_id,scope['package_name'],scope['package_sha256'],scope['package_bytes']));package.chmod(0o600)
    for row in scope['old_journals']:
        raw=client.api(base+'/releases/assets/'+str(row['asset_id']),binary=True);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'old_unknown_journal_changed')
    ci=client.api(f'repos/{scope["tooling_repository"]}/actions/runs/{scope["package_run_id"]}');job=client.api(f'repos/{scope["tooling_repository"]}/actions/jobs/{scope["package_job_id"]}')
    need(ci['head_sha']==scope['package_head_sha'] and ci['status']=='completed' and ci['conclusion']=='success' and ci['event']=='push' and ci['run_attempt']==1 and ci['actor']['login']=='h00l1gvn' and ci['path']==scope['package_workflow_path'] and job['run_id']==scope['package_run_id'] and job['head_sha']==scope['package_head_sha'] and job['name']=='package' and job['status']=='completed' and job['conclusion']=='success' and job['run_attempt']==1,'actual_package_CI_identity_mismatch')
    repair=json.loads((a.scope.parent/'permission-repair-scope.json').read_text())
    class BytesRunner:
        def run(self,args,label,timeout=120):
            result=run(args,label,timeout);need(result.returncode==0,'local_permission_command_failed');return result.stdout
    stored=permissions.check_package(package,repair['permission_repair'],BytesRunner(),work)
    strict_runner=strict.Runner(work/'strict-private');installed=strict_runner.package(package,work/'expanded-private')
    apps=list((work/'expanded-private').rglob('*.app'));need(len(apps)==1,'exact_export_primary_required')
    bundles=strict.bundle_set(apps[0],strict.scope_check(repair,'macos'),strict_runner,datetime.datetime.now(datetime.timezone.utc))
    need(len(bundles)==2,'exact_Mac2_bundles_required')
    fresh=fresh_collision(ASC(apple_token(os.environ)));save(work/'fresh-Apple-outcome.json',fresh)
    intent={'schema':'ResaleBurrow-validation-only-intent-1','operation_key':scope['operation_key']+'-Apple-validation-only','reserved_at':stamp(),'package_sha256':scope['package_sha256'],'package_run_id':scope['package_run_id'],'validation_ci_run':os.environ['GITHUB_RUN_ID'],'fresh_collision':fresh,'action':'altool_validate_app_only','Apple_upload_action':False,'outcome':'unknown_until_result'}
    save(work/INTENT,intent);journal=client.upload_journal(work/INTENT)
    keys=work/'ephemeral-private-keys';keys.mkdir(mode=0o700);keyid=os.environ['FASTLANE_KEY_ID'];issuer=os.environ['FASTLANE_ISSUER_ID'];argv=command(package,keyid,issuer);keypath=keys/('AuthKey_'+keyid+'.p8')
    keypath.write_text(os.environ['FASTLANE_KEY'].replace('\\n','\n').strip()+'\n');keypath.chmod(0o600)
    previous=os.environ.get('API_PRIVATE_KEYS_DIR');os.environ['API_PRIVATE_KEYS_DIR']=str(keys)
    try:
        try:result=run(argv,'single-Apple-validation',timeout=1200);status='validation_tool_reported_success' if result.returncode==0 else 'validation_rejected_stop_no_retry';exitcode=result.returncode
        except (subprocess.TimeoutExpired,OSError):status='validation_outcome_unknown_stop_no_retry';exitcode=None
    finally:
        keypath.unlink(missing_ok=True);keys.rmdir()
        if previous is None:os.environ.pop('API_PRIVATE_KEYS_DIR',None)
        else:os.environ['API_PRIVATE_KEYS_DIR']=previous
    need(sha(package.read_bytes())==scope['package_sha256'],'package_changed_during_validation')
    record={'schema':'ResaleBurrow-validation-only-result-1','recorded_at':stamp(),'status':status,'returncode':exitcode,'package_sha256':scope['package_sha256'],'source_sha':scope['source_sha'],'package_run_id':scope['package_run_id'],'validation_ci_run':os.environ['GITHUB_RUN_ID'],'intent':journal,'stored_payload':stored,'strict_bundle_count':len(bundles),'installer_chain_verified':installed['installer_chain_trust_verified'],'validation_attempts':1,'Apple_upload_action':False,'old_upload_journals_untouched':True,'no_rebuild_resign_install':True}
    save(work/RESULT,record);client.upload_journal(work/RESULT)
    need(status=='validation_tool_reported_success','validation_did_not_report_success_stop_no_retry')
    print('Exact corrected Mac package validation-only completed; no Apple upload or device action.')
if __name__=='__main__':
    try:main()
    except Exception as error:
        print(str(error) if isinstance(error,Stop) else 'validation_only_stopped_private_diagnostics_required');raise SystemExit(2)
