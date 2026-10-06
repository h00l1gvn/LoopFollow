#!/usr/bin/env python3
"""Exact build2 cached Store uploads: one transport, append-only private intent/results."""
import argparse,datetime,hashlib,json,os,pathlib,re,subprocess,sys,tempfile
from urllib.parse import urlparse,parse_qs
from urllib.request import Request,build_opener,HTTPRedirectHandler
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent))
import build2_contract as c
import validate_resale_export as strict
import mac_payload_permissions as permissions
SOURCE='038c9e2b61b5b6c28355c478c883edee8372e330'
EXPORT_HEAD='b2ca4a6181bd94fc969534de8299d743da3c3b7b'
EXPORT_RUN=37509737158
APPS={'ios':('6819601040','com.julienbell.ResaleBurrow','IOS',4,112427478251),'macos':('6819601423','com.julienbell.ResaleBurrow.mac','MAC_OS',2,112427477737),'tvos':('6819601651','com.julienbell.ResaleBurrow.tv','TV_OS',1,112427478149)}
BRANCH='codex/resale-burrow-build2-upload-cached'
class Stop(ValueError):pass
def need(v,k):
 if not v:raise Stop(k)
def sha(b):return hashlib.sha256(b).hexdigest()
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(p,v):
 with pathlib.Path(p).open('x') as f:json.dump(v,f,indent=2);f.write('\n')
 pathlib.Path(p).chmod(0o600)
def owner_gate(env):
 need(env.get('GITHUB_ACTIONS')=='true' and env.get('GITHUB_REPOSITORY')=='h00l1gvn/LoopFollow' and env.get('GITHUB_ACTOR')=='h00l1gvn' and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and env.get('GITHUB_REF')=='refs/heads/'+BRANCH and env.get('GITHUB_RUN_ATTEMPT')=='1','exact_owner_dispatch_required')
def package_manifest(v,pins):
 need(v.get('schema')=='ReBurrow-build2-cached-export-1' and v.get('source_sha')==SOURCE and v.get('version')=='0.1.0' and str(v.get('build'))=='2' and v.get('family')==pins['family'] and v.get('package_sha256')==pins['package_sha256'] and v.get('package_bytes')==pins['package_bytes'] and v.get('package_name')==pins['package_name'] and v.get('export_run_id')==EXPORT_RUN and v.get('export_job_id')==APPS[pins['family']][4] and v.get('export_head_sha')==EXPORT_HEAD and v.get('strict_validation_passed') is True and v.get('ephemeral_cleanup_verified') is True and v.get('recipient_context_authenticated') is True,'exact_cached_package_manifest_required')
def ci_gate(run,job,family):
 need(run.get('id')==EXPORT_RUN and run.get('head_sha')==EXPORT_HEAD and run.get('run_attempt')==1 and run.get('event')=='push' and run.get('path')=='.github/workflows/resale-build2-protected-export.yml' and run.get('actor',{}).get('login')=='h00l1gvn' and job.get('id')==APPS[family][4] and job.get('run_id')==EXPORT_RUN and job.get('head_sha')==EXPORT_HEAD and job.get('run_attempt')==1 and job.get('name')==f'export ({family})' and job.get('status')=='completed' and job.get('conclusion')=='success','actual_successful_family_export_required')
def marker_names(family):return [f'{kind}-{family}-0.1.0-2.json' for kind in (['validation-intent','validation-result','upload-intent','upload-result'] if family=='macos' else ['upload-intent','upload-result'])]
def stage_gate(names,pins,name=None):
 base={pins['package_name'],pins['manifest_name']};stages=marker_names(pins['family'])
 required=base if name is None else base|set(stages[:stages.index(name)])
 need(set(names)==required and len(names)==len(set(names)),'unexpected_or_prior_operation_marker_stop_no_retry')
def release_gate(row,pins):
 need(row.get('id')==pins['release_id'] and row.get('tag_name')==pins['release_tag']=='resale-burrow-0.1.0-build-2-'+pins['family']+'-'+SOURCE[:12] and row.get('target_commitish')==SOURCE and row.get('draft') is True and row.get('prerelease') is True,'exact_private_release_required')
def command(package,family,key,issuer,action):
 need(family in APPS and action in ('upload','validate') and re.fullmatch(r'[A-Z0-9]{5,30}',key or '') and re.fullmatch(r'[0-9a-fA-F-]{36}',issuer or ''),'altool_arguments_invalid')
 return ['/usr/bin/xcrun','altool','--'+action+'-app','-f',str(package),'-t',{'ios':'ios','macos':'macos','tvos':'appletvos'}[family],'--apiKey',key,'--apiIssuer',issuer,'--output-format','json']
def once(package,family,work,env,run,action):
 keys=work/('ephemeral-'+action+'-key');keys.mkdir(mode=0o700);file=keys/('AuthKey_'+env['FASTLANE_KEY_ID']+'.p8');previous=env.get('API_PRIVATE_KEYS_DIR')
 try:
  file.write_text(env['FASTLANE_KEY'].replace('\\n','\n').strip()+'\n');file.chmod(0o600);env['API_PRIVATE_KEYS_DIR']=str(keys)
  try:
   r=run(command(package,family,env['FASTLANE_KEY_ID'],env['FASTLANE_ISSUER_ID'],action),'single-Apple-'+action,1200)
   return ('tool_reported_success' if r.returncode==0 else 'tool_reported_failure_stop_no_retry',r.returncode)
  except (subprocess.TimeoutExpired,OSError):return ('outcome_unknown_stop_no_retry',None)
 finally:
  file.unlink(missing_ok=True);keys.rmdir()
  if previous is None:env.pop('API_PRIVATE_KEYS_DIR',None)
  else:env['API_PRIVATE_KEYS_DIR']=previous
class GitHub:
 def __init__(self,pins):self.pins=pins;self.base='repos/h00l1gvn/resale-burrow-native'
 def api(self,path,binary=False):
  need(path in {self.base,self.base+'/releases/'+str(self.pins['release_id']),f'repos/h00l1gvn/LoopFollow/actions/runs/{EXPORT_RUN}',f'repos/h00l1gvn/LoopFollow/actions/jobs/{APPS[self.pins["family"]][4]}'} or bool(re.fullmatch(re.escape(self.base)+r'/releases/assets/[1-9][0-9]*',path)),'GitHub_GET_outside_scope')
  r=subprocess.run(['gh','api',path]+(['-H','Accept: application/octet-stream'] if binary else []),capture_output=True,timeout=120);need(r.returncode==0,'private_GET_failed');return r.stdout if binary else json.loads(r.stdout)
 def asset(self,aid,name,digest,size,row):
  meta=self.api(self.base+'/releases/assets/'+str(aid));need(meta.get('id')==aid and meta.get('name')==name and meta.get('state')=='uploaded' and meta.get('size')==size and sum(a['id']==aid for a in row['assets'])==1,'private_asset_identity_mismatch');raw=self.api(self.base+'/releases/assets/'+str(aid),True);need(len(raw)==size and sha(raw)==digest,'private_asset_hash_mismatch');return raw
 def marker(self,path):
  need(path.name in marker_names(self.pins['family']),'marker_name_forbidden');row=self.api(self.base+'/releases/'+str(self.pins['release_id']));release_gate(row,self.pins);stage_gate([x['name'] for x in row['assets']],self.pins,path.name)
  r=subprocess.run(['gh','release','upload',self.pins['release_tag'],str(path),'--repo','h00l1gvn/resale-burrow-native'],capture_output=True,timeout=120);need(r.returncode==0,'journal_write_unknown_stop_no_retry');new=self.api(self.base+'/releases/'+str(self.pins['release_id']));release_gate(new,self.pins);need({x['name'] for x in new['assets']}=={x['name'] for x in row['assets']}|{path.name},'journal_stage_readback_unknown');found=[x for x in new['assets'] if x['name']==path.name];need(len(found)==1,'journal_readback_unknown');raw=self.api(self.base+'/releases/assets/'+str(found[0]['id']),True);need(raw==path.read_bytes(),'journal_readback_mismatch');return {'id':found[0]['id'],'sha256':sha(raw)}
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
class Apple:
 def __init__(self,token,family,opener=None):self.token=token;self.family=family;self.ids=set();self.opener=opener or build_opener(NoRedirect())
 def get(self,path):
  p=urlparse(path);q=parse_qs(p.query);base='/v1/apps/'+APPS[self.family][0]
  need((p.path in {base,base+'/builds',base+'/buildUploads'} or bool(re.fullmatch(r'/v1/builds/[A-Za-z0-9_-]{1,100}/preReleaseVersion',p.path) and p.path.split('/')[3] in self.ids)) and not p.scheme and not p.netloc and not p.fragment and set(q)<= {'limit','cursor'} and all(len(v)==1 for v in q.values()),'Apple_GET_outside_scope')
  try:
   with self.opener.open(Request('https://api.appstoreconnect.apple.com'+path,headers={'Authorization':'Bearer '+self.token,'Accept':'application/json'},method='GET'),timeout=60) as r:
    raw=r.read(2*1024**2+1);need(r.status==200 and len(raw)<=2*1024**2,'Apple_response_invalid');return json.loads(raw)
  except Stop:raise
  except Exception:raise Stop('Apple_GET_unavailable_no_upload') from None
 def collection(self,path):
  rows=[];seen=set()
  for _ in range(10):
   need(path not in seen,'Apple_pagination_loop');seen.add(path);v=self.get(path);need(isinstance(v.get('data'),list),'Apple_collection_unknown');rows+=v['data'];n=v.get('links',{}).get('next')
   if not n:return rows
   p=urlparse(n);need(p.scheme in ('','https') and p.netloc in ('','api.appstoreconnect.apple.com'),'Apple_pagination_origin_invalid');path=p.path+('?' +p.query if p.query else '')
  raise Stop('Apple_collection_incomplete')
 def collision(self):
  aid,bid,platform,_,_=APPS[self.family];app=self.get('/v1/apps/'+aid)['data'];need(app.get('id')==aid and app.get('attributes',{}).get('bundleId')==bid,'Apple_app_identity_mismatch');exact=[]
  for b in self.collection('/v1/apps/'+aid+'/builds?limit=200'):
   need(b.get('type')=='builds' and re.fullmatch(r'[A-Za-z0-9_-]{1,100}',b.get('id','')),'Apple_build_shape_unknown');self.ids.add(b['id']);v=self.get('/v1/builds/'+b['id']+'/preReleaseVersion')['data'];need(v.get('type')=='preReleaseVersions' and v.get('attributes',{}).get('platform')==platform and isinstance(b.get('attributes',{}).get('version'),str),'Apple_build_version_unknown')
   if v['attributes'].get('version')=='0.1.0' and b['attributes']['version']=='2':exact.append({'kind':'build','id':b['id']})
  for b in self.collection('/v1/apps/'+aid+'/buildUploads?limit=200'):
   a=b.get('attributes',{});need(b.get('type')=='buildUploads' and a.get('platform')==platform and isinstance(a.get('cfBundleVersion'),str) and isinstance(a.get('cfBundleShortVersionString'),str),'Apple_upload_shape_unknown')
   if a['cfBundleShortVersionString']=='0.1.0' and a['cfBundleVersion']=='2':exact.append({'kind':'buildUpload','id':b['id']})
  need(not exact,'exact_existing_build2_collision_stop_no_retry');return {'checked_at':stamp(),'complete':True,'exact_records':[]}
def fresh_collision(env,family,client_factory=Apple):
 import jwt
 need(env.get('TEAMID')==c.TEAM,'existing_team_secret_mismatch')
 key=env['FASTLANE_KEY'].replace('\\n','\n');t=int(datetime.datetime.now(datetime.timezone.utc).timestamp())
 token=jwt.encode({'iss':env['FASTLANE_ISSUER_ID'],'iat':t,'exp':t+600,'aud':'appstoreconnect-v1'},key,algorithm='ES256',headers={'kid':env['FASTLANE_KEY_ID'],'typ':'JWT'})
 return client_factory(token,family).collision()
def main():
 p=argparse.ArgumentParser();p.add_argument('--pins',type=pathlib.Path,required=True);p.add_argument('--scope',type=pathlib.Path,required=True);p.add_argument('--work',type=pathlib.Path,required=True);a=p.parse_args();owner_gate(os.environ);pins=json.loads(a.pins.read_text());scope=json.loads(a.scope.read_text());family=pins['family'];need(os.environ.get('APPROVED_FAMILY')==family and os.environ.get('APPROVED_PACKAGE_SHA256')==pins['package_sha256'],'exact_manual_package_approval_required');need(scope['source_sha']==SOURCE,'current_frozen_source_required');strict.scope_check(scope,family)
 work=a.work.resolve();need(work.is_relative_to(pathlib.Path(os.environ['RUNNER_TEMP']).resolve()) and not work.exists(),'private_work_required');work.mkdir(mode=0o700)
 def run(argv,label,timeout=120):
  r=subprocess.run([str(x) for x in argv],capture_output=True,timeout=timeout)
  for part,data in [('stdout',r.stdout),('stderr',r.stderr)]:
   q=work/(label+'-'+part+'.bin');q.write_bytes(data);q.chmod(0o600)
  save(work/(label+'-exit.json'),{'returncode':r.returncode,'at':stamp()});return r
 need(run(['/usr/bin/xcodebuild','-version'],'Xcode').stdout.decode().startswith('Xcode 26.2\n'),'current_Xcode_required');h=run(['/usr/bin/xcrun','altool','--help'],'altool-help');need(h.returncode==0 and all(f.encode() in h.stdout+h.stderr for f in ['--upload-app','--apiKey','--apiIssuer','--output-format']),'current_altool_upload_help_required')
 gh=GitHub(pins);need(gh.api(gh.base).get('private') is True,'private_repository_required');row=gh.api(gh.base+'/releases/'+str(pins['release_id']));release_gate(row,pins);stage_gate([x['name'] for x in row['assets']],pins);ci_gate(gh.api(f'repos/h00l1gvn/LoopFollow/actions/runs/{EXPORT_RUN}'),gh.api(f'repos/h00l1gvn/LoopFollow/actions/jobs/{APPS[family][4]}'),family)
 manifest=json.loads(gh.asset(pins['manifest_asset_id'],pins['manifest_name'],pins['manifest_sha256'],pins['manifest_bytes'],row));package_manifest(manifest,pins);package=work/pins['package_name'];package.write_bytes(gh.asset(pins['package_asset_id'],pins['package_name'],pins['package_sha256'],pins['package_bytes'],row));package.chmod(0o600)
 runner=strict.Runner(work/'strict-private');destination=work/'expanded';now=datetime.datetime.now(datetime.timezone.utc)
 if family=='macos':
  installer=runner.package(package,destination);apps=[x for x in destination.rglob('*.app') if (x/'Contents/Info.plist').is_file() and strict.load_plist(x/'Contents/Info.plist').get('CFBundleIdentifier')==APPS[family][1]];need(len(apps)==1,'exact_Mac_primary_required');primary=apps[0]
 else:destination.mkdir(mode=0o700);primary=strict.extract_ipa(package,destination)
 bundles=strict.bundle_set(primary,strict.scope_check(scope,family),runner,now);need(len(bundles)==APPS[family][3],'exact_family_bundle_count_required')
 if family=='macos':
  repair=c.source_payload_scope(permissions.tree_snapshot(primary),bundles)
  class PermissionRunner:
   def run(self,args,label,timeout=120):
    r=run(args,'stored-'+label,timeout);need(r.returncode==0,'stored_metadata_tool_failed');return r.stdout
  stored=permissions.check_package(package,repair,PermissionRunner(),work)
 for action in (['validate','upload'] if family=='macos' else ['upload']):
  kind='validation' if action=='validate' else 'upload';fresh=fresh_collision(os.environ,family);save(work/('fresh-outcome-'+kind+'.json'),fresh);intent={'schema':'ReBurrow-build2-'+kind+'-intent-1','operation_key':sha((SOURCE+family+'2'+pins['package_sha256']).encode())+'-'+kind,'created_at':stamp(),'family':family,'version':'0.1.0','build':'2','source_sha':SOURCE,'package_sha256':pins['package_sha256'],'export_run':EXPORT_RUN,'ci_run':os.environ['GITHUB_RUN_ID'],'fresh_collision':fresh,'attempts':1,'outcome':'unknown_until_result'};q=work/(kind+'-intent-'+family+'-0.1.0-2.json');save(q,intent);ref=gh.marker(q)
  status,code=once(package,family,work,os.environ,run,action);need(sha(package.read_bytes())==pins['package_sha256'],'package_changed_during_transport');result={**intent,'schema':'ReBurrow-build2-'+kind+'-result-1','completed_at':stamp(),'status':status,'returncode':code,'intent':ref,'strict_bundle_count':len(bundles),'no_rebuild_resign_or_install':True,'historical_journals_untouched':True,'processing_or_install_not_claimed':True};q=work/(kind+'-result-'+family+'-0.1.0-2.json');save(q,result);gh.marker(q);need(status=='tool_reported_success','Apple_transport_stopped_no_retry')
 print('Exact build2 upload completed once; processing and installation remain separate.')
if __name__=='__main__':
 try:main()
 except Exception as e:print(str(e) if isinstance(e,Stop) else 'build2_upload_stopped_protected_diagnostics_required');raise SystemExit(2)
