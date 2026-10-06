#!/usr/bin/env python3
"""Exactly four new Julien ad-hoc profiles. Hardware input stays private."""
from __future__ import annotations
import argparse,base64,copy,datetime,hashlib,json,os,pathlib,re,sys,time
from urllib.parse import urlsplit,parse_qs,urlencode
from urllib.request import Request
from urllib.error import HTTPError,URLError
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent))
import build2_contract as c
import build2_profile_audit as ap
import resale_apple_audit as audit
# Reuse the reviewed CMS dual-decode/signature verification, without Bryan routes.
from bryan.prepare_bryan_push_profiles import decode_cms,utc,write
SOURCE='038c9e2b61b5b6c28355c478c883edee8372e330'
RECIPIENT='62d6dc6cd0253c7d427f63fbadd9953247a6312146df856689955371cd3e6358'
SUFFIXES={'':('BRCY926N89','ResaleBurrowIOS',['phone','ipad']),'.widgets':('6Z47CLJRAP','ResaleBurrowIOSWidgets',['phone','ipad']),'.watch':('2P34357G7A','ResaleBurrowWatch',['watch']),'.watch.widgets':('79HZ4V5LFK','ResaleBurrowWatchWidgets',['watch'])}
EXACT={c.BASE+k:v for k,v in SUFFIXES.items()}
MODELS={'phone':'iPhone18,2','ipad':'iPad17,4','watch':'Watch7,12'}
UUID=r'[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}'

def validate_scope(s):
 c.require(s.get('source_sha')==SOURCE and s.get('source_frozen') is True and s.get('final_artwork_owner_approved') is True,'julien_frozen_source_required')
 c.require(s.get('team')==c.TEAM and s.get('group')==c.GROUP and s.get('version')=='0.1.0' and str(s.get('build'))=='2','julien_identity_mismatch')
 c.require(s.get('certificate_id')==ap.CERT_ID and s.get('certificate_sha256')==c.CERT_SHA and s.get('recipient_spki_sha256')==RECIPIENT,'julien_existing_certificate_recipient_required')
 rows=s.get('new_profiles');c.require(isinstance(rows,list) and len(rows)==4 and {r.get('bundle_id') for r in rows}==set(EXACT),'julien_exact_four_profiles_required')
 for r in rows:
  native,target,roles=EXACT[r['bundle_id']]
  c.require(r=={'bundle_id':r['bundle_id'],'native_bundle_resource_id':native,'target':target,'name':'ResaleBurrow Julien Build2 Ad Hoc '+target+' 2026-10-06','profile_type':'IOS_APP_ADHOC','device_roles':roles},'julien_profile_scope_changed')
 export=s.get('export_scope',{})
 c.require(export.get('source_sha')==SOURCE and export.get('source_frozen') is True and export.get('final_artwork_owner_approved') is True and export.get('team')==c.TEAM and export.get('group')==c.GROUP and export.get('version')=='0.1.0' and str(export.get('build'))=='2','julien_export_scope_changed')
 c.require(len(export.get('targets',[]))==7 and {r.get('bundle_id') for r in export['targets']}==set(c.TARGETS.values()),'julien_seven_targets_required')
 c.require(export.get('match_material_commit')=='4d7f92fe5c81c32823e8ace5aca316ee98c8a53e' and export.get('recipient_spki_sha256')==RECIPIENT and export.get('certificates',{}).get('distribution',{}).get('sha256')==c.CERT_SHA,'julien_material_changed')
 return rows

def private_input(v):
 c.require(isinstance(v,dict) and set(v)=={'schema','source_sha','team','devices','prior_team_membership_verified','prior_cms_sha256'} and v.get('schema')==1 and v.get('source_sha')==SOURCE and v.get('team')==c.TEAM and v.get('prior_team_membership_verified') is True and v.get('prior_cms_sha256')=='085768b76b77499f89016b5e6bfd29e825dc1c9a655c2380ff98122ca768f900','julien_private_provenance_changed')
 rows=v.get('devices');c.require(isinstance(rows,list) and len(rows)==3 and {r.get('role') for r in rows}==set(MODELS),'julien_three_physical_devices_required')
 out={}
 for r in rows:
  c.require(set(r)=={'role','model','udid'} and r['model']==MODELS[r['role']] and isinstance(r['udid'],str) and re.fullmatch('[A-Z0-9-]{8,64}',r['udid']),'julien_private_device_invalid')
  out[r['role']]=r['udid']
 c.require(len(set(out.values()))==3,'julien_devices_duplicate');return out

def checked_profile(resource,row,cert,now,decoder,members):
 a=resource.get('attributes',{});native=resource.get('id','')
 c.require(resource.get('type')=='profiles' and re.fullmatch('[A-Za-z0-9_-]{1,80}',native) and a.get('name')==row['name'] and a.get('profileType')=='IOS_APP_ADHOC' and a.get('profileState')=='ACTIVE','julien_active_profile_identity_required')
 try:raw=base64.b64decode(a.get('profileContent',''),validate=True)
 except (ValueError,TypeError):raise c.GateError('julien_profile_content_invalid') from None
 c.require(0<len(raw)<=2*1024**2,'julien_profile_content_bound');p=decoder(raw);e=p.get('Entitlements',{})
 c.require(p.get('Name')==row['name'] and p.get('TeamIdentifier')==[c.TEAM] and p.get('ApplicationIdentifierPrefix')==[c.TEAM] and e.get('application-identifier')==c.TEAM+'.'+row['bundle_id'] and e.get('com.apple.developer.team-identifier')==c.TEAM,'julien_signed_identity_changed')
 c.require(e.get('com.apple.security.application-groups')==[c.GROUP] and e.get('get-task-allow') is False and p.get('ProvisionsAllDevices',False) is False and p.get('DeveloperCertificates')==[cert],'julien_release_group_certificate_changed')
 c.require(not any(k in e for k in ['com.apple.developer.icloud-services','com.apple.developer.weatherkit','com.apple.developer.carplay-driving-task','com.apple.developer.aps-environment']),'julien_sensitive_capability_changed')
 if row['bundle_id'] in c.PUSH:c.require(e.get('aps-environment')=='production','production_aps_missing')
 else:c.require('aps-environment' not in e,'julien_widget_push_forbidden')
 created,expires=utc(p.get('CreationDate')),utc(p.get('ExpirationDate'));c.require(datetime.datetime(2026,10,6,tzinfo=datetime.timezone.utc)<=created<=now+datetime.timedelta(minutes=5) and now<expires<=datetime.datetime(2027,9,16,2,46,2,tzinfo=datetime.timezone.utc),'julien_profile_dates_invalid')
 uuid=p.get('UUID','');c.require(isinstance(uuid,str) and re.fullmatch(UUID,uuid),'julien_profile_uuid_invalid')
 devices=p.get('ProvisionedDevices');wanted={members[k] for k in row['device_roles']}
 c.require(isinstance(devices,list) and len(devices)==len(wanted) and all(isinstance(d,str) for d in devices) and {d.strip().upper() for d in devices}==wanted,'julien_exact_device_membership_changed')
 result={'bundle_id':row['bundle_id'],'native_profile_id':native,'name':row['name'],'uuid':uuid,'sha256':hashlib.sha256(raw).hexdigest(),'profile_type':'IOS_APP_ADHOC','native_readback_verified':True,'owner_private_device_membership_verified_by_exact_cms_hash':True,'device_roles':row['device_roles'],'certificate_sha256':c.CERT_SHA,'production_aps_verified':row['bundle_id'] in c.PUSH,'expires_at':expires.isoformat()}
 return result,raw

def request(row,bindings):
 return {'data':{'type':'profiles','attributes':{'name':row['name'],'profileType':'IOS_APP_ADHOC'},'relationships':{'bundleId':{'data':{'type':'bundleIds','id':row['native_bundle_resource_id']}},'certificates':{'data':[{'type':'certificates','id':ap.CERT_ID}]},'devices':{'data':[{'type':'devices','id':bindings[k]} for k in row['device_roles']]}}}}

class JulienClient(audit.ReadClient):
 def __init__(self,token,scope,opener=None):
  super().__init__('https://api.appstoreconnect.apple.com',token,opener);self.rows=copy.deepcopy(validate_scope(scope));self.profiles=set();self.bindings=None;self.private_devices=None
 def get_allowed(self,path):
  p=urlsplit(path);q=parse_qs(p.query,keep_blank_values=True)
  if p.scheme or p.netloc or p.fragment or not path.startswith('/') or any(len(v)!=1 for v in q.values()) or set(q)-{'limit','cursor','filter[identifier]','filter[udid]'}:return False
  if 'limit' in q and q['limit']!=['50']:return False
  if p.path=='/v1/bundleIds':return q.get('filter[identifier]') in [[x] for x in EXACT] and set(q)<={'filter[identifier]','limit','cursor'}
  if p.path=='/v1/devices':return self.private_devices is not None and q.get('filter[udid]') in [[x] for x in self.private_devices.values()] and set(q)<={'filter[udid]','limit','cursor'}
  if any(k.startswith('filter[') for k in q):return False
  if p.path=='/v1/certificates/'+ap.CERT_ID:return not q
  if p.path in {'/v1/profiles/'+x for x in self.profiles}:return not q
  if p.path in {'/v1/bundleIds/'+v[0]+'/'+tail for v in EXACT.values() for tail in ['profiles','bundleIdCapabilities']}:return set(q)<={'limit','cursor'}
  return False
 def get(self,path):
  p=urlsplit(path)
  if p.scheme or p.netloc:
   c.require(p.scheme=='https' and p.netloc=='api.appstoreconnect.apple.com' and not p.fragment,'julien_get_host_forbidden');path=p.path+('?' +p.query if p.query else '')
  c.require(self.get_allowed(path),'julien_get_outside_scope')
  req=Request(self.origin+path,headers={'Authorization':'Bearer '+self.token,'Accept':'application/json'},method='GET')
  try:
   with self.opener.open(req,timeout=45) as response:raw=response.read(4*1024**2+1)
   c.require(len(raw)<=4*1024**2,'julien_get_bound');value=json.loads(raw);c.require(isinstance(value,dict),'julien_get_shape');return value
  except HTTPError as e:raise audit.AuditError('Scoped metadata HTTP '+str(e.code),http_status=e.code) from None
  except (URLError,TimeoutError,OSError,ValueError):raise c.GateError('julien_get_unavailable') from None
 def create_profile(self,row):
  c.require(self.bindings is not None and row in self.rows,'julien_post_requires_exact_bindings');body=request(row,self.bindings)
  req=Request(self.origin+'/v1/profiles',data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json','Accept':'application/json'},method='POST')
  try:
   with self.opener.open(req,timeout=45) as response:
    c.require(response.status==201,'julien_post_unknown_status_no_retry');raw=response.read(4*1024**2+1)
   c.require(len(raw)<=4*1024**2,'julien_post_bound_unknown_stop');value=json.loads(raw).get('data');c.require(isinstance(value,dict) and value.get('type')=='profiles' and re.fullmatch('[A-Za-z0-9_-]{1,80}',value.get('id','')),'julien_post_unknown_shape_no_retry');self.profiles.add(value['id']);return value
  except HTTPError as e:raise c.GateError('julien_post_http_'+str(e.code)+'_unknown_stop_no_retry') from None
  except (URLError,TimeoutError,OSError,ValueError):raise c.GateError('julien_post_unknown_stop_no_retry') from None

def named(client,row):
 found=[r for r in client.collection('/v1/bundleIds/'+row['native_bundle_resource_id']+'/profiles?limit=50') if r.get('attributes',{}).get('name')==row['name']]
 c.require(len(found)<=1,'julien_named_profile_ambiguous');return found

def prepare(client,s,private,output,now=None,decoder=decode_cms,certificate=ap.certificate):
 rows=validate_scope(s);members=private_input(private);client.private_devices=members;now=now or datetime.datetime.now(datetime.timezone.utc)
 out=pathlib.Path(output);c.require(not out.exists() and not out.is_symlink(),'julien_output_collision');out.mkdir(parents=True,mode=0o700);out.chmod(0o700)
 cert=certificate(client,now);bindings={}
 for role,udid in members.items():
  found=client.collection('/v1/devices?'+urlencode({'filter[udid]':udid,'limit':50}))
  exact=[r for r in found if r.get('attributes',{}).get('udid','').strip().upper()==udid]
  c.require(len(exact)==1 and len(found)==1,'julien_existing_device_missing_or_ambiguous');r=exact[0];a=r.get('attributes',{})
  c.require(r.get('type')=='devices' and re.fullmatch('[A-Za-z0-9_-]{1,80}',r.get('id','')) and a.get('status')=='ENABLED' and a.get('platform')=='IOS','julien_registered_device_not_enabled');bindings[role]=r['id']
 c.require(len(set(bindings.values()))==3,'julien_registered_device_duplicate');client.bindings=bindings
 existing={}
 # Preflight all four bundles/capabilities/names before any profile POST.
 for row in rows:
  found=client.collection('/v1/bundleIds?'+urlencode({'filter[identifier]':row['bundle_id'],'limit':50}))
  c.require(len(found)==1 and found[0].get('attributes',{}).get('identifier')==row['bundle_id'] and found[0].get('id')==row['native_bundle_resource_id'],'julien_bundle_resource_changed')
  caps=client.collection('/v1/bundleIds/'+row['native_bundle_resource_id']+'/bundleIdCapabilities?limit=50');types={r.get('attributes',{}).get('capabilityType') for r in caps}
  c.require('APP_GROUPS' in types and (row['bundle_id'] not in c.PUSH or 'PUSH_NOTIFICATIONS' in types),'julien_existing_capability_required_no_mutation')
  found=named(client,row)
  if found:checked_profile(found[0],row,cert,now,decoder,members)
  existing[row['bundle_id']]=found
 completed=[]
 for row in rows:
  found=existing[row['bundle_id']];action='reused'
  if not found:
   write(out/(row['target']+'-intent-private.json'),{'recorded_at':now.isoformat(),'request':request(row,bindings),'unknown_post_stop_no_retry':True})
   created=client.create_profile(row);action='created';write(out/(row['target']+'-post-confirmed-private.json'),{'native_profile_id':created['id'],'known_post_success':True,'post_retry_allowed':False})
   for attempt in range(4):
    if attempt:time.sleep(15)
    found=named(client,row)
    if not found:continue
    c.require(found[0].get('id')==created['id'],'julien_readback_id_changed_no_retry')
    try:checked_profile(found[0],row,cert,now,decoder,members)
    except c.GateError as e:
     if str(e)!='production_aps_missing':raise
     continue
    break
   else:raise c.GateError('julien_readback_pending_no_post_retry')
  result,raw=checked_profile(found[0],row,cert,now,decoder,members);result['action']=action
  if action=='created' and created.get('attributes',{}).get('profileContent') is not None:c.require(raw==base64.b64decode(created['attributes']['profileContent'],validate=True),'julien_post_readback_content_changed')
  write(out/(result['native_profile_id']+'.mobileprovision'),raw,True);completed.append(result)
 c.require(len({r['native_profile_id'] for r in completed})==4 and len({r['uuid'] for r in completed})==4,'julien_profile_duplicate_identity')
 allowed={'bundle_id','native_profile_id','name','sha256','uuid','profile_type','native_readback_verified','owner_private_device_membership_verified_by_exact_cms_hash','device_roles'}
 final=copy.deepcopy(s['export_scope']);final.pop('native_profiles',None)
 final.update(distribution='ad-hoc',delivery_lane='julien-ad-hoc',signing_delivery='julien-ad-hoc-export-only',profile_material_mode='native-adhoc-get-with-immutable-match-certificates',adhoc_native_profiles=[{k:v for k,v in r.items() if k in allowed} for r in completed],watch_profile_membership_verified=True,physical_watch_install_verified=False,device_roles=['phone','ipad','watch'])
 for target in final['targets']:
  if target['family']=='ios':target['profile_type']='IOS_APP_ADHOC'
 result={'schema':1,'complete':True,'source_sha':SOURCE,'version':'0.1.0','build':'2','checked_at':now.isoformat(),'profiles':completed,'new_profile_count':sum(r['action']=='created' for r in completed),'registered_device_count':3,'hardware_values_retained':False,'capability_certificate_device_mutations':False,'old_profiles_deleted':False,'uploaded':False,'installed':False}
 write(out/'julien-signing-export-scope.json',final);write(out/'julien-profile-manifest.json',result);return result

def main():
 p=argparse.ArgumentParser();p.add_argument('--scope',type=pathlib.Path,required=True);p.add_argument('--private-input',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--execute-reviewed-four-profiles',action='store_true');a=p.parse_args()
 try:
  c.require(a.execute_reviewed_four_profiles and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('TEAMID')==c.TEAM,'julien_first_reviewed_ci_attempt_required')
  c.require(os.environ.get('GITHUB_REPOSITORY')=='h00l1gvn/LoopFollow' and os.environ.get('GITHUB_ACTOR')=='h00l1gvn' and os.environ.get('GITHUB_REF')=='refs/heads/codex/resale-burrow-build2-julien-direct' and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','julien_exact_manual_lane_required')
  root=pathlib.Path(os.environ['RUNNER_TEMP']).resolve();c.require(a.output.resolve().is_relative_to(root) and a.private_input.resolve().is_relative_to(root) and a.private_input.is_file() and not a.private_input.is_symlink() and a.private_input.stat().st_mode&0o077==0,'julien_private_runner_paths_required')
  s=json.loads(a.scope.read_text());prepare(JulienClient(audit.apple_token(os.environ),s),s,json.loads(a.private_input.read_text()),a.output);print(json.dumps({'status':'julien_four_profiles_verified','profiles':4,'devices_registered':0,'hardware_output':False}));return 0
 except (c.GateError,audit.AuditError) as e:print(json.dumps({'status':'stopped','code':str(e),'retry_allowed':False}));return 1
 except Exception:print(json.dumps({'status':'stopped','code':'julien_private_preparation_failure','retry_allowed':False}));return 1
if __name__=='__main__':raise SystemExit(main())
