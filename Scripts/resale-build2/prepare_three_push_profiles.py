#!/usr/bin/env python3
"""Exact three Push capability/profile grants; prepared, explicit reviewed CI action only.

No certificates, devices, deletions, unrelated capability changes, Match writes,
keychain, build or upload. Unknown POST stops. GET readback precedes acceptance.
"""
from __future__ import annotations
import argparse,base64,datetime,hashlib,json,os,pathlib,re
from urllib.parse import quote,urlencode
from urllib.request import Request
from urllib.error import HTTPError,URLError
import build2_contract as c
import build2_profile_audit as audit2
import resale_apple_audit as audit

EXACT={c.BASE:('ResaleBurrowIOS','IOS_APP_STORE'),c.BASE+'.watch':('ResaleBurrowWatch','IOS_APP_STORE'),c.BASE+'.mac':('ResaleBurrowMac','MAC_APP_STORE')}

def validate_scope(scope):
    c.require(scope.get('team')==c.TEAM and scope.get('group')==c.GROUP and scope.get('certificate_id')==audit2.CERT_ID and scope.get('certificate_sha256')==c.CERT_SHA and scope.get('version')=='0.1.0' and str(scope.get('build'))=='2','three_push_scope_identity_mismatch')
    rows=scope.get('targets');c.require(isinstance(rows,list) and len(rows)==3 and {r.get('bundle_id') for r in rows}==set(EXACT),'three_push_target_set_mismatch')
    c.require(len({r.get('native_bundle_resource_id') for r in rows})==3,'three_push_native_ids_ambiguous')
    for r in rows:
        target,kind=EXACT[r['bundle_id']]
        c.require(r.get('target')==target and r.get('profile_type')==kind and r.get('profile_name')=='ResaleBurrow Build2 AppStore '+target,'three_push_profile_identity_mismatch')
        c.require(isinstance(r.get('native_bundle_resource_id'),str) and re.fullmatch('[A-Za-z0-9_-]{1,80}',r['native_bundle_resource_id']),'three_push_native_id_invalid')
    return rows

def capability_request(row):
    return {'data':{'type':'bundleIdCapabilities','attributes':{'capabilityType':'PUSH_NOTIFICATIONS'},'relationships':{'bundleId':{'data':{'type':'bundleIds','id':row['native_bundle_resource_id']}}}}}
def profile_request(row):
    return {'data':{'type':'profiles','attributes':{'name':row['profile_name'],'profileType':row['profile_type']},'relationships':{'bundleId':{'data':{'type':'bundleIds','id':row['native_bundle_resource_id']}},'certificates':{'data':[{'type':'certificates','id':audit2.CERT_ID}]}}}}

class ThreeGrantClient(audit.ReadClient):
    def __init__(self,token,scope,opener=None):
        super().__init__('https://api.appstoreconnect.apple.com',token,opener);self.targets=validate_scope(scope)
    def _post(self,path,body):
        allowed=[('/v1/bundleIdCapabilities',capability_request(r)) for r in self.targets]+[('/v1/profiles',profile_request(r)) for r in self.targets]
        c.require((path,body) in allowed,'unapproved_three_grant_post')
        req=Request(self.origin+path,data=json.dumps(body,separators=(',',':')).encode(),headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json','Accept':'application/json','User-Agent':'ResaleBurrow-build2-three-grants'},method='POST')
        try:
            with self.opener.open(req,timeout=45) as response:
                c.require(response.status==201,'grant_post_unexpected_status_outcome_review_required');raw=response.read(4*1024**2+1)
            c.require(len(raw)<=4*1024**2,'grant_post_response_bound')
            value=json.loads(raw);c.require(isinstance(value,dict) and isinstance(value.get('data'),dict),'grant_post_response_invalid_outcome_review_required');return value['data']
        except HTTPError as e:raise c.GateError('grant_post_http_'+str(e.code)+'_outcome_review_required') from None
        except (URLError,TimeoutError,OSError,ValueError,UnicodeError):raise c.GateError('grant_post_unknown_stop_no_retry') from None
    def enable_push(self,row):return self._post('/v1/bundleIdCapabilities',capability_request(row))
    def create_profile(self,row):return self._post('/v1/profiles',profile_request(row))

def write(path,value):
    path=pathlib.Path(path);c.require(not path.exists() and not path.is_symlink(),'grant_evidence_collision')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as h:json.dump(value,h,indent=2);h.write('\n')

def capabilities(client,row):
    values=client.collection('/v1/bundleIds/'+quote(row['native_bundle_resource_id'],safe='')+'/bundleIdCapabilities?limit=50')
    selected=[v for v in values if v.get('attributes',{}).get('capabilityType')=='PUSH_NOTIFICATIONS']
    c.require(len(selected)<=1,'push_capability_ambiguous')
    if selected:c.require(isinstance(selected[0].get('id'),str) and re.fullmatch('[A-Za-z0-9_-]{1,80}',selected[0]['id']),'push_capability_resource_id_invalid')
    return selected

def profile_rows(client,row):
    values=client.collection('/v1/bundleIds/'+quote(row['native_bundle_resource_id'],safe='')+'/profiles?limit=50')
    selected=[v for v in values if v.get('attributes',{}).get('name')==row['profile_name']]
    c.require(len(selected)<=1,'build2_profile_name_ambiguous');return selected

def checked_profile(resource,row,cert,now,decoder):
    c.require(resource.get('attributes',{}).get('name')==row['profile_name'],'build2_profile_name_changed')
    content=resource.get('attributes',{}).get('profileContent');parsed=decoder(content)
    c.require(isinstance(parsed,dict) and parsed.get('Name')==row['profile_name'],'build2_profile_signed_name_changed')
    result=audit2.profile_evidence(resource,row['bundle_id'],cert,now,lambda _:parsed)
    c.require(result['reusable_for_build2'],'created_build2_profile_required_grants_missing')
    raw=base64.b64decode(content,validate=True)
    return {**result,'bundle_id':row['bundle_id'],'target':row['target'],'name':row['profile_name'],'certificate_sha256':c.CERT_SHA,'verified':True,'native_readback_verified':True},raw

def prepare(client,scope,output,now=None,decoder=audit.decode_profile):
    targets=validate_scope(scope);now=now or datetime.datetime.now(datetime.timezone.utc);cert=audit2.certificate(client,now)
    output=pathlib.Path(output);c.require(not output.exists() and not output.is_symlink(),'grant_output_collision');output.mkdir(parents=True,mode=0o700);output.chmod(0o700)
    completed=[]
    for row in targets:
        matches=[v for v in client.collection('/v1/bundleIds?'+urlencode({'filter[identifier]':row['bundle_id'],'limit':50})) if v.get('attributes',{}).get('identifier')==row['bundle_id']]
        c.require(len(matches)==1 and matches[0].get('id')==row['native_bundle_resource_id'],'owned_bundle_current_resource_mismatch')
        prefix=row['target'];current=capabilities(client,row);cap_action='reused'
        if not current:
            write(output/(prefix+'-capability-intent.json'),{'recorded_at':now.isoformat(),'action':'enable_push_only','body':capability_request(row),'unknown_outcome_requires_review':True})
            created=client.enable_push(row);current=capabilities(client,row)
            c.require(len(current)==1 and current[0].get('id')==created.get('id') and current[0].get('attributes',{}).get('capabilityType')=='PUSH_NOTIFICATIONS','push_creation_readback_missing_or_changed_stop')
            cap_action='created'
        write(output/(prefix+'-capability-confirmed.json'),{'bundle_id':row['bundle_id'],'capability_type':'PUSH_NOTIFICATIONS','native_capability_id':current[0].get('id'),'action':cap_action,'fresh_exact_relationship_readback':True})
        named=profile_rows(client,row);profile_action='reused'
        if not named:
            write(output/(prefix+'-profile-intent.json'),{'recorded_at':now.isoformat(),'action':'create_exact_build2_store_profile_existing_cert_only','body':profile_request(row),'unknown_outcome_requires_review':True})
            created=client.create_profile(row);c.require(isinstance(created.get('id'),str) and re.fullmatch('[A-Za-z0-9_-]{1,80}',created['id']),'created_profile_resource_id_missing_stop');named=profile_rows(client,row)
            c.require(len(named)==1 and named[0].get('id')==created.get('id'),'profile_creation_readback_missing_or_changed_stop');profile_action='created'
        result,raw=checked_profile(named[0],row,cert,now,decoder)
        if profile_action=='created' and created.get('attributes',{}).get('profileContent') is not None:c.require(raw==base64.b64decode(created['attributes']['profileContent'],validate=True),'profile_creation_readback_content_changed')
        extension='.provisionprofile' if row['profile_type']=='MAC_APP_STORE' else '.mobileprovision';path=output/(row['target']+extension)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as h:h.write(raw)
        result.update(action=profile_action,path=path.name,production_push_grant_verified=True)
        c.require(result['uuid'] not in {x['uuid'] for x in completed} and result['native_profile_id'] not in {x['native_profile_id'] for x in completed},'three_push_profile_uuid_or_id_duplicate')
        write(output/(prefix+'-profile-confirmed.json'),result);completed.append(result)
    result={'schema':1,'checked_at':now.isoformat(),'team':c.TEAM,'group':c.GROUP,'build':'2','source_frozen':False,'profiles':completed,'exact_push_receiving_bundle_ids':list(EXACT),'existing_certificate_id':audit2.CERT_ID,'certificate_sha256':c.CERT_SHA,'complete':True,'certificate_created':False,'old_profiles_deleted_or_overwritten':False,'match_modified':False,'keychain_modified':False,'app_built_or_uploaded':False,'device_action':False}
    write(output/'three-push-profile-manifest.json',result);return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--scope',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--execute-reviewed-three-push-profiles',action='store_true');a=p.parse_args()
    try:
        c.require(a.execute_reviewed_three_push_profiles and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1','reviewed_first_ci_attempt_required');c.require(os.environ.get('TEAMID')==c.TEAM,'ci_team_mismatch')
        c.require(a.output.resolve().is_relative_to(pathlib.Path(os.environ['RUNNER_TEMP']).resolve()),'grant_output_not_private_runner_scope')
        scope=json.loads(a.scope.read_text());validate_scope(scope);prepare(ThreeGrantClient(audit.apple_token(os.environ),scope),scope,a.output)
        print(json.dumps({'status':'three_owned_push_profiles_verified','profiles':3,'new_certificates':0,'app_uploads':0}));return 0
    except (c.GateError,audit.AuditError) as e:print(json.dumps({'status':'stopped','code':str(e),'retry_allowed':False}));return 1
    except Exception:print(json.dumps({'status':'stopped','code':'three_push_grants_unexpected_response','retry_allowed':False}));return 1
if __name__=='__main__':raise SystemExit(main())
