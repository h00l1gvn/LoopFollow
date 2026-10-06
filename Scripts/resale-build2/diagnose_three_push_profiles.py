#!/usr/bin/env python3
"""Bounded exact three owned names GET diagnostics; no account mutation method."""
import argparse,datetime,base64,hashlib,json,os
from pathlib import Path
from urllib.parse import urlencode,quote
import build2_contract as c
import build2_profile_audit as a
import resale_apple_audit as api
import prepare_three_push_profiles as p

def run(client,scope):
 targets=p.validate_scope(scope);now=datetime.datetime.now(datetime.timezone.utc);cert=a.certificate(client,now);rows=[]
 for row in targets:
  bundles=client.collection('/v1/bundleIds?'+urlencode({'filter[identifier]':row['bundle_id'],'limit':50}));exact=[r for r in bundles if r.get('attributes',{}).get('identifier')==row['bundle_id']]
  c.require(len(exact)==1 and exact[0].get('id')==row['native_bundle_resource_id'],'diagnostic_bundle_mismatch')
  caps=p.capabilities(client,row);native=p.profile_rows(client,row);result={'bundle_id':row['bundle_id'],'exact_name':row['profile_name'],'push_capability_exists':len(caps)==1,'exact_named_profile_count':len(native)}
  if native:
   resource=native[0];attrs=resource.get('attributes',{});content=attrs.get('profileContent');profile=api.decode_profile(content);ent=profile.get('Entitlements',{});expected=c.TEAM+'.'+row['bundle_id'];groups=ent.get('com.apple.security.application-groups');dates=[profile.get(k) for k in ['CreationDate','ExpirationDate']]
   def utc(v):return v.replace(tzinfo=datetime.timezone.utc) if isinstance(v,datetime.datetime) and v.tzinfo is None else v
   pushkey=c.PUSH[row['bundle_id']]
   result.update(native_profile_id=resource.get('id'),api_profile_state=attrs.get('profileState'),api_profile_type=attrs.get('profileType'),cms_name_exact=profile.get('Name')==row['profile_name'],team_exact=profile.get('TeamIdentifier')==[c.TEAM],prefix_exact=profile.get('ApplicationIdentifierPrefix')==[c.TEAM],dates_current=isinstance(dates[0],datetime.datetime) and isinstance(dates[1],datetime.datetime) and utc(dates[0])<=now<utc(dates[1]),application_identifier_exact=any(k in ent for k in ['application-identifier','com.apple.application-identifier']) and all(ent[k]==expected for k in ['application-identifier','com.apple.application-identifier'] if k in ent),entitlement_team_exact=ent.get('com.apple.developer.team-identifier')==c.TEAM,literal_group_exact=groups==[c.GROUP],mac_observed_group_permission_exact=isinstance(groups,list) and len(groups)==2 and set(groups)=={c.GROUP,c.TEAM+'.*'},get_task_allow_false=ent.get('get-task-allow',False) is False,no_device_fields='ProvisionedDevices' not in profile and not profile.get('ProvisionsAllDevices',False),certificate_exact=profile.get('DeveloperCertificates')==[cert],production_push_value=ent.get(pushkey),entitlement_key_names=sorted(ent),evidence=a.profile_evidence(resource,row['bundle_id'],cert,now,lambda _:profile))
  rows.append(result)
 return {'diagnostic_purpose':'authoritative_GET_after_Mac_build2_profile_creation','checked_at':now.isoformat(),'targets':rows,'account_mutations':0,'no_retry_or_profile_generation':True}

def main():
 q=argparse.ArgumentParser();q.add_argument('--scope',type=Path,required=True);q.add_argument('--report',type=Path,required=True);v=q.parse_args()
 try:
  c.require(os.environ.get('TEAMID')==c.TEAM,'diagnostic_team_mismatch');result=run(api.ReadClient('https://api.appstoreconnect.apple.com',api.apple_token(os.environ)),json.loads(v.scope.read_text()));p.write(v.report,result);print('Exact owned GET diagnostics saved privately. No account writes.');return 0
 except (c.GateError,api.AuditError) as e:print(json.dumps({'status':'stopped','code':str(e),'account_mutations':0}));return 1
 except Exception:print('Exact GET diagnostics stopped; no private values printed.');return 1
if __name__=='__main__':raise SystemExit(main())
