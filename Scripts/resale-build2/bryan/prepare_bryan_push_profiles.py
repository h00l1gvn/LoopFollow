#!/usr/bin/env python3
"""Prepare exactly two new Bryan ad-hoc Push profiles; never run implicitly.

Hardware values exist only in ephemeral memory/private encrypted evidence. Old
CMS content hashes inherit the independently verified private phone membership.
No devices, certificates, capabilities, deletes, builds, or installs are exposed.
"""
from __future__ import annotations
import argparse, base64, copy, datetime, hashlib, json, os, pathlib, plistlib, re, subprocess, sys, tempfile, time
from urllib.parse import urlsplit, parse_qs, urlencode
from urllib.request import Request
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import build2_contract as c
import build2_profile_audit as ap
import resale_apple_audit as audit

SOURCE='038c9e2b61b5b6c28355c478c883edee8372e330'
MEMBERSHIP_RECEIPT='c495b2505298db523dd69a1c1a570f5476ccfb58a6b0d7057246de8d2dd4c3cb'
RECIPIENT='62d6dc6cd0253c7d427f63fbadd9953247a6312146df856689955371cd3e6358'
OLD={
 c.BASE:('DMWQ2F9XCQ','ResaleBurrow Bryan Ad Hoc 2026-10-06','1fbf2d90098225bd69d032cfb780224ce1559dcb527136e58a56333dad136f76','75a2a28a-7033-418b-8721-7fdf6b1f895b'),
 c.BASE+'.widgets':('M7378SUWRA','ResaleBurrow iOS Widgets Bryan Ad Hoc 2026-10-06','33386d1ac15b71a00f3ebfa33758c4497fb5fc7632fbf1fee9977849757a902d','883d7efb-cabe-4be2-b2a3-43e00886c052'),
 c.BASE+'.watch':('234A433R79','ResaleBurrow Watch Bryan Ad Hoc 2026-10-06','1b2950135b3d42fa1bba36be3c1ad602ee9424e9e79b62c906441f6dbbdc7703','9d5525f2-c60f-46df-a631-ff8638ae5cc9'),
 c.BASE+'.watch.widgets':('UB47QM5B83','ResaleBurrow Watch Widgets Bryan Ad Hoc 2026-10-06','9c21a0178507b2c76edf8cf6888a8df802da39c7044c55cf5854ddabc9040f1b','eb951d40-2463-4ecc-a96f-3ccf8c11ac67'),
}
NEW={c.BASE:('BRCY926N89','ResaleBurrow Bryan Build2 Ad Hoc 2026-10-06'),c.BASE+'.watch':('2P34357G7A','ResaleBurrow Watch Bryan Build2 Ad Hoc 2026-10-06')}
UUID=r'[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}'

def validate_scope(s):
    c.require(s.get('source_sha')==SOURCE and s.get('source_frozen') is True and s.get('final_artwork_owner_approved') is True,'reviewed_build2_source_required')
    c.require(s.get('team')==c.TEAM and s.get('group')==c.GROUP and s.get('version')=='0.1.0' and str(s.get('build'))=='2','bryan_identity_mismatch')
    c.require(s.get('certificate_id')==ap.CERT_ID and s.get('certificate_sha256')==c.CERT_SHA,'existing_certificate_pin_required')
    c.require(s.get('recipient_spki_sha256')==RECIPIENT,'protected_recipient_pin_required')
    c.require(s.get('private_membership_receipt_sha256')==MEMBERSHIP_RECEIPT and s.get('old_four_private_phone_membership_verified') is True,'reviewed_private_membership_required')
    rows=s.get('old_profiles');c.require(isinstance(rows,list) and len(rows)==4 and {r.get('bundle_id') for r in rows}==set(OLD),'exact_old_four_required')
    for r in rows:
        ident=r['bundle_id']; native,name,digest,uuid=OLD[ident]
        c.require((r.get('native_profile_id'),r.get('name'),r.get('sha256'),r.get('uuid'))==(native,name,digest,uuid),'old_profile_pin_changed')
        c.require(r.get('owner_private_phone_membership_verified_by_exact_cms_hash') is True,'old_private_membership_not_verified')
    rows=s.get('new_profiles');c.require(isinstance(rows,list) and len(rows)==2 and {r.get('bundle_id') for r in rows}==set(NEW),'exact_two_new_profiles_required')
    for r in rows:
        native,name=NEW[r['bundle_id']]
        c.require(r.get('native_bundle_resource_id')==native and r.get('name')==name and r.get('profile_type')=='IOS_APP_ADHOC','new_profile_identity_changed')
    export=s.get('export_scope');c.require(isinstance(export,dict) and export.get('source_sha')==SOURCE and export.get('source_frozen') is True and export.get('final_artwork_owner_approved') is True and export.get('version')=='0.1.0' and str(export.get('build'))=='2' and export.get('team')==c.TEAM and export.get('group')==c.GROUP,'export_scope_mismatch')
    c.require({r.get('bundle_id') for r in export.get('targets',[])}==set(c.TARGETS.values()) and len(export['targets'])==7,'export_seven_targets_required')
    c.require(export.get('match_material_commit')=='4d7f92fe5c81c32823e8ace5aca316ee98c8a53e' and export.get('recipient_spki_sha256')==RECIPIENT and export.get('certificates',{}).get('distribution',{}).get('sha256')==c.CERT_SHA,'export_material_or_recipient_changed')
    for row in export['targets']:
        c.require(c.TARGETS.get(row.get('target'))==row['bundle_id'],'export_target_name_changed')
        osmin='10.0' if row['bundle_id'] in {c.BASE+'.watch',c.BASE+'.watch.widgets'} else ('13.0' if row['bundle_id'].startswith(c.BASE+'.mac') else '17.0')
        c.require(row.get('minimum_os')==osmin,'export_minimum_os_changed')
    return rows

def write(path,value,raw=False):
    p=pathlib.Path(path);c.require(not p.exists() and not p.is_symlink(),'private_evidence_collision')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as h:h.write(value if raw else (json.dumps(value,indent=2)+'\n').encode())

def decode_cms(raw):
    with tempfile.TemporaryDirectory(prefix='resale-bryan-cms-') as tmp:
        root=pathlib.Path(tmp);root.chmod(0o700);src=root/'profile.mobileprovision';out=root/'decoded.plist';write(src,raw,True)
        try:
            p=subprocess.run(['/usr/bin/openssl','cms','-verify','-inform','DER','-noverify','-in',str(src),'-out',str(out)],capture_output=True,timeout=30)
            c.require(p.returncode==0,'cms_signature_integrity_failed');out.chmod(0o600)
            p=subprocess.run(['/usr/bin/security','cms','-D','-i',str(src)],capture_output=True,timeout=30)
            c.require(p.returncode==0,'cms_platform_decode_failed');decoded=plistlib.loads(out.read_bytes())
            c.require(decoded==plistlib.loads(p.stdout),'cms_decoders_disagree');return decoded
        except (OSError,subprocess.TimeoutExpired,ValueError,plistlib.InvalidFileException):raise c.GateError('cms_decode_failed') from None

def utc(v):
    c.require(isinstance(v,datetime.datetime),'profile_date_missing')
    return v.replace(tzinfo=datetime.timezone.utc) if v.tzinfo is None else v.astimezone(datetime.timezone.utc)

def profile(resource,ident,name,cert,now,decoder,*,old=False,device=None):
    a=resource.get('attributes',{});native=resource.get('id','')
    c.require(resource.get('type')=='profiles' and re.fullmatch('[A-Za-z0-9_-]{1,80}',native) and a.get('name')==name and a.get('profileType')=='IOS_APP_ADHOC','profile_resource_identity_invalid')
    try:raw=base64.b64decode(a.get('profileContent',''),validate=True)
    except (ValueError,TypeError):raise c.GateError('profile_content_invalid') from None
    c.require(0<len(raw)<=2*1024**2,'profile_content_bound')
    if old:c.require(native==OLD[ident][0] and hashlib.sha256(raw).hexdigest()==OLD[ident][2],'old_profile_content_pin_changed')
    # Only the two exact hash-pinned historical receivers are provenance.
    # They are never restored/exported for build2. Widgets and new profiles
    # remain signing material and must be ACTIVE without exception.
    provenance_only=old and ident in NEW
    c.require(a.get('profileState') in ({'ACTIVE','INVALID'} if provenance_only else {'ACTIVE'}),'profile_resource_state_not_authorized')
    p=decoder(raw);e=p.get('Entitlements',{});c.require(isinstance(e,dict),'profile_entitlements_invalid')
    c.require(p.get('Name')==name and p.get('TeamIdentifier')==[c.TEAM] and p.get('ApplicationIdentifierPrefix')==[c.TEAM] and e.get('application-identifier')==c.TEAM+'.'+ident and e.get('com.apple.developer.team-identifier')==c.TEAM,'profile_signed_identity_changed')
    c.require('com.apple.application-identifier' not in e and e.get('com.apple.security.application-groups')==[c.GROUP] and e.get('get-task-allow') is False and p.get('ProvisionsAllDevices',False) is False and p.get('DeveloperCertificates')==[cert],'profile_group_release_or_certificate_changed')
    c.require(not any(k in e for k in ('com.apple.developer.aps-environment','com.apple.developer.icloud-services','com.apple.developer.weatherkit','com.apple.developer.carplay-driving-task')),'unapproved_sensitive_capability')
    if not old and ident in NEW:c.require(e.get('aps-environment')=='production','production_aps_missing')
    else:c.require('aps-environment' not in e,'old_or_widget_push_changed')
    created,expires=utc(p.get('CreationDate')),utc(p.get('ExpirationDate'))
    c.require(datetime.datetime(2026,10,6,tzinfo=datetime.timezone.utc)<=created<=now+datetime.timedelta(minutes=5) and now<expires<=datetime.datetime(2027,9,16,2,46,2,tzinfo=datetime.timezone.utc),'profile_dates_invalid')
    uuid=p.get('UUID','');c.require(isinstance(uuid,str) and re.fullmatch(UUID,uuid),'profile_uuid_invalid')
    if old:c.require(uuid.lower()==OLD[ident][3],'old_profile_uuid_changed')
    devices=p.get('ProvisionedDevices');c.require(isinstance(devices,list) and len(devices)==1 and isinstance(devices[0],str) and bool(devices[0].strip()),'exact_single_private_phone_required')
    hardware=devices[0].strip().upper()
    if device is not None:c.require(hardware==device,'private_phone_membership_changed')
    result={'bundle_id':ident,'native_profile_id':native,'name':name,'uuid':uuid,'sha256':hashlib.sha256(raw).hexdigest(),'profile_type':'IOS_APP_ADHOC','native_profile_state':a['profileState'],'historical_provenance_only':provenance_only,'native_readback_verified':True,'owner_private_phone_membership_verified_by_exact_cms_hash':True,'certificate_sha256':c.CERT_SHA,'production_aps_verified':not old and ident in NEW,'expires_at':expires.isoformat(),'watch_hardware_eligibility_verified':False}
    return result,raw,hardware

def request(row,device_id):
    return {'data':{'type':'profiles','attributes':{'name':row['name'],'profileType':'IOS_APP_ADHOC'},'relationships':{'bundleId':{'data':{'type':'bundleIds','id':row['native_bundle_resource_id']}},'certificates':{'data':[{'type':'certificates','id':ap.CERT_ID}]},'devices':{'data':[{'type':'devices','id':device_id}]}}}}

class BryanClient(audit.ReadClient):
    def __init__(self,token,scope,opener=None):
        super().__init__('https://api.appstoreconnect.apple.com',token,opener);self.rows=copy.deepcopy(validate_scope(scope));self.allowed_profiles={r[0] for r in OLD.values()};self.device_id=None
    def get_allowed(self,path):
        parsed=urlsplit(path);q=parse_qs(parsed.query)
        if parsed.scheme or parsed.netloc or parsed.fragment or not path.startswith('/'):return False
        if any(k not in {'limit','cursor','filter[identifier]'} for k in q) or any(len(v)!=1 for v in q.values()):return False
        if 'limit' in q and q['limit']!=['50']:return False
        if parsed.path=='/v1/bundleIds':return q.get('filter[identifier]') in [[x] for x in NEW] and set(q)<={'filter[identifier]','limit','cursor'}
        if 'filter[identifier]' in q:return False
        if parsed.path=='/v1/certificates/'+ap.CERT_ID:return not q
        if parsed.path in {'/v1/profiles/'+i for i in self.allowed_profiles}:return not q
        if parsed.path in {'/v1/profiles/'+OLD[x][0]+'/devices' for x in NEW}:return set(q)<={'limit','cursor'}
        if parsed.path in {'/v1/bundleIds/'+v[0]+'/'+tail for v in NEW.values() for tail in ['profiles','bundleIdCapabilities']}:return set(q)<={'limit','cursor'}
        return False
    def get(self,path):
        parsed=urlsplit(path)
        if parsed.scheme or parsed.netloc:
            c.require(parsed.scheme=='https' and parsed.netloc=='api.appstoreconnect.apple.com' and not parsed.fragment,'unapproved_bryan_profile_get_host')
            path=parsed.path+('?' + parsed.query if parsed.query else '')
        c.require(self.get_allowed(path),'unapproved_bryan_profile_get')
        req=Request(self.origin+path,headers={'Authorization':'Bearer '+self.token,'Accept':'application/json','User-Agent':'ResaleBurrow-build2-Bryan-profile-scope'},method='GET')
        try:
            with self.opener.open(req,timeout=45) as response:raw=response.read(4*1024**2+1)
            c.require(len(raw)<=4*1024**2,'profile_get_bound');value=json.loads(raw);c.require(isinstance(value,dict),'profile_get_shape');return value
        except HTTPError as e:raise audit.AuditError('Exact profile GET returned HTTP '+str(e.code),http_status=e.code) from None
        except (URLError,TimeoutError,OSError,ValueError):raise c.GateError('profile_get_unavailable') from None
    def bind_approved_device(self,value):
        c.require(self.device_id is None and isinstance(value,str) and re.fullmatch('[A-Za-z0-9_-]{1,80}',value),'private_device_binding_invalid');self.device_id=value
    def create_profile(self,row):
        c.require(self.device_id is not None and row in self.rows,'profile_post_without_exact_private_binding')
        c.require(row.get('bundle_id') in NEW and (row.get('native_bundle_resource_id'),row.get('name'))==NEW[row['bundle_id']] and row.get('profile_type')=='IOS_APP_ADHOC','profile_post_identity_changed')
        body=request(row,self.device_id)
        req=Request(self.origin+'/v1/profiles',data=json.dumps(body,separators=(',',':')).encode(),headers={'Authorization':'Bearer '+self.token,'Accept':'application/json','Content-Type':'application/json','User-Agent':'ResaleBurrow-build2-Bryan-profile-scope'},method='POST')
        try:
            with self.opener.open(req,timeout=45) as response:
                c.require(response.status==201,'profile_post_unexpected_status_unknown_stop');raw=response.read(4*1024**2+1)
            c.require(len(raw)<=4*1024**2,'profile_post_bound_unknown_stop');data=json.loads(raw).get('data')
            c.require(isinstance(data,dict) and data.get('type')=='profiles' and re.fullmatch('[A-Za-z0-9_-]{1,80}',data.get('id','')),'profile_post_shape_unknown_stop')
            self.allowed_profiles.add(data['id']);return data
        except HTTPError as e:raise c.GateError('profile_post_http_'+str(e.code)+'_unknown_stop_no_retry') from None
        except (URLError,TimeoutError,OSError,ValueError,UnicodeError):raise c.GateError('profile_post_unknown_stop_no_retry') from None

def named(client,row):
    results=client.collection('/v1/bundleIds/'+row['native_bundle_resource_id']+'/profiles?limit=50')
    matches=[r for r in results if r.get('attributes',{}).get('name')==row['name']]
    c.require(len(matches)<=1,'new_profile_name_ambiguous');return matches

def prepare(client,s,output,now=None,decoder=decode_cms,certificate=ap.certificate):
    rows=validate_scope(s);now=now or datetime.datetime.now(datetime.timezone.utc)
    out=pathlib.Path(output);c.require(not out.exists() and not out.is_symlink(),'preparation_output_collision');out.mkdir(parents=True,mode=0o700);out.chmod(0o700)
    cert=certificate(client,now);old={};private_phone=None
    # ALL four exact old CMS profiles and BOTH private API device relationships
    # are validated before the first POST. Public receipts contain neither value.
    for ident,(native,name,_,_) in OLD.items():
        resource=client.get('/v1/profiles/'+native).get('data',{});attrs=resource.get('attributes',{})
        try:
            observed_raw=base64.b64decode(attrs.get('profileContent',''),validate=True)
            observed_digest=hashlib.sha256(observed_raw).hexdigest() if 0<len(observed_raw)<=2*1024**2 else None
        except (ValueError,TypeError):observed_digest=None
        write(out/(native+'-old-observation-private.json'),{'native_profile_id':native,'bundle_id':ident,'observed_state':attrs.get('profileState') if attrs.get('profileState') in {'ACTIVE','INVALID'} else 'unexpected_or_missing','resource_id_matches_pin':resource.get('id')==native,'resource_type_matches':resource.get('type')=='profiles','exact_name_matches':attrs.get('name')==name,'profile_type_matches':attrs.get('profileType')=='IOS_APP_ADHOC','observed_cms_sha256':observed_digest,'cms_matches_reviewed_pin':observed_digest==OLD[ident][2],'historical_receiver_provenance_only':ident in NEW,'hardware_values_retained':False})
        result,raw,phone=profile(resource,ident,name,cert,now,decoder,old=True,device=private_phone)
        private_phone=phone;old[ident]=(result,raw);write(out/(native+'.mobileprovision'),raw,True)
    devices=[]
    for ident in NEW:
        found=client.collection('/v1/profiles/'+OLD[ident][0]+'/devices?limit=50')
        c.require(len(found)==1 and found[0].get('type')=='devices','old_profile_exact_single_device_relationship_required')
        resource=found[0];attrs=resource.get('attributes',{})
        c.require(attrs.get('udid','').strip().upper()==private_phone and attrs.get('status')=='ENABLED' and attrs.get('platform')=='IOS','old_device_relationship_membership_changed')
        c.require(isinstance(resource.get('id'),str) and re.fullmatch('[A-Za-z0-9_-]{1,80}',resource['id']),'device_relationship_resource_invalid');devices.append(resource['id'])
    c.require(len(set(devices))==1,'old_two_api_device_relationships_disagree');client.bind_approved_device(devices[0])
    existing={}
    for row in rows:
        exact=[r for r in client.collection('/v1/bundleIds?'+urlencode({'filter[identifier]':row['bundle_id'],'limit':50})) if r.get('attributes',{}).get('identifier')==row['bundle_id']]
        c.require(len(exact)==1 and exact[0].get('id')==row['native_bundle_resource_id'],'owned_bundle_resource_changed')
        caps=client.collection('/v1/bundleIds/'+row['native_bundle_resource_id']+'/bundleIdCapabilities?limit=50')
        c.require(sum(r.get('attributes',{}).get('capabilityType')=='PUSH_NOTIFICATIONS' for r in caps)==1,'existing_push_capability_required_no_mutation')
        values=named(client,row)
        if values:profile(values[0],row['bundle_id'],row['name'],cert,now,decoder,device=private_phone)
        existing[row['bundle_id']]=values
    completed=[]
    for row in rows:
        found=existing[row['bundle_id']];action='reused'
        if not found:
            write(out/(row['native_bundle_resource_id']+'-intent-private.json'),{'recorded_at':now.isoformat(),'request':request(row,devices[0]),'unknown_post_stop_no_retry':True})
            created=client.create_profile(row);action='created'
            write(out/(row['native_bundle_resource_id']+'-post-confirmed-private.json'),{'recorded_at':now.isoformat(),'native_profile_id':created['id'],'name':row['name'],'known_successful_profile_post':True,'post_retry_allowed':False})
            # Only GET may settle after known successful POST. Preserve the
            # actual resource ID in encrypted evidence even if all reads lag.
            for readback in range(4):
                if readback:time.sleep(15)
                found=named(client,row)
                if not found:continue
                c.require(len(found)==1 and found[0].get('id')==created.get('id'),'profile_creation_readback_identity_changed_stop_no_retry')
                try:profile(found[0],row['bundle_id'],row['name'],cert,now,decoder,device=private_phone)
                except c.GateError as error:
                    if str(error)!='production_aps_missing':raise
                    continue
                break
            else:raise c.GateError('profile_creation_readback_missing_or_aps_pending_stop_no_retry')
        result,raw,_=profile(found[0],row['bundle_id'],row['name'],cert,now,decoder,device=private_phone)
        if action=='created' and created.get('attributes',{}).get('profileContent') is not None:
            c.require(raw==base64.b64decode(created['attributes']['profileContent'],validate=True),'creation_readback_content_changed')
        write(out/(result['native_profile_id']+'.mobileprovision'),raw,True);result['action']=action;completed.append(result)
    for ident in OLD:
        if ident not in NEW:
            result=copy.deepcopy(old[ident][0]);result['action']='reused_unchanged';completed.append(result)
    c.require(len({r['native_profile_id'] for r in completed})==4 and len({r['uuid'] for r in completed})==4,'final_four_profile_identity_ambiguous')
    final=copy.deepcopy(s['export_scope']);final.pop('native_profiles',None)
    public_pin_keys={'bundle_id','native_profile_id','name','sha256','uuid','profile_type','owner_private_phone_membership_verified_by_exact_cms_hash','native_readback_verified'}
    pins=[{k:v for k,v in row.items() if k in public_pin_keys} for row in completed]
    final.update(distribution='ad-hoc',delivery_lane='bryan-ad-hoc',signing_delivery='bryan-ad-hoc-export-only',profile_material_mode='native-adhoc-get-with-immutable-match-certificates',adhoc_native_profiles=pins,watch_hardware_eligibility_verified=False)
    for target in final['targets']:
        if target['family']=='ios':target['profile_type']='IOS_APP_ADHOC'
    result={'schema':1,'checked_at':now.isoformat(),'source_sha':SOURCE,'version':'0.1.0','build':'2','team':c.TEAM,'group':c.GROUP,'complete':True,'profiles':completed,'new_profile_count':sum(r['action']=='created' for r in completed),'reused_widget_count':2,'old_private_membership_receipt_sha256':MEMBERSHIP_RECEIPT,'hardware_values_in_public_result':False,'certificate_or_device_or_capability_created':False,'old_profiles_deleted':False,'watch_hardware_eligibility_verified':False,'keychain_or_app_build_or_install':False}
    write(out/'bryan-signing-export-scope.json',final);write(out/'bryan-build2-profile-manifest.json',result);return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--scope',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--execute-reviewed-two-adhoc-profiles',action='store_true');a=p.parse_args()
    try:
        c.require(a.execute_reviewed_two_adhoc_profiles and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('TEAMID')==c.TEAM,'reviewed_first_ci_attempt_required')
        c.require(os.environ.get('GITHUB_REPOSITORY')=='h00l1gvn/LoopFollow' and os.environ.get('GITHUB_ACTOR')=='h00l1gvn' and os.environ.get('GITHUB_REF')=='refs/heads/codex/resale-burrow-build2-bryan-profiles' and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','exact_owner_dispatched_lane_required')
        c.require(a.output.resolve().is_relative_to(pathlib.Path(os.environ['RUNNER_TEMP']).resolve()),'private_runner_output_required')
        s=json.loads(a.scope.read_text());validate_scope(s);prepare(BryanClient(audit.apple_token(os.environ),s),s,a.output)
        print(json.dumps({'status':'exact_bryan_build2_profile_preparation_verified','profiles':4,'widgets_reused':2,'hardware_output':False,'build_or_install':False}));return 0
    except (c.GateError,audit.AuditError) as e:print(json.dumps({'status':'stopped','code':str(e),'retry_allowed':False}));return 1
    except Exception:print(json.dumps({'status':'stopped','code':'private_profile_preparation_failure','retry_allowed':False}));return 1
if __name__=='__main__':raise SystemExit(main())
