#!/usr/bin/env python3
"""Bounded exact-owned App ID/profile GET audit. No create/update/delete capability."""
from __future__ import annotations
import argparse,base64,datetime,hashlib,json,os,pathlib,re
from urllib.parse import quote,urlencode
import build3_contract as c
import resale_apple_audit as audit

EXPECTED={c.BASE:'IOS_APP_STORE',c.BASE+'.widgets':'IOS_APP_STORE',c.BASE+'.watch':'IOS_APP_STORE',c.BASE+'.watch.widgets':'IOS_APP_STORE',c.BASE+'.mac':'MAC_APP_STORE',c.BASE+'.mac.widgets':'MAC_APP_STORE',c.BASE+'.tv':'TVOS_APP_STORE'}
CERT_ID='9K5USY2222'

def certificate(client,now):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    r=client.get('/v1/certificates/'+CERT_ID).get('data',{});a=r.get('attributes',{})
    c.require(r.get('id')==CERT_ID and a.get('certificateType')=='DISTRIBUTION','approved_certificate_resource_mismatch')
    try:raw=base64.b64decode(a.get('certificateContent',''),validate=True);cert=x509.load_der_x509_certificate(raw)
    except (ValueError,TypeError):raise c.GateError('certificate_content_invalid') from None
    c.require(hashlib.sha256(raw).hexdigest()==c.CERT_SHA,'approved_certificate_fingerprint_mismatch')
    c.require([a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)]==[c.TEAM] and cert.not_valid_before_utc<=now<cert.not_valid_after_utc,'certificate_team_or_validity_mismatch')
    return cert.public_bytes(serialization.Encoding.DER)

def profile_evidence(resource,identifier,cert,now,decoder=audit.decode_profile):
    """Metadata only; never includes certificate/profile/hardware bytes or entitlements."""
    attrs=resource.get('attributes',{});native_id=resource.get('id')
    c.require(isinstance(native_id,str) and re.fullmatch('[A-Za-z0-9_-]{1,80}',native_id),'profile_resource_id_invalid')
    c.require(attrs.get('profileType')==EXPECTED[identifier],'profile_distribution_type_mismatch')
    content=attrs.get('profileContent');c.require(isinstance(content,str),'profile_content_missing')
    try:raw=base64.b64decode(content,validate=True)
    except (ValueError,TypeError):raise c.GateError('profile_content_invalid') from None
    c.require(0<len(raw)<=2*1024**2,'profile_content_bound')
    p=decoder(content);c.require(isinstance(p,dict),'profile_cms_decode_failed')
    ent=p.get('Entitlements',{});c.require(isinstance(ent,dict),'profile_entitlements_invalid')
    dates=[]
    for key in ['CreationDate','ExpirationDate']:
        v=p.get(key);c.require(isinstance(v,datetime.datetime),'profile_dates_missing');dates.append(v.replace(tzinfo=datetime.timezone.utc) if v.tzinfo is None else v)
    groups=ent.get('com.apple.security.application-groups')
    groupok=groups==[c.GROUP] or (identifier in {c.BASE+'.mac',c.BASE+'.mac.widgets'} and isinstance(groups,list) and len(groups)==2 and set(groups)=={c.GROUP,c.TEAM+'.*'})
    ids=[ent[k] for k in ('application-identifier','com.apple.application-identifier') if k in ent]
    structural=(attrs.get('profileState')=='ACTIVE' and p.get('TeamIdentifier')==[c.TEAM] and p.get('ApplicationIdentifierPrefix')==[c.TEAM] and dates[0]<=now<dates[1] and bool(ids) and all(v==c.TEAM+'.'+identifier for v in ids) and ent.get('com.apple.developer.team-identifier')==c.TEAM and groupok and ent.get('get-task-allow',False) is False and 'ProvisionedDevices' not in p and not p.get('ProvisionsAllDevices',False) and p.get('DeveloperCertificates')==[cert])
    push_ok=True
    try:c.require_push_grants(identifier,ent,ent)
    except c.GateError:push_ok=False
    uuid=p.get('UUID');c.require(isinstance(uuid,str) and re.fullmatch('[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}',uuid),'profile_uuid_invalid')
    return {'native_profile_id':native_id,'uuid':uuid,'profile_type':attrs['profileType'],'sha256':hashlib.sha256(raw).hexdigest(),'expires_at':dates[1].isoformat(),'current_explicit_owned_certificate_group_verified':bool(structural),'production_push_requirements_met':push_ok,'reusable_for_build3':bool(structural and push_ok)}

def run(client,now=None,decoder=audit.decode_profile):
    now=now or datetime.datetime.now(datetime.timezone.utc);cert=certificate(client,now);rows=[]
    for identifier in EXPECTED:
        matches=[r for r in client.collection('/v1/bundleIds?'+urlencode({'filter[identifier]':identifier,'limit':50})) if r.get('attributes',{}).get('identifier')==identifier]
        c.require(len(matches)==1,'exact_bundle_registration_missing_or_ambiguous');native_id=matches[0].get('id')
        c.require(isinstance(native_id,str) and re.fullmatch('[A-Za-z0-9_-]{1,80}',native_id),'bundle_resource_id_invalid')
        capabilities=client.collection('/v1/bundleIds/'+quote(native_id,safe='')+'/bundleIdCapabilities?limit=50')
        types={r.get('attributes',{}).get('capabilityType') for r in capabilities}
        candidates=[r for r in client.collection('/v1/bundleIds/'+quote(native_id,safe='')+'/profiles?limit=50') if r.get('attributes',{}).get('profileType')==EXPECTED[identifier]]
        evidence=[profile_evidence(r,identifier,cert,now,decoder) for r in candidates]
        receiver=identifier in c.PUSH;push_cap='PUSH_NOTIFICATIONS' in types
        rows.append({'bundle_id':identifier,'native_bundle_resource_id':native_id,'production_push_receiver':receiver,'push_capability_resource_observed':push_cap,'app_group_capability_resource_observed':'APP_GROUPS' in types,'profiles':evidence,'build3_profile_ready':any(r['reusable_for_build3'] for r in evidence),'receiving_push_capability_ready':not receiver or push_cap})
    return {'schema':'ResaleBurrow-build3-profile-capability-get-1','checked_at':now.isoformat(),'team':c.TEAM,'group':c.GROUP,'version':'0.1.0','build':'3','exact_targets':rows,'all_profile_ready':all(r['build3_profile_ready'] for r in rows),'all_receiving_push_capability_ready':all(r['receiving_push_capability_ready'] for r in rows),'credential_or_hardware_values_retained':False,'account_mutations':0,'source_frozen':False,'signed':False,'uploaded':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('--report',type=pathlib.Path,required=True);p.add_argument('--execute-reviewed-get-only',action='store_true');a=p.parse_args()
    try:
        c.require(a.execute_reviewed_get_only,'reviewed_get_execution_required');c.require(os.environ.get('TEAMID')==c.TEAM,'ci_team_mismatch');c.require(not a.report.exists() and not a.report.is_symlink(),'report_destination_collision')
        result=run(audit.ReadClient('https://api.appstoreconnect.apple.com',audit.apple_token(os.environ)))
        a.report.parent.mkdir(parents=True,exist_ok=True);fd=os.open(a.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as h:json.dump(result,h,indent=2);h.write('\n')
        print(json.dumps({'status':'get_audit_complete','targets':7,'all_profile_ready':result['all_profile_ready'],'all_receiving_push_capability_ready':result['all_receiving_push_capability_ready'],'account_mutations':0}));return 0
    except (c.GateError,audit.AuditError) as e:print(json.dumps({'status':'blocked','code':str(e)}));return 1
    except Exception:print(json.dumps({'status':'blocked','code':'profile_audit_unexpected_response'}));return 1
if __name__=='__main__':raise SystemExit(main())
