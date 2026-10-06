#!/usr/bin/env python3
"""Prepared exact-seven profile creation/reuse. No certificate creation/delete/upload.

No CLI network operation runs without --execute-reviewed-profile-creation.
Unknown POST outcomes are not retried; rerun GETs reuse valid exact-name profiles.
Profile bytes are kept private and Match-encrypted before the separate store commit.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, plistlib, re, secrets, subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urljoin, urlparse
from urllib.request import Request
import resale_apple_audit as audit

TEAM='N8K8G6QA36';GROUP='group.com.julienbell.ResaleBurrow'
BASE='com.julienbell.ResaleBurrow'
EXPECTED={BASE:'IOS_APP_STORE',BASE+'.widgets':'IOS_APP_STORE',BASE+'.watch':'IOS_APP_STORE',BASE+'.watch.widgets':'IOS_APP_STORE',BASE+'.mac':'MAC_APP_STORE',BASE+'.mac.widgets':'MAC_APP_STORE',BASE+'.tv':'TVOS_APP_STORE'}
CERT_ID='9K5USY2222';CERT_SHA='83418f42dfecf6e1709ea5528fb0f4f42b5df1189365147dc86747ace39de772'
INSTALLER_ID='WBR8H2GCGZ';INSTALLER_SHA='99d5b88d90d30283082420947296a6afa8e784cd5df9781c9eade2f7720f4df2'

def require(value, code):
    if not value: raise audit.AuditError(code)

def validate_scope(scope):
    require(scope.get('team')==TEAM and scope.get('group')==GROUP,'Reviewed scope identity mismatch.')
    targets=scope.get('targets',[])
    require(len(targets)==7 and len({r.get('bundle_id') for r in targets})==7 and {r.get('bundle_id'):r.get('profile_type') for r in targets}==EXPECTED,'Reviewed seven-profile scope mismatch.')
    exact_targets={r['bundle_id']:r['target'] for r in audit.CONFIG['targets']}
    require(all(r.get('target')==exact_targets[r['bundle_id']] for r in targets),'Reviewed target names differ.')
    certs=scope.get('certificates',{})
    for kind,identifier,fingerprint in (('distribution',CERT_ID,CERT_SHA),('mac_app_distribution',CERT_ID,CERT_SHA),('mac_installer_distribution',INSTALLER_ID,INSTALLER_SHA)):
        value=certs.get(kind,{})
        require(value.get('certificate_id')==identifier and value.get('sha256')==fingerprint and value.get('existing_private_key_challenge_verified') is True and value.get('exact_current_apple_certificate_verified') is True,'Verified existing certificate scope mismatch.')
    return targets

def profile_name(target): return 'ResaleBurrow AppStore '+target['target']

def profile_path(target):
    extension='.provisionprofile' if target['profile_type']=='MAC_APP_STORE' else '.mobileprovision'
    return 'profiles/appstore/AppStore_'+target['bundle_id']+extension

def profile_group_permission(target,groups):
    if groups==[GROUP]:return True
    # Exact native Mac CMS PAQRP4RMB6 includes the literal group plus this
    # same-Team permission wildcard. Signed binary entitlements stay literal.
    return target.get('profile_type')=='MAC_APP_STORE' and isinstance(groups,list) and len(groups)==2 and set(groups)=={GROUP,TEAM+'.*'}

def create_request(target, native_bundle_id):
    require(target.get('bundle_id') in EXPECTED and target.get('profile_type')==EXPECTED[target['bundle_id']],'Unapproved profile target.')
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,80}',native_bundle_id or ''),'Native bundle resource ID invalid.')
    return {'data':{'type':'profiles','attributes':{'name':profile_name(target),'profileType':target['profile_type']},'relationships':{'bundleId':{'data':{'type':'bundleIds','id':native_bundle_id}},'certificates':{'data':[{'type':'certificates','id':CERT_ID}]}}}}

class ProfileClient(audit.ReadClient):
    """Inherited GET boundaries plus exactly one structurally checked POST endpoint."""
    def create_profile(self, target, bundle_id):
        body=create_request(target,bundle_id)
        request=Request('https://api.appstoreconnect.apple.com/v1/profiles',data=json.dumps(body,separators=(',',':')).encode(),headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json','Accept':'application/json','User-Agent':'ResaleBurrow-exact-profile-preparation'},method='POST')
        try:
            with self.opener.open(request,timeout=45) as response:
                require(response.status==201,'Profile POST did not return Created; outcome needs a fresh GET review.')
                raw=response.read(4*1024*1024+1)
            require(len(raw)<=4*1024*1024,'Profile POST response exceeded the bound.')
            value=json.loads(raw)
            require(isinstance(value,dict) and isinstance(value.get('data'),dict),'Profile POST response shape was invalid.')
            return value['data']
        except HTTPError as error: raise audit.AuditError('Scoped profile POST failed; no automatic retry or deletion.',http_status=error.code,diagnostics=audit.error_diagnostics(error)) from None
        except (OSError,URLError,TimeoutError): raise audit.AuditError('Scoped profile POST outcome is unknown; stop and use fresh GETs before any retry.') from None
        except (ValueError,UnicodeError): raise audit.AuditError('Scoped profile POST response could not be read; stop and use fresh GETs before any retry.') from None

def verified_certificate(client, identifier, fingerprint, eligible):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    resource=client.get('/v1/certificates/'+identifier).get('data',{})
    require(resource.get('id')==identifier,'Existing certificate resource ID changed.')
    attrs=resource.get('attributes',{}); require(attrs.get('certificateType') in eligible,'Existing certificate type is not approved.')
    try: cert=x509.load_der_x509_certificate(base64.b64decode(attrs.get('certificateContent',''),validate=True))
    except Exception: raise audit.AuditError('Existing certificate content could not be verified.') from None
    require(cert.fingerprint(hashes.SHA256()).hex()==fingerprint,'Existing certificate fingerprint changed.')
    require([v.value for v in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)]==[TEAM],'Existing certificate Team differs.')
    require(cert.not_valid_before_utc<=datetime.now(timezone.utc)<cert.not_valid_after_utc,'Existing certificate is outside validity.')
    return cert.public_bytes(__import__('cryptography.hazmat.primitives.serialization',fromlist=['Encoding']).Encoding.DER)

def validate_profile(resource, target, certificate_der, decoder=audit.decode_profile):
    require(isinstance(resource.get('id'),str) and re.fullmatch(r'[A-Za-z0-9_-]{1,80}',resource['id']),'Native profile resource ID invalid.')
    attrs=resource.get('attributes',{})
    require(attrs.get('name')==profile_name(target),'Profile name is outside the exact owned scope.')
    summary=audit.profile_summary(resource,target['bundle_id'],{'profile_type':target['profile_type'],'group':True},TEAM,decoder)
    require(summary.get('productionRequirementsMet') is True,'Profile does not meet exact Team/AppGroup/type/date requirements.')
    content=attrs.get('profileContent');require(isinstance(content,str),'Profile signed content is missing.')
    profile=decoder(content);require(isinstance(profile,dict),'Signed profile content is unreadable.')
    ent=profile.get('Entitlements',{})
    require(profile.get('TeamIdentifier')==[TEAM] and profile.get('ApplicationIdentifierPrefix')==[TEAM],'Profile Team/prefix differs.')
    require(ent.get('com.apple.developer.team-identifier')==TEAM and profile_group_permission(target,ent.get('com.apple.security.application-groups')),'Profile Team/AppGroup entitlement differs.')
    require('ProvisionedDevices' not in profile and profile.get('ProvisionsAllDevices') is not True,'Profile is not an App Store profile.')
    require(profile.get('DeveloperCertificates')==[certificate_der],'Profile does not contain only the verified existing distribution certificate.')
    uuid=profile.get('UUID');require(isinstance(uuid,str) and re.fullmatch(r'[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}',uuid),'Profile UUID invalid.')
    require(profile.get('Name')==profile_name(target),'Signed profile name differs.')
    raw=base64.b64decode(content,validate=True);require(0<len(raw)<=2*1024*1024,'Profile binary exceeds the bound.')
    return {'bundle_id':target['bundle_id'],'target':target['target'],'uuid':uuid,'name':profile_name(target),'profile_type':target['profile_type'],'verified':True,'certificate_sha256':CERT_SHA,'sha256':hashlib.sha256(raw).hexdigest(),'path':profile_path(target),'expires_at':summary['expires']},raw

def encrypt_profile(raw,password):
    """Official Match V2 envelope; newly created profile only, no plaintext store."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt=secrets.token_bytes(8);keyiv=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,10000,68)
    value=AESGCM(keyiv[:32]).encrypt(keyiv[32:44],raw,keyiv[44:])
    return base64.b64encode(b'match_encrypted_v2__'+salt+value[-16:]+value[:-16])+b'\n'

def prepare_profiles(client,scope,output,password,decoder=audit.decode_profile):
    targets=validate_scope(scope);require(password,'MATCH_PASSWORD is required for encrypted scoped output.')
    cert_der=verified_certificate(client,CERT_ID,CERT_SHA,{'DISTRIBUTION'})
    verified_certificate(client,INSTALLER_ID,INSTALLER_SHA,{'MAC_INSTALLER_DISTRIBUTION'})
    output=Path(output);require(not output.exists(),'Refuse to replace a previous profile output directory; review/reuse it first.')
    output.mkdir(parents=True,mode=0o700);os.chmod(output,0o700)
    rows=[]
    for target in targets:
        values=client.collection('/v1/bundleIds?'+urlencode({'filter[identifier]':target['bundle_id'],'limit':50}))
        matches=[v for v in values if v.get('attributes',{}).get('identifier')==target['bundle_id']]
        require(len(matches)==1,'Exact registered bundle is missing or ambiguous.')
        bundle_id=matches[0].get('id');require(isinstance(bundle_id,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,80}',bundle_id),'Native bundle ID invalid.')
        profiles=client.collection('/v1/bundleIds/'+quote(bundle_id,safe='')+'/profiles?limit=50')
        named=[v for v in profiles if v.get('attributes',{}).get('name')==profile_name(target)]
        require(len(named)<=1,'Exact profile name is ambiguous; no automatic renewal/deletion.')
        action='reused' if named else 'created'
        if named: resource=named[0]
        else:
            # Durable intent before POST. Unknown result is not retried by this job.
            private_write(output/'latest-create-intent.json',{'bundle_id':target['bundle_id'],'name':profile_name(target),'created_at':datetime.now(timezone.utc).isoformat()})
            resource=client.create_profile(target,bundle_id)
        row,raw=validate_profile(resource,target,cert_der,decoder)
        encrypted=encrypt_profile(raw,password);destination=output/row['path'];destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        destination.write_bytes(encrypted);os.chmod(destination,0o600)
        row.update(action=action,encrypted_sha256=hashlib.sha256(encrypted).hexdigest(),native_profile_id=resource.get('id'))
        if action=='created':
            # Re-read the exact bundle relationship, never infer success from POST alone.
            readback=client.collection('/v1/bundleIds/'+quote(bundle_id,safe='')+'/profiles?limit=50')
            same=[v for v in readback if v.get('id')==resource['id'] and v.get('attributes',{}).get('name')==profile_name(target)]
            require(len(same)==1,'Created profile is not yet visible in exact native readback; preserve private evidence and stop.')
            verified,_=validate_profile(same[0],target,cert_der,decoder)
            require(verified['uuid']==row['uuid'] and verified['sha256']==row['sha256'],'Created profile readback differs from the validated POST result.')
        row['native_readback_verified']=True
        rows.append(row)
        private_write(output/'progress.json',{'profiles':rows,'complete':len(rows)==7,'no_certificate_creation':True,'no_deletion_or_upload':True})
    return {'schema':1,'prepared_at':datetime.now(timezone.utc).isoformat(),'team':TEAM,'group':GROUP,'source_sha':scope['source_sha'],'profiles':rows,'complete':True,'profile_count':7,'certificate_id':CERT_ID,'certificate_sha256':CERT_SHA,'installer_certificate_id':INSTALLER_ID,'installer_certificate_sha256':INSTALLER_SHA,'match_write_performed':False,'keychain_modified':False,'certificate_created':False,'app_upload_performed':False}

def private_write(path,value):
    path=Path(path);require(not path.is_symlink(),'Unsafe private output path.')
    with path.open('w') as handle: json.dump(value,handle,indent=2);handle.write('\n')
    os.chmod(path,0o600)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scope',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--execute-reviewed-profile-creation',action='store_true');a=p.parse_args()
    try:
        scope=json.loads(a.scope.read_text());validate_scope(scope)
        require(a.execute_reviewed_profile_creation,'Profile creation is prepared only; explicit reviewed execution flag required.')
        require(os.environ.get('TEAMID')==TEAM,'CI Team differs from reviewed scope.')
        client=ProfileClient('https://api.appstoreconnect.apple.com',audit.apple_token(os.environ))
        result=prepare_profiles(client,scope,a.output,os.environ.get('MATCH_PASSWORD',''))
        private_write(a.output/'profile-manifest.json',result)
        print('Exact seven profiles verified and encrypted privately. No certificate/store/keychain/upload changes.');return 0
    except audit.AuditError as error:
        print('Scoped profile job stopped: '+str(error));return 1
    except Exception:
        print('Scoped profile job stopped on an unexpected response; no diagnostic/private contents printed.');return 1

if __name__=='__main__':raise SystemExit(main())
