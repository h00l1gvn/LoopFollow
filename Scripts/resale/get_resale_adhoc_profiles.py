#!/usr/bin/env python3
"""GET four existing Bryan profiles; private raw output only, no device or cloud writes."""
from __future__ import annotations
import argparse,base64,hashlib,json,os,re
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlencode,quote
import resale_apple_audit as audit
import resale_scoped_profiles as profiles
import validate_adhoc_profiles as adhoc

SOURCE='1162d8a1f4fdda1c2678220c9102f9c03ab48c33'

def retrieve(client,output,delivery_sha,reviewed_profiles,decoder=audit.decode_profile):
    profiles.require(re.fullmatch(r'[0-9a-f]{40}',delivery_sha or ''),'Exact frozen delivery SHA is required.')
    profiles.require(isinstance(reviewed_profiles,list) and len(reviewed_profiles)==4 and {r.get('bundle_id') for r in reviewed_profiles}==set(adhoc.EXPECTED),'Four independently reviewed raw profile hashes are required.')
    reviewed={r['bundle_id']:r for r in reviewed_profiles}
    for bundle,(identifier,name) in adhoc.EXPECTED.items():
        r=reviewed[bundle];profiles.require(r.get('native_profile_id')==identifier and r.get('name')==name and re.fullmatch(r'[0-9a-f]{64}',r.get('sha256','')),'Reviewed ad-hoc ID/name/hash differs.')
    cert=profiles.verified_certificate(client,profiles.CERT_ID,profiles.CERT_SHA,{'DISTRIBUTION'})
    output=Path(output);profiles.require(not output.exists() and not output.is_symlink(),'Refuse to replace existing private profile retrieval.')
    output.mkdir(parents=True,mode=0o700);os.chmod(output,0o700);(output/'profiles').mkdir(mode=0o700)
    rows=[];selected_phone=None
    for bundle,(identifier,name) in adhoc.EXPECTED.items():
        bundles=client.collection('/v1/bundleIds?'+urlencode({'filter[identifier]':bundle,'limit':50}))
        exact=[r for r in bundles if r.get('attributes',{}).get('identifier')==bundle];profiles.require(len(exact)==1,'Exact owned bundle missing or ambiguous.')
        bid=exact[0].get('id');profiles.require(re.fullmatch(r'[A-Za-z0-9_-]{1,80}',bid or ''),'Bundle resource ID invalid.')
        native=client.collection('/v1/bundleIds/'+quote(bid,safe='')+'/profiles?limit=50')
        exact=[r for r in native if r.get('id')==identifier and r.get('attributes',{}).get('name')==name];profiles.require(len(exact)==1,'Exact already-created ad-hoc resource missing or ambiguous.')
        attrs=exact[0]['attributes'];profiles.require(attrs.get('profileType')=='IOS_APP_ADHOC' and attrs.get('profileState')=='ACTIVE','Exact ad-hoc type/state differs.')
        raw=base64.b64decode(attrs.get('profileContent',''),validate=True);profiles.require(0<len(raw)<=2*1024*1024,'Ad-hoc raw profile size invalid.')
        profiles.require(hashlib.sha256(raw).hexdigest()==reviewed[bundle]['sha256'],'Current ad-hoc profile differs from the independently reviewed native CMS bytes.')
        decoded=decoder(attrs['profileContent']);profiles.require(isinstance(decoded,dict),'Ad-hoc profile CMS could not be decoded.')
        info=adhoc.validate_profile(decoded,bundle)
        profiles.require(not reviewed[bundle].get('uuid') or info['uuid']==reviewed[bundle]['uuid'],'Ad-hoc profile UUID differs from the reviewed native CMS.')
        profiles.require(decoded.get('DeveloperCertificates')==[cert],'Ad-hoc profile certificate differs from current verified certificate.')
        device=decoded['ProvisionedDevices'][0].strip().upper()
        if selected_phone is None:selected_phone=device
        profiles.require(device==selected_phone,'Ad-hoc profiles do not select the same single private phone.')
        relative='profiles/'+identifier+'.mobileprovision';path=output/relative
        with path.open('xb') as handle:handle.write(raw)
        os.chmod(path,0o600)
        rows.append({'bundle_id':bundle,'native_profile_id':identifier,'name':name,'path':relative,'sha256':hashlib.sha256(raw).hexdigest(),'uuid':info['uuid'],'profile_type':'IOS_APP_ADHOC','certificate_sha256':profiles.CERT_SHA,'expires_at':info['expires_at'],'native_readback_verified':True})
    result={'schema':1,'source_sha':SOURCE,'delivery_sha':delivery_sha,'retrieved_at':datetime.now(timezone.utc).isoformat(),'complete':True,'team':profiles.TEAM,'group':profiles.GROUP,'profiles':rows,'authenticated_exact_profile_get':True,'same_single_phone_across_four_profiles':True,'private_owner_phone_membership_verified':False,'watch_hardware_eligibility_verified':False,'raw_hardware_identifier_in_report':False,'network_mutations':False,'keychain_modified':False,'signed_package_prepared':False,'uploaded':False}
    profiles.private_write(output/'adhoc-profile-manifest.json',result);return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--delivery-sha',required=True);p.add_argument('--scope',type=Path,required=True);a=p.parse_args()
    try:
        profiles.require(os.environ.get('TEAMID')==profiles.TEAM,'CI Team differs from reviewed scope.')
        scope=json.loads(a.scope.read_text());profiles.require(scope.get('source_sha')==SOURCE,'Frozen source differs.')
        retrieve(audit.ReadClient('https://api.appstoreconnect.apple.com',audit.apple_token(os.environ)),a.output,a.delivery_sha,scope.get('adhoc_native_profiles',[]))
        print('Four exact already-created ad-hoc profiles retrieved privately. No device/account writes.');return 0
    except (audit.AuditError,adhoc.Invalid) as error:print('Scoped ad-hoc GET stopped: '+str(error));return 1
    except Exception:print('Scoped ad-hoc GET stopped; no private data or upstream response printed.');return 1
if __name__=='__main__':raise SystemExit(main())
