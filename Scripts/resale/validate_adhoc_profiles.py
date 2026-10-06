#!/usr/bin/env python3
"""Supplied-input CMS/profile verification only; no network or device service.

Input manifest must come from the separately authenticated exact-profile GET.
Its independently pinned SHA is required. Hardware is read only from an explicit
owner-private file, never printed/copied. No profile download or signing occurs.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import subprocess
import tempfile

TEAM='N8K8G6QA36'; BASE='com.julienbell.ResaleBurrow'
GROUP='group.com.julienbell.ResaleBurrow'
CERT_SHA='83418f42dfecf6e1709ea5528fb0f4f42b5df1189365147dc86747ace39de772'
EXPECTED={
 BASE:('DMWQ2F9XCQ','ResaleBurrow Bryan Ad Hoc 2026-10-06'),
 BASE+'.widgets':('M7378SUWRA','ResaleBurrow iOS Widgets Bryan Ad Hoc 2026-10-06'),
 BASE+'.watch':('234A433R79','ResaleBurrow Watch Bryan Ad Hoc 2026-10-06'),
 BASE+'.watch.widgets':('UB47QM5B83','ResaleBurrow Watch Widgets Bryan Ad Hoc 2026-10-06'),
}

class Invalid(ValueError): pass

def require(value, code):
    if not value: raise Invalid(code)

def sha(data): return hashlib.sha256(data).hexdigest()

def private_read(path, limit=8*1024*1024):
    p=Path(path); s=p.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and not s.st_mode&0o077,'input_not_owner_private')
    require(s.st_size<=limit,'input_size_exceeds_bound')
    return p.read_bytes()

def utc(value):
    require(isinstance(value,datetime),'profile_date_missing')
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

def validate_manifest(manifest, source, delivery):
    require(manifest.get('complete') is True and manifest.get('team')==TEAM and manifest.get('group')==GROUP,'retrieval_manifest_incomplete_or_identity_mismatch')
    require(manifest.get('source_sha')==source and manifest.get('delivery_sha')==delivery,'retrieval_manifest_provenance_mismatch')
    require(manifest.get('authenticated_exact_profile_get') is True,'retrieval_manifest_not_authenticated')
    rows=manifest.get('profiles',[])
    require(len(rows)==4 and {r.get('bundle_id') for r in rows}==set(EXPECTED),'exact_four_profiles_required')
    for row in rows:
        ident=row['bundle_id']; native,name=EXPECTED[ident]
        require(row.get('native_profile_id')==native and row.get('name')==name,'native_profile_id_or_name_mismatch')
        require(isinstance(row.get('path'),str) and row['path'] and re.fullmatch(r'[a-f0-9]{64}',row.get('sha256','')),'profile_path_or_digest_missing')
        path=PurePosixPath(row['path'])
        require(not path.is_absolute() and path.parts==('profiles',native+'.mobileprovision') and '\\' not in row['path'],'profile_path_not_portable_exact_scope')
    return rows

def resolved_profile_path(manifest_path, row):
    root=Path(manifest_path).resolve().parent
    rel=PurePosixPath(row['path'])
    require(not rel.is_absolute() and '..' not in rel.parts,'profile_path_not_portable_exact_scope')
    current=root
    for part in rel.parts:
        current=current/part
        require(not current.is_symlink(),'profile_path_symlink')
    require(current.resolve().is_relative_to(root),'profile_path_escapes_manifest')
    return current

def validate_profile(profile, ident, *, device=None, now=None):
    now=now or datetime.now(timezone.utc)
    require(ident in EXPECTED,'unexpected_bundle')
    require(profile.get('Name')==EXPECTED[ident][1],'profile_name_mismatch')
    require(isinstance(profile.get('UUID'),str) and re.fullmatch(r'[A-Fa-f0-9-]{36}',profile['UUID']),'profile_uuid_invalid')
    require(profile.get('TeamIdentifier')==[TEAM] and profile.get('ApplicationIdentifierPrefix')==[TEAM],'profile_team_or_prefix_mismatch')
    ent=profile.get('Entitlements',{})
    require(ent.get('application-identifier')==TEAM+'.'+ident and ent.get('com.apple.developer.team-identifier')==TEAM,'profile_exact_app_identity_mismatch')
    require(ent.get('com.apple.security.application-groups')==[GROUP],'profile_exact_group_mismatch')
    require(ent.get('get-task-allow') is False and profile.get('ProvisionsAllDevices',False) is False,'profile_not_release_adhoc')
    require(not any(k in ent for k in ('aps-environment','com.apple.developer.icloud-services','com.apple.developer.weatherkit','com.apple.developer.carplay-driving-task')),'unexpected_sensitive_capability')
    created,expires=utc(profile.get('CreationDate')),utc(profile.get('ExpirationDate'))
    require(created<=now+timedelta(minutes=5) and created>=datetime(2026,10,6,tzinfo=timezone.utc),'profile_creation_outside_owned_window')
    require(now<expires<=datetime(2027,9,16,2,46,2,tzinfo=timezone.utc),'profile_expired_or_exceeds_existing_certificate')
    certificates=profile.get('DeveloperCertificates')
    require(isinstance(certificates,list) and len(certificates)==1 and isinstance(certificates[0],bytes) and sha(certificates[0])==CERT_SHA,'profile_existing_certificate_mismatch')
    devices=profile.get('ProvisionedDevices')
    require(isinstance(devices,list) and len(devices)==1 and isinstance(devices[0],str) and devices[0],'profile_single_phone_selection_required')
    if device is not None: require(devices[0].strip().upper()==device.strip().upper(),'private_phone_membership_mismatch')
    return {'bundle_id':ident,'native_profile_id':EXPECTED[ident][0],'profile_name':EXPECTED[ident][1],
      'uuid':profile['UUID'],'profile_type':'IOS_APP_ADHOC','exact_team_group_certificate_verified':True,
      'certificate_sha256':CERT_SHA,'created_at':created.isoformat(),'expires_at':expires.isoformat(),
      'selected_device_count':1,'private_phone_membership_verified':device is not None,
      'watch_hardware_eligibility_verified':False}

def decode_cms(raw, work):
    profile=work/'supplied.mobileprovision'; profile.write_bytes(raw); profile.chmod(0o600)
    decoded=work/'decoded-private.plist'
    try:
        # -noverify skips trust-chain evaluation, not signature verification.
        # Origin authenticity comes from pinned authenticated GET provenance;
        # this additionally verifies CMS content integrity before decoding.
        p=subprocess.run(['/usr/bin/openssl','cms','-verify','-inform','DER','-noverify','-in',str(profile),'-out',str(decoded)],capture_output=True,timeout=30)
        require(p.returncode==0,'cms_signature_integrity_failed')
        decoded.chmod(0o600)
        p=subprocess.run(['/usr/bin/security','cms','-D','-i',str(profile)],capture_output=True,timeout=30)
        require(p.returncode==0,'cms_platform_decode_failed')
        require(plistlib.loads(decoded.read_bytes())==plistlib.loads(p.stdout),'cms_decoders_disagree')
        return plistlib.loads(p.stdout)
    except (OSError,subprocess.TimeoutExpired,ValueError,plistlib.InvalidFileException):
        raise Invalid('cms_decode_unavailable_or_invalid') from None

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('manifest','manifest-sha256','source','delivery','report'): parser.add_argument('--'+key,required=True)
    parser.add_argument('--private-hardware-record')
    args=parser.parse_args(argv)
    require(re.fullmatch(r'[a-f0-9]{64}',args.manifest_sha256) and re.fullmatch(r'[a-f0-9]{40}',args.source) and re.fullmatch(r'[a-f0-9]{40}',args.delivery),'independent_provenance_pins_required')
    manifest_raw=private_read(args.manifest); require(sha(manifest_raw)==args.manifest_sha256,'manifest_digest_mismatch')
    rows=validate_manifest(json.loads(manifest_raw),args.source,args.delivery)
    device=private_read(args.private_hardware_record,256).decode().strip() if args.private_hardware_record else None
    require(device is None or bool(device),'empty_private_hardware_record')
    result=[]
    with tempfile.TemporaryDirectory(prefix='resale-cms-') as tmp:
        work=Path(tmp); work.chmod(0o700)
        for i,row in enumerate(rows):
            raw=private_read(resolved_profile_path(args.manifest,row)); require(sha(raw)==row['sha256'],'profile_file_digest_mismatch')
            folder=work/str(i); folder.mkdir(mode=0o700)
            summary=validate_profile(decode_cms(raw,folder),row['bundle_id'],device=device)
            result.append({**summary,'sha256':sha(raw),'cms_signature_integrity_verified':True})
    report={'status':'supplied_four_adhoc_profiles_verified','recorded_at':datetime.now(timezone.utc).isoformat(),
      'source_sha':args.source,'delivery_sha':args.delivery,'manifest_sha256':args.manifest_sha256,
      'profiles':result,'profile_count':4,'private_hardware_record_read':device is not None,
      'raw_hardware_identifier_written':False,'phone_queries':0,'install_attempts':0,
      'watch_hardware_eligibility_verified':False,'signed_package_validated':False,
      'cms_trust_note':'Integrity plus independently pinned authenticated retrieval; no standalone Apple CMS signer chain attestation.'}
    output=Path(args.report); require(not output.is_symlink(),'unsafe_report_destination')
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f: json.dump(report,f,indent=2); f.write('\n')
    print('Four supplied ad-hoc profiles validated; no phone queries or installation.')
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except Invalid as e: print(str(e)); raise SystemExit(2)
