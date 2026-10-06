#!/usr/bin/env python3
"""Read-only validation of the exact Resale Burrow Bryan ad-hoc re-export.

No archive/source signing, network, hardware query, keychain import, install or
upload. Reports never contain hardware identifiers or their fingerprints. The
independently reviewed scope binds the four exact CMS bytes/UUIDs and release.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import stat
import tempfile
import zipfile

import validate_resale_export as base

SOURCE='1162d8a1f4fdda1c2678220c9102f9c03ab48c33'
CERT='83418f42dfecf6e1709ea5528fb0f4f42b5df1189365147dc86747ace39de772'
CERT_EXPIRES=datetime.datetime(2027,9,16,2,46,2,tzinfo=datetime.timezone.utc)
EXPECTED={
 base.BASE:('DMWQ2F9XCQ','ResaleBurrow Bryan Ad Hoc 2026-10-06','1fbf2d90098225bd69d032cfb780224ce1559dcb527136e58a56333dad136f76'),
 base.BASE+'.widgets':('M7378SUWRA','ResaleBurrow iOS Widgets Bryan Ad Hoc 2026-10-06','33386d1ac15b71a00f3ebfa33758c4497fb5fc7632fbf1fee9977849757a902d'),
 base.BASE+'.watch':('234A433R79','ResaleBurrow Watch Bryan Ad Hoc 2026-10-06','1b2950135b3d42fa1bba36be3c1ad602ee9424e9e79b62c906441f6dbbdc7703'),
 base.BASE+'.watch.widgets':('UB47QM5B83','ResaleBurrow Watch Widgets Bryan Ad Hoc 2026-10-06','9c21a0178507b2c76edf8cf6888a8df802da39c7044c55cf5854ddabc9040f1b'),
}
require=base.require
Error=base.ValidationError


def utc(value,code):
    require(isinstance(value,datetime.datetime),code)
    return value.replace(tzinfo=datetime.timezone.utc) if value.tzinfo is None else value.astimezone(datetime.timezone.utc)


def scope_check(scope):
    targets=base.scope_check(scope,'ios')
    require(scope.get('source_sha')==SOURCE,'adhoc_frozen_source_mismatch')
    rows=scope.get('adhoc_native_profiles')
    require(isinstance(rows,list) and len(rows)==4 and {r.get('bundle_id') for r in rows}==set(EXPECTED),
            'adhoc_exact_four_profile_pins_required')
    require(len({r.get('uuid') for r in rows})==4,'adhoc_duplicate_profile_uuid')
    result={}
    for row in rows:
        identifier=row['bundle_id'];native,name,sha=EXPECTED[identifier]
        require((row.get('native_profile_id'),row.get('name'),row.get('sha256'))==(native,name,sha),
                'adhoc_profile_native_name_or_cms_pin_mismatch')
        require(isinstance(row.get('uuid'),str) and re.fullmatch(r'[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}',row['uuid']),
                'adhoc_explicit_profile_uuid_required')
        # Scope is suitable for public delivery tooling; refuse accidental raw
        # device/private records instead of serializing them into any report.
        require(set(row)<= {'bundle_id','native_profile_id','name','sha256','uuid','profile_type',
                           'owner_private_phone_membership_verified_by_exact_cms_hash'},
                'adhoc_profile_scope_has_unexpected_private_fields')
        require(row.get('owner_private_phone_membership_verified_by_exact_cms_hash') is True,
                'adhoc_previously_verified_private_phone_membership_required')
        if 'profile_type' in row:require(row['profile_type']=='IOS_APP_ADHOC','adhoc_profile_type_mismatch')
        result[identifier]=row
    return targets,result


class AdhocProfiles:
    def __init__(self, rows):
        self.rows=rows
        self.selected_phone=None
    def check(self,profile,signature,identifier,now,profile_path):
        expected=self.rows[identifier]
        require(base.digest(profile_path)==expected['sha256'],'adhoc_embedded_cms_bytes_mismatch')
        require(profile.get('Name')==expected['name'] and profile.get('UUID')==expected['uuid'],
                'adhoc_embedded_profile_name_or_uuid_mismatch')
        require(profile.get('TeamIdentifier')==[base.TEAM] and profile.get('ApplicationIdentifierPrefix')==[base.TEAM],
                'adhoc_profile_team_or_prefix_mismatch')
        ent=profile.get('Entitlements',{})
        require(isinstance(ent,dict) and base.identifier_entitlement(ent,identifier)
                and ent.get('com.apple.developer.team-identifier')==base.TEAM,'adhoc_profile_explicit_identity_mismatch')
        require(ent.get('com.apple.security.application-groups')==[base.GROUP],'adhoc_profile_literal_group_mismatch')
        require(ent.get('get-task-allow') is False and profile.get('ProvisionsAllDevices',False) is False,
                'adhoc_release_profile_required')
        for claims in [ent,signature.get('entitlements',{})]:
            require(not any(key in claims for key in ['aps-environment','com.apple.developer.icloud-services',
                    'com.apple.developer.weatherkit','com.apple.developer.carplay-driving-task']),
                    'adhoc_unexpected_sensitive_capability')
        created=utc(profile.get('CreationDate'),'adhoc_profile_creation_missing')
        expiry=utc(profile.get('ExpirationDate'),'adhoc_profile_expiry_missing')
        require(datetime.datetime(2026,10,6,tzinfo=datetime.timezone.utc)<=created<=now,
                'adhoc_profile_creation_outside_reviewed_window')
        require(now<expiry<=CERT_EXPIRES,'adhoc_profile_expired_or_beyond_certificate')
        leaf=signature.get('leaf_der')
        require(isinstance(leaf,bytes) and hashlib.sha256(leaf).hexdigest()==CERT,
                'adhoc_approved_distribution_leaf_mismatch')
        certificates=profile.get('DeveloperCertificates')
        require(isinstance(certificates,list) and len(certificates)==1 and certificates[0]==leaf,
                'adhoc_profile_certificate_binding_mismatch')
        devices=profile.get('ProvisionedDevices')
        require(isinstance(devices,list) and len(devices)==1 and isinstance(devices[0],str)
                and re.fullmatch(r'[A-Za-z0-9-]{8,64}',devices[0]),'adhoc_single_phone_profile_required')
        if self.selected_phone is None:self.selected_phone=devices[0]
        require(devices[0]==self.selected_phone,'adhoc_profiles_selected_phone_mismatch')
        return {'native_profile_id':expected['native_profile_id'],'profile_name':expected['name'],
                'profile_uuid':expected['uuid'],'profile_cms_sha256':expected['sha256'],
                'certificate_sha256':CERT,'expires_at':expiry.isoformat(),'profile_type':'IOS_APP_ADHOC',
                'selected_device_count':1,'same_selected_phone_verified':True,
                'raw_hardware_identifier_or_fingerprint_written':False}


def zip_preflight(path):
    require(path.is_file() and not path.is_symlink(),'adhoc_exact_regular_ipa_required')
    try:
        with zipfile.ZipFile(path) as z:
            entries=z.infolist();names=set();total=0
            require(0<len(entries)<=100000,'adhoc_zip_entry_limit')
            for entry in entries:
                p=pathlib.PurePosixPath(entry.filename);mode=entry.external_attr>>16
                require(not p.is_absolute() and '..' not in p.parts and '\\' not in entry.filename
                        and entry.filename not in names and not stat.S_ISLNK(mode),
                        'adhoc_unsafe_or_duplicate_ipa_member')
                names.add(entry.filename);total+=entry.file_size
                require(total<=2*1024**3,'adhoc_zip_size_limit')
    except (OSError,zipfile.BadZipFile):raise Error('adhoc_ipa_unreadable') from None


def archive_primary(archive):
    archive=pathlib.Path(archive)
    require(archive.is_dir() and archive.suffix=='.xcarchive' and not archive.is_symlink(),
            'adhoc_archive_missing')
    properties=base.load_plist(archive/'Info.plist').get('ApplicationProperties',{})
    require(properties.get('CFBundleIdentifier')==base.BASE,'adhoc_archive_primary_identifier_mismatch')
    name=properties.get('ApplicationPath');require(isinstance(name,str),'adhoc_archive_primary_path_missing')
    p=pathlib.PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts and '\\' not in name,'adhoc_archive_primary_path_invalid')
    primary=archive/'Products'/p
    require(primary.resolve().is_relative_to((archive/'Products/Applications').resolve()),
            'adhoc_archive_not_single_top_level_app')
    apps=list((archive/'Products/Applications').glob('*.app'))
    require(apps==[primary] and {p.name for p in (archive/'Products').iterdir()}=={'Applications'},
            'adhoc_archive_not_single_top_level_app')
    return primary


def validate(export_dir,scope,report,runner=None,now=None,*,archive=None):
    export_dir=pathlib.Path(export_dir);report=pathlib.Path(report)
    result={'schema':1,'family':'ios','distribution':'ad-hoc','source_sha_basis':scope.get('source_sha'),
            'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'failed',
            'signed_local_artifacts_verified':False,'archive_checked_here':False,
            'phone_queries':0,'installed':False,'uploaded':False,
            'watch_hardware_eligibility_verified':False,'raw_hardware_identifier_or_fingerprint_written':False}
    stage='scope'
    try:
        targets,profiles=scope_check(scope)
        runner=runner or base.Runner(report.parent/(report.stem+'-private'))
        now=now or datetime.datetime.now(datetime.timezone.utc)
        checker=AdhocProfiles(profiles)
        if archive is not None:
            stage='archive'
            primary=archive_primary(archive)
            result['archive_bundles']=base.bundle_set(primary,targets,runner,now,profile_validator=checker.check)
            result['archive_checked_here']=True
        stage='export';require(export_dir.is_dir() and not export_dir.is_symlink(),'adhoc_export_directory_missing')
        ipas=list(export_dir.glob('*.ipa'));require(len(ipas)==1,'adhoc_exact_one_export_ipa_required')
        ipa=ipas[0];zip_preflight(ipa)
        with tempfile.TemporaryDirectory(prefix='resale-adhoc-validation-',dir=report.parent) as temporary:
            dest=pathlib.Path(temporary)/'expanded';dest.mkdir(mode=0o700)
            primary=base.extract_ipa(ipa,dest)
            result['export_bundles']=base.bundle_set(primary,targets,runner,now,profile_validator=checker.check)
        result.update(status='passed',signed_local_artifacts_verified=True,exact_bundle_count=4,
                      export_artifact_sha256=base.digest(ipa),team=base.TEAM,group=base.GROUP,
                      approved_distribution_leaf_sha256=CERT,
                      same_single_selected_phone_verified=True,
                      private_bryan_membership_basis='Previously verified exact pinned CMS profiles; no hardware record read here',
                      source_sha_embedded_in_binary_verified=False)
    except Error as error:result.update(error_code=error.code,failed_stage=stage)
    except (OSError,ValueError,TypeError,KeyError,AttributeError):result.update(error_code='adhoc_artifact_or_scope_unreadable',failed_stage=stage)
    base.private_write(report,json.dumps(result,indent=2)+'\n')
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scope',type=pathlib.Path,required=True)
    p.add_argument('--export-dir',type=pathlib.Path,required=True)
    p.add_argument('--archive',type=pathlib.Path,
                   help='Optional fresh ad-hoc archive; validated independently from exported IPA')
    p.add_argument('--report',type=pathlib.Path,required=True)
    a=p.parse_args(argv)
    a.report.parent.mkdir(parents=True,exist_ok=True)
    try:scope=json.loads(a.scope.read_text())
    except (OSError,ValueError):
        base.private_write(a.report,json.dumps({'status':'failed','error_code':'adhoc_scope_unreadable'})+'\n')
        print('Ad-hoc export validation failed: adhoc_scope_unreadable')
        return 1
    r=validate(a.export_dir,scope,a.report,archive=a.archive)
    print(json.dumps({k:r[k] for k in ['status','error_code','failed_stage','exact_bundle_count','signed_local_artifacts_verified'] if k in r}))
    return 0 if r['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
