#!/usr/bin/env python3
"""Offline cached-export upload planner. It never uploads/dispatches/reads keys.

Receipts supplied to this planner must be independently authenticated/pinned by
the operator. Booleans alone cannot establish origin or signing authenticity.
"""
from datetime import datetime, timezone, timedelta
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

REPO='h00l1gvn/resale-burrow-native'
BASE='com.julienbell.ResaleBurrow'
TEAM='N8K8G6QA36';GROUP='group.com.julienbell.ResaleBurrow'
APPS={
 'ios':{'asc_id':'6819601040','bundle_id':BASE,'platform':'IOS','fastlane_platform':'ios','suffix':'.ipa','count':4},
 'macos':{'asc_id':'6819601423','bundle_id':BASE+'.mac','platform':'MAC_OS','fastlane_platform':'osx','suffix':'.pkg','count':2},
 'tvos':{'asc_id':'6819601651','bundle_id':BASE+'.tv','platform':'TV_OS','fastlane_platform':'appletvos','suffix':'.ipa','count':1},
}
class Invalid(ValueError):pass
def require(value,code):
    if not value:raise Invalid(code)
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def time(value):
    require(isinstance(value,str),'dated_receipt_required')
    try:r=datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError:raise Invalid('invalid_receipt_date') from None
    require(r.tzinfo is not None,'timezone_required');return r.astimezone(timezone.utc)

def validate_export(row,source,delivery):
    family=row.get('family');require(family in APPS,'only_three_app_store_families_allowed');app=APPS[family]
    require(row.get('distribution')=='app-store' and row.get('version')=='0.1.0' and str(row.get('build'))=='1','release_identity_or_distribution_mismatch')
    require(row.get('source_sha')==source and row.get('delivery_sha')==delivery,'export_provenance_mismatch')
    require(row.get('authenticated_recovery_verified') is True,'authenticated_recovery_required')
    p=Path(row.get('path',''));require(p.is_absolute() and p.is_file() and not p.is_symlink() and p.suffix==app['suffix'],'absolute_exact_export_file_required')
    require(re.fullmatch(r'[a-f0-9]{64}',row.get('sha256','')) and digest(p)==row['sha256'],'signed_export_digest_mismatch')
    validation=row.get('validation',{})
    require(validation.get('status')=='passed' and validation.get('signed_local_artifacts_verified') is True and validation.get('export_artifact_sha256')==row['sha256'],'exact_signed_export_validation_required')
    require(validation.get('family')==family and validation.get('team')==TEAM and validation.get('group')==GROUP and validation.get('exact_bundle_count')==app['count'],'validation_bundle_scope_mismatch')
    require(validation.get('source_sha_basis')==source and validation.get('uploaded') is False,'validation_provenance_or_upload_state_mismatch')
    return {'family':family,'asc_id':app['asc_id'],'bundle_id':app['bundle_id'],'platform':app['platform'],
      'path':str(p.resolve()),'sha256':row['sha256'],'version':'0.1.0','build':'1'}

def collision_precheck(value,family,*,now=None):
    now=now or datetime.now(timezone.utc);app=APPS[family]
    require(value.get('authenticated_get_only') is True and value.get('complete') is True,'exact_readonly_precheck_required')
    require(value.get('asc_id')==app['asc_id'] and value.get('bundle_id')==app['bundle_id'] and value.get('platform')==app['platform'],'precheck_app_or_platform_mismatch')
    checked=time(value.get('checked_at'));require(now-timedelta(minutes=10)<=checked<=now,'fresh_precheck_required')
    require(value.get('unknown_previous_upload') is False and value.get('pagination_complete') is True,'previous_upload_or_collection_unknown')
    for key in ('builds','build_uploads'):
        rows=value.get(key);require(isinstance(rows,list),'precheck_collection_missing')
        for row in rows:
            require(row.get('identity_resolved') is True,'unresolved_existing_upload_or_build')
            require(row.get('platform')==app['platform'] and isinstance(row.get('version'),str) and isinstance(row.get('build'),str),'existing_upload_coordinates_unknown')
            require(not(row['version']=='0.1.0' and row['build']=='1'),'exact_build_already_exists_or_inflight')
    return True

def fastlane_options(row):
    app=APPS[row['family']]
    # API key is injected only by the established cloud credential context.
    return {'apple_id':app['asc_id'],'app_identifier':app['bundle_id'],'app_platform':app['fastlane_platform'],
      'pkg' if row['family']=='macos' else 'ipa':row['path'],
      'app_version':'0.1.0','build_number':'1','skip_submission':True,
      'skip_waiting_for_build_processing':True,'distribute_external':False,'notify_external_testers':False}

def private_cache_plan(repository,rows):
    require(repository.get('full_name')==REPO and repository.get('private') is True,'private_exact_repository_required')
    require(len(rows)==3 and {r['family'] for r in rows}==set(APPS),'three_exact_exports_required')
    return {'repository':REPO,'draft':True,'prerelease':True,'tag_name':'resale-burrow-0.1.0-build-1-signed-cache',
      'assets':[{'name':'ResaleBurrow-'+r['family']+'-0.1.0-1'+APPS[r['family']]['suffix'],
        'path':r['path'],'sha256':r['sha256'],'family':r['family']} for r in rows],
      'additional_allowed_asset':'signed-export-cache-manifest.json',
      'prohibited_assets':['ad-hoc package','profiles','certificates','keys','raw logs','archive']}

def reserve_local_attempt(path,family,sha256):
    """One local checkpoint only. Cross-job exclusion also needs CI concurrency
    and a root-owned durable attempt record checked before every dispatch.
    Never reuse an attempt after timeout/unknown outcome without actual GETs.
    """
    require(family in APPS and re.fullmatch(r'[a-f0-9]{64}',sha256),'attempt_scope_invalid')
    p=Path(path);require(not p.is_symlink(),'unsafe_attempt_path')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump({'family':family,'asc_id':APPS[family]['asc_id'],'version':'0.1.0','build':'1','sha256':sha256,'reserved_at':datetime.now(timezone.utc).isoformat(),'outcome':'unknown_until_actual_receipt'},f)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('manifest','manifest-sha256','prechecks','source','delivery','repository-metadata','report'):p.add_argument('--'+key,required=True)
    a=p.parse_args(argv)
    require(re.fullmatch(r'[a-f0-9]{40}',a.source) and re.fullmatch(r'[a-f0-9]{40}',a.delivery),'immutable_commit_pins_required')
    raw=Path(a.manifest).read_bytes();require(hashlib.sha256(raw).hexdigest()==a.manifest_sha256,'manifest_pin_mismatch')
    m=json.loads(raw);require(m.get('complete') is True,'export_manifest_incomplete')
    rows=[validate_export(r,a.source,a.delivery) for r in m.get('exports',[])]
    checks=json.loads(Path(a.prechecks).read_text())
    for row in rows:collision_precheck(checks.get(row['family'],{}),row['family'])
    cache=private_cache_plan(json.loads(Path(a.repository_metadata).read_text()),rows)
    result={'status':'offline_plan_only','source_sha':a.source,'delivery_sha':a.delivery,'private_cache':cache,
      'fastlane_options':{r['family']:fastlane_options(r) for r in rows},'uploads_executed':0,
      'prechecks_must_be_repeated_immediately_before_upload':True,'processing_group_assignment_installation_separate':True}
    out=Path(a.report);fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(result,f,indent=2);f.write('\n')
    print('Offline exact cached-export plan created. No upload, dispatch or key access.')

if __name__=='__main__':
    try:main()
    except Invalid as e:print(str(e));raise SystemExit(2)
