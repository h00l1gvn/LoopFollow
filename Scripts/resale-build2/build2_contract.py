"""Build2 release guards only. No account, build, upload, signing or device operation."""
from __future__ import annotations
import hashlib,json,pathlib,plistlib,re

TEAM='N8K8G6QA36'
GROUP='group.com.julienbell.ResaleBurrow'
BASE='com.julienbell.ResaleBurrow'
OLD_SOURCE='1162d8a1f4fdda1c2678220c9102f9c03ab48c33'
CERT_SHA='83418f42dfecf6e1709ea5528fb0f4f42b5df1189365147dc86747ace39de772'
PUSH={BASE:'aps-environment',BASE+'.watch':'aps-environment',BASE+'.mac':'com.apple.developer.aps-environment'}
TARGETS={'ResaleBurrowIOS':BASE,'ResaleBurrowIOSWidgets':BASE+'.widgets','ResaleBurrowWatch':BASE+'.watch','ResaleBurrowWatchWidgets':BASE+'.watch.widgets','ResaleBurrowMac':BASE+'.mac','ResaleBurrowMacWidgets':BASE+'.mac.widgets','ResaleBurrowTV':BASE+'.tv'}

class GateError(Exception):pass
def require(value,code):
    if not value:raise GateError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def safe_relative(value):
    require(isinstance(value,str) and '\\' not in value and '\x00' not in value,'source_path_invalid')
    p=pathlib.PurePosixPath(value)
    require(bool(value) and not p.is_absolute() and '..' not in p.parts and str(p)==value,'source_path_invalid')
    return p

def require_push_grants(identifier,signed_entitlements,profile_entitlements):
    """Profile permissions and signed binary claims must agree; key creation is separate."""
    key=PUSH.get(identifier)
    require(identifier in TARGETS.values(),'unexpected_bundle')
    for ent in [signed_entitlements,profile_entitlements]:
        require(isinstance(ent,dict),'push_entitlements_invalid')
        if key:
            require(ent.get(key)=='production','production_push_grant_missing')
            other='com.apple.developer.aps-environment' if key=='aps-environment' else 'aps-environment'
            require(other not in ent,'wrong_platform_push_key')
        else:require('aps-environment' not in ent and 'com.apple.developer.aps-environment' not in ent,'unexpected_widget_or_tv_push')
    return {'production_push_verified':bool(key),'receiving_bundle_id':identifier}

def validate_freeze(review,source_manifest,checkout):
    """Rejects interim artwork, historical build1, stale manifests and private payloads."""
    require(review.get('root_release_reviewed') is True and review.get('selected_icon_owner_approved') is True and review.get('interim_artwork_rejected') is True,'final_artwork_or_release_review_missing')
    source=review.get('source_sha','');require(re.fullmatch('[0-9a-f]{40}',source or '') and source!=OLD_SOURCE,'new_immutable_source_required')
    require(review.get('version')=='0.1.0' and str(review.get('build'))=='2' and review.get('team')==TEAM and review.get('group')==GROUP,'build2_identity_mismatch')
    require(source_manifest.get('product_photos')==0 and source_manifest.get('credentials_profiles_databases_logs_or_workspace_history') is False,'private_source_payload_forbidden')
    rows=source_manifest.get('files');require(isinstance(rows,list) and 0<len(rows)<=2000,'source_manifest_invalid')
    root=pathlib.Path(checkout).resolve();seen=set()
    for row in rows:
        rel=str(safe_relative(row.get('path')));require(rel not in seen,'source_manifest_duplicate');seen.add(rel)
        allowed=(rel in {'.github/workflows/apple-validate.yml','NATIVE_SOURCE_MANIFEST.json'} or rel.startswith('apple/'))
        require(allowed and not any(x in pathlib.PurePosixPath(rel).parts for x in ['runtime','.git','.build','build','delivery']) and pathlib.PurePosixPath(rel).suffix.lower() not in {'.p8','.p12','.cer','.mobileprovision','.provisionprofile','.sqlite','.db','.log','.jpg','.jpeg','.webp'},'private_or_unapproved_source_member')
        path=root/rel;require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root),'source_member_missing')
        require(re.fullmatch('[0-9a-f]{64}',row.get('sha256','')) and sha(path.read_bytes())==row['sha256'],'source_manifest_hash_changed')
    icon=str(safe_relative(review.get('approved_icon_asset_path')))
    require(icon.startswith('apple/AssetsSource/') and icon.endswith('.png') and icon in seen and re.fullmatch('[0-9a-f]{64}',review.get('approved_icon_sha256','')) and sha((root/icon).read_bytes())==review['approved_icon_sha256'],'selected_icon_hash_mismatch')
    for target,identifier in TARGETS.items():
        relative=f'apple/Configuration/{target}.plist';require(relative in seen,'target_plist_manifest_missing')
        data=plistlib.loads((root/relative).read_bytes());require(str(data.get('CFBundleVersion'))=='2' and data.get('CFBundleShortVersionString')=='0.1.0' and data.get('CFBundleDisplayName')=='Re$Burrow','target_version_or_brand_mismatch')
        entfile=f'apple/Configuration/{target}.entitlements';require(entfile in seen,'target_entitlements_manifest_missing')
        ent=plistlib.loads((root/entfile).read_bytes());require(ent.get('com.apple.security.application-groups')==[GROUP],'source_group_changed')
        require_push_grants(identifier,ent,ent)
    return {'source_sha':source,'version':'0.1.0','build':'2','approved_icon_sha256':review['approved_icon_sha256'],'exact_targets':7,'product_photos':0,'account_operations':0,'release_dispatched':False}

def source_payload_scope(snapshot,validated_bundles):
    """Pins the fresh strict-validated Mac archive before making a packaging copy."""
    expected={BASE+'.mac',BASE+'.mac.widgets'}
    require(len(validated_bundles)==2 and {r.get('bundle_id') for r in validated_bundles}==expected and all(r.get('signature_verified') is True and r.get('profile_verified') is True and r.get('certificate_sha256')==CERT_SHA and r.get('version')=='0.1.0' and str(r.get('build'))=='2' for r in validated_bundles),'mac_archive_validation_required')
    files={k:r.get('sha256') for k,r in snapshot.items() if r.get('kind')=='file'}
    directories=[k for k,r in snapshot.items() if r.get('kind')=='directory']
    executable={'Contents/MacOS/ResaleBurrowMac','Contents/PlugIns/ResaleBurrowMacWidgets.appex/Contents/MacOS/ResaleBurrowMacWidgets'}
    require(0<len(files)<=25000 and 0<len(directories)<=10000 and '.' in directories and executable.issubset(files),'mac_payload_shape_invalid')
    for path,row in snapshot.items():
        if path!='.':safe_relative(path)
        require(row.get('kind') in {'file','directory'} and isinstance(row.get('mode'),int) and 0<=row['mode']<=0o777,'mac_payload_member_invalid')
        if row['kind']=='file':require(re.fullmatch('[0-9a-f]{64}',row.get('sha256','')) and bool(row['mode']&0o111)==(path in executable),'mac_unexpected_executable_or_hash')
    return {'source_file_sha256':files,'source_directories':directories,'exact_executables':sorted(executable),'no_rebuild':True,'no_application_resign':True,'no_upload':True}
