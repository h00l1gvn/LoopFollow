#!/usr/bin/env python3
"""Reviewed distinct one-attempt Mac upload; never retries or changes the old journal."""
from __future__ import annotations
import argparse, datetime, json, os, pathlib, re, subprocess
import validate_corrected_mac as v

UPLOAD_SCOPE_SHA='05caed543c7d864f73812dd8d81ad4b0f9cd3759857f0c5a386bcf577d7945bb'
RESOLUTION_SHA='e7cfd61def06179f64597028eacdbff252125b3750deaf4b41682a9e527e2d66'
VALIDATION_HELPER_SHA='4fdc2cf0160cc8d9c171f41e0cfcc9d99ca6783ff52e72576c87b0d29942b3b7'
BRANCH='codex/resale-burrow-mac-upload-readable'
Stop=v.Stop
need=v.need
sha=v.sha
save=v.save
stamp=v.stamp

def owner_gate(env):
    need(env.get('GITHUB_ACTIONS')=='true' and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and
         env.get('GITHUB_REPOSITORY')=='h00l1gvn/LoopFollow' and env.get('GITHUB_ACTOR')=='h00l1gvn' and
         env.get('GITHUB_REF')=='refs/heads/'+BRANCH and re.fullmatch(r'[0-9a-f]{40}',env.get('GITHUB_SHA','')) and
         re.fullmatch(r'[1-9][0-9]*',env.get('GITHUB_RUN_ID','')) and env.get('GITHUB_RUN_ATTEMPT')=='1' and
         env.get('APPROVED_PACKAGE_SHA256')=='e6a898b69bbced5bc355b1d41eb93e9c3997d417558095ddc05405862ce46f9f',
         'owner_corrected_upload_dispatch_required')

def command(package,keyid,issuer):
    argv=v.command(package,keyid,issuer)
    argv[2]='--upload-app'
    return argv

def help_gate(raw):
    text=raw.decode('utf8',errors='replace')
    need(all(flag in text for flag in ['--upload-app','--apiKey','--apiIssuer','--output-format']) and
         ('macos' in text.lower() or 'osx' in text.lower()), 'current_altool_upload_syntax_unavailable')

def single_upload(package,work,env,run):
    """Exactly one transport invocation; key material removed even on unknown outcome."""
    keyid=env['FASTLANE_KEY_ID'];issuer=env['FASTLANE_ISSUER_ID'];argv=command(package,keyid,issuer)
    keys=work/'ephemeral-private-keys';keys.mkdir(mode=0o700);keypath=keys/('AuthKey_'+keyid+'.p8')
    previous=env.get('API_PRIVATE_KEYS_DIR')
    try:
        keypath.write_text(env['FASTLANE_KEY'].replace('\\n','\n').strip()+'\n');keypath.chmod(0o600)
        env['API_PRIVATE_KEYS_DIR']=str(keys)
        try:
            result=run(argv,'single-Apple-upload',timeout=1200)
            return ('transport_tool_reported_success' if result.returncode==0 else 'upload_rejected_stop_no_retry',result.returncode)
        except (subprocess.TimeoutExpired,OSError):return 'upload_outcome_unknown_stop_no_retry',None
    finally:
        keypath.unlink(missing_ok=True);keys.rmdir()
        if previous is None:env.pop('API_PRIVATE_KEYS_DIR',None)
        else:env['API_PRIVATE_KEYS_DIR']=previous

def base_assets(scope,upload):
    return {
        scope['package_name']:upload['package_asset_id'],
        scope['manifest_name']:upload['manifest_asset_id'],
        v.INTENT:upload['validation_intent_asset_id'],
        v.RESULT:upload['validation_result_asset_id'],
    }

def release_check(row,scope,upload,initial=True):
    need(row.get('id')==upload['private_release_id'] and row.get('tag_name')==scope['new_private_release_tag'] and
         row.get('draft') is True and row.get('prerelease') is True and row.get('target_commitish')==scope['source_sha'],
         'corrected_private_release_identity_mismatch')
    rows=row.get('assets');need(isinstance(rows,list),'corrected_private_asset_list_unknown')
    names=[a.get('name') for a in rows];need(len(names)==len(set(names)),'duplicate_private_asset_names')
    expected=base_assets(scope,upload)
    for name,aid in expected.items():
        need(sum(a.get('name')==name and a.get('id')==aid and a.get('state')=='uploaded' for a in rows)==1,
             'exact_corrected_asset_identity_mismatch')
    new_names={upload[k] for k in ['resolution_name','intent_name','result_name']}
    if initial:
        need(not new_names.intersection(names),'prior_corrected_upload_marker_stop_no_retry')
        need(set(names)==set(expected),'unexpected_corrected_release_assets')
    else:
        need(set(names)<=set(expected)|new_names,'unexpected_corrected_release_assets')

def validation_check(result,intent,scope,upload):
    need(result.get('schema')=='ResaleBurrow-validation-only-result-1' and
         result.get('status')=='validation_tool_reported_success' and result.get('returncode')==0 and
         result.get('source_sha')==scope['source_sha'] and result.get('package_sha256')==scope['package_sha256'] and
         result.get('package_run_id')==scope['package_run_id'] and result.get('validation_ci_run')==str(upload['validation_run_id']) and
         result.get('intent')=={'id':upload['validation_intent_asset_id'],'sha256':upload['validation_intent_sha256']} and
         result.get('validation_attempts')==1 and result.get('strict_bundle_count')==2 and
         result.get('installer_chain_verified') is True and result.get('Apple_upload_action') is False and
         result.get('old_upload_journals_untouched') is True and result.get('no_rebuild_resign_install') is True,
         'actual_successful_validation_binding_required')
    stored=result.get('stored_payload',{})
    need(stored.get('stored_directories')==13 and stored.get('stored_regular_files')==15 and
         all(stored.get(k) is True for k in ['world_read_traverse_verified','root_ownership_verified',
             'group_other_write_absent','signed_file_hashes_match','bom_cpio_exact_modes_and_owners_agree']),
         'actual_validation_stored_payload_incomplete')
    need(intent.get('schema')=='ResaleBurrow-validation-only-intent-1' and
         intent.get('operation_key')==scope['operation_key']+'-Apple-validation-only' and
         intent.get('package_sha256')==scope['package_sha256'] and intent.get('package_run_id')==scope['package_run_id'] and
         intent.get('validation_ci_run')==str(upload['validation_run_id']) and intent.get('action')=='altool_validate_app_only' and
         intent.get('Apple_upload_action') is False and intent.get('fresh_collision',{}).get('complete') is True and
         intent.get('fresh_collision',{}).get('exact_records')==[], 'actual_validation_intent_binding_required')

def ci_check(ci,job,run_id,job_id,head,path,event,name):
    need(ci.get('id')==run_id and ci.get('head_sha')==head and ci.get('status')=='completed' and
         ci.get('conclusion')=='success' and ci.get('event')==event and ci.get('run_attempt')==1 and
         ci.get('actor',{}).get('login')=='h00l1gvn' and ci.get('path')==path and
         job.get('id')==job_id and job.get('run_id')==run_id and job.get('head_sha')==head and job.get('name')==name and
         job.get('status')=='completed' and job.get('conclusion')=='success' and job.get('run_attempt')==1,
         'exact_successful_CI_run_job_binding_required')

def resolution_check(value,scope,upload):
    expected={
        'schema':'ResaleBurrow-distinct-corrected-upload-resolution-1',
        'prior_upload_run_id':scope['old_upload_run_id'],'prior_package_sha256':scope['old_package_sha256'],
        'prior_journal_status':'unknown_stop_no_retry_preserved','new_package_sha256':scope['package_sha256'],
        'new_package_run_id':scope['package_run_id'],'new_package_head_sha':scope['package_head_sha'],
        'new_private_release_id':upload['private_release_id'],'new_validation_run_id':upload['validation_run_id'],
        'new_validation_result_asset_id':upload['validation_result_asset_id'],
        'new_validation_result_sha256':upload['validation_result_sha256'],'actual_validation_status':'validation_tool_reported_success',
        'stored_CPIO_BOM_and_signatures_revalidated':True,'source_rebuilt_or_app_resigned':False,
        'prior_unknown_journal_closed_or_overwritten':False,'absence_alone_used_as_retry_proof':False,
        'fresh_exact_collision_GET_required_before_new_upload':True,'new_operation_key':upload['operation_key'],
        'root_review_and_explicit_dispatch_required':True,
    }
    need(all(value.get(k)==x for k,x in expected.items()) and
         value.get('actual_Apple_error',{}).get('http')==409 and value.get('actual_Apple_error',{}).get('code')==-19241 and
         value.get('actual_Apple_error',{}).get('evidence_sha256')==upload['old_rejection_evidence_sha256'],
         'distinct_reviewed_resolution_required_old_journal_not_closed')

class GitHub(v.GitHub):
    def __init__(self,scope,upload):super().__init__(scope,upload['private_release_id']);self.upload=upload
    def api(self,path,binary=False):
        additional={f'repos/{self.scope["tooling_repository"]}/actions/runs/{self.upload["validation_run_id"]}',
                    f'repos/{self.scope["tooling_repository"]}/actions/jobs/{self.upload["validation_job_id"]}'}
        if path not in additional:return super().api(path,binary)
        need(not binary,'CI_metadata_binary_forbidden')
        result=subprocess.run(['gh','api',path],capture_output=True,timeout=120)
        need(result.returncode==0,'actual_validation_CI_GET_failed');return json.loads(result.stdout)
    def upload_journal(self,path):
        need(path.name in {self.upload[k] for k in ['resolution_name','intent_name','result_name']},
             'new_corrected_upload_journal_name_forbidden')
        base='repos/'+self.scope['private_repository']
        row=self.api(base+'/releases/'+str(self.rid));release_check(row,self.scope,self.upload,False)
        need(not any(a['name']==path.name for a in row['assets']),'prior_corrected_upload_journal_stop_no_retry')
        result=subprocess.run(['gh','release','upload',self.scope['new_private_release_tag'],str(path),
                               '--repo',self.scope['private_repository']],capture_output=True,timeout=120)
        need(result.returncode==0,'corrected_upload_journal_write_unknown_stop_no_retry')
        row=self.api(base+'/releases/'+str(self.rid));release_check(row,self.scope,self.upload,False)
        matches=[a for a in row['assets'] if a['name']==path.name]
        need(len(matches)==1,'corrected_upload_journal_readback_unknown')
        raw=self.api(base+'/releases/assets/'+str(matches[0]['id']),binary=True)
        need(sha(raw)==sha(path.read_bytes()),'corrected_upload_journal_readback_mismatch')
        return {'id':matches[0]['id'],'sha256':sha(raw)}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--scope',type=pathlib.Path,required=True)
    parser.add_argument('--upload-scope',type=pathlib.Path,required=True);parser.add_argument('--resolution',type=pathlib.Path,required=True)
    parser.add_argument('--work-dir',type=pathlib.Path,required=True);a=parser.parse_args()
    owner_gate(os.environ)
    need(a.scope.parent.resolve()==a.upload_scope.parent.resolve()==a.resolution.parent.resolve(),'same_reviewed_tooling_directory_required')
    raw=a.scope.read_bytes();need(sha(raw)==v.SCOPE_SHA,'reviewed_package_scope_hash_mismatch');scope=json.loads(raw)
    raw=a.upload_scope.read_bytes();need(sha(raw)==UPLOAD_SCOPE_SHA,'reviewed_upload_scope_hash_mismatch');upload=json.loads(raw)
    resolution_raw=a.resolution.read_bytes();need(sha(resolution_raw)==RESOLUTION_SHA,'reviewed_resolution_hash_mismatch')
    resolution_check(json.loads(resolution_raw),scope,upload)
    for name,expected in [('validate_corrected_mac.py',VALIDATION_HELPER_SHA),('validate_resale_export.py',scope['strict_validator_sha256']),
                          ('mac_payload_permissions.py',scope['permission_helper_sha256']),
                          ('permission-repair-scope.json','2895adf5ff55cd0ea58864169cf15af06be2138955d0e3c1bf19a868362768fb')]:
        need(sha((a.scope.parent/name).read_bytes())==expected,'reviewed_upload_dependency_hash_mismatch')
    need(subprocess.check_output(['git','rev-parse','HEAD']).decode().strip()==os.environ['GITHUB_SHA'],'upload_checkout_head_mismatch')
    work=a.work_dir.resolve();need(work.is_relative_to(pathlib.Path(os.environ['RUNNER_TEMP']).resolve()) and not work.exists(),'private_work_destination_required')
    work.mkdir(mode=0o700)
    def run(args,label,timeout=120):
        result=subprocess.run([str(x) for x in args],capture_output=True,timeout=timeout)
        for part,contents in [('stdout',result.stdout),('stderr',result.stderr)]:
            path=work/(label+'-'+part+'.bin');path.write_bytes(contents);path.chmod(0o600)
        save(work/(label+'-exit.json'),{'returncode':result.returncode,'observed_at':stamp()});return result
    xcode=run(['/usr/bin/xcodebuild','-version'],'xcode');need(xcode.returncode==0 and re.search(r'^Xcode 26\.2$',xcode.stdout.decode(),re.M),'current_Xcode26_2_required')
    help=run(['/usr/bin/xcrun','altool','--help'],'current-altool-help');need(help.returncode==0,'current_altool_help_failed');help_gate(help.stdout+help.stderr)
    client=GitHub(scope,upload);base='repos/'+scope['private_repository'];need(client.api(base)['private'] is True,'private_cache_repository_required')
    release=client.api(base+'/releases/'+str(upload['private_release_id']));release_check(release,scope,upload)
    def asset(aid,name,digest,size):
        meta=client.api(base+'/releases/assets/'+str(aid));need(meta['id']==aid and meta['name']==name and meta['state']=='uploaded' and meta['size']==size and any(x['id']==aid for x in release['assets']),'exact_corrected_asset_metadata_mismatch')
        raw=client.api(base+'/releases/assets/'+str(aid),binary=True);need(len(raw)==size and sha(raw)==digest,'exact_corrected_asset_hash_mismatch');return raw
    manifest=json.loads(asset(upload['manifest_asset_id'],scope['manifest_name'],upload['manifest_sha256'],upload['manifest_bytes']))
    v.manifest_check(manifest,scope,upload['private_release_id'],upload['package_asset_id'])
    package=work/scope['package_name'];package.write_bytes(asset(upload['package_asset_id'],scope['package_name'],scope['package_sha256'],scope['package_bytes']));package.chmod(0o600)
    result=json.loads(asset(upload['validation_result_asset_id'],v.RESULT,upload['validation_result_sha256'],upload['validation_result_bytes']))
    intent=json.loads(asset(upload['validation_intent_asset_id'],v.INTENT,upload['validation_intent_sha256'],upload['validation_intent_bytes']))
    validation_check(result,intent,scope,upload)
    def old_journals():
        for row in scope['old_journals']:
            raw=client.api(base+'/releases/assets/'+str(row['asset_id']),binary=True)
            need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'old_unknown_journal_changed')
    old_journals()
    for kind,event,name in [('package','push','package'),('validation','workflow_dispatch','validation')]:
        ci=client.api(f'repos/{scope["tooling_repository"]}/actions/runs/{upload[kind+"_run_id"]}')
        job=client.api(f'repos/{scope["tooling_repository"]}/actions/jobs/{upload[kind+"_job_id"]}')
        path=scope['package_workflow_path'] if kind=='package' else upload['validation_workflow_path']
        ci_check(ci,job,upload[kind+'_run_id'],upload[kind+'_job_id'],upload[kind+'_head_sha'],path,event,name)
    repair=json.loads((a.scope.parent/'permission-repair-scope.json').read_text())
    class BytesRunner:
        def run(self,args,label,timeout=120):
            result=run(args,label,timeout);need(result.returncode==0,'local_permission_command_failed');return result.stdout
    stored=v.permissions.check_package(package,repair['permission_repair'],BytesRunner(),work)
    strict_runner=v.strict.Runner(work/'strict-private');installed=strict_runner.package(package,work/'expanded-private')
    apps=list((work/'expanded-private').rglob('*.app'));need(len(apps)==1,'exact_export_primary_required')
    bundles=v.strict.bundle_set(apps[0],v.strict.scope_check(repair,'macos'),strict_runner,datetime.datetime.now(datetime.timezone.utc))
    need(len(bundles)==2,'exact_Mac2_bundles_required')
    fresh=v.fresh_collision(v.ASC(v.apple_token(os.environ)));save(work/'fresh-Apple-outcome.json',fresh)
    # The new resolution does not change or close the old upload result.
    path=work/upload['resolution_name'];path.write_bytes(resolution_raw);path.chmod(0o600);resolution_journal=client.upload_journal(path)
    intent={'schema':'ResaleBurrow-distinct-corrected-upload-intent-1','operation_key':upload['operation_key'],
            'reserved_at':stamp(),'package_sha256':scope['package_sha256'],'source_sha':scope['source_sha'],
            'package_run_id':scope['package_run_id'],'successful_validation_run_id':upload['validation_run_id'],
            'upload_ci_run':os.environ['GITHUB_RUN_ID'],'fresh_collision':fresh,'resolution':resolution_journal,
            'action':'altool_upload_app_once','prior_unknown_journal_unchanged':True,'outcome':'unknown_until_result'}
    save(work/upload['intent_name'],intent);intent_journal=client.upload_journal(work/upload['intent_name'])
    status,exitcode=single_upload(package,work,os.environ,run)
    need(sha(package.read_bytes())==scope['package_sha256'],'package_changed_during_upload');old_journals()
    record={'schema':'ResaleBurrow-distinct-corrected-upload-result-1','recorded_at':stamp(),'status':status,'returncode':exitcode,
            'operation_key':upload['operation_key'],'package_sha256':scope['package_sha256'],'source_sha':scope['source_sha'],
            'package_run_id':scope['package_run_id'],'successful_validation_run_id':upload['validation_run_id'],
            'upload_ci_run':os.environ['GITHUB_RUN_ID'],'intent':intent_journal,'resolution':resolution_journal,
            'stored_payload':stored,'strict_bundle_count':len(bundles),'installer_chain_verified':installed['installer_chain_trust_verified'],
            'upload_attempts':1,'old_upload_journals_untouched':True,'no_rebuild_resign_install':True,
            'processing_group_assignment_installation_not_claimed':True}
    save(work/upload['result_name'],record);client.upload_journal(work/upload['result_name'])
    need(status=='transport_tool_reported_success','upload_did_not_report_success_stop_no_retry')
    print('Exact corrected Mac upload tool completed once; processing and installation are not yet verified.')

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(str(error) if isinstance(error,Stop) else 'corrected_upload_stopped_private_diagnostics_required');raise SystemExit(2)
