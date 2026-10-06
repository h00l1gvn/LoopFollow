import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
import cached_upload as c

def workflow_text():
    # Preparation uses a flat reviewed bundle; CI stores workflow at repo root.
    candidates=(c.HERE/'resale-upload-cached.yml',c.HERE.parents[2]/'.github/workflows/resale-upload-cached.yml')
    for path in candidates:
        if path.is_file() and not path.is_symlink():return path.read_text()
    raise FileNotFoundError('Reviewed workflow absent from preparation and CI layouts')

class Response:
    status=200
    def __init__(self,raw):self.raw=raw
    def read(self,n):return self.raw[:n]
    def close(self):pass
class Opener:
    def __init__(self,values):self.values=list(values);self.calls=[]
    def open(self,request,timeout):
        self.calls.append(request)
        value=self.values.pop(0)
        if isinstance(value,Exception):raise value
        return Response(value)
class JsonHTTP:
    def __init__(self,values):self.values=values;self.calls=[]
    def json(self,url,**kwargs):
        self.calls.append((url,kwargs));value=self.values.get(url)
        if isinstance(value,Exception):raise value
        if value is None:raise AssertionError('unexpected request')
        return value
class FakeGitHub:
    def __init__(self,*,existing=None,marker_error=False,result_error=False):self.assets=list(existing or []);self.writes=[];self.marker_error=marker_error;self.result_error=result_error
    def collection(self,path):return copy.deepcopy(self.assets)
    def upload_marker_once(self,release,name,value):
        self.writes.append(name)
        if self.marker_error or (self.result_error and name.startswith('upload-result')):raise c.Invalid('write_outcome_unknown_no_retry')
        self.assets.append({'name':name});return {'asset_id':str(len(self.assets)),'name':name,'sha256':'a'*64,'bytes':20}
class FakeApple:
    def __init__(self,*,second_error=False):self.calls=0;self.second_error=second_error
    def precheck(self,family):
        self.calls+=1
        if self.calls==2 and self.second_error:raise c.Invalid('metadata_unavailable')
        return {'complete':True,'family':family}

def row(family='ios'):
    app=c.plan.APPS[family]
    return {'family':family,'asc_id':app['asc_id'],'bundle_id':app['bundle_id'],'version':'0.1.0','build':'1','distribution':'app-store','name':'ResaleBurrow-'+family+'-0.1.0-1'+app['suffix'],'asset_id':str(10+list(c.plan.APPS).index(family)),'bytes':12,'sha256':'a'*64,'export_ci':{'repository':c.TOOLING_REPO,'run_id':str(100+list(c.plan.APPS).index(family)),'head_sha':str(list(c.plan.APPS).index(family)+1)*40,'status':'completed','conclusion':'failure','event':'push'},'recovery':{'authenticated_recovery_verified':True,'archive_command_succeeded':True,'export_command_succeeded':True,'signed_local_validation_passed':True,'export_sha256':'a'*64,'recovery_receipt_sha256':'b'*64,'local_validation_receipt_sha256':'c'*64,'ci_failure_stage':'post_export_validation','validation_failure_resolved_locally':True}}
def manifest(families=('ios',)):
    return {'schema':'ResaleBurrow-signed-cache-2','complete':True,'repository':c.REPO,'source_sha':c.SOURCE,'approved_families':list(families),'exports':[row(f) for f in families]}
def validate(m,family='ios'):
    selected=next((r for r in m['exports'] if r['family']==family),row(family))
    return c.validate_cache_manifest(m,source=c.SOURCE,family=family,delivery=selected['export_ci']['head_sha'],run_id=selected['export_ci']['run_id'])
def tv_job_row():
    r=row('tvos');ci=r['export_ci']
    ci.update({'provenance_mode':c.TV_JOB_MODE,'run_attempt':1,'successful_job':{'id':'1234','run_id':ci['run_id'],'run_attempt':1,'head_sha':ci['head_sha'],'name':'export (tvos)','status':'completed','conclusion':'success'}})
    del r['recovery']['ci_failure_stage'];del r['recovery']['validation_failure_resolved_locally']
    return r
def tv_job_manifest():
    m=manifest(('tvos',));m['exports']=[tv_job_row()];return m
def actual_tv_run(r=None):
    ci=(r or tv_job_row())['export_ci']
    return {'id':int(ci['run_id']),**{k:ci[k] for k in ('head_sha','status','conclusion','event','run_attempt')}}
def actual_tv_job(r=None):
    job=copy.deepcopy((r or tv_job_row())['export_ci']['successful_job']);job['id']=int(job['id']);job['run_id']=int(job['run_id']);return job
def mac_component_row():
    r=row('macos');r['export_ci'].update({'run_id':c.MAC_COMPONENT_RUN['run_id'],'head_sha':c.MAC_COMPONENT_RUN['head_sha'],'run_attempt':1,'conclusion':'failure','name':c.MAC_PACKAGE_WORKFLOW_NAME,'workflow_path':c.MAC_PACKAGE_WORKFLOW_PATH})
    recovery=r['recovery']
    for key in ['archive_command_succeeded','export_command_succeeded','ci_failure_stage','validation_failure_resolved_locally']:del recovery[key]
    recovery.update({'packaging_method':c.MAC_PACKAGE_METHOD,'archive_origin':copy.deepcopy(c.MAC_ARCHIVE_ORIGIN),'signed_archive_input_validated':True,'package_command_succeeded':True,'substantive_archive_files_unchanged':True,'source_rebuilt':False,'application_resigned':False,'component_command_origin':copy.deepcopy(c.MAC_COMPONENT_COMMAND_ORIGIN),'component_command_receipt_sha256':c.MAC_COMPONENT_RECEIPT_SHA256,'archive_comparison_receipt_sha256':c.MAC_ARCHIVE_PROOF_SHA256,'archive_transport_metadata_exception':copy.deepcopy(c.MAC_ARCHIVE_METADATA_EXCEPTION),'ci_failure_stage':'installer_signature_status_wording','validation_failure_resolved_locally':True})
    return r
def mac_component_manifest():
    m=manifest(('macos',));m['exports']=[mac_component_row()];return m
class Tests(unittest.TestCase):
    def test_ios_subset_honest_failed_ci_local_pass(self):self.assertEqual(set(validate(manifest())),{'ios'})
    def test_distinct_three_family_delivery_runs(self):self.assertEqual(len(validate(manifest(tuple(c.plan.APPS)))),3)
    def test_not_approved_family_blocked(self):
        with self.assertRaisesRegex(c.Invalid,'approved_family'):validate(manifest(),'macos')
    def test_failure_requires_local_resolution(self):
        m=manifest();m['exports'][0]['recovery']['validation_failure_resolved_locally']=False
        with self.assertRaisesRegex(c.Invalid,'failed_export'):validate(m)
    def test_failure_before_export_blocked(self):
        m=manifest();m['exports'][0]['recovery']['export_command_succeeded']=False
        with self.assertRaisesRegex(c.Invalid,'authenticated_export'):validate(m)
    def test_wrong_delivery_pin_blocked(self):
        with self.assertRaisesRegex(c.Invalid,'selected_family'):c.validate_cache_manifest(manifest(),source=c.SOURCE,family='ios',delivery='f'*40,run_id='100')
    def test_unsigned_or_adhoc_cache_rejected(self):
        m=manifest();m['exports'][0]['distribution']='ad-hoc'
        with self.assertRaisesRegex(c.Invalid,'identity'):validate(m)
    def test_recovery_receipt_pin_required(self):
        m=manifest();m['exports'][0]['recovery']['recovery_receipt_sha256']=''
        with self.assertRaisesRegex(c.Invalid,'pinned_recovery'):validate(m)
    def test_duplicate_assets_blocked(self):
        m=manifest(('ios','tvos'));m['exports'][1]['asset_id']='10'
        with self.assertRaisesRegex(c.Invalid,'not_unique'):validate(m)
    def test_ci_exact_actual_conclusion_required(self):
        r=row();v={'id':r['export_ci']['run_id'],**r['export_ci']};v['conclusion']='success'
        with self.assertRaisesRegex(c.Invalid,'actual_family'):c.verify_export_run(v,r)
    def test_tv_successful_job_preserves_failed_whole_run(self):
        r=validate(tv_job_manifest(),'tvos')['tvos'];proof=c.verify_export_run(actual_tv_run(r),r,actual_tv_job(r))
        self.assertEqual(proof['conclusion'],'failure');self.assertEqual(proof['successful_job']['conclusion'],'success')
        self.assertNotIn('ci_failure_stage',r['recovery']);self.assertNotIn('validation_failure_resolved_locally',r['recovery'])
    def test_tv_mode_cannot_relax_another_family(self):
        m=manifest();m['exports'][0]['export_ci']=tv_job_row()['export_ci']
        with self.assertRaisesRegex(c.Invalid,'tv_successful_job_scope'):validate(m)
    def test_tv_mode_rejects_missing_or_wrong_job_pins(self):
        for key,value in [('id','bad'),('run_id','999'),('run_attempt',2),('head_sha','f'*40),('name','export (macos)'),('status','in_progress'),('conclusion','failure')]:
            with self.subTest(field=key):
                m=tv_job_manifest();m['exports'][0]['export_ci']['successful_job'][key]=value
                with self.assertRaisesRegex(c.Invalid,'tv_successful_job_pins'):validate(m,'tvos')
        m=tv_job_manifest();del m['exports'][0]['export_ci']['successful_job']
        with self.assertRaisesRegex(c.Invalid,'tv_successful_job_scope'):validate(m,'tvos')
    def test_tv_mode_rejects_misleading_family_failure_flags(self):
        for key,value in [('ci_failure_stage','post_export_validation'),('validation_failure_resolved_locally',True)]:
            with self.subTest(field=key):
                m=tv_job_manifest();m['exports'][0]['recovery'][key]=value
                with self.assertRaisesRegex(c.Invalid,'must_not_claim_family'):validate(m,'tvos')
    def test_tv_mode_retains_recovery_and_local_validation_gates(self):
        for key in ['authenticated_recovery_verified','archive_command_succeeded','export_command_succeeded','signed_local_validation_passed']:
            with self.subTest(field=key):
                m=tv_job_manifest();m['exports'][0]['recovery'][key]=False
                with self.assertRaisesRegex(c.Invalid,'authenticated_export'):validate(m,'tvos')
    def test_unknown_or_undeclared_job_mode_rejected(self):
        m=tv_job_manifest();m['exports'][0]['export_ci']['provenance_mode']='accept_any_job'
        with self.assertRaisesRegex(c.Invalid,'mode_unknown'):validate(m,'tvos')
        m=tv_job_manifest();del m['exports'][0]['export_ci']['provenance_mode']
        with self.assertRaisesRegex(c.Invalid,'undeclared_job'):validate(m,'tvos')
    def test_actual_tv_job_missing_or_mismatched_blocks(self):
        r=tv_job_row()
        with self.assertRaisesRegex(c.Invalid,'actual_tv'):c.verify_export_run(actual_tv_run(),r)
        for key,value in [('id',999),('run_id',999),('run_attempt',2),('head_sha','f'*40),('name','export (macos)'),('status','in_progress'),('conclusion','failure')]:
            with self.subTest(field=key):
                job=actual_tv_job();job[key]=value
                with self.assertRaisesRegex(c.Invalid,'actual_tv'):c.verify_export_run(actual_tv_run(),r,job)
    def test_actual_tv_run_attempt_and_real_conclusion_required(self):
        r=tv_job_row()
        for key,value in [('run_attempt',2),('conclusion','success'),('status','in_progress')]:
            with self.subTest(field=key):
                run=actual_tv_run();run[key]=value
                with self.assertRaises(c.Invalid):c.verify_export_run(run,r,actual_tv_job())
    def test_fresh_tv_job_get_exact_scope_and_default_ios_no_job_get(self):
        r=tv_job_row();base='https://api.github.com/repos/'+c.TOOLING_REPO+'/actions/'
        h=JsonHTTP({base+'runs/'+r['export_ci']['run_id']:actual_tv_run(),base+'jobs/1234':actual_tv_job()})
        proof=c.read_export_provenance(c.GitHub('TEST',h),r)
        self.assertEqual(proof['successful_job']['id'],1234);self.assertEqual(len(h.calls),2)
        r=row();run={'id':r['export_ci']['run_id'],**r['export_ci']};h=JsonHTTP({base+'runs/'+r['export_ci']['run_id']:run})
        self.assertEqual(c.read_export_provenance(c.GitHub('TEST',h),r)['conclusion'],'failure');self.assertEqual(len(h.calls),1)
    def test_unavailable_tv_job_metadata_stops(self):
        r=tv_job_row();base='https://api.github.com/repos/'+c.TOOLING_REPO+'/actions/'
        h=JsonHTTP({base+'runs/'+r['export_ci']['run_id']:actual_tv_run(),base+'jobs/1234':c.Invalid('metadata_unavailable')})
        with self.assertRaisesRegex(c.Invalid,'metadata_unavailable'):c.read_export_provenance(c.GitHub('TEST',h),r)
    def test_job_get_rejects_other_repo_queries_and_unrelated_paths(self):
        h=JsonHTTP({});g=c.GitHub('TEST',h)
        for path in ['/repos/other/repo/actions/jobs/1234','/repos/'+c.TOOLING_REPO+'/actions/jobs/1234?attempt=1','/repos/'+c.TOOLING_REPO+'/actions/jobs/1234/logs']:
            with self.subTest(path=path),self.assertRaisesRegex(c.Invalid,'outside_scope'):g.get(path)
        self.assertEqual(h.calls,[])
    def test_preserved_manifest_is_exact_single_root_pinned_history(self):
        self.assertEqual(c.PRESERVED_IOS_MANIFEST,{'asset_id':'615066957','name':'signed-export-cache-manifest-ios-0a0330c9077d.json','bytes':1495,'sha256':'0a0330c9077d35b56bdeeb87c03db2052603a0ff51dc4f3cf83b04eebf31551a'})
        m=tv_job_manifest();m['preserved_manifests']=[copy.deepcopy(c.PRESERVED_IOS_MANIFEST)];self.assertIn('tvos',validate(m,'tvos'))
        for key,value in [('asset_id','999'),('name','raw-profile.mobileprovision'),('bytes',1496),('sha256','f'*64)]:
            with self.subTest(field=key):
                changed=copy.deepcopy(m);changed['preserved_manifests'][0][key]=value
                with self.assertRaisesRegex(c.Invalid,'exact_history_scope'):validate(changed,'tvos')
        m['preserved_manifests']*=2
        with self.assertRaisesRegex(c.Invalid,'exact_history_scope'):validate(m,'tvos')
    def test_history_metadata_required_and_never_upload_input(self):
        rows=validate(tv_job_manifest(),'tvos');prior=c.PRESERVED_IOS_MANIFEST
        assets=[{'id':'9','name':c.MANIFEST_NAME,'size':42,'state':'uploaded'},{'id':'12','name':row('tvos')['name'],'size':12,'state':'uploaded'},{'id':prior['asset_id'],'name':prior['name'],'size':prior['bytes'],'state':'uploaded'}]
        c.verify_assets(assets,'9',42,rows,[prior])
        with self.assertRaisesRegex(c.Invalid,'unexpected_private'):c.verify_assets(assets,'9',42,rows)
        assets[-1]['size']=1496
        with self.assertRaisesRegex(c.Invalid,'exact_private'):c.verify_assets(assets,'9',42,rows,[prior])
    def test_history_fresh_bytes_and_hash_readback(self):
        raw=b'SYNTHETIC historical manifest';fixture={**c.PRESERVED_IOS_MANIFEST,'bytes':len(raw),'sha256':c.sha(raw)}
        class HistoryGitHub:
            def __init__(self):self.calls=[]
            def download_asset(self,*args):self.calls.append(args);return raw
        github=HistoryGitHub()
        with patch.object(c,'PRESERVED_IOS_MANIFEST',fixture):
            proof=c.read_preserved_manifests(github,[fixture]);self.assertFalse(proof[0]['upload_input']);self.assertTrue(proof[0]['hash_readback_verified'])
            self.assertEqual(github.calls,[(fixture['asset_id'],fixture['sha256'],fixture['bytes'])])
        wrong={**fixture,'sha256':'f'*64}
        with patch.object(c,'PRESERVED_IOS_MANIFEST',wrong),self.assertRaisesRegex(c.Invalid,'hash_readback_failed'):c.read_preserved_manifests(github,[wrong])
    def test_two_history_manifests_exact_order_and_pins(self):
        self.assertEqual(c.PRESERVED_TV_MANIFEST,{'asset_id':'615123112','name':'signed-export-cache-manifest-tvos-3a89887c4f7e.json','bytes':3299,'sha256':'3a89887c4f7e8f3728276fa4933afcf51a23661efea75a1447c264042e5dbfc9'})
        expected=[copy.deepcopy(c.PRESERVED_IOS_MANIFEST),copy.deepcopy(c.PRESERVED_TV_MANIFEST)]
        m=tv_job_manifest();m['preserved_manifests']=expected;self.assertIn('tvos',validate(m,'tvos'))
        for invalid in [[c.PRESERVED_TV_MANIFEST],list(reversed(expected)),expected+[expected[-1]]]:
            with self.subTest(value=invalid),self.assertRaisesRegex(c.Invalid,'exact_history_scope'):c.validate_preserved_manifests(invalid)
        for key,value in [('asset_id','999'),('name','signed-export-cache-manifest-other.json'),('bytes',3300),('sha256','f'*64)]:
            with self.subTest(field=key):
                invalid=copy.deepcopy(expected);invalid[1][key]=value
                with self.assertRaisesRegex(c.Invalid,'exact_history_scope'):c.validate_preserved_manifests(invalid)
    def test_two_history_manifests_need_native_metadata(self):
        rows=validate(tv_job_manifest(),'tvos');history=[c.PRESERVED_IOS_MANIFEST,c.PRESERVED_TV_MANIFEST]
        assets=[{'id':'9','name':c.MANIFEST_NAME,'size':42,'state':'uploaded'},{'id':'12','name':row('tvos')['name'],'size':12,'state':'uploaded'}]+[{'id':v['asset_id'],'name':v['name'],'size':v['bytes'],'state':'uploaded'} for v in history]
        c.verify_assets(assets,'9',42,rows,history)
        with self.assertRaisesRegex(c.Invalid,'exact_private'):c.verify_assets(assets[:-1],'9',42,rows,history)
        assets[-1]['state']='new'
        with self.assertRaisesRegex(c.Invalid,'exact_private'):c.verify_assets(assets,'9',42,rows,history)
    def test_two_history_manifests_each_fresh_hash_never_selected(self):
        iosraw=b'SYNTHETIC historical ios';tvraw=b'SYNTHETIC historical tv'
        ios={**c.PRESERVED_IOS_MANIFEST,'bytes':len(iosraw),'sha256':c.sha(iosraw)};tv={**c.PRESERVED_TV_MANIFEST,'bytes':len(tvraw),'sha256':c.sha(tvraw)}
        class HistoryGitHub:
            def __init__(self,alter_tv=False):self.calls=[];self.alter_tv=alter_tv
            def download_asset(self,*args):
                self.calls.append(args)
                return iosraw if args[0]==ios['asset_id'] else (b'altered' if self.alter_tv else tvraw)
        with patch.object(c,'PRESERVED_IOS_MANIFEST',ios),patch.object(c,'PRESERVED_TV_MANIFEST',tv):
            github=HistoryGitHub();proof=c.read_preserved_manifests(github,[ios,tv])
            self.assertEqual(len(github.calls),2);self.assertTrue(all(v['hash_readback_verified'] and not v['upload_input'] for v in proof))
            with self.assertRaisesRegex(c.Invalid,'hash_readback_failed'):c.read_preserved_manifests(HistoryGitHub(True),[ios,tv])
    def test_mac_component_truthfully_separates_archive_and_packaging(self):
        r=validate(mac_component_manifest(),'macos')['macos'];ci=r['export_ci']
        run={'id':ci['run_id'],'head_sha':ci['head_sha'],'status':ci['status'],'conclusion':ci['conclusion'],'event':ci['event'],'name':ci['name'],'path':ci['workflow_path'],'run_attempt':ci['run_attempt']}
        proof=c.verify_export_run(run,r)
        self.assertEqual(proof['packaging_method'],'productbuild_component');self.assertFalse(proof['current_run_archive_or_exportArchive_claimed']);self.assertTrue(proof['archive_and_command_origins_are_root_reviewed_attestations']);self.assertEqual(proof['conclusion'],'failure')
    def test_mac_component_does_not_relax_other_families(self):
        for family in ('ios','tvos'):
            with self.subTest(family=family):
                m=manifest((family,));m['exports'][0]['recovery']=mac_component_row()['recovery'];m['exports'][0]['export_ci'].update({'conclusion':'success','name':c.MAC_PACKAGE_WORKFLOW_NAME,'workflow_path':c.MAC_PACKAGE_WORKFLOW_PATH})
                with self.assertRaisesRegex(c.Invalid,'mac_component_exact_actual'):validate(m,family)
    def test_mac_component_requires_exact_failed_package_workflow(self):
        for key,value in [('conclusion','success'),('run_id','999'),('head_sha','f'*40),('run_attempt',2),('name','Another workflow'),('workflow_path','.github/workflows/other.yml')]:
            with self.subTest(field=key):
                m=mac_component_manifest();m['exports'][0]['export_ci'][key]=value
                with self.assertRaisesRegex(c.Invalid,'mac_component_exact_actual'):validate(m,'macos')
    def test_mac_component_requires_exact_original_archive_pins(self):
        for key,value in [('repository','other/repo'),('run_id','999'),('job_id','999'),('head_sha','f'*40),('archive_sha256','f'*64),('archive_command_succeeded',False)]:
            with self.subTest(field=key):
                m=mac_component_manifest();m['exports'][0]['recovery']['archive_origin'][key]=value
                with self.assertRaisesRegex(c.Invalid,'verified_archive_and_package'):validate(m,'macos')
    def test_mac_component_requires_current_validation_package_and_unchanged_input(self):
        for key,value in [('signed_archive_input_validated',False),('package_command_succeeded',False),('substantive_archive_files_unchanged',False),('source_rebuilt',True),('application_resigned',True)]:
            with self.subTest(field=key):
                m=mac_component_manifest();m['exports'][0]['recovery'][key]=value
                with self.assertRaisesRegex(c.Invalid,'verified_archive_and_package'):validate(m,'macos')
    def test_mac_component_cannot_claim_current_archive_or_exportArchive(self):
        for key,value in [('archive_command_succeeded',True),('export_command_succeeded',True)]:
            with self.subTest(field=key):
                m=mac_component_manifest();m['exports'][0]['recovery'][key]=value
                with self.assertRaisesRegex(c.Invalid,'must_not_claim_current'):validate(m,'macos')
    def test_mac_component_requires_authenticated_exact_command_receipt(self):
        for key,value in [('component_command_origin',{}),('component_command_receipt_sha256',''),('component_command_receipt_sha256','not-a-sha'),('component_command_receipt_sha256','d'*64)]:
            with self.subTest(field=key):
                m=mac_component_manifest();m['exports'][0]['recovery'][key]=value
                with self.assertRaisesRegex(c.Invalid,'authenticated_command'):validate(m,'macos')
        for key,value in [('run_id','999'),('job_id','999'),('head_sha','f'*40),('command','xcodebuild -exportArchive'),('exit_code',1)]:
            with self.subTest(origin_field=key):
                m=mac_component_manifest();m['exports'][0]['recovery']['component_command_origin'][key]=value
                with self.assertRaisesRegex(c.Invalid,'authenticated_command'):validate(m,'macos')
    def test_mac_component_requires_exact_wording_failure_resolved_locally(self):
        for key,value in [('ci_failure_stage','package_command_failed'),('validation_failure_resolved_locally',False)]:
            with self.subTest(field=key):
                m=mac_component_manifest();m['exports'][0]['recovery'][key]=value
                with self.assertRaisesRegex(c.Invalid,'exact_validation_resolution'):validate(m,'macos')
    def test_mac_component_requires_exact_substantive_archive_receipt(self):
        for key,value in [('archive_comparison_receipt_sha256','f'*64),('archive_transport_metadata_exception',{}),('archive_unchanged_by_packaging',True)]:
            with self.subTest(field=key):
                m=mac_component_manifest();m['exports'][0]['recovery'][key]=value
                with self.assertRaisesRegex(c.Invalid,'substantive_archive_proof'):validate(m,'macos')
    def test_mac_component_metadata_exception_cannot_cover_signed_payload(self):
        for key,value in [('relative_path','ResaleBurrow.xcarchive/Products/Applications/app.app/binary'),('sha256','f'*64),('bytes',173),('magic','wrong'),('version','wrong'),('outside_signed_app_and_widget_payload',False),('literal_tar_member_equality_claimed',True),('entry_descriptors',[])]:
            with self.subTest(field=key):
                m=mac_component_manifest();m['exports'][0]['recovery']['archive_transport_metadata_exception'][key]=value
                with self.assertRaisesRegex(c.Invalid,'substantive_archive_proof'):validate(m,'macos')
    def test_mac_component_retains_hash_and_local_validation_gates(self):
        for key,value in [('authenticated_recovery_verified',False),('signed_local_validation_passed',False),('export_sha256','f'*64),('local_validation_receipt_sha256','')]:
            with self.subTest(field=key):
                m=mac_component_manifest();m['exports'][0]['recovery'][key]=value
                with self.assertRaises(c.Invalid):validate(m,'macos')
    def test_unknown_packaging_method_blocked(self):
        m=mac_component_manifest();m['exports'][0]['recovery']['packaging_method']='unknown'
        with self.assertRaisesRegex(c.Invalid,'method_unknown'):validate(m,'macos')
    def test_actual_mac_package_run_must_keep_failure_and_exact_workflow(self):
        r=mac_component_row();ci=r['export_ci'];run={'id':ci['run_id'],'head_sha':ci['head_sha'],'status':ci['status'],'conclusion':ci['conclusion'],'event':ci['event'],'name':ci['name'],'path':ci['workflow_path'],'run_attempt':ci['run_attempt']}
        for key,value in [('name','Another workflow'),('path','.github/workflows/other.yml'),('conclusion','success'),('head_sha','f'*40),('run_attempt',2)]:
            with self.subTest(field=key):
                changed={**run,key:value}
                with self.assertRaises(c.Invalid):c.verify_export_run(changed,r)
    def test_fresh_mac_package_provenance_get_without_job_bypass(self):
        r=mac_component_row();ci=r['export_ci'];run={'id':ci['run_id'],'head_sha':ci['head_sha'],'status':ci['status'],'conclusion':ci['conclusion'],'event':ci['event'],'name':ci['name'],'path':ci['workflow_path'],'run_attempt':ci['run_attempt']}
        h=JsonHTTP({'https://api.github.com/repos/'+c.TOOLING_REPO+'/actions/runs/'+ci['run_id']:run})
        self.assertEqual(c.read_export_provenance(c.GitHub('TEST',h),r)['packaging_method'],c.MAC_PACKAGE_METHOD);self.assertEqual(len(h.calls),1)
    def test_private_cache_no_archive_profile_log(self):
        rows=validate(manifest());assets=[{'id':'9','name':c.MANIFEST_NAME,'size':42,'state':'uploaded'},{'id':'10','name':row()['name'],'size':12,'state':'uploaded'},{'id':'20','name':'raw-profile.mobileprovision','size':30,'state':'uploaded'}]
        with self.assertRaisesRegex(c.Invalid,'unexpected_private'):c.verify_assets(assets,'9',42,rows)
    def test_private_cache_exact_assets(self):
        rows=validate(manifest());assets=[{'id':'9','name':c.MANIFEST_NAME,'size':42,'state':'uploaded'},{'id':'10','name':row()['name'],'size':12,'state':'uploaded'}]
        c.verify_assets(assets,'9',42,rows)
    def test_github_unrelated_get_blocked(self):
        h=JsonHTTP({});g=c.GitHub('TEST',h)
        with self.assertRaisesRegex(c.Invalid,'outside_scope'):g.get('/repos/'+c.REPO+'/contents/secret')
        self.assertEqual(h.calls,[])
    def test_canonical_release_must_be_unique_private(self):
        base='https://api.github.com/repos/'+c.REPO
        h=JsonHTTP({base:{'full_name':c.REPO,'private':True},base+'/releases?per_page=100&page=1':[{'tag_name':c.TAG,'id':1},{'tag_name':c.TAG,'id':2}]})
        with self.assertRaisesRegex(c.Invalid,'not_unique'):c.GitHub('TEST',h).verify_private_release('1')
    def test_public_repo_rejected(self):
        base='https://api.github.com/repos/'+c.REPO;h=JsonHTTP({base:{'full_name':c.REPO,'private':False}})
        with self.assertRaisesRegex(c.Invalid,'private_repository'):c.GitHub('TEST',h).verify_private_release('1')
    def test_github_asset_redirect_strips_auth(self):
        url='https://api.github.com/repos/'+c.REPO+'/releases/assets/10';redirect=HTTPError(url,302,'',{'Location':'https://release-assets.githubusercontent.com/a?signature=test'},None)
        opener=Opener([redirect,b'PACKAGE']);raw=c.HTTP(opener).request(url,token='TEST',redirect_asset=True)
        self.assertEqual(raw,b'PACKAGE');self.assertEqual(opener.calls[0].get_header('Authorization'),'Bearer TEST');self.assertIsNone(opener.calls[1].get_header('Authorization'))
    def test_asset_external_redirect_blocked(self):
        url='https://api.github.com/repos/'+c.REPO+'/releases/assets/10';opener=Opener([HTTPError(url,302,'',{'Location':'https://evil.invalid/a'},None)])
        with self.assertRaisesRegex(c.Invalid,'outside_github'):c.HTTP(opener).request(url,token='TEST',redirect_asset=True)
        self.assertEqual(len(opener.calls),1)
    def test_asset_hash_mismatch_blocks(self):
        g=c.GitHub('TEST',c.HTTP(Opener([b'FAKE'])))
        with self.assertRaisesRegex(c.Invalid,'hash_mismatch'):g.download_asset('10','a'*64,4)
    def test_asset_size_bound_blocks(self):
        g=c.GitHub('TEST',c.HTTP(Opener([b'TOO LONG'])))
        with self.assertRaisesRegex(c.Invalid,'exceeds_bound'):g.download_asset('10','a'*64,4)
    def test_apple_query_unrelated_fields_blocks(self):
        h=JsonHTTP({});a=c.Apple('TEST',h)
        with self.assertRaisesRegex(c.Invalid,'query_outside'):a.get('/v1/apps/6819601040/builds?filter[version]=1')
        self.assertEqual(h.calls,[])
    def test_apple_unowned_build_blocks(self):
        with self.assertRaisesRegex(c.Invalid,'outside_owned'):c.Apple('TEST',JsonHTTP({})).get('/v1/builds/another/preReleaseVersion')
    def test_apple_pagination_external_blocks(self):
        p='/v1/apps/6819601040/builds?limit=200';h=JsonHTTP({'https://api.appstoreconnect.apple.com'+p:{'data':[],'links':{'next':'https://evil.invalid/v1/apps/6819601040/builds?limit=200'}}})
        with self.assertRaisesRegex(c.Invalid,'origin_changed'):c.Apple('TEST',h).collection(p)
    def apple_with(self,builds=[],uploads=[]):
        app=c.plan.APPS['ios'];base='https://api.appstoreconnect.apple.com/v1/apps/'+app['asc_id']
        values={base:{'data':{'id':app['asc_id'],'type':'apps','attributes':{'bundleId':app['bundle_id']}}},base+'/builds?limit=200':{'data':builds,'links':{}},base+'/buildUploads?limit=200':{'data':uploads,'links':{}}}
        for r in builds:values['https://api.appstoreconnect.apple.com/v1/builds/'+r['id']+'/preReleaseVersion']={'data':{'type':'preReleaseVersions','attributes':{'version':'0.1.0','platform':'IOS'}}}
        return c.Apple('TEST',JsonHTTP(values))
    def test_actual_empty_apple_precheck_passes(self):self.assertTrue(self.apple_with().precheck('ios')['complete'])
    def test_existing_exact_build_blocks(self):
        with self.assertRaisesRegex(c.plan.Invalid,'already_exists'):self.apple_with(builds=[{'id':'build1','type':'builds','attributes':{'version':'1'}}]).precheck('ios')
    def test_inflight_exact_upload_blocks(self):
        u={'id':'upload1','type':'buildUploads','attributes':{'cfBundleVersion':'1','cfBundleShortVersionString':'0.1.0','platform':'IOS','state':{'state':'PROCESSING'}}}
        with self.assertRaisesRegex(c.plan.Invalid,'already_exists'):self.apple_with(uploads=[u]).precheck('ios')
    def test_unresolved_upload_unknown_blocks(self):
        with self.assertRaisesRegex(c.Invalid,'coordinates_unknown'):self.apple_with(uploads=[{'id':'upload1','type':'buildUploads','attributes':{}}]).precheck('ios')
    def stage(self,g=None,a=None,u=None,execute=True):
        g=g or FakeGitHub();a=a or FakeApple();calls=[]
        def upload(r,w):calls.append(r);return (u(r,w) if u else {'status':'transport_reported_success','uploaded':True,'processing_verified':False,'installed':False})
        with tempfile.TemporaryDirectory() as d:
            result=c.execute_batch_stage(g,a,row(),'1',Path(d),uploader=upload,source=c.SOURCE,delivery='1'*40,execute=execute)
        return result,g,a,calls
    def test_readonly_preflight_does_not_write_or_upload(self):
        r,g,a,calls=self.stage(execute=False);self.assertEqual(r['upload_attempts'],0);self.assertEqual(g.writes,[]);self.assertEqual(calls,[])
    def test_one_upload_two_fresh_prechecks_durable_result(self):
        r,g,a,calls=self.stage();self.assertEqual(a.calls,2);self.assertEqual(len(calls),1);self.assertEqual(len(g.writes),2);self.assertEqual(r['upload_attempts'],1)
    def test_existing_intent_blocks_before_apple_or_uploader(self):
        g=FakeGitHub(existing=[{'name':'upload-intent-ios-0.1.0-1.json'}]);a=FakeApple()
        with self.assertRaisesRegex(c.Invalid,'durable_prior'):self.stage(g,a)
        self.assertEqual(a.calls,0);self.assertEqual(g.writes,[])
    def test_uncertain_reservation_never_uploads(self):
        g=FakeGitHub(marker_error=True);a=FakeApple();calls=[]
        with tempfile.TemporaryDirectory() as d,self.assertRaisesRegex(c.Invalid,'write_outcome_unknown'):c.execute_batch_stage(g,a,row(),'1',Path(d),uploader=lambda *x:calls.append(x),source=c.SOURCE,delivery='1'*40,execute=True)
        self.assertEqual(calls,[]);self.assertEqual(a.calls,1)
    def test_second_precheck_failure_stays_durable_unknown_no_upload(self):
        g=FakeGitHub();a=FakeApple(second_error=True);calls=[]
        with tempfile.TemporaryDirectory() as d,self.assertRaisesRegex(c.Invalid,'not_proven'):c.execute_batch_stage(g,a,row(),'1',Path(d),uploader=lambda *x:calls.append(x),source=c.SOURCE,delivery='1'*40,execute=True)
        self.assertEqual(calls,[]);self.assertEqual(len(g.writes),2)
    def test_failed_transport_no_retry_intent_blocks_later_run(self):
        g=FakeGitHub();calls=[]
        def fail(*args):calls.append(1);raise TimeoutError()
        with self.assertRaisesRegex(c.Invalid,'not_proven'):self.stage(g,u=fail)
        self.assertEqual(len(calls),1)
        with self.assertRaisesRegex(c.Invalid,'durable_prior'):self.stage(g)
    def test_success_result_write_unknown_blocks_rerun(self):
        g=FakeGitHub(result_error=True)
        with self.assertRaisesRegex(c.Invalid,'write_outcome_unknown'):self.stage(g)
        with self.assertRaisesRegex(c.Invalid,'durable_prior'):self.stage(g)
    def test_ci_owner_gate_before_git_or_credentials(self):
        with self.assertRaisesRegex(c.Invalid,'owner_ci'):c.ci_gate({'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':c.TOOLING_REPO,'GITHUB_ACTOR':'another'},Path('/tmp'))
    def test_push_registration_cannot_reach_executor(self):
        with self.assertRaisesRegex(c.Invalid,'owner_ci'):
            c.ci_gate({'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'push','GITHUB_REPOSITORY':c.TOOLING_REPO,'GITHUB_ACTOR':'h00l1gvn'},Path('/tmp'))
        s=workflow_text()
        self.assertIn('branches: [codex/resale-burrow-cached-upload]',s)
        self.assertIn('paths: [.github/workflows/resale-upload-cached.yml]',s)
        self.assertEqual(sum(line.startswith('    if:') for line in s.splitlines()),1)
        self.assertIn("    if: github.event_name == 'workflow_dispatch' && github.repository == 'h00l1gvn/LoopFollow' && github.actor == 'h00l1gvn'",s)
    def test_marker_scope_wrong_app_and_file_blocked(self):
        g=c.GitHub('TEST',JsonHTTP({}))
        for name in ['raw-key.json','upload-intent-other-0.1.0-1.json','upload-result-ios-0.2.0-1.json']:
            with self.assertRaisesRegex(c.Invalid,'outside_scope'):g.upload_marker_once('1',name,{})
    def test_fastfile_no_build_sign_or_groups(self):
        s=(c.HERE/'UploadFastfile').read_text();self.assertEqual(s.count('upload_to_testflight('),1)
        for forbidden in ['build_app(', 'match(', 'deliver(', 'pilot(', 'groups:', 'changelog:']:self.assertNotIn(forbidden,s)
    def test_workflow_default_off_concurrency_and_encrypted_only(self):
        s=workflow_text();self.assertIn('default: false',s);self.assertIn('cancel-in-progress: false',s);self.assertIn('resale-burrow-upload-${{ inputs.family }}-0.1.0-1',s)
        self.assertNotIn('xcodebuild',s);self.assertNotIn('MATCH_PASSWORD',s);self.assertNotIn('native-source',s);self.assertIn('path: ${{ runner.temp }}/resale-upload-encrypted/',s)

if __name__=='__main__':unittest.main()
