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
    return c.validate_cache_manifest(m,source=c.SOURCE,family=family,delivery=row(family)['export_ci']['head_sha'],run_id=row(family)['export_ci']['run_id'])
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
    def test_marker_scope_wrong_app_and_file_blocked(self):
        g=c.GitHub('TEST',JsonHTTP({}))
        for name in ['raw-key.json','upload-intent-other-0.1.0-1.json','upload-result-ios-0.2.0-1.json']:
            with self.assertRaisesRegex(c.Invalid,'outside_scope'):g.upload_marker_once('1',name,{})
    def test_fastfile_no_build_sign_or_groups(self):
        s=(c.HERE/'UploadFastfile').read_text();self.assertEqual(s.count('upload_to_testflight('),1)
        for forbidden in ['build_app(', 'match(', 'deliver(', 'pilot(', 'groups:', 'changelog:']:self.assertNotIn(forbidden,s)
    def test_workflow_default_off_concurrency_and_encrypted_only(self):
        s=(c.HERE/'resale-upload-cached.yml').read_text();self.assertIn('default: false',s);self.assertIn('cancel-in-progress: false',s);self.assertIn('resale-burrow-upload-${{ inputs.family }}-0.1.0-1',s)
        self.assertNotIn('xcodebuild',s);self.assertNotIn('MATCH_PASSWORD',s);self.assertNotIn('native-source',s);self.assertIn('path: ${{ runner.temp }}/resale-upload-encrypted/',s)

if __name__=='__main__':unittest.main()
