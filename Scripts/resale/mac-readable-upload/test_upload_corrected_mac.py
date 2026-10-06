import copy,json,pathlib,subprocess,tempfile,types,unittest
from unittest.mock import patch
import upload_corrected_mac as u

ROOT=pathlib.Path(__file__).parent
class Guards(unittest.TestCase):
    def setUp(self):
        self.scope=json.loads((ROOT/'corrected-package-scope.json').read_text())
        self.upload=json.loads((ROOT/'upload-scope.json').read_text())
    def release(self):
        return {'id':self.upload['private_release_id'],'tag_name':self.scope['new_private_release_tag'],
                'target_commitish':self.scope['source_sha'],'draft':True,'prerelease':True,
                'assets':[{'name':k,'id':v,'state':'uploaded'} for k,v in u.base_assets(self.scope,self.upload).items()]}
    def records(self):
        result={'schema':'ResaleBurrow-validation-only-result-1','status':'validation_tool_reported_success','returncode':0,
          'source_sha':self.scope['source_sha'],'package_sha256':self.scope['package_sha256'],'package_run_id':self.scope['package_run_id'],
          'validation_ci_run':str(self.upload['validation_run_id']),
          'intent':{'id':self.upload['validation_intent_asset_id'],'sha256':self.upload['validation_intent_sha256']},
          'validation_attempts':1,'strict_bundle_count':2,'installer_chain_verified':True,'Apple_upload_action':False,
          'old_upload_journals_untouched':True,'no_rebuild_resign_install':True,
          'stored_payload':{'stored_directories':13,'stored_regular_files':15,'world_read_traverse_verified':True,
            'root_ownership_verified':True,'group_other_write_absent':True,'signed_file_hashes_match':True,'bom_cpio_exact_modes_and_owners_agree':True}}
        intent={'schema':'ResaleBurrow-validation-only-intent-1','operation_key':self.scope['operation_key']+'-Apple-validation-only',
          'package_sha256':self.scope['package_sha256'],'package_run_id':self.scope['package_run_id'],
          'validation_ci_run':str(self.upload['validation_run_id']),'action':'altool_validate_app_only','Apple_upload_action':False,
          'fresh_collision':{'complete':True,'exact_records':[]}}
        return result,intent
    def test_exact_new_release_and_assets(self):u.release_check(self.release(),self.scope,self.upload)
    def test_old_release_id_or_tag_or_source_stops(self):
        for key,value in [('id',404532466),('tag_name','resale-burrow-0.1.0-build-1-signed-cache'),('target_commitish','0'*40),('draft',False)]:
            bad=self.release();bad[key]=value
            with self.subTest(key=key),self.assertRaises(u.Stop):u.release_check(bad,self.scope,self.upload)
    def test_any_new_resolution_intent_result_prior_marker_stops(self):
        for key in ['resolution_name','intent_name','result_name']:
            bad=self.release();bad['assets'].append({'name':self.upload[key],'id':8,'state':'uploaded'})
            with self.subTest(key=key),self.assertRaises(u.Stop):u.release_check(bad,self.scope,self.upload)
    def test_duplicate_name_or_changed_asset_id_stops(self):
        for mode in ['duplicate','wrongid','unuploaded','unrelated']:
            bad=self.release()
            if mode=='duplicate':bad['assets'].append(copy.deepcopy(bad['assets'][0]))
            elif mode=='wrongid':bad['assets'][0]['id']+=1
            elif mode=='unuploaded':bad['assets'][0]['state']='new'
            else:bad['assets'].append({'name':'unrelated','id':8,'state':'uploaded'})
            with self.subTest(mode=mode),self.assertRaises(u.Stop):u.release_check(bad,self.scope,self.upload)
    def test_successful_validation_binding(self):u.validation_check(*self.records(),self.scope,self.upload)
    def test_validation_failure_unknown_or_different_bytes_run_id_stops(self):
        for key,value in [('status','validation_outcome_unknown_stop_no_retry'),('returncode',1),('package_sha256',self.scope['old_package_sha256']),
                          ('validation_ci_run','37494502249'),('validation_attempts',2),('Apple_upload_action',True),('installer_chain_verified',False)]:
            result,intent=self.records();result[key]=value
            with self.subTest(key=key),self.assertRaises(u.Stop):u.validation_check(result,intent,self.scope,self.upload)
    def test_wrong_validation_intent_or_incomplete_payload_stops(self):
        for change in ['asset','digest','scope','permission','collision']:
            result,intent=self.records()
            if change=='asset':result['intent']['id']+=1
            elif change=='digest':result['intent']['sha256']='0'*64
            elif change=='scope':intent['package_run_id']+=1
            elif change=='permission':result['stored_payload']['world_read_traverse_verified']=False
            else:intent['fresh_collision']['exact_records']=[{'kind':'buildUpload','id':'existing'}]
            with self.subTest(change=change),self.assertRaises(u.Stop):u.validation_check(result,intent,self.scope,self.upload)
    def test_exact_ci_identity(self):
        ci={'id':3,'head_sha':'a'*40,'status':'completed','conclusion':'success','event':'workflow_dispatch','run_attempt':1,'actor':{'login':'h00l1gvn'},'path':'exact.yml'}
        job={'id':4,'run_id':3,'head_sha':'a'*40,'name':'validation','status':'completed','conclusion':'success','run_attempt':1}
        u.ci_check(ci,job,3,4,'a'*40,'exact.yml','workflow_dispatch','validation')
        for target,key,value in [('ci','id',9),('ci','head_sha','b'*40),('ci','path','other.yml'),('ci','run_attempt',2),('job','id',5),('job','name','package'),('job','conclusion','failure')]:
            c,j=copy.deepcopy(ci),copy.deepcopy(job);(c if target=='ci' else j)[key]=value
            with self.subTest(target=target,key=key),self.assertRaises(u.Stop):u.ci_check(c,j,3,4,'a'*40,'exact.yml','workflow_dispatch','validation')
    def test_distinct_resolution_does_not_close_old_journal(self):
        value=json.loads((ROOT/'reviewed-upload-resolution.json').read_text());u.resolution_check(value,self.scope,self.upload)
        for key,new in [('prior_unknown_journal_closed_or_overwritten',True),('new_package_sha256',self.scope['old_package_sha256']),('absence_alone_used_as_retry_proof',True),('new_validation_run_id',9)]:
            bad=copy.deepcopy(value);bad[key]=new
            with self.subTest(key=key),self.assertRaises(u.Stop):u.resolution_check(bad,self.scope,self.upload)
    def test_owner_manual_dispatch_gate(self):
        env={'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':'h00l1gvn/LoopFollow',
             'GITHUB_ACTOR':'h00l1gvn','GITHUB_REF':'refs/heads/'+u.BRANCH,'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'123',
             'GITHUB_RUN_ATTEMPT':'1','APPROVED_PACKAGE_SHA256':self.scope['package_sha256']}
        u.owner_gate(env)
        for key,value in [('GITHUB_EVENT_NAME','push'),('GITHUB_ACTOR','other'),('GITHUB_REF','refs/heads/main'),('GITHUB_RUN_ID','bad'),
                          ('GITHUB_RUN_ATTEMPT','2'),('APPROVED_PACKAGE_SHA256',self.scope['old_package_sha256'])]:
            bad=dict(env);bad[key]=value
            with self.subTest(key=key),self.assertRaises(u.Stop):u.owner_gate(bad)
    def test_command_upload_only_existing_ids_no_auto_retry(self):
        argv=u.command('/exact.pkg','ABCDE12345','01234567-89ab-cdef-0123-456789abcdef')
        self.assertEqual(argv[:3],['/usr/bin/xcrun','altool','--upload-app']);self.assertEqual(argv[3:7],['-f','/exact.pkg','-t','macos'])
        self.assertNotIn('--validate-app',argv);self.assertNotIn('--notarize-app',argv)
        with self.assertRaises(u.Stop):u.command('/pkg','x --other','01234567-89ab-cdef-0123-456789abcdef')
    def test_current_help_not_assumed_from_old_Xcode(self):
        u.help_gate(b'--upload-app --apiKey --apiIssuer --output-format macos')
        with self.assertRaises(u.Stop):u.help_gate(b'--validate-app --apiKey --apiIssuer --output-format macos')
    def test_network_routes_and_old_journal_write_rejected_before_subprocess(self):
        client=u.GitHub(self.scope,self.upload)
        with patch('subprocess.run',side_effect=AssertionError('network')):
            for path in ['repos/other/project/releases/1','repos/h00l1gvn/LoopFollow/actions/runs/1','repos/h00l1gvn/resale-burrow-native/releases/404532466']:
                with self.subTest(path=path),self.assertRaises(u.Stop):client.api(path)
            for name in ['upload-intent-macos-0.1.0-1.json','upload-result-macos-0.1.0-1.json',u.v.INTENT,u.v.RESULT]:
                with self.subTest(name=name),self.assertRaises(u.Stop):client.upload_journal(pathlib.Path(name))
    def test_single_transport_key_cleanup_success_failure_unknown(self):
        for outcome in [0,1,'timeout','error']:
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory() as tmp:
                work=pathlib.Path(tmp);env={'FASTLANE_KEY_ID':'ABCDE12345','FASTLANE_ISSUER_ID':'01234567-89ab-cdef-0123-456789abcdef',
                                          'FASTLANE_KEY':'fixture-not-real-key','API_PRIVATE_KEYS_DIR':'prior-private-dir'};calls=[]
                def run(argv,label,timeout):
                    calls.append(argv);key=work/'ephemeral-private-keys/AuthKey_ABCDE12345.p8'
                    self.assertTrue(key.is_file());self.assertEqual(key.stat().st_mode&0o777,0o600)
                    self.assertEqual(env['API_PRIVATE_KEYS_DIR'],str(key.parent))
                    if outcome=='timeout':raise subprocess.TimeoutExpired(argv,timeout)
                    if outcome=='error':raise OSError('unknown')
                    return types.SimpleNamespace(returncode=outcome)
                status,code=u.single_upload('/exact.pkg',work,env,run)
                self.assertEqual(len(calls),1);self.assertFalse((work/'ephemeral-private-keys').exists());self.assertEqual(env['API_PRIVATE_KEYS_DIR'],'prior-private-dir')
                self.assertEqual(status,'transport_tool_reported_success' if outcome==0 else 'upload_rejected_stop_no_retry' if outcome==1 else 'upload_outcome_unknown_stop_no_retry')
    def test_journal_existing_marker_stops_without_upload_call(self):
        client=u.GitHub(self.scope,self.upload);row=self.release();row['assets'].append({'name':self.upload['intent_name'],'id':9,'state':'uploaded'})
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/self.upload['intent_name'];path.write_text('{}')
            with patch.object(client,'api',return_value=row),patch('subprocess.run',side_effect=AssertionError('no write')):
                with self.assertRaises(u.Stop):client.upload_journal(path)

if __name__=='__main__':unittest.main()
