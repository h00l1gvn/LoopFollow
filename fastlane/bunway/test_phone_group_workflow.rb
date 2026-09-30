require 'minitest/autorun'
require 'yaml'

class BunwayPhoneGroupWorkflowTests < Minitest::Test
  ROOT = File.expand_path('../..', __dir__)
  def setup
    @workflow = YAML.load_file(File.join(ROOT, '.github/workflows/repair_BunwayPhoneGroup.yml'))
    @job = @workflow.fetch('jobs').fetch('repair')
    @steps = @job.fetch('steps')
  end
  def test_exact_repository_branch_and_event_guards
    guard = @job.fetch('if')
    ['h00l1gvn/LoopFollow','refs/heads/bunway-phone-group-repair',"github.event_name == 'push'","github.event_name == 'workflow_dispatch'"].each { |part| assert_includes guard, part }
    assert_equal ['bunway-phone-group-repair'], @workflow.fetch('on').fetch('push').fetch('branches')
    assert_equal({'contents'=>'read'}, @workflow.fetch('permissions'))
    assert_equal false, @workflow.fetch('concurrency').fetch('cancel-in-progress')
  end
  def test_no_build_sign_source_checkout_upload_or_new_testers
    text = @steps.map { |step| step['run'].to_s }.join("\n")
    [/\bxcodebuild\b/, /\b(?:build|release)_Bunway/, /\bupload_to_testflight\b/, /\bmatch\s*\(/, /\bgym\s*\(/, /\bcreate_beta_group\b/, /\badd_beta_testers\b/].each { |pattern| refute_match pattern, text }
    checkouts = @steps.select { |step| step['uses'].to_s.start_with?('actions/checkout@') }
    assert_equal 1, checkouts.length
    assert_equal false, checkouts.first.fetch('with').fetch('persist-credentials')
    refute checkouts.first.fetch('with').key?('repository')
  end
  def test_api_credentials_exist_only_in_gated_repair_step
    credential_steps = @steps.select { |step| step.fetch('env', {}).key?('FASTLANE_KEY') }
    assert_equal 1, credential_steps.length
    assert_equal 'group_repair', credential_steps.first.fetch('id')
    refute @job.fetch('env', {}).key?('FASTLANE_KEY')
  end
  def test_exact_coordinates_and_existing_group_secret
    env = @steps.find { |step| step['id']=='group_repair' }.fetch('env')
    assert_equal '0.4.1', env.fetch('BUNWAY_GROUP_REPAIR_VERSION')
    assert_equal '7', env.fetch('BUNWAY_GROUP_REPAIR_BUILD')
    assert_equal '${{ secrets.BUNWAY_PHONE_TESTFLIGHT_GROUP_ID }}', env.fetch('BUNWAY_PHONE_TESTFLIGHT_GROUP_ID')
    assert_equal '${{ runner.temp }}/bunway-phone-group-repair-api.log', env.fetch('BUNWAY_GROUP_REPAIR_DIAGNOSTIC_PATH')
  end
  def test_fastlane_raw_output_is_redirected_and_public_output_is_fixed
    run = @steps.find { |step| step['id']=='group_repair' }.fetch('run')
    assert_includes run, 'umask 077'
    assert_includes run, '> "$RUNNER_TEMP/bunway-phone-group-repair-cli.log" 2>&1'
    refute_match(/\b(?:cat|tail|head|tee)\b/, run)
    assert_equal 1, run.scan('bundle exec fastlane').length
  end
  def test_only_one_exact_encrypted_artifact_is_uploaded
    uploads = @steps.select { |step| step['uses'].to_s.start_with?('actions/upload-artifact@') }
    assert_equal 1, uploads.length
    config = uploads.first.fetch('with')
    assert_equal 'BunwayPhoneGroup.diagnostics.tar.gz.enc', config.fetch('path')
    assert_equal 7, config.fetch('retention-days')
    assert_equal 'error', config.fetch('if-no-files-found')
    refute_match(/[\*\n]/, config.fetch('path'))
    assert_includes uploads.first.fetch('if'), 'always()'
  end
  def test_actual_api_diagnostics_preserved_on_success_and_failure
    step = @steps.find { |item| item['id']=='encrypt_diagnostics' }
    assert_includes step.fetch('if'), "steps.group_repair.outcome == 'success'"
    assert_includes step.fetch('if'), "steps.group_repair.outcome == 'failure'"
    assert_includes step.fetch('run'), 'artifact_crypto.cjs encrypt'
    assert_includes step.fetch('run'), 'bunway-phone-group-repair-api.log'
    assert_includes step.fetch('run'), 'bunway-phone-group-repair-cli.log'
    refute_includes step.fetch('run'), 'glob('
    assert_equal '${{ secrets.BUNWAY_ARTIFACT_KEY }}', step.fetch('env').fetch('BUNWAY_ARTIFACT_KEY')
  end
  def test_cleanup_removes_only_private_plaintext_after_upload
    cleanup = @steps.last
    assert_equal 'always()', cleanup.fetch('if')
    %w[api.log cli.log diagnostics.tar.gz].each { |suffix| assert_includes cleanup.fetch('run'), "bunway-phone-group-repair-#{suffix}" }
    assert_includes cleanup.fetch('run'), '$RUNNER_TEMP'
    refute_includes cleanup.fetch('run'), 'rm -rf'
  end
  def test_lane_only_authenticates_and_verifies_existing_group
    source = File.read(File.join(ROOT, 'fastlane/Fastfile'))
    lane = source.split('lane :repair_BunwayPhoneGroup do',2).last.split('desc "Upload Bunway',2).first
    assert_includes lane, 'app_store_connect_api_key('
    assert_includes lane, 'BunwayPhoneGroupRepair.run!('
    %w[upload_to_testflight latest_testflight_build_number match gym build_app create_beta_group add_beta_testers].each { |word| refute_includes lane, word }
    assert_includes lane, 'version == "0.4.1" && number == "7"'
  end
end
