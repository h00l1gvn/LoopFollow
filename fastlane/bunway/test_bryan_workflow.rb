require 'minitest/autorun'
require 'yaml'
require 'open3'
require 'tmpdir'
require 'fileutils'

class BunwayBryanWorkflowTests < Minitest::Test
  ROOT = File.expand_path('../..', __dir__).freeze
  PATH = File.join(ROOT, '.github/workflows/build_BunwayBryan.yml').freeze

  def workflow
    YAML.load_file(PATH)
  end

  def steps
    workflow.fetch('jobs').fetch('build').fetch('steps')
  end

  def test_release_ref_and_repository_are_exact_and_no_other_apps_run
    job = workflow.fetch('jobs').fetch('build')
    assert_equal "github.repository == 'h00l1gvn/LoopFollow' && github.ref == 'refs/heads/bunway-bryan-release'", job['if']
    assert_equal ['bunway-bryan-release'], workflow.fetch('on').fetch('push').fetch('branches')
    assert_equal({'contents' => 'read'}, workflow['permissions'])
    builds = steps.select { |step| step['run'].to_s.include?('bundle exec fastlane') }
    assert_equal 1, builds.length
    assert_includes builds.first['run'], 'bundle exec fastlane ios build_BunwayBryan'
    refute_match(/upload_to_testflight|release_Bunway|devicectl|simctl|build_BunwayTV/, File.read(PATH))
  end

  def test_only_exact_encrypted_artifact_is_uploaded_after_verify_and_encrypt
    artifacts = steps.select { |step| step['uses'].to_s.start_with?('actions/upload-artifact@') }
    assert_equal 2, artifacts.length
    assert_equal ['BunwayBryan.build.log.enc', 'BunwayBryan.ipa.enc'], artifacts.map { |step| step.fetch('with').fetch('path') }.sort
    artifacts.each { |step| assert_equal 7, step.fetch('with').fetch('retention-days') }
    artifact = artifacts.find { |step| step.fetch('with')['path'] == 'BunwayBryan.ipa.enc' }
    assert_equal 'BunwayBryan.ipa.enc', artifact.fetch('with').fetch('path')
    assert_equal 'error', artifact.fetch('with').fetch('if-no-files-found')
    refute artifact.key?('if'), 'Uploading on failure would bypass verification/encryption.'
    verification = steps.index { |step| step['run'].to_s.include?('verify_exported_ipa.rb BunwayBryan.ipa') }
    encryption = steps.index { |step| step['run'].to_s.include?('artifact_crypto.cjs encrypt BunwayBryan.ipa') }
    assert_operator verification, :<, encryption
    assert_operator encryption, :<, steps.index(artifact)
  end

  def test_immutable_main_source_gate_and_nonpersistent_checkout_credentials
    checkouts = steps.select { |step| step['uses'].to_s.start_with?('actions/checkout@') }
    assert_equal 2, checkouts.length
    checkouts.each { |step| assert_equal false, step.fetch('with').fetch('persist-credentials') }
    source = checkouts.find { |step| step.fetch('with')['repository'] == 'h00l1gvn/bunway-app' }
    assert_equal '${{ steps.selected.outputs.source_sha }}', source.fetch('with').fetch('ref')
    assert_equal 0, source.fetch('with').fetch('fetch-depth')
    gate = steps.find { |step| step['name'] == 'Require selected source to be merged into Bunway main' }
    assert_includes gate['run'], 'merge-base --is-ancestor "$SOURCE_SHA" refs/remotes/origin/main'
    assert_operator steps.index(gate), :<, steps.index { |step| step['run'].to_s.include?('bundle exec fastlane') }
  end

  def test_raw_build_output_and_cleanup_remain_private_even_on_failure
    build = steps.find { |step| step['run'].to_s.include?('bundle exec fastlane') }
    assert_includes build['run'], '> "$RUNNER_TEMP/bunway-bryan-build.log" 2>&1'
    refute_match(/\b(?:cat|tail|tee)\b/, build['run'])
    assert_includes build['run'], 'exit 1'
    cleanup = steps.last
    assert_equal 'always()', cleanup['if']
    assert_includes cleanup['run'], 'rm -f BunwayBryan.ipa "$RUNNER_TEMP/bunway-bryan-build.log"'
    assert_includes cleanup['run'], 'rm -rf buildlog-bunway-bryan'
  end

  def test_artifact_key_exists_only_in_preflight_and_encrypt_environment
    consumers = steps.select { |step| (step['env'] || {}).key?('BUNWAY_ARTIFACT_KEY') }
    assert_equal 3, consumers.length
    consumers.each { |step| assert_equal '${{ secrets.BUNWAY_ARTIFACT_KEY }}', step['env']['BUNWAY_ARTIFACT_KEY'] }
    steps.each do |step|
      next if step['id'] == 'selected'
      refute_includes step['run'].to_s, '${{ secrets.'
      refute_includes step['run'].to_s, '$BUNWAY_ARTIFACT_KEY'
    end
    assert_equal false, workflow.fetch('on').fetch('workflow_dispatch').fetch('inputs').fetch('capabilities_ready').fetch('default')
    assert_includes consumers.first['env']['CONFIRMED'], "github.event_name == 'workflow_dispatch' && inputs.capabilities_ready == true"
  end

  def test_failed_run_diagnostics_require_a_build_attempt_and_successful_encryption
    encryption = steps.find { |step| step['id'] == 'encrypt_diagnostics' }
    artifact = steps.find { |step| (step['with'] || {})['path'] == 'BunwayBryan.build.log.enc' }
    assert_equal "failure() && (steps.bryan_build.outcome == 'failure' || steps.bryan_build.outcome == 'success')", encryption['if']
    assert_includes encryption['run'], 'artifact_crypto.cjs encrypt "$RUNNER_TEMP/bunway-bryan-build.log" BunwayBryan.build.log.enc'
    assert_includes encryption['run'], 'echo "preserved=true" >> "$GITHUB_OUTPUT"'
    assert_equal "failure() && steps.encrypt_diagnostics.outputs.preserved == 'true'", artifact['if']
    assert_operator steps.index(encryption), :<, steps.index(artifact)
    assert_operator steps.index { |step| step['run'].to_s.include?('verify_exported_ipa.rb BunwayBryan.ipa') }, :<, steps.index(encryption)
  end

  def run_preflight(overrides = {})
    Dir.mktmpdir('bunway-preflight-test-') do |directory|
      output = File.join(directory, 'output')
      environment = {'CONFIRMED' => 'true', 'SOURCE_SHA' => 'A' * 40,
                     'BUNWAY_BRYAN_UDID' => '00000000-0000000000000000',
                     'BUNWAY_ARTIFACT_KEY' => '12' * 32, 'GITHUB_OUTPUT' => output}.merge(overrides)
      step = steps.find { |entry| entry['id'] == 'selected' }
      stdout, stderr, status = Open3.capture3(environment, '/bin/bash', '-c', step['run'])
      [stdout, stderr, status, File.exist?(output) ? File.read(output) : nil]
    end
  end

  def test_preflight_accepts_only_confirmed_full_sha_hardware_and_valid_key
    stdout, stderr, status, output = run_preflight
    assert status.success?, stderr
    assert_empty stdout
    assert_empty stderr
    assert_equal 'source_sha=' + 'a' * 40 + "\n", output
  end

  def test_preflight_rejects_missing_confirmation_bad_sha_device_or_key_without_leaks
    [{'CONFIRMED' => 'false'}, {'SOURCE_SHA' => 'main'}, {'SOURCE_SHA' => 'a' * 39},
     {'BUNWAY_BRYAN_UDID' => 'synthetic-core-device-uuid'}, {'BUNWAY_ARTIFACT_KEY' => 'not-private-key'}].each do |override|
      stdout, stderr, status, output = run_preflight(override)
      refute status.success?
      assert_nil output
      assert_empty stdout
      refute_includes stderr, '12' * 32
      refute_includes stderr, '00000000-0000000000000000'
      refute_includes stderr, 'not-private-key'
    end
  end

  def test_no_existing_push_workflow_is_triggered_by_bryan_branch
    Dir.glob(File.join(ROOT, '.github/workflows/*.{yml,yaml}')).each do |path|
      next if path == PATH
      document = YAML.load_file(path)
      events = document['on'] || document[true]
      next unless events.is_a?(Hash) && events.key?('push')
      push = events['push']
      refute_nil push, "#{File.basename(path)} would run on every push"
      branches = push['branches']
      refute_nil branches, "#{File.basename(path)} needs an explicit unrelated branch"
      branches.each do |branch|
        refute File.fnmatch?(branch, 'bunway-bryan-release'), "#{File.basename(path)} would run another app"
      end
    end
  end
end
