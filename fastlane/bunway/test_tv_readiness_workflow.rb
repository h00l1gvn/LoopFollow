require 'minitest/autorun'
require 'yaml'
require 'json'
require 'open3'
require 'tmpdir'

class BunwayTVReadinessWorkflowTests < Minitest::Test
  ROOT = File.expand_path('../..',__dir__).freeze
  PATH = File.join(ROOT,'.github/workflows/build_Bunway.yml').freeze
  def workflow; YAML.load_file(PATH); end
  def steps; workflow.fetch('jobs').fetch('readiness').fetch('steps'); end
  def step(id); steps.find { |entry| entry['id']==id }; end

  def test_dispatch_only_exact_repository_ref_and_shared_signing_lock
    assert_equal ['workflow_dispatch','push'],workflow.fetch('on').keys
    assert_equal false,workflow.fetch('on').fetch('workflow_dispatch').fetch('inputs').fetch('readiness_only').fetch('default')
    assert_equal false,workflow.fetch('on').fetch('workflow_dispatch').fetch('inputs').fetch('enable_cloudkit').fetch('default')
    assert_equal "github.repository == 'h00l1gvn/LoopFollow' && github.ref == 'refs/heads/bunway-release' && github.event_name == 'workflow_dispatch' && inputs.readiness_only == true",workflow.fetch('jobs').fetch('readiness').fetch('if')
    assert_includes workflow.fetch('jobs').fetch('build').fetch('if'),'inputs.readiness_only != true'
    assert_equal({'contents'=>'read'},workflow['permissions'])
    assert_equal({'group'=>'bunway-store-delivery','cancel-in-progress'=>false},workflow['concurrency'])
    refute_includes workflow.fetch('jobs').fetch('readiness').to_json,'BUNWAY_CAPABILITIES_READY'
    refute_includes workflow.fetch('jobs').fetch('readiness').to_json,'capabilities_ready'
    refute_includes workflow.fetch('jobs').fetch('readiness').to_json,'source_sha'
  end

  def test_only_existing_readiness_lane_and_secret_values_never_interpolated
    run=step('probe')['run']
    assert_includes run,'bundle exec fastlane tvos check_BunwayTVReadiness'
    assert_includes run,'umask 077'
    assert_includes run,"> \"$RUNNER_TEMP/bunway-tv-readiness.log\" 2>&1"
    refute_match(/\b(?:cat|tail|tee)\b/,run)
    refute_match(/build_Bunway|release_Bunway|upload_to_testflight|generate_project|devicectl|simctl/,workflow.fetch('jobs').fetch('readiness').to_json)
    assert_equal "${{ inputs.enable_cloudkit && 'true' || 'false' }}",step('probe')['env']['BUNWAY_TV_ENABLE_CLOUDKIT']
    steps.each { |entry| refute_includes entry['run'].to_s,'${{ secrets.' }
    checkout=steps.find { |entry| entry['uses'].to_s.start_with?('actions/checkout@') }
    assert_equal false,checkout['with']['persist-credentials']
  end

  def test_failed_logs_only_encrypted_after_attempt_and_raw_logs_always_removed
    encryption=step('encrypt_diagnostics')
    assert_equal "failure() && steps.probe.outcome == 'failure'",encryption['if']
    assert_includes encryption['run'],'artifact_crypto.cjs encrypt'
    artifact=steps.find { |entry| entry['uses'].to_s.start_with?('actions/upload-artifact@') }
    assert_equal "failure() && steps.encrypt_diagnostics.outputs.preserved == 'true'",artifact['if']
    assert_equal 'BunwayTV-readiness.diagnostics.tar.gz.enc',artifact['with']['path']
    assert_equal 7,artifact['with']['retention-days']
    assert_equal 'error',artifact['with']['if-no-files-found']
    assert_equal 'always()',steps.last['if']
    ['readiness.log','readiness-proof.json','readiness-diagnostics.tar.gz','.enc'].each { |name| assert_includes steps.last['run'],name }
    assert_operator steps.index(encryption),:<,steps.index(artifact)
  end

  def test_lane_is_bounded_and_refreshes_only_tv_after_capability_helper
    source=File.read(File.join(ROOT,'fastlane/Fastfile'))
    lane=source.split('lane :check_BunwayTVReadiness do',2).last.split('desc "Build and sign Bunway for Apple TV"',2).first
    assert_includes lane,'BunwayTVReadiness.run('
    assert_includes lane,'bundle_ids: Spaceship::ConnectAPI::BundleId, team: TEAMID'
    assert_includes lane,'identifier = BunwayTVReadiness::IDENTIFIER'
    assert_includes lane,'platform: "tvos", readonly: false, force: true'
    assert_includes lane,'app_identifier: [identifier]'
    assert_includes lane,'team_id: TEAMID'
    refute_match(/gym\(|upload_to_testflight|BUNWAY_CAPABILITIES_READY|associate_cloud|BundleId\.create/,lane)
  end

  def test_public_success_summary_requires_complete_boolean_proof
    script=step('probe')['run'].split("python3 - <<'PY'\n",2).last.split("\nPY",2).first
    proof={'cloudkit_capability_verified'=>true,'profile_refreshed'=>true,'production_profile_verified'=>true,'exact_container_permission_verified'=>true,'capability_changed'=>false,'container_association_changed'=>false,'archive_or_upload_performed'=>false}
    Dir.mktmpdir('bunway-tv-proof-test-') do |directory|
      path=File.join(directory,'proof.json'); summary=File.join(directory,'summary')
      File.write(path,JSON.generate(proof))
      env={'BUNWAY_TV_READINESS_PROOF'=>path,'GITHUB_STEP_SUMMARY'=>summary}
      output,error,status=Open3.capture3(env,'python3','-c',script)
      assert status.success?,error
      assert_empty output; assert_empty error
      assert_includes File.read(summary),'No container association, archive, upload or device installation was performed.'
      proof['production_profile_verified']=false; File.write(path,JSON.generate(proof)); File.delete(summary)
      output,error,status=Open3.capture3(env,'python3','-c',script)
      refute status.success?
      assert_empty output
      assert_match(/proof was incomplete/,error)
      refute File.exist?(summary)
    end
  end
end
