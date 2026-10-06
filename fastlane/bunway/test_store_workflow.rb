require 'minitest/autorun'
require 'yaml'
require 'open3'
require 'tmpdir'
require 'fileutils'
require 'json'

class BunwayStoreWorkflowTests < Minitest::Test
  ROOT = File.expand_path('../..', __dir__).freeze
  PATH = File.join(ROOT, '.github/workflows/build_Bunway.yml').freeze
  def workflow; YAML.load_file(PATH); end
  def steps; workflow.fetch('jobs').fetch('build').fetch('steps'); end
  def step(id); steps.find { |entry| entry['id'] == id }; end

  def test_exact_repository_ref_and_nonbypassable_readiness
    assert_equal "github.repository == 'h00l1gvn/LoopFollow' && github.ref == 'refs/heads/bunway-release' && (github.event_name == 'workflow_dispatch' || vars.BUNWAY_CAPABILITIES_READY == 'true') && inputs.readiness_only != true", workflow.fetch('jobs').fetch('build')['if']
    assert_equal ['bunway-release'], workflow.fetch('on').fetch('push').fetch('branches')
    assert_equal({'contents'=>'read'}, workflow['permissions'])
    assert_equal false, workflow.fetch('on').fetch('workflow_dispatch').fetch('inputs').fetch('capabilities_ready').fetch('default')
    assert_equal false, workflow.fetch('on').fetch('workflow_dispatch').fetch('inputs').fetch('readiness_only').fetch('default')
    assert_equal false, workflow.fetch('on').fetch('workflow_dispatch').fetch('inputs').fetch('enable_cloudkit').fetch('default')
    assert_equal "${{ (github.event_name == 'workflow_dispatch' && inputs.capabilities_ready == true) || (github.event_name == 'push' && vars.BUNWAY_CAPABILITIES_READY == 'true') }}", step('selected').fetch('env').fetch('CONFIRMED')
  end

  def test_matrix_and_lanes_include_only_phone_and_tv
    expression=workflow.fetch('jobs').fetch('build').fetch('strategy').fetch('matrix')
    matrices=expression.scan(/'(\{[^']+\})'/).flatten.map { |value| JSON.parse(value).fetch('include') }
    assert_equal 3, matrices.length
    matrix=matrices.last
    assert_equal [matrix.first], matrices[0]
    assert_equal [matrix.last], matrices[1]
    selection=workflow.fetch('on').fetch('workflow_dispatch').fetch('inputs').fetch('platform')
    assert_equal 'all', selection['default']
    assert_equal ['all','ios','tvos'],selection['options']
    assert_includes expression, "inputs.platform == 'ios'"
    assert_includes expression, "inputs.platform == 'tvos'"
    assert_equal [
      {'platform'=>'ios','lane'=>'BunwayPhone','ipa'=>'BunwayPhone.ipa','buildlog'=>'buildlog-bunway-phone','group_secret'=>'BUNWAY_PHONE_TESTFLIGHT_GROUP_ID'},
      {'platform'=>'tvos','lane'=>'BunwayTV','ipa'=>'BunwayTV.ipa','buildlog'=>'buildlog-bunway-tv','group_secret'=>'BUNWAY_TV_TESTFLIGHT_GROUP_ID'}
    ],matrix
    lanes=steps.select { |entry| entry['run'].to_s.include?('bundle exec fastlane') }
    assert_equal 2,lanes.length
    assert_includes lanes[0]['run'],'build_${{ matrix.lane }}'
    assert_includes lanes[1]['run'],'release_${{ matrix.lane }}'
    refute_match(/build_BunwayBryan|LoopFollow\.ipa|MooByte\.ipa|devicectl|simctl/,File.read(PATH))
  end

  def test_immutable_source_and_main_ancestry_precede_signing
    assert_equal "${{ github.event_name == 'workflow_dispatch' && inputs.source_sha || vars.BUNWAY_SOURCE_SHA }}",step('selected').fetch('env').fetch('SOURCE_SHA')
    checkouts=steps.select { |entry| entry['uses'].to_s.start_with?('actions/checkout@') }
    assert_equal 2,checkouts.length
    checkouts.each { |entry| assert_equal false,entry.fetch('with').fetch('persist-credentials') }
    source=checkouts.find { |entry| entry.fetch('with')['repository']=='h00l1gvn/bunway-app' }
    assert_equal '${{ steps.selected.outputs.source_sha }}',source.fetch('with').fetch('ref')
    assert_equal 0,source.fetch('with').fetch('fetch-depth')
    gate=steps.find { |entry| entry['name']=='Require selected source to be merged into Bunway main' }
    assert_includes gate['run'],'merge-base --is-ancestor "$SOURCE_SHA" refs/remotes/origin/main'
    assert_operator steps.index(gate),:<,steps.index(step('store_build'))
  end

  def test_artifacts_are_exact_encrypted_files_with_short_retention
    artifacts=steps.select { |entry| entry['uses'].to_s.start_with?('actions/upload-artifact@') }
    assert_equal 2,artifacts.length
    assert_equal ['${{ matrix.ipa }}.enc','${{ matrix.ipa }}.diagnostics.tar.gz.enc'],artifacts.map { |entry| entry.fetch('with').fetch('path') }
    artifacts.each do |entry|
      assert_equal 7,entry.fetch('with').fetch('retention-days')
      assert_equal 'error',entry.fetch('with').fetch('if-no-files-found')
      refute_match(/\*|\n|buildlog/,entry.fetch('with').fetch('path'))
    end
    refute artifacts.first.key?('if')
    encryption=steps.index { |entry| entry['name']=='Encrypt the exact Store package' }
    assert_operator encryption,:<,steps.index(artifacts.first)
    assert_operator steps.index(artifacts.first),:<,steps.index(step('store_upload'))
  end

  def test_raw_build_and_upload_output_are_private_and_cleaned_always
    {'store_build'=>'build','store_upload'=>'upload'}.each do |id,kind|
      assert_includes step(id)['run'],'umask 077'
      assert_includes step(id)['run'],"> \"$RUNNER_TEMP/bunway-${{ matrix.platform }}-#{kind}.log\" 2>&1"
      refute_match(/\b(?:cat|tail|tee)\b/,step(id)['run'])
      assert_includes step(id)['run'],'exit 1'
    end
    assert_equal 'always()',steps.last['if']
    ['${{ matrix.ipa }}','-build.log','-upload.log','-diagnostics.tar.gz','${{ matrix.buildlog }}'].each { |value| assert_includes steps.last['run'],value }
  end

  def test_failure_diagnostics_require_build_attempt_and_successful_encryption
    encryption=step('encrypt_diagnostics')
    artifact=steps.find { |entry| (entry['with']||{})['path']=='${{ matrix.ipa }}.diagnostics.tar.gz.enc' }
    assert_equal "failure() && (steps.store_build.outcome == 'failure' || steps.store_build.outcome == 'success')",encryption['if']
    assert_includes encryption['run'],'artifact_crypto.cjs encrypt "$RUNNER_TEMP/bunway-${{ matrix.platform }}-diagnostics.tar.gz" ${{ matrix.ipa }}.diagnostics.tar.gz.enc'
    assert_equal "failure() && steps.encrypt_diagnostics.outputs.preserved == 'true'",artifact['if']
    assert_operator steps.index(encryption),:<,steps.index(artifact)
  end

  def test_key_is_scoped_to_preflight_and_encryption_with_node24
    consumers=steps.select { |entry| (entry['env']||{}).key?('BUNWAY_ARTIFACT_KEY') }
    assert_equal 3,consumers.length
    consumers.each { |entry| assert_equal '${{ secrets.BUNWAY_ARTIFACT_KEY }}',entry['env']['BUNWAY_ARTIFACT_KEY'] }
    node=steps.find { |entry| entry['uses'].to_s.start_with?('actions/setup-node@') }
    assert_equal '24',node.fetch('with').fetch('node-version')
    assert_equal step('store_build')['env'],step('store_upload')['env'].reject { |name,_value| name.end_with?('TESTFLIGHT_GROUP_ID') }
    assert_equal '${{ secrets[matrix.group_secret] }}',step('selected')['env']['BUNWAY_TESTFLIGHT_GROUP_ID']
    ['BUNWAY_PHONE_TESTFLIGHT_GROUP_ID','BUNWAY_TV_TESTFLIGHT_GROUP_ID'].each do |name|
      assert_equal '${{ secrets.'+name+' }}',step('store_upload')['env'][name]
      refute step('store_build')['env'].key?(name)
    end
    steps.each do |entry|
      refute_includes entry['run'].to_s,'${{ secrets.'
      refute_includes entry['run'].to_s,'$BUNWAY_ARTIFACT_KEY'
    end
  end

  def selection(overrides={})
    Dir.mktmpdir('bunway-store-preflight-') do |directory|
      output=File.join(directory,'output')
      env={'CONFIRMED'=>'true','SOURCE_SHA'=>'A'*40,'BUNWAY_ARTIFACT_KEY'=>'12'*32,'BUNWAY_TESTFLIGHT_GROUP_ID'=>'11111111-2222-3333-4444-555555555555','GITHUB_OUTPUT'=>output}.merge(overrides)
      stdout,stderr,status=Open3.capture3(env,'/bin/bash','-c',step('selected')['run'])
      [stdout,stderr,status,File.exist?(output) ? File.read(output) : nil]
    end
  end

  def test_selection_accepts_full_sha_without_outputting_key
    stdout,stderr,status,output=selection
    assert status.success?,stderr
    assert_empty stdout; assert_empty stderr
    assert_equal 'source_sha='+'a'*40+"\n",output
  end

  def test_selection_rejects_unready_invalid_sha_and_key_without_leaks
    [{'CONFIRMED'=>'false'},{'SOURCE_SHA'=>'main'},{'SOURCE_SHA'=>'a'*39},{'BUNWAY_ARTIFACT_KEY'=>'synthetic-private-value'},{'BUNWAY_TESTFLIGHT_GROUP_ID'=>'missing-private-group'}].each do |override|
      stdout,stderr,status,output=selection(override)
      refute status.success?; assert_nil output; assert_empty stdout
      refute_includes stderr,'synthetic-private-value'; refute_includes stderr,'12'*32
      refute_includes stderr,'missing-private-group'
    end
  end

  def test_diagnostic_archive_selects_exact_logs_and_excludes_symlinks
    code=step('encrypt_diagnostics')['run'].split("python3 - <<'PY'\n",2).last.split("\nPY\n",2).first
    Dir.mktmpdir('bunway-store-diagnostics-') do |directory|
      temporary=File.join(directory,'temporary'); workspace=File.join(directory,'workspace')
      FileUtils.mkdir_p([temporary,File.join(workspace,'buildlog-bunway-phone')])
      File.write(File.join(temporary,'bunway-ios-build.log'),'synthetic private signing output')
      File.write(File.join(temporary,'bunway-ios-upload.log'),'synthetic transporter output')
      File.write(File.join(workspace,'buildlog-bunway-phone','compile.log'),'synthetic xcode output')
      outside=File.join(directory,'private-key.txt'); File.write(outside,'synthetic key excluded')
      File.symlink(outside,File.join(workspace,'buildlog-bunway-phone','key.log'))
      File.write(File.join(workspace,'buildlog-bunway-phone','profile.mobileprovision'),'excluded profile')
      env={'PLATFORM'=>'ios','BUILD_LOG_DIR'=>'buildlog-bunway-phone','RUNNER_TEMP'=>temporary,'GITHUB_WORKSPACE'=>workspace}
      stdout,stderr,status=Open3.capture3(env,'python3','-c',code)
      assert status.success?,stderr; assert_empty stdout; assert_empty stderr
      archive=File.join(temporary,'bunway-ios-diagnostics.tar.gz')
      list='import json,sys,tarfile; t=tarfile.open(sys.argv[1]); print(json.dumps(t.getnames()))'
      names,stderr,status=Open3.capture3('python3','-c',list,archive)
      assert status.success?,stderr
      assert_equal ['fastlane-build.log','fastlane-upload.log','xcode/compile.log'],JSON.parse(names)
      assert_equal 0o600,File.stat(archive).mode & 0o777
    end
  end

  def test_all_workflow_push_filters_exclude_nonrelease_preparation_ref
    Dir.glob(File.join(ROOT,'.github/workflows/*.{yml,yaml}')).each do |path|
      document=YAML.load_file(path); events=document['on']||document[true]
      next unless events.is_a?(Hash) && events.key?('push')
      push=events['push']; refute_nil push,"#{File.basename(path)} runs on every push"
      branches=push['branches']; refute_nil branches,"#{File.basename(path)} needs an explicit branch"
      branches.each { |branch| refute File.fnmatch?(branch,'codex/bunway-protected-delivery'),"#{File.basename(path)} matches preparation ref" }
      refute events.key?('workflow_run'),"#{File.basename(path)} chains a preparation workflow"
    end
  end
end
