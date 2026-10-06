require 'minitest/autorun'
require 'yaml'
require 'open3'
require 'tmpdir'
require_relative 'julien_devices'
require_relative 'verify_exported_ipa'

class BunwayJulienDeliveryTests < Minitest::Test
  ROOT = File.expand_path('../..', __dir__).freeze
  DOCUMENT = YAML.load_file(File.join(ROOT, '.github/workflows/build_Bunway.yml')).freeze
  DEVICES = {'iphone'=>'00000000-0000000000000001', 'ipad'=>'00000000-0000000000000002'}.freeze
  def job; DOCUMENT.fetch('jobs').fetch('direct'); end
  def steps; job.fetch('steps'); end
  def step(id); steps.find { |value| value['id'] == id }; end

  def test_direct_dispatch_is_exclusive_no_push_no_bryan_and_shared_lock
    assert_equal "github.repository == 'h00l1gvn/LoopFollow' && github.ref == 'refs/heads/bunway-release' && github.event_name == 'workflow_dispatch' && inputs.direct_only == true && inputs.readiness_only != true && inputs.platform == 'ios'", job['if']
    assert_equal 'bunway-store-delivery', DOCUMENT.fetch('concurrency').fetch('group')
    assert_equal false, DOCUMENT.fetch('concurrency').fetch('cancel-in-progress')
    assert_equal false, DOCUMENT.fetch('on').fetch('workflow_dispatch').fetch('inputs').fetch('direct_only').fetch('default')
    %w[build readiness].each do |name|
      assert_includes DOCUMENT.fetch('jobs').fetch(name)['if'], 'inputs.direct_only != true'
    end
    refute_match(/Bryan|BRYAN|bryan|upload_to_testflight|release_Bunway|devicectl|simctl/, job.to_s)
    builds=steps.select { |entry| entry['run'].to_s.include?('bundle exec fastlane') }
    assert_equal 1, builds.length
    assert_includes builds.first['run'], 'ios build_BunwayJulien'
  end

  def test_exact_source_ancestry_and_export_validation_precede_encryption
    source=steps.find { |entry| (entry['with']||{})['repository']=='h00l1gvn/bunway-app' }
    assert_equal '${{ steps.selected.outputs.source_sha }}', source.fetch('with').fetch('ref')
    assert_equal 0, source.fetch('with').fetch('fetch-depth')
    steps.select { |entry| entry['uses'].to_s.start_with?('actions/checkout@') }.each { |entry| assert_equal false,entry.fetch('with').fetch('persist-credentials') }
    gate=steps.index { |entry| entry['run'].to_s.include?('merge-base --is-ancestor') }
    signed=steps.index { |entry| entry['run'].to_s.include?('verify_julien_exported_ipa.rb BunwayJulien.ipa') }
    encrypt=steps.index { |entry| entry['run'].to_s.include?('artifact_crypto.cjs encrypt BunwayJulien.ipa') }
    assert_operator gate,:<,steps.index(step('julien_build'))
    assert_operator steps.index(step('julien_build')),:<,signed
    assert_operator signed,:<,encrypt
    artifacts=steps.select { |entry| entry['uses'].to_s.start_with?('actions/upload-artifact@') }
    assert_equal 2,artifacts.length
    assert_equal ['BunwayJulien.ipa.enc','BunwayJulien.manifest.json.enc'],artifacts.first.fetch('with').fetch('path').split
    assert_equal 'BunwayJulien-encrypted-${{ github.run_id }}',artifacts.first.fetch('with').fetch('name')
    assert_operator encrypt,:<,steps.index(artifacts.first)
    artifacts.each { |entry| assert_equal 7,entry.fetch('with').fetch('retention-days'); assert_equal 'error',entry.fetch('with').fetch('if-no-files-found') }
  end

  def test_package_manifest_binds_actual_bytes_source_delivery_and_run
    entry=steps.find { |value| value['name']=='Bind the actual package to this reviewed source and delivery run' }
    %w[ipa_sha256 source_sha delivery_sha run_id CFBundleVersion CFBundleShortVersionString].each { |key| assert_includes entry['run'],key }
    assert_includes entry['run'],'hashlib.sha256(ipa.read_bytes()).hexdigest()'
    assert_equal '${{ steps.selected.outputs.source_sha }}',entry.fetch('env').fetch('SOURCE_SHA')
  end

  def test_private_logs_are_encrypted_and_plaintext_cleaned_always
    assert_includes step('julien_build')['run'], 'umask 077'
    assert_includes step('julien_build')['run'], '> "$RUNNER_TEMP/bunway-julien-build.log" 2>&1'
    refute_match(/\b(?:cat|tail|tee)\b/,step('julien_build')['run'])
    assert_equal "failure() && (steps.julien_build.outcome == 'failure' || steps.julien_build.outcome == 'success')",step('encrypt_diagnostics')['if']
    assert_equal 'always()',steps.last['if']
    assert_includes steps.last['run'],'BunwayJulien.manifest.json'
    steps.each { |entry| refute_includes entry['run'].to_s,'${{ secrets.' }
  end

  def selection(overrides={})
    Dir.mktmpdir('bunway-julien-preflight-') do |directory|
      path=File.join(directory,'output')
      env={'CONFIRMED'=>'true','SOURCE_SHA'=>'a'*40,'BUNWAY_JULIEN_DEVICE_UDIDS'=>JSON.generate(DEVICES),'BUNWAY_ARTIFACT_KEY'=>'12'*32,'GITHUB_OUTPUT'=>path}.merge(overrides)
      stdout,stderr,status=Open3.capture3(env,'/bin/bash','-c',step('selected')['run'])
      [stdout,stderr,status,File.exist?(path) ? File.read(path) : nil]
    end
  end

  def test_valid_private_targets_are_not_printed
    assert_equal DEVICES,BunwayJulienDevices.parse(JSON.generate(DEVICES))
    stdout,stderr,status,output=selection
    assert status.success?,stderr
    assert_empty stdout;assert_empty stderr
    assert_equal 'source_sha='+'a'*40+"\n",output
  end

  def test_bad_source_readiness_key_or_private_targets_fail_without_leaks
    bad=[nil,'not-json',JSON.generate({'iphone'=>DEVICES['iphone']}),JSON.generate(DEVICES.merge('bryan'=>'synthetic')),JSON.generate(DEVICES.merge('ipad'=>DEVICES['iphone'])),JSON.generate(DEVICES.merge('ipad'=>'not-a-hardware-udid'))]
    bad.each do |raw|
      error=assert_raises(BunwayJulienDevices::Invalid) { BunwayJulienDevices.parse(raw) }
      DEVICES.values.each { |value| refute_includes error.message,value }
    end
    [{ 'CONFIRMED'=>'false'},{'SOURCE_SHA'=>'main'},{'BUNWAY_ARTIFACT_KEY'=>'private-bad-key'},*bad.map { |raw| {'BUNWAY_JULIEN_DEVICE_UDIDS'=>raw.to_s} }].each do |override|
      stdout,stderr,status,output=selection(override)
      refute status.success?; assert_nil output; assert_empty stdout
      DEVICES.values.each { |value| refute_includes stderr,value }
      refute_includes stderr,'private-bad-key'
    end
  end

  def profile(identifier)
    {'TeamIdentifier'=>['SYNTHETIC'], 'ExpirationDate'=>(Time.now.utc+86400).iso8601,'ProvisionedDevices'=>DEVICES.values,
     'Entitlements'=>{'application-identifier'=>"SYNTHETIC.#{identifier}",'get-task-allow'=>false,
     'com.apple.security.application-groups'=>[BunwayProfileCheck::GROUP],'com.apple.developer.icloud-services'=>['CloudKit'],
     'com.apple.developer.icloud-container-identifiers'=>[BunwayProfileCheck::CONTAINER], 'com.apple.developer.icloud-container-environment'=>['Production'],
     'aps-environment'=>'production','com.apple.developer.weatherkit'=>true}}
  end

  def test_actual_profile_gate_requires_phone_and_widget_to_cover_both_owned_targets
    [BunwayExportCheck::IDS.first,BunwayExportCheck::IDS.last].each do |identifier|
      DEVICES.each_value { |device| assert BunwayExportCheck.validate_profile(profile(identifier),identifier,'SYNTHETIC',device) }
      value=profile(identifier);value['ProvisionedDevices']=[DEVICES['iphone']]
      assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.validate_profile(value,identifier,'SYNTHETIC',DEVICES['ipad']) }
    end
  end

  def test_fastlane_uses_only_existing_bunway_ids_and_checks_both_personal_devices
    lane=File.read(File.join(ROOT,'fastlane/Fastfile')).split('lane :build_BunwayJulien do',2).last.split('  desc ',2).first
    assert_includes lane,'BunwayJulienDevices.parse(ENV["BUNWAY_JULIEN_DEVICE_UDIDS"])'
    assert_includes lane,'devices.each_value do |device|'
    assert_includes lane,'match(type: "adhoc"'
    assert_includes lane,'app_identifier: signing_targets.keys, force: true'
    assert_includes lane,'device: bundle_id == "#{identifier}.watchkitapp" ? nil : device'
    assert_includes lane,'iCloudContainerEnvironment: "Production"'
    refute_match(/BUNWAY_BRYAN|register_devices|release_Bunway|upload_to_testflight/,lane)
  end
end
