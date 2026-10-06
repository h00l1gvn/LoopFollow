require 'minitest/autorun'
require 'fileutils'
require_relative 'verify_tv_exported_ipa'

class BunwayTVExportTests < Minitest::Test
  TEAM = 'SYNTHETIC_TEAM'.freeze
  VERSION = '0.5.0'.freeze
  BUILD = '10'.freeze

  def profile
    {'TeamIdentifier' => [TEAM], 'ExpirationDate' => (Time.now.utc + 86400).iso8601,
     'Entitlements' => {
       'application-identifier' => "LEGACY_PREFIX.#{BunwayTVExportCheck::IDENTIFIER}",
       'get-task-allow' => false,
       'com.apple.developer.icloud-services' => ['CloudKit'],
       'com.apple.developer.icloud-container-identifiers' => [BunwayProfileCheck::CONTAINER],
       'com.apple.developer.icloud-container-environment' => ['Production']}}
  end

  def signed
    value = profile['Entitlements']
    value['com.apple.developer.team-identifier'] = TEAM
    value['com.apple.developer.icloud-container-environment'] = 'Production'
    value
  end

  def info
    {'CFBundleIdentifier' => BunwayTVExportCheck::IDENTIFIER,
     'CFBundleSupportedPlatforms' => ['AppleTVOS'], 'DTPlatformName' => 'appletvos',
     'UIDeviceFamily' => [3], 'CFBundleShortVersionString' => VERSION,
     'CFBundleVersion' => BUILD}
  end

  def check_signed(value, authorized = profile)
    BunwayTVExportCheck.validate_signed(value, TEAM, authorized)
  end

  def test_valid_store_profile_and_signed_tv_metadata
    assert BunwayTVExportCheck.validate_profile(profile, TEAM)
    assert check_signed(signed)
    assert BunwayTVExportCheck.validate_info(info, VERSION, BUILD)
  end

  def test_profile_wildcard_grants_require_literal_signed_cloudkit
    ['*', ['*']].each do |grant|
      value = profile
      value['Entitlements']['com.apple.developer.icloud-services'] = grant
      assert BunwayTVExportCheck.validate_profile(value, TEAM)
      assert check_signed(signed, value)
    end
    [nil, [], '*', ['*'], ['CloudDocuments']].each do |grant|
      value = signed; value['com.apple.developer.icloud-services'] = grant
      assert_match(/missing CloudKit service/, assert_raises(BunwayTVExportCheck::Invalid) { check_signed(value) }.message)
    end
  end

  def test_expired_wrong_team_development_and_cloudless_profiles_rejected
    mutations = [
      ->(value) { value['ExpirationDate'] = (Time.now.utc - 86400).iso8601 },
      ->(value) { value['TeamIdentifier'] = ['OTHER'] },
      ->(value) { value['Entitlements']['get-task-allow'] = true },
      ->(value) { value['Entitlements'].delete('com.apple.developer.icloud-services') },
      ->(value) { value['Entitlements']['com.apple.developer.icloud-container-identifiers'] = ['other.container'] },
      ->(value) { value['Entitlements']['com.apple.developer.icloud-container-environment'] = ['Development'] }
    ]
    mutations.each do |mutation|
      value = profile; mutation.call(value)
      assert_raises(BunwayTVExportCheck::Invalid) { BunwayTVExportCheck.validate_profile(value, TEAM) }
    end
  end

  def test_ad_hoc_and_enterprise_profiles_rejected_for_store
    [{'ProvisionedDevices' => ['synthetic-device']}, {'ProvisionedDevices' => []},
     {'ProvisionsAllDevices' => true}].each do |extra|
      assert_match(/App Store distribution/, assert_raises(BunwayTVExportCheck::Invalid) {
        BunwayTVExportCheck.validate_profile(profile.merge(extra), TEAM)
      }.message)
    end
  end

  def test_signed_cloudkit_container_must_be_exactly_bunway
    [nil, [], ['*'], ['other.container'],
     [BunwayProfileCheck::CONTAINER, 'other.container']].each do |containers|
      value = signed; value['com.apple.developer.icloud-container-identifiers'] = containers
      assert_match(/wrong CloudKit container/, assert_raises(BunwayTVExportCheck::Invalid) { check_signed(value) }.message)
    end
  end

  def test_signed_environment_team_and_debug_permissions_rejected
    {'com.apple.developer.icloud-container-environment' => 'Development',
     'com.apple.developer.team-identifier' => 'OTHER', 'get-task-allow' => true}.each do |key, invalid|
      value = signed; value[key] = invalid
      assert_raises(BunwayTVExportCheck::Invalid) { check_signed(value) }
    end
  end

  def test_legacy_prefix_allowed_only_when_exact_profile_matches
    assert check_signed(signed)
    value = signed; value['application-identifier'] = "#{TEAM}.#{BunwayTVExportCheck::IDENTIFIER}"
    assert_match(/wrong explicit App ID/, assert_raises(BunwayTVExportCheck::Invalid) { check_signed(value) }.message)
    value = signed; value['application-identifier'] = 'LEGACY_PREFIX.*'
    assert_raises(BunwayTVExportCheck::Invalid) { check_signed(value) }
  end

  def test_tv_platform_device_family_and_reviewed_versions_are_required
    {'CFBundleIdentifier' => 'other.app', 'CFBundleSupportedPlatforms' => ['iPhoneOS'],
     'DTPlatformName' => 'iphonesimulator', 'UIDeviceFamily' => [1, 2],
     'CFBundleShortVersionString' => '0.4.1', 'CFBundleVersion' => '9'}.each do |key, invalid|
      value = info; value[key] = invalid
      assert_raises(BunwayTVExportCheck::Invalid) { BunwayTVExportCheck.validate_info(value, VERSION, BUILD) }
    end
  end

  def test_missing_expected_coordinates_or_missing_ipa_stop_before_extraction
    [['', VERSION, BUILD], [TEAM, '0.5', BUILD], [TEAM, VERSION, '0'],
     [TEAM, VERSION, 'main']].each do |team, version, build|
      assert_match(/expected Apple team/, assert_raises(BunwayTVExportCheck::Invalid) {
        BunwayTVExportCheck.verify('/synthetic-missing.ipa', team, version, build)
      }.message)
    end
    assert_match(/IPA is missing/, assert_raises(BunwayTVExportCheck::Invalid) {
      BunwayTVExportCheck.verify('/synthetic-missing.ipa', TEAM, VERSION, BUILD)
    }.message)
  end

  # Real ZIP extraction and plutil are used. Only Apple signing/profile operations
  # are synthetic, so tests never need certificates, secrets or a physical device.
  def plist(value)
    encode = lambda do |entry|
      case entry
      when Hash then '<dict>' + entry.map { |key, item| "<key>#{REXML::Text.normalize(key)}</key>#{encode.call(item)}" }.join + '</dict>'
      when Array then '<array>' + entry.map { |item| encode.call(item) }.join + '</array>'
      when Integer then "<integer>#{entry}</integer>"
      when TrueClass then '<true/>'
      when FalseClass then '<false/>'
      else "<string>#{REXML::Text.normalize(entry.to_s)}</string>"
      end
    end
    "<?xml version='1.0'?><plist version='1.0'>#{encode.call(value)}</plist>"
  end

  def with_ipa(metadata = info, signature_valid: true, signed_entitlements: signed)
    Dir.mktmpdir('bunway-tv-test-') do |directory|
      app = File.join(directory, 'Payload', 'BunwayTV.app')
      FileUtils.mkdir_p(app)
      File.write(File.join(app, 'Info.plist'), plist(metadata))
      File.write(File.join(app, 'embedded.mobileprovision'), 'synthetic profile')
      File.write(File.join(app, 'BunwayTV'), 'synthetic executable')
      yield app, :prepare if block_given?
      ipa = File.join(directory, 'BunwayTV.ipa')
      _out, error, status = Open3.capture3('/usr/bin/zip', '-qry', ipa, 'Payload', chdir: directory)
      assert status.success?, error
      original_capture = Open3.method(:capture3)
      capture = lambda do |*arguments, **options|
        if arguments.first == '/usr/bin/codesign'
          valid = arguments.include?('--display') || signature_valid
          output = arguments.include?('--display') ? plist(signed_entitlements) : ''
          [output, '', Struct.new(:success?).new(valid)]
        else
          original_capture.call(*arguments, **options)
        end
      end
      Open3.stub(:capture3, capture) do
        BunwayProfileCheck.stub(:decode, profile) { yield ipa, :verify }
      end
    end
  end

  def test_real_zip_and_plist_pipeline_accepts_expected_tv_package
    with_ipa do |path, phase|
      assert BunwayTVExportCheck.verify(path, TEAM, VERSION, BUILD) if phase == :verify
    end
  end

  def test_signature_failure_stops_actual_package_pipeline
    with_ipa(signature_valid: false) do |path, phase|
      next unless phase == :verify
      assert_match(/signature did not verify/, assert_raises(BunwayTVExportCheck::Invalid) {
        BunwayTVExportCheck.verify(path, TEAM, VERSION, BUILD)
      }.message)
    end
  end

  def test_actual_metadata_mismatch_and_unsigned_cloudkit_claim_rejected
    with_ipa(info.merge('CFBundleVersion' => '9')) do |path, phase|
      next unless phase == :verify
      assert_match(/wrong selected build/, assert_raises(BunwayTVExportCheck::Invalid) {
        BunwayTVExportCheck.verify(path, TEAM, VERSION, BUILD)
      }.message)
    end
    wrong = signed; wrong['com.apple.developer.icloud-container-environment'] = 'Development'
    with_ipa(signed_entitlements: wrong) do |path, phase|
      next unless phase == :verify
      assert_match(/CloudKit must be Production/, assert_raises(BunwayTVExportCheck::Invalid) {
        BunwayTVExportCheck.verify(path, TEAM, VERSION, BUILD)
      }.message)
    end
  end

  def test_embedded_extension_and_symlink_are_rejected
    [:extension, :symlink].each do |unexpected|
      with_ipa do |path, phase|
        if phase == :prepare
          FileUtils.mkdir_p(File.join(path, 'PlugIns', 'Unexpected.appex')) if unexpected == :extension
          File.symlink('BunwayTV', File.join(path, 'UnexpectedLink')) if unexpected == :symlink
        else
          assert_match(/unexpected symlinks or embedded apps/, assert_raises(BunwayTVExportCheck::Invalid) {
            BunwayTVExportCheck.verify(path, TEAM, VERSION, BUILD)
          }.message)
        end
      end
    end
  end
end
