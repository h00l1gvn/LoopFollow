require 'minitest/autorun'
require_relative 'verify_exported_ipa'

class BunwayExportTests < Minitest::Test
  TEAM = 'SYNTHETIC_TEAM'.freeze
  DEVICE = '00000000-0000000000000000'.freeze

  def profile(identifier)
    {'TeamIdentifier' => [TEAM], 'ExpirationDate' => (Time.now.utc + 86400).iso8601,
     'ProvisionedDevices' => [DEVICE], 'Entitlements' => {
       'application-identifier' => "LEGACY_PREFIX.#{identifier}", 'get-task-allow' => false,
       'com.apple.security.application-groups' => [BunwayProfileCheck::GROUP],
       'com.apple.developer.icloud-services' => ['CloudKit'],
       'com.apple.developer.icloud-container-identifiers' => [BunwayProfileCheck::CONTAINER],
       'com.apple.developer.icloud-container-environment' => ['Production'],
       'aps-environment' => 'production', 'com.apple.developer.weatherkit' => true}}
  end

  def signed(identifier)
    entitlements = profile(identifier)['Entitlements']
    entitlements['com.apple.developer.team-identifier'] = TEAM
    entitlements['com.apple.developer.icloud-container-environment'] = 'Production'
    entitlements
  end

  def check_signed(value, identifier = BunwayExportCheck::IDS.first)
    BunwayExportCheck.validate_signed(value, identifier, TEAM, profile(identifier))
  end

  def infos
    BunwayExportCheck::IDS.map { |identifier| [identifier, {'CFBundleShortVersionString' => '0.4.0', 'CFBundleVersion' => '5'}] }.to_h
  end

  def test_all_three_valid_profiles_and_signed_entitlements
    BunwayExportCheck::IDS.each do |identifier|
      assert BunwayExportCheck.validate_profile(profile(identifier), identifier, TEAM, DEVICE)
      assert check_signed(signed(identifier), identifier)
    end
    assert BunwayExportCheck.validate_versions(infos)
  end

  def test_profile_wildcard_grant_allows_only_a_concrete_signed_cloudkit_claim
    BunwayExportCheck::IDS.first(2).each do |identifier|
      ['*', ['*']].each do |permission|
        value = profile(identifier)
        value['Entitlements']['com.apple.developer.icloud-services'] = permission
        assert BunwayExportCheck.validate_profile(value, identifier, TEAM, DEVICE)
        assert BunwayExportCheck.validate_signed(signed(identifier), identifier, TEAM, value)
      end
    end
  end

  def test_signed_cloudkit_cannot_be_wildcard_missing_or_documents_only
    BunwayExportCheck::IDS.first(2).each do |identifier|
      ['*', ['*'], nil, ['CloudDocuments'], ['CloudKit-Anonymous']].each do |permission|
        value = signed(identifier)
        value['com.apple.developer.icloud-services'] = permission
        assert_match(/missing CloudKit service/, assert_raises(BunwayExportCheck::Invalid) { check_signed(value, identifier) }.message)
      end
    end
  end

  def test_legacy_app_identifier_prefix_is_allowed_only_if_profile_matches
    assert check_signed(signed(BunwayExportCheck::IDS.first))
    value = signed(BunwayExportCheck::IDS.first)
    value['application-identifier'] = "#{TEAM}.#{BunwayExportCheck::IDS.first}"
    assert_match(/wrong explicit App ID/, assert_raises(BunwayExportCheck::Invalid) { check_signed(value) }.message)
  end

  def test_phone_and_widget_profiles_must_include_the_hardware_phone
    [BunwayExportCheck::IDS.first, BunwayExportCheck::IDS.last].each do |identifier|
      value = profile(identifier); value['ProvisionedDevices'] = ['other-synthetic-device']
      error = assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.validate_profile(value, identifier, TEAM, DEVICE) }
      assert_match(/device is not included/, error.message)
      refute_includes error.message, DEVICE
    end
  end

  def test_watch_uses_its_own_device_list_without_claiming_phone_is_watch
    identifier = BunwayExportCheck::IDS[1]
    value = profile(identifier); value['ProvisionedDevices'] = ['synthetic-watch']
    assert BunwayExportCheck.validate_profile(value, identifier, TEAM, DEVICE)
  end

  def test_store_enterprise_and_development_profiles_are_rejected
    identifier = BunwayExportCheck::IDS.first
    value = profile(identifier); value.delete('ProvisionedDevices')
    assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.validate_profile(value, identifier, TEAM, nil) }
    value = profile(identifier); value['ProvisionsAllDevices'] = true
    assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.validate_profile(value, identifier, TEAM, DEVICE) }
    value = profile(identifier); value['Entitlements']['get-task-allow'] = true
    assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.validate_profile(value, identifier, TEAM, DEVICE) }
  end

  def test_expired_wrong_team_or_missing_weather_profile_rejected
    identifier = BunwayExportCheck::IDS.first
    mutations = [
      lambda { |value| value['ExpirationDate'] = (Time.now.utc - 86400).iso8601 },
      lambda { |value| value['TeamIdentifier'] = ['OTHER'] },
      lambda { |value| value['Entitlements'].delete('com.apple.developer.weatherkit') }
    ]
    mutations.each do |mutation|
      value = profile(identifier); mutation.call(value)
      assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.validate_profile(value, identifier, TEAM, DEVICE) }
    end
  end

  def test_final_entitlements_must_use_exact_group_and_container
    identifier = BunwayExportCheck::IDS.first
    ['com.apple.security.application-groups', 'com.apple.developer.icloud-container-identifiers'].each do |key|
      value = signed(identifier); value[key] << 'unrelated.app.container'
      assert_raises(BunwayExportCheck::Invalid) { check_signed(value) }
      value = signed(identifier); value.delete(key)
      assert_raises(BunwayExportCheck::Invalid) { check_signed(value) }
    end
  end

  def test_signed_phone_rejects_development_cloud_push_or_debug_permissions
    identifier = BunwayExportCheck::IDS.first
    {'com.apple.developer.icloud-container-environment' => 'Development',
     'aps-environment' => 'development', 'get-task-allow' => true,
     'com.apple.developer.team-identifier' => 'OTHER',
     'com.apple.developer.weatherkit' => false}.each do |key, wrong|
      value = signed(identifier); value[key] = wrong
      assert_raises(BunwayExportCheck::Invalid) { check_signed(value) }
    end
  end

  def test_signed_watch_requires_production_cloudkit
    identifier = BunwayExportCheck::IDS[1]
    value = signed(identifier); value['com.apple.developer.icloud-container-environment'] = 'Development'
    assert_raises(BunwayExportCheck::Invalid) { check_signed(value, identifier) }
  end

  def test_widget_requires_group_but_not_unused_cloud_capabilities
    identifier = BunwayExportCheck::IDS.last
    value = signed(identifier)
    value.delete('com.apple.developer.icloud-services')
    value.delete('com.apple.developer.icloud-container-identifiers')
    value.delete('com.apple.developer.icloud-container-environment')
    value.delete('aps-environment'); value.delete('com.apple.developer.weatherkit')
    assert check_signed(value, identifier)
  end

  def test_missing_extra_mismatched_or_blank_companion_versions_rejected
    value = infos; value.delete(BunwayExportCheck::IDS[1])
    assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.validate_versions(value) }
    value = infos; value['unrelated.app'] = value.values.first
    assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.validate_versions(value) }
    value = infos; value[BunwayExportCheck::IDS.last]['CFBundleVersion'] = '6'
    assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.validate_versions(value) }
    value = infos; value.each_value { |info| info['CFBundleVersion'] = '' }
    assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.validate_versions(value) }
  end

  def test_required_hardware_secret_is_checked_without_logging_value
    assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.verify('not-an-ipa', TEAM, 'not-a-hardware-device') }
    assert_raises(BunwayExportCheck::Invalid) { BunwayExportCheck.verify('not-an-ipa', '', DEVICE) }
  end
end
