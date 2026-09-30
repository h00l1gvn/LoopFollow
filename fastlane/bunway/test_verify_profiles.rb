require 'minitest/autorun'
require_relative 'verify_profiles'
class BunwayProfileTests < Minitest::Test
  ID = 'com.julienbell.bunway'.freeze
  def profile
    {'TeamIdentifier'=>['TEAM123'],'ExpirationDate'=>(Time.now.utc+86400).iso8601,
     'Entitlements'=>{'application-identifier'=>"TEAM123.#{ID}", 'get-task-allow'=>false,
      'com.apple.security.application-groups'=>[BunwayProfileCheck::GROUP],
      'com.apple.developer.icloud-services'=>['CloudKit'],
      'com.apple.developer.icloud-container-identifiers'=>[BunwayProfileCheck::CONTAINER],
      'com.apple.developer.icloud-container-environment'=>['Production'],
      'aps-environment'=>'production','com.apple.developer.weatherkit'=>true}}
  end
  def check(value)
    BunwayProfileCheck.validate(value,ID,'TEAM123',cloud:true,group:true,push:true,weather:true)
  end
  def test_valid_distribution_profile
    assert check(profile)
  end
  def test_icloud_profile_wildcard_permission_authorizes_cloudkit
    ['*', ['*']].each do |permission|
      value=profile; value['Entitlements']['com.apple.developer.icloud-services']=permission
      assert check(value)
    end
  end
  def test_icloud_permission_must_exist_and_cannot_replace_other_requirements
    [nil, [], ['CloudDocuments'], ['CloudKit-Anonymous']].each do |permission|
      value=profile; value['Entitlements']['com.apple.developer.icloud-services']=permission
      assert_match(/missing CloudKit service/,assert_raises(RuntimeError){check(value)}.message)
    end
    value=profile; value['Entitlements']['com.apple.developer.icloud-services']='*'
    value['Entitlements']['com.apple.developer.icloud-container-identifiers']=['*']
    assert_match(/missing CloudKit container/,assert_raises(RuntimeError){check(value)}.message)
    value=profile; value['Entitlements']['com.apple.developer.icloud-services']=['*']
    value['Entitlements']['com.apple.developer.icloud-container-environment']=['*']
    assert_match(/Production environment/,assert_raises(RuntimeError){check(value)}.message)
  end
  def test_missing_group_or_development_environment_rejected
    value=profile; value['Entitlements'].delete('com.apple.security.application-groups')
    assert_match(/missing App Group/,assert_raises(RuntimeError){check(value)}.message)
    value=profile; value['Entitlements']['com.apple.developer.icloud-container-environment']=['Development']
    assert_match(/Production environment/,assert_raises(RuntimeError){check(value)}.message)
  end
  def test_wrong_team_wildcard_expiration_or_push_rejected
    value=profile; value['TeamIdentifier']=['OTHER']; assert_raises(RuntimeError){check(value)}
    value=profile; value['Entitlements']['application-identifier']='TEAM123.*'; assert_raises(RuntimeError){check(value)}
    value=profile; value['ExpirationDate']=(Time.now.utc-86400).iso8601; assert_raises(RuntimeError){check(value)}
    value=profile; value['Entitlements']['aps-environment']='development'; assert_raises(RuntimeError){check(value)}
  end
  def test_ad_hoc_must_include_the_device
    value=profile; value['ProvisionedDevices']=['synthetic-device']
    assert BunwayProfileCheck.validate(value,ID,'TEAM123',cloud:true,group:true,device:'synthetic-device')
    assert_match(/not included/,assert_raises(RuntimeError){BunwayProfileCheck.validate(value,ID,'TEAM123',device:'different-device')}.message)
  end
  def test_xml_boolean_and_array_parse_without_external_gems
    xml='<plist><dict><key>enabled</key><true/><key>names</key><array><string>a</string><string>b</string></array></dict></plist>'
    assert_equal({'enabled'=>true,'names'=>['a','b']},BunwayProfileCheck.plist_value(REXML::Document.new(xml).elements['plist/dict']))
  end
end
