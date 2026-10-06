#!/usr/bin/env ruby
# Synthetic objects only. No Xcode project, keychain, profile, cloud or build is changed.
require 'minitest/autorun'
require 'tmpdir'
require 'stringio'
require_relative 'configure_resale_signing'

class ResaleSigningConfigurationTest < Minitest::Test
  Config = Struct.new(:name, :build_settings)
  Target = Struct.new(:name, :build_configurations)
  Project = Struct.new(:targets)
  SCOPE_PATH = File.join(__dir__, 'signing-export-scope.json')

  def setup
    @scope = JSON.parse(File.read(SCOPE_PATH))
    @project = Project.new(ResaleSigning::EXACT.map do |name, values|
      id, _, sdk, deployment, minimum = values
      Target.new(name, %w[Debug Release].map do |configuration|
        Config.new(configuration, {
          'PRODUCT_BUNDLE_IDENTIFIER'=>id, 'SDKROOT'=>sdk,
          'MARKETING_VERSION'=>'0.1.0', 'CURRENT_PROJECT_VERSION'=>'1',
          deployment=>minimum, 'CODE_SIGN_STYLE'=>'Automatic',
          'CODE_SIGN_IDENTITY'=>'', 'DEVELOPMENT_TEAM'=>ResaleSigning::TEAM,
          'UNRELATED_SETTING'=>'preserve me'
        })
      end)
    end)
  end

  def manifest(family)
    certificate = {'sha256'=>'a'*64, 'sha1'=>'b'*40, 'type'=>'DISTRIBUTION', 'verified'=>true}
    selected = @scope['targets'].select { |target| target['family']==family }
    {
      'schema'=>1, 'source_sha'=>ResaleSigning::SOURCE, 'family'=>family,
      'team'=>ResaleSigning::TEAM, 'group'=>ResaleSigning::GROUP,
      'profiles'=>selected.each_with_index.map do |target,index|
        {'bundle_id'=>target['bundle_id'], 'target'=>target['target'],
         'uuid'=>format('00000000-0000-0000-0000-%012d',index+1),
         'name'=>'Synthetic Fixture '+target['target'],
         'profile_type'=>target['profile_type'], 'verified'=>true,
         'certificate_sha256'=>certificate['sha256']}
      end,
      'signing_certificate'=>certificate,
      'installer_certificate'=>family=='macos' ? {
        'sha256'=>'c'*64, 'sha1'=>'d'*40, 'type'=>'MAC_INSTALLER_DISTRIBUTION', 'verified'=>true
      } : nil
    }
  end

  def snapshot
    JSON.generate(@project.targets.map { |target| [target.name,target.build_configurations.map { |config| [config.name,config.build_settings] }] })
  end

  def blocked_without_mutation(code, family='ios', material=nil)
    before = snapshot
    error = assert_raises(ResaleSigning::GuardError) do
      ResaleSigning.configure_in_memory(@project,@scope,material || manifest(family),family)
    end
    assert_equal code, error.message
    assert_equal before, snapshot
  end

  def assert_family_configuration(family, count)
    material=manifest(family)
    unselected=@project.targets.reject { |target| ResaleSigning::EXACT[target.name][1]==family }
    before=JSON.generate(unselected)
    original=Marshal.load(Marshal.dump(@project))
    plan=ResaleSigning.configure_in_memory(@project,@scope,material,family)
    assert_equal count, plan['mapping'].size
    assert_equal before, JSON.generate(unselected)
    @project.targets.each do |target|
      next unless plan['mapping'].key?(target.name)
      target.build_configurations.each_with_index do |config,index|
        settings=config.build_settings
        prior=original.targets.find { |item| item.name==target.name }.build_configurations[index].build_settings
        assert_equal 'Manual',settings['CODE_SIGN_STYLE']
        assert_equal ResaleSigning::TEAM,settings['DEVELOPMENT_TEAM']
        assert_equal material['signing_certificate']['sha1'],settings['CODE_SIGN_IDENTITY']
        assert_equal plan['mapping'][target.name]['uuid'],settings['PROVISIONING_PROFILE']
        assert_equal plan['mapping'][target.name]['name'],settings['PROVISIONING_PROFILE_SPECIFIER']
        preserved=prior.keys-%w[CODE_SIGN_STYLE CODE_SIGN_IDENTITY DEVELOPMENT_TEAM]
        preserved.each { |key| assert_equal prior[key],settings[key] }
      end
    end
    plan
  end

  def test_ios_configures_only_four_family_targets_and_preserves_other_settings
    plan=assert_family_configuration('ios',4)
    options=ResaleSigning.export_options(plan)
    assert_equal 'app-store-connect',options['method']
    assert_equal 'export',options['destination']
    assert_equal 'manual',options['signingStyle']
    assert_equal false,options['manageAppVersionAndBuildNumber']
    assert_equal false,options['uploadSymbols']
    assert_equal plan['mapping'].values.map { |item| item['uuid'] }.sort,options['provisioningProfiles'].values.sort
    refute options.key?('installerSigningCertificate')
  end

  def test_mac_configures_only_two_targets_and_uses_separate_installer
    plan=assert_family_configuration('macos',2)
    options=ResaleSigning.export_options(plan)
    assert_equal 'b'*40,options['signingCertificate']
    assert_equal 'd'*40,options['installerSigningCertificate']
    assert_equal 2,options['provisioningProfiles'].size
  end

  def test_tv_configures_only_tv_target
    assert_equal [ResaleSigning::BASE+'.tv'],ResaleSigning.export_options(assert_family_configuration('tvos',1))['provisioningProfiles'].keys
  end

  def test_missing_profile_mapping_refuses_all_mutation
    material=manifest('ios');material['profiles'].pop
    blocked_without_mutation('restore_profile_set_mismatch','ios',material)
  end

  def test_profile_bound_to_wrong_certificate_refuses
    material=manifest('ios');material['profiles'][0]['certificate_sha256']='e'*64
    blocked_without_mutation('restore_profile_validation_mismatch','ios',material)
  end

  def test_unverified_profile_refuses
    material=manifest('ios');material['profiles'][0]['verified']=false
    blocked_without_mutation('restore_profile_validation_mismatch','ios',material)
  end

  def test_development_certificate_refuses
    material=manifest('ios');material['signing_certificate']['type']='DEVELOPMENT'
    blocked_without_mutation('validated_distribution_certificate_missing','ios',material)
  end

  def test_fingerprint_must_be_lowercase_complete_hex
    material=manifest('ios');material['signing_certificate']['sha1']='B'*40
    blocked_without_mutation('validated_distribution_certificate_missing','ios',material)
  end

  def test_missing_mac_installer_identity_refuses_before_mutation
    material=manifest('macos');material['installer_certificate']=nil
    blocked_without_mutation('validated_mac_installer_certificate_missing','macos',material)
  end

  def test_nonmac_installer_cannot_sneak_into_export
    material=manifest('ios');material['installer_certificate']=manifest('macos')['installer_certificate']
    blocked_without_mutation('unexpected_installer_identity','ios',material)
  end

  def test_duplicate_uuid_refuses
    material=manifest('ios');material['profiles'][1]['uuid']=material['profiles'][0]['uuid']
    blocked_without_mutation('restore_profile_uuid_duplicate','ios',material)
  end

  def test_profile_name_control_characters_refuse
    material=manifest('ios');material['profiles'][0]['name']="Synthetic\nsecret"
    blocked_without_mutation('restore_profile_name_invalid','ios',material)
  end

  def test_scope_cannot_weaken_store_profile_type_even_if_manifest_agrees
    @scope['targets'][0]['profile_type']='IOS_APP_DEVELOPMENT'
    blocked_without_mutation('scope_target_identity_mismatch')
  end

  def test_scope_platform_mismatch_refuses
    @scope['targets'][0]['platform']='macOS'
    blocked_without_mutation('scope_target_identity_mismatch')
  end

  def test_wrong_frozen_source_refuses
    @scope['source_sha']='0'*40
    blocked_without_mutation('scope_identity_or_source_mismatch')
  end

  def test_unknown_target_refuses
    @project.targets[0].name='UnrelatedApp'
    blocked_without_mutation('project_target_set_mismatch')
  end

  def test_unrelated_bundle_or_sdk_refuses
    @project.targets[0].build_configurations[0].build_settings['PRODUCT_BUNDLE_IDENTIFIER']='unrelated.bundle'
    blocked_without_mutation('project_target_identity_mismatch')
  end

  def test_changed_minimum_os_refuses
    @project.targets[0].build_configurations[0].build_settings['IPHONEOS_DEPLOYMENT_TARGET']='16.0'
    blocked_without_mutation('project_version_or_minimum_os_mismatch')
  end

  def test_unknown_configuration_refuses
    @project.targets[0].build_configurations[0].name='Unreviewed'
    blocked_without_mutation('project_configurations_mismatch')
  end

  def test_conditional_signing_override_refuses
    @project.targets[0].build_configurations[0].build_settings['CODE_SIGN_IDENTITY[sdk=iphoneos*]']='Development'
    blocked_without_mutation('conditional_signing_setting_requires_review')
  end

  def test_other_team_refuses_even_on_unselected_target
    @project.targets.last.build_configurations[0].build_settings['DEVELOPMENT_TEAM']='OTHERTEAM'
    blocked_without_mutation('project_other_team_present')
  end

  def test_unknown_family_refuses
    blocked_without_mutation('unsupported_family','unrelated',manifest('ios'))
  end

  def test_cli_local_invocation_refuses_before_dependency_load_or_any_file_write
    prior=ENV['GITHUB_ACTIONS'];ENV.delete('GITHUB_ACTIONS')
    Dir.mktmpdir('resale-signing-fixture') do |directory|
      sentinel=File.join(directory,'canonical-marker');File.write(sentinel,'unchanged')
      stdout,_=capture_io do
        assert_equal 1,ResaleSigning.run_cli(%w[--family ios --checkout]+[directory])
      end
      response=JSON.parse(stdout)
      assert_equal 'runner_only_not_a_local_source_editor',response['error_code']
      assert_equal 'unchanged',File.read(sentinel)
      assert_equal ['canonical-marker'],Dir.children(directory)
      refute defined?(Xcodeproj)
    end
  ensure
    prior.nil? ? ENV.delete('GITHUB_ACTIONS') : ENV['GITHUB_ACTIONS']=prior
  end

  def test_private_report_has_mode_600
    Dir.mktmpdir('resale-signing-fixture') do |directory|
      path=File.join(directory,'report.json');File.write(path,'old');File.chmod(0644,path)
      ResaleSigning.private_write(path,"{\"status\":\"synthetic\"}\n")
      assert_equal 0600,File.stat(path).mode&0777
    end
  end

  def adhoc_scope_and_manifest
    @scope['adhoc_native_profiles']=ResaleSigning::ADHOC_PROFILES.each_with_index.map do |(id,pin),index|
      {'bundle_id'=>id,'native_profile_id'=>pin[0],'name'=>pin[1],'sha256'=>pin[2],
       'uuid'=>format('00000000-0000-0000-0000-%012d',index+1),
       'owner_private_phone_membership_verified_by_exact_cms_hash'=>true}
    end
    material=manifest('ios');material['distribution']='ad-hoc'
    material['signing_certificate']['sha256']=ResaleSigning::APPROVED_ADHOC_CERT
    material['profiles'].each do |profile|
      pin=@scope['adhoc_native_profiles'].find{|row|row['bundle_id']==profile['bundle_id']}
      profile.merge!('native_profile_id'=>pin['native_profile_id'],'name'=>pin['name'],
                     'sha256'=>pin['sha256'],'uuid'=>pin['uuid'],'profile_type'=>'IOS_APP_ADHOC',
                     'certificate_sha256'=>ResaleSigning::APPROVED_ADHOC_CERT)
    end
    material
  end

  def blocked_adhoc_without_mutation(code, material, family='ios', distribution='ad-hoc')
    before=snapshot
    error=assert_raises(ResaleSigning::GuardError){ResaleSigning.configure_in_memory(@project,@scope,material,family,distribution)}
    assert_equal code,error.message;assert_equal before,snapshot
  end

  def test_adhoc_only_four_ios_targets_release_testing_manual_with_exact_profile_map
    material=adhoc_scope_and_manifest
    unselected=@project.targets.reject{|target|ResaleSigning::EXACT[target.name][1]=='ios'}
    before=JSON.generate(unselected)
    plan=ResaleSigning.configure_in_memory(@project,@scope,material,'ios','ad-hoc')
    assert_equal before,JSON.generate(unselected)
    options=ResaleSigning.export_options(plan)
    assert_equal 'release-testing',options['method']
    assert_equal 'export',options['destination']
    assert_equal 'manual',options['signingStyle']
    assert_equal false,options['manageAppVersionAndBuildNumber']
    assert_equal 4,options['provisioningProfiles'].size
    assert_equal material['profiles'].map{|p|p['uuid']}.sort,options['provisioningProfiles'].values.sort
    @project.targets.each do |target|
      next unless plan['mapping'].key?(target.name)
      target.build_configurations.each do |config|
        assert_equal 'Manual',config.build_settings['CODE_SIGN_STYLE']
        assert_equal plan['mapping'][target.name]['uuid'],config.build_settings['PROVISIONING_PROFILE']
      end
    end
  end

  def test_adhoc_scope_can_explicitly_use_adhoc_type_without_weakening_other_families
    material=adhoc_scope_and_manifest
    @scope['targets'].select{|t|t['family']=='ios'}.each{|t|t['profile_type']='IOS_APP_ADHOC'}
    assert_equal 4,ResaleSigning.scope_plan(@scope,material,'ios','ad-hoc')['mapping'].size
    assert_raises(ResaleSigning::GuardError){ResaleSigning.scope_plan(@scope,manifest('ios'),'ios')}
  end

  def test_adhoc_cannot_apply_to_mac_tv_or_unknown_distribution
    material=adhoc_scope_and_manifest
    blocked_adhoc_without_mutation('adhoc_only_ios_family',material,'macos')
    blocked_adhoc_without_mutation('adhoc_only_ios_family',material,'tvos')
    blocked_adhoc_without_mutation('unsupported_distribution',material,'ios','enterprise')
  end

  def test_adhoc_approved_leaf_and_explicit_distribution_are_required
    material=adhoc_scope_and_manifest;material['signing_certificate']['sha256']='a'*64
    blocked_adhoc_without_mutation('adhoc_distribution_or_approved_leaf_mismatch',material)
    material=adhoc_scope_and_manifest;material.delete('distribution')
    blocked_adhoc_without_mutation('adhoc_distribution_or_approved_leaf_mismatch',material)
  end

  def test_adhoc_native_content_uuid_name_mapping_is_exact
    %w[native_profile_id sha256 uuid name].each do |key|
      material=adhoc_scope_and_manifest;material['profiles'][0][key]='wrong'
      blocked_adhoc_without_mutation('adhoc_restore_exact_cms_mapping_mismatch',material)
    end
  end

  def test_adhoc_scope_requires_prior_private_membership_without_hardware_values
    material=adhoc_scope_and_manifest
    @scope['adhoc_native_profiles'][0]['owner_private_phone_membership_verified_by_exact_cms_hash']=false
    blocked_adhoc_without_mutation('adhoc_safe_private_membership_attestation_required',material)
    material=adhoc_scope_and_manifest
    @scope['adhoc_native_profiles'][0]['hardware_identifier']='synthetic-no-real-device'
    blocked_adhoc_without_mutation('adhoc_safe_private_membership_attestation_required',material)
  end

  def test_default_store_mode_cannot_silently_accept_adhoc_material
    material=adhoc_scope_and_manifest
    before=snapshot
    error=assert_raises(ResaleSigning::GuardError){ResaleSigning.configure_in_memory(@project,@scope,material,'ios')}
    assert_equal 'restore_distribution_mismatch',error.message;assert_equal before,snapshot
  end
end
