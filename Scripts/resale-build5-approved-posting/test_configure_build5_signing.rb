#!/usr/bin/env ruby
# Synthetic objects only. No Xcode project, keychain, profile, cloud or build is changed.
require 'minitest/autorun'
require 'tmpdir'
require 'stringio'
require_relative 'configure_build5_signing'

class ResaleSigningConfigurationTest < Minitest::Test
  Config = Struct.new(:name, :build_settings)
  Target = Struct.new(:name, :build_configurations)
  Project = Struct.new(:targets)
  SCOPE_PATH = File.join(__dir__, 'signing-export-scope.json')

  def setup
    @scope = JSON.parse(File.read(SCOPE_PATH))
    @scope.merge!('source_sha'=>'a'*40,'source_frozen'=>true,'final_artwork_owner_approved'=>true)
    @project = Project.new(ResaleSigning::EXACT.map do |name, values|
      id, _, sdk, deployment, minimum = values
      Target.new(name, %w[Debug Release].map do |configuration|
        Config.new(configuration, {
          'PRODUCT_BUNDLE_IDENTIFIER'=>id, 'SDKROOT'=>sdk,
          'MARKETING_VERSION'=>'0.1.0', 'CURRENT_PROJECT_VERSION'=>'5',
          deployment=>minimum, 'CODE_SIGN_STYLE'=>'Automatic',
          'CODE_SIGN_IDENTITY'=>'', 'DEVELOPMENT_TEAM'=>ResaleSigning::TEAM,
          'UNRELATED_SETTING'=>'preserve me'
        })
      end)
    end)
  end

  def manifest(family)
    certificate = {'sha256'=>ResaleSigning::APPROVED_CERT, 'sha1'=>'b'*40, 'type'=>'DISTRIBUTION', 'verified'=>true}
    selected = @scope['targets'].select { |target| target['family']==family }
    {
      'schema'=>1, 'source_sha'=>@scope['source_sha'], 'family'=>family,
      'team'=>ResaleSigning::TEAM, 'group'=>ResaleSigning::GROUP,
      'profiles'=>selected.each_with_index.map do |target,index|
        pin=@scope['native_profiles'].find{|row|row['bundle_id']==target['bundle_id']}
        {'bundle_id'=>target['bundle_id'], 'target'=>target['target'],
         'uuid'=>pin['uuid'], 'name'=>pin['name'], 'native_profile_id'=>pin['native_profile_id'], 'sha256'=>pin['sha256'],
         'profile_type'=>target['profile_type'], 'verified'=>true, 'native_readback_verified'=>true,
         'certificate_sha256'=>certificate['sha256']}
      end,
      'signing_certificate'=>certificate,
      'installer_certificate'=>family=='macos' ? {
        'sha256'=>ResaleSigning::APPROVED_INSTALLER, 'sha1'=>'d'*40, 'type'=>'MAC_INSTALLER_DISTRIBUTION', 'verified'=>true
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
    blocked_without_mutation('restore_exact_native_profile_pin_mismatch','ios',material)
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
    [ResaleSigning::OLD_SOURCE,'dfa0263c85709eea23c7766580fb79ee9bdc5820'].each do |source|
      @scope['source_sha']=source
      blocked_without_mutation('scope_identity_or_source_mismatch')
    end
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

  def test_build1_scope_and_project_refuse
    @scope['build']='1';blocked_without_mutation('scope_version_mismatch')
    @scope['build']='5';@project.targets[0].build_configurations[0].build_settings['CURRENT_PROJECT_VERSION']='1'
    blocked_without_mutation('project_version_or_minimum_os_mismatch')
  end
  def test_scope_requires_new_frozen_source_and_owner_final_artwork
    ['source_frozen','final_artwork_owner_approved'].each do |field|
      @scope[field]=false;blocked_without_mutation('reviewed_frozen_source_and_artwork_required');@scope[field]=true
    end
  end
  def test_reviewed_new_source_is_dynamic_but_manifest_must_match
    @scope['source_sha']='2'*40
    assert_equal '2'*40,ResaleSigning.scope_plan(@scope,manifest('ios'),'ios')['source_sha']
    material=manifest('ios');material['source_sha']='5'*40
    blocked_without_mutation('restore_manifest_scope_mismatch','ios',material)
  end
  def test_same_team_unapproved_distribution_leaf_refuses
    material=manifest('ios');material['signing_certificate']['sha256']='a'*64
    blocked_without_mutation('validated_distribution_certificate_missing','ios',material)
  end
  def test_same_team_unapproved_installer_leaf_refuses
    material=manifest('macos');material['installer_certificate']['sha256']='c'*64
    blocked_without_mutation('validated_mac_installer_certificate_missing','macos',material)
  end
  def test_exact_native_profile_hash_id_name_and_uuid_refuse_changes
    ['sha256','native_profile_id','name','uuid'].each do |field|
      material=manifest('ios');material['profiles'][0][field]=field=='uuid' ? '00000000-0000-0000-0000-000000000001' : 'changed'
      blocked_without_mutation('restore_exact_native_profile_pin_mismatch','ios',material)
    end
  end
  def test_native_readback_required_in_restore
    material=manifest('ios');material['profiles'][0]['native_readback_verified']=false
    blocked_without_mutation('restore_exact_native_profile_pin_mismatch','ios',material)
  end
  def test_scope_native_profile_set_and_readback_cannot_be_weakened
    pin=@scope['native_profiles'].pop;blocked_without_mutation('scope_exact_native_profile_set_required');@scope['native_profiles'] << pin
    @scope['native_profiles'][0]['native_readback_verified']=false;blocked_without_mutation('scope_native_profile_identity_mismatch')
  end
  def test_store_only_ad_hoc_mode_refuses_before_mutation
    before=snapshot
    error=assert_raises(ResaleSigning::GuardError){ResaleSigning.configure_in_memory(@project,@scope,manifest('ios'),'ios','ad-hoc')}
    assert_equal 'store_distribution_only',error.message;assert_equal before,snapshot
  end
end
