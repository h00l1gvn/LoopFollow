#!/usr/bin/env ruby
# Runner-only manual signing configuration. No keychain import, signing, build, export or upload.
require 'json'
require 'optparse'
require 'digest'
require 'pathname'
require 'open3'
require 'fileutils'

module ResaleSigning
  TEAM = 'N8K8G6QA36'.freeze
  GROUP = 'group.com.julienbell.ResaleBurrow'.freeze
  OLD_SOURCE = '1162d8a1f4fdda1c2678220c9102f9c03ab48c33'.freeze
  TOOLING = '6e6f97a1b18781c7ffc6cf620f15293c29515fc5'.freeze
  BASE = 'com.julienbell.ResaleBurrow'.freeze
  APPROVED_CERT = '83418f42dfecf6e1709ea5528fb0f4f42b5df1189365147dc86747ace39de772'.freeze
  APPROVED_INSTALLER = '99d5b88d90d30283082420947296a6afa8e784cd5df9781c9eade2f7720f4df2'.freeze
  PROFILE_TYPES = {'ios'=>'IOS_APP_STORE','macos'=>'MAC_APP_STORE','tvos'=>'TVOS_APP_STORE'}.freeze
  PLATFORMS = {'iphoneos'=>'iOS','watchos'=>'watchOS','macosx'=>'macOS','appletvos'=>'tvOS'}.freeze
  EXACT = {
    'ResaleBurrowIOS'=>[BASE,'ios','iphoneos','IPHONEOS_DEPLOYMENT_TARGET','17.0'],
    'ResaleBurrowIOSWidgets'=>[BASE+'.widgets','ios','iphoneos','IPHONEOS_DEPLOYMENT_TARGET','17.0'],
    'ResaleBurrowWatch'=>[BASE+'.watch','ios','watchos','WATCHOS_DEPLOYMENT_TARGET','10.0'],
    'ResaleBurrowWatchWidgets'=>[BASE+'.watch.widgets','ios','watchos','WATCHOS_DEPLOYMENT_TARGET','10.0'],
    'ResaleBurrowMac'=>[BASE+'.mac','macos','macosx','MACOSX_DEPLOYMENT_TARGET','13.0'],
    'ResaleBurrowMacWidgets'=>[BASE+'.mac.widgets','macos','macosx','MACOSX_DEPLOYMENT_TARGET','13.0'],
    'ResaleBurrowTV'=>[BASE+'.tv','tvos','appletvos','TVOS_DEPLOYMENT_TARGET','17.0']
  }.freeze
  class GuardError < StandardError; end
  def self.require_guard(value, code); raise GuardError,code unless value; end
  def self.fingerprint(value, length); value.is_a?(String) && value.match?(/\A[0-9a-f]{#{length}}\z/); end
  def self.private_write(path, value)
    FileUtils.mkdir_p(File.dirname(path)); require_guard(!File.symlink?(path),'unsafe_output_path')
    File.open(path,File::WRONLY|File::CREAT|File::TRUNC,0600){|f| f.chmod(0600);f.write(value)}
  end
  def self.scope_plan(scope, manifest, family, distribution='app-store')
    require_guard(%w[ios macos tvos].include?(family),'unsupported_family')
    require_guard(distribution=='app-store','store_distribution_only')
    require_guard(scope['team']==TEAM && scope['group']==GROUP && fingerprint(scope['source_sha'],40) && scope['source_sha']!=OLD_SOURCE && scope['tooling_sha']==TOOLING,'scope_identity_or_source_mismatch')
    require_guard(scope['source_frozen']==true && scope['final_artwork_owner_approved']==true,'reviewed_frozen_source_and_artwork_required')
    require_guard(scope['version']=='0.1.0' && scope['build'].to_s=='3','scope_version_mismatch')
    targets=scope['targets'];require_guard(targets.is_a?(Array) && targets.size==7,'scope_targets_mismatch')
    require_guard(targets.map{|t|t['target']}.sort==EXACT.keys.sort,'scope_targets_mismatch')
    targets.each do |target|
      id,fam,sdk,_,minimum=EXACT[target['target']]
      profile_types=[PROFILE_TYPES[fam]]
      require_guard(target['bundle_id']==id && target['family']==fam && target['minimum_os']==minimum && target['platform']==PLATFORMS[sdk] && profile_types.include?(target['profile_type']),'scope_target_identity_mismatch')
    end
    require_guard(manifest['schema']==1 && manifest['source_sha']==scope['source_sha'] && manifest['family']==family && manifest['team']==TEAM && manifest['group']==GROUP,'restore_manifest_scope_mismatch')
    certificate=manifest['signing_certificate']
    require_guard(certificate.is_a?(Hash) && certificate['verified']==true && certificate['type']=='DISTRIBUTION' && certificate['sha256']==APPROVED_CERT && fingerprint(certificate['sha1'],40),'validated_distribution_certificate_missing')
    require_guard(!manifest.key?('distribution') || manifest['distribution']=='app-store','restore_distribution_mismatch')
    native=scope['native_profiles']
    require_guard(native.is_a?(Array) && native.size==7 && native.map{|p|p['bundle_id']}.sort==EXACT.values.map(&:first).sort,'scope_exact_native_profile_set_required')
    require_guard(native.map{|p|p['native_profile_id']}.uniq.size==7 && native.map{|p|p['uuid']}.uniq.size==7,'scope_native_profile_ids_or_uuid_duplicate')
    pins={}
    native.each do |pin|
      target=targets.find{|t|t['bundle_id']==pin['bundle_id']}
      require_guard(pin['target']==target['target'] && pin['profile_type']==target['profile_type'] && pin['native_readback_verified']==true,'scope_native_profile_identity_mismatch')
      require_guard(pin['native_profile_id'].is_a?(String) && pin['native_profile_id'].match?(/\A[A-Za-z0-9_-]{1,80}\z/) && fingerprint(pin['sha256'],64),'scope_native_profile_content_pin_invalid')
      require_guard(pin['uuid'].is_a?(String) && pin['uuid'].match?(/\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i),'scope_native_profile_uuid_invalid')
      require_guard(pin['name'].is_a?(String) && pin['name'].bytesize.between?(1,300) && !pin['name'].match?(/[\x00-\x1f\x7f]/),'scope_native_profile_name_invalid')
      pins[pin['bundle_id']]=pin
    end
    selected=targets.select{|t|t['family']==family};profiles=manifest['profiles']
    require_guard(profiles.is_a?(Array) && profiles.size==selected.size && profiles.map{|p|p['bundle_id']}.sort==selected.map{|t|t['bundle_id']}.sort,'restore_profile_set_mismatch')
    require_guard(profiles.map{|p|p['uuid']}.uniq.size==profiles.size,'restore_profile_uuid_duplicate')
    mapping={}
    selected.each do |target|
      profile=profiles.find{|p|p['bundle_id']==target['bundle_id']}
      expected_type=target['profile_type']
      require_guard(profile['verified']==true && profile['target']==target['target'] && profile['profile_type']==expected_type && profile['certificate_sha256']==certificate['sha256'],'restore_profile_validation_mismatch')
      pin=pins[target['bundle_id']]
      require_guard(profile['native_readback_verified']==true && profile.values_at('native_profile_id','name','sha256','uuid')==pin.values_at('native_profile_id','name','sha256','uuid'),'restore_exact_native_profile_pin_mismatch')
      require_guard(profile['uuid'].is_a?(String) && profile['uuid'].match?(/\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i),'restore_profile_uuid_invalid')
      require_guard(profile['name'].is_a?(String) && profile['name'].bytesize.between?(1,300) && !profile['name'].match?(/[\x00-\x1f\x7f]/),'restore_profile_name_invalid')
      mapping[target['target']]={'bundle_id'=>target['bundle_id'],'uuid'=>profile['uuid'],'name'=>profile['name']}
    end
    installer=manifest['installer_certificate']
    if family=='macos'
      require_guard(installer.is_a?(Hash) && installer['verified']==true && installer['type']=='MAC_INSTALLER_DISTRIBUTION' && installer['sha256']==APPROVED_INSTALLER && fingerprint(installer['sha1'],40),'validated_mac_installer_certificate_missing')
    else
      require_guard(installer.nil?,'unexpected_installer_identity')
    end
    {'source_sha'=>scope['source_sha'],'family'=>family,'distribution'=>distribution,'mapping'=>mapping,'certificate'=>certificate,'installer'=>installer}
  end
  def self.project_preflight(project, plan)
    targets=project.targets
    require_guard(targets.size==7 && targets.map(&:name).sort==EXACT.keys.sort,'project_target_set_mismatch')
    targets.each do |target|
      id,_,sdk,deployment,minimum=EXACT[target.name]
      require_guard(target.build_configurations.map(&:name).sort==%w[Debug Release],'project_configurations_mismatch')
      target.build_configurations.each do |config|
        settings=config.build_settings
        require_guard(settings['PRODUCT_BUNDLE_IDENTIFIER']==id && settings['SDKROOT']==sdk,'project_target_identity_mismatch')
        require_guard(settings['MARKETING_VERSION']=='0.1.0' && settings['CURRENT_PROJECT_VERSION'].to_s=='3' && settings[deployment]==minimum,'project_version_or_minimum_os_mismatch')
        require_guard(settings['DEVELOPMENT_TEAM'].nil? || ['',TEAM].include?(settings['DEVELOPMENT_TEAM']),'project_other_team_present')
        if plan['mapping'].key?(target.name)
          conflict=settings.keys.any?{|key|key.match?(/\A(?:CODE_SIGN_IDENTITY|CODE_SIGN_STYLE|DEVELOPMENT_TEAM|PROVISIONING_PROFILE(?:_SPECIFIER)?)\[/)}
          require_guard(!conflict,'conditional_signing_setting_requires_review')
        end
      end
    end
  end
  def self.configure_in_memory(project, scope, manifest, family, distribution='app-store')
    plan=scope_plan(scope,manifest,family,distribution);project_preflight(project,plan)
    # All identities/configurations/mappings are validated before the first settings mutation.
    unselected=project.targets.reject{|t|plan['mapping'].key?(t.name)}
    before=JSON.generate(unselected.map{|t|[t.name,t.build_configurations.map{|c|[c.name,c.build_settings]}]})
    project.targets.each do |target|
      next unless plan['mapping'].key?(target.name)
      profile=plan['mapping'][target.name]
      target.build_configurations.each do |config|
        config.build_settings.merge!('CODE_SIGN_STYLE'=>'Manual','DEVELOPMENT_TEAM'=>TEAM,'CODE_SIGN_IDENTITY'=>plan['certificate']['sha1'],'PROVISIONING_PROFILE'=>profile['uuid'],'PROVISIONING_PROFILE_SPECIFIER'=>profile['name'])
      end
    end
    after=JSON.generate(unselected.map{|t|[t.name,t.build_configurations.map{|c|[c.name,c.build_settings]}]})
    require_guard(before==after,'unselected_targets_changed')
    plan
  end
  def self.export_options(plan)
    options={'method'=>'app-store-connect','destination'=>'export','signingStyle'=>'manual','teamID'=>TEAM,'signingCertificate'=>plan['certificate']['sha1'],'provisioningProfiles'=>Hash[plan['mapping'].values.map{|p|[p['bundle_id'],p['uuid']]}],'manageAppVersionAndBuildNumber'=>false,'uploadSymbols'=>false}
    options['installerSigningCertificate']=plan['installer']['sha1'] if plan['family']=='macos'
    options
  end
  def self.runner_paths!(options, scope)
    require_guard(ENV['GITHUB_ACTIONS']=='true','runner_only_not_a_local_source_editor')
    require_guard(options.values_at(:checkout,:project,:scope,:manifest,:export_options,:report).all?,'required_arguments_missing')
    checkout=File.realpath(options[:checkout]);project=File.realpath(options[:project])
    allowed=%w[RUNNER_TEMP GITHUB_WORKSPACE].map{|key|ENV[key]}.compact.select{|p|File.directory?(p)}.map{|p|File.realpath(p)}
    require_guard(allowed.any?{|p|checkout.start_with?(p+'/')},'checkout_not_under_runner_workspace')
    require_guard(project==checkout+'/apple/ResaleBurrow.xcodeproj' && !File.symlink?(options[:project]),'project_not_in_exact_private_checkout')
    require_guard(!File.symlink?(File.join(project,'project.pbxproj')),'project_file_symlink_requires_review')
    head,_,status=Open3.capture3('git','-C',checkout,'rev-parse','HEAD');require_guard(status.success? && head.strip==scope['source_sha'],'checkout_frozen_source_mismatch')
    dirty,_,status=Open3.capture3('git','-C',checkout,'status','--porcelain');require_guard(status.success? && dirty.empty?,'checkout_not_clean_before_signing_configuration')
    [checkout,project]
  end
  def self.run_cli(argv)
    options={distribution:'app-store'};parser=OptionParser.new do |p|
      p.banner='bundle exec ruby configure_build2_signing.rb --family ios|macos|tvos --checkout <private runner source> --project <checkout/apple/ResaleBurrow.xcodeproj> --scope <signing scope.json> --manifest <private validated restore.json> --export-options <ExportOptions.plist> --report <private report.json>'
      %i[family checkout project scope manifest export_options report].each do |key|
        p.on('--'+key.to_s.tr('_','-')+' VALUE'){|value|options[key]=value}
      end
      p.on('--distribution VALUE','app-store only'){|value|options[:distribution]=value}
      p.on('--help'){puts p;return 0}
    end
    parser.parse!(argv)
    require_guard(ENV['GITHUB_ACTIONS']=='true','runner_only_not_a_local_source_editor')
    require_guard(options.values_at(:family,:checkout,:project,:scope,:manifest,:export_options,:report).all?,'required_arguments_missing')
    scope=JSON.parse(File.read(options[:scope]));manifest=JSON.parse(File.read(options[:manifest]));scope_plan(scope,manifest,options[:family],options[:distribution])
    checkout,project_path=runner_paths!(options,scope)
    require 'xcodeproj'
    require_guard(Gem.loaded_specs['xcodeproj'].version.to_s=='1.28.1','pinned_xcodeproj_version_required')
    project=Xcodeproj::Project.open(project_path);plan=configure_in_memory(project,scope,manifest,options[:family],options[:distribution])
    pbx=File.join(project_path,'project.pbxproj');before_sha=Digest::SHA256.file(pbx).hexdigest
    # Output artifacts must stay in the runner workspace as well.
    output_paths=options.values_at(:export_options,:report).map{|p|File.expand_path(p)}
    roots=%w[RUNNER_TEMP GITHUB_WORKSPACE].map{|key|ENV[key]}.compact.map{|p|File.expand_path(p)}
    require_guard(output_paths.uniq.size==2 && output_paths.all?{|p|roots.any?{|root|p.start_with?(root+'/')} && !p.start_with?(checkout+'/') && !File.symlink?(p)},'output_not_private_runner_artifact')
    output_paths.each do |path|
      FileUtils.mkdir_p(File.dirname(path));parent=File.realpath(File.dirname(path))
      require_guard(roots.any?{|root|parent==File.realpath(root) || parent.start_with?(File.realpath(root)+'/')} && !parent.start_with?(checkout+'/'),'output_parent_not_private_runner_artifact')
    end
    project.save
    export=export_options(plan);FileUtils.mkdir_p(File.dirname(options[:export_options]));Xcodeproj::Plist.write_to_path(export,options[:export_options]);File.chmod(0600,options[:export_options])
    report={'schema'=>1,'status'=>'runner_project_manual_signing_configured','source_sha'=>scope['source_sha'],'tooling_sha'=>TOOLING,'family'=>options[:family],'distribution'=>options[:distribution],'configured_bundle_ids'=>plan['mapping'].values.map{|p|p['bundle_id']},'project_before_sha256'=>before_sha,'project_after_sha256'=>Digest::SHA256.file(pbx).hexdigest,'restore_manifest_sha256'=>Digest::SHA256.file(options[:manifest]).hexdigest,'export_options_sha256'=>Digest::SHA256.file(options[:export_options]).hexdigest,'unselected_targets_unchanged'=>true,'canonical_source_modified'=>false,'keychain_modified'=>false,'built'=>false,'signed'=>false,'exported'=>false,'uploaded'=>false}
    private_write(options[:report],JSON.pretty_generate(report)+"\n");puts JSON.generate({'status'=>'configured','family'=>options[:family],'configured_target_count'=>plan['mapping'].size,'signed'=>false,'uploaded'=>false});0
  rescue GuardError => error
    puts JSON.generate({'status'=>'blocked','error_code'=>error.message});1
  rescue OptionParser::ParseError,JSON::ParserError,Errno::ENOENT,Errno::EACCES,LoadError
    puts JSON.generate({'status'=>'blocked','error_code'=>'arguments_source_or_pinned_dependency_unavailable'});1
  rescue StandardError
    # No raw exception/path/profile/certificate/account data reaches stdout.
    puts JSON.generate({'status'=>'blocked','error_code'=>'runner_configuration_failed'});1
  end
end
exit ResaleSigning.run_cli(ARGV) if $PROGRAM_NAME==__FILE__
