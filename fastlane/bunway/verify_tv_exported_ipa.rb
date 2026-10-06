# Inspect an actual Bunway TV Store IPA without printing profiles or signing data.
require_relative 'verify_profiles'
require 'tmpdir'

module BunwayTVExportCheck
  IDENTIFIER = 'com.julienbell.bunway.tv'.freeze
  class Invalid < StandardError; end

  def self.validate_profile(profile, team)
    begin
      BunwayProfileCheck.validate(profile, IDENTIFIER, team, cloud: true, environment: 'Production')
    rescue RuntimeError => error
      raise Invalid, error.message
    end
    if profile.key?('ProvisionedDevices') || profile['ProvisionsAllDevices'] == true
      raise Invalid, 'Bunway TV must use App Store distribution, not ad-hoc or enterprise provisioning.'
    end
    true
  end

  def self.validate_signed(entitlements, team, profile)
    failures = []
    actual = entitlements['application-identifier']
    authorized = (profile['Entitlements'] || {})['application-identifier']
    failures << 'wrong explicit App ID' unless actual == authorized && actual.to_s.end_with?(".#{IDENTIFIER}") && !actual.to_s.include?('*')
    failures << 'wrong signing team' unless entitlements['com.apple.developer.team-identifier'] == team
    failures << 'development signing' if entitlements['get-task-allow'] == true
    failures << 'missing CloudKit service' unless Array(entitlements['com.apple.developer.icloud-services']).include?('CloudKit')
    failures << 'wrong CloudKit container' unless Array(entitlements['com.apple.developer.icloud-container-identifiers']) == [BunwayProfileCheck::CONTAINER]
    failures << 'CloudKit must be Production' unless entitlements['com.apple.developer.icloud-container-environment'] == 'Production'
    raise Invalid, "Bunway TV: #{failures.join('; ')}" unless failures.empty?
    true
  end

  def self.validate_info(info, version, build)
    failures = []
    failures << 'wrong bundle identifier' unless info['CFBundleIdentifier'] == IDENTIFIER
    failures << 'wrong platform' unless Array(info['CFBundleSupportedPlatforms']) == ['AppleTVOS'] && info['DTPlatformName'] == 'appletvos'
    failures << 'wrong device family' unless Array(info['UIDeviceFamily']) == [3]
    failures << 'wrong reviewed source version' unless info['CFBundleShortVersionString'].to_s == version
    failures << 'wrong selected build' unless info['CFBundleVersion'].to_s == build
    raise Invalid, "Bunway TV: #{failures.join('; ')}" unless failures.empty?
    true
  end

  def self.read_plist(path)
    xml, _error, status = Open3.capture3('/usr/bin/plutil', '-convert', 'xml1', '-o', '-', path)
    raise Invalid, 'The Bunway TV property list could not be read.' unless status.success?
    BunwayProfileCheck.plist_value(REXML::Document.new(xml).elements['plist/dict'])
  rescue REXML::ParseException
    raise Invalid, 'The Bunway TV property list was malformed.'
  end

  def self.verify(path, team, version, build)
    unless !team.to_s.empty? && version.to_s.match?(/\A\d+\.\d+\.\d+\z/) && build.to_s.match?(/\A[1-9]\d*\z/)
      raise Invalid, 'The expected Apple team, reviewed version and selected build are required.'
    end
    path = File.expand_path(path)
    raise Invalid, 'The Bunway TV IPA is missing or is a symlink.' unless File.file?(path) && !File.symlink?(path)
    Dir.mktmpdir('bunway-tv-export-') do |temporary|
      listing, _error, status = Open3.capture3('/usr/bin/unzip', '-Z', '-1', path)
      entries = listing.lines.map(&:strip)
      if !status.success? || entries.empty? || entries.any? { |entry| entry.start_with?('/') || entry.include?('\\') || entry.split('/').include?('..') }
        raise Invalid, 'The Bunway TV archive layout is invalid.'
      end
      _out, _error, status = Open3.capture3('/usr/bin/unzip', '-q', path, '-d', temporary)
      raise Invalid, 'The Bunway TV IPA could not be extracted.' unless status.success?
      apps = Dir.glob(File.join(temporary, 'Payload', '*.app'))
      raise Invalid, 'The exported IPA must contain exactly one Bunway TV app.' unless apps.length == 1
      app = apps.first
      contents = Dir.glob(File.join(app, '**', '*'), File::FNM_DOTMATCH)
      raise Invalid, 'The Bunway TV export contains unexpected symlinks or embedded apps/extensions.' if File.symlink?(app) || contents.any? { |entry| File.symlink?(entry) || entry.end_with?('.app', '.appex') }
      _out, _error, status = Open3.capture3('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
      raise Invalid, 'The Bunway TV app or nested signature did not verify.' unless status.success?
      validate_info(read_plist(File.join(app, 'Info.plist')), version, build)
      profile = BunwayProfileCheck.decode(File.join(app, 'embedded.mobileprovision'))
      validate_profile(profile, team)
      xml, _error, status = Open3.capture3('/usr/bin/codesign', '--display', '--entitlements', '-', '--xml', app)
      raise Invalid, 'Signed Bunway TV entitlements could not be read.' unless status.success?
      entitlements = BunwayProfileCheck.plist_value(REXML::Document.new(xml).elements['plist/dict'])
      validate_signed(entitlements, team, profile)
    end
    true
  rescue REXML::ParseException
    raise Invalid, 'Signed Bunway TV entitlements were malformed.'
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    BunwayTVExportCheck.verify(ARGV.fetch(0), ENV['TEAMID'], ARGV.fetch(1), ARGV.fetch(2))
    puts 'Verified the exact signed Bunway TV Store export and Production CloudKit.'
  rescue BunwayTVExportCheck::Invalid => error
    warn "Bunway TV export verification: #{error.message}"; exit 1
  rescue StandardError
    warn 'Bunway TV export verification could not inspect the IPA. No profile or signing contents were printed.'; exit 1
  end
end
