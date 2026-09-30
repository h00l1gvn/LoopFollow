# Inspect an exported IPA locally without printing profiles, device IDs or entitlements.
require_relative 'verify_profiles'
require 'tmpdir'

module BunwayExportCheck
  IDS = ['com.julienbell.bunway', 'com.julienbell.bunway.watchkitapp', 'com.julienbell.bunway.widget'].freeze
  class Invalid < StandardError; end

  def self.validate_signed(entitlements, identifier, team, profile)
    failures = []
    actual = entitlements['application-identifier']
    authorized = (profile['Entitlements'] || {})['application-identifier']
    failures << 'wrong explicit App ID' unless actual == authorized && actual.to_s.end_with?(".#{identifier}")
    failures << 'wrong signing team' unless entitlements['com.apple.developer.team-identifier'] == team
    failures << 'development signing' if entitlements['get-task-allow'] == true
    failures << 'wrong App Group' unless Array(entitlements['com.apple.security.application-groups']) == [BunwayProfileCheck::GROUP]
    if identifier != IDS.last
      failures << 'missing CloudKit service' unless Array(entitlements['com.apple.developer.icloud-services']).include?('CloudKit')
      failures << 'wrong CloudKit container' unless Array(entitlements['com.apple.developer.icloud-container-identifiers']) == [BunwayProfileCheck::CONTAINER]
      failures << 'CloudKit must be Production' unless entitlements['com.apple.developer.icloud-container-environment'] == 'Production'
    end
    if identifier == IDS.first
      failures << 'Push Notifications must be Production' unless entitlements['aps-environment'] == 'production'
      failures << 'missing WeatherKit' unless entitlements['com.apple.developer.weatherkit'] == true
    end
    raise Invalid, "#{identifier}: #{failures.join('; ')}" unless failures.empty?
    true
  end

  def self.validate_profile(profile, identifier, team, device)
    begin
      BunwayProfileCheck.validate(profile, identifier, team,
        cloud: identifier != IDS.last, group: true,
        push: identifier == IDS.first, weather: identifier == IDS.first,
        environment: 'Production', device: identifier == IDS[1] ? nil : device)
    rescue RuntimeError => error
      raise Invalid, error.message
    end
    unless profile['ProvisionedDevices'].is_a?(Array) && !profile['ProvisionedDevices'].empty? && profile['ProvisionsAllDevices'] != true
      raise Invalid, "#{identifier}: exported profile must be ad-hoc distribution."
    end
    true
  end

  def self.validate_versions(infos)
    unless infos.keys.sort == IDS.sort
      raise Invalid, 'The exported phone must contain exactly its expected Watch and Widget companions.'
    end
    versions = infos.values.map { |info| [info['CFBundleShortVersionString'].to_s, info['CFBundleVersion'].to_s] }
    unless versions.uniq.length == 1 && versions.first.all? { |value| !value.empty? }
      raise Invalid, 'Phone, Watch and Widget version/build numbers must match.'
    end
    true
  end

  def self.read_plist(path)
    xml, _error, status = Open3.capture3('/usr/bin/plutil', '-convert', 'xml1', '-o', '-', path)
    raise Invalid, 'An exported bundle property list could not be read.' unless status.success?
    BunwayProfileCheck.plist_value(REXML::Document.new(xml).elements['plist/dict'])
  rescue REXML::ParseException
    raise Invalid, 'An exported bundle property list was malformed.'
  end

  def self.verify(path, team, device)
    raise Invalid, 'TEAMID and the registered hardware device secret are required.' unless !team.to_s.empty? && device.to_s.match?(/\A(?:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40})\z/)
    Dir.mktmpdir('bunway-export-') do |temporary|
      _out, _error, status = Open3.capture3('/usr/bin/unzip', '-q', path, '-d', temporary)
      raise Invalid, 'The exported IPA could not be extracted.' unless status.success?
      phones = Dir.glob(File.join(temporary, 'Payload', '*.app'))
      raise Invalid, 'The exported IPA must contain one phone app.' unless phones.length == 1
      phone = phones.first
      _out, _error, status = Open3.capture3('/usr/bin/codesign', '--verify', '--deep', '--strict', phone)
      raise Invalid, 'The exported app signature or a nested signature did not verify.' unless status.success?
      infos = {}
      bundles = [phone] + Dir.glob(File.join(phone, '**', '*.app')) + Dir.glob(File.join(phone, '**', '*.appex'))
      bundles.each do |bundle|
        info = read_plist(File.join(bundle, 'Info.plist'))
        identifier = info['CFBundleIdentifier']
        raise Invalid, 'An unexpected or duplicate embedded bundle was exported.' unless IDS.include?(identifier) && !infos.key?(identifier)
        infos[identifier] = info
        profile = BunwayProfileCheck.decode(File.join(bundle, 'embedded.mobileprovision'))
        validate_profile(profile, identifier, team, device)
        xml, _error, status = Open3.capture3('/usr/bin/codesign', '--display', '--entitlements', '-', '--xml', bundle)
        raise Invalid, 'Signed entitlements could not be extracted.' unless status.success?
        entitlements = BunwayProfileCheck.plist_value(REXML::Document.new(xml).elements['plist/dict'])
        validate_signed(entitlements, identifier, team, profile)
      end
      validate_versions(infos)
    end
    true
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    BunwayExportCheck.verify(ARGV.fetch(0), ENV['TEAMID'], ENV['BUNWAY_BRYAN_UDID'])
    puts 'Verified all three signed Bunway bundles, ad-hoc registration and Production CloudKit.'
  rescue BunwayExportCheck::Invalid => error
    warn "Bunway export verification: #{error.message}"; exit 1
  rescue StandardError
    warn 'Bunway export verification could not inspect the IPA. No profile or entitlement contents were printed.'; exit 1
  end
end
