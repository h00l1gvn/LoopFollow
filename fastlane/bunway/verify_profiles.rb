# Local profile checks only. This helper never modifies the Apple developer portal.
require 'open3'
require 'rexml/document'
require 'time'

module BunwayProfileCheck
  GROUP = 'group.com.julienbell.bunway'.freeze
  CONTAINER = 'iCloud.com.julienbell.bunway'.freeze
  def self.plist_value(node)
    case node.name
    when 'dict'
      nodes = node.elements.to_a; values = {}
      nodes.each_slice(2) { |key, value| values[key.text] = plist_value(value) }
      values
    when 'array' then node.elements.map { |entry| plist_value(entry) }
    when 'true' then true
    when 'false' then false
    when 'integer' then node.text.to_i
    else node.text.to_s
    end
  end
  def self.decode(path)
    xml, _error, status = Open3.capture3('/usr/bin/security', 'cms', '-D', '-i', path)
    raise "Cannot decode the provisioning profile for this Bunway target." unless status.success?
    document = REXML::Document.new(xml)
    plist_value(document.elements['plist/dict'])
  rescue REXML::ParseException
    raise "The Bunway provisioning profile could not be read."
  end
  def self.validate(profile, identifier, team, cloud: false, group: false, push: false, weather: false, environment: 'Production', device: nil)
    entitlements = profile['Entitlements'] || {}; failures = []
    failures << 'wrong Apple team' unless Array(profile['TeamIdentifier']).include?(team)
    application = entitlements['application-identifier'] || entitlements['com.apple.application-identifier']
    failures << 'wrong or wildcard App ID' unless application && application.end_with?(".#{identifier}")
    failures << 'expired profile' unless Time.iso8601(profile['ExpirationDate']).utc > Time.now.utc
    failures << 'development-only signing' if entitlements['get-task-allow'] == true && environment == 'Production'
    failures << 'missing App Group' if group && !Array(entitlements['com.apple.security.application-groups']).include?(GROUP)
    if cloud
      failures << 'missing CloudKit service' unless Array(entitlements['com.apple.developer.icloud-services']).include?('CloudKit')
      containers = Array(entitlements['com.apple.developer.icloud-container-identifiers']) + Array(entitlements['com.apple.developer.icloud-container-development-container-identifiers'])
      failures << 'missing CloudKit container' unless containers.include?(CONTAINER)
      available = Array(entitlements['com.apple.developer.icloud-container-environment'])
      failures << "CloudKit #{environment} environment is not authorized" unless available.include?(environment)
    end
    failures << 'Push Notifications are not Production' if push && environment == 'Production' && entitlements['aps-environment'] != 'production'
    failures << 'missing WeatherKit' if weather && entitlements['com.apple.developer.weatherkit'] != true
    failures << 'Bryan’s device is not included in this ad-hoc profile' if device && !Array(profile['ProvisionedDevices']).include?(device)
    raise "#{identifier}: #{failures.join('; ')}. Configure Apple capabilities and refresh this profile before delivering." unless failures.empty?
    true
  rescue ArgumentError, TypeError
    raise "#{identifier}: the provisioning profile has an invalid expiration date."
  end
  def self.find_path(identifier, type, expected_name)
    supplied = ENV["sigh_#{identifier}_#{type}_profile-path"]
    return supplied if supplied && File.file?(supplied)
    # Handle old and current Xcode locations without printing profile contents.
    roots = ['~/Library/Developer/Xcode/UserData/Provisioning Profiles', '~/Library/MobileDevice/Provisioning Profiles']
    roots.each do |root|
      Dir.glob(File.join(File.expand_path(root), '*.mobileprovision')).each do |path|
        begin
          return path if decode(path)['Name'] == expected_name
        rescue StandardError
          next
        end
      end
    end
    raise "No downloaded provisioning profile was found for #{identifier}."
  end
end
