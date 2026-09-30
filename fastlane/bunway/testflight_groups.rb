# Assign only an existing internal group to the exact processed IPA build.
# Group identifiers come from private CI configuration, never source or logs.
module BunwayTestFlightGroups
  class Invalid < StandardError; end
  GROUP_ID = /\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z/.freeze

  class Client
    def find_app(identifier)
      Spaceship::ConnectAPI::App.find(identifier)
    end
    def groups_for_app(app)
      # Fastlane 2.237 scopes this request with filter[app]=app.id and pages it.
      # Its BetaGroup model has no app accessor; this scoped list verifies ownership.
      app.get_beta_groups
    end
    def builds(app, version, number, platform)
      Spaceship::ConnectAPI::Build.all(app_id: app.id, version: version,
        build_number: number, platform: platform, processing_states: 'VALID',
        includes: 'app,preReleaseVersion', limit: 30)
    end
    def group_build_ids(group)
      group.fetch_builds.map(&:id)
    end
    def assign(build, group)
      build.add_beta_groups(beta_groups: [group])
    end
  end

  def self.validate_group_id!(value)
    raise Invalid, 'Configure the existing internal TestFlight group identifier securely.' unless value.is_a?(String) && value.match?(GROUP_ID)
    value.downcase
  end

  def self.package_coordinates(path, analyser: FastlaneCore::IpaFileAnalyser)
    # Fastfile lane code can run inside fastlane/, while gym exports at the CI
    # workspace root. Resolve before calling the SDK outside an action wrapper.
    path = package_path(path)
    version = analyser.fetch_app_version(path).to_s
    number = analyser.fetch_app_build(path).to_s
    pattern = /\A[0-9]+(?:\.[0-9]+){0,2}\z/
    raise Invalid, 'The Bunway IPA must contain its exact version and build number.' unless version.match?(pattern) && number.match?(pattern)
    { version: version, number: number }
  rescue Invalid
    raise
  rescue StandardError
    raise Invalid, 'The Bunway IPA version/build could not be read. No package contents were printed.'
  end

  def self.package_path(path, workspace: ENV['GITHUB_WORKSPACE'])
    File.expand_path(path, workspace.to_s.empty? ? Dir.pwd : workspace)
  end

  def self.assign!(identifier:, group_id:, version:, number:, platform:, client: Client.new, sleeper: ->(seconds) { Kernel.sleep(seconds) })
    group_id = validate_group_id!(group_id)
    raise Invalid, 'The Bunway TestFlight platform was invalid.' unless ['IOS', 'TV_OS'].include?(platform)
    app = client.find_app(identifier)
    raise Invalid, 'The exact Bunway App Store application could not be verified.' unless app && app.bundle_id == identifier
    groups = client.groups_for_app(app).select { |group| group.id == group_id }
    raise Invalid, 'The configured TestFlight group does not belong to the exact Bunway application.' unless groups.length == 1
    group = groups.first
    raise Invalid, 'Bunway delivery requires an existing internal TestFlight group.' unless group.is_internal_group == true

    matches = client.builds(app, version, number, platform).select do |build|
      build.app_id == app.id && build.bundle_id == identifier &&
        build.app_version.to_s == version && build.version.to_s == number &&
        build.pre_release_version && build.pre_release_version.platform == platform &&
        build.processing_state == 'VALID' && build.expired == false
    end
    raise Invalid, 'The exact processed Bunway IPA version/build could not be selected uniquely.' unless matches.length == 1
    build = matches.first
    return :already_assigned if client.group_build_ids(group).include?(build.id)

    begin
      client.assign(build, group)
    rescue StandardError
      # A lost POST response may still have applied the relationship. Read it
      # back instead of repeating the mutation or printing the upstream error.
    end
    [0, 2, 5, 10].each do |delay|
      sleeper.call(delay) if delay > 0
      return :assigned if client.group_build_ids(group).include?(build.id)
    end
    raise Invalid, 'The internal TestFlight group relationship was not confirmed for the exact processed build.'
  rescue Invalid
    raise
  rescue StandardError
    raise Invalid, 'TestFlight group verification could not complete. No group or tester details were printed.'
  end
end
