require 'json'
require 'time'
require_relative 'testflight_groups'

# This route changes only the existing group's relationship to this processed
# build. It never builds/uploads, changes compliance, or creates groups/testers.
module BunwayPhoneGroupRepair
  IDENTIFIER = 'com.julienbell.bunway'.freeze
  VERSION = '0.4.1'.freeze
  NUMBER = '7'.freeze

  # Fastlane has independent API-level and transport-level retry loops. Scope
  # both overrides to this fresh mutation client, preserving the normal GET
  # client and the authentication/TLS stack. TokenRefreshMiddleware refreshes
  # before a request; it does not resend after a response.
  module SingleAttemptRetries
    protected

    def with_asc_retry(*)
      yield
    end

    def with_retry(*)
      yield
    end
  end

  def self.mutation_client(recorder: nil)
    token = Spaceship::ConnectAPI.token
    raise BunwayTestFlightGroups::Invalid, 'The existing authenticated API token is required.' unless token
    client = Spaceship::ConnectAPI::TestFlight::Client.new(token: token)
    client.extend(SingleAttemptRetries)
    # The SDK's formatted exception omits Apple's error code. Record the
    # response body before its normal status/error handling; never headers.
    client.define_singleton_method(:handle_error) do |response|
      recorder.record('assignment_http_response', status: response.status, body: response.body) if recorder
      super(response)
    end
    client.singleton_class.send(:protected, :handle_error)
    client.client.options.timeout = 30
    client.client.options.open_timeout = 30
    client
  end

  class Recorder
    def initialize(path:, directory:, secrets: [])
      root = File.realpath(directory)
      destination = File.expand_path(path)
      unless File.realpath(File.dirname(destination)) == root && File.basename(destination) == 'bunway-phone-group-repair-api.log'
        raise BunwayTestFlightGroups::Invalid, 'Use the private runner directory for group repair diagnostics.'
      end
      @secrets = secrets.select { |value| value.is_a?(String) && !value.empty? }.sort_by { |value| -value.length }
      @file = File.open(destination, File::WRONLY | File::CREAT | File::EXCL, 0o600)
    end

    def record(stage, fields = {})
      line = JSON.generate(redact(time: Time.now.utc.iso8601, stage: stage, fields: fields))
      @file.puts(line)
      @file.flush
    end

    def redact(value)
      case value
      when Hash
        value.each_with_object({}) { |(key, item), result| result[key] = redact(item) }
      when Array
        value.map { |item| redact(item) }
      when String
        result = value.dup
        @secrets.each { |secret| result = result.gsub(secret, '[credential redacted]') }
        result = result.gsub(/-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----/m, '[credential redacted]')
        result = result.gsub(/Bearer\s+[A-Za-z0-9._~+\/-]+/i, 'Bearer [credential redacted]')
        result.gsub(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/, '[credential redacted]')
      else
        value
      end
    end

    def close
      @file.close unless @file.closed?
    end
  end

  class Client < BunwayTestFlightGroups::Client
    def initialize(recorder: nil)
      @recorder = recorder
    end

    def builds(app, version, number, platform)
      Spaceship::ConnectAPI::Build.all(app_id: app.id, version: version,
        build_number: number, platform: platform, processing_states: 'VALID',
        includes: 'app,preReleaseVersion,buildBetaDetail', limit: 30)
    end

    def assign(build, group)
      # Direct original SDK relationship method on the separate one-attempt
      # client. Do not swap any global client/token or invoke the retrying
      # global Build.add_beta_groups path.
      BunwayPhoneGroupRepair.mutation_client(recorder: @recorder).add_beta_groups_to_build(build_id: build.id, beta_group_ids: [group.id])
    end
  end

  class ObservedClient
    def initialize(client, recorder, configured_group_id)
      @client = client
      @recorder = recorder
      @membership_reads = 0
      @posts = 0
      @configured_group_id = configured_group_id
    end

    def attribute(object, name)
      object.respond_to?(name) ? object.public_send(name) : nil
    end

    def request(stage)
      yield
    rescue StandardError => error
      # Detailed Apple response stays in the owner-only encrypted diagnostic.
      # The normal console contains only fixed workflow status messages.
      @recorder.record(stage + '_error', exception_class: error.class.name, message: error.message)
      raise
    end

    def find_app(identifier)
      app = request('find_app') { @client.find_app(identifier) }
      @recorder.record('find_app', exact_bundle: app && app.bundle_id == IDENTIFIER)
      app
    end

    def groups_for_app(app)
      groups = request('groups_for_app') { @client.groups_for_app(app) }
      @recorder.record('groups_for_app', groups: groups.map { |group| {
        id: group.id, configured_group: group.id == @configured_group_id, is_internal_group: group.is_internal_group,
        has_access_to_all_builds: attribute(group, :has_access_to_all_builds)
      } })
      groups
    end

    def builds(app, version, number, platform)
      builds = request('builds') { @client.builds(app, version, number, platform) }
      @recorder.record('builds', candidates: builds.map { |build|
        detail = attribute(build, :build_beta_detail)
        { id: build.id, version: build.app_version, number: build.version,
          processing_state: build.processing_state, expired: build.expired,
          uses_non_exempt_encryption: attribute(build, :uses_non_exempt_encryption),
          internal_build_state: attribute(detail, :internal_build_state),
          external_build_state: attribute(detail, :external_build_state) }
      })
      builds
    end

    def group_build_ids(group)
      @membership_reads += 1
      ids = request('group_membership') { @client.group_build_ids(group) }
      @recorder.record('group_membership', read: @membership_reads, group: group.id, build_ids: ids)
      ids
    end

    def assign(build, group)
      @posts += 1
      @recorder.record('assignment_attempt', count: @posts, build: build.id, group: group.id)
      result = request('assignment') { @client.assign(build, group) }
      @recorder.record('assignment_response', received: true)
      result
    end
  end

  def self.run!(version:, number:, group_id:, recorder:, client: nil, sleeper: ->(seconds) { Kernel.sleep(seconds) })
    unless version == VERSION && number == NUMBER
      raise BunwayTestFlightGroups::Invalid, 'This reviewed repair selects only the existing Bunway phone 0.4.1 (7) build.'
    end
    recorder.record('repair_start', bundle: IDENTIFIER, version: version, number: number,
                    platform: 'IOS', changes_compliance: false, uploads_package: false)
    client ||= Client.new(recorder: recorder)
    result = BunwayTestFlightGroups.assign!(identifier: IDENTIFIER, group_id: group_id,
      version: version, number: number, platform: 'IOS', client: ObservedClient.new(client, recorder, group_id), sleeper: sleeper)
    recorder.record('repair_complete', relationship_confirmed: true, result: result)
    result
  rescue StandardError => error
    recorder.record('repair_failed', exception_class: error.class.name, message: error.message)
    raise
  end
end
