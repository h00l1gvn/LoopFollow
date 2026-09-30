require 'spaceship'
require 'fastlane/version'
require 'json'
require 'tmpdir'
require 'fileutils'
require_relative 'phone_group_repair'

# Runs under the complete locked release bundle, with an in-memory transport.
# No test-framework dependency, auth credentials, Apple call or real IPA.
class BunwayPhoneGroupSDKTests
  App = Struct.new(:id, :bundle_id)
  Group = Struct.new(:id, :is_internal_group, :has_access_to_all_builds, :app_id)
  Version = Struct.new(:platform)
  Detail = Struct.new(:internal_build_state, :external_build_state)
  Build = Struct.new(:id, :app_id, :bundle_id, :app_version, :version, :pre_release_version,
                     :processing_state, :expired, :uses_non_exempt_encryption, :build_beta_detail)
  Response = Struct.new(:status, :body, :headers)
  Options = Struct.new(:timeout, :open_timeout)
  Request = Struct.new(:body, :headers, :path) do
    def url(value); self.path = value; end
  end
  GROUP = '11111111-2222-3333-4444-555555555555'.freeze
  class Failed < StandardError; end

  class Transport
    attr_reader :options, :attempts, :requests
    def initialize(scenario, state)
      @scenario = scenario; @state = state; @attempts = 0; @requests = []
      @options = Options.new(300, 300)
    end
    def post(_url, _params, _headers)
      request = Request.new(nil, {})
      yield request
      @attempts += 1
      @requests << request
      if @scenario == :timeout || @scenario == :lost_response
        @state[:applied] = true if @scenario == :lost_response
        raise Faraday::TimeoutError, 'synthetic transport timeout'
      end
      raise Faraday::ConnectionFailed, 'synthetic lost connection' if @scenario == :connection
      @state[:applied] = true if @scenario == 204
      body = @scenario == 204 ? '' : {'errors'=>[{'status'=>@scenario.to_s, 'code'=>'SYNTHETIC', 'title'=>'Synthetic response', 'detail'=>'Synthetic test only'}]}
      Response.new(@scenario, body, {'retry-after'=>'0'})
    end
  end

  class ReadClient < BunwayPhoneGroupRepair::Client
    attr_reader :reads
    def initialize(state, recorder:)
      super(recorder: recorder)
      @state = state; @reads = 0
      @app = App.new('synthetic-app', BunwayPhoneGroupRepair::IDENTIFIER)
      @group = Group.new(GROUP, true, false, @app.id)
      @build = Build.new('synthetic-seven', @app.id, @app.bundle_id, '0.4.1', '7', Version.new('IOS'),
                        'VALID', false, nil, Detail.new('READY_FOR_BETA_TESTING','READY_FOR_BETA_SUBMISSION'))
    end
    def find_app(_id); @app; end
    def groups_for_app(_app); [@group]; end
    def builds(*); [@build]; end
    def group_build_ids(_group); @reads += 1; @state[:applied] ? [@build.id] : []; end
  end

  def assert(value)
    @assertions += 1
    raise Failed unless value
  end

  def fixture(scenario, already: false)
    directory = Dir.mktmpdir('bunway-sdk-group-')
    state = {applied: already}
    transport = Transport.new(scenario, state)
    token = Object.new
    api = Spaceship::ConnectAPI::TestFlight::Client.allocate
    api.extend(Spaceship::ConnectAPI::TestFlight::API)
    api.test_flight_request_client = api
    api.instance_variable_set(:@client, transport)
    api.instance_variable_set(:@token, token)
    api.define_singleton_method(:log_request) { |*| nil }
    api.define_singleton_method(:log_response) { |*| nil }
    original_new = Spaceship::ConnectAPI::TestFlight::Client.method(:new)
    original_token = Spaceship::ConnectAPI.method(:token)
    factory_calls = []
    Spaceship::ConnectAPI::TestFlight::Client.define_singleton_method(:new) do |token:|
      factory_calls << token
      api
    end
    Spaceship::ConnectAPI.define_singleton_method(:token) { token }
    path = File.join(directory, 'bunway-phone-group-repair-api.log')
    recorder = BunwayPhoneGroupRepair::Recorder.new(path: path, directory: directory)
    reader = ReadClient.new(state, recorder: recorder)
    outcome = nil
    begin
      outcome = BunwayPhoneGroupRepair.run!(version: '0.4.1', number: '7', group_id: GROUP,
        recorder: recorder, client: reader, sleeper: ->(_seconds) {})
    rescue BunwayTestFlightGroups::Invalid
      outcome = :unconfirmed
    end
    events = File.readlines(path).map { |line| JSON.parse(line) }
    yield transport, reader, events, outcome, factory_calls, token, api
  ensure
    recorder.close if recorder
    Spaceship::ConnectAPI::TestFlight::Client.define_singleton_method(:new, original_new) if original_new
    Spaceship::ConnectAPI.define_singleton_method(:token, original_token) if original_token
    FileUtils.remove_entry_secure(directory) if directory
  end

  def test_original_sdk_transport_sends_exact_relationship_once
    fixture(204) do |transport, reader, events, outcome, factory_calls, token, api|
      assert outcome == :assigned
      assert transport.attempts == 1
      assert reader.reads == 2
      assert !events.any? { |event| event['stage']=='assignment_error' }
      assert events.any? { |event| event['stage']=='assignment_response' && event['fields']['received']==true }
      assert events.any? { |event| event['stage']=='assignment_http_response' && event['fields']=={'status'=>204,'body'=>''} }
      assert factory_calls == [token]
      assert transport.options.timeout == 30 && transport.options.open_timeout == 30
      assert transport.requests.first.path == 'v1/builds/synthetic-seven/relationships/betaGroups'
      assert JSON.parse(transport.requests.first.body) == {'data'=>[{'type'=>'betaGroups','id'=>GROUP}]}
      assert api.method(:with_retry).owner == BunwayPhoneGroupRepair::SingleAttemptRetries
      assert api.method(:with_asc_retry).owner == BunwayPhoneGroupRepair::SingleAttemptRetries
      assert Spaceship::ConnectAPI::APIClient.instance_method(:with_asc_retry).owner != BunwayPhoneGroupRepair::SingleAttemptRetries
      assert Spaceship::Client.instance_method(:with_retry).owner != BunwayPhoneGroupRepair::SingleAttemptRetries
    end
  end

  def test_retryable_http_responses_and_transport_failures_never_repeat_post
    [500, 429, 401, :connection, :timeout].each do |scenario|
      fixture(scenario) do |transport, reader, events, outcome, _factory, _token, _api|
        assert outcome == :unconfirmed
        assert transport.attempts == 1
        assert reader.reads == 5
        assert events.any? { |event| event['stage']=='assignment_error' }
        if scenario.is_a?(Integer)
          response = events.find { |event| event['stage']=='assignment_http_response' }
          assert response && response['fields']['status']==scenario
          assert response['fields']['body']['errors'].first['code']=='SYNTHETIC'
        else
          assert !events.any? { |event| event['stage']=='assignment_http_response' }
        end
      end
    end
  end

  def test_lost_response_reconciles_by_get_without_repeating_http_post
    fixture(:lost_response) do |transport, reader, events, outcome, _factory, _token, _api|
      assert outcome == :assigned
      assert transport.attempts == 1
      assert reader.reads == 2
      assert events.any? { |event| event['stage']=='assignment_error' }
    end
  end

  def test_already_assigned_never_constructs_mutation_client
    fixture(204, already: true) do |transport, reader, _events, outcome, factory, _token, _api|
      assert outcome == :already_assigned
      assert transport.attempts == 0
      assert reader.reads == 1
      assert factory.empty?
    end
  end

  def run
    @assertions = 0
    raise Failed unless Fastlane::VERSION == '2.237.0'
    methods = public_methods.grep(/^test_/).sort
    failures = 0
    methods.each do |name|
      begin
        public_send(name)
      rescue StandardError => error
        failures += 1
        warn "Failed #{name}: #{error.class} (synthetic SDK transport; details omitted)"
      end
    end
    puts "#{methods.length} runs, #{@assertions} assertions, #{failures} failures, 0 errors, 0 skips"
    failures.zero?
  end
end

exit(BunwayPhoneGroupSDKTests.new.run ? 0 : 1)
