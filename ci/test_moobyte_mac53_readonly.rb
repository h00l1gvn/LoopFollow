# frozen_string_literal: true
# Dependency-free neutral tests; --sdk also verifies actual locked SDK auth offline.
require_relative 'moobyte_mac53_readonly'
M = MooByteMac53ReadOnly
def check(value); raise 'neutral_test_failed' unless value; end
def refused
  begin
    yield
  rescue M::Refused
    return
  end
  raise 'expected_read_only_refusal'
end

class NeutralHTTP
  attr_accessor :use_ssl, :verify_mode, :open_timeout, :read_timeout, :write_timeout, :max_retries
  attr_reader :calls
  def initialize(code = '200'); @code = code; @calls = []; end
  def request(request)
    raise 'mutation_request_rejected' unless request.is_a?(Net::HTTP::Get) && request.method == 'GET' && request.body.nil?
    @calls << request
    Struct.new(:code, :body).new(@code, JSON.generate({'data' => []}))
  end
end

class NeutralClient
  attr_reader :requests, :paths
  def initialize(build = '53', platform = 'MAC_OS', state = 'VALID', duplicate = false)
    @build, @platform, @state, @duplicate = build, platform, state, duplicate
    @requests = 0; @paths = []
  end
  def get(path, parameters = {})
    @requests += 1; @paths << [path, parameters]
    case path
    when '/v1/apps'
      {'data' => [{'id' => 'neutral-app', 'type' => 'apps', 'attributes' => {'bundleId' => M::BUNDLE}}]}
    when '/v1/preReleaseVersions'
      {'data' => [{'id' => 'neutral-version', 'type' => 'preReleaseVersions', 'attributes' => {'version' => '1.0', 'platform' => @platform}}]}
    when '/v1/builds'
      row = {'id' => 'neutral-build', 'type' => 'builds', 'attributes' => {'version' => @build, 'processingState' => @state, 'expired' => false},
        'relationships' => {'preReleaseVersion' => {'data' => {'id' => 'neutral-version'}}}}
      {'data' => @duplicate ? [row, row] : [row]}
    when '/v1/betaGroups', '/v1/builds/neutral-build/betaGroups'
      {'data' => [{'id' => 'neutral-internal', 'type' => 'betaGroups', 'attributes' => {'isInternalGroup' => true, 'hasAccessToAllBuilds' => true}}]}
    when '/v1/builds/neutral-build/buildBetaDetail'
      {'data' => {'id' => 'neutral-detail', 'type' => 'buildBetaDetails', 'attributes' => {'internalBuildState' => 'IN_BETA_TESTING'}}}
    else raise 'unexpected_neutral_read'
    end
  end
end

count = 0
http = NeutralHTTP.new
transport = M::Transport.new('neutral-no-secret-token', http_factory: ->(host, port) { check(host == M::HOST && port == 443); http })
transport.get('/v1/apps', {'filter[bundleId]' => M::BUNDLE})
check(http.calls.length == 1 && http.use_ssl && http.verify_mode == OpenSSL::SSL::VERIFY_PEER && http.max_retries == 0); count += 1
%w[/v1/certificates /v1/profiles /v1/betaTesters https://elsewhere.invalid/v1/apps /v1/builds/../betaGroups].each do |path|
  refused { transport.get(path) }
end
check(http.calls.length == 1 && !transport.respond_to?(:post) && !transport.respond_to?(:delete) && !transport.respond_to?(:patch)); count += 1
%w[302 401 403 500].each do |code|
  calls = NeutralHTTP.new(code)
  read = M::Transport.new('neutral', http_factory: ->(_host, _port) { calls })
  refused { read.get('/v1/apps') }; check(calls.calls.length == 1)
end
count += 1
client = NeutralClient.new; result = M.lookup(client)
check(result['exact_build_found'] && result['processing_state'] == 'VALID' && result['internal_testing_state'] == 'IN_BETA_TESTING')
check(result['existing_internal_group_accesses_all_builds'] && result['build_linked_internal_group_found'])
check(!result['named_group_membership_verified'] && !result['build_upload_or_assignment_performed'] && client.requests == 6); count += 1
build_parameters = client.paths.find { |path, _parameters| path == '/v1/builds' }[1]
check(build_parameters['include'] == 'preReleaseVersion' && build_parameters['filter[preReleaseVersion.version]'] == '1.0')
refused { M.lookup(NeutralClient.new('52')) }; refused { M.lookup(NeutralClient.new('53', 'IOS')) }
refused { M.lookup(NeutralClient.new('53', 'MAC_OS', 'VALID', true)) }; count += 1
check(M.lookup(NeutralClient.new('53', 'MAC_OS', 'PROCESSING'))['processing_state'] == 'PROCESSING'); count += 1
absent = Class.new { attr_reader :requests; def initialize; @requests = 0; end; def get(*); @requests += 1; {'data' => []}; end }.new
absence = M.lookup(absent); check(absence['lookup_succeeded'] && !absence['exact_build_found'] && absent.requests == 1); count += 1
budget = M::Transport.new('neutral', http_factory: ->(_host, _port) { NeutralHTTP.new })
M::MAX_REQUESTS.times { budget.get('/v1/apps') }; refused { budget.get('/v1/apps') }; count += 1
values = M.auth_values({'FASTLANE_KEY_ID' => ' NEUTRAL123 ', 'FASTLANE_ISSUER_ID' => ' neutral ', 'FASTLANE_KEY' => 'line1\\nline2'})
check(values == ['NEUTRAL123', 'neutral', "line1\nline2"]); count += 1

sdk_verified = false
if ARGV == ['--sdk']
  # Any network initiated by token creation, including an SDK POST, fails.
  Net::HTTP.prepend(Module.new do
    def request(*); raise 'network_forbidden_in_locked_sdk_token_test'; end
  end)
  key = OpenSSL::PKey::EC.generate('prime256v1')
  token = M.sdk_token({'FASTLANE_KEY_ID' => 'NEUTRAL123', 'FASTLANE_ISSUER_ID' => '00000000-0000-0000-0000-000000000000', 'FASTLANE_KEY' => key.to_pem})
  check(token.split('.').length == 3 && Fastlane::VERSION == '2.237.0')
  escaped = M.sdk_token({'FASTLANE_KEY_ID' => 'NEUTRAL123', 'FASTLANE_ISSUER_ID' => '00000000-0000-0000-0000-000000000000', 'FASTLANE_KEY' => key.to_pem.gsub("\n", '\\n')})
  check(escaped.split('.').length == 3)
  sdk_verified = true; count += 1
elsif !ARGV.empty?
  raise 'unknown_neutral_test_option'
end
puts JSON.generate({'neutral_tests_passed' => count, 'actual_locked_sdk_auth_verified_offline' => sdk_verified,
  'actual_apple_requests' => false, 'mutations' => false})
