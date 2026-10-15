# frozen_string_literal: true
# Exact read-only arrival check. No Fastfile, upload, assignment or signing lane.
require 'json'
require 'net/http'
require 'uri'
require 'openssl'

module MooByteMac53ReadOnly
  BUNDLE = 'local.rabbitload.mac'
  VERSION = '1.0'
  BUILD = '53'
  PLATFORM = 'MAC_OS'
  SDK_VERSION = '2.237.0'
  MAX_REQUESTS = 8
  HOST = 'api.appstoreconnect.apple.com'
  class Refused < StandardError; end

  def self.require_check(value, code)
    raise Refused, code unless value
  end

  class Transport
    attr_reader :requests
    def initialize(token, http_factory: nil)
      @token = token
      @http_factory = http_factory || ->(host, port) { Net::HTTP.new(host, port, nil) }
      @requests = 0
    end

    def get(path, parameters = {})
      # IDs are returned only by the fixed Apple API, never accepted as inputs.
      allowed = path == '/v1/apps' || path == '/v1/preReleaseVersions' || path == '/v1/builds' ||
        path == '/v1/betaGroups' || path.match?(%r{\A/v1/builds/[A-Za-z0-9-]{1,80}/(?:betaGroups|buildBetaDetail)\z})
      MooByteMac53ReadOnly.require_check(allowed && parameters.is_a?(Hash), 'read_route_refused')
      @requests += 1
      MooByteMac53ReadOnly.require_check(@requests <= MAX_REQUESTS, 'read_budget_exceeded')
      target = URI::HTTPS.build(host: HOST, path: path, query: parameters.empty? ? nil : URI.encode_www_form(parameters))
      request = Net::HTTP::Get.new(target)
      request['Authorization'] = 'Bearer ' + @token
      request['Accept'] = 'application/json'
      request['User-Agent'] = 'MooByte-Mac53-ReadOnly/1.0'
      MooByteMac53ReadOnly.require_check(request.method == 'GET' && request.body.nil?, 'only_get_permitted')
      http = @http_factory.call(HOST, 443)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.open_timeout = 12
      http.read_timeout = 20
      http.write_timeout = 12 if http.respond_to?(:write_timeout=)
      http.max_retries = 0 if http.respond_to?(:max_retries=)
      response = http.request(request)
      # No redirects, API retry layer or raw response/error logging.
      MooByteMac53ReadOnly.require_check(response.code == '200', 'apple_read_http_' + response.code.to_i.to_s)
      MooByteMac53ReadOnly.require_check(response.body && response.body.bytesize <= 1_000_000, 'read_response_bound')
      body = JSON.parse(response.body)
      MooByteMac53ReadOnly.require_check(body.is_a?(Hash) && !body.key?('errors'), 'apple_read_response_invalid')
      body
    rescue JSON::ParserError
      raise Refused, 'apple_read_json_invalid'
    end
  end

  def self.rows(body, type, bound)
    values = body['data']
    require_check(values.is_a?(Array) && values.length <= bound && values.all? { |row| row.is_a?(Hash) && row['type'] == type && row['id'].is_a?(String) && row['id'].match?(/\A[A-Za-z0-9-]{1,80}\z/) }, 'apple_read_rows_invalid')
    require_check(!body.dig('links', 'next'), 'read_pagination_requires_review')
    values
  end

  def self.base_result
    {'version' => VERSION, 'build' => BUILD, 'platform' => PLATFORM, 'lookup_succeeded' => true,
     'app_found' => false, 'exact_prerelease_found' => false, 'exact_build_found' => false,
     'processing_state' => 'UNKNOWN', 'internal_testing_state' => 'UNKNOWN',
     'internal_groups_read_succeeded' => false, 'existing_internal_group_found' => false,
     'existing_internal_group_accesses_all_builds' => false, 'build_linked_internal_group_found' => false,
     'named_group_membership_verified' => false, 'build_upload_or_assignment_performed' => false}
  end

  def self.lookup(client)
    result = base_result
    apps = rows(client.get('/v1/apps', {'filter[bundleId]' => BUNDLE, 'fields[apps]' => 'bundleId', 'limit' => '2'}), 'apps', 2)
    require_check(apps.length <= 1, 'exact_app_ambiguous')
    return result if apps.empty?
    app = apps.first
    require_check(app.dig('attributes', 'bundleId') == BUNDLE, 'exact_bundle_mismatch')
    result['app_found'] = true
    prereleases = rows(client.get('/v1/preReleaseVersions', {'filter[app]' => app['id'], 'filter[platform]' => PLATFORM,
      'filter[version]' => VERSION, 'fields[preReleaseVersions]' => 'version,platform', 'limit' => '2'}), 'preReleaseVersions', 2)
    require_check(prereleases.length <= 1, 'exact_prerelease_ambiguous')
    return result if prereleases.empty?
    prerelease = prereleases.first
    require_check(prerelease.dig('attributes', 'version') == VERSION && prerelease.dig('attributes', 'platform') == PLATFORM, 'exact_prerelease_mismatch')
    result['exact_prerelease_found'] = true
    builds = rows(client.get('/v1/builds', {'filter[app]' => app['id'], 'filter[preReleaseVersion.version]' => VERSION,
      'filter[version]' => BUILD, 'fields[builds]' => 'version,processingState,expired,preReleaseVersion',
      'include' => 'preReleaseVersion', 'fields[preReleaseVersions]' => 'version,platform', 'limit' => '2'}), 'builds', 2)
    require_check(builds.length <= 1, 'exact_build_ambiguous')
    return result if builds.empty?
    build = builds.first
    require_check(build.dig('attributes', 'version') == BUILD && build.dig('relationships', 'preReleaseVersion', 'data', 'id') == prerelease['id'], 'exact_build_mismatch')
    result['exact_build_found'] = true
    state = build.dig('attributes', 'processingState')
    require_check(%w[VALID PROCESSING FAILED INVALID].include?(state), 'build_processing_state_unknown')
    result['processing_state'] = state
    result['expired'] = build.dig('attributes', 'expired') == true
    # Read current group access only. No creation, membership assignment or tester reads.
    begin
      groups = rows(client.get('/v1/betaGroups', {'filter[app]' => app['id'], 'filter[isInternalGroup]' => 'true',
        'fields[betaGroups]' => 'isInternalGroup,hasAccessToAllBuilds', 'limit' => '50'}), 'betaGroups', 50)
      require_check(groups.all? { |group| group.dig('attributes', 'isInternalGroup') == true }, 'internal_group_filter_mismatch')
      linked = rows(client.get('/v1/builds/' + build['id'] + '/betaGroups',
        {'fields[betaGroups]' => 'isInternalGroup,hasAccessToAllBuilds', 'limit' => '50'}), 'betaGroups', 50)
      result['internal_groups_read_succeeded'] = true
      result['existing_internal_group_found'] = !groups.empty?
      result['existing_internal_group_accesses_all_builds'] = groups.any? { |group| group.dig('attributes', 'hasAccessToAllBuilds') == true }
      result['build_linked_internal_group_found'] = linked.any? { |group| group.dig('attributes', 'isInternalGroup') == true && groups.any? { |existing| existing['id'] == group['id'] } }
    rescue Refused
      result['internal_groups_read_succeeded'] = false
    end
    begin
      detail = client.get('/v1/builds/' + build['id'] + '/buildBetaDetail')['data']
      require_check(detail.is_a?(Hash) && detail['type'] == 'buildBetaDetails', 'build_beta_detail_invalid')
      value = detail.dig('attributes', 'internalBuildState')
      allowed = %w[PROCESSING PROCESSING_EXCEPTION MISSING_EXPORT_COMPLIANCE READY_FOR_BETA_TESTING IN_BETA_TESTING EXPIRED INVALID FAILED IN_EXPORT_COMPLIANCE_REVIEW EXPORT_COMPLIANCE_REJECTED]
      result['internal_testing_state'] = allowed.include?(value) ? value : 'UNKNOWN'
    rescue Refused
      result['internal_testing_state'] = 'UNKNOWN'
    end
    result['get_requests'] = client.requests
    result
  end

  def self.auth_values(environment)
    values = %w[FASTLANE_KEY_ID FASTLANE_ISSUER_ID FASTLANE_KEY].map { |name| environment[name] }
    require_check(values.all? { |value| value.is_a?(String) && !value.empty? }, 'existing_ci_key_unavailable')
    # Match the reviewed Fastfile's app_store_connect_api_key action semantics:
    # its default is plain PEM (not base64); literal backslash-n is normalized.
    [values[0].strip, values[1].strip, values[2].gsub('\\n', "\n")]
  end

  def self.sdk_token(environment = ENV)
    # Authentication is local JWT signing through the reviewed locked SDK.
    # It does not call App Store Connect, Fastfile, provisioning or upload APIs.
    require 'fastlane'
    require 'spaceship'
    require_check(Fastlane::VERSION == SDK_VERSION, 'locked_fastlane_version_mismatch')
    values = auth_values(environment)
    token = Spaceship::ConnectAPI::Token.create(key_id: values[0], issuer_id: values[1], key: values[2],
      duration: 300, is_key_content_base64: false, in_house: false)
    require_check(token.text.is_a?(String) && token.text.split('.').length == 3, 'local_sdk_token_invalid')
    token.text
  end

  def self.main
    require_check(ARGV == ['--execute-read-only'], 'explicit_read_only_action_required')
    puts JSON.generate(lookup(Transport.new(sdk_token)))
  rescue Refused => error
    puts JSON.generate({'version' => VERSION, 'build' => BUILD, 'lookup_succeeded' => false, 'safe_error' => error.message,
      'build_upload_or_assignment_performed' => false})
    exit 2
  rescue StandardError
    # Never expose JWT, key material, private Apple IDs, API bodies or stack traces.
    puts JSON.generate({'version' => VERSION, 'build' => BUILD, 'lookup_succeeded' => false,
      'safe_error' => 'read_only_lookup_unavailable', 'build_upload_or_assignment_performed' => false})
    exit 2
  end
end

MooByteMac53ReadOnly.main if $PROGRAM_NAME == __FILE__
