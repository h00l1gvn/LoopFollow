require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require_relative 'phone_group_repair'

class BunwayPhoneGroupRepairTests < Minitest::Test
  GROUP = '11111111-2222-3333-4444-555555555555'.freeze
  App = Struct.new(:id, :bundle_id)
  Group = Struct.new(:id, :is_internal_group, :has_access_to_all_builds, :app_id)
  Version = Struct.new(:platform)
  Detail = Struct.new(:internal_build_state, :external_build_state)
  Build = Struct.new(:id, :app_id, :bundle_id, :app_version, :version, :pre_release_version,
                     :processing_state, :expired, :uses_non_exempt_encryption, :build_beta_detail)
  class FakeClient
    attr_accessor :app, :groups, :records, :membership, :apply_post, :post_error, :membership_error
    attr_reader :events, :posts
    def initialize
      @app = App.new('app-one', BunwayPhoneGroupRepair::IDENTIFIER)
      @groups = [Group.new(GROUP, true, false, @app.id)]
      @records = [Build.new('build-seven', @app.id, @app.bundle_id, '0.4.1', '7', Version.new('IOS'),
                           'VALID', false, false, Detail.new('READY_FOR_BETA_TESTING', 'READY_FOR_BETA_SUBMISSION'))]
      @membership = []; @posts = 0; @events = []; @apply_post = true
    end
    def find_app(_id); @events << :app; @app; end
    def groups_for_app(app); @events << :groups; @groups.select { |group| group.app_id == app.id }; end
    def builds(*_args); @events << :builds; @records; end
    def group_build_ids(_group)
      @events << :membership
      raise @membership_error if @membership_error
      @membership
    end
    def assign(build, _group)
      @events << :post; @posts += 1
      @membership << build.id if @apply_post
      raise @post_error if @post_error
    end
    def upload(*); raise 'An upload must never be invoked'; end
    def update(*); raise 'Compliance must never be mutated'; end
    def create_beta_group(*); raise 'A group must never be created'; end
    def add_beta_testers(*); raise 'Testers must never be created'; end
  end

  def setup
    @directory = Dir.mktmpdir('bunway-repair-fixture-')
    @path = File.join(@directory, 'bunway-phone-group-repair-api.log')
    @recorder = BunwayPhoneGroupRepair::Recorder.new(path: @path, directory: @directory, secrets: [GROUP])
    @client = FakeClient.new
    @delays = []
  end
  def teardown
    @recorder.close
    FileUtils.remove_entry_secure(@directory)
  end
  def repair(overrides = {})
    BunwayPhoneGroupRepair.run!(**{version: '0.4.1', number: '7', group_id: GROUP,
      recorder: @recorder, client: @client, sleeper: ->(seconds) { @delays << seconds }}.merge(overrides))
  end
  def records
    File.readlines(@path).map { |line| JSON.parse(line) }
  end
  def stage(name)
    records.find { |item| item['stage'] == name }&.fetch('fields')
  end

  def test_get_first_and_one_post_confirm_the_existing_build
    assert_equal :assigned, repair
    assert_equal [:app, :groups, :builds, :membership, :post, :membership], @client.events
    assert_equal 1, @client.posts
    assert_equal true, stage('repair_complete')['relationship_confirmed']
  end
  def test_already_assigned_still_records_actual_fields_without_post
    @client.membership = ['build-seven']
    @client.groups.first.has_access_to_all_builds = true
    assert_equal :already_assigned, repair
    assert_equal 0, @client.posts
    assert_equal true, stage('groups_for_app')['groups'].first['has_access_to_all_builds']
    assert_equal true, stage('groups_for_app')['groups'].first['configured_group']
    candidate = stage('builds')['candidates'].first
    assert_equal false, candidate['uses_non_exempt_encryption']
    assert_equal 'READY_FOR_BETA_TESTING', candidate['internal_build_state']
  end
  def test_wrong_version_or_build_stops_before_any_api_request
    [{version: '0.4.0'}, {number: '8'}].each do |values|
      assert_raises(BunwayTestFlightGroups::Invalid) { repair(values) }
    end
    assert_empty @client.events
    assert_equal 0, @client.posts
  end
  def test_other_app_external_or_duplicate_exact_build_is_rejected_before_post
    @client.app.bundle_id = 'com.example.another'
    assert_raises(BunwayTestFlightGroups::Invalid) { repair }
    @client.app.bundle_id = BunwayPhoneGroupRepair::IDENTIFIER
    @client.groups.first.is_internal_group = false
    assert_raises(BunwayTestFlightGroups::Invalid) { repair }
    @client.groups.first.is_internal_group = true
    @client.records << @client.records.first.dup
    assert_raises(BunwayTestFlightGroups::Invalid) { repair }
    assert_equal 0, @client.posts
  end
  def test_missing_group_is_rejected_before_mutation
    assert_raises(BunwayTestFlightGroups::Invalid) { repair(group_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee') }
    assert_equal 0, @client.posts
  end
  def test_missing_membership_after_post_is_bounded_and_preserves_upstream_error
    @client.apply_post = false
    @client.post_error = RuntimeError.new('synthetic Apple response: STATE_ERROR.MISSING_EXPORT_COMPLIANCE')
    @client.records.first.uses_non_exempt_encryption = nil
    @client.records.first.build_beta_detail.internal_build_state = 'MISSING_EXPORT_COMPLIANCE'
    error = assert_raises(BunwayTestFlightGroups::Invalid) { repair }
    assert_equal 1, @client.posts
    assert_equal [2, 5, 10], @delays
    assert_equal 5, @client.events.count(:membership)
    assert_includes stage('assignment_error')['message'], 'STATE_ERROR.MISSING_EXPORT_COMPLIANCE'
    assert_nil stage('builds')['candidates'].first['uses_non_exempt_encryption']
    assert_equal 'MISSING_EXPORT_COMPLIANCE', stage('builds')['candidates'].first['internal_build_state']
    refute_includes error.message, 'synthetic Apple response'
  end
  def test_lost_post_response_is_not_repeated_when_readback_confirms
    @client.post_error = RuntimeError.new('synthetic lost response')
    assert_equal :assigned, repair
    assert_equal 1, @client.posts
    assert_includes stage('assignment_error')['message'], 'synthetic lost response'
    assert_equal true, stage('repair_complete')['relationship_confirmed']
  end
  def test_failed_membership_get_never_attempts_post
    @client.membership_error = RuntimeError.new('synthetic failed GET')
    assert_raises(BunwayTestFlightGroups::Invalid) { repair }
    assert_equal 0, @client.posts
    assert_equal 'synthetic failed GET', stage('group_membership_error')['message']
  end
  def test_unknown_api_fields_remain_unknown
    @client.groups.first.has_access_to_all_builds = nil
    @client.records.first.uses_non_exempt_encryption = nil
    @client.records.first.build_beta_detail = nil
    repair
    assert_nil stage('groups_for_app')['groups'].first['has_access_to_all_builds']
    assert_nil stage('builds')['candidates'].first['internal_build_state']
    assert_nil stage('builds')['candidates'].first['uses_non_exempt_encryption']
  end
  def test_recorder_redacts_nested_credentials_multiline_keys_and_bearer_tokens
    @recorder.close
    File.unlink(@path)
    secret = "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-KEY\n-----END PRIVATE KEY-----"
    @recorder = BunwayPhoneGroupRepair::Recorder.new(path: @path, directory: @directory, secrets: [secret, GROUP])
    jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJzeW50aGV0aWMifQ.c3ludGhldGlj'
    @recorder.record('synthetic', error: {message: secret + ' Bearer abc.def.ghi ' + jwt, group: GROUP})
    text = File.read(@path)
    refute_includes text, 'SYNTHETIC-KEY'
    refute_includes text, 'abc.def.ghi'
    refute_includes text, GROUP
    refute_includes text, jwt
    assert_equal 0o600, File.stat(@path).mode & 0o777
  end
  def test_recorder_refuses_an_existing_file_or_outside_directory
    assert_raises(Errno::EEXIST) { BunwayPhoneGroupRepair::Recorder.new(path: @path, directory: @directory) }
    sibling = Dir.mktmpdir('bunway-repair-outside-')
    assert_raises(BunwayTestFlightGroups::Invalid) do
      BunwayPhoneGroupRepair::Recorder.new(path: File.join(sibling, File.basename(@path)), directory: @directory)
    end
  ensure
    FileUtils.remove_entry_secure(sibling) if sibling
  end

  def test_api_adapter_requests_actual_beta_detail_relationship
    sdk = Module.new
    api = Class.new
    build = Class.new
    captured = nil
    build.define_singleton_method(:all) { |**arguments| captured = arguments; [] }
    api.const_set(:Build, build)
    sdk.const_set(:ConnectAPI, api)
    Object.const_set(:Spaceship, sdk)
    assert_empty BunwayPhoneGroupRepair::Client.new.builds(@client.app, '0.4.1', '7', 'IOS')
    assert_equal 'app,preReleaseVersion,buildBetaDetail', captured[:includes]
    assert_equal ['app-one', '0.4.1', '7', 'IOS', 'VALID', 30], captured.values_at(:app_id, :version, :build_number, :platform, :processing_states, :limit)
  ensure
    Object.send(:remove_const, :Spaceship) if Object.const_defined?(:Spaceship)
  end
end
