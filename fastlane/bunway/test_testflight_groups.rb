require 'minitest/autorun'
require_relative 'testflight_groups'

class BunwayTestFlightGroupsTests < Minitest::Test
  IDENTIFIER = 'com.julienbell.bunway'.freeze
  GROUP = '11111111-2222-3333-4444-555555555555'.freeze
  App = Struct.new(:id, :bundle_id)
  Group = Struct.new(:id, :is_internal_group, :app_id)
  Version = Struct.new(:platform)
  Build = Struct.new(:id, :app_id, :bundle_id, :app_version, :version, :pre_release_version, :processing_state, :expired)

  class FakeClient
    attr_accessor :app, :groups, :records, :membership, :membership_reads, :post_error, :apply_post
    attr_reader :assignments, :selected_coordinates, :reads
    def initialize
      @app = App.new('app-one', IDENTIFIER)
      @groups = [Group.new(GROUP, true, @app.id)]
      @records = [Build.new('build-five', @app.id, IDENTIFIER, '0.4.0', '5', Version.new('IOS'), 'VALID', false)]
      @membership = []; @membership_reads = nil; @assignments = []; @reads = 0; @apply_post = true
    end
    def find_app(_identifier); @app; end
    def groups_for_app(app); @groups.select { |group| group.app_id == app.id }; end
    def builds(app, version, number, platform)
      @selected_coordinates = [app.id, version, number, platform]
      @records
    end
    def group_build_ids(_group)
      @reads += 1
      return @membership_reads.shift unless @membership_reads.nil? || @membership_reads.empty?
      @membership
    end
    def assign(build, group)
      @assignments << [build.id, group.id]
      @membership << build.id if @apply_post
      raise @post_error if @post_error
    end
  end

  def setup
    @client = FakeClient.new
    @delays = []
  end
  def assign(overrides = {})
    BunwayTestFlightGroups.assign!(**{identifier: IDENTIFIER, group_id: GROUP, version: '0.4.0', number: '5', platform: 'IOS', client: @client, sleeper: ->(seconds) { @delays << seconds }}.merge(overrides))
  end
  def refused
    error = assert_raises(BunwayTestFlightGroups::Invalid) { yield }
    assert_empty @client.assignments
    refute_includes error.message, GROUP
    error
  end

  def test_assigns_only_exact_processed_build_and_verifies_relationship
    assert_equal :assigned, assign
    assert_equal [['build-five', GROUP]], @client.assignments
    assert_equal ['app-one', '0.4.0', '5', 'IOS'], @client.selected_coordinates
    assert_equal 2, @client.reads
  end
  def test_already_assigned_relationship_does_not_repeat_mutation
    @client.membership = ['build-five']
    assert_equal :already_assigned, assign
    assert_empty @client.assignments
    assert_equal 1, @client.reads
  end
  def test_group_from_another_app_is_rejected
    @client.groups.first.app_id = 'different-app'
    refused { assign }
  end
  def test_wrong_configured_group_is_rejected
    refused { assign(group_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee') }
  end
  def test_external_group_is_rejected
    @client.groups.first.is_internal_group = false
    refused { assign }
  end
  def test_app_bundle_identity_must_match
    @client.app.bundle_id = 'com.example.other-app'
    refused { assign }
  end
  def test_build_app_identity_must_match
    @client.records.first.app_id = 'other-app'
    refused { assign }
  end
  def test_build_marketing_version_must_match
    @client.records.first.app_version = '0.3.0'
    refused { assign }
  end
  def test_build_number_must_match_even_if_newer_build_is_available
    @client.records.first.version = '6'
    refused { assign }
  end
  def test_platform_must_match
    @client.records.first.pre_release_version.platform = 'TV_OS'
    refused { assign }
  end
  def test_processing_and_expiration_require_valid_current_build
    @client.records.first.processing_state = 'PROCESSING'
    refused { assign }
    @client.records.first.processing_state = 'VALID'; @client.records.first.expired = true
    refused { assign }
  end
  def test_duplicate_exact_candidates_are_rejected
    @client.records << @client.records.first.dup
    refused { assign }
  end
  def test_missing_relationship_after_mutation_fails_with_bounded_reads
    @client.apply_post = false
    error = assert_raises(BunwayTestFlightGroups::Invalid) { assign }
    assert_equal 1, @client.assignments.length
    assert_equal 5, @client.reads
    assert_equal [2, 5, 10], @delays
    refute_includes error.message, GROUP
  end
  def test_lost_post_response_is_resolved_by_actual_relationship_read
    @client.post_error = RuntimeError.new('synthetic-private-upstream-error')
    assert_equal :assigned, assign
    assert_equal 1, @client.assignments.length
  end
  def test_eventual_relationship_appears_without_repeating_post
    @client.membership_reads = [[], [], ['build-five']]
    assert_equal :assigned, assign
    assert_equal [2], @delays
    assert_equal 1, @client.assignments.length
  end
  def test_upstream_error_is_sanitised
    @client.define_singleton_method(:groups_for_app) { |_app| raise 'synthetic private group/tester details' }
    error = refused { assign }
    refute_includes error.message, 'synthetic'
  end
  def test_invalid_group_configuration_stops_before_reads
    refused { assign(group_id: 'not-a-private-group-id') }
    assert_nil @client.selected_coordinates
  end
  def test_actual_ipa_version_and_build_are_required
    analyser = Object.new
    analyser.define_singleton_method(:fetch_app_version) { |_path| '0.4.0' }
    analyser.define_singleton_method(:fetch_app_build) { |_path| '5' }
    assert_equal({version: '0.4.0', number: '5'}, BunwayTestFlightGroups.package_coordinates('synthetic.ipa', analyser: analyser))
    analyser.define_singleton_method(:fetch_app_build) { |_path| nil }
    assert_raises(BunwayTestFlightGroups::Invalid) { BunwayTestFlightGroups.package_coordinates('synthetic.ipa', analyser: analyser) }
    analyser.define_singleton_method(:fetch_app_build) { |_path| raise 'synthetic package/private details' }
    error = assert_raises(BunwayTestFlightGroups::Invalid) { BunwayTestFlightGroups.package_coordinates('synthetic.ipa', analyser: analyser) }
    refute_includes error.message, 'synthetic'
  end
end
