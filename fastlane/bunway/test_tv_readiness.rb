require 'minitest/autorun'
require_relative 'tv_readiness'

class BunwayTVReadinessTests < Minitest::Test
  TEAM = 'SYNTHETIC_TEAM'.freeze
  Capability = Struct.new(:capability_type, :settings)

  class Bundle
    attr_reader :identifier, :events
    attr_accessor :capabilities, :apply_mutation, :mutation_error
    def initialize(capabilities = [])
      @identifier = BunwayTVReadiness::IDENTIFIER
      @capabilities = capabilities
      @apply_mutation = true
      @events = []
    end
    def get_capabilities
      @events << :read
      capabilities
    end
    def create_capability(type, settings:)
      @events << [:create, type, settings]
      mutate
    end
    def update_capability(type, enabled:, settings:)
      @events << [:update, type, enabled, settings]
      mutate
    end
    def mutate
      raise mutation_error if mutation_error
      return unless apply_mutation
      @capabilities = [Capability.new('ICLOUD', [{'key'=>'ICLOUD_VERSION', 'options'=>[{'key'=>'XCODE_6','enabled'=>true}]}])]
    end
  end

  class Bundles
    attr_reader :identifiers
    def initialize(bundle, readback = bundle)
      @bundle = bundle; @readback = readback; @identifiers = []
    end
    def find(identifier)
      @identifiers << identifier
      @identifiers.length == 1 ? @bundle : @readback
    end
  end

  def ready_capability
    Capability.new('ICLOUD', [{'key'=>'ICLOUD_VERSION', 'options'=>[{'key'=>'XCODE_5','enabled'=>false},{'key'=>'XCODE_6','enabled'=>true}]}])
  end

  def profile
    {'TeamIdentifier'=>[TEAM], 'ExpirationDate'=>(Time.now.utc + 86400).iso8601,
     'Entitlements'=>{'application-identifier'=>"LEGACY_PREFIX.#{BunwayTVReadiness::IDENTIFIER}",
      'get-task-allow'=>false, 'com.apple.developer.icloud-services'=>['CloudKit'],
      'com.apple.developer.icloud-container-identifiers'=>[BunwayProfileCheck::CONTAINER],
      'com.apple.developer.icloud-container-environment'=>['Production']}}
  end

  def run_probe(bundle, allow_enable: false, value: profile, readback: bundle)
    @refreshes = 0
    @bundles = Bundles.new(bundle, readback)
    BunwayTVReadiness.run(bundle_ids: @bundles, team: TEAM, allow_enable: allow_enable,
      refresh_profile: -> { @refreshes += 1; value })
  end

  def test_ready_capability_is_read_back_without_mutation_then_profile_verified
    bundle = Bundle.new([ready_capability])
    proof = run_probe(bundle)
    assert_equal [:read, :read], bundle.events
    assert_equal [BunwayTVReadiness::IDENTIFIER]*2, @bundles.identifiers
    assert_equal 1, @refreshes
    assert_equal false, proof[:capability_changed]
    [:cloudkit_capability_verified,:profile_refreshed,:production_profile_verified,:exact_container_permission_verified].each { |key| assert_equal true, proof[key] }
    assert_equal false, proof[:container_association_changed]
    assert_equal false, proof[:archive_or_upload_performed]
  end

  def test_missing_cloudkit_requires_explicit_enable_before_profile_refresh
    bundle = Bundle.new
    assert_match(/Explicit CloudKit enablement/, assert_raises(BunwayTVReadiness::Invalid) { run_probe(bundle) }.message)
    assert_equal [:read], bundle.events
    assert_equal 0, @refreshes
  end

  def test_missing_capability_is_created_only_on_existing_tv_then_read_back
    bundle = Bundle.new
    proof = run_probe(bundle, allow_enable: true)
    assert_equal true, proof[:capability_changed]
    assert_equal [:read, [:create,'ICLOUD',[{key:'ICLOUD_VERSION', options:[{key:'XCODE_6',enabled:true}]}]], :read], bundle.events
    assert_equal 1, @refreshes
  end

  def test_existing_legacy_or_disabled_cloudkit_is_updated_without_delete_recreate
    [Capability.new('ICLOUD',[{'key'=>'ICLOUD_VERSION','options'=>[{'key'=>'XCODE_5','enabled'=>true}]}]),
     Capability.new('ICLOUD',[{'key'=>'ICLOUD_VERSION','options'=>[{'key'=>'XCODE_6','enabled'=>false}]}])].each do |capability|
      bundle = Bundle.new([capability])
      proof = run_probe(bundle, allow_enable: true)
      assert_equal true, proof[:capability_changed]
      assert_equal :update, bundle.events[1][0]
      assert_equal true, bundle.events[1][2]
      assert_equal :read, bundle.events.last
    end
  end

  def test_successful_mutation_response_is_not_readback_proof
    bundle = Bundle.new; bundle.apply_mutation = false
    assert_match(/independent readback/, assert_raises(BunwayTVReadiness::Invalid) { run_probe(bundle, allow_enable:true) }.message)
    assert_equal 0, @refreshes
    bundle = Bundle.new
    assert_raises(BunwayTVReadiness::Invalid) { run_probe(bundle,allow_enable:true,readback:nil) }
    assert_equal 0, @refreshes
  end

  def test_missing_identifier_is_not_created_and_no_profile_requested
    assert_match(/No identifier was created/, assert_raises(BunwayTVReadiness::Invalid) { run_probe(nil,allow_enable:true) }.message)
    assert_equal 0, @refreshes
    assert_equal [BunwayTVReadiness::IDENTIFIER], @bundles.identifiers
  end

  def test_upstream_errors_are_sanitized_and_no_profile_requested
    bundle = Bundle.new; bundle.mutation_error = 'synthetic-secret-should-not-be-printed'
    error = assert_raises(BunwayTVReadiness::Invalid) { run_probe(bundle,allow_enable:true) }
    refute_includes error.message, bundle.mutation_error
    assert_includes error.message, 'No container association was attempted'
    assert_equal 0, @refreshes
  end

  def test_profile_must_authorize_team_exact_container_cloudkit_and_production
    mutations = [
      ->(value) { value['TeamIdentifier']=['OTHER'] },
      ->(value) { value['Entitlements']['com.apple.developer.icloud-services']=[] },
      ->(value) { value['Entitlements']['com.apple.developer.icloud-container-identifiers']=['other.container'] },
      ->(value) { value['Entitlements']['com.apple.developer.icloud-container-environment']=['Development'] },
      ->(value) { value['ProvisionedDevices']=['synthetic-device'] },
      ->(value) { value['ProvisionsAllDevices']=true }
    ]
    mutations.each do |mutation|
      value = profile; mutation.call(value)
      error = assert_raises(BunwayTVReadiness::Invalid) { run_probe(Bundle.new([ready_capability]),value:value) }
      assert_match(/refreshed TV Store profile/, error.message)
      assert_equal 1, @refreshes
      refute_includes error.message, 'SYNTHETIC_TEAM'
    end
  end

  def test_missing_team_stops_before_any_apple_operation
    bundle = Bundle.new([ready_capability]); bundles=Bundles.new(bundle)
    assert_raises(BunwayTVReadiness::Invalid) {
      BunwayTVReadiness.run(bundle_ids:bundles,team:'',refresh_profile:->{ flunk 'must not refresh' })
    }
    assert_empty bundles.identifiers
    assert_empty bundle.events
  end
end
