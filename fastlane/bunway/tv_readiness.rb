# Bounded readiness only: existing TV identifier/capability and refreshed profile.
# This helper never creates an App ID, associates a container, archives or uploads.
require_relative 'verify_tv_exported_ipa'

module BunwayTVReadiness
  IDENTIFIER = BunwayTVExportCheck::IDENTIFIER
  ICLOUD = 'ICLOUD'.freeze
  VERSION_KEY = 'ICLOUD_VERSION'.freeze
  VERSION_OPTION = 'XCODE_6'.freeze
  class Invalid < StandardError; end

  def self.cloudkit_enabled?(capability)
    return false unless capability
    Array(capability.settings).any? do |setting|
      setting['key'] == VERSION_KEY && Array(setting['options']).any? do |option|
        option['key'] == VERSION_OPTION && option['enabled'] == true
      end
    end
  end

  def self.capability_for(bundle)
    bundle.get_capabilities.find { |capability| capability.capability_type == ICLOUD }
  end

  def self.ensure_capability(bundle_ids:, allow_enable: false)
    bundle = bundle_ids.find(IDENTIFIER)
    raise Invalid, 'The existing Bunway TV identifier could not be found. No identifier was created.' unless bundle && bundle.identifier == IDENTIFIER
    capability = capability_for(bundle)
    changed = false
    unless cloudkit_enabled?(capability)
      raise Invalid, 'Bunway TV CloudKit is not enabled. Explicit CloudKit enablement is required for this probe.' unless allow_enable
      settings = [{key: VERSION_KEY, options: [{key: VERSION_OPTION, enabled: true}]}]
      if capability
        bundle.update_capability(ICLOUD, enabled: true, settings: settings)
      else
        bundle.create_capability(ICLOUD, settings: settings)
      end
      changed = true
    end
    # Independent readback is required even when the mutation call succeeds.
    refreshed = bundle_ids.find(IDENTIFIER)
    unless refreshed && refreshed.identifier == IDENTIFIER && cloudkit_enabled?(capability_for(refreshed))
      raise Invalid, 'Bunway TV CloudKit enablement could not be verified by independent readback.'
    end
    {cloudkit_capability_verified: true, capability_changed: changed}
  rescue Invalid
    raise
  rescue StandardError
    raise Invalid, 'The Bunway TV capability operation failed. No container association was attempted; inspect the encrypted diagnostics.'
  end

  def self.run(bundle_ids:, team:, refresh_profile:, allow_enable: false)
    raise Invalid, 'The intended Apple team is required.' if team.to_s.empty?
    proof = ensure_capability(bundle_ids: bundle_ids, allow_enable: allow_enable)
    profile = refresh_profile.call
    BunwayTVExportCheck.validate_profile(profile, team)
    proof.merge(profile_refreshed: true, production_profile_verified: true,
                exact_container_permission_verified: true,
                container_association_changed: false, archive_or_upload_performed: false)
  rescue Invalid
    raise
  rescue BunwayTVExportCheck::Invalid
    raise Invalid, 'The refreshed TV Store profile does not authorize the expected team, CloudKit container and Production environment. Verify the existing container association in the Developer Portal.'
  rescue StandardError
    raise Invalid, 'The TV profile refresh or verification failed. Inspect the encrypted diagnostics.'
  end
end
