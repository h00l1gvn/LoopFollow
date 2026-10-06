require_relative 'verify_exported_ipa'
require_relative 'julien_devices'

if $PROGRAM_NAME == __FILE__
  begin
    devices = BunwayJulienDevices.parse(ENV['BUNWAY_JULIEN_DEVICE_UDIDS'])
    devices.each_value { |device| BunwayExportCheck.verify(ARGV.fetch(0), ENV['TEAMID'], device) }
    puts 'Verified Phone, Watch and Widget signatures, Production capabilities and both Julien device profiles.'
  rescue BunwayJulienDevices::Invalid, BunwayExportCheck::Invalid => error
    warn "Bunway personal export verification: #{error.message}"; exit 1
  rescue StandardError
    warn 'Bunway personal export verification failed. Private profiles and device values were not printed.'; exit 1
  end
end
