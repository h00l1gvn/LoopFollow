require 'json'

module BunwayJulienDevices
  class Invalid < StandardError; end
  def self.parse(raw)
    begin
      devices = JSON.parse(raw.to_s)
    rescue JSON::ParserError
      raise Invalid, 'Configure the private Julien iPhone and iPad hardware record.'
    end
    unless devices.is_a?(Hash) && devices.keys.sort == ['ipad', 'iphone'] &&
        devices.values.all? { |value| value.is_a?(String) && value.match?(/\A(?:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40})\z/) } &&
        devices.values.uniq.length == 2
      raise Invalid, 'The private device record must contain two distinct registered Julien hardware targets.'
    end
    devices
  end
end
