# frozen_string_literal: true
require 'digest'
require 'open3'
PINS = {
  'Gemfile' => 'c4d7c24a57bd57e7b62143b3af29af6dfc42e407425685ae8b65464e51d91b1f',
  'Gemfile.lock' => '8c21e506e0687cc9e3f6cd02877d5d4f679ab82ffaaec9810c21b7312807625b',
  'ci/moobyte_mac53_readonly.rb' => '581503583c62d5811ad7e3063cdcfb15eee88dbbd1f0f287328ac802d7494699',
  'ci/test_moobyte_mac53_readonly.rb' => '6ebcd0bff51a9e870761ec8315e52da77a052cacc053f9c0e7a9ab3832407515',
}.freeze
PINS.each do |path, expected|
  raise 'read_only_source_pin_mismatch' unless File.file?(path) && !File.symlink?(path) && Digest::SHA256.file(path).hexdigest == expected
end
changed, status = Open3.capture2('git','diff','--name-only','6e6f97a1b18781c7ffc6cf620f15293c29515fc5','HEAD')
raise 'read_only_baseline_diff_unavailable' unless status.success?
allowed = ['.github/workflows/build_MooByteMac.yml','ci/moobyte_mac53_readonly.rb','ci/test_moobyte_mac53_readonly.rb','ci/verify_moobyte_mac53_pins.rb']
raise 'unreviewed_tooling_change' unless changed.lines.map(&:strip).all? { |path| allowed.include?(path) }
raise 'locked_sdk_changed' unless File.read('Gemfile.lock').include?("fastlane (2.237.0)")
puts '{"read_only_source_pins_verified":true,"locked_sdk_unchanged":true}'
