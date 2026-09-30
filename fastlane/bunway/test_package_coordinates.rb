require 'tmpdir'
require 'fileutils'
require 'fastlane/version'
require 'fastlane_core/ipa_file_analyser'
require 'zip/version'
require_relative 'testflight_groups'

# Real locked SDK regression; no mocked analyser and no Apple/network calls.
# BUNWAY_TEST_IPA may point to an owner-only local IPA for an additional run.
class BunwayPackageCoordinatesTests
  class AssertionFailed < StandardError; end

  # This test runs under the release bundle, which contains no test framework.
  # Keep failures generic: an optional private IPA path must not enter CI output.
  def assert_equal(expected, actual)
    @assertions += 1
    raise AssertionFailed unless expected == actual
  end

  def refute(value)
    assert_equal false, !!value
  end

  def assert_raises(type)
    @assertions += 1
    begin
      yield
    rescue type => error
      return error
    end
    raise AssertionFailed
  end

  def run
    @assertions = 0
    tests = methods.grep(/^test_/).sort
    failures = 0
    tests.each do |test|
      begin
        setup
        public_send(test)
      rescue StandardError
        failures += 1
        warn "Failed: #{test} (package coordinate check failed; private details omitted)"
      ensure
        teardown
      end
    end
    puts "#{tests.length} runs, #{@assertions} assertions, #{failures} failures, 0 errors, 0 skips"
    failures.zero?
  end

  def setup
    @directory = Dir.mktmpdir('bunway-package-coordinates-')
    @workspace = File.join(@directory, 'workspace')
    @lane_directory = File.join(@directory, 'fastlane')
    FileUtils.mkdir_p([@workspace, @lane_directory], mode: 0o700)
    @ipa = File.join(@workspace, 'BunwayTV.ipa')
    if ENV['BUNWAY_TEST_IPA']
      FileUtils.copy_file(ENV.fetch('BUNWAY_TEST_IPA'), @ipa)
    else
      write_fixture(@ipa, '0.4.0', '5')
    end
    File.chmod(0o600, @ipa)
    @previous_workspace = ENV['GITHUB_WORKSPACE']
    ENV['GITHUB_WORKSPACE'] = @workspace
  end

  def teardown
    ENV['GITHUB_WORKSPACE'] = @previous_workspace
    FileUtils.remove_entry_secure(@directory) if @directory && File.directory?(@directory)
  end

  def write_fixture(path, version, build)
    info = <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0"><dict>
      <key>CFBundleIdentifier</key><string>com.julienbell.bunway.tv</string>
      <key>CFBundleShortVersionString</key><string>#{version}</string>
      <key>CFBundleVersion</key><string>#{build}</string>
      <key>DTPlatformName</key><string>appletvos</string>
      </dict></plist>
    XML
    Zip::OutputStream.open(path) do |archive|
      archive.put_next_entry('Payload/BunwayTV.app/Info.plist')
      archive.write(info)
    end
    File.chmod(0o600, path)
  end

  def expected
    {version: ENV.fetch('BUNWAY_TEST_VERSION', '0.4.0'), number: ENV.fetch('BUNWAY_TEST_BUILD', '5')}
  end

  def test_uses_real_locked_fastlane_analyser
    assert_equal '2.237.0', Fastlane::VERSION
    assert_equal '2.4.1', Zip::VERSION
    assert_equal 'appletvos', FastlaneCore::IpaFileAnalyser.fetch_app_platform(@ipa)
  end

  def test_relative_package_resolves_workspace_from_another_working_directory
    Dir.chdir(@lane_directory) do
      refute File.exist?('BunwayTV.ipa')
      assert_equal @ipa, BunwayTestFlightGroups.package_path('BunwayTV.ipa')
      assert_equal expected, BunwayTestFlightGroups.package_coordinates('BunwayTV.ipa')
    end
  end

  def test_absolute_package_reads_the_same_binary_from_another_working_directory
    Dir.chdir(@lane_directory) do
      assert_equal @ipa, BunwayTestFlightGroups.package_path(@ipa)
      assert_equal expected, BunwayTestFlightGroups.package_coordinates(@ipa)
    end
  end

  def test_an_absolute_path_cannot_be_redirected_by_another_workspace
    ENV['GITHUB_WORKSPACE'] = @lane_directory
    assert_equal @ipa, BunwayTestFlightGroups.package_path(@ipa)
    assert_equal expected, BunwayTestFlightGroups.package_coordinates(@ipa)
  end

  def test_real_sdk_missing_coordinates_are_rejected_without_falling_back
    invalid = File.join(@workspace, 'invalid.ipa')
    write_fixture(invalid, '', '5')
    error = assert_raises(BunwayTestFlightGroups::Invalid) { BunwayTestFlightGroups.package_coordinates(invalid) }
    assert_equal 'The Bunway IPA must contain its exact version and build number.', error.message
    refute error.message.include?(@directory)
  end
end

exit(BunwayPackageCoordinatesTests.new.run ? 0 : 1)
