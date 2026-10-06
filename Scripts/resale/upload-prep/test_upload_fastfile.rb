require 'json'
require 'tmpdir'
require 'digest'
require 'minitest/autorun'
module UI
  def self.user_error!(message); raise ArgumentError, message; end
end
class Harness
  attr_reader :uploads, :key_calls
  def initialize; @uploads=[]; @key_calls=[]; end
  def lane(_name); yield; end
  def app_store_connect_api_key(**value); @key_calls << value; {mock: true}; end
  def upload_to_testflight(**value); @uploads << value; end
  def run; instance_eval(File.read(File.join(__dir__, 'UploadFastfile'))); end
end
class UploadGuards < Minitest::Test
  def setup
    @old_env=ENV.to_h
    @old_gem=Gem.loaded_specs['fastlane']
    spec=Gem::Specification.new; spec.name='fastlane'; spec.version='2.237.0'; Gem.loaded_specs['fastlane']=spec
    @dir=Dir.mktmpdir; @package=File.join(@dir,'app.ipa');File.binwrite(@package,'TEST SIGNED BYTES');@options=File.join(@dir,'options.json')
    ENV['RESALE_EXECUTE_REVIEWED_UPLOAD']='true';ENV['TEAMID']='N8K8G6QA36';ENV['RESALE_PACKAGE_SHA256']=Digest::SHA256.file(@package).hexdigest
    ENV['RESALE_UPLOAD_OPTIONS']=@options;ENV['FASTLANE_KEY_ID']='SYNTHETIC';ENV['FASTLANE_ISSUER_ID']='SYNTHETIC';ENV['FASTLANE_KEY']='U1lOVEhFVElDIE9OTFk='
    @value={'apple_id'=>'6819601040','app_identifier'=>'com.julienbell.ResaleBurrow','app_platform'=>'ios','ipa'=>@package,'app_version'=>'0.1.0','build_number'=>'1','skip_submission'=>true,'skip_waiting_for_build_processing'=>true,'distribute_external'=>false,'notify_external_testers'=>false}
  end
  def teardown
    ENV.replace(@old_env);Gem.loaded_specs['fastlane']=@old_gem;FileUtils.remove_entry(@dir)
  end
  def invoke(value=@value)
    File.write(@options,JSON.generate(value));File.chmod(0600,@options);h=Harness.new;h.run;h
  end
  def test_exact_upload_one_call_no_distribution
    h=invoke;assert_equal 1,h.uploads.size;assert_equal 1,h.key_calls.size;assert_equal '6819601040',h.uploads[0][:apple_id];assert_equal true,h.uploads[0][:skip_submission];assert_equal false,h.uploads[0][:distribute_external]
  end
  def test_tv_exact_appletvos
    v=@value.dup;v['apple_id']='6819601651';v['app_identifier']='com.julienbell.ResaleBurrow.tv';v['app_platform']='appletvos';assert_equal 'appletvos',invoke(v).uploads[0][:app_platform]
  end
  def test_mac_exact_pkg_osx
    v=@value.dup;v['apple_id']='6819601423';v['app_identifier']='com.julienbell.ResaleBurrow.mac';v['app_platform']='osx';v['pkg']=v.delete('ipa');assert_equal 'osx',invoke(v).uploads[0][:app_platform]
  end
  def test_unreserved_upload_rejected
    ENV['RESALE_EXECUTE_REVIEWED_UPLOAD']='false';assert_raises(ArgumentError){invoke}
  end
  def test_changed_export_rejected
    File.write(@package,'CHANGED');assert_raises(ArgumentError){invoke}
  end
  def test_foreign_app_rejected
    @value['apple_id']='999';assert_raises(ArgumentError){invoke}
  end
  def test_extra_group_field_rejected
    @value['groups']=['PRIVATE'];assert_raises(ArgumentError){invoke}
  end
  def test_wrong_team_rejected
    ENV['TEAMID']='OTHER';assert_raises(ArgumentError){invoke}
  end
  def test_submission_setting_rejected
    @value['skip_submission']=false;assert_raises(ArgumentError){invoke}
  end
  def test_nonprivate_options_rejected
    File.write(@options,JSON.generate(@value));File.chmod(0644,@options);assert_raises(ArgumentError){Harness.new.run}
  end
end
