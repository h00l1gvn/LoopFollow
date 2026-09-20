#!/usr/bin/env ruby
require "xcodeproj"

root = File.expand_path("..", __dir__)
project_path = File.join(root, "LoopFollow.xcodeproj")
project = Xcodeproj::Project.open(project_path)

existing = project.targets.find { |target| target.name == "LoopFollowTV" }
exit 0 if existing

group = project.main_group.find_subpath("LoopFollowTV", true)
group.set_source_tree("<group>")
group.set_path("LoopFollowTV")
target = project.new_target(:application, "LoopFollowTV", :tvos, "17.0")

swift_files = %w[
  LoopFollowTVApp.swift Models.swift AppSecrets.swift NightscoutClient.swift
  APNSClient.swift DashboardModel.swift RootView.swift
]
swift_files.each do |name|
  ref = group.new_file(name)
  target.source_build_phase.add_file_reference(ref)
end
secrets = group.new_file("LoopTVSecrets.plist")
target.resources_build_phase.add_file_reference(secrets)
assets = group.new_file("Assets.xcassets")
target.resources_build_phase.add_file_reference(assets)

target.build_configurations.each do |config|
  config.build_settings["PRODUCT_BUNDLE_IDENTIFIER"] = "com.N8K8G6QA36.LoopFollow"
  config.build_settings["PRODUCT_NAME"] = "LoopFollowTV"
  config.build_settings["INFOPLIST_FILE"] = "LoopFollowTV/Info.plist"
  config.build_settings["SWIFT_VERSION"] = "5.0"
  config.build_settings["MARKETING_VERSION"] = "1.0"
  config.build_settings["CURRENT_PROJECT_VERSION"] = "1"
  config.build_settings["TARGETED_DEVICE_FAMILY"] = "3"
  config.build_settings["CODE_SIGN_STYLE"] = "Manual"
  config.build_settings["DEVELOPMENT_TEAM"] = "N8K8G6QA36"
  config.build_settings["LD_RUNPATH_SEARCH_PATHS"] = "$(inherited) @executable_path/Frameworks"
  config.build_settings["ASSETCATALOG_COMPILER_APPICON_NAME"] = "App Icon & Top Shelf Image"
  config.build_settings.delete("ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME")
end

project.save
scheme = Xcodeproj::XCScheme.new
scheme.add_build_target(target)
scheme.set_launch_target(target)
scheme.save_as(project_path, "LoopFollowTV", true)
