# Bunway 0.4 delivery prerequisites

The iOS0.4 archive now embeds Watch and Widget. Its release lane signs all three targets separately and exports a profile mapping for each. Merely adding entitlements to source does not register Apple capabilities or deploy CloudKit schema. These dependencies must be prepared before confirming the workflow's `capabilities_ready` checkbox or setting repository variable `BUNWAY_CAPABILITIES_READY=true`.

| Bundle identifier | Target | Required association |
| --- | --- | --- |
| `com.julienbell.bunway` | BunwayPhone | Existing iOS/iPadOS app; WeatherKit, CloudKit `iCloud.com.julienbell.bunway`, App Group `group.com.julienbell.bunway`, Push Notifications |
| `com.julienbell.bunway.watchkitapp` | BunwayWatch | New embedded independent Watch app; same CloudKit container and App Group |
| `com.julienbell.bunway.widget` | BunwayWidget | New Widget extension; same App Group |
| `com.julienbell.bunway.tv` | BunwayTV | Existing tvOS app; Nearby public showroom/camera use, current TV icon preserved |
| `com.julienbell.bunway.mac` | BunwayMac | Separate Mac CloudKit target; not uploaded by the iOS/tvOS workflow |
| `com.julienbell.bunway.spatial` | BunwaySpatial | Separate photo lookboard target; compile checked, not part of delivery workflow |

Before delivery:

1. In the intended Apple developer team, register the new Watch/Widget App IDs and the App Group. Associate the group with Phone/Watch/Widget. Associate the CloudKit container with Phone/Watch/Mac as appropriate and enable each required capability. The Fastlane lane does not do this automatically.
2. Follow the source repository's `apple/Shared/CLOUDKIT_SETUP.md` to create/test the record types and deploy schema to Production. Include `BunwayDeviceSnapshot.payload` (Bytes) in the private default zone, plus `BunwayPiece`, `BunwayLook`, `BunwayClosetMeta` fields. The workflow does not deploy CloudKit schema.
3. Confirm phone Push Notifications/remote-notification setup and WeatherKit are authorized for the existing ID. Regenerate the appropriate development/distribution profiles after the associations. `match` uses `force:true` for Bunway's three iOS archive IDs once prerequisites are confirmed, so older phone profiles do not omit the new entitlements. It uses the existing Match-Secrets storage.
4. Keep the selected source mirror code/assets public-safe. Do not push canonical local history containing generated personal references or test closet screenshots. No API keys, closet backups or private images belong in GitHub.
5. Inspect delivered signed entitlements. Phone/Watch/Widget must share the expected App Group; the CloudKit clients must use the same container and environment. A Debug development-signed direct install on Bryan’s phone normally targets Development, while TestFlight uses Production. Bryan’s direct-install release therefore needs a Production-capable ad-hoc profile/build if it must share Julien’s TestFlight Production closet. Include Bryan’s registered device in that profile; do not infer environment from configuration name.
6. Verify the Watch icon, Widget embedding, both household invitations, offline edits and privacy boundaries on actual devices. Compilation is already separate from those live checks.

The CI build number is at least the source generator's version (currently 0.4.1 build 7), or latest TestFlight build+1 if larger. The command-line build number is applied to all embedded targets so Apple does not see mismatched bundle builds. Resolve the exact marketing version/build from the validated exported IPA before matching the processed build to its existing TestFlight group.

The 0.4.1 source update adds the phone's visible Apple TV approval controls and supports native Mac editing on macOS 13. This workflow still delivers only the selected Phone/iPad and TV packages. Mac signing/installation and actual phone-to-TV approval are separate verification steps; a successful upload does not establish an installed device version.

The existing workflow's push trigger remains. A push cannot begin publishing until its prerequisites gate is confirmed. An explicit manual dispatch can set `capabilities_ready:true`; an ongoing release setup can use repository variable `BUNWAY_CAPABILITIES_READY=true`. This marker records verified account setup; it does not perform that setup. After confirmation, CI regenerates the project, requests profiles, builds/signs iOS and tvOS and uploads both to the existing internal TestFlight workflow.

No push, workflow dispatch, portal capability mutation, upload or device installation was performed while preparing these changes. The Cloudflare API studio is deployed separately; its missing login/key does not stop local wardrobe functions, but image generation remains unavailable until it is configured.

## What the release lane actually verifies

The readiness marker records that account setup/schema work was done. It is not sufficient by itself: after `match` downloads profiles, the phone lane decodes each signed `.mobileprovision` locally and verifies the intended team, explicit bundle ID, expiration, App Group and distribution signing. Phone/Watch must authorize the Bunway CloudKit container/service and Production environment; Phone must also authorize Production APNS and WeatherKit. Widget must authorize the App Group. Missing/wrong capabilities stop before archiving. Profile contents and secrets are not printed. Seven synthetic profile tests (36 assertions) cover CloudKit service permission formats, missing groups, wrong CloudKit environment, wrong team/wildcard/expiration/APNS and ad-hoc device membership. No developer-portal call is needed for these tests.

The export option `iCloudContainerEnvironment:Production` makes the intended signed environment explicit for TestFlight and ad-hoc. Verify the final exported phone and embedded Watch/Widget signed entitlements as well; a downloaded profile describes permitted capabilities, while the signed binary describes what was actually requested.

An iCloud service permission in a provisioning profile can be `*` (a string or
array entry), which authorizes the app to claim CloudKit. Apple's
[TN2415 profile example](https://developer.apple.com/library/archive/technotes/tn2415/_index.html)
shows that exact permission, and
[TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
explains profile permission allowlists. The profile validator accepts this service
grant while still requiring the exact Bunway container and Production environment.
The final signed-binary validator requires a concrete `CloudKit` claim and rejects
a wildcard, missing service, or documents-only claim.

## Bryan’s direct installation without TestFlight

`bundle exec fastlane ios build_BunwayBryan` prepares **BunwayBryan.ipa** using ad-hoc distribution and the same Production CloudKit container. It builds only; it does not upload or install. This lane has the three per-target profile/export mappings, checks the phone profile includes `BUNWAY_BRYAN_UDID`, and exports with Production explicitly selected.

Provide `BUNWAY_CAPABILITIES_READY=true` only after account/schema setup. Set `BUNWAY_BRYAN_UDID` to Bryan’s registered **hardware UDID** before running the lane; its syntax is checked. The previous handoff’s reachable iPhone16Pro CoreDevice UUID `5E868ABA-CF00-429B-A515-AEFF61B6CE09` is a routing identifier for `devicectl`, **not** a Developer Portal hardware UDID. Do not put that UUID into a provisioning profile. The paired Watch also needs its own registered hardware UDID in the Watch ad-hoc profile if you intend to install it; Widget uses the phone device.

Use the resulting distribution app/IPA with the existing device-install route after verifying its signed `com.apple.developer.icloud-container-environment` is `Production`. Installing a new Debug build over it would normally return that device to Development records, preventing Production closet sharing. Record the installed version/build independently; preparing an IPA does not prove the phone updated. No ad-hoc build, developer registration or direct installation was performed in this preparation task.
