# Bunway Store delivery privacy

`h00l1gvn/LoopFollow` is public. The Bunway Store workflow keeps IPAs and raw
Fastlane/Xcode/Transporter output off the public console and uploads only encrypted
files. The change applies only to `.github/workflows/build_Bunway.yml`; other apps'
workflows and the reviewed Bryan delivery route are unchanged.

IPAs contain compiled code/resources, public signing certificates and embedded
profile/entitlement metadata, rather than private signing keys. Clean app packages
normally do not contain users' closet databases or personal photos; the source
mirror must still exclude that data. Raw logs can reveal signing identities,
teams, profile names/UUIDs and source paths, and must remain private.

## Source and prerequisites

The existing Apple requirements in `BUNWAY_RELEASE_SETUP.md` still apply. This
change does not create capabilities or deploy CloudKit schema. The job runs only
on `h00l1gvn/LoopFollow` at the exact `bunway-release` ref. A false manual
`capabilities_ready` cannot be overridden by a repository variable; only a push
can use `BUNWAY_CAPABILITIES_READY=true`.

Manual runs require a full reviewed 40-character `source_sha`; push runs require
the nonsecret repository variable `BUNWAY_SOURCE_SHA`. The source is checked out at
that immutable SHA and must already be an ancestor of private Bunway `origin/main`.
Both checkouts disable persisted credentials.

The workflow checks the existing independent `BUNWAY_ARTIFACT_KEY` secret before
signing. It reuses the reviewed Node 24 AES-256-GCM helper from `BUNWAY_BRYAN_CI.md`
unchanged. Each encrypted file uses a fresh random nonce. No key is generated,
printed, passed in a command argument, or committed by this workflow.

Configure `BUNWAY_PHONE_TESTFLIGHT_GROUP_ID` and `BUNWAY_TV_TESTFLIGHT_GROUP_ID` as
private repository secrets using the existing group identifiers from the canonical
local handoff. Do not place their values in public source or documentation. The
workflow checks the selected group's identifier shape before any build. After
upload/processing, the release lane reads version/build from the actual IPA,
verifies the group belongs to the exact app and is internal, selects only that
exact valid unexpired build, assigns it if absent, then reads back the actual
group/build relationship. It does not create groups, add testers, submit external
beta review, or log group names/identifiers or tester details. An uncertain POST
is resolved by bounded relationship reads rather than repeating the mutation.

## Exact encrypted outputs

| Job | Artifact name | Only uploaded file |
| --- | --- | --- |
| iOS | `Bunway-BunwayPhone-encrypted-RUN_ID` | `BunwayPhone.ipa.enc` |
| tvOS | `Bunway-BunwayTV-encrypted-RUN_ID` | `BunwayTV.ipa.enc` |

The exact IPA is encrypted and preserved before its ordinary private upload to
Apple. Build and upload stdout/stderr are redirected to owner-readable runner
files; the public console receives fixed progress/failure messages.

After any failure following a build attempt, available build/upload logs and
regular `.log` files in the exact platform's Xcode log directory are collected
into a private archive and encrypted. Symlinks, profiles and unrelated files are
excluded. Only successful encryption enables the diagnostic artifact upload.

| Job | Failure artifact name | Only uploaded file |
| --- | --- | --- |
| iOS | `Bunway-BunwayPhone-encrypted-diagnostics-RUN_ID` | `BunwayPhone.ipa.diagnostics.tar.gz.enc` |
| tvOS | `Bunway-BunwayTV-encrypted-diagnostics-RUN_ID` | `BunwayTV.ipa.diagnostics.tar.gz.enc` |

Artifacts expire after seven days. `always()` cleanup removes plaintext IPAs,
build/upload logs, diagnostic archives and Xcode log directories. No plaintext
artifact or broad workspace glob is uploaded, including on failure.

Use the private local download/decryption steps in `BUNWAY_BRYAN_CI.md`, substituting
these exact Store artifact and file names. Keep decrypted IPAs/archives outside
repositories and source mirrors, and share only sanitised errors from raw logs.

## Safe preparation and validation

The prepared commit can be pushed for review to `codex/bunway-protected-delivery`.
Synthetic tests assert that every inherited workflow push filter excludes that
preparation ref. It does not run either release route or set readiness. A later
actual release-ref push requires verified Apple readiness.

```sh
ruby fastlane/bunway/test_verify_profiles.rb
ruby fastlane/bunway/test_verify_exported_ipa.rb
node --test fastlane/bunway/test_artifact_crypto.cjs
ruby fastlane/bunway/test_bryan_workflow.rb
ruby fastlane/bunway/test_store_workflow.rb
ruby fastlane/bunway/test_testflight_groups.rb
```

The Store tests exercise source/key gates, exact encrypted artifact paths,
private output redirection, failure encryption, source ancestry ordering, log
selection/symlink exclusion and preparation-ref isolation. They make no Apple
requests, signing changes or deployments.
