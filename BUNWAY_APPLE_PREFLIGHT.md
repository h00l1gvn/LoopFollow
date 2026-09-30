# Bunway Apple preflight

This isolated branch audits existing Apple account metadata using the existing
GitHub CI credentials. It does not build or deliver an app, mutate identifiers or
capabilities, issue provisioning profiles or certificates, register devices, or
change CloudKit schema.

## Run boundary

The workflow is `.github/workflows/bunway_apple_preflight.yml`. Its only automatic
trigger is a push to the exact `codex/bunway-apple-preflight` branch affecting the
five listed audit files. Its job also checks that exact branch, and the GitHub
token has only `contents: read`. Pushes to `bunway-release`, `main`, or `dev` cannot
run this audit. Nothing calls an inherited release or provisioning workflow.

A new `workflow_dispatch` workflow must exist on the repository's default branch
before it can be dispatched. This repository's default branch is `main`; this
audit deliberately does not merge into that unrelated app branch. The exact
isolated-branch push trigger allows a reviewed audit commit to run without doing
so. See [GitHub's manual workflow documentation](https://docs.github.com/actions/managing-workflow-runs/manually-running-a-workflow).

Reviewed inherited triggers at this branch's base:

| Workflow | Triggers | Runs on an audit-branch push? |
| --- | --- | --- |
| `add_identifiers.yml` | Manual dispatch | No |
| `auto_version_dev.yml` | Push to `dev` | No |
| `build_Bunway.yml` | Manual dispatch; restricted push to `bunway-release` | No |
| `build_LoopFollow.yml` | Manual dispatch; default-branch Sunday schedule | No |
| `build_LoopFollowTV.yml` | Manual dispatch | No |
| `build_MooByteMac.yml` | Manual dispatch; restricted push to `main` | No |
| `build_MooBytePhone.yml` | Manual dispatch; restricted push to `main` | No |
| `build_MooByteTV.yml` | Manual dispatch; restricted push to `main` | No |
| `create_certs.yml` | Manual dispatch; explicit reusable-workflow call | No |
| `lint.yml` | Pull request; manual dispatch | No; a later PR can run lint |
| `prepare_MooByteDevices.yml` | Manual dispatch; restricted push to `main` | No |
| `tag_on_main.yml` | Push to `main`; manual dispatch | No |
| `validate_secrets.yml` | Manual dispatch; explicit reusable-workflow call | No |
| `warn_main_pr.yml` | Pull-request target opened/edited against `main` | No |

The mocked workflow test parses every inherited YAML trigger, rejects ambiguous
push branch filters and `workflow_run` chains, and verifies that this audit is
the only workflow eligible for a push to its branch. A scheduled run of an
existing default-branch workflow remains independent of this audit.

## What the audit checks

The Python script uses a ten-minute ES256 token from `FASTLANE_KEY_ID`,
`FASTLANE_ISSUER_ID`, and `FASTLANE_KEY`; `TEAMID` is used only to compare profile
entitlements. Requests are GET-only, bounded, refuse redirects, and cannot send
authorization to another host. Apple documents the read endpoints for
[existing bundle capabilities](https://developer.apple.com/documentation/appstoreconnectapi/get-v1-bundleids-_id_-bundleidcapabilities)
and [existing bundle profiles](https://developer.apple.com/documentation/appstoreconnectapi/get-v1-bundleids-_id_-profiles).

Both of those Apple endpoint pages document a maximum `limit` of 200. This audit
uses a conservative page size of 50 for every initial Apple collection request.
Because live API behavior can reject an optional query parameter, an HTTP 400
gets at most one GET-only retry per collection with only `limit` removed. All
other filters, the host restriction, response size bound, and pagination bound
remain enforced. Other HTTP failures are not retried by this compatibility path.
`optionalLimitRetries` records its count; it does not infer why Apple rejected a
request.

Identifier lookup, capability metadata, and profile metadata have separate
verification flags and fixed stage labels in `metadataErrors`. A failed
capability request does not prevent inspection of existing profiles. Failures
contain the endpoint category and sanitised HTTP status. Structured diagnostics
may also contain an exact allow-listed Apple error-code enum or known query
parameter name. Unknown values, URLs, messages, details, headers, account IDs,
and raw error bodies are excluded; error-body parsing is bounded to 8 KiB.

It inspects these exact IDs:

| Target | Bundle ID | Required App Store profile entitlements |
| --- | --- | --- |
| Phone | `com.julienbell.bunway` | App Group, Production CloudKit container/service, Production push, WeatherKit |
| Watch | `com.julienbell.bunway.watchkitapp` | App Group, Production CloudKit container/service |
| Widget | `com.julienbell.bunway.widget` | App Group |
| TV | `com.julienbell.bunway.tv` | Valid tvOS App Store profile with exact ID and team |

The expected group is `group.com.julienbell.bunway`; the expected CloudKit
container is `iCloud.com.julienbell.bunway`. Every target also requires an active,
unexpired App Store profile with the expected team, explicit bundle ID, and
distribution signing entitlement. Capability labels alone do not prove container
or group association: the actual signed profile entitlement booleans are reported
separately. If Apple does not return signed profile content or decoding fails,
entitlements are explicitly unverified.

On the macOS runner, CMS profile decoding happens through a pipe into
`security cms -D`, then an in-memory plist parser. No raw profile files, private
keys, certificate restoration, or keychain changes occur. Device identifiers,
profile names/UUIDs, raw entitlements, account identifiers, tokens, and secret
values are excluded from the report.

If `GH_PAT` permits it, the script reads the existing `Match-Secrets` repository's
tree metadata and counts encrypted profile filenames for these four IDs. It
never fetches or decrypts a blob and never uses `MATCH_PASSWORD`. Filename counts
do not prove profile contents or usable signing identities.

The only artifact is sanitised `report.json`, retained for seven days. A matching
summary is appended to the workflow job summary. An unavailable account/API is
reported as unverified, not as a confirmed missing identifier. An absent ID with
a successful exact API lookup is reported as confirmed absent.

## What still requires separate verification

The report always keeps `releaseReadinessVerified`,
`cloudKitProductionSchemaVerified`, and `signingIdentityVerified` false. Existing
profile metadata cannot prove that Bunway's Production CloudKit schema is deployed
or that usable distribution private keys are available. Those requirements must
be established before the separate Bunway release workflow is run. This preflight
does not set `BUNWAY_CAPABILITIES_READY` or invoke any build, Match, signing, upload,
or installation lane.

## Local synthetic validation

Use Python 3.12 and a temporary virtual environment; no Apple credentials are needed:

```sh
python3.12 -m venv /tmp/bunway-apple-preflight-venv
/tmp/bunway-apple-preflight-venv/bin/python -m pip install --only-binary=:all: -r Scripts/bunway_apple_preflight_requirements.txt
/tmp/bunway-apple-preflight-venv/bin/python -m unittest discover -s Scripts -p 'test_bunway_apple_preflight.py' -v
```

Directory names in the workflow are case-sensitive: the existing tracked
directory is `Scripts/`, not `scripts/`.
