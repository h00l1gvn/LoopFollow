# Cached App Store upload-only lane — prepared, not executed

This directory is a reviewed candidate for the existing sanctioned shared Apple CI repository `h00l1gvn/LoopFollow`. It has no push trigger. Copy these public-safe source files to `Scripts/resale/upload-prep/` and put `resale-upload-cached.yml` at `.github/workflows/resale-upload-cached.yml` only after root reviews their frozen hashes. The workflow uses the existing pinned Gemfile/Gemfile.lock, with their exact SHA-256 checked; it does not change signing assets or the native source. No upload, release creation, workflow dispatch or credential access was performed by the preparer.

The fixed owned application set is iOS `6819601040`, Mac `6819601423`, TV `6819601651`, version `0.1.0`, build `1`. Source is frozen at `1162d8a1f4fdda1c2678220c9102f9c03ab48c33`. The same release identity is checked in every signed primary/embedded bundle by the unchanged strict export validator. No archive, resign, match, profile generation or keychain installation exists in this job.

## Private cache and provenance

Create one **private** draft/prerelease under `h00l1gvn/resale-burrow-native`, tag `resale-burrow-0.1.0-build-1-signed-cache`. Only validated App Store exported packages and a minimal pinned manifest belong in that cache. Package names are `ResaleBurrow-ios-0.1.0-1.ipa`, `ResaleBurrow-macos-0.1.0-1.pkg`, and `ResaleBurrow-tvos-0.1.0-1.ipa`. Do not cache archives, standalone profiles/certificates, key material, raw logs, photos, or ad-hoc packages. The private exported packages naturally contain their required embedded provisioning profiles.

`cache-manifest-schema-example.json` is intentionally unfilled and cannot pass validation. Use schema `ResaleBurrow-signed-cache-2`, `approved_families:['ios']` for the first independently reviewed iOS subset, and only actual validated exports in `exports[]`. Each family carries its own immutable export CI run/head/event/status/conclusion and authenticated recovery/local validation receipt hashes. Mac/TV are independent later lanes; a shared successful run is not invented. A failed run is allowed only when root's actual evidence establishes successful archive/export and a resolved **post-export validation** failure with authenticated recovery and a fresh signed local pass. The executor performs another full platform-tool validation against the exact cached bytes.

**Trust boundary:** the root-approved manifest hash authenticates the recovery flags and receipt hashes. They are operator-reviewed attestations, not CI step proof independently obtained by this executor. The executor verifies the actual run metadata via an authenticated GET and matches its real failure/success conclusion; it does not fetch archives or raw CI logs. `source_sha_basis` is provenance, not proof that the source commit is embedded in the Mach-O binary. The exact package SHA prevents substituting different bytes after root's review.

Pass the independent release ID, manifest asset ID/SHA/byte count, selected family export run/delivery SHA, and explicit execution boolean to a reviewed owner `workflow_dispatch`. A manifest may list any reviewed nonempty subset of the three families. It must describe every cached package currently present. Root can add later validated packages and replace only the owned manifest after a new review; never replace/delete intent/result records or change package bytes. An unlisted cache asset or unknown actual API response blocks the job.

## Collision and once-only upload guard

The executor first checks exact private repository/release identity, unique canonical tag, asset metadata, byte counts, hash pins and actual family CI provenance. Private GitHub download redirects accept only the official release-assets/objects hosts and discard Authorization on redirect. Package hashes are checked after download, during validation and immediately before the Fastlane action.

Fresh authenticated GETs check the exact owned ASC app identity, all paginated builds, and all paginated `buildUploads` including in-flight uploads. Build versions are resolved through the observed build's pre-release version; incomplete metadata or any existing `0.1.0(1)` stops regardless of processing state. No Apple API write is part of this metadata precheck.

`execute_reviewed_upload` defaults **false**. False performs GET/validation/preflight only. True first creates an atomic, uniquely named private cache asset `upload-intent-{family}-0.1.0-1.json`, reads it back by hash, then repeats the fresh ASC collision check. GitHub Actions also serializes all same-family/version/build runs with cancellation disabled. Only after both guards does one `upload_to_testflight` invocation occur, with submission/distribution/waiting disabled and no groups or changelog.

Any previous intent/result blocks every later attempt. Reservation write/readback uncertainty means zero Fastlane calls. Upload timeout/failure, an unrecognized result or result-journal failure leaves the durable intent and stops. There is no retry/resume action in this helper. Root must resolve unknown outcomes using actual ASC build/upload metadata and preserve the historical journal before proposing any recovery. A Fastlane return means transport reported success; processing, compliance review, TestFlight assignment, device installation, launch and acceptance remain separate.

## Diagnostics and privacy

Secrets are referenced only through existing CI names `GH_PAT`, `TEAMID`, `FASTLANE_KEY_ID`, `FASTLANE_ISSUER_ID`, `FASTLANE_KEY`. Their values stay in environment/memory; no secret value is a CLI argument or a cache marker. Raw tool/Fastlane diagnostics, expanded signed bundles and the exact final receipt remain in a private ephemeral directory. An `always()` step RSA-wraps an AES-GCM artifact to the existing public recipient key, pinned by SPKI SHA; only ciphertext/envelope enter the public tooling run's artifact store. Plaintext is removed afterward. A failure to preserve encrypted diagnostics remains a failed delivery gate, not claimed successful protection. Durable private intent/result assets provide the cross-run checkpoint even if diagnostic preservation fails.

No buyer/account data, hardware IDs, private recipient key, raw signing assets or public release is created by this preparation. Future authenticated private cache setup/dispatch is root's separate execution step.

## Primary implementation references

- [Apple: upload builds](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/): upload is distinct from processing/distribution.
- [Apple App Store Connect API](https://developer.apple.com/app-store-connect/api/): official OpenAPI 4.5 defines app build and build-upload collections, nested upload state, marketing version/platform and build number fields.
- [Fastlane upload_to_testflight](https://docs.fastlane.tools/actions/upload_to_testflight/): skip submission and waiting, use existing API-key credentials and exact app identifiers.
- [Fastlane 2.237.0 Pilot manager](https://github.com/fastlane/fastlane/blob/2.237.0/pilot/lib/pilot/manager.rb): exact `ios`, `appletvos`, `osx` platform values.
- [GitHub release assets REST](https://docs.github.com/en/rest/releases/assets): unique release asset names support the atomic private intent reservation.

Offline tests use synthetic metadata and byte fixtures only. No successful test establishes live credential permissions, actual GitHub asset transfer, Transporter acceptance or installation. Those execution gates remain open.
