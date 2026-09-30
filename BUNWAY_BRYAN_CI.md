# Bryan's build-only Bunway delivery

This route exports a signed **ad-hoc, Production CloudKit** `BunwayBryan.ipa` for Bryan's registered iPhone. It runs only on `h00l1gvn/LoopFollow` at `bunway-bryan-release`. It does not upload to TestFlight, install on a device, start the TV workflow, or run another app's Fastlane lane.

The delivery repository is public. Therefore its artifacts contain only authenticated AES-256-GCM ciphertext: `BunwayBryan.ipa.enc` after successful verification, or `BunwayBryan.build.log.enc` when compilation or a later export/encryption/upload step fails and a diagnostic log exists. Both expire after seven days. Raw Fastlane/Xcode output is redirected to the ephemeral runner; its console shows fixed progress/failure messages. No plaintext IPA, build log, provisioning profile, key, or broad artifact glob is uploaded, including on failure.

## Prerequisites before running

Complete the Apple setup in [BUNWAY_RELEASE_SETUP.md](BUNWAY_RELEASE_SETUP.md) first. The phone, Watch and Widget App IDs must have their required capabilities, the Bunway App Group/container must be assigned, and the schema must be deployed to **Production**. Bryan's **hardware UDID**, rather than a CoreDevice routing UUID, must be registered for the ad-hoc phone and Widget profiles. The embedded Watch must have a valid ad-hoc profile; this route does not prove that a particular Watch is registered or installed.

Merge the reviewed, cloud-safe Bunway release into the private `h00l1gvn/bunway-app` repository's `main`. Choose its **full 40-character source SHA**. The workflow checks out that immutable SHA and checks it is an ancestor of `origin/main`; it never falls back to the latest moving branch. The source mirror must exclude personal photos, closet data, generated looks and private configuration.

Existing delivery secrets are reused in place: `GH_PAT`, `TEAMID`, `FASTLANE_KEY_ID`, `FASTLANE_ISSUER_ID`, `FASTLANE_KEY`, and `MATCH_PASSWORD`. The existing `build_BunwayBryan` lane refreshes only the three Bunway ad-hoc profiles through Match, reads the latest Bunway TestFlight build number to choose a unique build, and signs with Apple Distribution. It does not upload the result. Profile refresh is an Apple-account action and must wait until setup is approved.

Add these two dedicated **secrets** through secure stdin after review:

- `BUNWAY_BRYAN_UDID`: Bryan's privately recorded, registered hardware UDID.
- `BUNWAY_ARTIFACT_KEY`: a fresh independent 256-bit key encoded as 64 hexadecimal characters. Never reuse Match's password or an account/API credential.

Keep the artifact key in a private regular file on your Mac, outside all repositories, with mode `0600`. Record which run uses which key. Do not overwrite an older key while its artifacts are still needed. Secret preparation can happen before Apple setup is finished; it does not start a build or authorize a release. Leave readiness unset/false and do not push the release branch until the remaining setup is approved and verified. The key's value must never appear in a command argument, URL, console, chat, repository, CI file, or artifact. For example, once a private key file exists, this passes its contents directly through stdin:

```sh
gh secret set BUNWAY_ARTIFACT_KEY --repo h00l1gvn/LoopFollow < "$HOME/.config/bunway/ipa-artifact-key.hex"
gh secret set BUNWAY_BRYAN_UDID --repo h00l1gvn/LoopFollow < "$HOME/.config/bunway/bryan-hardware-udid.txt"
```

Configure these **repository variables**, which contain no secrets:

- `BUNWAY_BRYAN_SOURCE_SHA`: the full reviewed source SHA already merged into private Bunway `main`.
- `BUNWAY_BRYAN_CAPABILITIES_READY`: the string `true`, set only after the Apple capabilities, Production schema and hardware registration are verified. Leave unset or `false` until then.

The readiness flag records that an operator checked account setup. It cannot create or verify a CloudKit schema by itself. Downloaded profiles and the final exported app receive independent checks, but live CloudKit sharing and device installation still need their own tests.

For the 0.4.1 approval-screen update, select the reviewed source already merged into private Bunway main after Store package signing completes. Keep the Store and ad-hoc Match profile writes sequential. The local installer must compare the package's marketing version and exact build with independently expected release coordinates before updating the verified hardware. An interrupted installation and a failed installed-app metadata query leave the actual installed version unresolved; they do not authorize uninstalling the existing app or resetting pairing.

## Selective initial run

The first run uses an explicitly named branch push. GitHub's manual-dispatch discovery generally requires a workflow on the default branch; this path does not depend on first merging the workflow into LoopFollow's main branch. See GitHub's [workflow trigger documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).

After reviewing the local delivery-tools commit, configuring the approved source SHA, and completing all prerequisites, push that exact prepared commit to `bunway-bryan-release`. Only changes to this workflow, the Bunway Fastlane helpers, `fastlane/Fastfile`, or this guide trigger it. No other existing workflow has a push filter matching that branch. Keep the existing `bunway-release` checkout unchanged.

After the push, verify that GitHub enqueued this exact workflow on the intended
branch and delivery commit. If initial branch creation produces no run, a reviewed
update to this watched guide can provide a subsequent push event on the existing
branch. Keep the immutable application source and readiness checks in place, and
record the resulting delivery SHA separately from any Store run already in progress.

```sh
git -C /tmp/bunway-bryan-delivery-ci-20260930 push origin HEAD:bunway-bryan-release
gh run list --repo h00l1gvn/LoopFollow --workflow build_BunwayBryan.yml --limit 5
```

A later rerun can use `gh run rerun RUN_ID --repo h00l1gvn/LoopFollow`. If GitHub makes this workflow available for manual dispatch, select **the same** `bunway-bryan-release` ref, provide the full source SHA, and explicitly check `capabilities_ready`. A false dispatch checkbox cannot be overridden by the repository variable. The repository/ref guard prevents execution on another branch or fork.

## What must pass before the IPA is preserved

The workflow pins Xcode 26.2, Node 24 and the existing Fastlane 2.237.0 dependency. It regenerates the selected source's targets, runs the synthetic gate/encryption tests, and runs only `ios build_BunwayBryan`.

After export, the validator verifies the phone's complete nested code signature, extracts the actual signed entitlements from every app/extension, and checks:

- Exactly the expected Phone, Watch and Widget bundle identifiers, with matching version/build numbers.
- Matching explicit signed App ID and profile, correct Apple team, unexpired ad-hoc profiles and no development/debug signing.
- Bryan's hardware device included in the Phone and Widget profiles; a valid device list in the Watch profile.
- The exact Bunway App Group on all three bundles.
- The exact Bunway CloudKit container and **Production** environment on Phone and Watch.
- Production Push Notifications and WeatherKit on Phone.

A missing capability, wrong device/profile, unexpected bundle, mismatched version, or invalid signature prevents IPA encryption/upload. Profile/entitlement/device values are not printed. Failed raw build logs are uploaded only after encryption succeeds, using the same independent artifact key with a separately randomized nonce.

## Private local download and decryption

Download the artifact into a private local folder. Keep it outside the public delivery checkout and the Bunway source mirror. Substitute the actual run ID; it is safe metadata. The encrypted IPA name is `BunwayBryan-encrypted-RUN_ID`; failure diagnostics use `BunwayBryan-encrypted-diagnostics-RUN_ID`.

```sh
umask 077
mkdir -p "$HOME/.config/bunway/private-builds/RUN_ID"
gh run download RUN_ID --repo h00l1gvn/LoopFollow \
  --name BunwayBryan-encrypted-RUN_ID \
  --dir "$HOME/.config/bunway/private-builds/RUN_ID"
node /tmp/bunway-bryan-delivery-ci-20260930/fastlane/bunway/artifact_crypto.cjs decrypt \
  "$HOME/.config/bunway/private-builds/RUN_ID/BunwayBryan.ipa.enc" \
  "$HOME/.config/bunway/private-builds/RUN_ID/BunwayBryan.ipa" \
  --key-file "$HOME/.config/bunway/ipa-artifact-key.hex"
```

Use Node 24 for local decryption as well. If `node` is not on the Mac's PATH, the existing Codex bundled executable is `$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node`; substitute its quoted path for `node` above. The Mac's system Ruby/LibreSSL cannot reliably process this AES-GCM authenticated data, so the helper uses Node's standard crypto implementation.

The helper accepts a private key-file path for **local decryption only**; it refuses world/group-readable key files, files owned by another user, and symlinks. Decrypted output has mode `0600`. It authenticates before atomically replacing the final output; wrong keys, altered headers/content/tags, incomplete downloads, and unsupported formats leave any existing output intact and remove temporary plaintext. CI encryption reads its key only from `BUNWAY_ARTIFACT_KEY` in the step environment.

For a failed run, download the explicit encrypted diagnostic artifact and use the same decrypt command with `.build.log.enc` input and a private `.build.log` output. Review it locally and report only relevant sanitized compiler/signing errors. Do not paste or upload the raw log, which may contain device/profile metadata.

The file envelope uses Node's [standard OpenSSL-backed crypto API](https://nodejs.org/docs/latest-v24.x/api/crypto.html#cryptocreatecipherivalgorithm-key-iv-options) for AES-256-GCM, a fresh 96-bit random nonce per file, a 128-bit authentication tag, and authenticated header bytes containing a format identifier, version, nonce and plaintext length. A deployment key is never generated by the workflow or committed by these helpers.

Actual signing, CloudKit connectivity, installation on Bryan's phone, and the installed version remain separate verification steps after this build-only route has succeeded.
