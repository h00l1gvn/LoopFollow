# Bryan build 2 profile preparation

Prepared locally only. No profile requests, CI push/dispatch, signing, device
query, installation, or upload has been performed by this preparation.

The immutable source is `038c9e2b61b5b6c28355c478c883edee8372e330`,
version `0.1.0`, build `2`, Team `N8K8G6QA36`. Only the existing approved
distribution certificate `9K5USY2222` is allowed.

The only mutation route is `POST /v1/profiles`, for these two exact names:

- `ResaleBurrow Bryan Build2 Ad Hoc 2026-10-06`
- `ResaleBurrow Watch Bryan Build2 Ad Hoc 2026-10-06`

Both must contain production `aps-environment`. The old iOS and Watch widget
profiles are reused byte-for-byte. No capability, device, certificate, profile
deletion, Match mutation, or app-delivery operation is available.

Before any POST, the helper authenticates the old four exact profile GETs,
verifies their independently approved CMS hashes and CMS signature integrity,
checks current dates, exact certificate/Team/literal group/release identity,
and compares their single approved phone membership in memory. It then reads
only the old primary and Watch `/v1/profiles/{id}/devices` relationships. Both
must identify one identical enabled iOS device whose hardware value matches
the old approved CMS values. There is no physical phone or Watch query.
Watch hardware eligibility remains unverified.

The old private membership receipt is anchored by SHA-256
`c495b2505298db523dd69a1c1a570f5476ccfb58a6b0d7057246de8d2dd4c3cb`.
The source scope contains its sanitized verified-content attestation only;
raw hardware identifiers and hardware fingerprints are not included.

The future owner-dispatched workflow must retain the existing parent public
dependencies under `Scripts/resale-build2/` and this folder under
`Scripts/resale-build2/bryan/`. Copy this workflow separately to
`.github/workflows/resale-build2-bryan-push-profiles.yml` without changing its
bytes. Registration pushes run no job. Dispatch is restricted to the exact
repository, owner, branch and first run attempt. The frozen-file check and
synthetic tests run before credential-bearing steps.

The guarded future command is:

```sh
python Scripts/resale-build2/bryan/prepare_bryan_push_profiles.py \
  --execute-reviewed-two-adhoc-profiles \
  --scope Scripts/resale-build2/bryan/bryan-profile-preparation-scope.json \
  --output "$RUNNER_TEMP/resale-build2-bryan-profiles/profiles"
```

The current reviewed scope authorizes preparation, not execution. Root must
review any previous private attempt journal before a later dispatch. Unknown
POST, HTTP error, readback still absent after its GET bound, ambiguous name, or
invalid existing profile stops with no POST retry or replacement. A valid existing profile
of the exact new name can be reused.

After a known successful POST only, the helper preserves its actual resource ID
in private evidence and permits at most four exact-name GET readbacks, spaced
15 seconds apart. Each nonempty result must retain that exact ID and pass CMS
checks. Absent/settling APS after the fourth GET stops; it never repeats POST.

Actual successful output includes four raw profiles, a sanitized
`bryan-build2-profile-manifest.json`, and an emitted
`bryan-signing-export-scope.json`. The latter retains the seven-target build 2
source/artwork metadata and contains exactly four `adhoc_native_profiles` with
actual ID/name/CMS hash/UUID/type and private membership/readback booleans.
It sets `distribution: ad-hoc`, `delivery_lane: bryan-ad-hoc`, and
`profile_material_mode: native-adhoc-get-with-immutable-match-certificates`.
No new ID or UUID is predicted before account confirmation.

Raw profiles, temporary decoded CMS, API response details, logs, and POST
intent records are private. CI uploads only the RSA/AES-GCM protected archive
and envelope. In-memory hardware and private POST device resource IDs never
appear in public summaries. Subsequent package recovery, signing/export,
fresh readiness, preserving installation and installed-version readback are
separate reviewed lanes.

Endpoint references: Apple's [profile device relationship](https://developer.apple.com/documentation/appstoreconnectapi/get-v1-profiles-_id_-devices),
[owned bundle profile relationship](https://developer.apple.com/documentation/appstoreconnectapi/get-v1-bundleids-_id_-profiles),
and [profile creation endpoint](https://developer.apple.com/documentation/appstoreconnectapi/post-v1-profiles).
These are developer-account profile operations, separate from a physical-device
query. The preparer does not use the general device collection endpoint.
