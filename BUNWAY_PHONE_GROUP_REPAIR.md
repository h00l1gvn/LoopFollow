# Bunway existing-build group repair

This protected route selects only the already uploaded and processed **Bunway
phone 0.4.1 (7)**. Store run `36786063117` exported and uploaded that exact build
from reviewed source `25c3aac3e38b67273f7f9da0ae04ddb74a8aaa8d`; its final group
relationship verification failed. The TV lane completed. This route does not
build, sign, upload a package, install an app, create a group/tester, or change an
encryption/compliance declaration.

The helper verifies the exact phone application, existing app-scoped internal
group and one exact VALID, unexpired IOS build. It reads current group membership
first. If already present, it makes no mutation. Otherwise it attempts one group
assignment and bounded readbacks, without repeating the POST. A separate SDK
mutation client retains the existing token/TLS stack and disables both API and
transport retry loops only on that instance, with 30-second request/open
timeouts. Normal GET and shipping clients are unchanged. A dependency-free
locked-SDK transport regression gates the API step and exercises 500, 429, 401,
connection failure, timeout and lost-response reconciliation without networking.
It preserves real
`hasAccessToAllBuilds`, `usesNonExemptEncryption`, `internalBuildState` and
`externalBuildState` GET fields, actual mutation HTTP status/body (including
Apple's error code), and any upstream exception privately. The response observer
scrubs nested secret values before JSON encoding and never records headers. Missing
compliance or automatic-distribution behavior must be concluded from these
actual fields and responses; this repair never supplies a compliance answer.

Use the existing secrets `FASTLANE_KEY_ID`, `FASTLANE_ISSUER_ID`, `FASTLANE_KEY`,
`BUNWAY_PHONE_TESTFLIGHT_GROUP_ID` and `BUNWAY_ARTIFACT_KEY`. A reviewed push to
**`bunway-phone-group-repair`** is the supported route while the existing
`BUNWAY_CAPABILITIES_READY` variable is true. Push a new reviewed commit that
changes one of the workflow's watched paths; creating a ref at an already
existing commit has previously failed to enqueue a run. Do not push this patch
to Store/Bryan release branches merely to repair a processed build.

The optional manual event requires `confirm_existing_build=true` and the same
exact branch. GitHub may not expose a new manual workflow until it is present
on the default branch; no default-branch modification is needed for the narrow
push route. Review the exact run SHA/branch/event before accepting its receipt.

All Fastlane output is redirected to owner-only runner files. Only the exact
AES-GCM encrypted diagnostic archive is uploaded, on success or failure, with
seven-day retention. The key remains an existing secret and is never put in a
command argument, file or artifact on CI. Decrypt with the reviewed Node helper
and the local owner-only artifact key into the established private build folder.
Inspect only sanitized fields/errors in chat; retain raw diagnostics outside Git.

A successful job proves the current processed build's intended internal group
relationship. Installed version and live features still require device checks.
