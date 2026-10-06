# Exact iOS build 3 processing reader

This separate job reads only app 6819601040, bundle com.julienbell.ResaleBurrow,
marketing version 0.1.0, build 3, IOS. Its source is frozen
526c52eb2dd0fb2591a2f7b65aaca26d3a3a39a6, whose single Store upload succeeded.
It reads only the existing internal group e83d545b-4efe-4492-8ccb-6bf41c1008ba
(historically Julien Devices). Tester identifiers are counted in memory and discarded;
names, addresses and tester details are never requested. Existing build relationship
IDs are counted and compared to the observed exact build, with no old build detail reads.

Registration pushes skip the sole job. A reviewed owner manual dispatch makes one
bounded GET pass through the existing CI-only Apple credential references. Redirects,
other apps, unfiltered builds, wrong versions/platforms, unrelated groups and unknown
build-detail routes are rejected. Diagnostics and the minimal result are RSA/AES-GCM
protected with the existing recipient. There is no signing, upload, assignment, tester,
profile, device or account mutation method in the reader. Upload journals are untouched.

No build record is not proof of upload failure or permission to upload again. A partial
read retains an already observed build state but cannot claim readiness. Eligibility is
conservative: exact unambiguous build/app/version/platform, processing VALID, nonexpired
with a known future expiry, usesNonExemptEncryption false, internal state
READY_FOR_BETA_TESTING or IN_BETA_TESTING, exact existing internal group's app match and
at least one existing tester. Individual Julien membership is not inferred from counts.

## Separately reviewed future add-build request (NOT implemented or authorized here)

Apple documents the additive endpoint:
`POST /v1/betaGroups/e83d545b-4efe-4492-8ccb-6bf41c1008ba/relationships/builds`
with JSON `{"data":[{"type":"builds","id":"ACTUAL_FRESH_EXACT_BUILD3_ID"}]}`.
A successful response is 204. This adds one build; it does not replace existing build
or tester relationships. Never use PATCH to replace the relationship collection.

Before any future assignment, root must review the actual build ID and authorize that
single linkage. Fresh GET must recheck all eligibility gates, exact group ownership,
existing member/build counts and absence of this build from the group's relationships.
If already assigned, do not POST. Persist a private intent before one POST, never retry
unknown/conflict outcomes, then independently GET the relationship and require old
builds preserved, exact new build present and tester membership unchanged. No tester,
group, encryption declaration, metadata, upload or source changes accompany it.

Primary sources checked 2026-10-06:

- https://developer.apple.com/documentation/appstoreconnectapi/get-v1-builds
- https://developer.apple.com/documentation/appstoreconnectapi/get-v1-builds-_id_-buildbetadetail
- https://developer.apple.com/documentation/appstoreconnectapi/get-v1-betagroups-_id_
- https://developer.apple.com/documentation/appstoreconnectapi/get-v1-betagroups-_id_-relationships-builds
- https://developer.apple.com/documentation/appstoreconnectapi/get-v1-betagroups-_id_-relationships-betatesters
- https://developer.apple.com/documentation/appstoreconnectapi/post-v1-betagroups-_id_-relationships-builds
- https://developer.apple.com/documentation/appstoreconnectapi/betagroupbuildslinkagesrequest
