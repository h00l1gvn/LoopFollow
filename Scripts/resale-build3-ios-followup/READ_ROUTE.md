# Exact build3 testing follow-up — GET only

This preserved, separate reader fixes the optional linkage/opaque detail ID contract in the failed read37541953562. It cannot assign builds, change encryption declarations, upload, rebuild or create testers/groups. One owner manual dispatch follows a skipped registration push only after root review.

Only app6819601040 / IOS /0.1.0(3), source526c52eb2dd0fb2591a2f7b65aaca26d3a3a39a6, exact already observed build7887cf1c-a499-441a-9fc1-dd89123ac42e and group e83d545b-4efe-4492-8ccb-6bf41c1008ba are in scope. No builds collection or other app GET occurs.

Five bounded routes: exact build GET including app/prerelease, exact buildBetaDetail GET including build, exact existing group GET including app, and two group linkage collections for tester/build counts. Group linkage IDs are counted in memory and discarded; no tester identity fields are requested or retained.

Detail query: fields[buildBetaDetails]=internalBuildState,build & include=build & fields[builds]=version. Exact included build UUID/version must match; an optional detail.relationships.build.data, when present, must also match. The unused detail resource ID accepts a nonempty opaque string at most512 characters without controls; it is never used in an outgoing URL or retained. Path-bound build/group IDs stay exact.

Diagnostic output retains stage, data-object/type-known booleans, ID-format class, expected-key presence and included-array presence only; no opaque IDs, arbitrary attributes, raw resource body or contacts.

Official schema: https://developer.apple.com/documentation/appstoreconnectapi/buildbetadetail ; https://developer.apple.com/documentation/appstoreconnectapi/buildbetadetail/relationships-data.dictionary/build-data.dictionary ; https://developer.apple.com/documentation/appstoreconnectapi/get-v1-builds-_id_-buildbetadetail . These document opaque ID, optional relationship data and include=build. The original failed report does not distinguish which of the two guard assumptions failed.

Eligibility requires exact verified app/version/UUID/platform, VALID/nonexpired/future expiry, usesNonExemptEncryption:false, READY_FOR_BETA_TESTING or IN_BETA_TESTING, exact owned internal group and nonzero current tester count. Unknown or partial stays ineligible; no retry of any upload is implied.
