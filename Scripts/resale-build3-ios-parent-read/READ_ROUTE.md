# Exact owned-parent iOS build3 reader

GET-only; no assignment or upload. Exact app6819601040, IOS0.1.0(3), build7887cf1c-a499-441a-9fc1-dd89123ac42e, source526c52eb2dd0fb2591a2f7b65aaca26d3a3a39a6, existing internal group e83d545b-4efe-4492-8ccb-6bf41c1008ba. Previous three partial reads remain unchanged.

Fresh exact build GET verifies app/bundle/version/platform/status/expiry. Documented GET /v1/builds/{our exact verified build}/buildBetaDetail provides authoritative parent relationship binding, recorded as exact_owned_parent_endpoint. Detail resource type, bounded opaque ID and internal state remain validated. Optional null/absent build linkage and empty includes are permitted; any non-null contradictory linkage or duplicate/mismatching included build/attributes rejects the result.

Group resource exact ID/internal status is verified. Optional representations must agree when present. If they lack proof, documented GET /v1/betaGroups/{exact known group}/app with fields[apps]=bundleId must independently return exact app6819601040/bundlecom.julienbell.ResaleBurrow. Only then are existing member/build relationships counted in memory; member IDs/names/emails are not retained. No unrelated IDs or account fields are fetched.

Official primary references: https://developer.apple.com/documentation/appstoreconnectapi/get-v1-builds-_id_-buildbetadetail and https://developer.apple.com/documentation/appstoreconnectapi/get-v1-betagroups-_id_-app . Unknown/partial never becomes eligible; actual bound internal state is retained through later group failures.
