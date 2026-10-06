#!/usr/bin/env python3
"""One Mac-only ASC GET snapshot. No package, upload, resolution or retry action."""
from __future__ import annotations
import argparse, hashlib, json, os, re, subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import cached_upload as reviewed

APP = reviewed.plan.APPS['macos']
BRANCH = 'codex/resale-burrow-mac-outcome-get'
SOURCE = '1162d8a1f4fdda1c2678220c9102f9c03ab48c33'
PRIOR_RUN = '37449861460'
PRIOR_PACKAGE = '6fa68c3c5f90c03e57a2614bda728e1884c3b52c242d2a07429a5e409341c9b3'
HELPERS = {
    'cached_upload.py': '19b3db0a19f7a1d0662a08972b26565b4a0d5d14611dbb8ad152bf82ed78cb79',
    'plan_cached_upload.py': '088751d6a92394af573c857a59f52933487ac09658a0f2596ad1c1d9aadce416',
    'upload-requirements.txt': '8cf710466bed3f56185c7ba0b4627049765cb5df2a9855b4abb987b52594ab15',
}

class MacOnlyApple(reviewed.Apple):
    def get(self, path):
        parsed = urlparse(path)
        routes = {'/v1/apps/' + APP['asc_id'],
                  '/v1/apps/' + APP['asc_id'] + '/builds',
                  '/v1/apps/' + APP['asc_id'] + '/buildUploads'}
        match = re.fullmatch(r'/v1/builds/([A-Za-z0-9_-]{1,100})/preReleaseVersion', parsed.path)
        owned = bool(match and match[1] in self.build_ids)
        reviewed.require(parsed.path in routes or owned, 'outcome_probe_not_exact_Mac_GET')
        return super().get(path)

def exact_outcome(client):
    """Return selected metadata only; even a FAILED upload is a collision hold."""
    app = client.get('/v1/apps/' + APP['asc_id']).get('data', {})
    reviewed.require(app.get('type') == 'apps' and app.get('id') == APP['asc_id'] and
                     app.get('attributes', {}).get('bundleId') == APP['bundle_id'],
                     'outcome_Mac_app_identity_unknown')
    builds = []
    for row in client.collection('/v1/apps/' + APP['asc_id'] + '/builds?limit=200'):
        reviewed.require(row.get('type') == 'builds' and reviewed.resource_id(row.get('id')),
                         'outcome_build_identity_unknown')
        client.build_ids.add(row['id'])
        version = client.get('/v1/builds/' + row['id'] + '/preReleaseVersion').get('data', {})
        attrs = version.get('attributes', {})
        build = row.get('attributes', {}).get('version')
        reviewed.require(version.get('type') == 'preReleaseVersions' and
                         isinstance(attrs.get('version'), str) and
                         attrs.get('platform') == APP['platform'] and isinstance(build, str),
                         'outcome_build_coordinates_unknown')
        if attrs['version'] == '0.1.0' and build == '1':
            builds.append({'id': row['id'], 'version': attrs['version'], 'build': build,
                           'platform': attrs['platform'], 'exact_owned_identity_resolved': True})
    uploads = []
    for row in client.collection('/v1/apps/' + APP['asc_id'] + '/buildUploads?limit=200'):
        attrs = row.get('attributes', {})
        state = attrs.get('state', {})
        state = state.get('state') if isinstance(state, dict) else None
        reviewed.require(row.get('type') == 'buildUploads' and reviewed.resource_id(row.get('id')) and
                         isinstance(attrs.get('cfBundleShortVersionString'), str) and
                         isinstance(attrs.get('cfBundleVersion'), str) and
                         attrs.get('platform') == APP['platform'] and isinstance(state, str),
                         'outcome_upload_coordinates_or_state_unknown')
        if attrs['cfBundleShortVersionString'] == '0.1.0' and attrs['cfBundleVersion'] == '1':
            uploads.append({'id': row['id'], 'version': attrs['cfBundleShortVersionString'],
                            'build': attrs['cfBundleVersion'], 'platform': attrs['platform'],
                            'state': state, 'exact_owned_identity_resolved': True})
    result = {'schema': 'ResaleBurrow-Mac-post-rejection-GET-1',
              'checked_at': datetime.now(timezone.utc).isoformat(),
              'authenticated_GET_only': True, 'collections_complete': True,
              'family': 'macos', 'asc_id': APP['asc_id'], 'bundle_id': APP['bundle_id'],
              'platform': APP['platform'], 'version': '0.1.0', 'build': '1',
              'prior_upload_run': PRIOR_RUN, 'prior_package_sha256': PRIOR_PACKAGE,
              'exact_builds': builds, 'exact_build_uploads': uploads,
              'exact_current_records_absent': not builds and not uploads,
              'collision_hold': bool(builds or uploads),
              'Apple_error_correlation_lookup': 'Not attempted: no documented resource linkage in the reviewed helper.',
              'absence_is_not_delivery_rejection_proof_alone': True,
              'resolution_record_created': False, 'prior_unknown_journals_modified': False,
              'retry_authorized': False, 'upload_executed': False}
    return result

def verify_sources(root):
    for name, expected in HELPERS.items():
        path = root / name
        reviewed.require(path.is_file() and not path.is_symlink() and
                         hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                         'outcome_reviewed_helper_hash_mismatch')

def owner_gate(environment):
    reviewed.require(environment.get('GITHUB_ACTIONS') == 'true' and
                     environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and
                     environment.get('GITHUB_REPOSITORY') == 'h00l1gvn/LoopFollow' and
                     environment.get('GITHUB_ACTOR') == 'h00l1gvn' and
                     environment.get('GITHUB_REF') == 'refs/heads/' + BRANCH and
                     re.fullmatch(r'[a-f0-9]{40}', environment.get('GITHUB_SHA', '')),
                     'outcome_owner_dispatch_gate_failed')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-source-only', action='store_true')
    args = parser.parse_args()
    verify_sources(Path(__file__).resolve().parent)
    if args.verify_source_only:
        print('Reviewed helper hashes verified; no account request.'); return
    owner_gate(os.environ)
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)
    reviewed.require(head.returncode == 0 and head.stdout.decode().strip() == os.environ['GITHUB_SHA'],
                     'outcome_checkout_head_mismatch')
    reviewed.require(args.output is not None and args.output.is_absolute(), 'outcome_private_output_required')
    result = exact_outcome(MacOnlyApple(reviewed.apple_token(os.environ)))
    reviewed.save(args.output, result)
    print('Exact Mac GET snapshot saved privately; no upload, journal mutation or retry.')

if __name__ == '__main__':
    try: main()
    except reviewed.Invalid as error:
        print(str(error)); raise SystemExit(2)
    except Exception:
        print('outcome_unexpected_private_failure'); raise SystemExit(2)
