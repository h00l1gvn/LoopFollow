#!/usr/bin/env python3
"""One additive assignment to one existing group; no build/upload/legal methods."""
import argparse, base64, hashlib, json, os, pathlib, re, time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler

SOURCE = '79bbd8e2c59fa94c6a3f97942dd0053e5f3086ad'
TEAM = 'N8K8G6QA36'
APP = '6819601040'
BUNDLE = 'com.julienbell.ResaleBurrow'
GROUP = 'e83d545b-4efe-4492-8ccb-6bf41c1008ba'
BUILD_ID = None  # actual exact ID is bound only from a reviewed ready-build scope
BRANCH = 'codex/resale-burrow-build5-approved-posting-ios-existing-group-assignment'
ORIGIN = 'https://api.appstoreconnect.apple.com'
POST_PATH = '/v1/betaGroups/' + GROUP + '/relationships/builds'
APP_QUERY = {'fields[apps]': 'bundleId'}
BUILD_QUERY = {'filter[app]': APP, 'filter[version]': '5', 'filter[preReleaseVersion.version]': '0.1.0', 'filter[preReleaseVersion.platform]': 'IOS', 'include': 'preReleaseVersion,app', 'fields[builds]': 'version,expirationDate,expired,processingState,usesNonExemptEncryption,preReleaseVersion,app', 'fields[preReleaseVersions]': 'version,platform', 'fields[apps]': 'bundleId', 'limit': '200'}
GROUP_QUERY = {'fields[betaGroups]': 'isInternalGroup,hasAccessToAllBuilds,app', 'include': 'app', 'fields[apps]': 'bundleId'}
DETAIL_QUERY = {'include': 'build', 'fields[buildBetaDetails]': 'internalBuildState,build', 'fields[builds]': 'version'}
LINK_QUERY = {'limit': '200'}

class Stop(Exception):
    def __init__(self, code, status=None):
        super().__init__(code)
        self.code, self.status = code, status

def need(ok, code):
    if not ok:
        raise Stop(code)

def route(path, query):
    return path + '?' + urlencode(query)

def resource(row, kind, identity=None):
    need(isinstance(row, dict) and row.get('type') == kind and isinstance(row.get('id'), str) and 0 < len(row['id']) <= 512 and not any(ord(c) < 32 or ord(c) == 127 for c in row['id']) and (identity is None or row['id'] == identity), 'resource_identity_invalid')
    return row

def link(row, key, kind, identity):
    return resource(row.get('relationships', {}).get(key, {}).get('data'), kind, identity)

def owned_binding(response, row, relationship, kind, identity, attribute, expected):
    """Apple may omit includes/linkage; every present ownership proof must agree."""
    relationships = row.get('relationships')
    if relationships is None:
        relationships = {}
    need(isinstance(relationships, dict), 'ownership_relationship_shape_invalid')
    linked = False
    if relationship in relationships:
        value = relationships[relationship]
        need(value is None or isinstance(value, dict), 'ownership_relationship_shape_invalid')
        if value is not None and value.get('data') is not None:
            resource(value['data'], kind, identity)
            linked = True
    included = response.get('included') if response.get('included') is not None else []
    need(isinstance(included, list) and all(isinstance(r, dict) for r in included), 'ownership_included_shape_invalid')
    candidates = [r for r in included if isinstance(r, dict) and r.get('type') == kind]
    if candidates:
        need(len(candidates) == 1, 'ownership_included_ambiguous')
        target = resource(candidates[0], kind, identity)
        attrs = target.get('attributes', {})
        need(isinstance(attrs, dict), 'ownership_included_attributes_invalid')
        if attribute in attrs:
            need(attrs[attribute] == expected, 'ownership_included_attribute_contradiction')
    if linked:
        return 'exact_relationship_data'
    if len(candidates) == 1:
        return 'unique_exact_included_resource'
    return None

def stamp(value):
    try:
        d = datetime.fromisoformat(value.replace('Z', '+00:00'))
        need(d.tzinfo is not None, 'timestamp_invalid')
        return d.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        raise Stop('timestamp_invalid') from None

def exact_ids(rows, kind):
    values = [resource(row, kind)['id'] for row in rows]
    need(len(values) == len(set(values)), 'duplicate_relationship_identity')
    return set(values)

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

class Client:
    def __init__(self, token, opener=None):
        self.token = token
        self.opener = opener or build_opener(NoRedirect())
        self.owned_build = self.owned_group = False
        self.request_count = self.post_count = 0
        self.post_response_status = None

    def validate_get(self, path):
        p = urlparse(urljoin(ORIGIN + '/', path))
        need(p.scheme == 'https' and p.netloc == 'api.appstoreconnect.apple.com' and not p.username and not p.password and not p.fragment, 'origin_outside_scope')
        pairs = parse_qsl(p.query, keep_blank_values=True)
        need(len(pairs) == len(dict(pairs)), 'duplicate_query_parameter')
        q = dict(pairs)
        q.pop('cursor', None)
        valid = (p.path == '/v1/apps/' + APP and q == APP_QUERY) or (p.path == '/v1/builds' and q == BUILD_QUERY) or (p.path == '/v1/betaGroups/' + GROUP and q == GROUP_QUERY)
        valid |= self.owned_build and p.path == '/v1/builds/' + BUILD_ID + '/buildBetaDetail' and q == DETAIL_QUERY
        valid |= self.owned_group and p.path in {POST_PATH, '/v1/betaGroups/' + GROUP + '/relationships/betaTesters'} and q == LINK_QUERY
        valid |= self.owned_group and p.path == '/v1/betaGroups/' + GROUP + '/app' and q == APP_QUERY
        need(valid, 'GET_outside_exact_scope')

    def get(self, path):
        self.validate_get(path)
        need(self.request_count < 40, 'request_budget_exhausted')
        self.request_count += 1
        try:
            with self.opener.open(Request(urljoin(ORIGIN + '/', path), headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json'}, method='GET'), timeout=30) as response:
                raw = response.read(2 * 1024**2 + 1)
            need(len(raw) <= 2 * 1024**2, 'response_too_large')
            value = json.loads(raw)
            need(isinstance(value, dict), 'response_not_object')
            return value
        except HTTPError as error:
            raise Stop('apple_GET_http_error', error.code) from None
        except (URLError, TimeoutError, OSError):
            raise Stop('apple_GET_unavailable') from None
        except (ValueError, UnicodeError):
            raise Stop('apple_GET_unreadable') from None

    def collection(self, path):
        anchor = urlparse(urljoin(ORIGIN + '/', path))
        query = dict(parse_qsl(anchor.query))
        seen, rows, included = set(), [], []
        for _ in range(5):
            need(path not in seen, 'pagination_cycle')
            seen.add(path)
            value = self.get(path)
            need(isinstance(value.get('data'), list) and isinstance(value.get('included', []), list), 'collection_shape_invalid')
            rows += value['data']
            included += value.get('included', [])
            need(len(rows) <= 1000 and len(included) <= 2000, 'collection_bound')
            following = value.get('links', {}).get('next')
            if not following:
                return rows, included
            need(isinstance(following, str), 'pagination_invalid')
            p = urlparse(urljoin(ORIGIN + '/', following))
            q = dict(parse_qsl(p.query)); q.pop('cursor', None)
            need(p.path == anchor.path and q == query, 'pagination_scope_changed')
            self.validate_get(following)
            path = following
        raise Stop('collection_incomplete')

    def add_exact_build_once(self):
        need(self.owned_build and self.owned_group and self.post_count == 0, 'POST_not_authorized_or_already_attempted')
        self.post_count += 1  # advance before transport; unknown outcomes cannot retry
        body = json.dumps({'data': [{'type': 'builds', 'id': BUILD_ID}]}, separators=(',', ':')).encode()
        request = Request(ORIGIN + POST_PATH, data=body, headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json', 'Content-Type': 'application/json'}, method='POST')
        try:
            with self.opener.open(request, timeout=30) as response:
                self.post_response_status = response.status
                need(response.status == 204, 'POST_unexpected_response_stop_no_retry')
        except HTTPError as error:
            self.post_response_status = error.code
            raise Stop('POST_http_error_stop_no_retry', error.code) from None
        except (URLError, TimeoutError, OSError):
            raise Stop('POST_unknown_outcome_stop_no_retry') from None

def snapshot(client, now):
    app = resource(client.get(route('/v1/apps/' + APP, APP_QUERY)).get('data'), 'apps', APP)
    need(app.get('attributes', {}).get('bundleId') == BUNDLE, 'app_bundle_mismatch')
    builds, included = client.collection(route('/v1/builds', BUILD_QUERY))
    need(len(builds) == 1, 'exact_build_missing_or_ambiguous')
    b = resource(builds[0], 'builds', BUILD_ID); attrs = b.get('attributes', {})
    need(attrs.get('version') == '5', 'build_number_mismatch')
    link(b, 'app', 'apps', APP)
    pre = resource(b.get('relationships', {}).get('preReleaseVersion', {}).get('data'), 'preReleaseVersions')['id']
    versions = [r for r in included if isinstance(r, dict) and r.get('type') == 'preReleaseVersions' and r.get('id') == pre]
    need(len(versions) == 1 and versions[0].get('attributes', {}).get('version') == '0.1.0' and versions[0].get('attributes', {}).get('platform') == 'IOS', 'version_platform_unverified')
    need(attrs.get('processingState') == 'VALID' and attrs.get('expired') is False and attrs.get('usesNonExemptEncryption') is False and stamp(attrs.get('expirationDate')) > now, 'build_not_ready_nonexpired_encryption_false')
    client.owned_build = True
    detail = client.get(route('/v1/builds/' + BUILD_ID + '/buildBetaDetail', DETAIL_QUERY))
    data = resource(detail.get('data'), 'buildBetaDetails')
    detail_basis = owned_binding(detail, data, 'build', 'builds', BUILD_ID, 'version', '5')
    # This documented parent relationship GET already names the freshly owned exact build.
    need(client.owned_build, 'exact_owned_parent_build_required')
    detail_basis = detail_basis or 'exact_owned_parent_endpoint'
    internal = data.get('attributes', {}).get('internalBuildState')
    need(internal in {'READY_FOR_BETA_TESTING', 'IN_BETA_TESTING'}, 'internal_build_not_ready')
    group_response = client.get(route('/v1/betaGroups/' + GROUP, GROUP_QUERY))
    g = resource(group_response.get('data'), 'betaGroups', GROUP)
    group_basis = owned_binding(group_response, g, 'app', 'apps', APP, 'bundleId', BUNDLE)
    need(g.get('attributes', {}).get('isInternalGroup') is True and g.get('attributes', {}).get('hasAccessToAllBuilds') is False, 'existing_manual_internal_group_unverified')
    client.owned_group = True
    if group_basis is None:
        related = resource(client.get(route('/v1/betaGroups/' + GROUP + '/app', APP_QUERY)).get('data'), 'apps', APP)
        need(related.get('attributes', {}).get('bundleId') == BUNDLE, 'group_direct_app_bundle_mismatch')
        group_basis = 'exact_group_app_endpoint'
    testers, _ = client.collection(route('/v1/betaGroups/' + GROUP + '/relationships/betaTesters', LINK_QUERY))
    assigned, _ = client.collection(route(POST_PATH, LINK_QUERY))
    members, linked_builds = exact_ids(testers, 'betaTesters'), exact_ids(assigned, 'builds')
    need(len(members) == 1, 'existing_tester_count_changed')
    return {'members': members, 'builds': linked_builds, 'internal': internal, 'detail_binding_basis': detail_basis, 'group_binding_basis': group_basis}

def scope_gate(scope):
    global BUILD_ID
    need(scope.get('frozen') is True and scope.get('assignment_authorized') is True and scope.get('dispatchable') is True, 'assignment_scope_held')
    actual_build = scope.get('build_id')
    need(isinstance(actual_build, str) and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', actual_build) is not None and actual_build not in {'7887cf1c-a499-441a-9fc1-dd89123ac42e','85cb5457-2b13-45d7-a199-42d1beb616aa'}, 'actual_build5_uuid_required')
    need(BUILD_ID is None or BUILD_ID == actual_build, 'assignment_build_identity_changed')
    for key, value in {'source_sha': SOURCE, 'team': TEAM, 'app_id': APP, 'bundle_id': BUNDLE, 'platform': 'IOS', 'version': '0.1.0', 'build': '5', 'build_id': actual_build, 'beta_group_id': GROUP, 'expected_tester_count': 1, 'expected_prior_build_count': 4}.items():
        need(scope.get(key) == value, 'assignment_scope_identity_changed')
    evidence = scope.get('verified_reader_result_sha256')
    need(isinstance(evidence, str) and re.fullmatch('[0-9a-f]{64}', evidence) is not None and scope.get('reader_confirmed_internal_ready') is True, 'actual_ready_reader_evidence_required')
    BUILD_ID = actual_build

def private_write(path, value):
    need(not path.exists() and not path.is_symlink(), 'new_private_receipt_required')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('x') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    path.chmod(0o600)

def assign(client, scope, intent, now=None):
    scope_gate(scope)
    need(not intent.exists() and not intent.is_symlink(), 'prior_assignment_intent_stop_no_retry')
    now = now or datetime.now(timezone.utc)
    before = snapshot(client, now)
    result = {'schema': 'ReBurrow-iOS-build5-existing-group-assignment-1', 'source_sha': SOURCE, 'app_id': APP, 'version': '0.1.0', 'build': '5', 'build_id': BUILD_ID, 'group_id': GROUP, 'started_at': now.isoformat(), 'status': 'blocked_before_POST', 'POST_attempts': 0, 'assignment_changed': False, 'tester_count_before': len(before['members']), 'prior_build_count': len(before['builds'] - {BUILD_ID}), 'retry_authorized': False, 'upload_or_legal_or_device_actions': 0, 'detail_binding_basis': before['detail_binding_basis'], 'group_binding_basis': before['group_binding_basis']}
    need(len(before['builds'] - {BUILD_ID}) == 4, 'prior_build_count_changed')
    if BUILD_ID in before['builds']:
        need(before['internal'] == 'IN_BETA_TESTING', 'assigned_build_testing_unverified')
        result.update(status='already_assigned_no_POST', tester_relationships_preserved=True, old_builds_preserved=True, exact_build_testing=True, completed_at=datetime.now(timezone.utc).isoformat())
        return result
    result['operation_key'] = hashlib.sha256((SOURCE + ':' + GROUP + ':' + BUILD_ID).encode()).hexdigest()
    private_write(intent, {**result, 'status': 'intent_recorded_before_one_POST', 'reader_result_sha256': scope['verified_reader_result_sha256']})
    result.update(intent_recorded=True, intent_sha256=hashlib.sha256(intent.read_bytes()).hexdigest())
    result['assignment_changed'] = None  # a transport failure cannot establish unchanged account state
    try:
        client.add_exact_build_once()
        result['POST_attempts'] = 1
        after = snapshot(client, datetime.now(timezone.utc))
        need(after['members'] == before['members'], 'tester_relationships_changed_stop_no_retry')
        need(after['builds'] == before['builds'] | {BUILD_ID}, 'additive_build_relationship_readback_failed_stop_no_retry')
        need(after['internal'] == 'IN_BETA_TESTING', 'accepted_POST_testing_not_yet_verified_stop_no_retry')
        result.update(status='assigned_and_testing_verified', assignment_changed=True, exact_build_testing=True, tester_relationships_preserved=True, old_builds_preserved=True, assigned_build_count=len(after['builds']))
    except Stop as error:
        result.update(status='unknown_or_failed_assignment_stop_no_retry', error_code=error.code, http_status=error.status, POST_attempts=client.post_count, account_state='unknown')
    except Exception:
        result.update(status='unknown_stop_no_retry', error_code='assignment_transport_or_readback_incomplete', POST_attempts=client.post_count, account_state='unknown')
    result['POST_response_status'] = client.post_response_status
    result['completed_at'] = datetime.now(timezone.utc).isoformat()
    return result

def owner_gate(env):
    need(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_REPOSITORY') == 'h00l1gvn/LoopFollow' and env.get('GITHUB_ACTOR') == 'h00l1gvn' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and env.get('GITHUB_REF') == 'refs/heads/' + BRANCH and env.get('GITHUB_RUN_ATTEMPT') == '1', 'exact_owner_once_dispatch_required')

def token(env):
    need(env.get('TEAMID') == TEAM and all(env.get(k) for k in ['FASTLANE_KEY_ID', 'FASTLANE_ISSUER_ID', 'FASTLANE_KEY']), 'existing_CI_credentials_unavailable')
    key = env['FASTLANE_KEY'].replace('\\n', '\n').strip()
    try:
        if '-----BEGIN PRIVATE KEY-----' not in key:
            key = base64.b64decode(key, validate=True).decode()
        import jwt
        now = int(time.time())
        return jwt.encode({'iss': env['FASTLANE_ISSUER_ID'], 'iat': now, 'exp': now + 600, 'aud': 'appstoreconnect-v1'}, key, algorithm='ES256', headers={'kid': env['FASTLANE_KEY_ID'], 'typ': 'JWT'})
    except Exception:
        raise Stop('CI_token_unavailable') from None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scope', type=pathlib.Path, required=True)
    parser.add_argument('--intent', type=pathlib.Path, required=True)
    parser.add_argument('--report', type=pathlib.Path, required=True)
    parser.add_argument('--execute-assignment-once', action='store_true')
    args = parser.parse_args()
    client = None
    try:
        scope = json.loads(args.scope.read_text())
        scope_gate(scope)  # held/stub evidence fails before credential access
        need(args.execute_assignment_once, 'explicit_one_assignment_flag_required')
        owner_gate(os.environ)
        need(not args.report.exists() and not args.report.is_symlink() and not args.intent.exists() and not args.intent.is_symlink(), 'prior_assignment_receipt_stop_no_retry')
        client = Client(token(os.environ))
        result = assign(client, scope, args.intent)
    except Stop as error:
        result = {'status': 'blocked_before_assignment', 'error_code': error.code, 'http_status': error.status, 'POST_attempts': 0, 'retry_authorized': False}
    except Exception:
        result = {'status': 'unknown_stop_no_retry', 'error_code': 'assignment_incomplete', 'retry_authorized': False, 'POST_attempts': client.post_count if client else 0, 'account_state': 'unknown', 'intent_recorded': args.intent.is_file()}
    private_write(args.report, result)
    print(json.dumps({'status': result['status'], 'retry_authorized': False}))
    return 0 if result['status'] in {'already_assigned_no_POST', 'assigned_and_testing_verified'} else 2

if __name__ == '__main__':
    raise SystemExit(main())
