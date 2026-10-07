import copy, json, pathlib, tempfile, unittest, subprocess, sys
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.parse import urlparse
import assign_ios_build5 as m
m.BUILD_ID = '44444444-4444-4444-4444-444444444444'  # synthetic; never an Apple observation

def rel(kind, identity):
    return {'data': {'type': kind, 'id': identity}}

def scope():
    return {'frozen': True, 'dispatchable': True, 'assignment_authorized': True, 'source_sha': m.SOURCE, 'team': m.TEAM, 'app_id': m.APP, 'bundle_id': m.BUNDLE, 'platform': 'IOS', 'version': '0.1.0', 'build': '5', 'build_id': m.BUILD_ID, 'beta_group_id': m.GROUP, 'expected_tester_count': 1, 'expected_prior_build_count': 4, 'verified_reader_result_sha256': 'a' * 64, 'reader_confirmed_internal_ready': True}

def fixtures():
    return {
        '/v1/apps/' + m.APP: {'data': {'type': 'apps', 'id': m.APP, 'attributes': {'bundleId': m.BUNDLE}}},
        '/v1/builds': {'data': [{'type': 'builds', 'id': m.BUILD_ID, 'attributes': {'version': '5', 'processingState': 'VALID', 'expired': False, 'expirationDate': '2026-12-31T00:00:00Z', 'usesNonExemptEncryption': False}, 'relationships': {'app': rel('apps', m.APP), 'preReleaseVersion': rel('preReleaseVersions', 'pre3')}}], 'included': [{'type': 'preReleaseVersions', 'id': 'pre3', 'attributes': {'version': '0.1.0', 'platform': 'IOS'}}]},
        '/v1/builds/' + m.BUILD_ID + '/buildBetaDetail': {'data': {'type': 'buildBetaDetails', 'id': 'opaque/detail=id', 'attributes': {'internalBuildState': 'READY_FOR_BETA_TESTING'}}, 'included': [{'type': 'builds', 'id': m.BUILD_ID, 'attributes': {'version': '5'}}]},
        '/v1/betaGroups/' + m.GROUP: {'data': {'type': 'betaGroups', 'id': m.GROUP, 'attributes': {'isInternalGroup': True, 'hasAccessToAllBuilds': False}, 'relationships': {'app': rel('apps', m.APP)}}, 'included': [{'type': 'apps', 'id': m.APP, 'attributes': {'bundleId': m.BUNDLE}}]},
        '/v1/betaGroups/' + m.GROUP + '/app': {'data': {'type': 'apps', 'id': m.APP, 'attributes': {'bundleId': m.BUNDLE}}},
        '/v1/betaGroups/' + m.GROUP + '/relationships/betaTesters': {'data': [{'type': 'betaTesters', 'id': 'private-tester', 'attributes': {'email': 'never-retain@example.invalid'}}]},
        m.POST_PATH: {'data': [{'type': 'builds', 'id': 'old-build1'}, {'type': 'builds', 'id': 'old-build2'}, {'type': 'builds', 'id': 'old-build3'}, {'type': 'builds', 'id': 'old-build4'}]},
    }

class Fake(m.Client):
    def __init__(self, rows=None, after=None, unknown=False):
        super().__init__('not-a-real-token')
        self.rows, self.after, self.unknown = rows or fixtures(), after, unknown
    def get(self, path):
        self.validate_get(path)
        self.request_count += 1
        return copy.deepcopy(self.rows[urlparse(path).path])
    def add_exact_build_once(self):
        m.need(self.owned_build and self.owned_group and self.post_count == 0, 'POST_not_authorized_or_already_attempted')
        self.post_count += 1
        if self.unknown:
            raise m.Stop('POST_unknown_outcome_stop_no_retry')
        self.rows[m.POST_PATH]['data'].append({'type': 'builds', 'id': m.BUILD_ID})
        self.rows['/v1/builds/' + m.BUILD_ID + '/buildBetaDetail']['data']['attributes']['internalBuildState'] = 'IN_BETA_TESTING'
        if self.after:
            self.after(self.rows)

class Assignment(unittest.TestCase):
    def execute(self, client=None, s=None):
        with tempfile.TemporaryDirectory() as folder:
            intent = pathlib.Path(folder) / 'intent.json'
            result = m.assign(client or Fake(), s or scope(), intent)
            if intent.exists():
                self.assertEqual(intent.stat().st_mode & 0o777, 0o600)
            return result
    def test_additive_exact_assignment_preserves_old_builds_and_members(self):
        c = Fake(); result = self.execute(c)
        self.assertEqual(result['status'], 'assigned_and_testing_verified')
        self.assertEqual((result['POST_attempts'], result['assigned_build_count'], result['tester_count_before']), (1, 5, 1))
        self.assertTrue(result['old_builds_preserved'] and result['tester_relationships_preserved'])
        for private in ['private-tester', 'never-retain', 'old-build1', 'opaque/detail']:
            self.assertNotIn(private, json.dumps(result))
    def test_already_assigned_testing_never_posts(self):
        c = Fake(); c.rows[m.POST_PATH]['data'].append({'type': 'builds', 'id': m.BUILD_ID})
        c.rows['/v1/builds/' + m.BUILD_ID + '/buildBetaDetail']['data']['attributes']['internalBuildState'] = 'IN_BETA_TESTING'
        self.assertEqual(self.execute(c)['status'], 'already_assigned_no_POST')
        self.assertEqual(c.post_count, 0)
    def test_held_stub_and_missing_actual_reader_stop_before_get(self):
        for delta in [{'frozen': False}, {'build_id': None}, {'dispatchable': False}, {'verified_reader_result_sha256': None}, {'reader_confirmed_internal_ready': False}]:
            c = Fake()
            with self.assertRaises(m.Stop): self.execute(c, {**scope(), **delta})
            self.assertEqual((c.request_count, c.post_count), (0, 0))
    def test_real_cli_held_scope_stops_before_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder); held = root / 'scope.json'; held.write_text(json.dumps({**scope(), 'frozen': False}))
            call = subprocess.run([sys.executable, str(pathlib.Path(m.__file__)), '--execute-assignment-once', '--scope', str(held), '--intent', str(root / 'intent.json'), '--report', str(root / 'report.json')], capture_output=True, text=True, env={'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertEqual(call.returncode, 2); self.assertFalse((root / 'intent.json').exists())
            self.assertEqual(json.loads((root / 'report.json').read_text())['error_code'], 'assignment_scope_held')
    def test_processing_expired_and_encryption_block_assignment(self):
        for delta in [{'processingState': 'PROCESSING'}, {'expired': True}, {'expirationDate': '2026-01-01T00:00:00Z'}, {'expirationDate': None}, {'usesNonExemptEncryption': None}, {'usesNonExemptEncryption': True}]:
            c = Fake(); c.rows['/v1/builds']['data'][0]['attributes'].update(delta)
            with self.assertRaises(m.Stop): self.execute(c)
            self.assertEqual(c.post_count, 0)
    def test_exact_app_platform_build_and_native_uuid_required(self):
        for kind in ['app', 'platform', 'number', 'uuid', 'ambiguous']:
            c = Fake(); row = c.rows['/v1/builds']
            if kind == 'app': row['data'][0]['relationships']['app'] = rel('apps', 'other-app')
            if kind == 'platform': row['included'][0]['attributes']['platform'] = 'MAC_OS'
            if kind == 'number': row['data'][0]['attributes']['version'] = '2'
            if kind == 'uuid': row['data'][0]['id'] = 'different-build'
            if kind == 'ambiguous': row['data'] *= 2
            with self.assertRaises(m.Stop): self.execute(c)
            self.assertEqual(c.post_count, 0)
    def test_detail_opaque_id_allowed_but_exact_included_build_required(self):
        self.assertEqual(self.execute()['status'], 'assigned_and_testing_verified')
        for kind in ['wrong', 'duplicate', 'link']:
            c = Fake(); d = c.rows['/v1/builds/' + m.BUILD_ID + '/buildBetaDetail']
            if kind == 'wrong': d['included'][0]['id'] = 'other-build'
            if kind == 'duplicate': d['included'] *= 2
            if kind == 'link': d['data']['relationships'] = {'build': rel('builds', 'other-build')}
            with self.assertRaises(m.Stop): self.execute(c)
            self.assertEqual(c.post_count, 0)
    def test_detail_links_only_relationship_valid_with_exact_included_build(self):
        c = Fake()
        c.rows['/v1/builds/' + m.BUILD_ID + '/buildBetaDetail']['data']['relationships'] = {'build': {'links': {'related': '/unused-do-not-follow'}}}
        self.assertEqual(self.execute(c)['status'], 'assigned_and_testing_verified')
        c = Fake()
        c.rows['/v1/builds/' + m.BUILD_ID + '/buildBetaDetail']['data']['relationships'] = {'build': {'data': None}}
        self.assertEqual(self.execute(c)['status'], 'assigned_and_testing_verified')
    def test_external_autoaccess_wrong_app_or_tester_count_stop(self):
        for kind in ['external', 'auto', 'app', 'none', 'extra']:
            c = Fake(); g = c.rows['/v1/betaGroups/' + m.GROUP]['data']
            if kind == 'external': g['attributes']['isInternalGroup'] = False
            if kind == 'auto': g['attributes']['hasAccessToAllBuilds'] = True
            if kind == 'app': g['relationships']['app'] = rel('apps', 'other-app')
            if kind == 'none': c.rows['/v1/betaGroups/' + m.GROUP + '/relationships/betaTesters']['data'] = []
            if kind == 'extra': c.rows['/v1/betaGroups/' + m.GROUP + '/relationships/betaTesters']['data'].append({'type': 'betaTesters', 'id': 'other-tester'})
            with self.assertRaises(m.Stop): self.execute(c)
            self.assertEqual(c.post_count, 0)
    def test_group_links_only_requires_exact_included_app_bundle(self):
        c = Fake(); g = c.rows['/v1/betaGroups/' + m.GROUP]
        g['data']['relationships'] = {'app': {'links': {'related': '/unused-do-not-follow'}}}
        self.assertEqual(self.execute(c)['status'], 'assigned_and_testing_verified')
        for change in ['wrong', 'duplicate', 'wrong_bundle']:
            c = Fake(); g = c.rows['/v1/betaGroups/' + m.GROUP]
            if change == 'wrong': g['included'][0]['id'] = 'wrong-app'
            if change == 'duplicate': g['included'] *= 2
            if change == 'wrong_bundle': g['included'][0]['attributes']['bundleId'] = 'com.other.app'
            with self.assertRaises(m.Stop): self.execute(c)
            self.assertEqual(c.post_count, 0)
    def test_optional_include_linkage_or_included_proof_with_conflicts_rejected(self):
        for kind, relation, identity, attribute, expected in [('builds', 'build', m.BUILD_ID, 'version', '5'), ('apps', 'app', m.APP, 'bundleId', m.BUNDLE)]:
            row = {'relationships': {relation: rel(kind, identity)}}
            m.owned_binding({}, row, relation, kind, identity, attribute, expected)
            m.owned_binding({'included': []}, row, relation, kind, identity, attribute, expected)
            included = {'included': [{'type': kind, 'id': identity, 'attributes': {attribute: expected}}]}
            m.owned_binding(included, {'relationships': {relation: {'links': {'related': '/do-not-follow'}}}}, relation, kind, identity, attribute, expected)
            self.assertIsNone(m.owned_binding({}, {}, relation, kind, identity, attribute, expected))
            self.assertIsNone(m.owned_binding({'included': []}, {'relationships': {relation: {'links': {}}}}, relation, kind, identity, attribute, expected))
            for response, data in [(included, {'relationships': {relation: rel(kind, 'wrong')}}), ({'included': [{'type': kind, 'id': 'wrong'}]}, row), ({'included': included['included'] * 2}, row), ({'included': [{'type': kind, 'id': identity, 'attributes': {attribute: 'contradictory'}}]}, row)]:
                with self.assertRaises(m.Stop): m.owned_binding(response, data, relation, kind, identity, attribute, expected)
        c = Fake(); detail = c.rows['/v1/builds/' + m.BUILD_ID + '/buildBetaDetail']; detail.pop('included'); detail['data']['relationships'] = {'build': rel('builds', m.BUILD_ID)}
        c.rows['/v1/betaGroups/' + m.GROUP].pop('included')
        self.assertEqual(self.execute(c)['status'], 'assigned_and_testing_verified')
    def test_exact_parent_detail_with_null_or_absent_binding_and_direct_group_app(self):
        for representation in [{}, {'relationships': {'build': {'data': None}}}, {'relationships': {'build': None}}, {'relationships': {'build': {'links': {}}}}]:
            c = Fake(); detail = c.rows['/v1/builds/' + m.BUILD_ID + '/buildBetaDetail']
            detail['included'] = []; detail['data'].pop('relationships', None); detail['data'].update(representation)
            group = c.rows['/v1/betaGroups/' + m.GROUP]; group.pop('included'); group['data']['relationships'] = {'app': {'data': None}}
            r = self.execute(c)
            self.assertEqual(r['status'], 'assigned_and_testing_verified')
            self.assertEqual(r['detail_binding_basis'], 'exact_owned_parent_endpoint')
            self.assertEqual(r['group_binding_basis'], 'exact_group_app_endpoint')
        for delta in [{'id': 'other-app'}, {'attributes': {'bundleId': 'com.other.app'}}]:
            c = Fake(); g = c.rows['/v1/betaGroups/' + m.GROUP]; g['included'] = []; g['data']['relationships'] = {}
            c.rows['/v1/betaGroups/' + m.GROUP + '/app']['data'].update(delta)
            with self.assertRaises(m.Stop): self.execute(c)
            self.assertEqual(c.post_count, 0)
    def test_unknown_post_retains_intent_and_never_retries(self):
        c = Fake(unknown=True)
        with tempfile.TemporaryDirectory() as folder:
            intent = pathlib.Path(folder) / 'intent.json'
            r = m.assign(c, scope(), intent)
            self.assertEqual(r['status'], 'unknown_or_failed_assignment_stop_no_retry')
            self.assertEqual(c.post_count, 1); self.assertTrue(intent.exists())
            with self.assertRaises(m.Stop): m.assign(c, scope(), intent)
            self.assertEqual(c.post_count, 1)
    def test_lost_old_build_or_changed_tester_never_claims_success(self):
        for change in [lambda rows: rows[m.POST_PATH]['data'].pop(0), lambda rows: rows['/v1/betaGroups/' + m.GROUP + '/relationships/betaTesters']['data'][0].update(id='different-private-tester'), lambda rows: rows['/v1/builds/' + m.BUILD_ID + '/buildBetaDetail']['data']['attributes'].update(internalBuildState='READY_FOR_BETA_TESTING')]:
            c = Fake(after=change); r = self.execute(c)
            self.assertEqual(r['status'], 'unknown_or_failed_assignment_stop_no_retry'); self.assertEqual(c.post_count, 1)
            self.assertIsNone(r['assignment_changed'])
    def test_unexpected_post_exception_and_malformed_readback_preserve_intent_count(self):
        class Exploding(Fake):
            def add_exact_build_once(self):
                self.post_count += 1
                raise RuntimeError('do-not-retain-private-error')
        for c in [Exploding(), Fake(after=lambda rows: rows['/v1/builds'].update(data=None))]:
            r = self.execute(c)
            self.assertIn(r['status'], {'unknown_stop_no_retry', 'unknown_or_failed_assignment_stop_no_retry'})
            self.assertEqual(r['POST_attempts'], 1); self.assertEqual(r['account_state'], 'unknown')
            self.assertTrue(r['intent_recorded']); self.assertEqual(len(r['intent_sha256']), 64)
            self.assertIsNone(r['assignment_changed']); self.assertNotIn('do-not-retain', json.dumps(r))
    def test_transport_post_body_exact_and_attempt_advanced_before_unknown(self):
        class Opener:
            def open(self, req, timeout):
                self.req = req
                raise URLError('private diagnostic not retained')
        o = Opener(); c = m.Client('fake-token', o); c.owned_build = c.owned_group = True
        with self.assertRaises(m.Stop): c.add_exact_build_once()
        self.assertEqual(o.req.get_method(), 'POST'); self.assertEqual(o.req.full_url, m.ORIGIN + m.POST_PATH)
        self.assertEqual(json.loads(o.req.data), {'data': [{'type': 'builds', 'id': m.BUILD_ID}]})
        with self.assertRaises(m.Stop): c.add_exact_build_once()
        self.assertEqual(c.post_count, 1)
    def test_path_and_pagination_escape_rejected(self):
        c = m.Client('fake'); c.owned_build = c.owned_group = True
        for p in ['/v1/betaTesters', '/v1/profiles', '/v1/builds', 'https://other.invalid' + m.POST_PATH, m.route('/v1/builds/other/buildBetaDetail', m.DETAIL_QUERY), m.route(m.POST_PATH, {'limit': '200', 'include': 'betaTesters'})]:
            with self.assertRaises(m.Stop): c.validate_get(p)
        c = Fake(); c.rows['/v1/builds']['links'] = {'next': m.route('/v1/builds', {**m.BUILD_QUERY, 'filter[app]': 'other'})}
        with self.assertRaises(m.Stop): self.execute(c)
        self.assertEqual(c.post_count, 0)
    def test_owner_attempt_and_branch_gate(self):
        e = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'h00l1gvn/LoopFollow', 'GITHUB_ACTOR': 'h00l1gvn', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/' + m.BRANCH, 'GITHUB_RUN_ATTEMPT': '1'}
        m.owner_gate(e)
        for delta in [{'GITHUB_EVENT_NAME': 'push'}, {'GITHUB_RUN_ATTEMPT': '2'}, {'GITHUB_ACTOR': 'other'}, {'GITHUB_REF': 'refs/heads/main'}]:
            with self.assertRaises(m.Stop): m.owner_gate({**e, **delta})

if __name__ == '__main__': unittest.main()
