"""Synthetic tests: no Apple/GitHub network calls, real keys, or signing changes."""
import base64
import importlib.util
import io
import json
import plistlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse

spec = importlib.util.spec_from_file_location('bunway_apple_preflight', Path(__file__).with_name('bunway_apple_preflight.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
TEAM = 'SYNTHETIC1'
SECRET = 'synthetic-private-key-never-print'

def profile(identifier, **overrides):
    entitlements = {
        'application-identifier': TEAM + '.' + identifier,
        'get-task-allow': False,
        'com.apple.security.application-groups': [audit.GROUP],
        'com.apple.developer.icloud-services': ['CloudKit'],
        'com.apple.developer.icloud-container-identifiers': [audit.CONTAINER],
        'com.apple.developer.icloud-container-environment': 'Production',
        'aps-environment': 'production',
        'com.apple.developer.weatherkit': True,
    }
    entitlements.update(overrides)
    return {'TeamIdentifier': [TEAM], 'ExpirationDate': datetime.now(timezone.utc) + timedelta(days=30), 'Entitlements': entitlements, 'ProvisionedDevices': ['synthetic-device-identifier-never-print']}

def resource(identifier, kind='IOS_APP_STORE', state='ACTIVE'):
    return {'attributes': {'profileType': kind, 'profileState': state, 'expirationDate': '2099-01-01T00:00:00Z', 'profileContent': 'synthetic-base64-profile', 'name': SECRET}}

class FakeApple:
    def __init__(self, missing=(), capabilities=None):
        self.missing = missing
        self.paths = []
        self.capabilities = capabilities or ['ICLOUD', 'APP_GROUPS', 'PUSH_NOTIFICATIONS', 'WEATHERKIT']
    def collection(self, path):
        self.paths.append(path)
        if path.startswith('/v1/bundleIds?'):
            identifier = parse_qs(urlparse(path).query)['filter[identifier]'][0]
            return [] if identifier in self.missing else [{'id': identifier, 'attributes': {'identifier': identifier}}]
        if '/bundleIdCapabilities?' in path:
            return [{'attributes': {'capabilityType': label, 'settings': SECRET}} for label in self.capabilities]
        if '/profiles?' in path:
            identifier = path.split('/')[3]
            return [resource(identifier, 'TVOS_APP_STORE' if identifier.endswith('.tv') else 'IOS_APP_STORE')]
        raise AssertionError('Unexpected read path')

class StrictLimitAPI:
    """Mock live API: rejects oversized limits and optional capability limits."""
    def __init__(self, capability_mode='accept', profile_error=None):
        self.capability_mode = capability_mode
        self.profile_error = profile_error
        self.requests = []
    def open(self, request, timeout):
        self.requests.append(request)
        parsed = urlparse(request.full_url)
        query = parse_qs(parsed.query)
        limit = int(query['limit'][0]) if 'limit' in query else None
        if limit is not None and limit > 50: raise HTTPError(request.full_url, 400, SECRET, {}, None)
        if parsed.path == '/v1/bundleIds':
            identifier = query['filter[identifier]'][0]
            data = [{'id':identifier, 'attributes':{'identifier':identifier}}]
        elif parsed.path.endswith('/bundleIdCapabilities'):
            if self.capability_mode == 'fail' or (self.capability_mode == 'reject_limit' and limit is not None): raise HTTPError(request.full_url, 400, SECRET, {}, None)
            data = [{'attributes':{'capabilityType':'ICLOUD'}}]
        elif parsed.path.endswith('/profiles'):
            if self.profile_error: raise HTTPError(request.full_url, self.profile_error, SECRET, {}, None)
            identifier = parsed.path.split('/')[3]
            value = resource(identifier, 'TVOS_APP_STORE' if identifier.endswith('.tv') else 'IOS_APP_STORE')
            value['attributes']['profileContent'] = identifier
            data = [value]
        else:
            raise AssertionError('Unexpected read path')
        return io.BytesIO(json.dumps({'data':data}).encode())

class ProfileTests(unittest.TestCase):
    def summarise(self, name='Phone', value=None, kind=None, state='ACTIVE'):
        requirements = audit.TARGETS[name]
        identifier = requirements['id']
        decoded = value or profile(identifier)
        return audit.profile_summary(resource(identifier, kind or ('TVOS_APP_STORE' if name == 'TV' else 'IOS_APP_STORE'), state), identifier, requirements, TEAM, lambda _: decoded)
    def test_all_production_phone_requirements(self):
        result = self.summarise()
        self.assertTrue(result['productionRequirementsMet'])
        self.assertTrue(all(result['checks'].values()))
    def test_development_cloud_and_push_do_not_pass_production(self):
        value = profile(audit.TARGETS['Phone']['id'], **{'get-task-allow': True, 'aps-environment': 'development', 'com.apple.developer.icloud-container-environment': 'Development'})
        result = self.summarise(value=value, kind='IOS_APP_DEVELOPMENT')
        self.assertFalse(result['productionRequirementsMet'])
        for key in ('productionCloudKit', 'productionPush', 'distributionSigning', 'appStoreType'): self.assertFalse(result['checks'][key])
    def test_missing_group_container_and_weather_are_detected(self):
        value = profile(audit.TARGETS['Phone']['id'], **{'com.apple.security.application-groups': [], 'com.apple.developer.icloud-container-identifiers': [], 'com.apple.developer.weatherkit': False})
        result = self.summarise(value=value)
        for key in ('expectedAppGroup', 'expectedCloudKitContainer', 'weatherKit'): self.assertFalse(result['checks'][key])
    def test_wrong_team_wildcard_expired_and_invalid_profile_fail(self):
        value = profile(audit.TARGETS['Phone']['id'], **{'application-identifier': TEAM + '.*'})
        value['TeamIdentifier'] = ['OTHERTEAM']; value['ExpirationDate'] = datetime(2000, 1, 1)
        result = self.summarise(value=value, state='INVALID')
        for key in ('expectedTeam', 'explicitBundleID', 'unexpired', 'activeProfile'): self.assertFalse(result['checks'][key])
    def test_naive_iso_expiration_is_handled_without_crash(self):
        value = profile(audit.TARGETS['Phone']['id']); value['ExpirationDate'] = '2099-01-01T00:00:00'
        self.assertTrue(self.summarise(value=value)['checks']['unexpired'])
    def test_tv_checks_baseline_without_phone_entitlements(self):
        value = profile(audit.TARGETS['TV']['id']); value['Entitlements'] = {'application-identifier': TEAM + '.' + audit.TARGETS['TV']['id'], 'get-task-allow': False}
        result = self.summarise(name='TV', value=value)
        self.assertTrue(result['productionRequirementsMet'])
        self.assertNotIn('productionCloudKit', result['checks'])
    def test_unknown_profile_content_is_unverified(self):
        requirements = audit.TARGETS['Watch']
        result = audit.profile_summary(resource(requirements['id']), requirements['id'], requirements, TEAM, lambda _: None)
        self.assertFalse(result['entitlementsVerified']); self.assertFalse(result['productionRequirementsMet'])
    def test_profile_output_contains_no_raw_secret_or_device_id(self):
        text = json.dumps(self.summarise())
        self.assertNotIn(SECRET, text); self.assertNotIn('synthetic-device-identifier-never-print', text)
        self.assertNotIn('profileContent', text); self.assertNotIn('application-identifier', text)
    def test_cms_decoder_is_pipe_only(self):
        value = {'Entitlements': {'get-task-allow': False}}
        fake = SimpleNamespace(returncode=0, stdout=plistlib.dumps(value), stderr=b'')
        with patch.object(audit.subprocess, 'run', return_value=fake) as run:
            self.assertEqual(audit.decode_profile(base64.b64encode(b'CMS-fixture').decode()), value)
        args, options = run.call_args
        self.assertEqual(args[0], ['/usr/bin/security', 'cms', '-D'])
        self.assertEqual(options['input'], b'CMS-fixture')

class ClientTests(unittest.TestCase):
    def test_only_get_and_same_api_host(self):
        seen = []
        def open_request(request, timeout):
            seen.append(request)
            return io.BytesIO(b'{"data": []}')
        client = audit.ReadClient('https://api.appstoreconnect.apple.com', SECRET, SimpleNamespace(open=open_request))
        self.assertEqual(client.collection('/v1/bundleIds?limit=50'), [])
        self.assertEqual(seen[0].get_method(), 'GET')
        self.assertEqual(seen[0].get_header('Authorization'), 'Bearer ' + SECRET)
        for path in ('https://other.example/v1', '//other.example/v1', 'http://api.appstoreconnect.apple.com/v1', 'https://user@api.appstoreconnect.apple.com/v1', '/v1#secret'):
            with self.assertRaises(audit.AuditError): client.get(path)
        self.assertEqual(len(seen), 1)
    def test_http_errors_never_echo_upstream_bodies_or_headers(self):
        def fail(request, timeout): raise HTTPError(request.full_url, 403, SECRET, {'secret': SECRET}, io.BytesIO(SECRET.encode()))
        client = audit.ReadClient('https://api.appstoreconnect.apple.com', SECRET, SimpleNamespace(open=fail))
        with self.assertRaisesRegex(audit.AuditError, '^Metadata access returned HTTP 403\\.$') as error: client.get('/v1/bundleIds')
        self.assertNotIn(SECRET, str(error.exception))
    def test_structured_diagnostics_allow_only_known_codes_and_parameters(self):
        payload = {'errors':[{'code':'PARAMETER_ERROR.INVALID','detail':SECRET,'title':SECRET,'source':{'parameter':'limit','pointer':SECRET}}, {'code':SECRET,'source':{'parameter':SECRET}}, {'code':'FORBIDDEN','source':{'parameter':'filter[identifier]'}}]}
        def fail(request, timeout): raise HTTPError(request.full_url, 400, SECRET, {'Authorization':SECRET}, io.BytesIO(json.dumps(payload).encode()))
        client = audit.ReadClient('https://api.appstoreconnect.apple.com', SECRET, SimpleNamespace(open=fail))
        with self.assertRaises(audit.AuditError) as error: client.get('/v1/bundleIds')
        self.assertEqual(error.exception.diagnostics, [{'code':'PARAMETER_ERROR.INVALID','parameter':'limit'}, {'code':'FORBIDDEN','parameter':'filter[identifier]'}])
        self.assertNotIn(SECRET, json.dumps(error.exception.diagnostics))
    def test_oversized_error_body_does_not_produce_diagnostics(self):
        failure = HTTPError('https://api.appstoreconnect.apple.com/v1',400,SECRET,{},io.BytesIO(b'X'*8193))
        self.assertEqual(audit.error_diagnostics(failure), [])
    def test_redirect_handler_will_not_forward_credentials(self):
        self.assertIsNone(audit.NoRedirect().redirect_request(None, None, 307, '', {}, 'https://other.example'))
    def test_pagination_cannot_forward_authorization_to_another_host(self):
        seen = []
        def request(req, timeout):
            seen.append(req)
            return io.BytesIO(b'{"data": [], "links":{"next":"https://other.example/collect"}}')
        client = audit.ReadClient('https://api.appstoreconnect.apple.com', SECRET, SimpleNamespace(open=request))
        with self.assertRaises(audit.AuditError): client.collection('/v1/bundleIds')
        self.assertEqual(len(seen), 1)
    def test_jwt_lifetime_and_base64_key_without_real_signing(self):
        captured = {}
        def encode(payload, key, **kwargs): captured.update(payload=payload, key=key, **kwargs); return 'synthetic-jwt'
        pem = '-----BEGIN PRIVATE KEY-----\n'+SECRET+'\n-----END PRIVATE KEY-----'
        environment = {'FASTLANE_KEY_ID':'synthetic-kid','FASTLANE_ISSUER_ID':'synthetic-issuer','FASTLANE_KEY':base64.b64encode(pem.encode()).decode(),'TEAMID':TEAM}
        with patch.dict(sys.modules, {'jwt':SimpleNamespace(encode=encode)}): self.assertEqual(audit.apple_token(environment, now=100), 'synthetic-jwt')
        self.assertEqual(captured['payload']['exp'], 700); self.assertEqual(captured['payload']['aud'], 'appstoreconnect-v1'); self.assertEqual(captured['key'], pem)
    def test_signing_errors_do_not_echo_key(self):
        environment = {'FASTLANE_KEY_ID':'kid','FASTLANE_ISSUER_ID':'issuer','FASTLANE_KEY':'-----BEGIN PRIVATE KEY-----\n'+SECRET,'TEAMID':TEAM}
        with patch.dict(sys.modules, {'jwt':SimpleNamespace(encode=lambda *a, **k: (_ for _ in ()).throw(ValueError(SECRET)))}):
            with self.assertRaises(audit.AuditError) as error: audit.apple_token(environment)
        self.assertNotIn(SECRET, str(error.exception))

class AuditTests(unittest.TestCase):
    def live_mock(self, server):
        client = audit.ReadClient('https://api.appstoreconnect.apple.com', SECRET, server)
        return audit.audit(client, TEAM, decoder=lambda content: profile(content))
    def test_every_collection_uses_conservative_limit_accepted_by_strict_api(self):
        server = StrictLimitAPI()
        result = self.live_mock(server)
        self.assertTrue(result['metadataAccessSucceeded'])
        self.assertEqual(len(server.requests), 12)
        for request in server.requests:
            self.assertEqual(request.get_method(), 'GET')
            self.assertEqual(parse_qs(urlparse(request.full_url).query)['limit'], ['50'])
        self.assertTrue(all(target['profilesVerified'] and target['capabilitiesVerified'] for target in result['targets']))
    def test_optional_limit_rejection_retries_same_get_without_limit(self):
        server = StrictLimitAPI(capability_mode='reject_limit')
        result = self.live_mock(server)
        self.assertTrue(result['metadataAccessSucceeded'])
        self.assertEqual(result['optionalLimitRetries'], 4)
        requests = [request for request in server.requests if '/bundleIdCapabilities' in request.full_url]
        self.assertEqual(len(requests), 8)
        for first, second in zip(requests[::2], requests[1::2]):
            self.assertEqual(urlparse(first.full_url).path, urlparse(second.full_url).path)
            self.assertEqual(parse_qs(urlparse(first.full_url).query), {'limit':['50']})
            self.assertEqual(urlparse(second.full_url).query, '')
            self.assertEqual(second.get_method(), 'GET')
    def test_capability_failures_do_not_prevent_profile_reads_and_are_stage_labelled(self):
        server = StrictLimitAPI(capability_mode='fail')
        result = self.live_mock(server)
        self.assertFalse(result['metadataAccessSucceeded'])
        self.assertEqual(len([request for request in server.requests if '/bundleIdCapabilities' in request.full_url]), 8)
        for target in result['targets']:
            self.assertFalse(target['capabilitiesVerified']); self.assertTrue(target['profilesVerified'])
            self.assertTrue(target['appStoreProfileRequirementsMet'])
            self.assertEqual(target['metadataErrorStage'], 'capabilities')
            self.assertEqual(target['metadataErrors'], [{'stage':'capabilities','message':'Metadata access returned HTTP 400.'}])
        rendered = audit.summary(result)
        self.assertIn('Phone capabilities: Metadata access returned HTTP 400.', rendered)
        self.assertNotIn(SECRET, rendered); self.assertNotIn('https://', rendered)
    def test_profile_failure_is_distinguished_and_auth_error_is_not_retried(self):
        server = StrictLimitAPI(profile_error=403)
        result = self.live_mock(server)
        self.assertEqual(result['optionalLimitRetries'], 0)
        for target in result['targets']:
            self.assertTrue(target['capabilitiesVerified']); self.assertFalse(target['profilesVerified'])
            self.assertEqual(target['metadataErrorStage'], 'profiles')
            self.assertEqual(target['metadataErrors'], [{'stage':'profiles','message':'Metadata access returned HTTP 403.'}])
    def test_absent_id_is_verified_absent_and_schema_never_inferred(self):
        identifier = audit.TARGETS['Watch']['id']
        client = FakeApple(missing=[identifier])
        result = audit.audit(client, TEAM, decoder=lambda _: profile(audit.TARGETS['Phone']['id']))
        watch = next(item for item in result['targets'] if item['target'] == 'Watch')
        self.assertTrue(watch['idVerified']); self.assertFalse(watch['exists'])
        self.assertFalse(result['releaseReadinessVerified']); self.assertFalse(result['cloudKitProductionSchemaVerified']); self.assertFalse(result['signingIdentityVerified'])
        self.assertTrue(result['metadataAccessSucceeded'])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertFalse(any('/v1/bundleIds/' + identifier + '/' in path for path in client.paths))
    def test_caps_are_labels_only_and_raw_settings_not_reported(self):
        result = audit.audit(FakeApple(capabilities=['ICLOUD', 'APP_GROUPS', 'secret with spaces']), TEAM, decoder=lambda _: None)
        self.assertEqual(result['targets'][0]['capabilityTypes'], ['APP_GROUPS', 'ICLOUD'])
        self.assertNotIn(SECRET, json.dumps(result)); self.assertNotIn('settings', json.dumps(result))
    def test_access_failure_is_unverified_not_absent(self):
        client = FakeApple()
        client.collection = lambda _: (_ for _ in ()).throw(audit.AuditError('Metadata access returned HTTP 401.'))
        result = audit.audit(client, TEAM)
        self.assertFalse(result['metadataAccessSucceeded'])
        for target in result['targets']:
            self.assertFalse(target['idVerified']); self.assertNotIn('exists', target)
            self.assertEqual(target['metadataErrorStage'], 'identifier_lookup')
    def test_match_uses_tree_metadata_never_blobs_or_profile_decryption(self):
        paths = []
        def get(path):
            paths.append(path)
            return {'default_branch':'main'} if len(paths)==1 else {'tree':[{'type':'blob','path':'profiles/appstore/AppStore_com.julienbell.bunway.mobileprovision'}, {'type':'blob','path':'certs/distribution/key.p12'}, {'type':'blob','path':'profiles/development/Development_com.julienbell.bunway.widget.mobileprovision'}]}
        result = audit.match_metadata(SimpleNamespace(get=get), 'synthetic-owner')
        self.assertTrue(result['available']); self.assertEqual(result['encryptedProfileCounts']['Phone']['appStore'], 1)
        self.assertEqual(result['encryptedProfileCounts']['Widget']['development'], 1)
        self.assertFalse(result['contentsVerified']); self.assertFalse(result['signingIdentityRestored'])
        self.assertEqual(paths, ['/repos/synthetic-owner/Match-Secrets', '/repos/synthetic-owner/Match-Secrets/git/trees/main?recursive=1'])
    def test_unexpected_failure_writes_safe_unverified_report(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'report.json'
            output = io.StringIO()
            with patch.object(sys, 'argv', ['audit', '--report', str(path)]), patch.object(audit, 'apple_token', side_effect=ValueError(SECRET)), redirect_stdout(output):
                self.assertEqual(audit.main(), 1)
            result = json.loads(path.read_text())
            self.assertFalse(result['metadataAccessSucceeded'])
            self.assertFalse(result['releaseReadinessVerified'])
            self.assertNotIn(SECRET, output.getvalue()); self.assertNotIn(SECRET, path.read_text())

class WorkflowIsolationTests(unittest.TestCase):
    def test_push_branch_cannot_run_inherited_workflows(self):
        import yaml
        root = Path(__file__).resolve().parents[1]
        runners = []
        for path in sorted((root/'.github/workflows').glob('*.yml')):
            value = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            events = value.get('on', {})
            if not isinstance(events, dict): continue
            self.assertNotIn('workflow_run', events, str(path))
            push = events.get('push')
            if push is None: continue
            self.assertIsInstance(push, dict, str(path))
            # Exact branches make this an allow-list, without wildcard ambiguity.
            branches = push.get('branches')
            self.assertIsInstance(branches, list, str(path))
            self.assertFalse(any('*' in branch or '?' in branch or '!' in branch for branch in branches), str(path))
            if 'codex/bunway-apple-preflight' in branches: runners.append(path.name)
        self.assertEqual(runners, ['bunway_apple_preflight.yml'])
        workflow = yaml.load((root/'.github/workflows/bunway_apple_preflight.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(workflow['permissions'], {'contents':'read'})
        self.assertEqual(workflow['jobs']['audit']['if'], "github.ref == 'refs/heads/codex/bunway-apple-preflight'")
        encoded = json.dumps(workflow)
        for forbidden in ('MATCH_PASSWORD', 'fastlane ', 'workflow_call', 'workflow_run', 'create_certs', 'add_identifiers'): self.assertNotIn(forbidden, encoded)
        self.assertTrue((root/'Scripts/bunway_apple_preflight.py').is_file())

if __name__ == '__main__': unittest.main()
