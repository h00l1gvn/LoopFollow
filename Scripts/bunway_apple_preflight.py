#!/usr/bin/env python3
"""Read-only Bunway Apple metadata audit. Never issues profiles or prints credentials."""
from __future__ import annotations
import argparse, base64, json, os, plistlib, re, subprocess, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, build_opener, HTTPRedirectHandler

GROUP = 'group.com.julienbell.bunway'
CONTAINER = 'iCloud.com.julienbell.bunway'
PAGE_LIMIT = 50
ERROR_CODES = frozenset({'PARAMETER_ERROR.INVALID', 'PARAMETER_ERROR.UNKNOWN', 'PARAMETER_ERROR.REQUIRED', 'ENTITY_ERROR.ATTRIBUTE.INVALID', 'ENTITY_ERROR.RELATIONSHIP.INVALID', 'NOT_FOUND', 'FORBIDDEN', 'NOT_AUTHORIZED', 'ACCESS_DENIED', 'RATE_LIMIT_EXCEEDED', 'INTERNAL_ERROR', 'BAD_GATEWAY', 'UNAUTHORIZED', 'INVALID_REQUEST'})
ERROR_PARAMETERS = frozenset({'limit', 'filter[identifier]', 'fields[bundleIdCapabilities]', 'fields[profiles]'})
TARGETS = {
    'Phone': {'id': 'com.julienbell.bunway', 'cloud': True, 'group': True, 'push': True, 'weather': True},
    'Watch': {'id': 'com.julienbell.bunway.watchkitapp', 'cloud': True, 'group': True},
    'Widget': {'id': 'com.julienbell.bunway.widget', 'group': True},
    'TV': {'id': 'com.julienbell.bunway.tv'},
}

class AuditError(Exception):
    """Contains only a fixed message/status; never an upstream body or credential."""
    def __init__(self, message: str, http_status: int | None = None, diagnostics: list[dict] | None = None):
        super().__init__(message)
        self.http_status = http_status
        self.diagnostics = diagnostics or []

def error_diagnostics(error: HTTPError) -> list[dict]:
    """Extract only fixed known enum/parameter values, never upstream detail."""
    try:
        raw = error.read(8193)
        if len(raw) > 8192: return []
        body = json.loads(raw)
        errors = body.get('errors') if isinstance(body, dict) else None
        if not isinstance(errors, list): return []
        result = []
        for value in errors[:5]:
            if not isinstance(value, dict): continue
            code = value.get('code')
            source = value.get('source')
            parameter = source.get('parameter') if isinstance(source, dict) else None
            safe = {}
            if isinstance(code, str) and code in ERROR_CODES: safe['code'] = code
            if isinstance(parameter, str) and parameter in ERROR_PARAMETERS: safe['parameter'] = parameter
            if safe: result.append(safe)
        return result
    except (AttributeError, OSError, TypeError, ValueError, UnicodeError):
        return []

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class ReadClient:
    def __init__(self, origin: str, token: str, opener=None):
        self.origin, self.token = origin, token
        self.opener = opener or build_opener(NoRedirect())
        self.query_compatibility_retries = 0
    def get(self, path: str) -> dict:
        url = urljoin(self.origin + '/', path)
        parsed, expected = urlparse(url), urlparse(self.origin)
        if parsed.scheme != 'https' or parsed.netloc != expected.netloc or parsed.username or parsed.password or parsed.fragment:
            raise AuditError('A metadata link was outside the authorized API host.')
        request = Request(url, headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json', 'User-Agent': 'Bunway-read-only-preflight'}, method='GET')
        try:
            with self.opener.open(request, timeout=45) as response:
                raw = response.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024: raise AuditError('Metadata response was too large.')
            value = json.loads(raw)
            if not isinstance(value, dict): raise AuditError('Metadata response was not a JSON object.')
            return value
        except HTTPError as error:
            raise AuditError(f'Metadata access returned HTTP {error.code}.', http_status=error.code, diagnostics=error_diagnostics(error)) from None
        except (URLError, TimeoutError, OSError):
            raise AuditError('Metadata service could not be reached.') from None
        except (ValueError, UnicodeError):
            raise AuditError('Metadata response could not be read.') from None
    def collection(self, path: str) -> list[dict]:
        result = []
        retried_without_limit = False
        for _ in range(20):
            try:
                value = self.get(path)
            except AuditError as error:
                # Some live relationship endpoints reject an optional limit
                # despite its documented presence. Retry only that GET once,
                # retaining all other parameters and the same host boundary.
                parts = urlparse(path)
                query = parse_qsl(parts.query, keep_blank_values=True)
                if error.http_status != 400 or retried_without_limit or not any(key == 'limit' for key, _ in query): raise
                path = urlunparse(parts._replace(query=urlencode([(key, value) for key, value in query if key != 'limit'])))
                retried_without_limit = True
                self.query_compatibility_retries += 1
                value = self.get(path)
            data = value.get('data')
            if not isinstance(data, list): raise AuditError('Metadata collection was incomplete.')
            result.extend(entry for entry in data if isinstance(entry, dict))
            links = value.get('links') or {}
            if not isinstance(links, dict): raise AuditError('Metadata pagination was invalid.')
            next_page = links.get('next')
            if not next_page: return result
            if not isinstance(next_page, str): raise AuditError('Metadata pagination was invalid.')
            path = next_page
        raise AuditError('Metadata pagination exceeded its bounded audit limit.')


def apple_token(environment: dict[str, str], now: int | None = None) -> str:
    required = ('FASTLANE_KEY_ID', 'FASTLANE_ISSUER_ID', 'FASTLANE_KEY', 'TEAMID')
    if any(not environment.get(key) for key in required): raise AuditError('Required Apple CI credentials are not configured.')
    key = environment['FASTLANE_KEY'].replace('\\n', '\n').strip()
    if '-----BEGIN PRIVATE KEY-----' not in key:
        try: key = base64.b64decode(key, validate=True).decode('utf-8')
        except (ValueError, UnicodeError): raise AuditError('The stored Apple key format could not be read.') from None
    current = int(time.time()) if now is None else now
    try:
        import jwt
        return jwt.encode({'iss': environment['FASTLANE_ISSUER_ID'], 'iat': current, 'exp': current + 600, 'aud': 'appstoreconnect-v1'}, key, algorithm='ES256', headers={'kid': environment['FASTLANE_KEY_ID'], 'typ': 'JWT'})
    except Exception:
        raise AuditError('The stored Apple API key could not sign an audit request.') from None


def decode_profile(content: str) -> dict | None:
    """Decode CMS in a pipe. No profile file, certificate key, or raw XML is saved."""
    try:
        raw = base64.b64decode(content, validate=True)
        if len(raw) > 2 * 1024 * 1024: return None
        process = subprocess.run(['/usr/bin/security', 'cms', '-D'], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if process.returncode: return None
        value = plistlib.loads(process.stdout)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, subprocess.SubprocessError, plistlib.InvalidFileException):
        return None


def profile_summary(resource: dict, identifier: str, requirements: dict, team: str, decoder=decode_profile) -> dict:
    attributes = resource.get('attributes') or {}
    # Allow only public enum/date fields. Never echo arbitrary upstream strings.
    def enum(value):
        return value if isinstance(value, str) and re.fullmatch(r'[A-Z0-9_]{1,80}', value) else None
    date = attributes.get('expirationDate')
    result = {'type': enum(attributes.get('profileType')), 'state': enum(attributes.get('profileState')), 'expires': date if isinstance(date, str) and re.fullmatch(r'[0-9T:.+Z-]{1,40}', date) else None, 'entitlementsVerified': False, 'productionRequirementsMet': False}
    content = attributes.get('profileContent')
    profile = decoder(content) if isinstance(content, str) and content else None
    if not profile:
        result['unverifiedReason'] = 'Signed profile content was unavailable or could not be decoded.'
        return result
    entitlements = profile.get('Entitlements') or {}
    application = entitlements.get('application-identifier') or entitlements.get('com.apple.application-identifier') or ''
    expiration = profile.get('ExpirationDate')
    if isinstance(expiration, datetime): expiry = expiration.replace(tzinfo=timezone.utc) if expiration.tzinfo is None else expiration
    else:
        try:
            expiry = datetime.fromisoformat(str(expiration).replace('Z', '+00:00'))
            if expiry.tzinfo is None: expiry = expiry.replace(tzinfo=timezone.utc)
        except ValueError: expiry = None
    checks = {
        'expectedTeam': team in (profile.get('TeamIdentifier') or []),
        'explicitBundleID': isinstance(application, str) and application.endswith('.' + identifier),
        'unexpired': expiry is not None and expiry > datetime.now(timezone.utc),
        'distributionSigning': entitlements.get('get-task-allow') is not True,
        'activeProfile': attributes.get('profileState') == 'ACTIVE',
        'appStoreType': attributes.get('profileType') == ('TVOS_APP_STORE' if identifier.endswith('.tv') else 'IOS_APP_STORE'),
    }
    if requirements.get('group'): checks['expectedAppGroup'] = GROUP in (entitlements.get('com.apple.security.application-groups') or [])
    if requirements.get('cloud'):
        checks['cloudKitService'] = 'CloudKit' in (entitlements.get('com.apple.developer.icloud-services') or [])
        containers = (entitlements.get('com.apple.developer.icloud-container-identifiers') or []) + (entitlements.get('com.apple.developer.icloud-container-development-container-identifiers') or [])
        checks['expectedCloudKitContainer'] = CONTAINER in containers
        environments = entitlements.get('com.apple.developer.icloud-container-environment') or []
        checks['productionCloudKit'] = 'Production' in ([environments] if isinstance(environments, str) else environments)
    if requirements.get('push'): checks['productionPush'] = entitlements.get('aps-environment') == 'production'
    if requirements.get('weather'): checks['weatherKit'] = entitlements.get('com.apple.developer.weatherkit') is True
    result.update(entitlementsVerified=True, checks=checks, productionRequirementsMet=all(checks.values()))
    return result


def match_metadata(client: ReadClient | None, owner: str) -> dict:
    """Read only encrypted profile filenames. Never fetch/decrypt a blob or private key."""
    if not client: return {'available': False, 'reason': 'Match repository read credential was not configured.'}
    if not re.fullmatch(r'[A-Za-z0-9_-]+', owner): return {'available': False, 'reason': 'Match repository owner was invalid.'}
    try:
        repository = f'/repos/{owner}/Match-Secrets'
        branch = client.get(repository).get('default_branch')
        if not isinstance(branch, str): raise AuditError('Match repository branch metadata was incomplete.')
        tree = client.get(repository + '/git/trees/' + quote(branch, safe='') + '?recursive=1')
        entries = tree.get('tree')
        if not isinstance(entries, list) or tree.get('truncated'): raise AuditError('Match profile listing was incomplete.')
        counts = {}
        for name, requirements in TARGETS.items():
            identifier = requirements['id']
            paths = [entry.get('path', '') for entry in entries if isinstance(entry, dict) and entry.get('type') == 'blob' and isinstance(entry.get('path'), str) and entry['path'].startswith('profiles/') and entry['path'].endswith('_' + identifier + '.mobileprovision')]
            counts[name] = {'appStore': sum('AppStore_' in path for path in paths), 'adHoc': sum('AdHoc_' in path for path in paths), 'development': sum('Development_' in path for path in paths)}
        return {'available': True, 'encryptedProfileCounts': counts, 'contentsVerified': False, 'signingIdentityRestored': False}
    except AuditError as error:
        return {'available': False, 'reason': str(error)}


def audit(apple: ReadClient, team: str, github: ReadClient | None = None, owner: str = '', decoder=decode_profile) -> dict:
    report = {'mode': 'read_only', 'releaseReadinessVerified': False, 'cloudKitProductionSchemaVerified': False, 'cloudKitNote': 'Schema and container associations require separate account verification. This audit never changes them.', 'signingIdentityVerified': False, 'targets': [], 'matchStorage': match_metadata(github, owner), 'metadataAccessSucceeded': True}
    for name, requirements in TARGETS.items():
        identifier = requirements['id']; target = {'target': name, 'identifier': identifier, 'idVerified': False, 'capabilitiesVerified': False, 'profilesVerified': False, 'appStoreProfileRequirementsMet': False}
        def record_error(stage: str, error: AuditError):
            value = {'stage': stage, 'message': str(error)}
            if error.diagnostics: value['diagnostics'] = error.diagnostics
            target.setdefault('metadataErrors', []).append(value)
            target.setdefault('metadataError', str(error))
            target.setdefault('metadataErrorStage', stage)
            report['metadataAccessSucceeded'] = False
        try:
            resources = apple.collection('/v1/bundleIds?' + urlencode({'filter[identifier]': identifier, 'limit': PAGE_LIMIT}))
            bundle = next((entry for entry in resources if entry.get('attributes', {}).get('identifier') == identifier), None)
            target['idVerified'] = True; target['exists'] = bundle is not None
        except AuditError as error:
            record_error('identifier_lookup', error)
            report['targets'].append(target)
            continue
        if bundle:
            bundle_id = quote(str(bundle['id']), safe='')
            try:
                capabilities = apple.collection(f'/v1/bundleIds/{bundle_id}/bundleIdCapabilities?limit={PAGE_LIMIT}')
                # Only capability type labels are reported; never raw settings or associated records.
                labels = [entry.get('attributes', {}).get('capabilityType') for entry in capabilities]
                target['capabilityTypes'] = sorted({label for label in labels if isinstance(label, str) and re.fullmatch(r'[A-Z0-9_]{1,80}', label)})
                target['capabilitiesVerified'] = True
            except AuditError as error:
                record_error('capabilities', error)
            # Profile reads remain useful even if the capabilities read failed.
            try:
                profiles = apple.collection(f'/v1/bundleIds/{bundle_id}/profiles?limit={PAGE_LIMIT}')
                summaries = [profile_summary(profile, identifier, requirements, team, decoder) for profile in profiles]
                target['profiles'] = summaries; target['profilesVerified'] = True
                target['appStoreProfileRequirementsMet'] = any(value['productionRequirementsMet'] for value in summaries)
            except AuditError as error:
                record_error('profiles', error)
        report['targets'].append(target)
    report['optionalLimitRetries'] = getattr(apple, 'query_compatibility_retries', 0)
    return report


def summary(report: dict) -> str:
    lines = ['## Bunway Apple preflight — read only', '', '**This report does not start a release. Production CloudKit schema remains unverified.**', '', '| Target | App ID | Profile requirements |', '| --- | --- | --- |']
    for target in report.get('targets', []):
        identity = 'present' if target.get('exists') else 'absent' if target.get('idVerified') else 'unverified'
        profile = 'verified' if target.get('appStoreProfileRequirementsMet') else 'not verified'
        lines.append(f"| {target['target']} | {identity} | {profile} |")
        for error in target.get('metadataErrors', []): lines.append(f"\n{target['target']} {error['stage']}: {error['message']}\n")
    lines += ['', 'No capabilities, IDs, groups, containers, profiles, certificates, devices, or CloudKit schema were created or changed. No archive, upload, or installation was performed. Match inspection lists encrypted profile filenames only; it does not restore signing identities.', '']
    return '\n'.join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--report', type=Path, required=True); parser.add_argument('--summary', type=Path)
    args = parser.parse_args()
    try:
        apple = ReadClient('https://api.appstoreconnect.apple.com', apple_token(os.environ))
        github = ReadClient('https://api.github.com', os.environ['GH_PAT']) if os.environ.get('GH_PAT') else None
        report = audit(apple, os.environ['TEAMID'], github, os.environ.get('GITHUB_REPOSITORY_OWNER', ''))
    except AuditError as error:
        report = {'mode': 'read_only', 'releaseReadinessVerified': False, 'cloudKitProductionSchemaVerified': False, 'metadataAccessSucceeded': False, 'error': str(error), 'targets': []}
    except Exception:
        # Unexpected response shapes also must not expose upstream data in a traceback.
        report = {'mode': 'read_only', 'releaseReadinessVerified': False, 'cloudKitProductionSchemaVerified': False, 'metadataAccessSucceeded': False, 'error': 'Metadata audit could not complete. No account changes were made.', 'targets': []}
    args.report.parent.mkdir(parents=True, exist_ok=True); args.report.write_text(json.dumps(report, indent=2) + '\n')
    if args.summary:
        with args.summary.open('a') as destination: destination.write(summary(report)); destination.write('\n' + report['error'] + '\n' if report.get('error') else '')
    print(json.dumps(report, indent=2))
    return 0 if report['metadataAccessSucceeded'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
