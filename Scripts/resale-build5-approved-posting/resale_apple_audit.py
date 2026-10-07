#!/usr/bin/env python3
"""GET-only exact-scope ResaleBurrow CI credential/signing-material audit. No portal/Match/keychain mutation."""
from __future__ import annotations
import argparse, base64, json, os, plistlib, re, subprocess, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, build_opener, HTTPRedirectHandler

CONFIG = json.loads((Path(__file__).parent / 'scope.json').read_text())
GROUP = CONFIG['group']
PAGE_LIMIT = 50
ERROR_CODES = frozenset({'NOT_FOUND', 'FORBIDDEN', 'NOT_AUTHORIZED', 'ACCESS_DENIED', 'RATE_LIMIT_EXCEEDED', 'UNAUTHORIZED'})
ERROR_PARAMETERS = frozenset({'limit', 'filter[identifier]', 'filter[bundleId]'})
TARGETS = {t['target']: {'id': t['bundle_id'], 'group': True, 'profile_type': t['profile_type'], 'primary_asc': t['primary_asc']} for t in CONFIG['targets']}

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
        if origin not in ('https://api.github.com', 'https://api.appstoreconnect.apple.com'):
            raise AuditError('Unapproved metadata origin.')
        self.origin, self.token = origin, token
        self.opener = opener or build_opener(NoRedirect())
        self.query_compatibility_retries = 0
    def get(self, path: str) -> dict:
        url = urljoin(self.origin + '/', path)
        parsed, expected = urlparse(url), urlparse(self.origin)
        if parsed.scheme != 'https' or parsed.netloc != expected.netloc or parsed.username or parsed.password or parsed.fragment:
            raise AuditError('A metadata link was outside the authorized API host.')
        validate_metadata_path(self.origin, parsed)
        request = Request(url, headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json', 'User-Agent': 'ResaleBurrow-read-only-preflight'}, method='GET')
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
        anchor = urlparse(urljoin(self.origin + '/', path))
        filter_values = {k:v for k,v in parse_qsl(anchor.query) if k.startswith('filter[')}
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
            next_parts = urlparse(urljoin(self.origin + '/', next_page))
            if next_parts.path != anchor.path or {k:v for k,v in parse_qsl(next_parts.query) if k.startswith('filter[')} != filter_values:
                raise AuditError('Metadata pagination escaped the original exact collection scope.')
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


def validate_metadata_path(origin, parsed):
    query = dict(parse_qsl(parsed.query))
    if origin == 'https://api.appstoreconnect.apple.com':
        if parsed.path == '/v1/bundleIds' and query.get('filter[identifier]') in {t['id'] for t in TARGETS.values()} and set(query) <= {'filter[identifier]','limit','cursor'}: return
        if re.fullmatch(r'/v1/certificates/[A-Za-z0-9_-]+', parsed.path) and not query: return
        if re.fullmatch(r'/v1/bundleIds/[A-Za-z0-9_-]+/(bundleIdCapabilities|profiles)', parsed.path) and set(query) <= {'limit','cursor'}: return
        if parsed.path == '/v1/apps' and query.get('filter[bundleId]') in {t['id'] for t in TARGETS.values() if t['primary_asc']} and set(query) <= {'filter[bundleId]','limit','cursor'}: return
    else:
        allowed = ['/repos/' + CONFIG['source_repository'], '/repos/' + CONFIG['source_repository'] + '/git/commits/' + CONFIG['source_sha'], '/repos/' + CONFIG['match_repository'], '/repos/' + CONFIG['match_repository'] + '/git/trees/master']
        if parsed.path in allowed and set(query) <= {'recursive'}: return
        if re.fullmatch('/repos/' + re.escape(CONFIG['match_repository']) + r'/git/blobs/[0-9a-f]{40}', parsed.path) and not query: return
    raise AuditError('Metadata path is outside the exact approved audit scope.')

def decrypt_match_candidates(encoded: bytes, password: str):
    """Official Match 2.237 V2 authentication and V1 legacy compatibility, memory only."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    import hashlib
    data = base64.b64decode(b''.join(encoded.split()), validate=True)
    if data.startswith(b'match_encrypted_v2__'):
        salt, tag, ciphertext = data[20:28], data[28:44], data[44:]
        keyiv = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 10000, 68)
        yield AESGCM(keyiv[:32]).decrypt(keyiv[32:44], ciphertext + tag, keyiv[44:])
    elif data.startswith(b'Salted__'):
        salt = data[8:16]
        for digest in ('md5', 'sha256'):
            try:
                keyiv = b''; last = b''
                while len(keyiv) < 48:
                    last = hashlib.new(digest, last + password.encode() + salt).digest(); keyiv += last
                decryptor = Cipher(algorithms.AES(keyiv[:32]), modes.CBC(keyiv[32:48])).decryptor()
                padded = decryptor.update(data[16:]) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                yield unpadder.update(padded) + unpadder.finalize()
            except Exception: continue
    else: raise AuditError('Existing encrypted certificate format was not recognized.')

def certificate_key_check(raw: bytes, team: str, certificate_raw: bytes | None = None, diagnostics: dict | None = None):
    """Accept real PKCS12 or Fastlane's PEM .p12 with its exact paired .cer.

    Diagnostics contain fixed counters only, never parser exceptions, subjects or keys.
    Fastlane 2.237 cert/runner.rb writes a PEM private key under the .p12 name.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PublicFormat, load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    def count(stage):
        if diagnostics is not None:
            values = diagnostics.setdefault('stage_counts', {})
            values[stage] = values.get(stage, 0) + 1
    def fail(reason):
        if diagnostics is not None:
            values = diagnostics.setdefault('failure_counts', {})
            values[reason] = values.get(reason, 0) + 1
        return False
    key = cert = None
    key_format = 'pkcs12'
    try: key, cert, _ = pkcs12.load_key_and_certificates(raw, b'')
    except (ValueError, TypeError): pass
    if key is None:
        key_format = 'pem_with_paired_certificate'
        try: key = load_pem_private_key(raw, password=None)
        except (ValueError, TypeError): return fail('private_key_parse_failed')
        count('private_key_parsed')
        if certificate_raw is None: return fail('paired_certificate_missing')
        try:
            cert = x509.load_der_x509_certificate(certificate_raw)
        except ValueError:
            try: cert = x509.load_pem_x509_certificate(certificate_raw)
            except ValueError: return fail('paired_certificate_parse_failed')
    else: count('private_key_parsed')
    if cert is None: return fail('embedded_certificate_missing')
    count('certificate_parsed')
    teams = [x.value for x in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)]
    expiry = cert.not_valid_after_utc
    valid_from = cert.not_valid_before_utc
    now = datetime.now(timezone.utc)
    if teams != [team]: return fail('certificate_team_mismatch')
    count('certificate_team_verified')
    if not valid_from <= now < expiry: return fail('certificate_outside_validity')
    count('certificate_dates_verified')
    if cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo): return fail('private_key_certificate_mismatch')
    count('private_key_certificate_match')
    message = b'ResaleBurrow signing preflight fixed local challenge; no Apple operation'
    try:
        if isinstance(key, rsa.RSAPrivateKey):
            signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256()); cert.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            signature = key.sign(message, ec.ECDSA(hashes.SHA256())); cert.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else: return fail('private_key_type_unsupported')
    except Exception: return fail('private_key_challenge_failed')
    count('private_key_challenge_verified')
    return {'fingerprint':cert.fingerprint(hashes.SHA256()).hex(), 'expires_at':expiry.isoformat(), 'key_format':key_format}

def eligible_certificate_classes(native_type):
    return {'DISTRIBUTION':('distribution','mac_app_distribution'), 'IOS_DISTRIBUTION':('distribution',), 'MAC_APP_DISTRIBUTION':('mac_app_distribution',), 'MAC_INSTALLER_DISTRIBUTION':('mac_installer_distribution',)}.get(native_type,())

def audit_existing_certificate_keys(client, entries, apple=None):
    """Only shared distribution/installer key + exact sibling cert blobs, memory only."""
    password = os.environ.get('MATCH_PASSWORD')
    result = {'mode':'get_only_memory_decryption', 'distribution':False, 'mac_app_distribution':False, 'mac_installer_distribution':False, 'selected':{}, 'stage_counts':{}, 'failure_counts':{}, 'keychain_modified':False, 'new_certificate_created':False}
    def count(stage, failure=False):
        values = result['failure_counts' if failure else 'stage_counts']
        values[stage] = values.get(stage, 0) + 1
    if not password: return dict(result, limitation='MATCH_PASSWORD is not configured; private-key usability unverified.')
    relevant = [e for e in entries if re.fullmatch(r'certs/(distribution|mac_app_distribution|mac_installer_distribution)/[A-Za-z0-9_-]+[.]p12',e.get('path','')) and re.fullmatch(r'[0-9a-f]{40}',e.get('sha',''))]
    if len(relevant) > 20: return dict(result, limitation='Existing certificate list exceeded the bounded audit limit.')
    paths = {}
    for entry in entries:
        path = entry.get('path', '')
        if re.fullmatch(r'certs/(distribution|mac_app_distribution|mac_installer_distribution)/[A-Za-z0-9_-]+[.](p12|cer)', path) and re.fullmatch(r'[0-9a-f]{40}', entry.get('sha', '')):
            if path in paths: return dict(result, limitation='Existing certificate tree contained an ambiguous duplicate path.')
            paths[path] = entry
    def decrypted_blob(entry, kind):
        try:
            blob = client.get('/repos/' + CONFIG['match_repository'] + '/git/blobs/' + entry['sha'])
            count(kind + '_blob_get_succeeded')
            if blob.get('encoding') != 'base64' or not isinstance(blob.get('content'), str):
                count(kind + '_blob_encoding_invalid', True); return []
            encrypted = base64.b64decode(b''.join(blob['content'].encode().split()), validate=True)
            if not encrypted or len(encrypted) > 2 * 1024 * 1024:
                count(kind + '_blob_size_invalid', True); return []
            values = list(decrypt_match_candidates(encrypted, password))
            if not values: count(kind + '_decrypt_no_candidate', True)
            else: count(kind + '_decrypt_succeeded')
            return values
        except AuditError as error:
            count(kind + '_metadata_get_failed', True)
            result.setdefault('limitations', []).append({'reason': str(error), 'http_status': error.http_status})
        except Exception: count(kind + '_decrypt_or_encoding_failed', True)
        return []
    for e in sorted(relevant, key=lambda entry: entry['path']):
        count('private_key_candidate_selected')
        paired = paths.get(e['path'].removesuffix('.p12') + '.cer')
        if paired: count('exact_paired_certificate_selected')
        else: count('paired_certificate_path_missing', True)
        key_values = decrypted_blob(e, 'private_key')
        if not key_values: continue
        cert_values = decrypted_blob(paired, 'paired_certificate') if paired else []
        for raw in key_values:
            for certificate_raw in cert_values or [None]:
                try:
                    check=certificate_key_check(raw,CONFIG['team'],certificate_raw,result)
                    if not check: continue
                    if apple is None:
                        count('current_apple_client_missing', True); continue
                    identifier=e['path'].rsplit('/',1)[-1].removesuffix('.p12')
                    resource=apple.get('/v1/certificates/'+quote(identifier,safe='')).get('data',{})
                    count('current_apple_certificate_get_succeeded')
                    if resource.get('id') != identifier:
                        count('current_apple_certificate_id_mismatch', True); continue
                    native=resource.get('attributes',{})
                    from cryptography import x509
                    from cryptography.hazmat.primitives import hashes
                    try: native_cert=x509.load_der_x509_certificate(base64.b64decode(native.get('certificateContent',''), validate=True))
                    except Exception:
                        count('current_apple_certificate_parse_failed', True); continue
                    if native_cert.fingerprint(hashes.SHA256()).hex() != check['fingerprint']:
                        count('current_apple_certificate_fingerprint_mismatch', True); continue
                    count('current_apple_certificate_fingerprint_verified')
                    classes=eligible_certificate_classes(native.get('certificateType'))
                    if not classes:
                        count('current_apple_certificate_type_ineligible', True); continue
                    count('current_apple_certificate_type_verified')
                    for kind in classes:
                        if not result[kind]:
                            result[kind]=True
                            result['selected'][kind]={'certificate_id':identifier,'sha256':check['fingerprint'],'type':native['certificateType'],'expires_at':check['expires_at'],'existing_private_key_challenge_verified':True,'exact_current_apple_certificate_verified':True}
                    count('verified_' + check['key_format'])
                    break
                except AuditError as error:
                    count('current_apple_certificate_get_failed', True)
                    result.setdefault('limitations',[]).append({'reason':str(error),'http_status':error.http_status})
                except Exception: count('bounded_certificate_check_failed', True)
    result['note']='Usability matches exact current Apple certificate GET and local private-key challenge under the encrypted store, not an archive/export result. Missing/failed material is unverified; no new certificate is justified automatically.'
    return result


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
        'explicitBundleID': application == team + '.' + identifier,
        'unexpired': expiry is not None and expiry > datetime.now(timezone.utc),
        'distributionSigning': entitlements.get('get-task-allow') is not True,
        'activeProfile': attributes.get('profileState') == 'ACTIVE',
        'appStoreType': attributes.get('profileType') == requirements['profile_type'],
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


def match_metadata(client: ReadClient | None, owner: str, apple=None) -> dict:
    if not client: return {'available': False, 'reason': 'Match read credential was not configured.'}
    try:
        repo = '/repos/' + CONFIG['match_repository']
        metadata = client.get(repo)
        if metadata.get('private') is not True: raise AuditError('Signing material repository is not private.')
        tree = client.get(repo + '/git/trees/master?recursive=1')
        entries = tree.get('tree')
        if not isinstance(entries, list) or tree.get('truncated'): raise AuditError('Match tree was incomplete.')
        counts = {}
        for name, requirement in TARGETS.items():
            suffix = '.provisionprofile' if requirement['profile_type'] == 'MAC_APP_STORE' else '.mobileprovision'
            paths = [e.get('path','') for e in entries if e.get('type') == 'blob' and e.get('path','').startswith('profiles/') and e.get('path','').endswith('_' + requirement['id'] + suffix)]
            counts[name] = {'appStore': sum('AppStore_' in p for p in paths)}
        materials = audit_existing_certificate_keys(client, entries, apple)
        return {'available': True, 'branch': 'master', 'encryptedProfileCounts': counts, 'certificate_material': materials, 'profilesDecrypted': False, 'signingIdentityRestoredToKeychain': False}
    except AuditError as error:
        return {'available': False, 'reason': str(error)}


def audit(apple: ReadClient, team: str, github: ReadClient | None = None, owner: str = '', decoder=decode_profile) -> dict:
    report = {'mode': 'read_only', 'releaseReadinessVerified': False, 'signingIdentityInstalled': False, 'targets': [], 'matchStorage': match_metadata(github, owner, apple), 'metadataAccessSucceeded': True}
    for name, requirements in TARGETS.items():
        identifier = requirements['id']; target = {'target': name, 'identifier': identifier, 'idVerified': False, 'capabilitiesVerified': False, 'profilesVerified': False, 'appStoreProfileRequirementsMet': False, 'primaryASCRecordVerified': False}
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
                target['groupAssociationVerifiedByCapabilityLabel'] = False
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
        if requirements.get('primary_asc'):
            try:
                apps = apple.collection('/v1/apps?' + urlencode({'filter[bundleId]': identifier, 'limit': PAGE_LIMIT}))
                target['primaryASCRecordVerified'] = any(a.get('attributes',{}).get('bundleId') == identifier for a in apps)
            except AuditError as error: record_error('asc_record_lookup', error)
        report['targets'].append(target)
    if github:
        try:
            repo = github.get('/repos/' + CONFIG['source_repository'])
            commit = github.get('/repos/' + CONFIG['source_repository'] + '/git/commits/' + CONFIG['source_sha'])
            report['privateSourceAccessVerified'] = repo.get('private') is True and commit.get('sha') == CONFIG['source_sha']
        except AuditError as error:
            report['privateSourceAccessVerified'] = False; report['privateSourceAccessError'] = str(error)
    else: report['privateSourceAccessVerified'] = False
    material=report.get('matchStorage',{}).get('certificate_material',{})
    report['credentialContextVerified']=report['metadataAccessSucceeded'] and report.get('privateSourceAccessVerified') is True and report.get('matchStorage',{}).get('available') is True and all(material.get(k) is True for k in ('distribution','mac_app_distribution','mac_installer_distribution'))
    report['canCreateExactScopedProfilesUsingExistingCertificates']=report['credentialContextVerified']
    report['optionalLimitRetries'] = getattr(apple, 'query_compatibility_retries', 0)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--report', type=Path, required=True); parser.add_argument('--summary', type=Path)
    args = parser.parse_args()
    try:
        if os.environ.get('TEAMID') != CONFIG['team']: raise AuditError('CI Team does not match the reviewed Resale scope.')
        apple = ReadClient('https://api.appstoreconnect.apple.com', apple_token(os.environ))
        github = ReadClient('https://api.github.com', os.environ['GH_PAT']) if os.environ.get('GH_PAT') else None
        report = audit(apple, os.environ['TEAMID'], github, os.environ.get('GITHUB_REPOSITORY_OWNER', ''))
    except AuditError as error:
        report = {'mode': 'read_only', 'releaseReadinessVerified': False, 'cloudKitProductionSchemaVerified': False, 'metadataAccessSucceeded': False, 'error': str(error), 'targets': []}
    except Exception:
        # Unexpected response shapes also must not expose upstream data in a traceback.
        report = {'mode': 'read_only', 'releaseReadinessVerified': False, 'cloudKitProductionSchemaVerified': False, 'metadataAccessSucceeded': False, 'error': 'Metadata audit could not complete. No account changes were made.', 'targets': []}
    args.report.parent.mkdir(parents=True, exist_ok=True); args.report.write_text(json.dumps(report, indent=2) + '\n'); os.chmod(args.report, 0o600)
    if args.summary:
        with args.summary.open('a') as destination: destination.write('ResaleBurrow scoped GET-only audit finished; inspect sanitized report. No Apple, Match, source or delivery mutation.\n')
    print(json.dumps(report, indent=2))
    return 0 if report.get('credentialContextVerified') is True else 1

if __name__ == '__main__':
    raise SystemExit(main())
