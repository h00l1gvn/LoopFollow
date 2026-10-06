// Resale envelope around the unchanged reviewed Bunway AES-GCM file helper.
// Random artifact AES key is RSA-OAEP wrapped; recipient private key stays local.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const envelope = require('./artifact_crypto.cjs');
const VERSION = 1;
const FAMILIES = new Set(['ios', 'macos', 'tvos']);
class Invalid extends Error {}

function readRegular(file, maximum, requirePrivate = false) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size < 1 || info.size > maximum) throw new Invalid('Invalid key or manifest file.');
    if (requirePrivate && ((info.mode & 0o077) || (process.getuid && info.uid !== process.getuid()))) throw new Invalid('Recipient private key must be an owner-only file.');
    return fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
}
function manifest(file) {
  const value = JSON.parse(readRegular(file, 65536).toString('utf8'));
  if (!/^[0-9a-f]{40}$/.test(value.source_sha || '') || !/^[0-9a-f]{64}$/.test(value.recipient_spki_sha256 || '')) throw new Invalid('Reviewed source and recipient fingerprint are required.');
  return value;
}
function context(scope, family, runId) {
  if (!FAMILIES.has(family) || !/^[1-9][0-9]{0,24}$/.test(runId || '')) throw new Invalid('Exact family and trusted run ID are required.');
  return Buffer.from(`ResaleBurrow export v${VERSION}|${scope.source_sha}|${family}|${runId}`);
}
function publicKey(file, scope) {
  const key = crypto.createPublicKey(readRegular(file, 16384));
  const der = key.export({type:'spki', format:'der'});
  const fingerprint = crypto.createHash('sha256').update(der).digest('hex');
  if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 3072 || fingerprint !== scope.recipient_spki_sha256) throw new Invalid('Recipient does not match the reviewed RSA key.');
  return key;
}
function sha256(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    if (!fs.fstatSync(fd).isFile()) throw new Invalid('Artifact must be a regular file.');
    const hash = crypto.createHash('sha256'), bytes = Buffer.alloc(65536);
    for (;;) { const n = fs.readSync(fd, bytes, 0, bytes.length, null); if (!n) break; hash.update(bytes.subarray(0, n)); }
    return hash.digest('hex');
  } finally { fs.closeSync(fd); }
}
function writeMetadata(file, value) {
  if (fs.existsSync(file)) throw new Invalid('Refuse to replace an existing envelope manifest.');
  fs.writeFileSync(file, JSON.stringify(value, null, 2)+'\n', {flag:'wx', mode:0o600});
}
function protect(input, output, metadata, publicFile, scopeFile, family, runId) {
  if (fs.existsSync(output) || fs.existsSync(metadata)) throw new Invalid('Refuse to replace an existing encrypted artifact.');
  const scope = manifest(scopeFile), label = context(scope, family, runId), recipient = publicKey(publicFile, scope);
  const key = crypto.randomBytes(32);
  const temp = fs.mkdtempSync(path.join(path.dirname(path.resolve(output)), '.resale-envelope-'));
  fs.chmodSync(temp, 0o700);
  let outputCreated = false, metadataCreated = false;
  try {
    envelope.encrypt(input, path.join(temp, 'ciphertext'), key);
    fs.linkSync(path.join(temp, 'ciphertext'), output); outputCreated = true;
    const wrapped = crypto.publicEncrypt({key:recipient, padding:crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash:'sha256', oaepLabel:label}, key);
    writeMetadata(metadata, {version:VERSION, source_sha:scope.source_sha, family, run_id:runId, recipient_spki_sha256:scope.recipient_spki_sha256, ciphertext_sha256:sha256(output), wrapped_key:wrapped.toString('base64')});
    metadataCreated = true;
  } catch (error) {
    // Only newly created outputs belong to this call; input/source are untouched.
    for (const file of [...(outputCreated ? [output] : []), ...(metadataCreated ? [metadata] : [])]) { try { fs.unlinkSync(file); } catch (_) {} }
    throw error;
  } finally { key.fill(0); fs.rmSync(temp, {recursive:true, force:true}); }
}
function recover(input, output, metadata, privateFile, scopeFile, family, runId) {
  if (fs.existsSync(output)) throw new Invalid('Refuse to replace an existing recovered artifact.');
  const scope = manifest(scopeFile), label = context(scope, family, runId);
  const info = JSON.parse(readRegular(metadata, 16384).toString('utf8'));
  if (info.version !== VERSION || info.source_sha !== scope.source_sha || info.family !== family || info.run_id !== runId || info.recipient_spki_sha256 !== scope.recipient_spki_sha256 || !/^[0-9a-f]{64}$/.test(info.ciphertext_sha256 || '') || sha256(input) !== info.ciphertext_sha256) throw new Invalid('Artifact context or ciphertext differs from the trusted run.');
  const privateKey = crypto.createPrivateKey(readRegular(privateFile, 16384, true));
  const pub = crypto.createPublicKey(privateKey), der = pub.export({type:'spki', format:'der'});
  if (privateKey.asymmetricKeyType !== 'rsa' || privateKey.asymmetricKeyDetails.modulusLength < 3072 || crypto.createHash('sha256').update(der).digest('hex') !== scope.recipient_spki_sha256) throw new Invalid('Private recipient key does not match the reviewed fingerprint.');
  if (typeof info.wrapped_key !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(info.wrapped_key) || info.wrapped_key.length > 2048) throw new Invalid('Invalid wrapped artifact key.');
  let key;
  const temp = fs.mkdtempSync(path.join(path.dirname(path.resolve(output)), '.resale-recovery-'));
  fs.chmodSync(temp, 0o700);
  try {
    key = crypto.privateDecrypt({key:privateKey, padding:crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash:'sha256', oaepLabel:label}, Buffer.from(info.wrapped_key, 'base64'));
    if (key.length !== 32) throw new Invalid('Invalid artifact key length.');
    envelope.decrypt(input, path.join(temp, 'plaintext'), key);
    fs.linkSync(path.join(temp, 'plaintext'), output);
  } finally { if (key) key.fill(0); fs.rmSync(temp, {recursive:true, force:true}); }
}
module.exports = {protect, recover, Invalid};
if (require.main === module) {
  try {
    const [mode, input, output, metadata, recipient, scope, family, runId] = process.argv.slice(2);
    if (process.argv.length !== 10 || !['protect','recover'].includes(mode)) throw new Invalid('Use protect/recover INPUT OUTPUT ENVELOPE RECIPIENT_FILE REVIEWED_SCOPE FAMILY TRUSTED_RUN_ID.');
    module.exports[mode](input, output, metadata, recipient, scope, family, runId);
    console.log('Protected artifact operation completed. No key, source or plaintext was printed.');
  } catch (_) { console.error('Protected artifact validation failed. No secret or diagnostic content was printed.'); process.exitCode = 1; }
}
