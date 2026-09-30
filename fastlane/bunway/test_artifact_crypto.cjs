const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const artifact = require('./artifact_crypto.cjs');
// Synthetic fixtures only; these are not deployment keys or personal files.
const KEY = Buffer.from('12'.repeat(32), 'hex');
const WRONG_KEY = Buffer.from('34'.repeat(32), 'hex');

function fixture(check) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bunway-crypto-test-'));
  const plain = path.join(directory, 'synthetic.ipa');
  const encrypted = path.join(directory, 'synthetic.ipa.enc');
  const output = path.join(directory, 'restored.ipa');
  const bytes = Buffer.concat(Array.from({ length: 5000 }, () => Buffer.from('PK\x03\x04synthetic-clothed-fixture\x00\xff', 'latin1')));
  fs.writeFileSync(plain, bytes);
  const encrypt = () => artifact.encrypt(plain, encrypted, KEY);
  const changeByte = offset => {
    const data = fs.readFileSync(encrypted); data[offset] ^= 1; fs.writeFileSync(encrypted, data);
  };
  const reject = (key = KEY) => {
    fs.writeFileSync(output, 'keep existing file');
    assert.throws(() => artifact.decrypt(encrypted, output, key), artifact.Invalid);
    assert.equal(fs.readFileSync(output, 'utf8'), 'keep existing file');
    assert.deepEqual(fs.readdirSync(directory).filter(name => name.startsWith('.bunway-artifact-')), []);
  };
  try { check({ directory, plain, encrypted, output, bytes, encrypt, changeByte, reject }); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test('streamed binary round trip leaves private files and no temporary plaintext', () => fixture(({ plain, encrypted, output, bytes, encrypt, directory }) => {
  assert.equal(encrypt(), true);
  assert.equal(fs.statSync(encrypted).mode & 0o077, 0);
  assert.equal(artifact.decrypt(encrypted, output, KEY), true);
  assert.deepEqual(fs.readFileSync(output), bytes);
  assert.equal(fs.statSync(output).mode & 0o077, 0);
  assert.deepEqual(fs.readdirSync(directory).filter(name => name.startsWith('.bunway-artifact-')), []);
}));

test('repeated encryptions use distinct random nonces', () => fixture(({ encrypted, encrypt }) => {
  encrypt(); const first = fs.readFileSync(encrypted);
  encrypt(); const second = fs.readFileSync(encrypted);
  assert.notDeepEqual(first, second);
  const offset = artifact.MAGIC.length + 1;
  assert.notDeepEqual(first.subarray(offset, offset + 12), second.subarray(offset, offset + 12));
}));

test('wrong key preserves existing output and removes temporary plaintext', () => fixture(({ encrypt, reject }) => { encrypt(); reject(WRONG_KEY); }));

test('changed ciphertext and tag are rejected', () => fixture(({ encrypt, reject, changeByte, encrypted }) => {
  encrypt(); changeByte(artifact.HEADER_BYTES + 10); reject();
  encrypt(); changeByte(fs.statSync(encrypted).size - 1); reject();
}));

test('nonce is authenticated as header data', () => fixture(({ encrypt, reject, changeByte }) => {
  encrypt(); changeByte(artifact.MAGIC.length + 1); reject();
}));

test('magic, version, and declared size are validated', () => fixture(({ encrypt, reject, changeByte }) => {
  for (const offset of [0, artifact.MAGIC.length, artifact.HEADER_BYTES - 1]) { encrypt(); changeByte(offset); reject(); }
}));

test('truncated, appended, and short-header downloads are rejected', () => fixture(({ encrypt, reject, encrypted }) => {
  encrypt(); fs.writeFileSync(encrypted, fs.readFileSync(encrypted).subarray(0, -1)); reject();
  encrypt(); fs.appendFileSync(encrypted, 'trailing'); reject();
  fs.writeFileSync(encrypted, 'short header'); reject();
}));

test('same-path and zero-length input are rejected without replacing files', () => fixture(({ plain, bytes, encrypted, encrypt }) => {
  assert.throws(() => artifact.encrypt(plain, plain, KEY), artifact.Invalid);
  assert.deepEqual(fs.readFileSync(plain), bytes);
  fs.writeFileSync(plain, ''); assert.throws(encrypt, artifact.Invalid);
  assert.equal(fs.existsSync(encrypted), false);
}));

test('symlink input and output are rejected', () => fixture(({ directory, plain, encrypted, encrypt }) => {
  const input = path.join(directory, 'linked-input'); fs.symlinkSync(plain, input);
  assert.throws(() => artifact.encrypt(input, encrypted, KEY), artifact.Invalid);
  fs.symlinkSync(plain, encrypted); assert.throws(encrypt, artifact.Invalid);
  assert.equal(fs.realpathSync(encrypted), fs.realpathSync(plain));
}));

test('local key must be a private regular file', () => fixture(({ directory }) => {
  const file = path.join(directory, 'synthetic.hex');
  fs.writeFileSync(file, '12'.repeat(32) + '\n', { mode: 0o600 });
  assert.deepEqual(artifact.localKey(file), KEY);
  fs.chmodSync(file, 0o644); assert.throws(() => artifact.localKey(file), artifact.Invalid);
  fs.chmodSync(file, 0o600); const link = path.join(directory, 'linked-key'); fs.symlinkSync(file, link);
  assert.throws(() => artifact.localKey(link), artifact.Invalid);
}));

test('bad key errors never echo submitted values', () => {
  for (const bad of ['bad-private-fixture', '12'.repeat(31), '12'.repeat(33), 'zz'.repeat(32)]) {
    assert.throws(() => artifact.keyBytes(bad), error => error instanceof artifact.Invalid && !error.message.includes(bad));
  }
});

test('CLI encrypts from environment and decrypts from private local key file', () => fixture(({ plain, encrypted, output, directory, bytes }) => {
  const helper = path.join(__dirname, 'artifact_crypto.cjs');
  const result = spawnSync(process.execPath, [helper, 'encrypt', plain, encrypted], { encoding: 'utf8', env: { ...process.env, BUNWAY_ARTIFACT_KEY: '12'.repeat(32) } });
  assert.equal(result.status, 0, result.stderr); assert.equal((result.stdout + result.stderr).includes('12'.repeat(32)), false);
  const file = path.join(directory, 'synthetic.hex'); fs.writeFileSync(file, '12'.repeat(32), { mode: 0o600 });
  const restored = spawnSync(process.execPath, [helper, 'decrypt', encrypted, output, '--key-file', file], { encoding: 'utf8', env: { ...process.env, BUNWAY_ARTIFACT_KEY: '' } });
  assert.equal(restored.status, 0, restored.stderr); assert.deepEqual(fs.readFileSync(output), bytes);
  assert.equal((restored.stdout + restored.stderr).includes('12'.repeat(32)), false);
}));
