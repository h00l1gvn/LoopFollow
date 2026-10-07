const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {test, before, after} = require('node:test');
const {protect, recover} = require('./protect_resale_artifact.cjs');
let root, pub, priv, scope;
before(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'resale-synthetic-envelope-')); fs.chmodSync(root, 0o700);
  const keys = crypto.generateKeyPairSync('rsa', {modulusLength:3072});
  pub = path.join(root, 'recipient.pub'); priv = path.join(root, 'recipient.key'); scope = path.join(root, 'scope.json');
  fs.writeFileSync(pub, keys.publicKey.export({type:'spki', format:'pem'}), {mode:0o600});
  fs.writeFileSync(priv, keys.privateKey.export({type:'pkcs8', format:'pem'}), {mode:0o600});
  const sha = crypto.createHash('sha256').update(keys.publicKey.export({type:'spki', format:'der'})).digest('hex');
  fs.writeFileSync(scope, JSON.stringify({source_sha:'a'.repeat(40), recipient_spki_sha256:sha}), {mode:0o600});
});
after(() => fs.rmSync(root, {recursive:true, force:true}));
function files(label) {
  const dir = path.join(root, label); fs.mkdirSync(dir, {mode:0o700});
  const input = path.join(dir, 'synthetic.tar'); fs.writeFileSync(input, Buffer.from('synthetic signed-package fixture; no production key'), {mode:0o600});
  return {input, output:path.join(dir, 'artifact.gcm'), meta:path.join(dir, 'envelope.json'), plain:path.join(dir, 'recovered.tar')};
}
test('round trip uses random wrapped key and owner-only authenticated output', () => {
  const f = files('roundtrip'); protect(f.input, f.output, f.meta, pub, scope, 'ios', '123');
  recover(f.output, f.plain, f.meta, priv, scope, 'ios', '123');
  assert.deepEqual(fs.readFileSync(f.plain), fs.readFileSync(f.input));
  assert.equal(fs.statSync(f.plain).mode & 0o777, 0o600);
  const metadata = JSON.parse(fs.readFileSync(f.meta)); assert.equal(Buffer.from(metadata.wrapped_key, 'base64').length, 384);
  assert.equal(fs.readFileSync(f.meta, 'utf8').includes('PRIVATE KEY'), false);
  assert.equal(fs.readFileSync(f.meta, 'utf8').includes('synthetic signed'), false);
  assert.throws(() => protect(f.input, f.output, f.meta, pub, scope, 'ios', '123'));
});
test('wrong source, family or run cannot authenticate a valid envelope', () => {
  const f=files('context'); protect(f.input,f.output,f.meta,pub,scope,'macos','456');
  assert.throws(() => recover(f.output,f.plain,f.meta,priv,scope,'ios','456'));
  assert.throws(() => recover(f.output,f.plain,f.meta,priv,scope,'macos','999'));
  const changed=path.join(root,'different-scope.json'); const json=JSON.parse(fs.readFileSync(scope)); json.source_sha='b'.repeat(40); fs.writeFileSync(changed,JSON.stringify(json));
  assert.throws(() => recover(f.output,f.plain,f.meta,priv,changed,'macos','456')); assert.equal(fs.existsSync(f.plain),false);
});
test('modified ciphertext and wrapped key never create plaintext', () => {
  const f=files('modified'); protect(f.input,f.output,f.meta,pub,scope,'tvos','789');
  const original=fs.readFileSync(f.output); const changed=Buffer.from(original); changed[changed.length-1]^=1; fs.writeFileSync(f.output,changed);
  assert.throws(() => recover(f.output,f.plain,f.meta,priv,scope,'tvos','789')); assert.equal(fs.existsSync(f.plain),false);
  fs.writeFileSync(f.output,original); const info=JSON.parse(fs.readFileSync(f.meta)); const wrapped=Buffer.from(info.wrapped_key,'base64'); wrapped[10]^=1; info.wrapped_key=wrapped.toString('base64'); fs.writeFileSync(f.meta,JSON.stringify(info));
  assert.throws(() => recover(f.output,f.plain,f.meta,priv,scope,'tvos','789')); assert.equal(fs.existsSync(f.plain),false);
});
test('recipient pin, private permissions and symlinks are enforced', () => {
  const f=files('keyguard'); const other=crypto.generateKeyPairSync('rsa',{modulusLength:3072}); const otherPub=path.join(root,'other.pub'); fs.writeFileSync(otherPub,other.publicKey.export({type:'spki',format:'pem'}));
  assert.throws(() => protect(f.input,f.output,f.meta,otherPub,scope,'ios','123'));
  protect(f.input,f.output,f.meta,pub,scope,'ios','123'); fs.chmodSync(priv,0o644);
  assert.throws(() => recover(f.output,f.plain,f.meta,priv,scope,'ios','123')); fs.chmodSync(priv,0o600);
  const link=path.join(root,'private-symlink'); fs.symlinkSync(priv,link); assert.throws(() => recover(f.output,f.plain,f.meta,link,scope,'ios','123'));
});
