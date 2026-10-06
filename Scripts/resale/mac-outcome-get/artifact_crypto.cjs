// Authenticated file envelope. Only encrypted output is allowed into CI artifacts.
// Uses Node's standard OpenSSL-backed crypto API, never custom cryptography.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MAGIC = Buffer.from('BUNWAY-ARTIFACT-GCM', 'ascii');
const VERSION = 1;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = MAGIC.length + 1 + NONCE_BYTES + 8;
const MAX_BYTES = 4 * 1024 * 1024 * 1024;
class Invalid extends Error {}

function keyBytes(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Invalid('Provide a 256-bit hexadecimal artifact key securely.');
  }
  return Buffer.from(hex, 'hex');
}

function isSymlink(file) {
  try { return fs.lstatSync(file).isSymbolicLink(); }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}

function openRegular(file) {
  if (isSymlink(file)) throw new Invalid('Input must be a regular file, not a symlink.');
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  if (!fs.fstatSync(descriptor).isFile()) {
    fs.closeSync(descriptor);
    throw new Invalid('Input must be a regular file.');
  }
  return descriptor;
}

function localKey(file) {
  const descriptor = openRegular(file);
  try {
    const info = fs.fstatSync(descriptor);
    if ((info.mode & 0o077) !== 0 || (process.getuid && info.uid !== process.getuid())) {
      throw new Invalid('The local artifact key must be an owner-only private file.');
    }
    if (info.size > 128) throw new Invalid('The local artifact key file has an invalid size.');
    return keyBytes(fs.readFileSync(descriptor, 'utf8').trim());
  } finally { fs.closeSync(descriptor); }
}

function privateOutput(file, write) {
  if (isSymlink(file)) throw new Invalid('The output must not replace a symlink.');
  const parent = path.dirname(path.resolve(file));
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const temporary = fs.mkdtempSync(path.join(parent, '.bunway-artifact-'));
  fs.chmodSync(temporary, 0o700);
  const temporaryFile = path.join(temporary, 'output');
  let descriptor;
  try {
    descriptor = fs.openSync(temporaryFile, 'wx', 0o600);
    write(descriptor);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor); descriptor = undefined;
    fs.renameSync(temporaryFile, file);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

function writeAll(descriptor, bytes) {
  let offset = 0;
  while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset);
}

function readExact(descriptor, length, position) {
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const count = fs.readSync(descriptor, bytes, offset, length - offset, position + offset);
    if (!count) throw new Invalid('The encrypted artifact is incomplete.');
    offset += count;
  }
  return bytes;
}

function differentPaths(input, output) {
  if (path.resolve(input) === path.resolve(output)) throw new Invalid('Input and output must be different file paths.');
}

function encrypt(input, output, key) {
  differentPaths(input, output);
  const source = openRegular(input);
  try {
    const size = fs.fstatSync(source).size;
    if (size < 1 || size > MAX_BYTES) throw new Invalid('Artifact size must be between one byte and four GiB.');
    const nonce = crypto.randomBytes(NONCE_BYTES);
    const header = Buffer.alloc(HEADER_BYTES);
    MAGIC.copy(header); header[MAGIC.length] = VERSION;
    nonce.copy(header, MAGIC.length + 1); header.writeBigUInt64BE(BigInt(size), HEADER_BYTES - 8);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
    cipher.setAAD(header);
    privateOutput(output, target => {
      writeAll(target, header);
      const buffer = Buffer.alloc(65536);
      let processed = 0;
      for (;;) {
        const count = fs.readSync(source, buffer, 0, buffer.length, null);
        if (!count) break;
        processed += count;
        writeAll(target, cipher.update(buffer.subarray(0, count)));
      }
      if (processed !== size) throw new Invalid('The input changed length during encryption. No artifact was replaced.');
      writeAll(target, cipher.final()); writeAll(target, cipher.getAuthTag());
    });
  } finally { fs.closeSync(source); }
  return true;
}

function decrypt(input, output, key) {
  differentPaths(input, output);
  const source = openRegular(input);
  try {
    const header = readExact(source, HEADER_BYTES, 0);
    if (!header.subarray(0, MAGIC.length).equals(MAGIC) || header[MAGIC.length] !== VERSION) {
      throw new Invalid('Unsupported Bunway encrypted-artifact format or version.');
    }
    const sizeBig = header.readBigUInt64BE(HEADER_BYTES - 8);
    if (sizeBig < 1n || sizeBig > BigInt(MAX_BYTES)) throw new Invalid('The encrypted artifact declares an invalid length.');
    const size = Number(sizeBig);
    if (fs.fstatSync(source).size !== HEADER_BYTES + size + TAG_BYTES) throw new Invalid('The encrypted artifact has an invalid or incomplete length.');
    const nonce = header.subarray(MAGIC.length + 1, MAGIC.length + 1 + NONCE_BYTES);
    const tag = readExact(source, TAG_BYTES, HEADER_BYTES + size);
    const cipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
    cipher.setAAD(header); cipher.setAuthTag(tag);
    privateOutput(output, target => {
      let position = HEADER_BYTES;
      while (position < HEADER_BYTES + size) {
        const chunk = readExact(source, Math.min(65536, HEADER_BYTES + size - position), position);
        writeAll(target, cipher.update(chunk)); position += chunk.length;
      }
      try { writeAll(target, cipher.final()); }
      catch (_) { throw new Invalid('Artifact authentication failed: wrong key or changed content. No plaintext output was replaced.'); }
      // Authentication completed before privateOutput atomically renames this file.
    });
  } finally { fs.closeSync(source); }
  return true;
}

module.exports = { MAGIC, VERSION, NONCE_BYTES, TAG_BYTES, HEADER_BYTES, MAX_BYTES, Invalid, keyBytes, localKey, encrypt, decrypt };

if (require.main === module) {
  try {
    const [mode, input, output, option, keyFile] = process.argv.slice(2);
    if (!['encrypt', 'decrypt'].includes(mode) || !input || !output ||
        (option !== undefined && !(mode === 'decrypt' && option === '--key-file' && keyFile)) || process.argv.length > 7) {
      throw new Invalid('Use encrypt INPUT OUTPUT with BUNWAY_ARTIFACT_KEY in the environment, or decrypt INPUT OUTPUT --key-file PRIVATE_KEY_FILE.');
    }
    const key = keyFile ? localKey(keyFile) : keyBytes(process.env.BUNWAY_ARTIFACT_KEY);
    try { module.exports[mode](input, output, key); }
    finally { key.fill(0); }
    console.log(mode === 'encrypt' ? 'Encrypted artifact authenticated and saved. No key or plaintext was printed.' : 'Artifact authenticated and saved with private file permissions.');
  } catch (error) {
    console.error(error instanceof Invalid ? `Bunway artifact: ${error.message}` : 'Bunway artifact could not be processed. No key or file contents were printed.');
    process.exitCode = 1;
  }
}
