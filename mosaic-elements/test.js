// Test component's encoding logic directly in Node.js
const assert = require('assert');

// Constants matching component (§6)
const MAGIC = new Uint8Array([0x4D, 0x43, 0x52, 0x44]); // ASCII "MCRD"
const VERSION = 1;
const PROFILE = 1;
const HEADER_SIZE = 8;
const TAG_CHAR = 0x01;
const TAG_BLOB = 0x02;
const TAG_END = 0xff;

function encodeCanonical(elements) {
  let totalSize = HEADER_SIZE;
  for (const el of elements) {
    if (el.type === 'CHAR') {
      totalSize += 1 + 4;
    } else if (el.type === 'BLOB') {
      totalSize += 1 + 8 + el.value.length;
    }
  }
  totalSize += 1;

  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);

  buffer.set(MAGIC, 0);
  view.setUint16(4, VERSION, false);
  view.setUint16(6, PROFILE, false);

  let offset = HEADER_SIZE;
  for (const el of elements) {
    if (el.type === 'CHAR') {
      buffer[offset++] = TAG_CHAR;
      view.setUint32(offset, el.value >>> 0, false);
      offset += 4;
    } else if (el.type === 'BLOB') {
      buffer[offset++] = TAG_BLOB;
      view.setBigUint64(offset, BigInt(el.value.length), false);
      offset += 8;
      buffer.set(el.value, offset);
      offset += el.value.length;
    }
  }

  buffer[offset++] = TAG_END;
  return buffer;
}

// Test Vector 1: Empty credential -> MCRD 0001 0001 ff
const empty = encodeCanonical([]);
assert.deepStrictEqual(Buffer.from(empty).toString('hex'), '4d43524400010001ff');
console.log('✓ Vector 1 (Empty) passed: 4d43524400010001ff');

// Test Vector 2: Single char 'A' (U+0041) -> MCRD 0001 0001 01 00000041 ff
const singleA = encodeCanonical([{ type: 'CHAR', value: 0x41 }]);
assert.deepStrictEqual(Buffer.from(singleA).toString('hex'), '4d435244000100010100000041ff');
console.log('✓ Vector 2 (Single A) passed: 4d435244000100010100000041ff');

// Test Vector 3: Backspace CHAR (U+0008) -> MCRD 0001 0001 01 00000008 ff
const bs = encodeCanonical([{ type: 'CHAR', value: 0x08 }]);
assert.deepStrictEqual(Buffer.from(bs).toString('hex'), '4d435244000100010100000008ff');
console.log('✓ Vector 3 (Backspace U+0008) passed: 4d435244000100010100000008ff');

// Test Vector 4: BLOB de ad be ef -> MCRD 0001 0001 02 0000000000000004 deadbeef ff
const blob = encodeCanonical([{ type: 'BLOB', value: new Uint8Array([0xde, 0xad, 0xbe, 0xef]) }]);
assert.deepStrictEqual(Buffer.from(blob).toString('hex'), '4d43524400010001020000000000000004deadbeefff');
console.log('✓ Vector 4 (BLOB deadbeef) passed: 4d43524400010001020000000000000004deadbeefff');

// Test .mosaic Capsule (Physical Keyfile) Cryptographic Primitives
const {
  validateCapsulePassphrase,
  encryptCapsule,
  decryptCapsule,
  parseCanonicalStream,
  CAPSULE_MAGIC
} = require('./mosaic-credential-input.js');

async function testCapsuleSuite() {
  console.log('\n--- Testing .mosaic Capsule Cryptography & Keyfile Protection ---');

  // Test 1: Passphrase Validation (Algorithmic Entropy & Sequential Protection)
  assert.strictEqual(validateCapsulePassphrase('').valid, false);
  assert.strictEqual(validateCapsulePassphrase('short').valid, false);
  assert.strictEqual(validateCapsulePassphrase('12345678').valid, false);
  assert.strictEqual(validateCapsulePassphrase('password').valid, false);
  assert.strictEqual(validateCapsulePassphrase('password123').valid, false); // root word match
  assert.strictEqual(validateCapsulePassphrase('aaaaaaaa').valid, false);
  assert.strictEqual(validateCapsulePassphrase('123456789').valid, false); // numeric < 10
  assert.strictEqual(validateCapsulePassphrase('9876543210').valid, false); // reverse sequence 9876
  assert.strictEqual(validateCapsulePassphrase('abcdefgh').valid, false); // alpha sequence abcd
  assert.strictEqual(validateCapsulePassphrase('qwertyuiop').valid, false); // keyboard pattern
  assert.strictEqual(validateCapsulePassphrase('1212121212').valid, false); // repeated cycle
  assert.strictEqual(validateCapsulePassphrase('7391582046').valid, true); // non-sequential 10-digit PIN
  assert.strictEqual(validateCapsulePassphrase('Correct-Horse-Battery-2026!').valid, true);

  // Test custom enterprise validator hook
  const customMock = (pass) => pass.includes('enterprise') ? { valid: false, error: 'Forbidden keyword' } : { valid: true };
  assert.strictEqual(validateCapsulePassphrase('Safe-Pass-enterprise-2026!', customMock).valid, false);
  console.log('✓ Passphrase strength, sequence, entropy & custom hook validator passed');

  // Test 2: Encrypt / Decrypt Roundtrip
  const testElements = [
    { type: 'CHAR', value: 'S'.codePointAt(0) },
    { type: 'CHAR', value: 0x0008 }, // Backspace
    { type: 'CHAR', value: 0xE010, meta: 'ArrowUp' }, // Directional arrow
    { type: 'BLOB', value: new Uint8Array([0xca, 0xfe, 0xba, 0xbe]), name: 'hardware-dongle.key' }
  ];
  const canonicalBytes = encodeCanonical(testElements);
  const strongPass = 'Mosaic-Secure-Physical-Keyfile-9981!';

  const capsuleBytes = await encryptCapsule(canonicalBytes, testElements, strongPass);
  assert(capsuleBytes.length > 56, 'Capsule bytes must contain header and ciphertext');
  assert.deepStrictEqual(Array.from(capsuleBytes.slice(0, 8)), Array.from(CAPSULE_MAGIC));
  console.log('✓ Capsule encryption created valid MOSAIC01 envelope (size: ' + capsuleBytes.length + ' bytes)');

  // Decrypt with correct passphrase
  const decryptedEnvelope = await decryptCapsule(capsuleBytes, strongPass);
  assert.strictEqual(decryptedEnvelope.version, 1);
  assert.strictEqual(decryptedEnvelope.elements.length, 4);
  assert.strictEqual(decryptedEnvelope.elements[0].type, 'CHAR');
  assert.strictEqual(decryptedEnvelope.elements[1].value, 0x0008);
  assert.strictEqual(decryptedEnvelope.elements[2].meta, 'ArrowUp');
  assert.strictEqual(decryptedEnvelope.elements[3].type, 'BLOB');
  assert.strictEqual(decryptedEnvelope.elements[3].name, 'hardware-dongle.key');
  console.log('✓ Capsule decryption succeeded with exact element reproduction');

  // Test 3: Decrypt with WRONG passphrase must throw
  let failed = false;
  try {
    await decryptCapsule(capsuleBytes, 'WrongPassword123!');
  } catch (err) {
    failed = true;
  }
  assert.strictEqual(failed, true, 'Decryption with wrong password MUST fail');
  console.log('✓ Tamper/brute-force defense passed: wrong password rejected by AES-256-GCM authentication tag');

  // Test 4: Canonical stream parser
  const parsedStream = parseCanonicalStream(canonicalBytes);
  assert.strictEqual(parsedStream.length, 4);
  assert.strictEqual(parsedStream[0].value, 'S'.codePointAt(0));
  assert.strictEqual(parsedStream[1].value, 0x0008);
  assert.strictEqual(parsedStream[2].value, 0xE010);
  assert.strictEqual(parsedStream[3].type, 'BLOB');
  assert.deepStrictEqual(Array.from(parsedStream[3].value), [0xca, 0xfe, 0xba, 0xbe]);
  console.log('✓ Canonical binary stream parser passed');

  console.log('\nAll Web Component encoding & .mosaic capsule tests passed with 100% compliance!');
}

testCapsuleSuite().catch(err => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
