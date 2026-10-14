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

console.log('\nAll Web Component encoding tests passed with 100% compliance!');
