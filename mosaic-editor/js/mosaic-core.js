/**
 * Mosaic Credential Core (JavaScript / Web Implementation)
 * Specification: Mosaic Credential Technical Specification v0.1
 * Sections: 4 (Data Model), 5 (Backspace), 6 (Canonical Binary MC v1), 7 (Policy), 8 (Prehash)
 */

export const MAGIC = new Uint8Array([0x4D, 0x43, 0x52, 0x44]); // ASCII "MCRD"
export const VERSION = 1;
export const PROFILE = 1;

export const TAG_CHAR = 0x01;
export const TAG_BLOB = 0x02;
export const TAG_END = 0xFF;

export const HEADER_SIZE = 8;
export const CHAR_SIZE = 5;
export const BLOB_HEADER_SIZE = 9;
export const END_SIZE = 1;

export const PREHASH_PREFIX = new TextEncoder().encode("MOSAIC-CREDENTIAL/PREHASH/V1\0");

/**
 * Validates that codepoint is a valid Unicode scalar value (§4.1).
 * Rejects isolated UTF-16 surrogates U+D800 - U+DFFF.
 */
export function validateScalar(codepoint) {
  if ((codepoint >= 0 && codepoint <= 0xD7FF) || (codepoint >= 0xE000 && codepoint <= 0x10FFFF)) {
    return String.fromCodePoint(codepoint);
  }
  throw new Error(`INVALID_SCALAR: code point U+${codepoint.toString(16).toUpperCase().padStart(4, '0')} is not a Unicode scalar value`);
}

/**
 * Element constructors
 */
export function createChar(charOrCodePoint) {
  let cp;
  if (typeof charOrCodePoint === 'string') {
    cp = charOrCodePoint.codePointAt(0);
  } else {
    cp = charOrCodePoint;
  }
  validateScalar(cp);
  return {
    type: 'CHAR',
    codepoint: cp,
    char: String.fromCodePoint(cp),
    isBackspace: cp === 0x0008,
    isControl: cp < 32 || (cp >= 0x7F && cp <= 0x9F)
  };
}

export function createBlob(bytes, filename = 'blob.bin') {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return {
    type: 'BLOB',
    data: u8,
    length: u8.length,
    filename: filename
  };
}

/**
 * Canonical Binary Encoder (§6)
 * Returns Uint8Array of canonical serialization:
 * HEADER (8) || ELEMENTS (CHAR: 5B, BLOB: 9B + length) || END (1B)
 */
export function encodeElements(elements) {
  let totalLength = HEADER_SIZE;
  for (const el of elements) {
    if (el.type === 'CHAR') {
      totalLength += CHAR_SIZE;
    } else if (el.type === 'BLOB') {
      totalLength += BLOB_HEADER_SIZE + el.data.length;
    }
  }
  totalLength += END_SIZE;

  const buf = new Uint8Array(totalLength);
  const view = new DataView(buf.buffer);

  // Header: MCRD (4) + version (u16 be) + profile (u16 be)
  buf.set(MAGIC, 0);
  view.setUint16(4, VERSION, false);
  view.setUint16(6, PROFILE, false);

  let cursor = HEADER_SIZE;
  for (const el of elements) {
    if (el.type === 'CHAR') {
      buf[cursor] = TAG_CHAR;
      cursor += 1;
      view.setUint32(cursor, el.codepoint, false);
      cursor += 4;
    } else if (el.type === 'BLOB') {
      buf[cursor] = TAG_BLOB;
      cursor += 1;
      // Big-endian u64 length
      view.setBigUint64(cursor, BigInt(el.data.length), false);
      cursor += 8;
      buf.set(el.data, cursor);
      cursor += el.data.length;
    }
  }

  // Mandatory END tag
  buf[cursor] = TAG_END;
  return buf;
}

/**
 * Strict Canonical Binary Parser (§6)
 */
export function parseCanonical(buf) {
  if (buf.length < HEADER_SIZE) {
    throw new Error(`TRUNCATED_INPUT: expected at least ${HEADER_SIZE} bytes for header`);
  }

  for (let i = 0; i < 4; i++) {
    if (buf[i] !== MAGIC[i]) {
      throw new Error(`INVALID_TAG: invalid magic byte 0x${buf[i].toString(16)}`);
    }
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const version = view.getUint16(4, false);
  if (version !== VERSION) {
    throw new Error(`UNSUPPORTED_VERSION: version ${version} is not supported`);
  }

  const profile = view.getUint16(6, false);
  if (profile !== PROFILE) {
    throw new Error(`UNSUPPORTED_PROFILE: profile ${profile} is not supported`);
  }

  let cursor = HEADER_SIZE;
  const elements = [];

  while (cursor < buf.length) {
    const tag = buf[cursor++];
    if (tag === TAG_END) {
      if (cursor < buf.length) {
        throw new Error(`TRAILING_DATA: ${buf.length - cursor} bytes after END marker`);
      }
      return elements;
    } else if (tag === TAG_CHAR) {
      if (cursor + 4 > buf.length) {
        throw new Error(`TRUNCATED_INPUT: expected 4 bytes for CHAR codepoint`);
      }
      const cp = view.getUint32(cursor, false);
      cursor += 4;
      elements.push(createChar(cp));
    } else if (tag === TAG_BLOB) {
      if (cursor + 8 > buf.length) {
        throw new Error(`TRUNCATED_INPUT: expected 8 bytes for BLOB length`);
      }
      const length = Number(view.getBigUint64(cursor, false));
      cursor += 8;
      if (cursor + length > buf.length) {
        throw new Error(`LENGTH_MISMATCH: declared ${length} bytes, got ${buf.length - cursor}`);
      }
      const slice = buf.slice(cursor, cursor + length);
      cursor += length;
      elements.push(createBlob(slice));
    } else {
      throw new Error(`INVALID_TAG: unrecognized tag 0x${tag.toString(16).padStart(2, '0')}`);
    }
  }

  throw new Error(`TRUNCATED_INPUT: missing END marker`);
}

/**
 * Domain-Separated SHA-256 Prehash (§8.2)
 * D = SHA-256(PREFIX || S)
 */
export async function computePrehash(elements) {
  const canonicalBytes = encodeElements(elements);
  const combined = new Uint8Array(PREHASH_PREFIX.length + canonicalBytes.length);
  combined.set(PREHASH_PREFIX, 0);
  combined.set(canonicalBytes, PREHASH_PREFIX.length);

  const digestBuffer = await crypto.subtle.digest("SHA-256", combined);
  return new Uint8Array(digestBuffer);
}

/**
 * Convert byte array to hexadecimal string
 */
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert hex string to byte array
 */
export function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Interpret elements for the visual preview (§5.2)
 * U+0008 explicitly deletes the preceding character in the visual preview.
 * Returns { previewText, rawCount }
 */
export function renderPreview(elements) {
  const chars = [];
  for (const el of elements) {
    if (el.type === 'CHAR') {
      if (el.codepoint === 0x0008) { // Backspace
        if (chars.length > 0) {
          chars.pop();
        }
      } else {
        chars.push(el.char);
      }
    } else if (el.type === 'BLOB') {
      chars.push(`[BLOB:${el.length}B]`);
    }
  }
  return chars.join('');
}
