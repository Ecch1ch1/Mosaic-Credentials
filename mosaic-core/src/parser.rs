//! Canonical binary parser for MC v1 format (§6).
//!
//! The parser enforces strict validation:
//! - Unknown tags, truncated fields, unsupported versions and profiles are rejected.
//! - Trailing bytes after END are rejected.
//! - BLOB declared lengths must match actual payload.
//! - Invalid Unicode scalar values (surrogates) are rejected.

use crate::error::{Error, Result};
use crate::types::{
    validate_scalar, Element, MAGIC, TAG_BLOB, TAG_CHAR, TAG_END,
};

/// Parsed header fields from an MC v1 stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    pub profile: u16,
}

/// Parse a complete MC v1 canonical binary stream from a byte slice.
///
/// Returns the list of elements. Enforces all validation rules from §6.
pub fn parse(data: &[u8]) -> Result<Vec<Element>> {
    let mut cursor = 0;

    // --- Header ---
    let _header = parse_header(data, &mut cursor)?;

    // --- Elements ---
    let mut elements = Vec::new();
    loop {
        if cursor >= data.len() {
            return Err(Error::TruncatedInput { expected: 1 });
        }

        let tag = data[cursor];
        cursor += 1;

        match tag {
            TAG_CHAR => {
                let element = parse_char_body(data, &mut cursor)?;
                elements.push(element);
            }
            TAG_END => {
                // §6.5: Trailing bytes after END are invalid.
                let remaining = data.len() - cursor;
                if remaining > 0 {
                    return Err(Error::TrailingData(remaining));
                }
                return Ok(elements);
            }
            TAG_BLOB => {
                let element = parse_blob_body(data, &mut cursor)?;
                elements.push(element);
            }
            other => {
                return Err(Error::InvalidTag(other));
            }
        }
    }
}

/// Parse just the header, advancing the cursor past it.
fn parse_header(data: &[u8], cursor: &mut usize) -> Result<Header> {
    // Magic: 4 bytes
    if data.len() < *cursor + 4 {
        return Err(Error::TruncatedInput {
            expected: 4 - (data.len() - *cursor),
        });
    }
    if &data[*cursor..*cursor + 4] != &MAGIC {
        return Err(Error::InvalidVerifier(format!(
            "invalid magic: expected MCRD, got {:?}",
            &data[*cursor..*cursor + 4]
        )));
    }
    *cursor += 4;

    // Version: u16
    let version = read_u16(data, cursor)?;
    if version != 1 {
        return Err(Error::UnsupportedVersion(version));
    }

    // Profile: u16
    let profile = read_u16(data, cursor)?;
    if profile != 1 {
        return Err(Error::UnsupportedProfile(profile));
    }

    Ok(Header { version, profile })
}

/// Parse a CHAR body (codepoint u32) after the tag has been consumed.
fn parse_char_body(data: &[u8], cursor: &mut usize) -> Result<Element> {
    let code_point = read_u32(data, cursor)?;
    let c = validate_scalar(code_point)?;
    Ok(Element::Char(c))
}

/// Parse a BLOB body (length u64 + payload) after the tag has been consumed.
fn parse_blob_body(data: &[u8], cursor: &mut usize) -> Result<Element> {
    let length = read_u64(data, cursor)?;

    // Validate available data against declared length.
    let available = (data.len() - *cursor) as u64;
    if length > available {
        return Err(Error::LengthMismatch {
            declared: length,
            actual: available,
        });
    }

    let length_usize = length as usize;
    let payload = data[*cursor..*cursor + length_usize].to_vec();
    *cursor += length_usize;
    Ok(Element::Blob(payload))
}

// --- Integer reading helpers (big-endian) ---

fn read_u16(data: &[u8], cursor: &mut usize) -> Result<u16> {
    if data.len() < *cursor + 2 {
        return Err(Error::TruncatedInput {
            expected: 2 - (data.len() - *cursor),
        });
    }
    let value = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]);
    *cursor += 2;
    Ok(value)
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32> {
    if data.len() < *cursor + 4 {
        return Err(Error::TruncatedInput {
            expected: 4 - (data.len() - *cursor),
        });
    }
    let value = u32::from_be_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(value)
}

fn read_u64(data: &[u8], cursor: &mut usize) -> Result<u64> {
    if data.len() < *cursor + 8 {
        return Err(Error::TruncatedInput {
            expected: 8 - (data.len() - *cursor),
        });
    }
    let value = u64::from_be_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
        data[*cursor + 4],
        data[*cursor + 5],
        data[*cursor + 6],
        data[*cursor + 7],
    ]);
    *cursor += 8;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder;

    #[test]
    fn round_trip_text() {
        let elements = vec![
            Element::Char('H'),
            Element::Char('e'),
            Element::Char('l'),
            Element::Char('l'),
            Element::Char('o'),
        ];
        let encoded = encoder::encode(&elements);
        let parsed = parse(&encoded).unwrap();
        assert_eq!(parsed, elements);
    }

    #[test]
    fn round_trip_mixed() {
        let elements = vec![
            Element::Char('A'),
            Element::Blob(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            Element::Char('\u{0008}'), // Backspace
            Element::Blob(vec![]),      // empty blob
            Element::Char('Z'),
        ];
        let encoded = encoder::encode(&elements);
        let parsed = parse(&encoded).unwrap();
        assert_eq!(parsed, elements);
    }

    #[test]
    fn round_trip_empty() {
        let elements: Vec<Element> = vec![];
        let encoded = encoder::encode(&elements);
        let parsed = parse(&encoded).unwrap();
        assert_eq!(parsed, elements);
    }

    #[test]
    fn reject_bad_magic() {
        let mut encoded = encoder::encode(&[]);
        encoded[0] = b'X'; // corrupt magic
        assert!(parse(&encoded).is_err());
    }

    #[test]
    fn reject_bad_version() {
        let mut encoded = encoder::encode(&[]);
        encoded[5] = 0x02; // version = 2
        assert!(matches!(
            parse(&encoded),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn reject_bad_profile() {
        let mut encoded = encoder::encode(&[]);
        encoded[7] = 0x02; // profile = 2
        assert!(matches!(
            parse(&encoded),
            Err(Error::UnsupportedProfile(2))
        ));
    }

    #[test]
    fn reject_unknown_tag() {
        let mut encoded = encoder::encode(&[]);
        // Insert an unknown tag before END
        let end_pos = encoded.len() - 1;
        encoded.insert(end_pos, 0x03); // unknown tag
        assert!(matches!(parse(&encoded), Err(Error::InvalidTag(0x03))));
    }

    #[test]
    fn reject_trailing_data() {
        let mut encoded = encoder::encode(&[]);
        encoded.push(0x00); // trailing byte after END
        assert!(matches!(parse(&encoded), Err(Error::TrailingData(1))));
    }

    #[test]
    fn reject_truncated_header() {
        let data = b"MCR"; // only 3 bytes
        assert!(parse(data).is_err());
    }

    #[test]
    fn reject_missing_end() {
        let mut encoded = encoder::encode(&[]);
        encoded.pop(); // remove END marker
        assert!(parse(&encoded).is_err());
    }

    #[test]
    fn reject_surrogate() {
        // Manually construct a CHAR with a surrogate code point U+D800
        let mut data = Vec::new();
        data.extend_from_slice(b"MCRD");
        data.extend_from_slice(&1u16.to_be_bytes()); // version
        data.extend_from_slice(&1u16.to_be_bytes()); // profile
        data.push(0x01); // CHAR tag
        data.extend_from_slice(&0xD800u32.to_be_bytes()); // surrogate!
        data.push(0xFF); // END

        assert!(matches!(
            parse(&data),
            Err(Error::InvalidScalar(0xD800))
        ));
    }

    #[test]
    fn reject_truncated_blob() {
        // Construct a BLOB that declares 100 bytes but only has 2
        let mut data = Vec::new();
        data.extend_from_slice(b"MCRD");
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.push(0x02); // BLOB tag
        data.extend_from_slice(&100u64.to_be_bytes()); // declares 100 bytes
        data.extend_from_slice(&[0xAA, 0xBB]); // only 2 bytes
        data.push(0xFF);

        assert!(matches!(
            parse(&data),
            Err(Error::LengthMismatch { declared: 100, .. })
        ));
    }

    #[test]
    fn blob_tag_bytes_inside_payload() {
        // §6.6: tag-like bytes inside a BLOB have no structural meaning
        let inner = vec![0x01, 0x02, 0xFF, 0x01]; // looks like tags but isn't
        let elements = vec![Element::Blob(inner.clone())];
        let encoded = encoder::encode(&elements);
        let parsed = parse(&encoded).unwrap();
        assert_eq!(parsed, elements);
    }

    #[test]
    fn max_unicode_scalar() {
        let elements = vec![Element::Char('\u{10FFFF}')];
        let encoded = encoder::encode(&elements);
        let parsed = parse(&encoded).unwrap();
        assert_eq!(parsed, elements);
    }

    #[test]
    fn nul_and_control_chars() {
        let elements = vec![
            Element::Char('\0'),       // NUL
            Element::Char('\u{0008}'), // Backspace
            Element::Char('\t'),       // Tab
            Element::Char('\n'),       // Line feed
            Element::Char('\r'),       // Carriage return
            Element::Char('\u{007F}'), // DEL
        ];
        let encoded = encoder::encode(&elements);
        let parsed = parse(&encoded).unwrap();
        assert_eq!(parsed, elements);
    }

    #[test]
    fn parser_fuzz_random_bytes_never_panics() {
        // Pseudo-random linear congruential generator (LCG) for deterministic fast fuzzing
        let mut seed: u64 = 0xDEADBEEFCAFE;
        let mut next_byte = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 33) as u8
        };

        // 1. Completely random byte buffers of varying lengths
        for len in [0, 1, 2, 3, 4, 7, 8, 9, 13, 20, 64, 128, 512, 1024] {
            for _ in 0..100 {
                let random_data: Vec<u8> = (0..len).map(|_| next_byte()).collect();
                // MUST NOT panic, only return Ok or Err
                let _ = parse(&random_data);
            }
        }

        // 2. Bit-flipped and mutated valid streams
        let valid_stream = encoder::encode(&[
            Element::Char('P'),
            Element::Char('\u{0008}'),
            Element::Blob(vec![1, 2, 3, 4]),
            Element::Char('X'),
        ]);

        for _ in 0..500 {
            let mut mutated = valid_stream.clone();
            // Mutate 1 to 3 random bytes
            let num_mutations = (next_byte() % 3) + 1;
            for _ in 0..num_mutations {
                let idx = (next_byte() as usize) % mutated.len();
                mutated[idx] = next_byte();
            }
            let _ = parse(&mutated);
        }

        // 3. Truncations of valid stream
        for i in 0..valid_stream.len() {
            let _ = parse(&valid_stream[..i]);
        }
    }
}

