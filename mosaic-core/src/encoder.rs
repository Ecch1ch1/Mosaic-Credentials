//! Canonical binary encoder for MC v1 format (§6).
//!
//! All multibyte integers are unsigned big-endian. Payload lengths count bytes,
//! not characters or bits.
//!
//! The encoder can operate in two modes:
//! 1. **Buffered**: Encode a complete element list into a `Vec<u8>`.
//! 2. **Streaming**: Feed elements to a writer for incremental emission.

use crate::error::{Error, Result};
use crate::types::{Element, MAGIC, PROFILE, TAG_BLOB, TAG_CHAR, TAG_END, VERSION};
use std::io::Write;

/// Encode a complete list of elements into the MC v1 canonical binary format.
///
/// This is the buffered convenience API. For large credentials, use
/// [`StreamEncoder`] instead.
pub fn encode(elements: &[Element]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut encoder = StreamEncoder::new(&mut buf);
    // These writes to a Vec cannot fail.
    encoder.write_header().expect("Vec write cannot fail");
    for element in elements {
        encoder.write_element(element).expect("Vec write cannot fail");
    }
    encoder.write_end().expect("Vec write cannot fail");
    buf
}

/// Streaming encoder that writes MC v1 canonical bytes to any [`Write`] sink.
///
/// The caller is responsible for calling methods in the correct order:
/// 1. [`write_header()`](StreamEncoder::write_header)
/// 2. [`write_element()`](StreamEncoder::write_element) for each element
/// 3. [`write_end()`](StreamEncoder::write_end)
pub struct StreamEncoder<W: Write> {
    writer: W,
}

impl<W: Write> StreamEncoder<W> {
    /// Wrap a writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Write the MC v1 header: magic(4) + version(2) + profile(2).
    pub fn write_header(&mut self) -> Result<()> {
        self.writer.write_all(&MAGIC)?;
        self.writer.write_all(&VERSION.to_be_bytes())?;
        self.writer.write_all(&PROFILE.to_be_bytes())?;
        Ok(())
    }

    /// Write a single element (CHAR or BLOB).
    pub fn write_element(&mut self, element: &Element) -> Result<()> {
        match element {
            Element::Char(c) => self.write_char(*c),
            Element::Blob(data) => self.write_blob(data),
        }
    }

    /// Write a CHAR element: tag(0x01) + codepoint(u32 big-endian).
    fn write_char(&mut self, c: char) -> Result<()> {
        self.writer.write_all(&[TAG_CHAR])?;
        self.writer.write_all(&(c as u32).to_be_bytes())?;
        Ok(())
    }

    /// Write a BLOB element: tag(0x02) + length(u64 big-endian) + payload.
    fn write_blob(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(&[TAG_BLOB])?;
        self.writer.write_all(&(data.len() as u64).to_be_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    /// Write a BLOB header only (for streaming large blobs).
    /// The caller must then write exactly `length_bytes` of payload data.
    pub fn write_blob_header(&mut self, length_bytes: u64) -> Result<()> {
        self.writer.write_all(&[TAG_BLOB])?;
        self.writer.write_all(&length_bytes.to_be_bytes())?;
        Ok(())
    }

    /// Write raw payload bytes (for streaming blob data after a header).
    pub fn write_blob_payload(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data)?;
        Ok(())
    }

    /// Write the END marker: tag(0xFF).
    pub fn write_end(&mut self) -> Result<()> {
        self.writer.write_all(&[TAG_END])?;
        Ok(())
    }

    /// Consume the encoder and return the inner writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Get a mutable reference to the underlying writer.
    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }
}

/// Encode a single CHAR element to bytes (without header/end).
/// Useful for test inspection.
pub fn encode_char(c: char) -> [u8; 5] {
    let cp = c as u32;
    [
        TAG_CHAR,
        (cp >> 24) as u8,
        (cp >> 16) as u8,
        (cp >> 8) as u8,
        cp as u8,
    ]
}

/// Compute the total canonical encoded size for a list of elements,
/// including header and END.
pub fn encoded_size(elements: &[Element]) -> Result<u64> {
    let mut size: u64 = crate::types::HEADER_SIZE as u64; // header
    for element in elements {
        match element {
            Element::Char(_) => {
                size = size
                    .checked_add(crate::types::CHAR_ENCODED_SIZE as u64)
                    .ok_or(Error::IntegerOverflow)?;
            }
            Element::Blob(data) => {
                size = size
                    .checked_add(crate::types::BLOB_HEADER_SIZE as u64)
                    .ok_or(Error::IntegerOverflow)?;
                size = size
                    .checked_add(data.len() as u64)
                    .ok_or(Error::IntegerOverflow)?;
            }
        }
    }
    size = size
        .checked_add(crate::types::END_SIZE as u64)
        .ok_or(Error::IntegerOverflow)?;
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_char_a() {
        // §6.3 example: 'A' → 01 00 00 00 41
        let bytes = encode_char('A');
        assert_eq!(bytes, [0x01, 0x00, 0x00, 0x00, 0x41]);
    }

    #[test]
    fn encode_backspace() {
        // §6.3 example: Backspace → 01 00 00 00 08
        let bytes = encode_char('\u{0008}');
        assert_eq!(bytes, [0x01, 0x00, 0x00, 0x00, 0x08]);
    }

    #[test]
    fn encode_full_credential() {
        let elements = vec![
            Element::Char('H'),
            Element::Char('i'),
        ];
        let encoded = encode(&elements);

        // Header: MCRD (4) + version 1 (2) + profile 1 (2) = 8 bytes
        assert_eq!(&encoded[0..4], b"MCRD");
        assert_eq!(&encoded[4..6], &[0x00, 0x01]); // version
        assert_eq!(&encoded[6..8], &[0x00, 0x01]); // profile

        // CHAR 'H': 01 00 00 00 48
        assert_eq!(&encoded[8..13], &[0x01, 0x00, 0x00, 0x00, 0x48]);

        // CHAR 'i': 01 00 00 00 69
        assert_eq!(&encoded[13..18], &[0x01, 0x00, 0x00, 0x00, 0x69]);

        // END: FF
        assert_eq!(encoded[18], 0xFF);
        assert_eq!(encoded.len(), 19);
    }

    #[test]
    fn encode_with_blob() {
        let elements = vec![
            Element::Char('A'),
            Element::Blob(vec![0xDE, 0xAD]),
        ];
        let encoded = encode(&elements);

        // Header (8) + CHAR (5) + BLOB header (9) + payload (2) + END (1) = 25
        assert_eq!(encoded.len(), 25);

        // BLOB at offset 13: tag(02) + length(8 bytes for u64=2) + payload(DE AD)
        assert_eq!(encoded[13], 0x02); // tag
        assert_eq!(
            &encoded[14..22],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
        ); // length = 2
        assert_eq!(&encoded[22..24], &[0xDE, 0xAD]); // payload
        assert_eq!(encoded[24], 0xFF); // END
    }

    #[test]
    fn encode_empty_blob() {
        let elements = vec![Element::Blob(vec![])];
        let encoded = encode(&elements);
        // Header (8) + BLOB header (9) + payload (0) + END (1) = 18
        assert_eq!(encoded.len(), 18);
    }

    #[test]
    fn encoded_size_matches() {
        let elements = vec![
            Element::Char('X'),
            Element::Blob(vec![1, 2, 3]),
            Element::Char('Y'),
        ];
        let computed = encoded_size(&elements).unwrap();
        let actual = encode(&elements).len() as u64;
        assert_eq!(computed, actual);
    }
}
