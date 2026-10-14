//! Core data types for the Mosaic Credential data model.
//!
//! A credential is an ordered sequence of elements (§4):
//!
//! ```text
//! Credential := Element*
//! Element    := CHAR | BLOB
//! ```

use crate::error::{Error, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A single element within a Mosaic Credential.
///
/// The order of elements is part of the secret (§3.1). Elements MUST NOT be
/// sorted or treated as an unordered set.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Element {
    /// A single Unicode scalar value (§4.1).
    ///
    /// Accepted range: U+0000–U+D7FF and U+E000–U+10FFFF.
    /// This includes NUL, Backspace (U+0008), combining characters, etc.
    #[zeroize(skip)]
    Char(char),

    /// An opaque byte sequence (§4.4), typically a file.
    ///
    /// Every byte is significant. The core MUST NOT decode, decompress, or
    /// inspect the content. A zero-length BLOB is valid and differs from the
    /// absence of a BLOB.
    Blob(Vec<u8>),
}

/// Validates that a `u32` code point is a Unicode scalar value and returns the
/// corresponding `char`.
///
/// Rejects isolated UTF-16 surrogates (U+D800–U+DFFF) and values above
/// U+10FFFF, as required by §4.1.
pub fn validate_scalar(code_point: u32) -> Result<char> {
    char::from_u32(code_point).ok_or(Error::InvalidScalar(code_point))
}

/// The Backspace scalar value used in credential-entry mode (§5.1).
///
/// In the credential data model, Backspace is represented as `CHAR(U+0008)`.
/// It MUST NOT automatically remove the preceding credential element.
pub const BACKSPACE: char = '\u{0008}';

/// Tag byte for CHAR elements in the canonical binary format (§6.3).
pub const TAG_CHAR: u8 = 0x01;

/// Tag byte for BLOB elements in the canonical binary format (§6.4).
pub const TAG_BLOB: u8 = 0x02;

/// Tag byte for the END marker in the canonical binary format (§6.5).
pub const TAG_END: u8 = 0xFF;

/// Magic bytes at the start of an MC v1 canonical stream (§6.2).
pub const MAGIC: [u8; 4] = *b"MCRD";

/// The only version supported by this implementation.
pub const VERSION: u16 = 1;

/// The only profile supported by this implementation.
pub const PROFILE: u16 = 1;

/// Size of the canonical header in bytes: magic(4) + version(2) + profile(2).
pub const HEADER_SIZE: usize = 8;

/// Size of a serialized CHAR element in bytes: tag(1) + codepoint(4).
pub const CHAR_ENCODED_SIZE: usize = 5;

/// Size of a BLOB element header in bytes: tag(1) + length(8).
/// The payload follows immediately after.
pub const BLOB_HEADER_SIZE: usize = 9;

/// Size of the END marker in bytes: tag(1).
pub const END_SIZE: usize = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_scalars() {
        assert_eq!(validate_scalar(0x0000).unwrap(), '\0');
        assert_eq!(validate_scalar(0x0008).unwrap(), '\u{0008}'); // Backspace
        assert_eq!(validate_scalar(0x0041).unwrap(), 'A');
        assert_eq!(validate_scalar(0xD7FF).unwrap(), '\u{D7FF}');
        assert_eq!(validate_scalar(0xE000).unwrap(), '\u{E000}');
        assert_eq!(validate_scalar(0x10FFFF).unwrap(), '\u{10FFFF}');
    }

    #[test]
    fn reject_surrogates() {
        // Isolated UTF-16 surrogates are not Unicode scalar values (§4.1).
        for cp in 0xD800..=0xDFFF {
            assert!(
                matches!(validate_scalar(cp), Err(Error::InvalidScalar(v)) if v == cp),
                "U+{cp:04X} should be rejected"
            );
        }
    }

    #[test]
    fn reject_above_unicode() {
        assert!(validate_scalar(0x110000).is_err());
        assert!(validate_scalar(u32::MAX).is_err());
    }

    #[test]
    fn element_equality() {
        // CHAR('A') != BLOB(b"A")  (§4.4)
        assert_ne!(Element::Char('A'), Element::Blob(vec![0x41]));

        // BLOB(A) + BLOB(B) != BLOB(A||B)  (§4.4)
        let a = Element::Blob(vec![1, 2]);
        let b = Element::Blob(vec![3, 4]);
        let ab = Element::Blob(vec![1, 2, 3, 4]);
        assert_ne!(vec![a.clone(), b.clone()], vec![ab]);

        // Zero-length BLOB is valid and differs from no BLOB
        let empty_blob = Element::Blob(vec![]);
        assert_ne!(empty_blob, a);
    }
}
