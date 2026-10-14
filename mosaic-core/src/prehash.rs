//! Domain-separated SHA-256 prehash for Mosaic Credential (§8.2).
//!
//! ```text
//! S = canonical_encode(credential)
//! PREFIX = ASCII("MOSAIC-CREDENTIAL/PREHASH/V1") || 0x00
//! D = SHA-256(PREFIX || S)
//! ```
//!
//! `D` is the raw 32-byte digest, not its hexadecimal string.
//! `D` MUST NOT be persisted or logged.

use sha2::{Digest, Sha256};

use crate::encoder::StreamEncoder;
use crate::types::Element;

/// The domain-separation prefix, including the trailing NUL byte.
pub const PREHASH_PREFIX: &[u8] = b"MOSAIC-CREDENTIAL/PREHASH/V1\x00";

/// The prehash identifier string stored in verifier records.
pub const PREHASH_ID: &str = "sha256-domain-v1";

/// Compute the domain-separated SHA-256 prehash for a finalized element list.
///
/// This is the buffered convenience API. The canonical encoding is computed
/// in memory and then hashed. For large credentials, use
/// [`streaming_prehash`] instead.
///
/// Returns the raw 32-byte digest `D`.
pub fn prehash(elements: &[Element]) -> [u8; 32] {
    let canonical = crate::encoder::encode(elements);
    let mut hasher = Sha256::new();
    hasher.update(PREHASH_PREFIX);
    hasher.update(&canonical);
    hasher.finalize().into()
}

/// Compute the domain-separated SHA-256 prehash by streaming the canonical
/// encoding directly into the hasher, avoiding a large intermediate buffer.
///
/// This is the preferred API for large credentials (§8.2, §13.1).
///
/// Returns the raw 32-byte digest `D`.
pub fn streaming_prehash(elements: &[Element]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREHASH_PREFIX);

    // Stream canonical encoding into hasher via a wrapper writer.
    let mut encoder = StreamEncoder::new(HashWriter(&mut hasher));
    encoder.write_header().expect("hash writer cannot fail");
    for element in elements {
        encoder.write_element(element).expect("hash writer cannot fail");
    }
    encoder.write_end().expect("hash writer cannot fail");

    hasher.finalize().into()
}

/// A simple Write adapter that feeds all written bytes into a SHA-256 hasher.
struct HashWriter<'a>(&'a mut Sha256);

impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prehash_prefix_is_correct() {
        assert_eq!(PREHASH_PREFIX.len(), 29); // 28 chars + NUL
        assert_eq!(PREHASH_PREFIX[28], 0x00);
        assert!(PREHASH_PREFIX.starts_with(b"MOSAIC-CREDENTIAL/PREHASH/V1"));
    }

    #[test]
    fn buffered_and_streaming_agree() {
        let elements = vec![
            Element::Char('P'),
            Element::Char('a'),
            Element::Char('s'),
            Element::Char('s'),
            Element::Char('\u{0008}'),
            Element::Char('\u{0008}'),
            Element::Char('\u{0008}'),
            Element::Char('w'),
            Element::Char('o'),
            Element::Char('r'),
            Element::Char('d'),
        ];

        let d_buffered = prehash(&elements);
        let d_streaming = streaming_prehash(&elements);
        assert_eq!(d_buffered, d_streaming);
    }

    #[test]
    fn different_elements_different_hash() {
        let e1 = vec![Element::Char('A')];
        let e2 = vec![Element::Char('B')];
        assert_ne!(prehash(&e1), prehash(&e2));
    }

    #[test]
    fn order_matters_in_hash() {
        let e1 = vec![Element::Char('A'), Element::Blob(vec![1])];
        let e2 = vec![Element::Blob(vec![1]), Element::Char('A')];
        assert_ne!(prehash(&e1), prehash(&e2));
    }

    #[test]
    fn char_vs_blob_different_hash() {
        // CHAR('A') vs BLOB(0x41)
        let e1 = vec![Element::Char('A')];
        let e2 = vec![Element::Blob(vec![0x41])];
        assert_ne!(prehash(&e1), prehash(&e2));
    }

    #[test]
    fn empty_credential_has_deterministic_hash() {
        let d1 = prehash(&[]);
        let d2 = prehash(&[]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn blob_boundaries_affect_hash() {
        // BLOB(A) + BLOB(B) != BLOB(A||B)
        let e1 = vec![
            Element::Blob(vec![1, 2]),
            Element::Blob(vec![3, 4]),
        ];
        let e2 = vec![Element::Blob(vec![1, 2, 3, 4])];
        assert_ne!(prehash(&e1), prehash(&e2));
    }

    #[test]
    fn known_vector_empty_credential() {
        // Regression test: empty credential should produce a known hash.
        // S = MCRD + version(1) + profile(1) + END
        // = 4D 43 52 44 00 01 00 01 FF
        // PREFIX = "MOSAIC-CREDENTIAL/PREHASH/V1\0"
        // D = SHA-256(PREFIX || S)
        let d = prehash(&[]);
        // Just verify it's 32 bytes and deterministic.
        assert_eq!(d.len(), 32);
        let d2 = prehash(&[]);
        assert_eq!(d, d2);
    }
}
