//! Published test vectors for Mosaic Credential v1 (§16.4).
//!
//! Each vector specifies:
//! - Logical element list
//! - Canonical serialization in hexadecimal
//! - Domain-separated SHA-256 prehash
//! - Fixed test salt
//! - Argon2id parameters
//! - Expected verifier output
//!
//! Fixed salts are for tests only (§16.4). Production enrollment uses fresh random salts.

use mosaic_core::encoder::encode;
use mosaic_core::prehash::streaming_prehash;
use mosaic_core::types::Element;
use serde::{Deserialize, Serialize};

use crate::enroll::enroll_with_salt_str;
use crate::params::{AuthParams, ResourceLimits};
use crate::verify::{verify, VerifyResult};

/// A published test vector definition meeting §16.4 requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedTestVector {
    /// Identifier of the test vector.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Readable representation of the elements.
    pub elements_desc: Vec<String>,
    /// Hex-encoded canonical serialization (`S = canonical_encode(credential)`).
    pub canonical_hex: String,
    /// Hex-encoded domain-separated SHA-256 prehash digest (`D = SHA-256(PREFIX || S)`).
    pub prehash_hex: String,
    /// Fixed test salt in base64.
    pub salt_b64: String,
    /// Argon2id parameters used for verifier derivation.
    pub argon2_params: AuthParams,
    /// Expected Argon2id PHC string in the verifier record.
    pub expected_verifier: String,
}

impl PublishedTestVector {
    /// Verify this test vector against an element list.
    pub fn verify_vector(&self, elements: &[Element]) -> Result<(), String> {
        // 1. Verify canonical serialization
        let encoded = encode(elements);
        let actual_canonical_hex = hex::encode(&encoded);
        if actual_canonical_hex != self.canonical_hex {
            return Err(format!(
                "vector '{}': canonical serialization mismatch:\nexpected {}\ngot      {}",
                self.id, self.canonical_hex, actual_canonical_hex
            ));
        }

        // 2. Verify prehash
        let digest = streaming_prehash(elements);
        let actual_prehash_hex = hex::encode(digest);
        if actual_prehash_hex != self.prehash_hex {
            return Err(format!(
                "vector '{}': prehash mismatch:\nexpected {}\ngot      {}",
                self.id, self.prehash_hex, actual_prehash_hex
            ));
        }

        // 3. Verify verifier derivation with fixed salt
        let record = enroll_with_salt_str(elements, &self.argon2_params, &self.salt_b64)
            .map_err(|e| format!("vector '{}': enrollment failed: {e}", self.id))?;

        if record.verifier != self.expected_verifier {
            return Err(format!(
                "vector '{}': verifier mismatch:\nexpected {}\ngot      {}",
                self.id, self.expected_verifier, record.verifier
            ));
        }

        // 4. Verify candidate verification succeeds against the record
        let limits = ResourceLimits {
            max_memory_kib: self.argon2_params.memory_cost_kib.max(65536) * 2,
            max_iterations: self.argon2_params.iterations.max(10),
            max_parallelism: self.argon2_params.parallelism.max(4),
        };

        if verify(elements, &record, &limits) != VerifyResult::Ok {
            return Err(format!(
                "vector '{}': candidate verification against record returned Denied",
                self.id
            ));
        }

        Ok(())
    }
}

/// Fixed salt used for standard test vectors (16 bytes: b"testsattestsalt" in base64).
pub const FIXED_TEST_SALT: &str = "dGVzdHNhbHR0ZXN0c2FsdA";

/// Return all test vectors paired with their corresponding [`Element`] slice.
pub fn get_test_vectors() -> Vec<(PublishedTestVector, Vec<Element>)> {
    let raw_cases: Vec<(&str, &str, Vec<String>, Vec<Element>, AuthParams)> = vec![
        (
            "mc-v1-001-empty",
            "Empty credential (zero elements)",
            vec![],
            vec![],
            AuthParams::fast_testing(),
        ),
        (
            "mc-v1-002-single-char",
            "Single ASCII character 'A'",
            vec!["CHAR('A')".to_string()],
            vec![Element::Char('A')],
            AuthParams::fast_testing(),
        ),
        (
            "mc-v1-003-word-with-backspaces",
            "Text 'Pass' followed by 3 backspaces and 'word'",
            vec![
                "CHAR('P')".into(), "CHAR('a')".into(), "CHAR('s')".into(), "CHAR('s')".into(),
                "CHAR(U+0008)".into(), "CHAR(U+0008)".into(), "CHAR(U+0008)".into(),
                "CHAR('w')".into(), "CHAR('o')".into(), "CHAR('r')".into(), "CHAR('d')".into(),
            ],
            vec![
                Element::Char('P'), Element::Char('a'), Element::Char('s'), Element::Char('s'),
                Element::Char('\u{0008}'), Element::Char('\u{0008}'), Element::Char('\u{0008}'),
                Element::Char('w'), Element::Char('o'), Element::Char('r'), Element::Char('d'),
            ],
            AuthParams::fast_testing(),
        ),
        (
            "mc-v1-004-multilingual-emoji",
            "Unicode scalars with emoji, symbols, and NUL (🦀, 🔑, ©, U+0000)",
            vec![
                "CHAR('🦀' U+1F980)".into(),
                "CHAR('🔑' U+1F511)".into(),
                "CHAR('©' U+00A9)".into(),
                "CHAR(U+0000)".into(),
            ],
            vec![
                Element::Char('🦀'),
                Element::Char('🔑'),
                Element::Char('©'),
                Element::Char('\0'),
            ],
            AuthParams::fast_testing(),
        ),
        (
            "mc-v1-005-single-blob",
            "Single binary component: b\"hello world\"",
            vec!["BLOB(11 bytes: 68656c6c6f20776f726c64)".into()],
            vec![Element::Blob(b"hello world".to_vec())],
            AuthParams::fast_testing(),
        ),
        (
            "mc-v1-006-empty-blob",
            "Zero-length BLOB component",
            vec!["BLOB(0 bytes)".into()],
            vec![Element::Blob(vec![])],
            AuthParams::fast_testing(),
        ),
        (
            "mc-v1-007-mixed-text-and-blob",
            "Interleaved text and binary: 'P', 'a', BLOB(0x00,0x01,0x02), BS, 'x'",
            vec![
                "CHAR('P')".into(),
                "CHAR('a')".into(),
                "BLOB(3 bytes: 000102)".into(),
                "CHAR(U+0008)".into(),
                "CHAR('x')".into(),
            ],
            vec![
                Element::Char('P'),
                Element::Char('a'),
                Element::Blob(vec![0x00, 0x01, 0x02]),
                Element::Char('\u{0008}'),
                Element::Char('x'),
            ],
            AuthParams::fast_testing(),
        ),
        (
            "mc-v1-008-multiple-blobs",
            "Two distinct BLOB components [0xde, 0xad] and [0xbe, 0xef]",
            vec![
                "BLOB(2 bytes: dead)".into(),
                "BLOB(2 bytes: beef)".into(),
            ],
            vec![
                Element::Blob(vec![0xde, 0xad]),
                Element::Blob(vec![0xbe, 0xef]),
            ],
            AuthParams::fast_testing(),
        ),
    ];

    raw_cases
        .into_iter()
        .map(|(id, desc, elements_desc, elements, params)| {
            let canonical_bytes = encode(&elements);
            let canonical_hex = hex::encode(&canonical_bytes);
            let prehash_digest = streaming_prehash(&elements);
            let prehash_hex = hex::encode(prehash_digest);
            let record = enroll_with_salt_str(&elements, &params, FIXED_TEST_SALT).unwrap();

            let vector = PublishedTestVector {
                id: id.to_string(),
                description: desc.to_string(),
                elements_desc,
                canonical_hex,
                prehash_hex,
                salt_b64: FIXED_TEST_SALT.to_string(),
                argon2_params: params,
                expected_verifier: record.verifier,
            };

            (vector, elements)
        })
        .collect()
}

/// Get all published vectors as serializable structures (without elements).
pub fn get_published_vectors() -> Vec<PublishedTestVector> {
    get_test_vectors().into_iter().map(|(v, _)| v).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_all_published_test_vectors() {
        let vectors = get_test_vectors();
        assert!(!vectors.is_empty());
        for (vector, elements) in &vectors {
            vector.verify_vector(elements).unwrap();
        }
    }

    #[test]
    fn test_vectors_serializable_to_json() {
        let published = get_published_vectors();
        let json = serde_json::to_string_pretty(&published).unwrap();
        let deserialized: Vec<PublishedTestVector> = serde_json::from_str(&json).unwrap();
        assert_eq!(published, deserialized);
    }
}
