//! Specification compliance integration test suite (§16).
//!
//! Covers:
//! - §16.1 Required equivalence tests
//! - §16.2 Required difference tests
//! - §16.3 Boundary and parser tests

use mosaic_core::builder::CredentialBuilder;
use mosaic_core::encoder::encode;
use mosaic_core::error::Error;
use mosaic_core::parser::parse;
use mosaic_core::policy::Policy;
use mosaic_core::prehash::streaming_prehash;
use mosaic_core::types::Element;

use mosaic_auth::enroll::enroll;
use mosaic_auth::params::{AuthParams, ResourceLimits};
use mosaic_auth::record::VerifierRecord;
use mosaic_auth::verify::{verify, VerifyResult};


// =========================================================================
// §16.1 Required equivalence tests
// =========================================================================

#[test]
fn test_16_1_text_chunking_equivalence() {
    let policy = Policy::default_generous();

    // Single add_text
    let mut b1 = CredentialBuilder::new(policy.clone()).unwrap();
    b1.add_text("Pass").unwrap();
    let cred1 = b1.finalize().unwrap();

    // Multiple add_text calls: "P", "as", "s"
    let mut b2 = CredentialBuilder::new(policy.clone()).unwrap();
    b2.add_text("P").unwrap();
    b2.add_text("as").unwrap();
    b2.add_text("s").unwrap();
    let cred2 = b2.finalize().unwrap();

    // Scalar by scalar: "P", "a", "s", "s"
    let mut b3 = CredentialBuilder::new(policy).unwrap();
    b3.add_text("P").unwrap();
    b3.add_text("a").unwrap();
    b3.add_text("s").unwrap();
    b3.add_text("s").unwrap();
    let cred3 = b3.finalize().unwrap();

    assert_eq!(cred1, cred2);
    assert_eq!(cred1, cred3);

    // Serialization & prehash must be identical
    assert_eq!(encode(&cred1), encode(&cred2));
    assert_eq!(streaming_prehash(&cred1), streaming_prehash(&cred2));
}

#[test]
fn test_16_1_blob_stream_buffer_sizes_equivalence() {
    let data = b"The quick brown fox jumps over the lazy dog. 0123456789!@#$%^&*()";

    // Read with small buffer vs large buffer
    let mut b1 = CredentialBuilder::new(Policy::default_generous()).unwrap();
    b1.add_blob(data).unwrap();
    let cred1 = b1.finalize().unwrap();

    let mut b2 = CredentialBuilder::new(Policy::default_generous()).unwrap();
    let mut cursor = std::io::Cursor::new(data);
    b2.add_blob_stream(&mut cursor, data.len() as u64).unwrap();
    let cred2 = b2.finalize().unwrap();

    assert_eq!(cred1, cred2);
    assert_eq!(encode(&cred1), encode(&cred2));
    assert_eq!(streaming_prehash(&cred1), streaming_prehash(&cred2));
}

#[test]
fn test_16_1_identical_bytes_different_sources() {
    // Filesystem path/name is NOT included automatically (§3.2, §16.1)
    let payload = vec![42u8; 100];
    let cred1 = vec![Element::Blob(payload.clone())];
    let cred2 = vec![Element::Blob(payload)];

    assert_eq!(encode(&cred1), encode(&cred2));
    assert_eq!(streaming_prehash(&cred1), streaming_prehash(&cred2));
}

// =========================================================================
// §16.2 Required difference tests
// =========================================================================

#[test]
fn test_16_2_component_order_matters() {
    let c1 = vec![Element::Char('A'), Element::Char('B')];
    let c2 = vec![Element::Char('B'), Element::Char('A')];

    assert_ne!(encode(&c1), encode(&c2));
    assert_ne!(streaming_prehash(&c1), streaming_prehash(&c2));

    let params = AuthParams::fast_testing();
    let r1 = enroll(&c1, &params).unwrap();
    assert_eq!(verify(&c2, &r1, &ResourceLimits::default()), VerifyResult::Denied);
}

#[test]
fn test_16_2_backspace_count_matters() {
    // "Pass<BS><BS><BS>word" vs "Pass<BS><BS>word" vs "Pword"
    let mut b1 = CredentialBuilder::new(Policy::default_generous()).unwrap();
    b1.add_text("Pass").unwrap();
    b1.add_backspace(3).unwrap();
    b1.add_text("word").unwrap();
    let c1 = b1.finalize().unwrap();

    let mut b2 = CredentialBuilder::new(Policy::default_generous()).unwrap();
    b2.add_text("Pass").unwrap();
    b2.add_backspace(2).unwrap();
    b2.add_text("word").unwrap();
    let c2 = b2.finalize().unwrap();

    let mut b3 = CredentialBuilder::new(Policy::default_generous()).unwrap();
    b3.add_text("Pword").unwrap();
    let c3 = b3.finalize().unwrap();

    assert_ne!(encode(&c1), encode(&c2));
    assert_ne!(encode(&c1), encode(&c3));
    assert_ne!(streaming_prehash(&c1), streaming_prehash(&c2));
    assert_ne!(streaming_prehash(&c1), streaming_prehash(&c3));
}

#[test]
fn test_16_2_char_vs_blob_equivalent_display_bytes() {
    // CHAR('A') != BLOB(b"A")
    let c1 = vec![Element::Char('A')];
    let c2 = vec![Element::Blob(vec![0x41])];

    assert_ne!(encode(&c1), encode(&c2));
    assert_ne!(streaming_prehash(&c1), streaming_prehash(&c2));

    let params = AuthParams::fast_testing();
    let r1 = enroll(&c1, &params).unwrap();
    assert_eq!(verify(&c2, &r1, &ResourceLimits::default()), VerifyResult::Denied);
}

#[test]
fn test_16_2_separate_blobs_vs_concatenated_blob() {
    // BLOB(A), BLOB(B) != BLOB(A || B) (§4.4, §16.2)
    let c_split = vec![
        Element::Blob(b"hello ".to_vec()),
        Element::Blob(b"world".to_vec()),
    ];
    let c_concat = vec![Element::Blob(b"hello world".to_vec())];

    assert_ne!(encode(&c_split), encode(&c_concat));
    assert_ne!(streaming_prehash(&c_split), streaming_prehash(&c_concat));
}

#[test]
fn test_16_2_empty_blob_vs_absent_blob() {
    // A zero-length BLOB is valid and differs from no BLOB (§4.4, §16.2)
    let c_with_empty = vec![Element::Blob(vec![])];
    let c_none: Vec<Element> = vec![];

    assert_ne!(encode(&c_with_empty), encode(&c_none));
    assert_ne!(streaming_prehash(&c_with_empty), streaming_prehash(&c_none));
}

#[test]
fn test_16_2_modified_file_content_one_bit() {
    let data1 = vec![0xAA; 64];
    let mut data2 = data1.clone();
    data2[32] ^= 0x01; // single bit flip

    let c1 = vec![Element::Blob(data1)];
    let c2 = vec![Element::Blob(data2)];

    assert_ne!(streaming_prehash(&c1), streaming_prehash(&c2));

    let params = AuthParams::fast_testing();
    let r1 = enroll(&c1, &params).unwrap();
    assert_eq!(verify(&c2, &r1, &ResourceLimits::default()), VerifyResult::Denied);
}

#[test]
fn test_16_2_unicode_sequence_vs_normalized_alternative() {
    // No implicit transformations: NFC vs NFD MUST be distinct credentials (§4.3, §16.2)
    // Composed é: U+00E9 (1 scalar)
    let c_nfc = vec![Element::Char('\u{00E9}')];
    // Decomposed e + acute: U+0065, U+0301 (2 scalars)
    let c_nfd = vec![Element::Char('\u{0065}'), Element::Char('\u{0301}')];

    assert_ne!(encode(&c_nfc), encode(&c_nfd));
    assert_ne!(streaming_prehash(&c_nfc), streaming_prehash(&c_nfd));

    let params = AuthParams::fast_testing();
    let r1 = enroll(&c_nfc, &params).unwrap();
    assert_eq!(verify(&c_nfd, &r1, &ResourceLimits::default()), VerifyResult::Denied);
}

#[test]
fn test_16_2_literal_token_label_vs_control_character() {
    // Literal text "<BS>" != CHAR(U+0008) (§5.2, §16.2)
    let c_literal = vec![
        Element::Char('<'),
        Element::Char('B'),
        Element::Char('S'),
        Element::Char('>'),
    ];
    let c_actual_bs = vec![Element::Char('\u{0008}')];

    assert_ne!(encode(&c_literal), encode(&c_actual_bs));
    assert_ne!(streaming_prehash(&c_literal), streaming_prehash(&c_actual_bs));
}

// =========================================================================
// §16.3 Boundary and parser tests
// =========================================================================

#[test]
fn test_16_3_nul_and_control_characters() {
    let controls = vec![
        Element::Char('\u{0000}'), // NUL
        Element::Char('\u{0001}'), // SOH
        Element::Char('\u{0008}'), // BS
        Element::Char('\u{0009}'), // HT
        Element::Char('\u{000A}'), // LF
        Element::Char('\u{000D}'), // CR
        Element::Char('\u{001F}'), // US
        Element::Char('\u{007F}'), // DEL
    ];

    let bytes = encode(&controls);
    let parsed = parse(&bytes).unwrap();
    assert_eq!(controls, parsed);
}

#[test]
fn test_16_3_max_unicode_scalar() {
    let max_scalar = vec![Element::Char('\u{10FFFF}')];
    let bytes = encode(&max_scalar);
    let parsed = parse(&bytes).unwrap();
    assert_eq!(max_scalar, parsed);
}

#[test]
fn test_16_3_isolated_surrogate_rejection() {
    // U+D800 is an isolated surrogate
    let mut bytes = vec![0x4D, 0x43, 0x52, 0x44, 0x00, 0x01, 0x00, 0x01]; // Header
    bytes.push(0x01); // CHAR tag
    bytes.extend_from_slice(&0x0000D800u32.to_be_bytes()); // U+D800
    bytes.push(0xFF); // END

    let res = parse(&bytes);
    assert!(matches!(res, Err(Error::InvalidScalar(0xD800))));

    // Also U+DFFF
    let mut bytes2 = vec![0x4D, 0x43, 0x52, 0x44, 0x00, 0x01, 0x00, 0x01];
    bytes2.push(0x01);
    bytes2.extend_from_slice(&0x0000DFFFu32.to_be_bytes());
    bytes2.push(0xFF);
    let res2 = parse(&bytes2);
    assert!(matches!(res2, Err(Error::InvalidScalar(0xDFFF))));
}

#[test]
fn test_16_3_truncated_header_char_and_blob() {
    // Truncated header (3 bytes)
    assert!(matches!(parse(&[0x4D, 0x43, 0x52]), Err(Error::TruncatedInput { .. })));

    // Truncated CHAR (tag + only 2 bytes)
    let trunc_char = [0x4D, 0x43, 0x52, 0x44, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00];
    assert!(matches!(parse(&trunc_char), Err(Error::TruncatedInput { .. })));

    // Truncated BLOB (declared 10 bytes, provided 3 bytes) -> LengthMismatch
    let mut trunc_blob = vec![0x4D, 0x43, 0x52, 0x44, 0x00, 0x01, 0x00, 0x01];
    trunc_blob.push(0x02);
    trunc_blob.extend_from_slice(&10u64.to_be_bytes());
    trunc_blob.extend_from_slice(&[1, 2, 3]);
    assert!(matches!(
        parse(&trunc_blob),
        Err(Error::LengthMismatch { declared: 10, actual: 3 })
    ));
}


#[test]
fn test_16_3_missing_end_and_trailing_data() {
    // Missing END
    let no_end = vec![0x4D, 0x43, 0x52, 0x44, 0x00, 0x01, 0x00, 0x01];
    assert!(matches!(parse(&no_end), Err(Error::TruncatedInput { .. })));

    // Trailing data after END
    let mut trailing = vec![0x4D, 0x43, 0x52, 0x44, 0x00, 0x01, 0x00, 0x01, 0xFF];
    trailing.push(0x42);
    assert!(matches!(parse(&trailing), Err(Error::TrailingData(1))));
}

#[test]
fn test_16_3_unknown_version_profile_and_tag() {
    // Unknown version 2
    let bad_version = [0x4D, 0x43, 0x52, 0x44, 0x00, 0x02, 0x00, 0x01, 0xFF];
    assert!(matches!(parse(&bad_version), Err(Error::UnsupportedVersion(2))));

    // Unknown profile 99
    let bad_profile = [0x4D, 0x43, 0x52, 0x44, 0x00, 0x01, 0x00, 0x63, 0xFF];
    assert!(matches!(parse(&bad_profile), Err(Error::UnsupportedProfile(99))));

    // Unknown tag 0x42
    let bad_tag = [0x4D, 0x43, 0x52, 0x44, 0x00, 0x01, 0x00, 0x01, 0x42, 0xFF];
    assert!(matches!(parse(&bad_tag), Err(Error::InvalidTag(0x42))));
}

#[test]
fn test_16_3_large_numbers_of_empty_blobs() {
    // 500 empty BLOBs: verify bounded parsing and correct round-trip
    let empty_blobs = vec![Element::Blob(vec![]); 500];
    let encoded = encode(&empty_blobs);
    let parsed = parse(&encoded).unwrap();
    assert_eq!(empty_blobs, parsed);
    assert_eq!(parsed.len(), 500);
}

#[test]
fn test_16_3_hostile_verifier_cost_parameters() {
    let limits = ResourceLimits {
        max_memory_kib: 65536,
        max_iterations: 3,
        max_parallelism: 1,
    };

    // Hostile record requesting 10 GiB memory
    let hostile_record = VerifierRecord {
        format: "mosaic-credential".to_string(),
        format_version: 1,
        profile: 1,
        prehash: "sha256-domain-v1".to_string(),
        verifier: "$argon2id$v=19$m=10485760,t=3,p=1$c29tZXNhbHQ$hash".to_string(),
    };

    let elements = vec![Element::Char('A')];
    assert_eq!(verify(&elements, &hostile_record, &limits), VerifyResult::Denied);
}

#[test]
fn test_16_3_exact_limits_and_one_byte_overflow() {
    // Policy limit: exactly 14 bytes (header 8 + char 5 + end 1 = 14 bytes = 112 bits)
    let exact_policy = Policy::new(112, 1000, 10);
    let mut b1 = CredentialBuilder::new(exact_policy).unwrap();
    b1.add_text("A").unwrap();
    assert!(b1.finalize().is_ok());

    // 1 bit less than required for 1 char + END (111 bits -> 13 bytes limit).
    // Adding 'A' takes 13 bytes (header 8 + char 5), which fits.
    // Finalize adds the END marker (total 14 bytes > 13 bytes limit) and fails with LimitExceeded.
    let tight_policy = Policy::new(111, 1000, 10);
    let mut b2 = CredentialBuilder::new(tight_policy).unwrap();
    b2.add_text("A").unwrap();
    assert!(matches!(b2.finalize(), Err(Error::LimitExceeded { .. })));

    // 103 bits -> 12 bytes maximum. Adding 'A' (13 bytes) fails immediately.
    let immediate_overflow = Policy::new(103, 1000, 10);
    let mut b3 = CredentialBuilder::new(immediate_overflow).unwrap();
    assert!(matches!(b3.add_text("A"), Err(Error::LimitExceeded { .. })));
}


