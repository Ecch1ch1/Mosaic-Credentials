//! Verification pipeline for Mosaic Credential (§10.2).
//!
//! 1. Load and validate the stored record.
//! 2. Select its exact format/profile/prehash interpretation.
//! 3. Build and validate the candidate credential.
//! 4. Recompute D.
//! 5. Call the vetted Argon2 verification API with the stored record.
//! 6. Return a generic authentication result externally.
//! 7. On success, upgrade approved cryptographic parameters if needed.
//!
//! Do NOT generate a new salt and compare unrelated enrollment outputs.
//! Verification uses the salt and parameters in the stored record [S1].

use argon2::{Argon2, PasswordHash, PasswordVerifier};

use mosaic_core::error::Error;
use mosaic_core::prehash::streaming_prehash;
use mosaic_core::types::Element;

use crate::params::ResourceLimits;
use crate::record::VerifierRecord;

/// The result of a verification attempt.
///
/// This is a generic authentication result (§10.2 step 6). Internal details
/// such as error codes MUST NOT leak to unauthenticated callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// The candidate credential matches the stored verifier.
    Ok,
    /// The candidate credential does not match, OR the record is invalid.
    Denied,
}

/// Verify a candidate credential against a stored verifier record.
///
/// This implements the full verification pipeline from §10.2.
///
/// # Arguments
///
/// * `elements` — The candidate credential's finalized element list.
/// * `record` — The stored verifier record to verify against.
/// * `limits` — Resource limits for accepting the stored parameters.
///
/// # Returns
///
/// [`VerifyResult::Ok`] if the credential matches, [`VerifyResult::Denied`]
/// otherwise. Errors in validation also produce `Denied` — the caller
/// MUST NOT receive internal error details.
pub fn verify(
    elements: &[Element],
    record: &VerifierRecord,
    limits: &ResourceLimits,
) -> VerifyResult {
    match verify_inner(elements, record, limits) {
        Ok(true) => VerifyResult::Ok,
        _ => VerifyResult::Denied,
    }
}

/// Internal verification that returns detailed errors for diagnostics.
///
/// This function is NOT exposed to unauthenticated callers.
pub(crate) fn verify_inner(
    elements: &[Element],
    record: &VerifierRecord,
    limits: &ResourceLimits,
) -> Result<bool, Error> {
    // Step 1: Load and validate the stored record.
    record
        .validate()
        .map_err(|e| Error::InvalidVerifier(e))?;

    // Step 2: Parse the PHC string to extract parameters.
    let parsed_hash = PasswordHash::new(&record.verifier)
        .map_err(|e| Error::InvalidVerifier(format!("cannot parse PHC string: {e}")))?;

    // Extract and validate Argon2 parameters against resource limits.
    if let Some(params) = extract_params_from_phc(&parsed_hash) {
        limits.check(&params).map_err(|e| Error::ResourcePolicyRejected(e))?;
    }

    // Step 4: Recompute D from the candidate.
    let digest = streaming_prehash(elements);

    // Step 5: Call the vetted Argon2 verification API.
    let argon2 = Argon2::default();
    let result = argon2.verify_password(&digest, &parsed_hash);

    Ok(result.is_ok())
}

/// Extract AuthParams from a parsed PHC hash for resource-limit checking.
fn extract_params_from_phc(hash: &PasswordHash) -> Option<crate::params::AuthParams> {
    // The argon2 crate's PasswordHash stores params in the PHC string.
    // We parse m, t, p from the params field.
    let params_str = hash.params.iter().collect::<Vec<_>>();

    let mut memory_cost_kib = 65536u32;
    let mut iterations = 3u32;
    let mut parallelism = 1u32;

    for (ident, value) in params_str {
        match ident.as_str() {
            "m" => {
                if let Ok(v) = value.decimal() {
                    memory_cost_kib = v;
                }
            }
            "t" => {
                if let Ok(v) = value.decimal() {
                    iterations = v;
                }
            }
            "p" => {
                if let Ok(v) = value.decimal() {
                    parallelism = v;
                }
            }
            _ => {}
        }
    }

    Some(crate::params::AuthParams {
        memory_cost_kib,
        iterations,
        parallelism,
        salt_length_bytes: 16,
        output_length_bytes: 32,
    })
}

/// Check whether a stored verifier record should be upgraded to match target parameters (§10.2 step 7, §10.3).
///
/// Returns `true` if the stored parameters are weaker than `target_params`
/// (e.g. fewer iterations or less memory cost).
pub fn needs_upgrade(record: &VerifierRecord, target_params: &crate::params::AuthParams) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(&record.verifier) else {
        return false;
    };
    if let Some(current_params) = extract_params_from_phc(&parsed_hash) {
        current_params.memory_cost_kib < target_params.memory_cost_kib
            || current_params.iterations < target_params.iterations
            || current_params.parallelism < target_params.parallelism
    } else {
        false
    }
}

/// Upgrade a verified credential by deriving a fresh verifier with new parameters and a fresh salt (§10.3).
///
/// MUST only be called after successful verification of the candidate credential.
pub fn upgrade_verifier(
    elements: &[Element],
    target_params: &crate::params::AuthParams,
) -> Result<VerifierRecord, Error> {
    crate::enroll::enroll(elements, target_params)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll::enroll;
    use crate::params::AuthParams;

    #[test]
    fn verify_correct_credential() {
        let elements = vec![
            Element::Char('P'),
            Element::Char('a'),
            Element::Char('s'),
            Element::Char('s'),
        ];
        let params = AuthParams::fast_testing();
        let record = enroll(&elements, &params).unwrap();
        let limits = ResourceLimits::default();

        assert_eq!(verify(&elements, &record, &limits), VerifyResult::Ok);
    }

    #[test]
    fn verify_wrong_credential() {
        let correct = vec![Element::Char('A')];
        let wrong = vec![Element::Char('B')];
        let params = AuthParams::fast_testing();
        let record = enroll(&correct, &params).unwrap();
        let limits = ResourceLimits::default();

        assert_eq!(verify(&wrong, &record, &limits), VerifyResult::Denied);
    }

    #[test]
    fn verify_order_matters() {
        let e1 = vec![Element::Char('A'), Element::Char('B')];
        let e2 = vec![Element::Char('B'), Element::Char('A')];
        let params = AuthParams::fast_testing();
        let record = enroll(&e1, &params).unwrap();
        let limits = ResourceLimits::default();

        assert_eq!(verify(&e1, &record, &limits), VerifyResult::Ok);
        assert_eq!(verify(&e2, &record, &limits), VerifyResult::Denied);
    }

    #[test]
    fn verify_backspace_matters() {
        // "Pass<BS><BS><BS>word" ≠ "Pword"
        let with_bs = vec![
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
        let without_bs = vec![
            Element::Char('P'),
            Element::Char('w'),
            Element::Char('o'),
            Element::Char('r'),
            Element::Char('d'),
        ];
        let params = AuthParams::fast_testing();
        let record = enroll(&with_bs, &params).unwrap();
        let limits = ResourceLimits::default();

        assert_eq!(verify(&with_bs, &record, &limits), VerifyResult::Ok);
        assert_eq!(verify(&without_bs, &record, &limits), VerifyResult::Denied);
    }

    #[test]
    fn verify_char_vs_blob() {
        let char_a = vec![Element::Char('A')];
        let blob_a = vec![Element::Blob(vec![0x41])];
        let params = AuthParams::fast_testing();
        let record = enroll(&char_a, &params).unwrap();
        let limits = ResourceLimits::default();

        assert_eq!(verify(&char_a, &record, &limits), VerifyResult::Ok);
        assert_eq!(verify(&blob_a, &record, &limits), VerifyResult::Denied);
    }

    #[test]
    fn verify_blob_boundaries() {
        let split = vec![
            Element::Blob(vec![1, 2]),
            Element::Blob(vec![3, 4]),
        ];
        let concat = vec![Element::Blob(vec![1, 2, 3, 4])];
        let params = AuthParams::fast_testing();
        let record = enroll(&split, &params).unwrap();
        let limits = ResourceLimits::default();

        assert_eq!(verify(&split, &record, &limits), VerifyResult::Ok);
        assert_eq!(verify(&concat, &record, &limits), VerifyResult::Denied);
    }

    #[test]
    fn verify_empty_blob_vs_no_blob() {
        let with_empty = vec![Element::Blob(vec![])];
        let without: Vec<Element> = vec![];
        let params = AuthParams::fast_testing();
        let record = enroll(&with_empty, &params).unwrap();
        let limits = ResourceLimits::default();

        assert_eq!(verify(&with_empty, &record, &limits), VerifyResult::Ok);
        assert_eq!(verify(&without, &record, &limits), VerifyResult::Denied);
    }

    #[test]
    fn deny_invalid_record() {
        let elements = vec![Element::Char('A')];
        let bad_record = VerifierRecord {
            format: "wrong".to_string(),
            format_version: 1,
            profile: 1,
            prehash: "sha256-domain-v1".to_string(),
            verifier: "$argon2id$v=19$m=256,t=1,p=1$s$h".to_string(),
        };
        let limits = ResourceLimits::default();
        assert_eq!(verify(&elements, &bad_record, &limits), VerifyResult::Denied);
    }

    #[test]
    fn test_upgrade_workflow() {
        let elements = vec![Element::Char('S'), Element::Char('e'), Element::Char('c')];
        let old_params = AuthParams::fast_testing();
        let old_record = enroll(&elements, &old_params).unwrap();
        let limits = ResourceLimits::default();

        assert_eq!(verify(&elements, &old_record, &limits), VerifyResult::Ok);

        let target_params = AuthParams {
            memory_cost_kib: 512,
            iterations: 2,
            parallelism: 1,
            ..AuthParams::fast_testing()
        };

        assert!(needs_upgrade(&old_record, &target_params));

        let upgraded_record = upgrade_verifier(&elements, &target_params).unwrap();
        assert_eq!(verify(&elements, &upgraded_record, &limits), VerifyResult::Ok);
        assert!(!needs_upgrade(&upgraded_record, &target_params));
    }
}

