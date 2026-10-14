//! Enrollment pipeline for Mosaic Credential (§10.1).
//!
//! 1. Load application-controlled policy.
//! 2. Build the ordered credential.
//! 3. Validate structure and limits incrementally.
//! 4. Stream canonical serialization into SHA-256 with the domain prefix.
//! 5. Generate a fresh salt.
//! 6. Derive the Argon2id verifier.
//! 7. Persist only the versioned verifier record.
//! 8. Release transient sensitive data as far as the runtime permits.

use argon2::{Argon2, Params, Version};
use password_hash::SaltString;

/// We use password_hash's re-exported rand_core (v0.6) to ensure version
/// compatibility with SaltString::generate.
fn generate_salt() -> SaltString {
    SaltString::generate(password_hash::rand_core::OsRng)
}

use mosaic_core::error::Error;
use mosaic_core::prehash::streaming_prehash;
use mosaic_core::types::Element;

use crate::params::AuthParams;
use crate::record::VerifierRecord;

/// Enroll a credential: compute the prehash, derive an Argon2id verifier with
/// a fresh random salt, and return a storable [`VerifierRecord`].
///
/// The salt MUST come from an OS-backed CSPRNG. Failure to obtain randomness
/// MUST abort enrollment (§8.3).
///
/// `D` (the prehash digest) is NOT persisted or logged (§8.2).
pub fn enroll(elements: &[Element], params: &AuthParams) -> Result<VerifierRecord, Error> {
    // Validate params before expensive work.
    params.validate().map_err(|e| Error::ResourcePolicyRejected(e))?;

    // Step 4: Stream canonical serialization into SHA-256 with domain prefix.
    let mut digest = streaming_prehash(elements);

    // Step 5: Generate a fresh salt from OS CSPRNG.
    let salt = generate_salt();

    // Step 6: Derive the Argon2id verifier.
    let argon2_params = Params::new(
        params.memory_cost_kib,
        params.iterations,
        params.parallelism,
        Some(params.output_length_bytes),
    )
    .map_err(|e| Error::InvalidVerifier(format!("invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

    // Use the Argon2 password_hash API to produce a PHC string.
    use argon2::PasswordHasher;
    use zeroize::Zeroize;
    let hash_result = argon2.hash_password(&digest, &salt);
    digest.zeroize();
    let hash = hash_result
        .map_err(|e| Error::InvalidVerifier(format!("Argon2 hashing failed: {e}")))?;

    let phc_string = hash.to_string();

    // Step 7: Build the verifier record.
    let record = VerifierRecord::new(phc_string);

    // Step 8: Release transient sensitive data.
    // `digest` and `salt` are dropped here. Explicit zeroization is best-effort
    // without claiming complete removal from all copies (§13.4).

    Ok(record)
}

/// Enroll with a fixed salt — FOR TESTING AND DETERMINISTIC TEST VECTORS ONLY (§16.4).
///
/// Production enrollment MUST use [`enroll()`] with a fresh random salt.
/// Fixed salts are exclusively for generating deterministic test vectors.
pub fn enroll_with_salt(
    elements: &[Element],
    params: &AuthParams,
    salt: &SaltString,
) -> Result<VerifierRecord, Error> {
    params.validate().map_err(|e| Error::ResourcePolicyRejected(e))?;

    let digest = streaming_prehash(elements);

    let argon2_params = Params::new(
        params.memory_cost_kib,
        params.iterations,
        params.parallelism,
        Some(params.output_length_bytes),
    )
    .map_err(|e| Error::InvalidVerifier(format!("invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

    use argon2::PasswordHasher;
    let hash = argon2
        .hash_password(&digest, salt)
        .map_err(|e| Error::InvalidVerifier(format!("Argon2 hashing failed: {e}")))?;

    Ok(VerifierRecord::new(hash.to_string()))
}

/// Convenience helper to enroll with a base64-encoded fixed salt string.
///
/// FOR TESTING AND DETERMINISTIC TEST VECTORS ONLY (§16.4).
pub fn enroll_with_salt_str(
    elements: &[Element],
    params: &AuthParams,
    salt_b64: &str,
) -> Result<VerifierRecord, Error> {
    let salt = SaltString::from_b64(salt_b64)
        .map_err(|e| Error::InvalidVerifier(format!("invalid salt base64: {e}")))?;
    enroll_with_salt(elements, params, &salt)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_basic() {
        let elements = vec![
            Element::Char('t'),
            Element::Char('e'),
            Element::Char('s'),
            Element::Char('t'),
        ];
        let params = AuthParams::fast_testing();
        let record = enroll(&elements, &params).unwrap();

        // Record should be valid.
        record.validate().unwrap();

        // Verifier should be an Argon2id PHC string.
        assert!(record.verifier.starts_with("$argon2id$"));
    }

    #[test]
    fn enroll_produces_different_salts() {
        let elements = vec![Element::Char('A')];
        let params = AuthParams::fast_testing();
        let r1 = enroll(&elements, &params).unwrap();
        let r2 = enroll(&elements, &params).unwrap();
        // Same credential but different random salts → different verifiers.
        assert_ne!(r1.verifier, r2.verifier);
    }

    #[test]
    fn enroll_with_fixed_salt_deterministic() {
        let elements = vec![Element::Char('A')];
        let params = AuthParams::fast_testing();
        let salt = SaltString::from_b64("dGVzdHNhbHR0ZXN0c2FsdA").unwrap();
        let r1 = enroll_with_salt(&elements, &params, &salt).unwrap();
        let r2 = enroll_with_salt(&elements, &params, &salt).unwrap();
        assert_eq!(r1.verifier, r2.verifier);
    }
}
