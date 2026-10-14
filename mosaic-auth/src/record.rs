//! Verifier record storage and serialization (§9).
//!
//! The record stores only the versioned verifier — never the original text,
//! files, prehash digest, component ordering, or file previews.
//!
//! Record size is independent of original payload size.

use serde::{Deserialize, Serialize};

/// A stored verifier record for a Mosaic Credential.
///
/// Example JSON:
/// ```json
/// {
///   "format": "mosaic-credential",
///   "format_version": 1,
///   "profile": 1,
///   "prehash": "sha256-domain-v1",
///   "verifier": "$argon2id$v=19$m=65536,t=3,p=1$..."
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierRecord {
    /// Format identifier. Always `"mosaic-credential"`.
    pub format: String,

    /// Format version. Currently `1`.
    pub format_version: u16,

    /// Profile identifier. Currently `1`.
    pub profile: u16,

    /// Prehash algorithm identifier. Currently `"sha256-domain-v1"`.
    pub prehash: String,

    /// The Argon2 PHC string carrying salt, parameters, and derived output.
    pub verifier: String,
}

impl VerifierRecord {
    /// The expected format identifier string.
    pub const FORMAT: &'static str = "mosaic-credential";

    /// The expected prehash identifier string.
    pub const PREHASH_ID: &'static str = "sha256-domain-v1";

    /// Create a new record with the given Argon2 PHC string.
    pub fn new(verifier_phc: String) -> Self {
        Self {
            format: Self::FORMAT.to_string(),
            format_version: 1,
            profile: 1,
            prehash: Self::PREHASH_ID.to_string(),
            verifier: verifier_phc,
        }
    }

    /// Validate the record's metadata fields against supported values.
    ///
    /// Returns an error string if any field is unsupported or missing.
    pub fn validate(&self) -> Result<(), String> {
        if self.format != Self::FORMAT {
            return Err(format!(
                "unsupported format: expected '{}', got '{}'",
                Self::FORMAT,
                self.format
            ));
        }
        if self.format_version != 1 {
            return Err(format!(
                "unsupported format_version: expected 1, got {}",
                self.format_version
            ));
        }
        if self.profile != 1 {
            return Err(format!(
                "unsupported profile: expected 1, got {}",
                self.profile
            ));
        }
        if self.prehash != Self::PREHASH_ID {
            return Err(format!(
                "unsupported prehash: expected '{}', got '{}'",
                Self::PREHASH_ID,
                self.prehash
            ));
        }
        if self.verifier.is_empty() {
            return Err("verifier string is empty".to_string());
        }
        if !self.verifier.starts_with("$argon2id$") {
            return Err(format!(
                "verifier does not appear to be an Argon2id PHC string: '{}'",
                &self.verifier[..self.verifier.len().min(30)]
            ));
        }
        Ok(())
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize to compact JSON (no whitespace).
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_json() {
        let record = VerifierRecord::new(
            "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );
        let json = record.to_json().unwrap();
        let parsed = VerifierRecord::from_json(&json).unwrap();
        assert_eq!(record, parsed);
    }

    #[test]
    fn validate_good_record() {
        let record = VerifierRecord::new(
            "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$hash".to_string(),
        );
        record.validate().unwrap();
    }

    #[test]
    fn reject_bad_format() {
        let mut record = VerifierRecord::new("$argon2id$v=19$m=65536,t=3,p=1$s$h".to_string());
        record.format = "not-mosaic".to_string();
        assert!(record.validate().is_err());
    }

    #[test]
    fn reject_bad_version() {
        let mut record = VerifierRecord::new("$argon2id$v=19$m=65536,t=3,p=1$s$h".to_string());
        record.format_version = 2;
        assert!(record.validate().is_err());
    }

    #[test]
    fn reject_empty_verifier() {
        let mut record = VerifierRecord::new(String::new());
        record.verifier = String::new();
        assert!(record.validate().is_err());
    }

    #[test]
    fn reject_non_argon2id_verifier() {
        let record = VerifierRecord::new("$bcrypt$somehash".to_string());
        assert!(record.validate().is_err());
    }
}
