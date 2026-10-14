//! Mosaic Credential Authentication Library
//!
//! Enrollment, verification, record validation, and parameter management
//! for Mosaic Credential v1.
//!
//! This crate implements sections 8–10 and 13 of the Mosaic Credential
//! Technical Specification.

pub mod enroll;
pub mod params;
pub mod record;
pub mod test_vectors;
pub mod verify;

/// Convenience re-exports for common auth operations.
pub mod prelude {
    pub use crate::enroll::{enroll, enroll_with_salt, enroll_with_salt_str};
    pub use crate::params::{AuthParams, ResourceLimits};
    pub use crate::record::VerifierRecord;
    pub use crate::test_vectors::{get_published_vectors, get_test_vectors, PublishedTestVector};
    pub use crate::verify::{needs_upgrade, upgrade_verifier, verify, VerifyResult};
}



