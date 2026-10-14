//! Mosaic Credential Core Library
//!
//! Data model, canonical encoder/parser, size policies, and domain-separated
//! SHA-256 prehash for Mosaic Credential v1.
//!
//! This crate implements the foundation specified in sections 3–8 of the
//! Mosaic Credential Technical Specification.

pub mod builder;
pub mod encoder;
pub mod error;
pub mod parser;
pub mod policy;
pub mod prehash;
pub mod types;

/// Convenience re-exports for the most commonly used types.
pub mod prelude {
    pub use crate::builder::CredentialBuilder;
    pub use crate::encoder::{encode, StreamEncoder};
    pub use crate::error::{Error, Result};
    pub use crate::parser::parse;
    pub use crate::policy::Policy;
    pub use crate::prehash::{prehash, streaming_prehash};
    pub use crate::types::{Element, BACKSPACE};
}
