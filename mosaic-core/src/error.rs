//! Error types for the Mosaic Credential library.
//!
//! Each variant maps to a diagnostic error code from the specification (§13.4).
//! These are internal errors — applications MUST separate them from public
//! authentication responses.

use thiserror::Error;

/// All errors that can occur within the Mosaic Credential core.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// A value outside the Unicode scalar-value range was encountered.
    /// Isolated UTF-16 surrogates (U+D800–U+DFFF) trigger this error.
    #[error("INVALID_SCALAR: code point U+{0:04X} is not a Unicode scalar value")]
    InvalidScalar(u32),

    /// The canonical format version is not supported by this implementation.
    #[error("UNSUPPORTED_VERSION: version {0} is not supported")]
    UnsupportedVersion(u16),

    /// The profile identifier is not supported by this implementation.
    #[error("UNSUPPORTED_PROFILE: profile {0} is not supported")]
    UnsupportedProfile(u16),

    /// An unknown element tag byte was encountered during parsing.
    #[error("INVALID_TAG: tag 0x{0:02X} is not recognized")]
    InvalidTag(u8),

    /// The input ended before a complete element or header could be read.
    #[error("TRUNCATED_INPUT: expected {expected} more bytes")]
    TruncatedInput { expected: usize },

    /// Bytes were found after the END marker.
    #[error("TRAILING_DATA: {0} bytes after END marker")]
    TrailingData(usize),

    /// The declared BLOB length did not match the actual payload bytes available.
    #[error("LENGTH_MISMATCH: declared {declared} bytes, got {actual}")]
    LengthMismatch { declared: u64, actual: u64 },

    /// A configured size or element-count limit was exceeded.
    #[error("LIMIT_EXCEEDED: {description}")]
    LimitExceeded { description: String },

    /// An integer arithmetic operation overflowed during size accounting.
    #[error("INTEGER_OVERFLOW: size computation overflowed")]
    IntegerOverflow,

    /// An I/O error occurred during streaming read or write.
    #[error("IO_ERROR: {0}")]
    IoError(String),

    /// The operating-system CSPRNG could not provide random bytes.
    #[error("RANDOMNESS_FAILURE: could not obtain secure random bytes")]
    RandomnessFailure,

    /// A stored verifier record is malformed or contains unsupported parameters.
    #[error("INVALID_VERIFIER: {0}")]
    InvalidVerifier(String),

    /// A resource policy check rejected the operation (e.g., hostile Argon2
    /// parameters in a stored record).
    #[error("RESOURCE_POLICY_REJECTED: {0}")]
    ResourcePolicyRejected(String),

    /// The builder has already been finalized or has encountered an error.
    /// No further data can be added.
    #[error("BUILDER_FINALIZED: builder cannot accept further data")]
    BuilderFinalized,
}

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e.to_string())
    }
}
