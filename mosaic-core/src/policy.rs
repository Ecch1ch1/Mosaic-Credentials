//! Size-limit policy enforcement for Mosaic Credential (§7).
//!
//! The integrating application chooses the policy. A person authenticating
//! MUST NOT be able to raise server limits by supplying their own policy (§7.1).
//!
//! All limits are expressed in **bits** to match the specification. Because v1
//! serialization is byte-aligned, an odd bit limit accepts only complete bytes
//! that fit within it.

use crate::error::{Error, Result};

/// Size and element-count policy for credential construction and parsing.
///
/// All bit-based limits accept only whole bytes that fit within the limit.
/// For example, a limit of 13 bits cannot accommodate 2 bytes (16 bits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Maximum total size of the canonical serialization in bits, including
    /// header, tags, length fields, and END marker.
    /// The prehash domain prefix is NOT counted (§7.1).
    pub max_encoded_bits: u64,

    /// Maximum size of a single BLOB payload in bits.
    /// Applied separately to each BLOB (§7.1).
    pub max_blob_bits: u64,

    /// Maximum number of CHAR and BLOB elements, including empty BLOBs.
    pub max_elements: u64,
}

impl Policy {
    /// Create a new policy with the given limits.
    pub fn new(max_encoded_bits: u64, max_blob_bits: u64, max_elements: u64) -> Self {
        Self {
            max_encoded_bits,
            max_blob_bits,
            max_elements,
        }
    }

    /// A generous default: 250 MB total, 250 MB per blob, 100 000 elements.
    pub fn default_generous() -> Self {
        Self {
            max_encoded_bits: 2_000_000_000,  // 250 MB in bits
            max_blob_bits: 2_000_000_000,     // 250 MB per blob
            max_elements: 100_000,
        }
    }

    /// A restrictive policy suitable for text-only credentials:
    /// ~1 KB total, no large blobs, 1000 elements.
    pub fn text_only() -> Self {
        Self {
            max_encoded_bits: 8_000,     // 1000 bytes
            max_blob_bits: 0,            // no blobs
            max_elements: 1_000,
        }
    }

    /// Convert a bit limit to the maximum number of whole bytes that fit.
    pub fn bits_to_max_bytes(bits: u64) -> u64 {
        bits / 8
    }
}

/// Tracks cumulative sizes during credential construction and enforces limits
/// using checked arithmetic (§7.3).
///
/// The implementation MUST:
/// - Count sizes incrementally using checked arithmetic.
/// - Reject a size violation without producing a usable verifier.
/// - Never silently truncate input.
/// - Avoid allocating memory solely from an untrusted length field.
/// - Detect mismatches between advertised and observed lengths.
/// - Bound element count independently of byte count.
#[derive(Debug, Clone)]
pub struct SizeAccountant {
    policy: Policy,
    /// Current total encoded size in bytes.
    encoded_bytes: u64,
    /// Current element count.
    element_count: u64,
}

impl SizeAccountant {
    /// Create a new accountant for the given policy, with the header size
    /// already counted.
    pub fn new(policy: Policy) -> Result<Self> {
        let header_bytes = crate::types::HEADER_SIZE as u64;
        let max_bytes = Policy::bits_to_max_bytes(policy.max_encoded_bits);
        if header_bytes > max_bytes {
            return Err(Error::LimitExceeded {
                description: format!(
                    "header size ({header_bytes} bytes) exceeds max_encoded_bits ({} bits = {max_bytes} bytes)",
                    policy.max_encoded_bits
                ),
            });
        }
        Ok(Self {
            policy,
            encoded_bytes: header_bytes,
            element_count: 0,
        })
    }

    /// Record the addition of `byte_count` bytes to the encoded stream.
    /// Returns an error if the total exceeds `max_encoded_bits`.
    pub fn add_encoded_bytes(&mut self, byte_count: u64) -> Result<()> {
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(byte_count)
            .ok_or(Error::IntegerOverflow)?;

        let max_bytes = Policy::bits_to_max_bytes(self.policy.max_encoded_bits);
        if self.encoded_bytes > max_bytes {
            return Err(Error::LimitExceeded {
                description: format!(
                    "total encoded size ({} bytes) exceeds limit ({max_bytes} bytes from {} bits)",
                    self.encoded_bytes, self.policy.max_encoded_bits
                ),
            });
        }
        Ok(())
    }

    /// Record the addition of one element. Returns an error if the count
    /// exceeds `max_elements`.
    pub fn add_element(&mut self) -> Result<()> {
        self.element_count = self
            .element_count
            .checked_add(1)
            .ok_or(Error::IntegerOverflow)?;

        if self.element_count > self.policy.max_elements {
            return Err(Error::LimitExceeded {
                description: format!(
                    "element count ({}) exceeds limit ({})",
                    self.element_count, self.policy.max_elements
                ),
            });
        }
        Ok(())
    }

    /// Validate that a single BLOB payload does not exceed `max_blob_bits`.
    pub fn check_blob_size(&self, payload_bytes: u64) -> Result<()> {
        let payload_bits = payload_bytes
            .checked_mul(8)
            .ok_or(Error::IntegerOverflow)?;

        if payload_bits > self.policy.max_blob_bits {
            return Err(Error::LimitExceeded {
                description: format!(
                    "BLOB payload ({payload_bytes} bytes = {payload_bits} bits) exceeds max_blob_bits ({})",
                    self.policy.max_blob_bits
                ),
            });
        }
        Ok(())
    }

    /// Account for the END marker.
    pub fn add_end(&mut self) -> Result<()> {
        self.add_encoded_bytes(crate::types::END_SIZE as u64)
    }

    /// Current total encoded bytes (read-only).
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }

    /// Current element count (read-only).
    pub fn element_count(&self) -> u64 {
        self.element_count
    }

    /// The policy this accountant enforces (read-only).
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_to_bytes_conversion() {
        assert_eq!(Policy::bits_to_max_bytes(0), 0);
        assert_eq!(Policy::bits_to_max_bytes(7), 0);
        assert_eq!(Policy::bits_to_max_bytes(8), 1);
        assert_eq!(Policy::bits_to_max_bytes(13), 1); // 13 bits → 1 whole byte
        assert_eq!(Policy::bits_to_max_bytes(16), 2);
        assert_eq!(Policy::bits_to_max_bytes(2_000_000_000), 250_000_000);
    }

    #[test]
    fn accountant_rejects_tiny_limit() {
        // A limit too small for even the header should fail.
        let policy = Policy::new(7 * 8, 0, 0); // 7 bytes < 8-byte header
        assert!(SizeAccountant::new(policy).is_err());
    }

    #[test]
    fn accountant_tracks_sizes() {
        let policy = Policy::new(200 * 8, 100 * 8, 10);
        let mut acc = SizeAccountant::new(policy).unwrap();
        assert_eq!(acc.encoded_bytes(), 8); // header counted

        acc.add_encoded_bytes(5).unwrap(); // one CHAR
        acc.add_element().unwrap();
        assert_eq!(acc.encoded_bytes(), 13);
        assert_eq!(acc.element_count(), 1);
    }

    #[test]
    fn accountant_enforces_encoded_limit() {
        let policy = Policy::new(100 * 8, 100 * 8, 1000); // 100 bytes max
        let mut acc = SizeAccountant::new(policy).unwrap();
        // Header is 8 bytes. Adding 93 more would = 101, which exceeds 100.
        assert!(acc.add_encoded_bytes(93).is_err());
    }

    #[test]
    fn accountant_enforces_element_limit() {
        let policy = Policy::new(1_000_000, 1_000_000, 2);
        let mut acc = SizeAccountant::new(policy).unwrap();
        acc.add_element().unwrap();
        acc.add_element().unwrap();
        assert!(acc.add_element().is_err());
    }

    #[test]
    fn accountant_enforces_blob_limit() {
        let policy = Policy::new(1_000_000, 80, 100); // max 10 bytes per blob
        let acc = SizeAccountant::new(policy).unwrap();
        acc.check_blob_size(10).unwrap();
        assert!(acc.check_blob_size(11).is_err());
    }
}
