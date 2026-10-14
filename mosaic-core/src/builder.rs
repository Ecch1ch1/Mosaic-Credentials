//! Credential builder for composing ordered element sequences (§4, §5, §12.3).
//!
//! The builder records CHAR and BLOB elements in the user-selected order.
//! Once finalized, no further data can be added.
//!
//! # Equivalence guarantee (§4.2)
//!
//! `add_text("Pass")` is equivalent to `add_text("Pa"); add_text("ss")` —
//! API call boundaries are not secret elements.

use crate::error::{Error, Result};
use crate::policy::{Policy, SizeAccountant};
use crate::types::{Element, BACKSPACE, BLOB_HEADER_SIZE, CHAR_ENCODED_SIZE};

/// Builds a credential by accumulating elements in order.
///
/// The builder enforces size policies incrementally. It transitions to a
/// finalized state after [`finalize()`](CredentialBuilder::finalize) and cannot
/// accept further data.
#[derive(Debug)]
pub struct CredentialBuilder {
    elements: Vec<Element>,
    accountant: SizeAccountant,
    finalized: bool,
}

impl CredentialBuilder {
    /// Create a new builder with the given size policy.
    pub fn new(policy: Policy) -> Result<Self> {
        Ok(Self {
            elements: Vec::new(),
            accountant: SizeAccountant::new(policy)?,
            finalized: false,
        })
    }

    /// Ensure the builder has not been finalized.
    fn check_not_finalized(&self) -> Result<()> {
        if self.finalized {
            return Err(Error::BuilderFinalized);
        }
        Ok(())
    }

    /// Add a single Unicode scalar value as a CHAR element.
    fn add_char(&mut self, c: char) -> Result<()> {
        self.check_not_finalized()?;
        self.accountant.add_element()?;
        self.accountant.add_encoded_bytes(CHAR_ENCODED_SIZE as u64)?;
        self.elements.push(Element::Char(c));
        Ok(())
    }

    /// Expand a text string into individual CHAR elements (§4.2).
    ///
    /// API call boundaries are not secret elements. Multiple calls with
    /// substrings produce the same credential as a single call with the
    /// full string:
    ///
    /// ```
    /// # use mosaic_core::prelude::*;
    /// let policy = Policy::default_generous();
    /// let mut b1 = CredentialBuilder::new(policy.clone()).unwrap();
    /// b1.add_text("Pass").unwrap();
    ///
    /// let mut b2 = CredentialBuilder::new(policy).unwrap();
    /// b2.add_text("Pa").unwrap();
    /// b2.add_text("ss").unwrap();
    ///
    /// assert_eq!(b1.elements(), b2.elements());
    /// ```
    ///
    /// An empty string adds no elements (§4.2).
    pub fn add_text(&mut self, text: &str) -> Result<()> {
        for c in text.chars() {
            self.add_char(c)?;
        }
        Ok(())
    }

    /// Add `count` Backspace elements — `CHAR(U+0008)` each (§5.1).
    ///
    /// This is a convenience operation. Backspace does NOT remove the
    /// preceding element; it is itself a secret element.
    pub fn add_backspace(&mut self, count: usize) -> Result<()> {
        for _ in 0..count {
            self.add_char(BACKSPACE)?;
        }
        Ok(())
    }

    /// Add a BLOB element from an in-memory byte slice (§4.4).
    ///
    /// Every byte is significant. A zero-length BLOB is valid.
    pub fn add_blob(&mut self, data: &[u8]) -> Result<()> {
        self.check_not_finalized()?;

        let payload_len = data.len() as u64;
        self.accountant.check_blob_size(payload_len)?;
        self.accountant.add_element()?;
        // BLOB encoded size = tag(1) + length(8) + payload
        let encoded_size = (BLOB_HEADER_SIZE as u64)
            .checked_add(payload_len)
            .ok_or(Error::IntegerOverflow)?;
        self.accountant.add_encoded_bytes(encoded_size)?;

        self.elements.push(Element::Blob(data.to_vec()));
        Ok(())
    }

    /// Add a BLOB element from a stream with a known length (§12.4).
    ///
    /// The BLOB length precedes its content in the canonical format, so the
    /// adapter MUST know the payload length before emitting that BLOB.
    pub fn add_blob_stream<R: std::io::Read>(
        &mut self,
        reader: &mut R,
        length_bytes: u64,
    ) -> Result<()> {
        self.check_not_finalized()?;

        self.accountant.check_blob_size(length_bytes)?;
        self.accountant.add_element()?;
        let encoded_size = (BLOB_HEADER_SIZE as u64)
            .checked_add(length_bytes)
            .ok_or(Error::IntegerOverflow)?;
        self.accountant.add_encoded_bytes(encoded_size)?;

        // Read exactly the declared number of bytes.
        // Avoid allocating solely from an untrusted length by reading in chunks.
        let mut data = Vec::new();
        let mut remaining = length_bytes;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            let n = reader.read(&mut buf[..to_read]).map_err(Error::from)?;
            if n == 0 {
                return Err(Error::LengthMismatch {
                    declared: length_bytes,
                    actual: length_bytes - remaining,
                });
            }
            data.extend_from_slice(&buf[..n]);
            remaining -= n as u64;
        }

        self.elements.push(Element::Blob(data));
        Ok(())
    }

    /// Read-only access to the accumulated elements.
    pub fn elements(&self) -> &[Element] {
        &self.elements
    }

    /// Current element count.
    pub fn element_count(&self) -> usize {
        self.elements.len()
    }

    /// Whether this builder has been finalized.
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Finalize the builder and return the elements.
    ///
    /// After finalization, the builder cannot accept further data.
    /// This is single-use (§12.3).
    pub fn finalize(mut self) -> Result<Vec<Element>> {
        self.check_not_finalized()?;
        // Account for the END marker.
        self.accountant.add_end()?;
        self.finalized = true;
        Ok(self.elements)
    }

    /// Access the underlying size accountant (read-only).
    pub fn accountant(&self) -> &SizeAccountant {
        &self.accountant
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generous() -> Policy {
        Policy::default_generous()
    }

    #[test]
    fn text_equivalence() {
        // §4.2: add_text("Pass") == add_text("Pa") + add_text("ss")
        let mut b1 = CredentialBuilder::new(generous()).unwrap();
        b1.add_text("Pass").unwrap();

        let mut b2 = CredentialBuilder::new(generous()).unwrap();
        b2.add_text("Pa").unwrap();
        b2.add_text("ss").unwrap();

        assert_eq!(b1.elements(), b2.elements());
    }

    #[test]
    fn empty_text_adds_nothing() {
        let mut b = CredentialBuilder::new(generous()).unwrap();
        b.add_text("").unwrap();
        assert_eq!(b.element_count(), 0);
    }

    #[test]
    fn backspace_is_char_u0008() {
        let mut b = CredentialBuilder::new(generous()).unwrap();
        b.add_text("Pass").unwrap();
        b.add_backspace(3).unwrap();
        b.add_text("word").unwrap();

        // §5.1: The sequence is P,a,s,s,BS,BS,BS,w,o,r,d
        let elements = b.elements();
        assert_eq!(elements.len(), 11);
        assert_eq!(elements[4], Element::Char('\u{0008}'));
        assert_eq!(elements[5], Element::Char('\u{0008}'));
        assert_eq!(elements[6], Element::Char('\u{0008}'));
    }

    #[test]
    fn backspace_differs_from_deletion() {
        // §5.1: "Pass<BS><BS><BS>word" ≠ "Pword"
        let mut b1 = CredentialBuilder::new(generous()).unwrap();
        b1.add_text("Pass").unwrap();
        b1.add_backspace(3).unwrap();
        b1.add_text("word").unwrap();

        let mut b2 = CredentialBuilder::new(generous()).unwrap();
        b2.add_text("Pword").unwrap();

        assert_ne!(b1.elements(), b2.elements());
    }

    #[test]
    fn blob_zero_length() {
        let mut b = CredentialBuilder::new(generous()).unwrap();
        b.add_blob(&[]).unwrap();
        assert_eq!(b.elements(), &[Element::Blob(vec![])]);
    }

    #[test]
    fn blob_boundaries() {
        // §4.4: BLOB(A), BLOB(B) != BLOB(A || B)
        let mut b1 = CredentialBuilder::new(generous()).unwrap();
        b1.add_blob(&[1, 2]).unwrap();
        b1.add_blob(&[3, 4]).unwrap();

        let mut b2 = CredentialBuilder::new(generous()).unwrap();
        b2.add_blob(&[1, 2, 3, 4]).unwrap();

        assert_ne!(b1.elements(), b2.elements());
    }

    #[test]
    fn char_vs_blob() {
        // §4.4: CHAR('A') != BLOB(b"A")
        let mut b1 = CredentialBuilder::new(generous()).unwrap();
        b1.add_text("A").unwrap();

        let mut b2 = CredentialBuilder::new(generous()).unwrap();
        b2.add_blob(&[0x41]).unwrap();

        assert_ne!(b1.elements(), b2.elements());
    }

    #[test]
    fn finalized_builder_rejects_data() {
        let mut b = CredentialBuilder::new(generous()).unwrap();
        b.add_text("test").unwrap();
        let _elements = b.finalize().unwrap();

        // Builder is consumed by finalize(), so we can't call add_text on it.
        // The type system enforces single-use.
    }

    #[test]
    fn order_matters() {
        // §3.1: Different orderings are different credentials.
        let mut b1 = CredentialBuilder::new(generous()).unwrap();
        b1.add_text("A").unwrap();
        b1.add_blob(&[1]).unwrap();

        let mut b2 = CredentialBuilder::new(generous()).unwrap();
        b2.add_blob(&[1]).unwrap();
        b2.add_text("A").unwrap();

        assert_ne!(b1.elements(), b2.elements());
    }

    #[test]
    fn stream_blob() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut cursor = std::io::Cursor::new(&data);

        let mut b = CredentialBuilder::new(generous()).unwrap();
        b.add_blob_stream(&mut cursor, 4).unwrap();

        assert_eq!(b.elements(), &[Element::Blob(data)]);
    }

    #[test]
    fn stream_blob_length_mismatch() {
        let data = vec![0xDE, 0xAD]; // only 2 bytes
        let mut cursor = std::io::Cursor::new(&data);

        let mut b = CredentialBuilder::new(generous()).unwrap();
        let err = b.add_blob_stream(&mut cursor, 4).unwrap_err();
        assert!(matches!(err, Error::LengthMismatch { .. }));
    }
}
