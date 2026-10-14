//! WebAssembly bindings for Mosaic Credential (§12.1).
//!
//! Exposes the core data model, canonical serialization, parser, and prehash
//! to JavaScript and TypeScript in browsers and WebAssembly runtimes.

use wasm_bindgen::prelude::*;

use mosaic_core::builder::CredentialBuilder;
use mosaic_core::encoder::encode;
use mosaic_core::parser::parse;
use mosaic_core::policy::Policy;
use mosaic_core::prehash::streaming_prehash;
use mosaic_core::types::Element;
use mosaic_auth::test_vectors::get_published_vectors;


#[wasm_bindgen]
pub struct WasmCredentialBuilder {
    builder: Option<CredentialBuilder>,
    elements: Vec<Element>,
}

#[wasm_bindgen]
impl WasmCredentialBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(max_encoded_bits: u64, max_blob_bits: u64, max_elements: u64) -> Result<WasmCredentialBuilder, JsValue> {
        let policy = Policy::new(max_encoded_bits, max_blob_bits, max_elements);
        let builder = CredentialBuilder::new(policy).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(Self {
            builder: Some(builder),
            elements: Vec::new(),
        })
    }

    #[wasm_bindgen]
    pub fn default_generous() -> Result<WasmCredentialBuilder, JsValue> {
        let policy = Policy::default_generous();
        let builder = CredentialBuilder::new(policy).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(Self {
            builder: Some(builder),
            elements: Vec::new(),
        })
    }

    #[wasm_bindgen]
    pub fn add_text(&mut self, text: &str) -> Result<(), JsValue> {
        let builder = self.builder.as_mut().ok_or_else(|| JsValue::from_str("builder finalized"))?;
        builder.add_text(text).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn add_backspace(&mut self, count: usize) -> Result<(), JsValue> {
        let builder = self.builder.as_mut().ok_or_else(|| JsValue::from_str("builder finalized"))?;
        builder.add_backspace(count).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn add_blob(&mut self, data: &[u8]) -> Result<(), JsValue> {
        let builder = self.builder.as_mut().ok_or_else(|| JsValue::from_str("builder finalized"))?;
        builder.add_blob(data).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn finalize(&mut self) -> Result<usize, JsValue> {
        let builder = self.builder.take().ok_or_else(|| JsValue::from_str("builder already finalized"))?;
        let elements = builder.finalize().map_err(|e| JsValue::from_str(&e.to_string()))?;
        let count = elements.len();
        self.elements = elements;
        Ok(count)
    }

    #[wasm_bindgen]
    pub fn canonical_hex(&self) -> String {
        let bytes = encode(&self.elements);
        hex::encode(bytes)
    }

    #[wasm_bindgen]
    pub fn prehash_hex(&self) -> String {
        let digest = streaming_prehash(&self.elements);
        hex::encode(digest)
    }

    #[wasm_bindgen]
    pub fn element_count(&self) -> usize {
        self.elements.len()
    }
}

/// Compute the domain-separated SHA-256 prehash hex for a hex-encoded canonical sequence.
#[wasm_bindgen]
pub fn prehash_from_canonical_hex(canonical_hex: &str) -> Result<String, JsValue> {
    let bytes = hex::decode(canonical_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let elements = parse(&bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let digest = streaming_prehash(&elements);
    Ok(hex::encode(digest))
}

/// Parse and validate canonical hex, returning element count or error.
#[wasm_bindgen]
pub fn validate_canonical_hex(canonical_hex: &str) -> Result<usize, JsValue> {
    let bytes = hex::decode(canonical_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let elements = parse(&bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(elements.len())
}

/// Retrieve the published test vectors as JSON string (§16.4).
#[wasm_bindgen]
pub fn get_published_vectors_json() -> String {
    let vectors = get_published_vectors();
    serde_json::to_string_pretty(&vectors).unwrap_or_else(|_| "[]".to_string())
}
