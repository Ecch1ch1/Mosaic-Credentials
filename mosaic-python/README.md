# mosaic-credential (Python)

Python bindings and reference implementation for **Mosaic Credential v1** (`mosaic-core` / `mosaic-auth`).

Conforms strictly to the **Mosaic Credential Technical Specification v0.1**.

## Features

- **Structured Secret Composition**: Interleave arbitrary Unicode text (with exact scalar preservation) and arbitrary binary files (BLOBs).
- **Exact Backspace Semantics (§5.1)**: Backspace is represented as `CHAR(U+0008)` as a deliberate secret element rather than automatically discarding preceding input.
- **Canonical MC v1 Streaming Binary Serialization (§6)**.
- **Domain-Separated SHA-256 Prehashing (§8.2)**.
- **Argon2id Verifier Derivation (§8.3)** with compact JSON verifier storage (`VerifierRecord`).
- **Enforces Size Policies (§7)**: Limits on total encoded bits, maximum blob bits, and maximum element counts.
- **Cross-Platform Test Vector Compatibility (§16.4)**: Verified 100% against published test vectors matching Rust and WebAssembly implementations.

## Installation

```bash
pip install mosaic-credential
```

## Quickstart API (§12.3)

```python
from mosaic_credential import CredentialBuilder, Policy, AuthParams, enroll, verify, VerifyResult

# 1. Define application size policy
policy = Policy(
    max_encoded_bits=2_000_000_000,
    max_blob_bits=2_000_000_000,
    max_elements=100_000,
)

# 2. Build the credential
builder = CredentialBuilder(policy)
builder.add_text("Pass")
builder.add_backspace(count=3)
builder.add_blob(b"\x00\x01\x02\x03\x04")
builder.add_text("word")

credential = builder.finalize()

# 3. Enroll (produces compact JSON verifier record)
record = enroll(credential, AuthParams.default())
record_json = record.to_json()
print("Stored record:\n", record_json)

# 4. Verify candidate
candidate_builder = CredentialBuilder(policy)
candidate_builder.add_text("Pass")
candidate_builder.add_backspace(count=3)
candidate_builder.add_blob(b"\x00\x01\x02\x03\x04")
candidate_builder.add_text("word")

result = verify(candidate_builder.finalize(), record)
assert result == VerifyResult.OK
```

## Running Tests

```bash
pytest tests/ -v
```
