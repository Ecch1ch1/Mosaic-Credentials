# 🧩 Mosaic Credentials (MC v0.1)

> **Next-generation structured authentication secrets combining arbitrary Unicode scalars, raw binary BLOBs, and keystroke secrets into brute-force-proof credentials.**

[![CI](https://github.com/Ecch1ch1/Mosaic-Credentials/actions/workflows/ci.yml/badge.svg)](https://github.com/Ecch1ch1/Mosaic-Credentials/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MPL_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)](mosaic-core/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](mosaic-python/)
[![WebAssembly](https://img.shields.io/badge/WASM-Compatible-purple?logo=webassembly)](mosaic-wasm/)
[![KDF](https://img.shields.io/badge/KDF-Argon2id-brightgreen)](https://en.wikipedia.org/wiki/Argon2)
[![Test Vectors](https://img.shields.io/badge/Vectors-100%25%20Verified-success)](test-vectors/published_test_vectors.json)

---

## 📖 Overview

Traditional passwords limit users to a single string of ASCII characters, vulnerable to automated dictionary crawlers, GPU cracking rigs (Hashcat), and keystroke shoulder surfing.

**Mosaic Credentials** redefines authentication by allowing credentials to be structured sequences of:
1. **Arbitrary Unicode Scalars**: Full Unicode code points (emoji, math symbols, ancient scripts, zero-width joiners).
2. **Backspace as a Secret (`U+0008`)**: Backspaces typed in credential-entry mode are preserved as secret elements rather than visual deletions, completely confounding dictionary attacks and keystroke guessers.
3. **Arbitrary Binary BLOBs**: Files, image snippets, cryptographic seeds, audio bytes, or biometric chunks interleaved directly into the sequence.

### 🛡️ Why It Is Practically Unbruteforceable
* **Astronomical Key Space**: Adding even a 1 KB file chunk creates $256^{1024} = 2^{8192} \approx 10^{2466}$ possibilities (surpassing the atoms in the universe).
* **Constant Database Footprint**: Regardless of whether your secret is 8 characters or a 100 MB file, it is streamed into a domain-separated SHA-256 prehash and hashed with memory-hard **Argon2id**. The database **only ever stores a compact ~220-byte record**.
* **Zero Pass-the-Hash**: The server requires the raw framed secret sequence $S$ to authenticate. Possession of the stored database hash grants an attacker zero ability to log in.

---

## 🏛️ Architecture & Framing

A Mosaic Credential wire stream $S$ is strictly framed in big-endian binary format:

```text
+----------+---------------+---------------+-----+----------+
|  0x01    | Element 1     | Element 2     | ... |  0xFF    |
| (HEADER) | (CHAR / BLOB) | (CHAR / BLOB) |     |  (END)   |
+----------+---------------+---------------+-----+----------+
```

* **Header**: Magic byte `0x01` (`MC v1`).
* **CHAR Element**: Tag `0x01` || 4-byte big-endian Unicode scalar value ($0 \le U \le 0x10FFFF$, excluding surrogate codepoints).
* **BLOB Element**: Tag `0x02` || 8-byte big-endian length $L$ || $L$ raw bytes.
* **END Delimiter**: Byte `0xFF`.

### Two-Stage Cryptographic Derivation
1. **Domain-Separated Prehash**:
   $$D = \text{SHA-256}\Big(\text{"MOSAIC-CREDENTIAL/PREHASH/V1\textbackslash 0"} \parallel S\Big)$$
2. **Memory-Hard Verification**:
   $$\text{Verifier} = \text{Argon2id}\Big(\text{password}=D,\; \text{salt}=\text{CSPRNG}(16),\; m=65536\text{ KiB},\; t=3,\; p=4\Big)$$

---

## 📦 Repository Structure

| Package / Folder | Description |
| :--- | :--- |
| [`mosaic-core/`](mosaic-core/) | Core Rust crate: Types, streaming framing parser, binary encoder, validation policy, and prehash. |
| [`mosaic-auth/`](mosaic-auth/) | Authentication crate: Argon2id enrollment, constant-time verification, and PHC string encoding. |
| [`mosaic-cli/`](mosaic-cli/) | Command-line interface for enrollment, verification, inspection, and spec testing. |
| [`mosaic-python/`](mosaic-python/) | Pure Python package (`mosaic_credential`) with matching crypto, builder, and auth. |
| [`mosaic-wasm/`](mosaic-wasm/) | WebAssembly bindings compiled with `wasm-bindgen` for browser and edge runtimes. |
| [`mosaic-editor/`](mosaic-editor/) | Modern dark-mode visual builder for interactive credential composition and vector testing. |
| [`mosaic-demo-app/`](mosaic-demo-app/) | Full-stack live web application with SQLite database, registration, and login. |
| [`test-vectors/`](test-vectors/) | Published canonical test vectors verified across Rust, Python, and JavaScript. |

---

## 🚀 Quick Start

### 1. Build and Run All Tests (Rust)
```bash
cargo test --workspace
```
Runs the 95+ unit and spec-compliance integration tests.

### 2. Rust CLI
```bash
# Enroll a credential from CLI inputs:
cargo run -p mosaic-cli -- enroll --user alice --text "Pass" --backspace 3 --text "word"

# Verify a credential:
cargo run -p mosaic-cli -- verify --record '{"version":1,"kdf_type":"argon2id",...}' --text "Pass" --backspace 3 --text "word"

# Run published test vector suite:
cargo run -p mosaic-cli -- test-vectors --verify
```

### 3. Python Package
```bash
cd mosaic-python
pip install .
pytest tests/ -v
```

```python
from mosaic_credential.core import MosaicCredentialBuilder
from mosaic_credential.auth import enroll_credential, verify_credential

# Build a credential with text, backspaces, and binary data
builder = MosaicCredentialBuilder()
builder.add_text("Pass")
builder.add_backspaces(3)
builder.add_text("word")
builder.add_blob(b"\xde\xad\xbe\xef")
credential = builder.build()

# Enroll (generates Argon2id record)
record = enroll_credential(credential)

# Verify
assert verify_credential(credential, record) is True
```

### 4. Interactive Visual Builder
Open [`mosaic-editor/index.html`](mosaic-editor/index.html) in your browser or run:
```bash
python3 -m http.server 8088 --directory mosaic-editor
```
Visit `http://localhost:8088` to visually construct secrets, preview backspaces, and run live cryptographic test vectors.

### 5. Full-Stack Web App Demo (with SQLite)
```bash
cd mosaic-demo-app
python3 server.py
```
Open `http://localhost:5050` to register users, test logins, and inspect live database records.

---

## 🗄️ Database Integration

Mosaic Credentials seamlessly integrates with any database (SQLite, PostgreSQL, MongoDB, MySQL). You only need a single text/JSON column (~220 bytes):

```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    credential_record JSON NOT NULL, -- Stored Argon2id VerifierRecord (~200 bytes)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

For detailed schema examples and ORM models, see [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md).

---

## 📜 Specification & Compliance

This implementation strictly adheres to the official specification:
- [Technical Specification (v0.1)](mosaic-credential-technical-specification-en.md)
- [Published Canonical Test Vectors](test-vectors/published_test_vectors.json)

---

## 📄 License

Licensed under the **Mozilla Public License 2.0 (MPL-2.0)** ([LICENSE](LICENSE)).

* **Commercial & SaaS Use**: You are free to integrate and use this library in commercial applications, paid websites, and SaaS products.
* **Copyleft on Modifications**: Any modifications, copies, or derivative distributions of this library's source code must remain free and open source under MPL-2.0.
* **No Closed-Source Resale**: You may not sell, re-brand, or close-source this library as a standalone paid commercial product.
