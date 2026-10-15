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

### 🛡️ Security Model & Invariants

* **Strict Avalanche Effect on Arbitrary Streams**: A credential can incorporate arbitrary input data—from short mnemonics to multi-megabyte binary assets. Through SHA-256's strict avalanche criterion, changing even a single bit in a 50 MB file, modifying an image's EXIF metadata, or swapping the position of an arrow key completely scrambles the 256-bit prehash $D$ ($2^{256} > 1.15 \times 10^{77}$ states). Authentication does not invert the hash; it only requires that the identical sequence produces the matching $D$.
* **Hidden Composition Multiplier**: Unlike traditional passwords where attackers know they are cracking an alphanumeric string, the stored Argon2id verifier reveals **zero information about the credential's structural composition**. The database contains no indicators of element counts, types, non-printable control keys, or binary BLOBs. An attacker cannot run conventional dictionary rules—they must guess the entire multi-dimensional composition.
* **Zero Pass-the-Hash**: The server requires the candidate secret sequence $S$ at authentication time to recompute $D$. Possession of the stored database verifier grants an attacker zero ability to authenticate.
* **Constant Database Footprint**: Regardless of whether a secret is 8 characters or a 100 MB file, it streams into a fixed 32-byte domain-separated prehash and is hashed with memory-hard **Argon2id**. The database **only ever stores a compact ~220-byte PHC record**.

---

## 🏛️ Architecture & Framing

A Mosaic Credential wire stream $S$ is strictly framed in big-endian binary format (§6.2):

```text
+-----------------------------------+---------------+---------------+-----+----------+
| 0x4D 0x43 0x52 0x44  0x0001 0x0001| Element 1     | Element 2     | ... |  0xFF    |
|   MAGIC ("MCRD")     VER=1  PROF=1| (CHAR / BLOB) | (CHAR / BLOB) |     |  (END)   |
+-----------------------------------+---------------+---------------+-----+----------+
```

* **Header (8 bytes)**: Magic ASCII `MCRD` (`0x4D435244`) || Version `0x0001` (u16 BE) || Profile `0x0001` (u16 BE).
* **CHAR Element**: Tag `0x01` || 4-byte big-endian Unicode scalar value ($0 \le U \le 0x10FFFF$, excluding surrogate codepoints).
* **BLOB Element**: Tag `0x02` || 8-byte big-endian length $L$ || $L$ raw bytes.
* **END Delimiter**: Byte `0xFF`.

### Two-Stage Cryptographic Derivation
1. **Domain-Separated Prehash**:
   $$D = \text{SHA-256}\Big(\text{"MOSAIC-CREDENTIAL/PREHASH/V1"} \parallel \text{0x00} \parallel S\Big)$$
2. **Memory-Hard Verification**:
   $$\text{Verifier} = \text{Argon2id}\Big(\text{password}=D, \text{salt}=\text{CSPRNG}(16), m=65536\text{ KiB}, t=3, p=1\Big)$$

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

## ⚡ Framework Integration Recipes

Ready-to-use, copy-pasteable 1-minute integration guides for your frontend and backend stack:

* **React / Next.js**: [Reusable TypeScript Component & Form Handler](FRAMEWORK_RECIPES.md#2-react--nextjs-typescript)
* **Vanilla HTML + CSS**: [Single Script Drop-in](FRAMEWORK_RECIPES.md#1-vanilla-html--css)
* **Python (FastAPI)**: [Pydantic Models & Async Endpoints](FRAMEWORK_RECIPES.md#3-fastapi)
* **Python (Flask)**: [Standard 5-Line Verification Route](FRAMEWORK_RECIPES.md#4-flask)
* **Rust (Axum)**: [High-Performance Async Route Handler](FRAMEWORK_RECIPES.md#5-axum-rust)
* **Rust (Actix-Web)**: [Standard Actix JSON Handler](FRAMEWORK_RECIPES.md#6-actix-web-rust)

See [FRAMEWORK_RECIPES.md](FRAMEWORK_RECIPES.md) for full code examples.

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

## 🎬 Conception & Authorship

> *"Like directing a movie — the vision, creative architecture, and core ideas are human; the code was pair-programmed with AI."*

* **Conceived, Architected & Directed by**: [Ecch1ch1](https://github.com/Ecch1ch1)
  * Originated the core paradigm: multi-modal secrets, backspace-as-secret preservation, portable vs. OS-bound hardware modes, and developer drop-in ergonomics.
* **Engineered via AI Pair-Programming**:
  * Implementation pair-programmed with Google DeepMind Antigravity, rigorously audited against RFC-style test vectors, memory zeroization, and cross-platform verification.

---

## 📄 License

Licensed under the **Mozilla Public License 2.0 (MPL-2.0)** ([LICENSE](LICENSE)).

* **Commercial & SaaS Use**: You are free to integrate and use this library in commercial applications, paid websites, and SaaS products.
* **Copyleft on Modifications**: Any modifications, copies, or derivative distributions of this library's source code must remain free and open source under MPL-2.0.
* **No Closed-Source Resale**: You may not sell, re-brand, or close-source this library as a standalone paid commercial product.
