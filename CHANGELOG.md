# Changelog

All notable changes to the [Mosaic Credentials](https://github.com/Ecch1ch1/Mosaic-Credentials) project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Physical Keyfile Capsule (`.mosaic`)**:
  - Encrypted offline keyfile format (`MOSAIC01`) enabling users to store multi-modal credentials (text, backspaces, arrow keys, and exact binary BLOBs/files) on a physical USB flash drive.
  - Military-grade encryption: **AES-256-GCM** with keys derived via **PBKDF2-HMAC-SHA256 (200,000 iterations)** using the native Web Crypto API.
  - Zero external runtime dependencies: all cryptographic operations and UI drawers run natively in `<mosaic-credential-input>`.
  - Automatic file detection: dragging and dropping a `.mosaic` file prompts the user to enter their master passphrase and unlocks the credential into the input stream.
  - Algorithmic passphrase strength and entropy validator preventing trivial or low-entropy master passphrases.
- **Project Documentation**:
  - Added this canonical `CHANGELOG.md` tracking repository updates and specification milestones.

### Security & Hardening
- **CI / GitHub Actions (`.github/workflows/ci.yml`)**:
  - Enforced top-level `permissions: contents: read` to satisfy GitHub CodeQL security policies and prevent unauthorized token misuse.
- **Demo Server (`mosaic-demo-app/server.py`)**:
  - Replaced generic exception handlers that returned internal error strings with structured, safe handlers to eliminate CWE-209 / CWE-497 stack trace exposure alerts.
- **Stealth / Secret Mode Invariants**:
  - Strictly concealed physical capsule export/unlock drawers and toolbar triggers when `secret-mode` or `stealth` is active to preserve 100% plausible deniability.

---

## [0.1.1] - 2026-10-18

### Added
- **Secret / Stealth Mode (`secret-mode` / `stealth`)**:
  - Disguised input mode appearing visually as a standard masked password field for public kiosks or shoulder-surfing threat models.
  - Secret Backspace capture: hitting Backspace deletes a visible bullet on screen while recording the non-destructive scalar `U+0008` in the cryptographic sequence.
- **Quick-Clear Reset Button (`✕`)**:
  - Discrete single-click reset button inside the input container for fast, seamless credential resets without manually selecting all tokens.
- **File Provenance & Exactness Notice**:
  - Built-in UI hint advising users that exact byte-for-byte binary files are required and warning against chat app recompression (e.g., WhatsApp, Messenger).
- **CSS Shadow Parts**:
  - Exposed `part="container"`, `part="input-row"`, `part="token"`, `part="toolbar"`, `part="clear-btn"` for deep styling and white-labeling in enterprise design systems.
- **Interactive Live Demo (`docs/index.html`)**:
  - Hosted on GitHub Pages with interactive theme switcher (*Midnight Indigo*, *Neon Cyberpunk*, *Light Minimalist*).
  - Real-time cryptographic wire inspector showing MC v1 canonical byte streams and domain-separated prehashes.

### Changed
- Refactored token rendering for enhanced accessibility and responsive touch interfaces.
- Bumped workspace crates (`mosaic-credential-core`, `mosaic-credential-auth`, `mosaic-credential-cli`, `mosaic-credential-wasm`), npm package `@mosaic-credentials/elements`, and PyPI `mosaic-credential` to v0.1.1.

---

## [0.1.0] - 2026-10-14

### Added
- **Initial Public Release of Mosaic Credentials**:
  - Specification `SPECIFICATION.md` defining MC v1 Big-Endian Binary Framing (`MCRD\x00\x01\x00\x01`), Element Tags (`0x01` CHAR, `0x02` BLOB, `0xFF` END), and Domain-Separated Prehashing (`MOSAIC-CREDENTIAL/PREHASH/V1\0`).
- **Rust Core & Auth Engine**:
  - `mosaic-credential-core`: zero-allocation binary encoder, parser, streaming hasher, and policy accountant.
  - `mosaic-credential-auth`: enrollment and verification engine backed by Argon2id with memory-hard defense against offline GPU dictionary attacks.
- **Multi-Platform Ecosystem**:
  - `mosaic-credential-cli` (`mosaic`): command-line interface for credential inspection, enrollment, and verification.
  - `mosaic-credential-wasm`: WebAssembly bindings for client-side hashing and wire framing.
  - `mosaic-credential` (Python SDK): Python wrapper providing native verification bindings for Flask, FastAPI, and Django.
  - `@mosaic-credentials/elements`: drop-in Web Component (`<mosaic-credential-input>`) with rich tokens, backspaces, directional arrows, and drag-and-drop file attachment.
  - `mosaic-demo-app`: interactive full-stack Flask authentication demo showcasing real-time SQLite enrollment and login.
- **Licensing**:
  - Licensed under the Mozilla Public License 2.0 ([MPL-2.0](LICENSE)).
