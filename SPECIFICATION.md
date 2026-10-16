# Mosaic Credential
## Technical Design and Implementation Specification

Version: 0.1.0 (Release)  
Status: Reference Specification & Implementation v0.1.0  
Working name: Mosaic Credential (MC)  
Architect & Author: Ecch1ch1  
Repository: https://github.com/Ecch1ch1/Mosaic-Credentials  
License: MPL-2.0

## 1. Purpose

Mosaic Credential is a library for constructing and verifying structured authentication secrets composed of arbitrary Unicode characters and arbitrary binary components in a user-selected sequence.

A credential may contain text, images, audio, video, documents, arbitrary byte sequences, or any combination of these. Control characters, including Backspace, are legitimate secret elements rather than automatically discarded editing instructions.

The library stores a compact verifier rather than the original credential. Its storage size does not grow with the size of the original files.

This project introduces an input format, deterministic serialization, verification pipeline, and integration APIs. It does not introduce a new cryptographic primitive. “Credential” is the preferred product term; the result remains a reproducible authentication secret, not automatically a second factor or a phishing-resistant protocol.

The project name is provisional. Trademark and package-name availability have not been checked.

## 2. Normative Language

MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY describe requirements within this draft. They do not imply that this document is an established external standard.

## 3. Core Semantics

### 3.1 User-selected order

There is no prescribed arrangement of components. Users may place text and binary components in any sequence.

Once selected, that sequence is part of the secret. Verification MUST preserve order. Components MUST NOT be sorted or treated as an unordered set.

The following are different credentials:

```text
Pass[image]wo[audio]rd
Pa[image][audio]ssword
[audio]Password[image]
```

### 3.2 Exact identity

Verification uses exact serialized content, not visual or semantic similarity.

- Two visually identical images may be different credentials.
- Two recordings of the same sound are normally different inputs.
- Renaming a file does not change its binary content.
- Recompression, embedded metadata changes, or format conversion can change the credential.
- A file's embedded metadata is included because it is part of its bytes.
- Filesystem paths, filenames, modification timestamps, permissions, and externally supplied MIME types are not included automatically.

### 3.3 Scope

Version 1 supports:

- All Unicode scalar values, including control and formatting characters.
- Arbitrary byte sequences through binary components.
- User-selected interleaving and ordering.
- Streaming processing.
- Configurable size limits expressed in bits.
- Versioned, platform-independent serialization.
- Salted, computationally expensive verifier generation.

Version 1 does not support:

- Perceptual image matching or audio recognition.
- Biometric authentication.
- Timing-based keystroke authentication.
- Automatic tolerance of altered files.
- Arbitrary non-byte-aligned binary components.
- Automatic integration into unmodified third-party login forms.
- A new cipher, hash algorithm, or unaudited custom cryptographic implementation.

## 4. Data Model

A credential is an ordered sequence of elements:

```text
Credential := Element*
Element    := CHAR | BLOB
```

### 4.1 CHAR

A CHAR represents one Unicode scalar value.

Accepted values are U+0000 through U+D7FF and U+E000 through U+10FFFF. This includes NUL, Backspace, Tab, line breaks, combining characters, emoji components, and nonprinting characters.

Isolated UTF-16 surrogates are not Unicode scalar values. Text adapters MUST reject them, not silently replace them. Arbitrary malformed encodings remain representable as BLOB bytes.

A user-perceived character may contain multiple scalar values. The library preserves that exact sequence.

### 4.2 Text convenience API

`add_text()` expands its input into CHAR elements. API call boundaries are not secret elements.

These calls MUST be equivalent:

```python
builder.add_text("Pass")
```

```python
builder.add_text("Pa")
builder.add_text("ss")
```

Typing and pasting the same scalar-value sequence MUST produce the same credential, unless explicit additional secret elements are inserted.

An empty text string adds no elements.

### 4.3 No implicit transformations

The core MUST NOT perform:

- Whitespace trimming.
- Case folding.
- Unicode NFC, NFD, NFKC, or NFKD normalization.
- CRLF/LF conversion.
- Control-character removal.
- NUL termination or truncation.
- Invalid-character replacement.

Any future normalization profile MUST have a separate profile identifier and explicit semantics.

### 4.4 BLOB

A BLOB represents one byte sequence, typically a file. Every byte is significant.

A BLOB MAY contain any content regardless of extension or MIME type. The authentication core MUST NOT decode, decompress, play, execute, or semantically inspect it.

Component boundaries matter:

```text
BLOB(A), BLOB(B) != BLOB(A || B)
CHAR("A") != BLOB(b"A")
```

A zero-length BLOB is valid and differs from no BLOB.

## 5. Backspace and Input Editing

### 5.1 Required credential behavior

In the credential-entry profile, Backspace is represented as CHAR(U+0008). It MUST NOT automatically remove the preceding credential element.

Example:

```text
Text("Pass")
Backspace
Backspace
Backspace
Text("word")
```

The scalar sequence is:

```text
U+0050 U+0061 U+0073 U+0073
U+0008 U+0008 U+0008
U+0077 U+006F U+0072 U+0064
```

It is different from `Text("Pword")`.

`add_backspace(count=3)` is a convenience operation that adds three CHAR(U+0008) elements. It is not a third serialized element type.

### 5.2 Display versus authenticated data

An editor MAY show:

```text
Structural view: Pass<BS><BS><BS>word
Preview:         Pword
```

The preview is not the authenticated representation. U+0008 does not itself remove preceding characters from an in-memory string. The optional preview renderer explicitly interprets it.

The structural view MUST distinguish actual control characters from ordinary text that merely resembles a token label.

Version 1 does not define terminal emulation, cursor motion, or graphical deletion of arbitrary Unicode grapheme clusters. A preview MUST document its rendering rules and MUST NOT affect serialization.

### 5.3 Correcting entry errors

Because Backspace inserts a secret element, the editor MUST provide separate controls such as:

- Remove the last element.
- Delete the selected element.
- Clear the entire input.

These are editor operations and are not added to the credential.

### 5.4 Keyboard adapters

The core receives scalar values and BLOBs, not raw keyboard events.

A web or native adapter MUST deliberately map the Backspace action to U+0008 in credential-entry mode. A normal password input's final value is insufficient to retain this history.

Adapters MUST test physical keyboards, mobile keyboards, IME composition, clipboard input, repeated key events, and accessibility tools. They MUST avoid double-counting a single edit through overlapping event handlers.

Modifier keys such as Shift are not automatically credential elements. The Delete key is not automatically U+007F. Additional mappings require explicit specification.

### 5.5 Secret / Stealth Mode profile

To preserve shoulder-surfing resistance and visual compatibility with legacy password fields, an adapter MAY implement a Secret / Stealth Mode (e.g., `<mosaic-credential-input secret-mode>`):

1. **Visual Presentation**:
   - Renders as a standard password field displaying bullet characters (`••••••`).
   - Hides token lists, preview badges, drag-and-drop dropzones, and editing toolbars.
   - To an onlooker or screen-recording software, the interaction appears identical to entering a traditional password.

2. **Backspace Retention with Masking**:
   - Every physical or virtual Backspace keypress appends `CHAR(U+0008)` to the canonical credential stream.
   - Visually, the adapter deletes one bullet character from the display. This delivers standard visual feedback and misleads shoulder-surfers without mutating the canonical stream.

3. **Reset Operation**:
   - An explicit "Select-All" (`Ctrl+A` or `Cmd+A`) followed by `Backspace` or `Delete` MUST clear and reset the entire builder to empty.
   - This provides the user with an intuitive way to start over without committing editing noise into the credential.

4. **Private Use Area (PUA) Key Mappings**:
   - Navigation and control keys that do not have standard printable Unicode representations are mapped into Unicode Plane 0 Private Use Area (`U+E000`–`U+F8FF`):
     - `ArrowUp`: `CHAR(U+E010)`
     - `ArrowDown`: `CHAR(U+E011)`
     - `ArrowLeft`: `CHAR(U+E012)`
     - `ArrowRight`: `CHAR(U+E013)`
     - Function keys `F1` through `F12`: `CHAR(U+E021)` through `CHAR(U+E02C)`
   - Modifier keys (Shift, Ctrl, Alt, Meta) MUST NOT be captured as independent elements.

5. **Portability Invariant**:
   - Secret Mode is strictly **Portable** (never OS-bound). The generated canonical stream and verifier MUST evaluate identically across Linux, Windows, macOS, Android, and iOS.

## 6. Canonical Binary Format: MC v1

This is a proposed project format, not an existing standard.

All multibyte integers are unsigned big-endian. Payload lengths count bytes, not characters or bits.

### 6.1 Structure

```text
HEADER || ELEMENT* || END
```

### 6.2 Header

| Field | Encoding | Value |
|---|---|---|
| magic | 4 bytes | ASCII `MCRD` |
| version | u16 | 1 |
| profile | u16 | 1 |

Profile 1 defines the exact-character and opaque-binary semantics in this document.

### 6.3 CHAR encoding

```text
tag:       u8  = 0x01
codepoint: u32 = Unicode scalar value
```

Each CHAR occupies five serialized bytes. This intentionally simple reference format favors unambiguous implementation over text compactness.

Example, `A`:

```text
01 00 00 00 41
```

Example, Backspace:

```text
01 00 00 00 08
```

Invalid scalar values MUST be rejected.

### 6.4 BLOB encoding

```text
tag:          u8  = 0x02
length_bytes: u64
content:      exactly length_bytes bytes
```

The advertised length MUST equal the actual payload length. Read-buffer and network-packet boundaries MUST NOT affect serialization.

### 6.5 END encoding

```text
tag: u8 = 0xFF
```

END is mandatory. Trailing bytes after END are invalid. Unknown tags, truncated fields, unsupported versions, and unsupported profiles MUST be rejected.

### 6.6 Boundary safety

Explicit tags and lengths distinguish text from BLOBs and distinguish separate BLOBs from their concatenation. A parser MUST consume exactly the declared number of BLOB bytes; tag-like bytes inside a BLOB have no structural meaning.

## 7. Size Policies

### 7.1 Configuration authority

The integrating application chooses the policy. A person authenticating MUST NOT be able to raise server limits by supplying their own policy.

Suggested configuration fields:

```text
max_encoded_bits
max_blob_bits
max_elements
```

`max_encoded_bits` applies to the complete canonical serialization, including header, tags, length fields, and END. The prehash domain prefix is not counted.

`max_blob_bits` applies separately to each BLOB payload. `max_elements` counts CHAR and BLOB elements, including empty BLOBs.

A UI MAY additionally report payload-only size, but MUST label it separately.

### 7.2 Units

| Configured size | Bits |
|---|---:|
| 19 MB | 152,000,000 |
| 250 MB | 2,000,000,000 |
| 19 MiB | 159,383,552 |
| 250 MiB | 2,097,152,000 |

MB means 1,000,000 bytes. MiB means 1,048,576 bytes.

Because v1 serialization is byte-aligned, an odd bit limit accepts only complete bytes that fit within it. A limit of 13 bits cannot accommodate two bytes.

The serialized format adds overhead, so a 250 MB source file does not fit within a 250 MB total encoded limit.

### 7.3 Enforcement

The implementation MUST:

- Count sizes incrementally using checked arithmetic.
- Reject a size violation without producing a usable verifier.
- Never silently truncate input.
- Avoid allocating memory solely from an untrusted length field.
- Detect mismatches between advertised and observed lengths.
- Bound element count independently of byte count.

The credential-size limit and Argon2 memory cost are independent settings.

### 7.4 Existing credentials

Applications SHOULD distinguish enrollment policy from verification policy. Reducing a size limit can lock out existing credentials. Policy migrations MUST account for them explicitly.

## 8. Cryptographic Pipeline

### 8.1 Algorithm selection

The proposed pipeline uses:

1. Canonical streaming serialization.
2. Domain-separated SHA-256 prehashing.
3. Argon2id with a fresh random salt.

SHA-256 compresses the potentially large stream. Argon2id makes offline candidate testing expensive. Fast hashing alone is not sufficient for human-influenced authentication secrets. [S1]

ChaCha20 is a stream cipher, and ChaCha20-Poly1305 is authenticated encryption. Neither is a replacement for this verifier derivation. They may be relevant to an independently designed encrypted-export feature. [S2]

### 8.2 Exact construction

```text
S = canonical_encode(credential)

PREFIX = ASCII("MOSAIC-CREDENTIAL/PREHASH/V1") || 0x00

D = SHA-256(PREFIX || S)

V = Argon2id(
    password = D,
    salt = fresh_random_salt,
    parameters = configured_parameters
)
```

`D` is the raw 32-byte digest, not its hexadecimal string.

`S` MUST be streamed where practical rather than assembled as one large allocation. `D` MUST NOT be persisted or logged.

The composition is a proposed project design and requires independent review before production security claims.

### 8.3 Proposed default parameters

```text
Argon2 variant:       Argon2id
Argon2 version:       19
memory_cost_kib:      65536
iterations:          3
parallelism:         1
salt_length_bytes:   16
output_length_bytes: 32
```

These are project starting values, not universal optimums. Deployments MUST benchmark expected hardware and concurrency.

OWASP lists an Argon2id minimum configuration of 19 MiB memory, two iterations, and parallelism one, and discusses balancing work factor against availability. [S1]

The salt MUST come from an operating-system-backed cryptographically secure random source. Failure to obtain randomness MUST abort enrollment.

### 8.4 Fail-Closed Resource Limits and Parameter Validation

To defend verification nodes against algorithmic complexity attacks, denial-of-service, and parameter-downgrade attacks, implementations MUST enforce a fail-closed resource guard during verification:

1. **Mandatory Explicit Parameters**:
   - The PHC string stored in the verifier record MUST explicitly specify the parameters $m$ (memory cost in KiB), $t$ (time iterations), and $p$ (parallelism).
   - If any parameter is omitted, non-numeric, or malformed, verification MUST fail closed immediately (`INVALID_VERIFIER`). Implementations MUST NOT fall back to permissive or silent default values.

2. **Reference Resource Guard Bounds**:
   The reference implementation enforces the following limits:
   - Memory cost $m$: $19\,456 \le m \le 1\,048\,576\text{ KiB}$ ($19\text{ MiB}$ OWASP minimum to $1\text{ GiB}$ DoS ceiling).
   - Time cost $t$: $1 \le t \le 10$ iterations.
   - Parallelism $p$: $1 \le p \le 4$ lanes.
   - Salt length: $\ge 16$ bytes.
   - Hash output length: $\ge 32$ bytes.

3. **Rejection Behavior**:
   - Any stored verifier requiring resources exceeding these bounds MUST be rejected immediately without evaluating Argon2id (`RESOURCE_POLICY_REJECTED`).

### 8.5 Security interpretation

A large input does not automatically provide equally large cryptographic strength. The SHA-256 prehash has a fixed 256-bit output space. Input length, hash output size, collision resistance, and practical guessing resistance are different quantities.

The security of a selected credential depends on the unknown content and its predictability. File secrecy and independent randomness can matter much more than file size.

The design MUST remain meaningful when the attacker knows the specification, source code, serialization, and verification algorithms.

## 9. Verifier Storage

Example logical record:

```json
{
  "format": "mosaic-credential",
  "format_version": 1,
  "profile": 1,
  "prehash": "sha256-domain-v1",
  "verifier": "$argon2id$v=19$m=65536,t=3,p=1$..."
}
```

The Argon2 PHC string carries salt, parameters, and derived output. Records MUST be validated against supported identifiers and resource bounds before use.

Do not store:

- Original text or files.
- Prehash D.
- Component ordering or component-type inventories.
- File previews or names by default.
- Actual credential size unless independently justified.

Record size is independent of original payload size, apart from ordinary identifier and parameter representation.

## 10. Enrollment and Verification

### 10.1 Enrollment

1. Load application-controlled policy.
2. Build the ordered credential.
3. Validate structure and limits incrementally.
4. Stream canonical serialization into SHA-256 with the domain prefix.
5. Generate a fresh salt.
6. Derive the Argon2id verifier.
7. Persist only the versioned verifier record.
8. Release transient sensitive data as far as the runtime permits.

An application SHOULD require a repeated entry or equivalent reproducibility check before committing enrollment.

### 10.2 Verification

1. Load and validate the stored record.
2. Select its exact format/profile/prehash interpretation.
3. Build and validate the candidate credential.
4. Recompute D.
5. Call the vetted Argon2 verification API with the stored record.
6. Return a generic authentication result externally.
7. On success, upgrade approved cryptographic parameters if needed.

Do not generate a new salt and compare unrelated enrollment outputs. Verification uses the salt and parameters in the stored record. [S1]

### 10.3 Migration

Argon2 work factors MAY be upgraded after successful authentication. A change to credential semantics or serialization requires a new version/profile and explicit migration behavior.

Unsupported versions MUST fail closed; the implementation MUST NOT guess a compatible interpretation.

## 11. Deployment Modes

### 11.1 Local processing

```text
Editor -> local core -> local verifier
```

Original components remain on the local device, subject to that device's security.

### 11.2 Full-input server processing

```text
Client -> TLS -> bounded server parser -> prehash -> Argon2id
```

Advantages:

- Server can validate the original structure and input limits.
- One authoritative verifier implementation.

Trade-offs:

- Every authentication may upload large data.
- The server receives potentially sensitive file contents.
- Upload bandwidth, timeouts, and concurrent work require strict limits.

### 11.3 Client-side prehashing

```text
Client: credential -> D
Server: D -> Argon2id verification
```

Advantages:

- Small authentication request.
- Server does not receive original files.

Limitations:

- Server cannot verify original credential size or composition from D.
- D is a reusable credential equivalent if accepted directly by the server.
- Theft of D permits replay without the original components.
- TLS remains required.
- A malicious client script may capture the secret before hashing.

This is not a challenge-response, PAKE, or phishing-resistant protocol. Such a protocol requires a separate design and review.

Deployments MUST configure accepted authentication modes explicitly and MUST NOT accidentally treat arbitrary prehash bytes as a validated full-input credential.

## 12. Language and Implementation Architecture

### 12.1 Reference workspace layout

The reference implementation provides the following ecosystem components:

```text
mosaic-core       Rust core library: data model, parser, canonical streaming encoder, limits, prehash
mosaic-auth       Rust auth library: enrollment, Argon2id verifier derivation, fail-closed resource guard
mosaic-python     Python package (mosaic_credential): pure reference implementation and test runner
mosaic-elements   Standard Web Component (<mosaic-credential-input>) with Visual and Secret Modes
mosaic-demo-app   Full-stack interactive demonstration application (FastAPI + SQLite + Presets)
mosaic-cli        CLI tool for local enrollment, verification, and diagnostics
mosaic-wasm       Browser WebAssembly bindings (Rust/wasm-bindgen)
test-vectors      Published canonical JSON test vectors for cross-language verification
```

Rust serves as the high-assurance core for native programs and WebAssembly. PyO3 supports Rust-based Python extension modules, while wasm-bindgen provides Rust/WebAssembly-to-JavaScript integration. [S3][S4]

### 12.2 Multi-Language and UI Ecosystem

- **Python (`mosaic-python`)**: Implements both the complete reference specification in Python for backend integration and serves as the runner for automated cross-validation against the canonical test vectors.
- **Web Components (`mosaic-elements`)**: Implements the zero-dependency `<mosaic-credential-input>` custom element supporting visual composition, drag-and-drop, Secret/Stealth Mode, and direct DOM event dispatching.
- **Demo Application (`mosaic-demo-app`)**: A live full-stack demonstration with SQLite inspection, interactive KDF cost parameter configuration, and instant credential presets.

### 12.3 Illustrative API

The following is proposed API syntax, not an existing package:

```python
policy = Policy(
    max_encoded_bits=2_000_000_000,
    max_blob_bits=2_000_000_000,
    max_elements=100_000,
)

builder = CredentialBuilder(policy)
builder.add_text("Pass")
builder.add_backspace(count=3)
builder.add_file(cat_stream, length_bytes=cat_size)
builder.add_text("word")
builder.add_file(audio_stream, length_bytes=audio_size)

record = register(builder, auth_parameters)
```

Verification uses a newly constructed candidate:

```python
result = verify(candidate_builder, stored_record)
```

Builder finalization is single-use. A finalized or failed builder cannot accept further data. Pending errors MUST prevent verifier generation.

### 12.4 Large-file API

The BLOB length precedes its content in the canonical format. Therefore the adapter MUST know the payload length before emitting that BLOB.

For unknown-length streams, an adapter must safely spool or otherwise establish the length before canonical emission. Version 1 does not define an alternative chunked BLOB wire encoding.

A fully buffered UI builder is optional. The core MUST also support incremental emission, where earlier elements cannot be edited without restarting hashing or explicitly retaining sufficient source data.

## 13. Resource and Operational Security

### 13.1 Streaming

- Use bounded read buffers.
- Check advertised lengths against actual data.
- Detect early EOF and excess bytes within the component boundary.
- Do not suppress I/O errors.
- Avoid relying on file extensions or names for security.
- Ensure a changing file cannot produce a silently accepted partial read.

Where a stable snapshot cannot be guaranteed, enrollment SHOULD include confirmation using the same intended source bytes.

### 13.2 Opaque file handling

The core MUST NOT decode images, extract archives, render documents, or execute files. Preview generation belongs in a separate, appropriately isolated layer and MUST NOT change the bytes authenticated by the core.

### 13.3 Availability

Applications MUST bound:

- Request size and upload duration.
- Concurrent uploads.
- Concurrent Argon2 operations.
- Failed-attempt frequency.
- Accepted verifier parameters.

Expensive password hashing must be tuned with denial-of-service and concurrency costs in mind. [S1]

### 13.4 Sensitive data handling

- Never log credentials, BLOB contents, or D.
- Avoid automatic form persistence and analytics capture.
- Avoid plaintext temporary exports.
- Minimize memory copies.
- Use explicit zeroization where feasible without claiming complete removal from all runtime, OS, browser, or swap copies.
- Separate diagnostic error codes from public authentication responses.

Suggested internal errors:

```text
INVALID_SCALAR
UNSUPPORTED_VERSION
UNSUPPORTED_PROFILE
INVALID_TAG
TRUNCATED_INPUT
TRAILING_DATA
LENGTH_MISMATCH
LIMIT_EXCEEDED
INTEGER_OVERFLOW
IO_ERROR
RANDOMNESS_FAILURE
INVALID_VERIFIER
RESOURCE_POLICY_REJECTED
BUILDER_FINALIZED
```

## 14. Threat Model

### 14.1 Intended protections

The design aims to support high-uncertainty secrets without requiring users to memorize every byte, while storing only salted verifiers.

An attacker with only the verifier database must test candidate credentials through the prehash and Argon2id pipeline, assuming no implementation flaw or independent account recovery bypass.

### 14.2 Non-guarantees

The format alone does not prevent:

- Weak user choices.
- Credential capture on a compromised endpoint.
- Theft of all required files.
- Replay of an accepted client prehash.
- Phishing.
- Insecure account recovery.
- Malicious browser-delivered code.

Unknown structure can add uncertainty, but the design MUST NOT depend on keeping its algorithms secret. Large permitted input space is not proof that a user's actual selection is unpredictable.

## 15. Recovery and Backup

Verifiers do not reconstruct original credentials. Applications MUST define recovery separately.

Possible recovery mechanisms include one-time recovery codes, another independent authenticator, or a controlled reset process. Recovery is an alternate account-access path and belongs in the threat model.

Exact-file credentials require exact-byte backups. A re-saved image or a newly recorded sound is not a substitute for the original file.

Encrypted credential export is outside v1. If added, it requires a separately reviewed format, key-management design, authenticated encryption, and nonce handling. ChaCha20-Poly1305 is potentially relevant to that separate feature. [S2]

## 16. Test Plan

### 16.1 Required equivalence tests

- One `add_text("Pass")` call versus multiple calls producing the same scalar sequence.
- The same BLOB read using different buffer sizes.
- Identical bytes under different file names.
- Matching results across Rust, Python bindings, and WASM.

### 16.2 Required difference tests

- Different component order.
- Different Backspace count.
- CHAR versus a BLOB containing equivalent display bytes.
- Separate BLOBs versus one concatenated BLOB.
- Empty BLOB versus absent BLOB.
- Modified file content.
- Original Unicode sequence versus a normalized alternative.
- Literal token-label text versus a control-character element.

These are verification expectations for test cases, not a claim that mathematical hash collisions are impossible.

### 16.3 Boundary and parser tests

- NUL and control characters.
- Maximum Unicode scalar value.
- Isolated surrogate rejection.
- Exact limits and one-byte overflow.
- Declared-length overflow and mismatch.
- Truncated header, CHAR, and BLOB.
- Missing END and trailing data.
- Unknown version, profile, and tag.
- Large numbers of empty BLOBs.
- Interrupted reads.
- Hostile verifier cost parameters.

The parser SHOULD undergo fuzzing and property-based tests.

### 16.4 Published test vectors

Each vector MUST specify:

```text
Logical element list
Canonical serialization in hexadecimal
Domain-separated SHA-256 prehash
Fixed test salt
Argon2id parameters
Expected verifier output
```

Fixed salts are for tests only. Production enrollment uses fresh random salts.

### 16.5 Performance tests

Measure peak memory, sustained read throughput, prehash time, Argon2 time, concurrent authentication behavior, cancellation, and 19 MB / 250 MB scale inputs.

Large-payload tests MUST verify bounded working memory rather than only successful completion.

## 17. Implementation Milestones

- [x] **1. Freeze data model and Backspace semantics** — Completed in v0.1.0.
- [x] **2. Implement canonical serializer, parser, and size accounting** — Implemented in `mosaic-core`.
- [x] **3. Publish test vectors and cross-language tests** — Published in `test-vectors/published_test_vectors.json`.
- [x] **4. Implement streaming prehash** — Implemented in `mosaic-core` with domain separation.
- [x] **5. Integrate a maintained Argon2id implementation** — Implemented in `mosaic-auth` and `mosaic-python`.
- [x] **6. Implement verifier record validation and fail-closed resource guard** — Implemented in `mosaic-auth` and `mosaic-python`.
- [x] **7. Build a CLI** — Standalone binary in `mosaic-cli` and `python3 -m mosaic_credential.cli`.
- [x] **8. Add Python reference implementation** — Packaged in `mosaic-python` with 100% test passing.
- [x] **9. Add standard Web Component and demo application** — Shipped `<mosaic-credential-input>` with Secret Mode in `mosaic-elements` and interactive demo in `mosaic-demo-app`.
- [x] **10. Perform fuzzing and boundary testing** — Panic-freedom parser fuzz tests running in CI across 1,600+ random inputs; independent third-party security review welcomed.

## 18. Release Acceptance Criteria

A v1 release requires:

- Deterministic canonical encoding across supported targets.
- No silent text or binary transformations.
- Correct preservation of Backspace and other control characters.
- Strict component ordering and boundaries.
- Correct limit enforcement without truncation.
- Streaming large-input processing.
- No persistence of source credentials or prehash D.
- Safe verifier-parameter bounds.
- Cross-platform test-vector agreement.
- Clearly documented deployment and recovery limitations.

The project's principal contribution is a consistent, usable structured-secret format with compact verifier storage. It must not claim that megabyte size alone guarantees security or that the design has been audited before an audit occurs.

## 19. External Technical Sources

[S1] OWASP Password Storage Cheat Sheet  
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

[S2] RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols  
https://www.rfc-editor.org/rfc/rfc8439

[S3] PyO3 — Rust bindings for the Python interpreter  
https://github.com/pyo3/pyo3

[S4] The wasm-bindgen Guide  
https://wasm-bindgen.github.io/wasm-bindgen/

External sources support the selected building blocks. They do not endorse or audit the proposed Mosaic Credential format or its composition.
