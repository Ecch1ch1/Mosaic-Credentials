# Mosaic Credential — Website & Database Integration Guide

This guide explains how to integrate **Mosaic Credential (MC)** into websites, web applications, and backend databases.

---

## 1. Storage Size & Database Architecture

### A. How Much Storage Does a 100 MB Credential Take?
**~160 to 200 bytes per user.**

No matter how large the credential is (even 100 MB or 1 GB of combined text and files), the storage size **never grows**. The pipeline streams the data into a fixed 32-byte SHA-256 prehash digest ($D$), which Argon2id turns into a standard compact PHC string.

### B. What Gets Stored in the Database?
You store **only** the `VerifierRecord` JSON object:

```json
{
  "format": "mosaic-credential",
  "format_version": 1,
  "profile": 1,
  "prehash": "sha256-domain-v1",
  "verifier": "$argon2id$v=19$m=65536,t=3,p=1$dGVzdHNhbHR...$GTUU0fhDSX..."
}
```

> [!CAUTION]
> **What You MUST NEVER Store (§9, §13.4):**
> - Never store original text or file contents.
> - Never store the intermediate prehash digest $D$.
> - Never store file names, previews, or component ordering lists.

---

## 2. Universal Database Schemas

You can connect Mosaic Credential to any SQL or NoSQL database. You only need a single column or field to hold the record JSON or string.

### PostgreSQL
```sql
CREATE TABLE users (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username          VARCHAR(255) UNIQUE NOT NULL,
    email             VARCHAR(255) UNIQUE NOT NULL,
    
    -- Store the VerifierRecord as JSONB or TEXT:
    credential_record JSONB NOT NULL,
    
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);
```

### SQLite
```sql
CREATE TABLE users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT UNIQUE NOT NULL,
    credential_record TEXT NOT NULL
);
```

### MongoDB / Document DBs
```javascript
// Document structure:
{
  "_id": ObjectId("..."),
  "username": "alice",
  "credential_record": {
    "format": "mosaic-credential",
    "format_version": 1,
    "profile": 1,
    "prehash": "sha256-domain-v1",
    "verifier": "$argon2id$v=19$m=65536,t=3,p=1$..."
  }
}
```

---

## 3. How to Connect Backend Logic

### Python Example (`FastAPI` / `Flask` / `Django`)

```python
from mosaic_credential import CredentialBuilder, Policy, enroll, verify, VerifierRecord, VerifyResult

# Registration endpoint (§10.1)
@app.post("/api/register")
def register(username: str, credential_json: dict):
    # 1. Build credential from submitted elements
    builder = CredentialBuilder(Policy(max_encoded_bits=160_000_000)) # 20 MB limit
    for el in credential_json["elements"]:
        if el["type"] == "CHAR":
            builder.add_text(el["char"])
        elif el["type"] == "BLOB":
            builder.add_blob(bytes.fromhex(el["hex"]))

    # 2. Derive Argon2id verifier
    record = enroll(builder.finalize())

    # 3. Save to database
    db.execute(
        "INSERT INTO users (username, credential_record) VALUES (?, ?)",
        (username, record.to_json())
    )
    return {"status": "registered"}

# Authentication endpoint (§10.2)
@app.post("/api/login")
def login(username: str, candidate_json: dict):
    # 1. Fetch stored record from database
    row = db.query_one("SELECT credential_record FROM users WHERE username = ?", (username,))
    if not row:
        return {"status": "denied"} # Generic failure

    stored_record = VerifierRecord.from_json(row["credential_record"])

    # 2. Build candidate credential
    candidate_builder = CredentialBuilder()
    for el in candidate_json["elements"]:
        if el["type"] == "CHAR":
            candidate_builder.add_text(el["char"])
        elif el["type"] == "BLOB":
            candidate_builder.add_blob(bytes.fromhex(el["hex"]))

    # 3. Verify
    result = verify(candidate_builder.finalize(), stored_record)
    if result == VerifyResult.OK:
        return {"status": "authenticated"}
    return {"status": "denied"}
```

---

## 4. Architectural Choices for Websites (§11)

There are two primary ways websites can implement this:

### Option 1: Client-Side Prehashing (§11.3) — **Fastest & Best for Bandwidth**
- **How it works**: The user's browser uses the JavaScript core (`mosaic-core.js`) to stream characters and large files into the 32-byte prehash ($D$) directly on their machine via the native `crypto.subtle` Web Crypto API.
- **Network Traffic**: Only the tiny **32-byte prehash** is sent across the network to your server!
- **Benefits**:
  - The user never uploads large 100 MB files over the internet.
  - Zero server bandwidth or upload timeout concerns.
  - The server never sees the raw files or text.

### Option 2: Server-Side Processing (§11.2) — **Authoritative Validation**
- **How it works**: Client sends the elements / files via a standard `multipart/form-data` upload. The server streams the payload into `mosaic-core` / `mosaic-auth`.
- **Benefits**: Server can strictly enforce exact file policies, element counts, and inspect metadata before hashing.

---

## 5. How to Visualize the Credential on Your Website

When designing a user interface for Mosaic Credential, follow the core UI principles from **Section 5.2 & 5.3**:

### A. The Two Views (§5.2)
1. **Structural View (The Real Authenticated Secret)**:
   - Display each component as an interactive "pill" or badge.
   - Ordinary characters: `'P'`, `'a'`, `'s'`, `'s'`.
   - Control characters: Highlighted with distinct styling (e.g. glowing orange badge for `⌫ <BS>`, cyan badge for `⚙ <TAB>`).
   - Binary Files: Display as a file chip showing the filename, byte size, and icon (e.g. `📦 image.png (42 KB)`).
2. **Visual Display Preview**:
   - Show how the credential would look if backspaces were executed (e.g., `Pass` + 3 backspaces + `word` renders visually as `Pword`).
   - **Always add a disclaimer**: *"Display preview only — backspaces are preserved as secret elements in your real credential."*

### B. Separate Editor Controls (§5.3)
Because pressing `Backspace` inserts a secret element `CHAR(U+0008)`, you must provide dedicated UI buttons for editing:
- **`[ ↩ Remove Last Element ]`**: Drops the last element from the list without adding anything.
- **`[ 🗑 Clear All ]`**: Resets the secret back to empty.
- **`[ × ]` Click to Delete on any element pill**: Removes that specific character or file.
- **Dual Mode Toggle**:
  - *Credential Mode*: Backspace key inserts `CHAR(U+0008)`.
  - *Standard Edit Mode*: Backspace key acts like a normal text box editor.

### C. Setting Maximum Password Sizes (§7)
Always configure the policy to prevent users from consuming unreasonable resources:

```javascript
// Recommended Web Policy (e.g., 20 MB total limit, max 5,000 elements):
const webPolicy = {
  max_encoded_bits: 160_000_000, // 20 MB in bits (20 * 1,000,000 * 8)
  max_blob_bits:    160_000_000, // Max 20 MB for any single file
  max_elements:     5_000        // Max 5,000 characters/files
};
```

In your UI, display an active progress bar showing:
- **`Total Size: 1.2 MB / 20.0 MB`**
- **`Elements: 14 / 5,000`**
- File dropzone rejecting any file exceeding `max_blob_bits` before processing.
