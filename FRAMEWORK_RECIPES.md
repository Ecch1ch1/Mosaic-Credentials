# ⚡ Mosaic Credentials: Framework Integration Recipes

Quick, copy-pasteable 1-minute integration guides for modern frontends and backends.

---

## 🎨 Frontend Recipes

### 1. Vanilla HTML + CSS

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
  <!-- 1. Include the component -->
  <script src="https://cdn.jsdelivr.net/npm/@mosaic-credentials/elements/mosaic-credential-input.js"></script>
  <style>
    /* 2. Optional: Style with CSS Variables */
    mosaic-credential-input {
      --mosaic-bg: #111827;
      --mosaic-border: #374151;
      --mosaic-focus: #6366f1;
      --mosaic-text: #f9fafb;
      --mosaic-radius: 8px;
    }
  </style>
</head>
<body>
  <form action="/api/login" method="POST">
    <label>Username</label>
    <input type="text" name="username" required />

    <label>Mosaic Secret</label>
    <!-- 3. Drop in the element -->
    <mosaic-credential-input 
      name="credential" 
      placeholder="Type secret or drop files...">
    </mosaic-credential-input>

    <button type="submit">Sign In</button>
  </form>
</body>
</html>
```

---

### 2. React / Next.js (TypeScript)

Create a reusable React wrapper component `MosaicInput.tsx`:

```tsx
'use client';

import React, { useEffect, useRef } from 'react';

// Client-side import for Next.js / React
export function MosaicInput({
  name = 'credential',
  placeholder = 'Type secret or drop files...',
  mode = 'portable',
  onChange,
}: {
  name?: string;
  placeholder?: string;
  mode?: 'portable' | 'os-bound';
  onChange?: (base64Payload: string) => void;
}) {
  const ref = useRef<HTMLElement>(null);

  useEffect(() => {
    // Dynamic import to prevent SSR issues in Next.js
    import('@mosaic-credentials/elements');

    const el = ref.current;
    if (!el) return;

    const handleChange = (e: any) => {
      if (onChange) onChange(e.detail.base64);
    };

    el.addEventListener('change', handleChange);
    return () => el.removeEventListener('change', handleChange);
  }, [onChange]);

  return (
    // @ts-ignore
    <mosaic-credential-input
      ref={ref}
      name={name}
      mode={mode}
      placeholder={placeholder}
    />
  );
}
```

#### Usage in a Next.js / React Form:
```tsx
export default function LoginPage() {
  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    
    // formData.get('credential') contains the canonical Base64 wire payload
    const res = await fetch('/api/login', {
      method: 'POST',
      body: formData,
    });
    if (res.ok) alert('Logged in!');
  }

  return (
    <form onSubmit={handleSubmit}>
      <input type="text" name="username" required />
      <MosaicInput name="credential" />
      <button type="submit">Sign In</button>
    </form>
  );
}
```

---

## 🐍 Python Backend Recipes

### 3. FastAPI

```python
from fastapi import FastAPI, Form, HTTPException, status
from pydantic import BaseModel
from mosaic_credential.core import parse_credential_stream
from mosaic_credential.auth import enroll_credential, verify_credential
import base64

app = FastAPI()

# In-memory demo DB: { username: verifier_record_json }
USER_DB = {}

class AuthRequest(BaseModel):
    username: str
    credential_base64: str

@app.post("/api/register")
def register(req: AuthRequest):
    # Decode canonical wire format from frontend
    raw_bytes = base64.b64decode(req.credential_base64)
    credential = parse_credential_stream(raw_bytes)

    # Derive Argon2id verifier record (~200 bytes)
    record = enroll_credential(credential)
    USER_DB[req.username] = record.to_json()
    return {"message": "User registered successfully"}

@app.post("/api/login")
def login(req: AuthRequest):
    if req.username not in USER_DB:
        raise HTTPException(status_code=401, detail="Access denied")

    raw_bytes = base64.b64decode(req.credential_base64)
    candidate = parse_credential_stream(raw_bytes)
    stored_record = USER_DB[req.username]

    # Verify candidate against stored Argon2id record
    if not verify_credential(candidate, stored_record):
        raise HTTPException(status_code=401, detail="Access denied")

    return {"message": "Authenticated successfully"}
```

---

### 4. Flask

```python
from flask import Flask, request, jsonify
from mosaic_credential.core import parse_credential_stream
from mosaic_credential.auth import enroll_credential, verify_credential
import base64

app = Flask(__name__)
USER_DB = {}

@app.route('/api/login', methods=['POST'])
def login():
    username = request.form.get('username')
    credential_b64 = request.form.get('credential')

    if not username or not credential_b64 or username not in USER_DB:
        return jsonify({"error": "Access denied"}), 401

    raw_bytes = base64.b64decode(credential_b64)
    candidate = parse_credential_stream(raw_bytes)
    stored_record = USER_DB[username]

    if verify_credential(candidate, stored_record):
        return jsonify({"success": True, "token": "session-123"})
    return jsonify({"error": "Access denied"}), 401
```

---

## 🦀 Rust Backend Recipes

### 5. Axum (Rust)

```rust
use axum::{routing::post, Json, Router, http::StatusCode};
use serde::{Deserialize, Serialize};
use mosaic_core::parser::parse_stream;
use mosaic_auth::{enroll, verify, params::AuthParams, record::VerifierRecord};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

#[derive(Deserialize)]
struct AuthPayload {
    username: String,
    credential: String, // Base64 canonical wire stream
}

type Db = Arc<Mutex<HashMap<String, VerifierRecord>>>;

async fn login_handler(
    db: axum::extract::Extension<Db>,
    Json(payload): Json<AuthPayload>,
) -> Result<String, StatusCode> {
    let raw_bytes = BASE64.decode(&payload.credential).map_err(|_| StatusCode::BAD_REQUEST)?;
    let elements = parse_stream(&raw_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    let users = db.lock().unwrap();
    let stored_record = users.get(&payload.username).ok_or(StatusCode::UNAUTHORIZED)?;

    let limits = Default::default();
    match verify(&elements, stored_record, &limits) {
        mosaic_auth::verify::VerifyResult::Ok => Ok("Authenticated!".into()),
        mosaic_auth::verify::VerifyResult::Denied => Err(StatusCode::UNAUTHORIZED),
    }
}
```

---

### 6. Actix-Web (Rust)

```rust
use actix_web::{post, web, HttpResponse, Responder};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use mosaic_core::parser::parse_stream;
use mosaic_auth::{verify, record::VerifierRecord};

#[post("/api/login")]
async fn login(
    body: web::Json<AuthPayload>,
    stored: web::Data<VerifierRecord>,
) -> impl Responder {
    let Ok(raw_bytes) = BASE64.decode(&body.credential) else {
        return HttpResponse::BadRequest().finish();
    };
    let Ok(elements) = parse_stream(&raw_bytes) else {
        return HttpResponse::BadRequest().finish();
    };

    match verify(&elements, &stored, &Default::default()) {
        mosaic_auth::verify::VerifyResult::Ok => HttpResponse::Ok().body("Logged in!"),
        mosaic_auth::verify::VerifyResult::Denied => HttpResponse::Unauthorized().finish(),
    }
}
```
