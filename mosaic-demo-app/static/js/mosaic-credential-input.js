/**
 * Mosaic Credential Drop-in Web Component
 * Specification: MC v0.1 (Strict Big-Endian Binary Framing)
 * 
 * Usage:
 *   <script src="mosaic-credential-input.js"></script>
 *   <mosaic-credential-input name="password" placeholder="Type secret or drop files..."></mosaic-credential-input>
 */

(function () {
  'use strict';

  // Constants (§6)
  const MAGIC = new Uint8Array([0x4D, 0x43, 0x52, 0x44]); // ASCII "MCRD"
  const VERSION = 1;
  const PROFILE = 1;
  const HEADER_SIZE = 8;
  const TAG_CHAR = 0x01;
  const TAG_BLOB = 0x02;
  const TAG_END = 0xff;
  const PREHASH_DOMAIN_PREFIX = new TextEncoder().encode("MOSAIC-CREDENTIAL/PREHASH/V1\0");

  // Capsule Keyfile Constants (.mosaic)
  const CAPSULE_MAGIC = new Uint8Array([0x4D, 0x4F, 0x53, 0x41, 0x49, 0x43, 0x30, 0x31]); // "MOSAIC01" (8 bytes)
  const CAPSULE_ITERATIONS = 200000;

  function validateCapsulePassphrase(passphrase, customValidator = null) {
    if (!passphrase || typeof passphrase !== 'string') {
      return { valid: false, error: 'Passphrase cannot be empty.' };
    }
    if (passphrase.length < 8) {
      return { valid: false, error: 'Passphrase must be at least 8 characters long.' };
    }
    if (/^[0-9]+$/.test(passphrase) && passphrase.length < 10) {
      return { valid: false, error: 'Numeric-only PINs must be at least 10 digits.' };
    }

    // 1. Check unique character entropy (rejects e.g. aaaaaaaa, abababab, 12121212)
    const uniqueChars = new Set(passphrase).size;
    if (uniqueChars < 4) {
      return { valid: false, error: 'Passphrase has too few unique characters (low entropy).' };
    }

    // 2. Check repeated chunk sequences (e.g. abcabcabc, 123123123)
    if (/(.{2,})\1{2,}/.test(passphrase)) {
      return { valid: false, error: 'Passphrase contains repeated pattern sequences.' };
    }

    // 3. Algorithmic sequential run detector (catches 4+ sequential ASCII runs like 1234, abcd, 9876, dcba)
    const lower = passphrase.toLowerCase();
    let seqRun = 1;
    let revRun = 1;
    for (let i = 1; i < lower.length; i++) {
      const diff = lower.charCodeAt(i) - lower.charCodeAt(i - 1);
      if (diff === 1) {
        seqRun++;
        if (seqRun >= 4) return { valid: false, error: 'Passphrase contains sequential character runs (e.g. 1234, abcd).' };
      } else {
        seqRun = 1;
      }
      if (diff === -1) {
        revRun++;
        if (revRun >= 4) return { valid: false, error: 'Passphrase contains reverse sequential runs (e.g. 4321, dcba).' };
      } else {
        revRun = 1;
      }
    }

    // 4. Common root words & keyboard walk submatches
    const predictableRoots = ['password', 'qwerty', 'asdfgh', 'zxcvbn', 'admin', 'iloveyou', 'mosaicpass', 'masterkey'];
    for (const root of predictableRoots) {
      if (lower.includes(root)) {
        return { valid: false, error: 'Passphrase contains predictable common pattern or word: "' + root + '"' };
      }
    }

    // 5. Pluggable custom validator hook (e.g. enterprise policy or zxcvbn)
    if (typeof customValidator === 'function') {
      const customRes = customValidator(passphrase);
      if (customRes && customRes.valid === false) {
        return customRes;
      }
    }

    return { valid: true, error: null };
  }

  async function encryptCapsule(canonicalBytes, elementsMeta, passphrase) {
    const cryptoObj = (typeof crypto !== 'undefined' && crypto.subtle) ? crypto : (globalThis.crypto || null);
    if (!cryptoObj || !cryptoObj.subtle) {
      throw new Error('Web Crypto API is not available.');
    }
    const salt = cryptoObj.getRandomValues(new Uint8Array(32));
    const iv = cryptoObj.getRandomValues(new Uint8Array(12));

    const passKey = await cryptoObj.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const aesKey = await cryptoObj.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: CAPSULE_ITERATIONS,
        hash: 'SHA-256'
      },
      passKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    let binaryCanonical = '';
    for (let i = 0; i < canonicalBytes.length; i++) binaryCanonical += String.fromCharCode(canonicalBytes[i]);
    const canonicalBase64 = btoa(binaryCanonical);

    const envelope = {
      format: 'MOSAIC-CAPSULE-v1',
      version: 1,
      created: new Date().toISOString(),
      canonical: canonicalBase64,
      elements: elementsMeta.map(el => {
        if (el.type === 'BLOB') {
          let b = '';
          for (let i = 0; i < el.value.length; i++) b += String.fromCharCode(el.value[i]);
          return { type: 'BLOB', name: el.name, base64: btoa(b) };
        }
        return el;
      })
    };

    const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
    const ciphertext = await cryptoObj.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      plaintext
    );

    const result = new Uint8Array(8 + 32 + 12 + 4 + ciphertext.byteLength);
    result.set(CAPSULE_MAGIC, 0);
    result.set(salt, 8);
    result.set(iv, 40);
    new DataView(result.buffer, result.byteOffset, result.byteLength).setUint32(52, CAPSULE_ITERATIONS, false);
    result.set(new Uint8Array(ciphertext), 56);
    return result;
  }

  async function decryptCapsule(capsuleBytes, passphrase) {
    const cryptoObj = (typeof crypto !== 'undefined' && crypto.subtle) ? crypto : (globalThis.crypto || null);
    if (!cryptoObj || !cryptoObj.subtle) {
      throw new Error('Web Crypto API is not available.');
    }
    if (capsuleBytes.length < 8 + 32 + 12 + 4 + 16) {
      throw new Error('Capsule file too short or corrupted.');
    }
    for (let i = 0; i < 8; i++) {
      if (capsuleBytes[i] !== CAPSULE_MAGIC[i]) {
        throw new Error('Invalid capsule magic header.');
      }
    }
    const salt = capsuleBytes.slice(8, 40);
    const iv = capsuleBytes.slice(40, 52);
    const iterations = new DataView(capsuleBytes.buffer, capsuleBytes.byteOffset, capsuleBytes.byteLength).getUint32(52, false);
    const ciphertext = capsuleBytes.slice(56);

    const passKey = await cryptoObj.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const aesKey = await cryptoObj.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: 'SHA-256'
      },
      passKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decryptedPlaintext = await cryptoObj.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      ciphertext
    );

    const envelope = JSON.parse(new TextDecoder().decode(decryptedPlaintext));
    return envelope;
  }

  function parseCanonicalStream(buffer) {
    if (buffer.length < 9) throw new Error('Credential stream too short');
    for (let i = 0; i < 4; i++) {
      if (buffer[i] !== MAGIC[i]) throw new Error('Invalid magic bytes');
    }
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const version = view.getUint16(4, false);
    const profile = view.getUint16(6, false);
    if (version !== 1 || profile !== 1) throw new Error('Unsupported version or profile');

    let offset = 8;
    const elements = [];
    while (offset < buffer.length) {
      const tag = buffer[offset++];
      if (tag === TAG_END) break;
      if (tag === TAG_CHAR) {
        if (offset + 4 > buffer.length) throw new Error('Truncated CHAR element');
        const scalar = view.getUint32(offset, false);
        offset += 4;
        let meta = undefined;
        if (scalar >= 0xE010 && scalar <= 0xE013) {
          const arrowMap = { 0xE010: 'ArrowUp', 0xE011: 'ArrowDown', 0xE012: 'ArrowLeft', 0xE013: 'ArrowRight' };
          meta = arrowMap[scalar];
        } else if (scalar >= 0xE021 && scalar <= 0xE02C) {
          meta = 'F' + (scalar - 0xE020);
        }
        elements.push({ type: 'CHAR', value: scalar, meta });
      } else if (tag === TAG_BLOB) {
        if (offset + 8 > buffer.length) throw new Error('Truncated BLOB length');
        const len = Number(view.getBigUint64(offset, false));
        offset += 8;
        if (offset + len > buffer.length) throw new Error('Truncated BLOB payload');
        const blobBytes = buffer.slice(offset, offset + len);
        offset += len;
        elements.push({ type: 'BLOB', value: blobBytes, name: 'attached-data.bin' });
      } else {
        throw new Error('Unknown tag in stream: ' + tag);
      }
    }
    return elements;
  }

  const template = typeof document !== 'undefined' ? document.createElement('template') : null;
  if (template) {
    template.innerHTML = `
    <style>
      :host {
        display: block;
        font-family: var(--mosaic-font, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif);
        box-sizing: border-box;
        --bg-color: var(--mosaic-bg, #161822);
        --border-color: var(--mosaic-border, #2d3148);
        --border-focus: var(--mosaic-focus, #6366f1);
        --text-color: var(--mosaic-text, #f1f5f9);
        --text-muted: var(--mosaic-muted, #94a3b8);
        --accent-color: var(--mosaic-accent, #6366f1);
        --bs-badge-bg: var(--mosaic-bs-bg, #dc2626);
        --blob-badge-bg: var(--mosaic-blob-bg, #059669);
        --radius: var(--mosaic-radius, 10px);
      }

      *, *::before, *::after {
        box-sizing: border-box;
      }

      .mosaic-container {
        position: relative;
        background: var(--bg-color);
        border: 1.5px solid var(--border-color);
        border-radius: var(--radius);
        padding: 8px 12px;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        display: flex;
        flex-direction: column;
        gap: 6px;
      }

      .mosaic-container:focus-within {
        border-color: var(--border-focus);
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      }

      .mosaic-container.drag-over {
        border-color: #38bdf8;
        background: rgba(56, 189, 248, 0.08);
      }

      .input-row {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 5px;
        min-height: 38px;
        cursor: text;
      }

      .tokens-list {
        display: inline-flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 5px;
      }

      .token-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        font-size: 12px;
        font-weight: 600;
        padding: 2px 7px;
        border-radius: 6px;
        user-select: none;
        animation: popIn 0.15s ease-out;
      }

      @keyframes popIn {
        from { transform: scale(0.8); opacity: 0; }
        to { transform: scale(1); opacity: 1; }
      }

      .token-char {
        background: rgba(255, 255, 255, 0.07);
        color: var(--text-color);
        border: 1px solid rgba(255, 255, 255, 0.1);
        font-family: monospace;
      }

      .token-bs {
        background: rgba(220, 38, 38, 0.2);
        color: #fca5a5;
        border: 1px solid rgba(220, 38, 38, 0.4);
      }

      .token-blob {
        background: rgba(5, 150, 105, 0.2);
        color: #6ee7b7;
        border: 1px solid rgba(5, 150, 105, 0.4);
      }

      .token-badge .token-del {
        cursor: pointer;
        opacity: 0.6;
        margin-left: 2px;
        font-size: 10px;
        transition: opacity 0.1s;
      }
      .token-badge .token-del:hover {
        opacity: 1;
        color: #ef4444;
      }

      .text-entry {
        flex: 1 1 80px;
        min-width: 60px;
        background: transparent;
        border: none;
        outline: none;
        color: var(--text-color);
        font-size: 14px;
        padding: 4px 0;
        font-family: inherit;
      }

      .text-entry::placeholder {
        color: var(--text-muted);
      }

      .toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-top: 4px;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
        font-size: 11px;
        color: var(--text-muted);
      }

      .actions-left, .actions-right {
        display: flex;
        align-items: center;
        gap: 6px;
      }

      .tool-btn {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 4px;
        color: var(--text-muted);
        cursor: pointer;
        padding: 3px 7px;
        font-size: 11px;
        display: inline-flex;
        align-items: center;
        gap: 4px;
        transition: all 0.15s ease;
      }

      .tool-btn:hover {
        background: rgba(255, 255, 255, 0.12);
        color: var(--text-color);
      }

      .tool-btn.active {
        background: var(--accent-color);
        color: #fff;
        border-color: var(--accent-color);
      }

      .token-arrow {
        background: rgba(14, 165, 233, 0.2);
        color: #7dd3fc;
        border: 1px solid rgba(14, 165, 233, 0.4);
      }

      .token-os {
        background: rgba(168, 85, 247, 0.2);
        color: #d8b4fe;
        border: 1px solid rgba(168, 85, 247, 0.4);
      }

      .tool-btn-os.active {
        background: #9333ea;
        color: white;
        border-color: #a855f7;
      }

      .tool-btn-danger:hover {
        background: rgba(239, 68, 68, 0.2);
        color: #fca5a5;
        border-color: rgba(239, 68, 68, 0.4);
      }

      .entropy-indicator {
        font-weight: 500;
        font-size: 11px;
      }

      .entropy-strong {
        color: #10b981;
      }
      .entropy-empty {
        color: var(--text-muted);
      }

      input[type="file"] {
        display: none;
      }

      /* Secret / Stealth Mode: Looks like standard password field */
      :host([secret-mode]) .toolbar,
      :host([stealth]) .toolbar {
        display: none !important;
      }

      :host([secret-mode]) .tokens-list,
      :host([stealth]) .tokens-list {
        display: none !important;
      }

      :host([secret-mode]) .mosaic-container,
      :host([stealth]) .mosaic-container {
        padding: 9px 12px;
        min-height: 40px;
      }

      :host([secret-mode]) .text-entry,
      :host([stealth]) .text-entry {
        width: 100%;
        font-size: 15px;
        letter-spacing: 0.12em;
      }

      .quick-clear-btn {
        background: transparent;
        border: none;
        color: var(--text-muted);
        cursor: pointer;
        font-size: 13px;
        line-height: 1;
        padding: 4px 6px;
        border-radius: 4px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        transition: all 0.15s ease;
        opacity: 0;
        pointer-events: none;
        user-select: none;
        flex-shrink: 0;
      }

      .quick-clear-btn.visible {
        opacity: 0.6;
        pointer-events: auto;
      }

      .quick-clear-btn:hover {
        opacity: 1;
        color: #ef4444;
        background: rgba(239, 68, 68, 0.15);
      }

      :host([secret-mode]) .quick-clear-btn,
      :host([stealth]) .quick-clear-btn {
        margin-left: auto;
        font-size: 15px;
      }

      .file-exactness-note {
        display: flex;
        align-items: flex-start;
        gap: 6px;
        font-size: 11px;
        line-height: 1.4;
        color: var(--text-muted);
        background: rgba(56, 189, 248, 0.05);
        border: 1px solid rgba(56, 189, 248, 0.14);
        border-radius: 6px;
        padding: 5px 8px;
        margin-top: 2px;
        user-select: none;
      }

      .file-exactness-note strong {
        color: var(--text-color);
      }

      .capsule-drawer {
        display: none;
        background: rgba(15, 23, 42, 0.96);
        border: 1px solid var(--border-focus);
        border-radius: var(--radius);
        padding: 12px;
        margin-top: 8px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
        backdrop-filter: blur(12px);
      }

      .capsule-drawer.open {
        display: block;
      }

      .capsule-drawer-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 8px;
      }

      .capsule-drawer-title {
        font-size: 13px;
        font-weight: 700;
        color: var(--text-color);
        display: flex;
        align-items: center;
        gap: 6px;
      }

      .capsule-close-btn {
        background: transparent;
        border: none;
        color: var(--text-muted);
        cursor: pointer;
        font-size: 14px;
        padding: 2px 6px;
        border-radius: 4px;
      }

      .capsule-close-btn:hover {
        color: #ef4444;
      }

      .capsule-field {
        margin-bottom: 8px;
      }

      .capsule-label {
        display: block;
        font-size: 11px;
        color: var(--text-muted);
        margin-bottom: 4px;
        font-weight: 600;
      }

      .capsule-input {
        width: 100%;
        background: rgba(0, 0, 0, 0.4);
        border: 1px solid var(--border-color);
        color: var(--text-color);
        padding: 6px 10px;
        border-radius: 6px;
        font-size: 13px;
        outline: none;
        font-family: inherit;
      }

      .capsule-input:focus {
        border-color: var(--border-focus);
      }

      .capsule-actions {
        display: flex;
        gap: 8px;
        justify-content: flex-end;
        margin-top: 10px;
      }

      .capsule-btn-primary {
        background: var(--accent-color);
        color: white;
        border: none;
        padding: 6px 14px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        transition: opacity 0.15s;
      }

      .capsule-btn-primary:hover {
        opacity: 0.9;
      }

      .capsule-btn-cancel {
        background: transparent;
        color: var(--text-muted);
        border: 1px solid var(--border-color);
        padding: 6px 12px;
        border-radius: 6px;
        font-size: 12px;
        cursor: pointer;
      }

      .capsule-error {
        font-size: 11px;
        color: #ef4444;
        margin-top: 4px;
        display: none;
      }

      .capsule-hint {
        font-size: 11px;
        color: var(--text-muted);
        line-height: 1.4;
        margin-bottom: 10px;
      }

      :host([secret-mode]) #capsuleBtn,
      :host([stealth]) #capsuleBtn,
      :host([secret-mode]) .capsule-drawer,
      :host([stealth]) .capsule-drawer {
        display: none !important;
      }
    </style>

    <div class="mosaic-container" id="container" part="container">
      <div class="input-row" id="inputRow" part="input-row">
        <div class="tokens-list" id="tokensList" part="tokens-list"></div>
        <input type="text" class="text-entry" id="textEntry" autocomplete="off" spellcheck="false" part="input" />
        <button type="button" class="quick-clear-btn" id="quickClearBtn" part="clear-btn" title="Clear all elements (Reset)" aria-label="Clear all elements">✕</button>
      </div>

      <div class="file-exactness-note" id="fileNote" part="file-note">
        <span>ℹ️</span>
        <span><strong>File Exactness:</strong> Files must be exact byte-for-byte originals. Chat apps (WhatsApp, Messenger) recompress media and strip metadata, which alters the credential.</span>
      </div>

      <div class="toolbar" part="toolbar">
        <div class="actions-left" part="actions-left">
          <button type="button" class="tool-btn" id="bsBtn" part="tool-btn" title="Insert Secret Backspace token U+0008">
            ⌫ +Backspace
          </button>
          <button type="button" class="tool-btn" id="arrowsBtn" part="tool-btn" title="Insert Directional Arrow Token">
            🎮 ⬆⬇⬅➡
          </button>
          <button type="button" class="tool-btn" id="attachBtn" part="tool-btn" title="Attach file or binary BLOB">
            📎 +File
          </button>
          <button type="button" class="tool-btn" id="capsuleBtn" part="capsule-btn" title="Export or manage encrypted .mosaic keyfile">
            💾 .mosaic Key
          </button>
          <button type="button" class="tool-btn" id="modeBtn" part="tool-btn" title="Toggle between Standard Portable Mode and Device-Bound Mode">
            🌐 Mode: Portable
          </button>
          <button type="button" class="tool-btn" id="viewToggleBtn" part="tool-btn" title="Toggle Secret Visibility">
            👁️ Peek
          </button>
        </div>

        <div class="actions-right" part="actions-right">
          <span class="entropy-indicator entropy-empty" id="entropy" part="status">0 elements</span>
          <button type="button" class="tool-btn tool-btn-danger" id="clearBtn" part="toolbar-clear-btn" title="Clear all elements">
            ✕ Clear
          </button>
        </div>
      </div>

      <div class="capsule-drawer" id="capsuleDrawer" part="capsule-drawer">
        <div class="capsule-drawer-header">
          <span class="capsule-drawer-title" id="capsuleDrawerTitle">💾 Export .mosaic Keyfile</span>
          <button type="button" class="capsule-close-btn" id="capsuleCloseBtn">✕</button>
        </div>
        <div id="capsuleDrawerBody"></div>
      </div>

      <input type="file" id="fileInput" multiple />
    </div>
    `;
  }

  const HTMLElementBase = typeof HTMLElement !== 'undefined' ? HTMLElement : class {};

  class MosaicCredentialInput extends HTMLElementBase {
    static formAssociated = true;

    constructor() {
      super();
      if (typeof HTMLElement === 'undefined') return;
      this._internals = this.attachInternals ? this.attachInternals() : null;
      this.attachShadow({ mode: 'open' });
      this.shadowRoot.appendChild(template.content.cloneNode(true));

      // Elements state
      this.elements = []; // Array of { type: 'CHAR', value: number, meta?: string } | { type: 'BLOB', value: Uint8Array, name: string }
      this.masked = true; // Visual mask
      this.bindingMode = 'portable'; // 'portable' (default) or 'os-bound'
      this.isSecretMode = false;
      this._bsHandledInKeyDown = false;

      // Cache DOM
      this.$container = this.shadowRoot.getElementById('container');
      this.$inputRow = this.shadowRoot.getElementById('inputRow');
      this.$tokensList = this.shadowRoot.getElementById('tokensList');
      this.$textEntry = this.shadowRoot.getElementById('textEntry');
      this.$quickClearBtn = this.shadowRoot.getElementById('quickClearBtn');
      this.$fileNote = this.shadowRoot.getElementById('fileNote');
      this.$bsBtn = this.shadowRoot.getElementById('bsBtn');
      this.$arrowsBtn = this.shadowRoot.getElementById('arrowsBtn');
      this.$attachBtn = this.shadowRoot.getElementById('attachBtn');
      this.$modeBtn = this.shadowRoot.getElementById('modeBtn');
      this.$fileInput = this.shadowRoot.getElementById('fileInput');
      this.$viewToggleBtn = this.shadowRoot.getElementById('viewToggleBtn');
      this.$clearBtn = this.shadowRoot.getElementById('clearBtn');
      this.$entropy = this.shadowRoot.getElementById('entropy');
      this.$capsuleBtn = this.shadowRoot.getElementById('capsuleBtn');
      this.$capsuleDrawer = this.shadowRoot.getElementById('capsuleDrawer');
      this.$capsuleDrawerTitle = this.shadowRoot.getElementById('capsuleDrawerTitle');
      this.$capsuleDrawerBody = this.shadowRoot.getElementById('capsuleDrawerBody');
      this.$capsuleCloseBtn = this.shadowRoot.getElementById('capsuleCloseBtn');

      // Bind methods
      this._onKeyDown = this._onKeyDown.bind(this);
      this._onInput = this._onInput.bind(this);
      this._onFileChange = this._onFileChange.bind(this);
      this._onDragOver = this._onDragOver.bind(this);
      this._onDragLeave = this._onDragLeave.bind(this);
      this._onDrop = this._onDrop.bind(this);
    }

    static get observedAttributes() {
      return ['placeholder', 'name', 'required', 'theme', 'mode', 'secret-mode', 'stealth'];
    }

    attributeChangedCallback(name, oldValue, newValue) {
      if (name === 'placeholder' && this.$textEntry) {
        this.$textEntry.placeholder = newValue || '';
      } else if (name === 'mode' && newValue) {
        this.setMode(newValue);
      } else if (name === 'secret-mode' || name === 'stealth') {
        this._updateSecretModeState();
      }
    }

    connectedCallback() {
      // Attributes init
      if (this.hasAttribute('placeholder')) {
        this.$textEntry.placeholder = this.getAttribute('placeholder');
      }
      if (this.hasAttribute('mode')) {
        this.setMode(this.getAttribute('mode'));
      }
      this._updateSecretModeState();

      // Event listeners
      this.$inputRow.addEventListener('click', () => this.$textEntry.focus());
      this.$quickClearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.clear();
        this.$textEntry.focus();
      });
      this.$textEntry.addEventListener('keydown', this._onKeyDown);
      this.$textEntry.addEventListener('input', this._onInput);
      this.$textEntry.addEventListener('paste', (e) => {
        if (this.isSecretMode) {
          const text = (e.clipboardData || window.clipboardData)?.getData('text');
          if (text) {
            for (const ch of text) {
              this.elements.push({ type: 'CHAR', value: ch.codePointAt(0) });
            }
            this._updateFormValue();
          }
        }
      });
      this.$bsBtn.addEventListener('click', () => this.addBackspace());
      this.$arrowsBtn.addEventListener('click', () => this.promptArrowPicker());
      this.$modeBtn.addEventListener('click', () => this.toggleMode());
      this.$attachBtn.addEventListener('click', () => this.$fileInput.click());
      this.$fileInput.addEventListener('change', this._onFileChange);
      this.$viewToggleBtn.addEventListener('click', () => this.toggleMask());
      this.$clearBtn.addEventListener('click', () => this.clear());
      if (this.$capsuleBtn) {
        this.$capsuleBtn.addEventListener('click', () => this.toggleCapsuleDrawer());
      }
      if (this.$capsuleCloseBtn) {
        this.$capsuleCloseBtn.addEventListener('click', () => this.closeCapsuleDrawer());
      }

      // Drag and drop
      this.$container.addEventListener('dragover', this._onDragOver);
      this.$container.addEventListener('dragleave', this._onDragLeave);
      this.$container.addEventListener('drop', this._onDrop);

      this._updateFormValue();
    }

    _updateSecretModeState() {
      const isSecret = this.hasAttribute('secret-mode') || this.hasAttribute('stealth');
      this.isSecretMode = isSecret;
      if (isSecret) {
        this.closeCapsuleDrawer();
        this.bindingMode = 'portable'; // Secret mode is strictly portable (§secret-mode)
        this.$textEntry.type = 'password';
      } else {
        this.$textEntry.type = 'text';
      }
      if (this.$fileNote) {
        this.$fileNote.style.display = isSecret ? 'none' : 'flex';
      }
      this._updateClearBtnVisibility();
    }

    get secretMode() {
      return this.isSecretMode;
    }

    set secretMode(val) {
      if (val) {
        this.setAttribute('secret-mode', '');
      } else {
        this.removeAttribute('secret-mode');
        this.removeAttribute('stealth');
      }
      this._updateSecretModeState();
    }

    setMode(mode) {
      if (this.isSecretMode) {
        this.bindingMode = 'portable'; // Secret mode is strictly portable
        return;
      }
      this.bindingMode = mode === 'os-bound' ? 'os-bound' : 'portable';
      if (this.bindingMode === 'os-bound') {
        this.$modeBtn.textContent = '🖥️ Mode: OS-Bound';
        this.$modeBtn.classList.add('tool-btn-os', 'active');
      } else {
        this.$modeBtn.textContent = '🌐 Mode: Portable';
        this.$modeBtn.classList.remove('tool-btn-os', 'active');
      }
    }

    toggleMode() {
      const nextMode = this.bindingMode === 'portable' ? 'os-bound' : 'portable';
      this.setMode(nextMode);
    }

    promptArrowPicker() {
      // Quickly cycle through directional arrows or insert Arrow Up
      this.addArrow('ArrowUp');
      this.$textEntry.focus();
    }

    // Public API
    addChar(char) {
      const code = typeof char === 'string' ? char.codePointAt(0) : char;
      this.elements.push({ type: 'CHAR', value: code });
      this._renderTokens();
      this._updateFormValue();
    }

    addText(text) {
      for (const char of text) {
        this.addChar(char);
      }
    }

    addBackspace() {
      this.elements.push({ type: 'CHAR', value: 0x0008 });
      this._renderTokens();
      this._updateFormValue();
      this.$textEntry.focus();
    }

    addArrow(key) {
      if (this.bindingMode === 'os-bound') {
        const platform = navigator.platform || (navigator.userAgentData && navigator.userAgentData.platform) || 'OS';
        const signature = `OS:${platform}:${key}`;
        this.addBlob(new TextEncoder().encode(signature), signature);
      } else {
        // Portable mode: Canonical PUA
        const puaMap = {
          'ArrowUp': 0xE010,
          'ArrowDown': 0xE011,
          'ArrowLeft': 0xE012,
          'ArrowRight': 0xE013,
        };
        const scalar = puaMap[key] || 0xE010;
        this.elements.push({ type: 'CHAR', value: scalar, meta: key });
        this._renderTokens();
        this._updateFormValue();
      }
    }

    addFunctionKey(fKey) {
      if (this.bindingMode === 'os-bound') {
        const platform = navigator.platform || (navigator.userAgentData && navigator.userAgentData.platform) || 'OS';
        const signature = `OS:${platform}:${fKey}`;
        this.addBlob(new TextEncoder().encode(signature), signature);
      } else {
        const num = parseInt(fKey.replace('F', ''), 10) || 1;
        const scalar = 0xE020 + num; // F1 -> 0xE021, F12 -> 0xE02C
        this.elements.push({ type: 'CHAR', value: scalar, meta: fKey });
        this._renderTokens();
        this._updateFormValue();
      }
    }

    addBlob(bytes, name = 'binary.bin') {
      const array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      this.elements.push({ type: 'BLOB', value: array, name });
      this._renderTokens();
      this._updateFormValue();
    }

    deleteLastElement() {
      if (this.elements.length > 0) {
        this.elements.pop();
        this._renderTokens();
        this._updateFormValue();
      }
    }

    removeElementAt(index) {
      if (index >= 0 && index < this.elements.length) {
        this.elements.splice(index, 1);
        this._renderTokens();
        this._updateFormValue();
      }
    }

    clear() {
      this.elements = [];
      this.$textEntry.value = '';
      this._renderTokens();
      this._updateFormValue();
    }

    toggleMask() {
      this.masked = !this.masked;
      this.$viewToggleBtn.classList.toggle('active', !this.masked);
      this.$viewToggleBtn.textContent = this.masked ? '👁️ Peek' : '🔒 Hide';
      this._renderTokens();
    }

    closeCapsuleDrawer() {
      if (this.$capsuleDrawer) {
        this.$capsuleDrawer.classList.remove('open');
      }
      if (this.$capsuleDrawerBody) {
        this.$capsuleDrawerBody.innerHTML = '';
      }
    }

    toggleCapsuleDrawer() {
      if (this.isSecretMode) return; // Strict stealth invariant
      if (!this.$capsuleDrawer) return;
      if (this.$capsuleDrawer.classList.contains('open')) {
        this.closeCapsuleDrawer();
        return;
      }
      if (this.elements.length === 0) {
        this.openEmptyCapsuleDrawer();
      } else {
        this.openExportCapsuleDrawer();
      }
    }

    openEmptyCapsuleDrawer() {
      if (this.isSecretMode || !this.$capsuleDrawerBody) return;
      this.$capsuleDrawerTitle.textContent = '💾 .mosaic Keyfile';
      this.$capsuleDrawerBody.innerHTML = `
        <div class="capsule-hint">
          No credential elements entered yet.<br>
          You can load an existing encrypted <strong>.mosaic</strong> keyfile from your physical USB drive, or type/attach elements first to export.
        </div>
        <div class="capsule-actions">
          <button type="button" class="capsule-btn-cancel" id="drawerCancelBtn">Cancel</button>
          <button type="button" class="capsule-btn-primary" id="drawerLoadFileBtn">📂 Select .mosaic File</button>
        </div>
      `;
      this.$capsuleDrawer.classList.add('open');
      this.$capsuleDrawerBody.querySelector('#drawerLoadFileBtn').addEventListener('click', () => {
        this.closeCapsuleDrawer();
        this.$fileInput.click();
      });
      this.$capsuleDrawerBody.querySelector('#drawerCancelBtn').addEventListener('click', () => {
        this.closeCapsuleDrawer();
      });
    }

    openExportCapsuleDrawer() {
      if (this.isSecretMode || !this.$capsuleDrawerBody) return;
      this.$capsuleDrawerTitle.textContent = '💾 Export Encrypted .mosaic Keyfile';
      this.$capsuleDrawerBody.innerHTML = `
        <div class="capsule-hint">
          Encrypt your full multi-modal credential (including secret keystrokes and exact binary files) into a portable <strong>.mosaic</strong> capsule for an offline USB drive.
        </div>
        <div class="capsule-field">
          <label class="capsule-label" for="exportPass">Master Passphrase (min 8 characters)</label>
          <input type="password" class="capsule-input" id="exportPass" placeholder="Enter a strong passphrase" autocomplete="new-password" />
        </div>
        <div class="capsule-field">
          <label class="capsule-label" for="exportConfirm">Confirm Passphrase</label>
          <input type="password" class="capsule-input" id="exportConfirm" placeholder="Re-enter passphrase" autocomplete="new-password" />
        </div>
        <div class="capsule-error" id="exportError"></div>
        <div class="capsule-actions">
          <button type="button" class="capsule-btn-cancel" id="exportCancelBtn">Cancel</button>
          <button type="button" class="capsule-btn-primary" id="exportDownloadBtn">🔒 Download .mosaic Keyfile</button>
        </div>
      `;
      this.$capsuleDrawer.classList.add('open');

      const passInput = this.$capsuleDrawerBody.querySelector('#exportPass');
      const confirmInput = this.$capsuleDrawerBody.querySelector('#exportConfirm');
      const errorDiv = this.$capsuleDrawerBody.querySelector('#exportError');
      const downloadBtn = this.$capsuleDrawerBody.querySelector('#exportDownloadBtn');
      const cancelBtn = this.$capsuleDrawerBody.querySelector('#exportCancelBtn');

      setTimeout(() => passInput.focus(), 50);

      cancelBtn.addEventListener('click', () => this.closeCapsuleDrawer());

      const handleExport = async () => {
        errorDiv.style.display = 'none';
        const pass = passInput.value;
        const confirm = confirmInput.value;

        if (pass !== confirm) {
          errorDiv.textContent = 'Passphrases do not match.';
          errorDiv.style.display = 'block';
          return;
        }

        const validation = validateCapsulePassphrase(pass, this.capsulePassphraseValidator);
        if (!validation.valid) {
          errorDiv.textContent = validation.error;
          errorDiv.style.display = 'block';
          return;
        }

        downloadBtn.disabled = true;
        downloadBtn.textContent = 'Encrypting (200k rounds)...';

        try {
          const canonicalBytes = this.encodeCanonical();
          const capsuleBytes = await encryptCapsule(canonicalBytes, this.elements, pass);

          const blob = new Blob([capsuleBytes], { type: 'application/octet-stream' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'credential.mosaic';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);

          this.closeCapsuleDrawer();
        } catch (err) {
          errorDiv.textContent = 'Encryption failed: ' + (err.message || err);
          errorDiv.style.display = 'block';
          downloadBtn.disabled = false;
          downloadBtn.textContent = '🔒 Download .mosaic Keyfile';
        }
      };

      downloadBtn.addEventListener('click', handleExport);
      passInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') confirmInput.focus();
      });
      confirmInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleExport();
      });
    }

    promptUnlockCapsule(capsuleBytes, filename) {
      if (this.isSecretMode) {
        this.addBlob(capsuleBytes, filename || 'capsule.bin');
        return;
      }

      this.$capsuleDrawerTitle.textContent = `🔓 Unlock ${filename || '.mosaic Keyfile'}`;
      this.$capsuleDrawerBody.innerHTML = `
        <div class="capsule-hint">
          This is an encrypted <strong>.mosaic</strong> keyfile. Enter the master passphrase to decrypt and load your credential.
        </div>
        <div class="capsule-field">
          <label class="capsule-label" for="unlockPass">Master Passphrase</label>
          <input type="password" class="capsule-input" id="unlockPass" placeholder="Enter passphrase to decrypt" autocomplete="current-password" />
        </div>
        <div class="capsule-error" id="unlockError"></div>
        <div class="capsule-actions">
          <button type="button" class="capsule-btn-cancel" id="unlockCancelBtn">Cancel</button>
          <button type="button" class="capsule-btn-primary" id="unlockSubmitBtn">🔓 Decrypt & Load</button>
        </div>
      `;
      this.$capsuleDrawer.classList.add('open');

      const passInput = this.$capsuleDrawerBody.querySelector('#unlockPass');
      const errorDiv = this.$capsuleDrawerBody.querySelector('#unlockError');
      const submitBtn = this.$capsuleDrawerBody.querySelector('#unlockSubmitBtn');
      const cancelBtn = this.$capsuleDrawerBody.querySelector('#unlockCancelBtn');

      setTimeout(() => passInput.focus(), 50);

      cancelBtn.addEventListener('click', () => this.closeCapsuleDrawer());

      const handleUnlock = async () => {
        errorDiv.style.display = 'none';
        const pass = passInput.value;
        if (!pass) {
          errorDiv.textContent = 'Passphrase cannot be empty.';
          errorDiv.style.display = 'block';
          return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = 'Decrypting (200k rounds)...';

        try {
          const envelope = await decryptCapsule(capsuleBytes, pass);
          
          let newElements = [];
          if (envelope && Array.isArray(envelope.elements)) {
            newElements = envelope.elements.map(el => {
              if (el.type === 'BLOB') {
                const binary = atob(el.base64);
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                return { type: 'BLOB', name: el.name || 'file.bin', value: bytes };
              }
              return { ...el };
            });
          } else if (envelope && envelope.canonical) {
            const binary = atob(envelope.canonical);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            newElements = parseCanonicalStream(bytes);
          } else {
            throw new Error('Unrecognized capsule format.');
          }

          this.elements = newElements;
          this.$textEntry.value = '';
          this._renderTokens();
          this._updateFormValue();
          this.closeCapsuleDrawer();
        } catch (err) {
          errorDiv.textContent = 'Decryption failed: Incorrect passphrase or corrupted keyfile.';
          errorDiv.style.display = 'block';
          submitBtn.disabled = false;
          submitBtn.textContent = '🔓 Decrypt & Load';
        }
      };

      submitBtn.addEventListener('click', handleUnlock);
      passInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleUnlock();
      });
    }

    // Serialization to MC v1 Binary Format (§6)
    encodeCanonical() {
      let totalSize = HEADER_SIZE;
      for (const el of this.elements) {
        if (el.type === 'CHAR') {
          totalSize += 1 + 4; // Tag 0x01 + 4 bytes BE scalar
        } else if (el.type === 'BLOB') {
          totalSize += 1 + 8 + el.value.length; // Tag 0x02 + 8 bytes BE len + bytes
        }
      }
      totalSize += 1; // END 0xFF

      const buffer = new Uint8Array(totalSize);
      const view = new DataView(buffer.buffer);

      // Header: MCRD (4) + version (u16) + profile (u16)
      buffer.set(MAGIC, 0);
      view.setUint16(4, VERSION, false);
      view.setUint16(6, PROFILE, false);

      let offset = HEADER_SIZE;
      for (const el of this.elements) {
        if (el.type === 'CHAR') {
          buffer[offset++] = TAG_CHAR;
          view.setUint32(offset, el.value >>> 0, false);
          offset += 4;
        } else if (el.type === 'BLOB') {
          buffer[offset++] = TAG_BLOB;
          view.setBigUint64(offset, BigInt(el.value.length), false);
          offset += 8;
          buffer.set(el.value, offset);
          offset += el.value.length;
        }
      }

      buffer[offset++] = TAG_END;
      return buffer;
    }

    // Returns Base64-encoded canonical wire format
    getBase64() {
      const bytes = this.encodeCanonical();
      let binary = '';
      const len = bytes.byteLength;
      for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    }

    // Calculates Domain-Separated Prehash (SHA-256)
    async getPrehash() {
      const canonical = this.encodeCanonical();
      const combined = new Uint8Array(PREHASH_DOMAIN_PREFIX.length + canonical.length);
      combined.set(PREHASH_DOMAIN_PREFIX, 0);
      combined.set(canonical, PREHASH_DOMAIN_PREFIX.length);
      const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
      return new Uint8Array(hashBuffer);
    }

    // Internal Event Handlers
    _onKeyDown(e) {
      if (this.isSecretMode) {
        if (e.key === 'Backspace') {
          // If all text is selected (e.g. Ctrl+A or Cmd+A), clear completely
          const hasFullSelection = this.$textEntry.selectionStart === 0 &&
                                   this.$textEntry.selectionEnd === this.$textEntry.value.length &&
                                   this.$textEntry.value.length > 0;
          if (hasFullSelection) {
            this.clear();
            return;
          }

          // In secret mode: Backspace is recorded as secret scalar CHAR(0x0008).
          // We let the browser's native backspace visually delete one bullet from $textEntry.value!
          this.elements.push({ type: 'CHAR', value: 0x0008 });
          this._updateFormValue();
          this._bsHandledInKeyDown = true;
          return;
        } else if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) {
          e.preventDefault();
          this.addArrow(e.key);
          return;
        } else if (/^F([1-9]|1[0-2])$/.test(e.key)) {
          e.preventDefault();
          this.addFunctionKey(e.key);
          return;
        } else if (e.key === 'Enter') {
          return;
        }
        return;
      }

      // Standard Rich Token Mode
      if (e.key === 'Backspace') {
        // If user holds Shift+Backspace, delete last token
        if (e.shiftKey) {
          e.preventDefault();
          this.deleteLastElement();
          return;
        }

        // Standard Backspace in input field
        if (this.$textEntry.value.length === 0) {
          e.preventDefault();
          // Secret Backspace Mode: Insert CHAR(0x0008)
          this.addBackspace();
        }
      } else if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) {
        e.preventDefault();
        this._flushTextEntry();
        this.addArrow(e.key);
      } else if (/^F([1-9]|1[0-2])$/.test(e.key)) {
        e.preventDefault();
        this._flushTextEntry();
        this.addFunctionKey(e.key);
      } else if (e.key === 'Enter') {
        // If Enter pressed with text in buffer, flush it
        this._flushTextEntry();
        // Allow form submission to proceed naturally
      }
    }

    _onInput(e) {
      if (this.isSecretMode) {
        if (e.inputType === 'insertText' && e.data) {
          for (const ch of e.data) {
            this.elements.push({ type: 'CHAR', value: ch.codePointAt(0) });
          }
          this._updateFormValue();
        } else if (e.inputType === 'deleteContentBackward') {
          if (!this._bsHandledInKeyDown) {
            this.elements.push({ type: 'CHAR', value: 0x0008 });
            this._updateFormValue();
          }
          this._bsHandledInKeyDown = false;
        }
        return;
      }

      if (e.inputType === 'insertText' && e.data) {
        for (const ch of e.data) {
          this.addChar(ch);
        }
        this.$textEntry.value = '';
      } else if (this.$textEntry.value.length > 0) {
        for (const ch of this.$textEntry.value) {
          this.addChar(ch);
        }
        this.$textEntry.value = '';
      }
      this._updateClearBtnVisibility();
    }

    _flushTextEntry() {
      if (this.isSecretMode) return;
      if (this.$textEntry.value.length > 0) {
        for (const ch of this.$textEntry.value) {
          this.addChar(ch);
        }
        this.$textEntry.value = '';
      }
    }

    _processFile(file) {
      const reader = new FileReader();
      reader.onload = () => {
        const bytes = new Uint8Array(reader.result);
        const isMosaicExt = file.name && file.name.toLowerCase().endsWith('.mosaic');
        const hasCapsuleMagic = bytes.length >= 8 &&
          bytes[0] === CAPSULE_MAGIC[0] &&
          bytes[1] === CAPSULE_MAGIC[1] &&
          bytes[2] === CAPSULE_MAGIC[2] &&
          bytes[3] === CAPSULE_MAGIC[3] &&
          bytes[4] === CAPSULE_MAGIC[4] &&
          bytes[5] === CAPSULE_MAGIC[5] &&
          bytes[6] === CAPSULE_MAGIC[6] &&
          bytes[7] === CAPSULE_MAGIC[7];

        if (!this.isSecretMode && (hasCapsuleMagic || isMosaicExt)) {
          this.promptUnlockCapsule(bytes, file.name);
        } else {
          this.addBlob(bytes, file.name);
        }
      };
      reader.readAsArrayBuffer(file);
    }

    _onFileChange(e) {
      const files = Array.from(e.target.files);
      for (const file of files) {
        this._processFile(file);
      }
      this.$fileInput.value = '';
    }

    _onDragOver(e) {
      e.preventDefault();
      this.$container.classList.add('drag-over');
    }

    _onDragLeave(e) {
      this.$container.classList.remove('drag-over');
    }

    _onDrop(e) {
      e.preventDefault();
      this.$container.classList.remove('drag-over');
      if (e.dataTransfer && e.dataTransfer.files) {
        for (const file of e.dataTransfer.files) {
          this._processFile(file);
        }
      }
    }

    _updateClearBtnVisibility() {
      if (this.$quickClearBtn) {
        const hasContent = this.elements.length > 0 || (this.$textEntry && this.$textEntry.value.length > 0);
        this.$quickClearBtn.classList.toggle('visible', hasContent);
      }
    }

    _renderTokens() {
      this.$tokensList.innerHTML = '';

      this.elements.forEach((el, index) => {
        const badge = document.createElement('span');
        badge.className = 'token-badge';
        badge.setAttribute('part', 'token');

        if (el.type === 'CHAR') {
          if (el.value === 0x0008) {
            badge.classList.add('token-bs');
            badge.innerHTML = `⌫ BS <span class="token-del" data-index="${index}">✕</span>`;
          } else if (el.value >= 0xE010 && el.value <= 0xE013) {
            badge.classList.add('token-arrow');
            const arrowIcons = { 0xE010: '⬆ UP', 0xE011: '⬇ DOWN', 0xE012: '⬅ LEFT', 0xE013: '➡ RIGHT' };
            const icon = this.masked ? '▲' : (arrowIcons[el.value] || '⬆');
            badge.innerHTML = `${icon} <span class="token-del" data-index="${index}">✕</span>`;
          } else if (el.value >= 0xE021 && el.value <= 0xE02C) {
            badge.classList.add('token-arrow');
            const fLabel = `F${el.value - 0xE020}`;
            const icon = this.masked ? '⚙' : fLabel;
            badge.innerHTML = `${icon} <span class="token-del" data-index="${index}">✕</span>`;
          } else {
            badge.classList.add('token-char');
            const displayChar = this.masked ? '●' : String.fromCodePoint(el.value);
            badge.innerHTML = `${displayChar} <span class="token-del" data-index="${index}">✕</span>`;
          }
        } else if (el.type === 'BLOB') {
          if (el.name && el.name.startsWith('OS:')) {
            badge.classList.add('token-os');
            const label = this.masked ? '🖥️ OS-Key' : `🖥️ ${el.name}`;
            badge.innerHTML = `${label} <span class="token-del" data-index="${index}">✕</span>`;
          } else {
            badge.classList.add('token-blob');
            const sizeKb = (el.value.length / 1024).toFixed(1);
            badge.innerHTML = `📄 ${el.name} (${sizeKb}K) <span class="token-del" data-index="${index}">✕</span>`;
          }
        }

        badge.querySelector('.token-del').addEventListener('click', (ev) => {
          ev.stopPropagation();
          this.removeElementAt(index);
        });

        this.$tokensList.appendChild(badge);
      });

      // Update counter / entropy indicator
      const count = this.elements.length;
      if (count === 0) {
        this.$entropy.className = 'entropy-indicator entropy-empty';
        this.$entropy.textContent = '0 elements';
      } else {
        const hasBlob = this.elements.some(e => e.type === 'BLOB');
        const hasBs = this.elements.some(e => e.type === 'CHAR' && e.value === 0x0008);
        this.$entropy.className = 'entropy-indicator entropy-strong';
        let badgeDesc = `${count} items`;
        if (hasBlob && hasBs) badgeDesc += ' (🛡️ Hybrid Matrix)';
        else if (hasBlob) badgeDesc += ' (🔒 BLOB Protected)';
        else if (hasBs) badgeDesc += ' (⌫ Keystroke Protected)';
        this.$entropy.textContent = badgeDesc;
      }

      this._updateClearBtnVisibility();
    }

    _updateFormValue() {
      const base64Value = this.elements.length > 0 ? this.getBase64() : '';
      if (this._internals && this._internals.setFormValue) {
        this._internals.setFormValue(base64Value);
      }

      this._updateClearBtnVisibility();

      // Dispatch change event
      this.dispatchEvent(new CustomEvent('change', {
        detail: {
          elementCount: this.elements.length,
          base64: base64Value
        },
        bubbles: true
      }));

      // Dispatch custom credential-change event
      this.dispatchEvent(new CustomEvent('credential-change', {
        detail: {
          elementCount: this.elements.length,
          base64: base64Value
        },
        bubbles: true
      }));
    }
  }

  // Register Web Component
  if (typeof customElements !== 'undefined' && !customElements.get('mosaic-credential-input')) {
    customElements.define('mosaic-credential-input', MosaicCredentialInput);
  }

  // Export to global if module or script
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      MosaicCredentialInput,
      validateCapsulePassphrase,
      encryptCapsule,
      decryptCapsule,
      parseCanonicalStream,
      CAPSULE_MAGIC,
      CAPSULE_ITERATIONS
    };
  } else if (typeof window !== 'undefined') {
    window.MosaicCredentialInput = MosaicCredentialInput;
    window.MosaicCapsule = {
      validateCapsulePassphrase,
      encryptCapsule,
      decryptCapsule,
      parseCanonicalStream,
      CAPSULE_MAGIC,
      CAPSULE_ITERATIONS
    };
  }
})();
