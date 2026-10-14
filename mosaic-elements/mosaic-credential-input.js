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

  const template = document.createElement('template');
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
    </style>

    <div class="mosaic-container" id="container">
      <div class="input-row" id="inputRow">
        <div class="tokens-list" id="tokensList"></div>
        <input type="text" class="text-entry" id="textEntry" autocomplete="off" spellcheck="false" />
      </div>

      <div class="toolbar">
        <div class="actions-left">
          <button type="button" class="tool-btn" id="bsBtn" title="Insert Secret Backspace token U+0008">
            ⌫ +Backspace
          </button>
          <button type="button" class="tool-btn" id="arrowsBtn" title="Insert Directional Arrow Token">
            🎮 ⬆⬇⬅➡
          </button>
          <button type="button" class="tool-btn" id="attachBtn" title="Attach file or binary BLOB">
            📎 +File
          </button>
          <button type="button" class="tool-btn" id="modeBtn" title="Toggle between Standard Portable Mode and Device-Bound Mode">
            🌐 Mode: Portable
          </button>
          <button type="button" class="tool-btn" id="viewToggleBtn" title="Toggle Secret Visibility">
            👁️ Peek
          </button>
        </div>

        <div class="actions-right">
          <span class="entropy-indicator entropy-empty" id="entropy">0 elements</span>
          <button type="button" class="tool-btn tool-btn-danger" id="clearBtn" title="Clear all elements">
            ✕ Clear
          </button>
        </div>
      </div>
      <input type="file" id="fileInput" multiple />
    </div>
  `;

  class MosaicCredentialInput extends HTMLElement {
    static formAssociated = true;

    constructor() {
      super();
      this._internals = this.attachInternals ? this.attachInternals() : null;
      this.attachShadow({ mode: 'open' });
      this.shadowRoot.appendChild(template.content.cloneNode(true));

      // Elements state
      this.elements = []; // Array of { type: 'CHAR', value: number, meta?: string } | { type: 'BLOB', value: Uint8Array, name: string }
      this.masked = true; // Visual mask
      this.bindingMode = 'portable'; // 'portable' (default) or 'os-bound'

      // Cache DOM
      this.$container = this.shadowRoot.getElementById('container');
      this.$inputRow = this.shadowRoot.getElementById('inputRow');
      this.$tokensList = this.shadowRoot.getElementById('tokensList');
      this.$textEntry = this.shadowRoot.getElementById('textEntry');
      this.$bsBtn = this.shadowRoot.getElementById('bsBtn');
      this.$arrowsBtn = this.shadowRoot.getElementById('arrowsBtn');
      this.$attachBtn = this.shadowRoot.getElementById('attachBtn');
      this.$modeBtn = this.shadowRoot.getElementById('modeBtn');
      this.$fileInput = this.shadowRoot.getElementById('fileInput');
      this.$viewToggleBtn = this.shadowRoot.getElementById('viewToggleBtn');
      this.$clearBtn = this.shadowRoot.getElementById('clearBtn');
      this.$entropy = this.shadowRoot.getElementById('entropy');

      // Bind methods
      this._onKeyDown = this._onKeyDown.bind(this);
      this._onInput = this._onInput.bind(this);
      this._onFileChange = this._onFileChange.bind(this);
      this._onDragOver = this._onDragOver.bind(this);
      this._onDragLeave = this._onDragLeave.bind(this);
      this._onDrop = this._onDrop.bind(this);
    }

    static get observedAttributes() {
      return ['placeholder', 'name', 'required', 'theme', 'mode'];
    }

    attributeChangedCallback(name, oldValue, newValue) {
      if (name === 'placeholder' && this.$textEntry) {
        this.$textEntry.placeholder = newValue || '';
      } else if (name === 'mode' && newValue) {
        this.setMode(newValue);
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

      // Event listeners
      this.$inputRow.addEventListener('click', () => this.$textEntry.focus());
      this.$textEntry.addEventListener('keydown', this._onKeyDown);
      this.$textEntry.addEventListener('input', this._onInput);
      this.$bsBtn.addEventListener('click', () => this.addBackspace());
      this.$arrowsBtn.addEventListener('click', () => this.promptArrowPicker());
      this.$modeBtn.addEventListener('click', () => this.toggleMode());
      this.$attachBtn.addEventListener('click', () => this.$fileInput.click());
      this.$fileInput.addEventListener('change', this._onFileChange);
      this.$viewToggleBtn.addEventListener('click', () => this.toggleMask());
      this.$clearBtn.addEventListener('click', () => this.clear());

      // Drag and drop
      this.$container.addEventListener('dragover', this._onDragOver);
      this.$container.addEventListener('dragleave', this._onDragLeave);
      this.$container.addEventListener('drop', this._onDrop);

      this._updateFormValue();
    }

    setMode(mode) {
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
    }

    _flushTextEntry() {
      if (this.$textEntry.value.length > 0) {
        for (const ch of this.$textEntry.value) {
          this.addChar(ch);
        }
        this.$textEntry.value = '';
      }
    }

    _onFileChange(e) {
      const files = Array.from(e.target.files);
      for (const file of files) {
        const reader = new FileReader();
        reader.onload = () => {
          this.addBlob(new Uint8Array(reader.result), file.name);
        };
        reader.readAsArrayBuffer(file);
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
          const reader = new FileReader();
          reader.onload = () => {
            this.addBlob(new Uint8Array(reader.result), file.name);
          };
          reader.readAsArrayBuffer(file);
        }
      }
    }

    _renderTokens() {
      this.$tokensList.innerHTML = '';

      this.elements.forEach((el, index) => {
        const badge = document.createElement('span');
        badge.className = 'token-badge';

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
    }

    _updateFormValue() {
      const base64Value = this.elements.length > 0 ? this.getBase64() : '';
      if (this._internals && this._internals.setFormValue) {
        this._internals.setFormValue(base64Value);
      }

      // Also dispatch custom change event
      this.dispatchEvent(new CustomEvent('change', {
        detail: {
          elementCount: this.elements.length,
          base64: base64Value
        },
        bubbles: true
      }));
    }
  }

  // Register Web Component
  if (!customElements.get('mosaic-credential-input')) {
    customElements.define('mosaic-credential-input', MosaicCredentialInput);
  }

  // Export to global if module or script
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { MosaicCredentialInput };
  } else {
    window.MosaicCredentialInput = MosaicCredentialInput;
  }
})();
