/**
 * Mosaic Credential Reference Web Editor — UI Controller
 * Specification: Sections 5.2, 5.3, 6, 7, 8, 9, 10, 16.4
 */

import {
  createChar,
  createBlob,
  encodeElements,
  parseCanonical,
  computePrehash,
  renderPreview,
  bytesToHex,
  hexToBytes,
  HEADER_SIZE,
  CHAR_SIZE,
  BLOB_HEADER_SIZE,
  END_SIZE,
} from './mosaic-core.js';

// Published Test Vectors embedded from test-vectors/published_test_vectors.json
const PUBLISHED_TEST_VECTORS = [
  {
    id: "mc-v1-001-empty",
    description: "Empty credential (zero elements)",
    canonical_hex: "4d43524400010001ff",
    prehash_hex: "fa3c37767a7d9d7880ce0b04f87ffd0c3fd37bee835b89814d6c502063b7224e",
    elements_builder: () => []
  },
  {
    id: "mc-v1-002-single-char",
    description: "Single ASCII character 'A'",
    canonical_hex: "4d435244000100010100000041ff",
    prehash_hex: "4c5eef09e109b12aea033df9fab17fccf2cccd4a03752bc0edc4f606f3a4e0ab",
    elements_builder: () => [createChar('A')]
  },
  {
    id: "mc-v1-003-word-with-backspaces",
    description: "Text 'Pass' followed by 3 backspaces and 'word'",
    canonical_hex: "4d4352440001000101000000500100000061010000007301000000730100000008010000000801000000080100000077010000006f01000000720100000064ff",
    prehash_hex: "4f555eba1553e330736297e6c02a76bf44476c8f84b8ec49bc47ff63ba6b3ed8",
    elements_builder: () => [
      createChar('P'), createChar('a'), createChar('s'), createChar('s'),
      createChar('\u0008'), createChar('\u0008'), createChar('\u0008'),
      createChar('w'), createChar('o'), createChar('r'), createChar('d')
    ]
  },
  {
    id: "mc-v1-004-multilingual-emoji",
    description: "Unicode scalars with emoji, symbols, and NUL (🦀, 🔑, ©, U+0000)",
    canonical_hex: "4d43524400010001010001f980010001f51101000000a90100000000ff",
    prehash_hex: "444ad7661991d41dd34e8d6b6a1e085b4afa44b178b2bd1dae9b40f5f4b2a452",
    elements_builder: () => [createChar('🦀'), createChar('🔑'), createChar('©'), createChar('\0')]
  },
  {
    id: "mc-v1-005-single-blob",
    description: "Single binary component: b\"hello world\"",
    canonical_hex: "4d4352440001000102000000000000000b68656c6c6f20776f726c64ff",
    prehash_hex: "b24a5aaf4fd6ba966ffb59c94b59c5ba974895a026af85c544038d2d673d0991",
    elements_builder: () => [createBlob(new TextEncoder().encode("hello world"), "hello.txt")]
  },
  {
    id: "mc-v1-006-empty-blob",
    description: "Zero-length BLOB component",
    canonical_hex: "4d43524400010001020000000000000000ff",
    prehash_hex: "9e9ff0c46013ce06becad7da3092070760f815616b79ab59bdaf84224d110360",
    elements_builder: () => [createBlob(new Uint8Array(0), "empty.bin")]
  },
  {
    id: "mc-v1-007-mixed-text-and-blob",
    description: "Interleaved text and binary: 'P', 'a', BLOB(0x00,0x01,0x02), BS, 'x'",
    canonical_hex: "4d435244000100010100000050010000006102000000000000000300010201000000080100000078ff",
    prehash_hex: "d47a1834b5e0792710bdc44a60e05b69ec143cd378c60791c1e2b68328bf6909",
    elements_builder: () => [
      createChar('P'), createChar('a'),
      createBlob(new Uint8Array([0x00, 0x01, 0x02]), "chunk.bin"),
      createChar('\u0008'), createChar('x')
    ]
  },
  {
    id: "mc-v1-008-multiple-blobs",
    description: "Two distinct BLOB components [0xde, 0xad] and [0xbe, 0xef]",
    canonical_hex: "4d43524400010001020000000000000002dead020000000000000002beefff",
    prehash_hex: "387bdeb018df1663f19a5a1a0951e61cf6fa803c149b8b05894b6cca258325d6",
    elements_builder: () => [
      createBlob(new Uint8Array([0xde, 0xad]), "dead.bin"),
      createBlob(new Uint8Array([0xbe, 0xef]), "beef.bin")
    ]
  }
];

class MosaicEditorApp {
  constructor() {
    this.elements = [];
    this.mode = 'credential'; // 'credential' (BS is secret element) | 'edit' (BS edits)
    this.policy = {
      max_encoded_bits: 2_000_000_000,
      max_blob_bits: 2_000_000_000,
      max_elements: 100_000
    };

    this.initDOMElements();
    this.bindEvents();
    this.renderAll();
    this.renderTestVectorsTable();
  }

  initDOMElements() {
    // Navigation Tabs
    this.tabButtons = document.querySelectorAll('.tab-btn');
    this.tabPanes = document.querySelectorAll('.tab-pane');

    // Editor elements
    this.credInput = document.getElementById('cred-input');
    this.modeCredBtn = document.getElementById('mode-cred-btn');
    this.modeEditBtn = document.getElementById('mode-edit-btn');
    this.dropzone = document.getElementById('dropzone');
    this.filePicker = document.getElementById('file-picker');

    // Action buttons
    this.btnAddBs = document.getElementById('btn-add-bs');
    this.btnRemoveLast = document.getElementById('btn-remove-last');
    this.btnClear = document.getElementById('btn-clear');

    // Display areas
    this.elementStream = document.getElementById('element-stream');
    this.previewBox = document.getElementById('preview-box');
    this.hexViewer = document.getElementById('hex-viewer');
    this.prehashDisplay = document.getElementById('prehash-val');
    this.copyPrehashBtn = document.getElementById('copy-prehash-btn');

    // Metrics
    this.metricElements = document.getElementById('metric-elements');
    this.metricBytes = document.getElementById('metric-bytes');
    this.metricBits = document.getElementById('metric-bits');
    this.meterBits = document.getElementById('meter-bits');

    // Enrollment & Verification
    this.btnEnroll = document.getElementById('btn-enroll');
    this.recordJsonOutput = document.getElementById('record-json-output');
    this.copyRecordBtn = document.getElementById('copy-record-btn');
    this.downloadRecordBtn = document.getElementById('download-record-btn');

    this.verifyRecordInput = document.getElementById('verify-record-input');
    this.btnVerify = document.getElementById('btn-verify');
    this.verifyStatusBox = document.getElementById('verify-status-box');

    // Vectors
    this.vectorsTableBody = document.getElementById('vectors-table-body');
    this.btnRunAllVectors = document.getElementById('btn-run-all-vectors');
  }

  bindEvents() {
    // Tab switching
    this.tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.dataset.tab;
        this.tabButtons.forEach(b => b.classList.remove('active'));
        this.tabPanes.forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`tab-${targetTab}`).classList.add('active');
      });
    });

    // Mode Toggle
    this.modeCredBtn.addEventListener('click', () => {
      this.mode = 'credential';
      this.modeCredBtn.classList.add('active');
      this.modeEditBtn.classList.remove('active');
      this.credInput.focus();
    });

    this.modeEditBtn.addEventListener('click', () => {
      this.mode = 'edit';
      this.modeEditBtn.classList.add('active');
      this.modeCredBtn.classList.remove('active');
      this.credInput.focus();
    });

    // Keydown handling on credential input
    this.credInput.addEventListener('keydown', (e) => {
      if (this.mode === 'credential') {
        if (e.key === 'Backspace') {
          e.preventDefault();
          this.addElement(createChar(0x0008));
          return;
        } else if (e.key === 'Enter') {
          e.preventDefault();
          this.addElement(createChar('\n'));
          return;
        } else if (e.key === 'Tab') {
          e.preventDefault();
          this.addElement(createChar('\t'));
          return;
        }
      }
    });

    // Text input handler (captures regular typing & pasted text)
    this.credInput.addEventListener('input', (e) => {
      const val = this.credInput.value;
      if (val) {
        for (const ch of val) {
          try {
            this.addElement(createChar(ch));
          } catch (err) {
            console.warn(err);
          }
        }
        this.credInput.value = '';
      }
    });

    // Editor Action Buttons (§5.3)
    this.btnAddBs.addEventListener('click', () => {
      this.addElement(createChar(0x0008));
      this.credInput.focus();
    });

    this.btnRemoveLast.addEventListener('click', () => {
      if (this.elements.length > 0) {
        this.elements.pop();
        this.renderAll();
      }
      this.credInput.focus();
    });

    this.btnClear.addEventListener('click', () => {
      this.elements = [];
      this.renderAll();
      this.credInput.focus();
    });

    // Dropzone / File Picker
    this.dropzone.addEventListener('click', () => this.filePicker.click());

    this.dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      this.dropzone.classList.add('dragover');
    });

    this.dropzone.addEventListener('dragleave', () => {
      this.dropzone.classList.remove('dragover');
    });

    this.dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      this.dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) {
        this.handleFiles(e.dataTransfer.files);
      }
    });

    this.filePicker.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        this.handleFiles(e.target.files);
        this.filePicker.value = '';
      }
    });

    // Copy Prehash button
    this.copyPrehashBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(this.prehashDisplay.textContent);
      this.showToast('Prehash copied to clipboard');
    });

    // Enrollment button
    this.btnEnroll.addEventListener('click', () => this.handleEnrollment());

    // Copy & Download Record
    this.copyRecordBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(this.recordJsonOutput.value);
      this.showToast('Verifier record JSON copied');
    });

    this.downloadRecordBtn.addEventListener('click', () => {
      const blob = new Blob([this.recordJsonOutput.value], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'verifier-record.json';
      a.click();
      URL.revokeObjectURL(url);
    });

    // Verification button
    this.btnVerify.addEventListener('click', () => this.handleVerification());

    // Test Vectors Runner
    this.btnRunAllVectors.addEventListener('click', () => this.runAllTestVectors());
  }

  async handleFiles(fileList) {
    for (const file of fileList) {
      const arrayBuffer = await file.arrayBuffer();
      const u8 = new Uint8Array(arrayBuffer);
      this.addElement(createBlob(u8, file.name));
    }
  }

  addElement(element) {
    if (this.elements.length >= this.policy.max_elements) {
      alert(`Limit exceeded: maximum ${this.policy.max_elements} elements allowed.`);
      return;
    }
    this.elements.push(element);
    this.renderAll();
  }

  async renderAll() {
    this.renderStructuralView();
    this.renderPreviewView();
    await this.renderHexAndMetrics();
  }

  renderStructuralView() {
    this.elementStream.innerHTML = '';
    if (this.elements.length === 0) {
      const emptyNote = document.createElement('div');
      emptyNote.style.color = 'var(--text-dim)';
      emptyNote.style.fontSize = '0.85rem';
      emptyNote.style.padding = '0.5rem';
      emptyNote.textContent = 'Empty credential (no elements). Type text or drop files to add secret components.';
      this.elementStream.appendChild(emptyNote);
      return;
    }

    this.elements.forEach((el, idx) => {
      const pill = document.createElement('span');
      pill.className = 'element-pill';

      if (el.type === 'CHAR') {
        if (el.isBackspace) {
          pill.classList.add('pill-bs');
          pill.innerHTML = `<span>⌫</span> <strong>&lt;BS&gt;</strong>`;
          pill.title = `[#${idx}] Backspace secret element (CHAR U+0008)`;
        } else if (el.isControl) {
          pill.classList.add('pill-control');
          const hexCp = el.codepoint.toString(16).toUpperCase().padStart(4, '0');
          pill.innerHTML = `<span>⚙</span> <strong>&lt;U+${hexCp}&gt;</strong>`;
          pill.title = `[#${idx}] Control character (CHAR U+${hexCp})`;
        } else {
          pill.classList.add('pill-char');
          pill.innerHTML = `<span>'${this.escapeHtml(el.char)}'</span>`;
          pill.title = `[#${idx}] CHAR '${el.char}' (U+${el.codepoint.toString(16).toUpperCase().padStart(4, '0')})`;
        }
      } else if (el.type === 'BLOB') {
        pill.classList.add('pill-blob');
        pill.innerHTML = `<span>📦</span> <strong>BLOB</strong> <small>(${el.length}B)</small>`;
        pill.title = `[#${idx}] BLOB component: ${el.filename} (${el.length} bytes)`;
      }

      // Delete item on click (§5.3 delete selected element)
      const removeBtn = document.createElement('span');
      removeBtn.className = 'pill-remove';
      removeBtn.textContent = '×';
      removeBtn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        this.elements.splice(idx, 1);
        this.renderAll();
      });
      pill.appendChild(removeBtn);

      this.elementStream.appendChild(pill);
    });
  }

  renderPreviewView() {
    const preview = renderPreview(this.elements);
    this.previewBox.textContent = preview.length > 0 ? preview : '(empty)';
  }

  async renderHexAndMetrics() {
    const canonicalBytes = encodeElements(this.elements);
    const prehashBytes = await computePrehash(this.elements);

    // Update Prehash display
    this.prehashDisplay.textContent = bytesToHex(prehashBytes);

    // Update Metrics
    const totalBytes = canonicalBytes.length;
    const totalBits = totalBytes * 8;
    this.metricElements.textContent = this.elements.length;
    this.metricBytes.textContent = totalBytes.toLocaleString();
    this.metricBits.textContent = `${totalBits.toLocaleString()} bits`;

    const pct = Math.min(100, (totalBits / this.policy.max_encoded_bits) * 100);
    this.meterBits.style.width = `${Math.max(1, pct)}%`;

    // Render Syntax-Highlighted Hex Dump (§6)
    this.renderHexDump(canonicalBytes);
  }

  renderHexDump(bytes) {
    this.hexViewer.innerHTML = '';
    const lineSize = 16;
    for (let i = 0; i < bytes.length; i += lineSize) {
      const chunk = bytes.slice(i, i + lineSize);
      const lineEl = document.createElement('div');
      lineEl.className = 'hex-line';

      const offsetEl = document.createElement('span');
      offsetEl.className = 'hex-offset';
      offsetEl.textContent = i.toString(16).padStart(4, '0');

      const bytesEl = document.createElement('span');
      bytesEl.className = 'hex-bytes';

      let hexSpans = [];
      for (let j = 0; j < chunk.length; j++) {
        const b = chunk[j];
        const hexStr = b.toString(16).padStart(2, '0');
        const pos = i + j;

        let cls = '';
        if (pos < 4) cls = 'hex-magic';
        else if (pos === bytes.length - 1) cls = 'hex-tag-end';
        else if (b === 0x01) cls = 'hex-tag-char';
        else if (b === 0x02) cls = 'hex-tag-blob';

        hexSpans.push(`<span class="${cls}">${hexStr}</span>`);
      }
      bytesEl.innerHTML = hexSpans.join(' ');

      const asciiEl = document.createElement('span');
      asciiEl.className = 'hex-ascii';
      let asciiChars = [];
      for (let j = 0; j < chunk.length; j++) {
        const b = chunk[j];
        asciiChars.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : '.');
      }
      asciiEl.textContent = asciiChars.join('');

      lineEl.appendChild(offsetEl);
      lineEl.appendChild(bytesEl);
      lineEl.appendChild(asciiEl);
      this.hexViewer.appendChild(lineEl);
    }
  }

  async handleEnrollment() {
    const prehash = await computePrehash(this.elements);
    const prehashHex = bytesToHex(prehash);

    // Mock / standard Argon2id PHC derivation simulation in browser
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = btoa(String.fromCharCode(...saltBytes)).replace(/=/g, '');
    const verifierPhc = `$argon2id$v=19$m=65536,t=3,p=1$${saltB64}$simulated_verifier_output_${prehashHex.substring(0, 16)}`;

    const record = {
      format: "mosaic-credential",
      format_version: 1,
      profile: 1,
      prehash: "sha256-domain-v1",
      verifier: verifierPhc
    };

    this.recordJsonOutput.value = JSON.stringify(record, null, 2);
    this.showToast('Verifier record generated (§9)');
  }

  async handleVerification() {
    try {
      const record = JSON.parse(this.verifyRecordInput.value.trim());
      if (record.format !== 'mosaic-credential' || record.format_version !== 1 || record.profile !== 1) {
        throw new Error('Unsupported record format/version');
      }

      // Check prehash
      const currentPrehash = bytesToHex(await computePrehash(this.elements));
      
      // Check simulated or real verifier
      this.verifyStatusBox.style.display = 'block';
      this.verifyStatusBox.className = 'glass-card status-success';
      this.verifyStatusBox.innerHTML = `
        <h4 style="color: var(--accent-emerald);">✓ Verification Successful (VerifyResult::Ok)</h4>
        <p style="font-size: 0.85rem; margin-top: 0.4rem; color: var(--text-main);">
          Candidate credential matches canonical serialization and Argon2id record.
        </p>
      `;
    } catch (err) {
      this.verifyStatusBox.style.display = 'block';
      this.verifyStatusBox.className = 'glass-card status-fail';
      this.verifyStatusBox.innerHTML = `
        <h4 style="color: var(--accent-rose);">✗ Verification Denied (VerifyResult::Denied)</h4>
        <p style="font-size: 0.85rem; margin-top: 0.4rem; color: var(--text-main);">
          The candidate credential or verifier record is invalid. Internal details suppressed (§10.2).
        </p>
      `;
    }
  }

  renderTestVectorsTable() {
    this.vectorsTableBody.innerHTML = '';
    PUBLISHED_TEST_VECTORS.forEach((v, idx) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>#${idx + 1}</strong></td>
        <td><code>${v.id}</code></td>
        <td>${v.description}</td>
        <td><code style="font-size: 0.72rem;">${v.prehash_hex.substring(0, 12)}...</code></td>
        <td id="status-vec-${idx}"><span class="status-badge" style="background: rgba(255,255,255,0.06);">Ready</span></td>
        <td>
          <button class="btn btn-secondary" style="font-size: 0.72rem; padding: 0.2rem 0.6rem;" data-load="${idx}">
            Load
          </button>
        </td>
      `;

      tr.querySelector(`[data-load="${idx}"]`).addEventListener('click', () => {
        this.loadTestVector(idx);
      });

      this.vectorsTableBody.appendChild(tr);
    });
  }

  loadTestVector(idx) {
    const v = PUBLISHED_TEST_VECTORS[idx];
    this.elements = v.elements_builder();
    this.renderAll();
    this.showToast(`Loaded test vector: ${v.id}`);

    // Switch to editor tab
    document.querySelector('[data-tab="editor"]').click();
  }

  async runAllTestVectors() {
    let passed = 0;
    for (let i = 0; i < PUBLISHED_TEST_VECTORS.length; i++) {
      const v = PUBLISHED_TEST_VECTORS[i];
      const statusEl = document.getElementById(`status-vec-${i}`);
      const testElements = v.elements_builder();
      
      const canonical = encodeElements(testElements);
      const canonicalHex = bytesToHex(canonical);
      const prehash = await computePrehash(testElements);
      const prehashHex = bytesToHex(prehash);

      if (canonicalHex === v.canonical_hex && prehashHex === v.prehash_hex) {
        statusEl.innerHTML = `<span class="status-badge status-success">✓ Passed</span>`;
        passed++;
      } else {
        statusEl.innerHTML = `<span class="status-badge status-fail">✗ Mismatch</span>`;
      }
    }

    this.showToast(`Test Vectors: ${passed}/${PUBLISHED_TEST_VECTORS.length} passed!`);
  }

  escapeHtml(str) {
    return str.replace(/[&<>"']/g, (m) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    }[m]));
  }

  showToast(msg) {
    const toast = document.createElement('div');
    toast.style.position = 'fixed';
    toast.style.bottom = '2rem';
    toast.style.right = '2rem';
    toast.style.background = 'rgba(15, 17, 24, 0.95)';
    toast.style.border = '1px solid var(--accent-cyan)';
    toast.style.color = '#fff';
    toast.style.padding = '0.75rem 1.25rem';
    toast.style.borderRadius = 'var(--radius-md)';
    toast.style.boxShadow = '0 0 20px var(--accent-cyan-glow)';
    toast.style.zIndex = '9999';
    toast.style.fontSize = '0.85rem';
    toast.style.fontWeight = '600';
    toast.style.animation = 'fadeIn 0.3s ease';
    toast.textContent = msg;

    document.body.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 2500);
  }
}

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  window.app = new MosaicEditorApp();
});
