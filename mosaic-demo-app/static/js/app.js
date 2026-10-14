/**
 * Mosaic Credential Full-Stack Test Site — Frontend Controller
 */

// Helper: convert Uint8Array to Hex string
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Credential Form State Manager
class CredentialFormManager {
  constructor(options) {
    this.prefix = options.prefix; // 'reg' or 'login'
    this.elements = [];
    this.mode = 'credential'; // 'credential' | 'edit'

    this.inputEl = document.getElementById(`${this.prefix}-input`);
    this.modeCredBtn = document.getElementById(`${this.prefix}-mode-cred`);
    this.modeEditBtn = document.getElementById(`${this.prefix}-mode-edit`);
    this.streamEl = document.getElementById(`${this.prefix}-stream`);
    this.previewEl = document.getElementById(`${this.prefix}-preview`);
    this.dropzoneEl = document.getElementById(`${this.prefix}-dropzone`);
    this.filePickerEl = document.getElementById(`${this.prefix}-file-picker`);
    this.addBsBtn = document.getElementById(`${this.prefix}-add-bs`);
    this.removeLastBtn = document.getElementById(`${this.prefix}-remove-last`);
    this.clearBtn = document.getElementById(`${this.prefix}-clear`);

    this.bindEvents();
    this.render();
  }

  bindEvents() {
    this.modeCredBtn.addEventListener('click', () => {
      this.mode = 'credential';
      this.modeCredBtn.classList.add('active');
      this.modeEditBtn.classList.remove('active');
      this.inputEl.focus();
    });

    this.modeEditBtn.addEventListener('click', () => {
      this.mode = 'edit';
      this.modeEditBtn.classList.add('active');
      this.modeCredBtn.classList.remove('active');
      this.inputEl.focus();
    });

    this.inputEl.addEventListener('keydown', (e) => {
      if (this.mode === 'credential') {
        if (e.key === 'Backspace') {
          e.preventDefault();
          this.addChar(0x0008);
        } else if (e.key === 'Enter') {
          e.preventDefault();
          this.addChar(10); // '\n'
        } else if (e.key === 'Tab') {
          e.preventDefault();
          this.addChar(9); // '\t'
        }
      }
    });

    this.inputEl.addEventListener('input', () => {
      const val = this.inputEl.value;
      if (val) {
        for (const ch of val) {
          this.elements.push({
            type: 'CHAR',
            char: ch,
            codepoint: ch.codePointAt(0),
            isBackspace: ch.codePointAt(0) === 8
          });
        }
        this.inputEl.value = '';
        this.render();
      }
    });

    this.addBsBtn.addEventListener('click', () => {
      this.addChar(0x0008);
      this.inputEl.focus();
    });

    this.removeLastBtn.addEventListener('click', () => {
      if (this.elements.length > 0) {
        this.elements.pop();
        this.render();
      }
      this.inputEl.focus();
    });

    this.clearBtn.addEventListener('click', () => {
      this.elements = [];
      this.render();
      this.inputEl.focus();
    });

    this.dropzoneEl.addEventListener('click', () => this.filePickerEl.click());

    this.dropzoneEl.addEventListener('dragover', (e) => {
      e.preventDefault();
      this.dropzoneEl.classList.add('dragover');
    });

    this.dropzoneEl.addEventListener('dragleave', () => {
      this.dropzoneEl.classList.remove('dragover');
    });

    this.dropzoneEl.addEventListener('drop', (e) => {
      e.preventDefault();
      this.dropzoneEl.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) {
        this.handleFiles(e.dataTransfer.files);
      }
    });

    this.filePickerEl.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        this.handleFiles(e.target.files);
        this.filePickerEl.value = '';
      }
    });
  }

  addChar(cp) {
    this.elements.push({
      type: 'CHAR',
      char: String.fromCodePoint(cp),
      codepoint: cp,
      isBackspace: cp === 8
    });
    this.render();
  }

  async handleFiles(files) {
    for (const file of files) {
      const buffer = await file.arrayBuffer();
      const u8 = new Uint8Array(buffer);
      this.elements.push({
        type: 'BLOB',
        hex: bytesToHex(u8),
        filename: file.name,
        length: u8.length
      });
    }
    this.render();
  }

  setElements(newElements) {
    this.elements = newElements;
    this.render();
  }

  getPayload() {
    return this.elements.map(el => {
      if (el.type === 'CHAR') {
        return { type: 'CHAR', char: el.char, codepoint: el.codepoint };
      } else {
        return { type: 'BLOB', hex: el.hex, filename: el.filename };
      }
    });
  }

  render() {
    // 1. Structural stream view
    this.streamEl.innerHTML = '';
    if (this.elements.length === 0) {
      this.streamEl.innerHTML = '<span style="color: var(--text-dim); font-size: 0.82rem; padding: 0.2rem;">(Empty secret. Type text or drop files)</span>';
    } else {
      this.elements.forEach((el, idx) => {
        const pill = document.createElement('span');
        pill.className = 'element-pill';
        if (el.type === 'CHAR') {
          if (el.isBackspace) {
            pill.classList.add('pill-bs');
            pill.innerHTML = `⌫ &lt;BS&gt;`;
          } else {
            pill.classList.add('pill-char');
            pill.textContent = `'${el.char}'`;
          }
        } else if (el.type === 'BLOB') {
          pill.classList.add('pill-blob');
          pill.innerHTML = `📦 ${el.filename || 'blob'} (${el.length || el.hex.length/2}B)`;
        }

        const del = document.createElement('span');
        del.className = 'pill-del';
        del.textContent = '×';
        del.addEventListener('click', (ev) => {
          ev.stopPropagation();
          this.elements.splice(idx, 1);
          this.render();
        });
        pill.appendChild(del);
        this.streamEl.appendChild(pill);
      });
    }

    // 2. Display preview (§5.2)
    const previewChars = [];
    for (const el of this.elements) {
      if (el.type === 'CHAR') {
        if (el.isBackspace) {
          if (previewChars.length > 0) previewChars.pop();
        } else {
          previewChars.push(el.char);
        }
      } else if (el.type === 'BLOB') {
        previewChars.push(`[BLOB:${el.length || el.hex.length/2}B]`);
      }
    }
    this.previewEl.textContent = previewChars.length > 0 ? previewChars.join('') : '(empty)';
  }
}

// App Controller
class DemoApp {
  constructor() {
    this.regManager = new CredentialFormManager({ prefix: 'reg' });
    this.loginManager = new CredentialFormManager({ prefix: 'login' });

    this.initTabs();
    this.initForms();
    this.initPresets();
    this.loadDatabase();
  }

  initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const panes = document.querySelectorAll('.tab-pane');

    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        tabBtns.forEach(b => b.classList.remove('active'));
        panes.forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`tab-${tab}`).classList.add('active');

        if (tab === 'database') {
          this.loadDatabase();
        }
      });
    });
  }

  initForms() {
    // Registration Form Submit
    document.getElementById('btn-submit-register').addEventListener('click', async () => {
      const username = document.getElementById('reg-username').value.trim();
      const statusBox = document.getElementById('reg-status');

      if (!username) {
        statusBox.className = 'status-alert status-alert-error';
        statusBox.textContent = 'Please enter a username.';
        statusBox.style.display = 'block';
        return;
      }

      statusBox.style.display = 'none';

      try {
        const res = await fetch('/api/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: username,
            elements: this.regManager.getPayload(),
            fast_mode: true
          })
        });

        const data = await res.json();
        if (data.success) {
          statusBox.className = 'status-alert status-alert-success';
          statusBox.innerHTML = `
            <strong>✓ Registration Successful!</strong><br>
            User <code>${data.username}</code> (ID: ${data.user_id}) stored in SQLite.<br>
            <strong>Storage Footprint in DB:</strong> <span class="size-chip">${data.storage_size_bytes} bytes</span> (${data.element_count} elements)<br>
            <details style="margin-top: 0.5rem; font-size: 0.78rem;">
              <summary style="cursor: pointer; color: var(--accent-cyan);">View Stored VerifierRecord JSON (§9)</summary>
              <pre style="background: rgba(0,0,0,0.5); padding: 0.5rem; border-radius: 4px; margin-top: 0.4rem; overflow: auto;">${JSON.stringify(data.stored_record, null, 2)}</pre>
            </details>
          `;
          statusBox.style.display = 'block';

          // Auto-fill login username
          document.getElementById('login-username').value = username;

          // Reload DB list
          this.loadDatabase();
        } else {
          statusBox.className = 'status-alert status-alert-error';
          statusBox.textContent = `Registration Failed: ${data.error}`;
          statusBox.style.display = 'block';
        }
      } catch (err) {
        statusBox.className = 'status-alert status-alert-error';
        statusBox.textContent = `Server error: ${err.message}`;
        statusBox.style.display = 'block';
      }
    });

    // Login Form Submit
    document.getElementById('btn-submit-login').addEventListener('click', async () => {
      const username = document.getElementById('login-username').value.trim();
      const statusBox = document.getElementById('login-status');

      if (!username) {
        statusBox.className = 'status-alert status-alert-error';
        statusBox.textContent = 'Please enter a username.';
        statusBox.style.display = 'block';
        return;
      }

      statusBox.style.display = 'none';

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: username,
            elements: this.loginManager.getPayload()
          })
        });

        const data = await res.json();
        if (data.success) {
          statusBox.className = 'status-alert status-alert-success';
          statusBox.innerHTML = `
            <div style="font-size: 1.1rem; font-weight: 700;">🎉 Authentication Successful (VerifyResult::OK)</div>
            <div style="font-size: 0.88rem; margin-top: 0.3rem;">Welcome back, <strong>${data.user.username}</strong>! User verified against stored Argon2id verifier in SQLite.</div>
          `;
          statusBox.style.display = 'block';
        } else {
          statusBox.className = 'status-alert status-alert-error';
          statusBox.innerHTML = `
            <div style="font-weight: 700;">✗ Authentication Denied (VerifyResult::DENIED)</div>
            <div style="font-size: 0.85rem; margin-top: 0.2rem;">${data.message}</div>
          `;
          statusBox.style.display = 'block';
        }
      } catch (err) {
        statusBox.className = 'status-alert status-alert-error';
        statusBox.textContent = `Server error: ${err.message}`;
        statusBox.style.display = 'block';
      }
    });

    // Reset DB button
    document.getElementById('btn-reset-db').addEventListener('click', async () => {
      if (confirm('Clear all users from the SQLite database?')) {
        await fetch('/api/database/reset', { method: 'POST' });
        this.loadDatabase();
      }
    });
  }

  initPresets() {
    document.getElementById('preset-alice').addEventListener('click', () => {
      document.getElementById('reg-username').value = 'alice';
      const els = [
        { type: 'CHAR', char: 'P', codepoint: 80 },
        { type: 'CHAR', char: 'a', codepoint: 97 },
        { type: 'CHAR', char: 's', codepoint: 115 },
        { type: 'CHAR', char: 's', codepoint: 115 },
        { type: 'CHAR', char: '\u0008', codepoint: 8, isBackspace: true },
        { type: 'CHAR', char: '\u0008', codepoint: 8, isBackspace: true },
        { type: 'CHAR', char: '\u0008', codepoint: 8, isBackspace: true },
        { type: 'CHAR', char: 'w', codepoint: 119 },
        { type: 'CHAR', char: 'o', codepoint: 111 },
        { type: 'CHAR', char: 'r', codepoint: 114 },
        { type: 'CHAR', char: 'd', codepoint: 100 },
      ];
      this.regManager.setElements(els);
      document.querySelector('[data-tab="register"]').click();
    });

    document.getElementById('preset-bob').addEventListener('click', () => {
      document.getElementById('reg-username').value = 'bob';
      const fakeImageBytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]);
      const els = [
        { type: 'CHAR', char: 'B', codepoint: 66 },
        { type: 'CHAR', char: 'o', codepoint: 111 },
        { type: 'CHAR', char: 'b', codepoint: 98 },
        { type: 'BLOB', hex: bytesToHex(fakeImageBytes), filename: 'avatar.png', length: fakeImageBytes.length },
        { type: 'CHAR', char: '9', codepoint: 57 },
        { type: 'CHAR', char: '9', codepoint: 57 },
      ];
      this.regManager.setElements(els);
      document.querySelector('[data-tab="register"]').click();
    });

    document.getElementById('preset-charlie').addEventListener('click', () => {
      document.getElementById('reg-username').value = 'charlie';
      const els = [
        { type: 'CHAR', char: '🦀', codepoint: 0x1F980 },
        { type: 'CHAR', char: '🔑', codepoint: 0x1F511 },
        { type: 'CHAR', char: '©', codepoint: 0x00A9 },
        { type: 'CHAR', char: '\0', codepoint: 0 },
      ];
      this.regManager.setElements(els);
      document.querySelector('[data-tab="register"]').click();
    });
  }

  async loadDatabase() {
    const tbody = document.getElementById('db-users-body');
    const countEl = document.getElementById('db-user-count');
    const pathEl = document.getElementById('db-file-path');

    try {
      const res = await fetch('/api/database');
      const data = await res.json();

      countEl.textContent = `${data.count} registered user(s)`;
      pathEl.textContent = data.database_file;
      tbody.innerHTML = '';

      if (data.users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">Database is empty. Register a user above to see their record stored!</td></tr>';
        return;
      }

      data.users.forEach(u => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>#${u.id}</strong></td>
          <td><strong style="color: var(--text-bright);">${u.username}</strong></td>
          <td><span class="size-chip">${u.size_bytes} bytes</span></td>
          <td><div class="json-preview">${JSON.stringify(u.record)}</div></td>
          <td style="font-size: 0.78rem; color: var(--text-dim);">${u.created_at}</td>
          <td>
            <button class="btn btn-secondary" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;" data-copy="${u.id}">Copy</button>
            <button class="btn btn-danger" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;" data-del="${u.id}">Delete</button>
          </td>
        `;

        tr.querySelector(`[data-copy="${u.id}"]`).addEventListener('click', () => {
          navigator.clipboard.writeText(JSON.stringify(u.record, null, 2));
          alert(`Copied VerifierRecord JSON for ${u.username}`);
        });

        tr.querySelector(`[data-del="${u.id}"]`).addEventListener('click', async () => {
          if (confirm(`Delete user ${u.username}?`)) {
            await fetch('/api/database/delete', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ id: u.id })
            });
            this.loadDatabase();
          }
        });

        tbody.appendChild(tr);
      });

    } catch (err) {
      console.error(err);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.demoApp = new DemoApp();
});
