/**
 * Mosaic Credential Full-Stack Test Site — Frontend Controller
 * Powered by <mosaic-credential-input> Web Component & SQLite backend
 */

class DemoApp {
  constructor() {
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
      const regInput = document.getElementById('reg-cred-input');

      if (!username) {
        statusBox.className = 'status-alert status-alert-error';
        statusBox.textContent = 'Please enter a username.';
        statusBox.style.display = 'block';
        return;
      }

      statusBox.style.display = 'none';

      try {
        const b64Payload = regInput.getBase64();
        const kdfMode = document.getElementById('reg-kdf-mode')?.value || 'prod';
        const res = await fetch('/api/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: username,
            credential_base64: b64Payload,
            fast_mode: (kdfMode === 'fast')
          })
        });

        const data = await res.json();
        if (data.success) {
          const memStr = data.params && data.params.memory_cost_kib >= 65536 ? '64 MiB (OWASP Recommended)' : `${data.params?.memory_cost_kib || 256} KiB (Fast Testing)`;
          statusBox.className = 'status-alert status-alert-success';
          statusBox.innerHTML = `
            <strong>✓ Registration Successful!</strong><br>
            User <code>${data.username}</code> (ID: ${data.user_id}) stored in SQLite.<br>
            <strong>Argon2id KDF:</strong> <span class="size-chip">${memStr}</span> (t=${data.params?.iterations || 3}, p=${data.params?.parallelism || 1})<br>
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
      const loginInput = document.getElementById('login-cred-input');

      if (!username) {
        statusBox.className = 'status-alert status-alert-error';
        statusBox.textContent = 'Please enter a username.';
        statusBox.style.display = 'block';
        return;
      }

      statusBox.style.display = 'none';

      try {
        const b64Payload = loginInput.getBase64();
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: username,
            credential_base64: b64Payload
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

    // Secret Mode Registration Form Submit
    document.getElementById('btn-submit-secret-register').addEventListener('click', async () => {
      const username = document.getElementById('secret-reg-username').value.trim();
      const statusBox = document.getElementById('secret-reg-status');
      const regInput = document.getElementById('secret-reg-cred-input');

      if (!username) {
        statusBox.className = 'status-alert status-alert-error';
        statusBox.textContent = 'Please enter a username for secret registration.';
        statusBox.style.display = 'block';
        return;
      }

      statusBox.style.display = 'none';

      try {
        const b64Payload = regInput.getBase64();
        const kdfMode = document.getElementById('secret-reg-kdf-mode')?.value || 'prod';
        const res = await fetch('/api/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: username,
            credential_base64: b64Payload,
            fast_mode: (kdfMode === 'fast')
          })
        });

        const data = await res.json();
        if (data.success) {
          const memStr = data.params && data.params.memory_cost_kib >= 65536 ? '64 MiB (OWASP Recommended)' : `${data.params?.memory_cost_kib || 256} KiB (Fast Testing)`;
          statusBox.className = 'status-alert status-alert-success';
          statusBox.innerHTML = `
            <strong>✓ Stealth Registration Successful!</strong><br>
            User <code>${data.username}</code> stored in SQLite via stealth password input.<br>
            <strong>Argon2id KDF:</strong> <span class="size-chip">${memStr}</span> (t=${data.params?.iterations || 3}, p=${data.params?.parallelism || 1})<br>
            <strong>Storage Footprint in DB:</strong> <span class="size-chip">${data.storage_size_bytes} bytes</span> (${data.element_count} elements)<br>
            <details style="margin-top: 0.5rem; font-size: 0.78rem;">
              <summary style="cursor: pointer; color: var(--accent-cyan);">View Stored VerifierRecord JSON (§9)</summary>
              <pre style="background: rgba(0,0,0,0.5); padding: 0.5rem; border-radius: 4px; margin-top: 0.4rem; overflow: auto;">${JSON.stringify(data.stored_record, null, 2)}</pre>
            </details>
          `;
          statusBox.style.display = 'block';

          // Auto-fill login username
          document.getElementById('secret-login-username').value = data.username;

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

    // Secret Mode Login Form Submit
    document.getElementById('btn-submit-secret-login').addEventListener('click', async () => {
      const username = document.getElementById('secret-login-username').value.trim();
      const statusBox = document.getElementById('secret-login-status');
      const loginInput = document.getElementById('secret-login-cred-input');

      if (!username) {
        statusBox.className = 'status-alert status-alert-error';
        statusBox.textContent = 'Please enter a username.';
        statusBox.style.display = 'block';
        return;
      }

      statusBox.style.display = 'none';

      try {
        const b64Payload = loginInput.getBase64();
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: username,
            credential_base64: b64Payload
          })
        });

        const data = await res.json();
        if (data.success) {
          statusBox.className = 'status-alert status-alert-success';
          statusBox.innerHTML = `
            <div style="font-size: 1.1rem; font-weight: 700;">🎉 Stealth Authentication Successful (VerifyResult::OK)</div>
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
    // Preset: Alice (Pass<BS><BS><BS>word)
    document.getElementById('preset-alice').addEventListener('click', () => {
      document.getElementById('reg-username').value = 'alice';
      const regInput = document.getElementById('reg-cred-input');
      regInput.clear();
      regInput.addText("Pass");
      regInput.addBackspace();
      regInput.addBackspace();
      regInput.addBackspace();
      regInput.addText("word");
      document.querySelector('[data-tab="register"]').click();
    });

    // Preset: Bob (Bob + Binary PNG header + 99)
    document.getElementById('preset-bob').addEventListener('click', () => {
      document.getElementById('reg-username').value = 'bob';
      const fakeImageBytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]);
      const regInput = document.getElementById('reg-cred-input');
      regInput.clear();
      regInput.addText("Bob");
      regInput.addBlob(fakeImageBytes, "avatar.png");
      regInput.addText("99");
      document.querySelector('[data-tab="register"]').click();
    });

    // Preset: Charlie (🦀 + ArrowUp + ArrowDown + 🔑)
    document.getElementById('preset-charlie').addEventListener('click', () => {
      document.getElementById('reg-username').value = 'charlie';
      const regInput = document.getElementById('reg-cred-input');
      regInput.clear();
      regInput.addChar("🦀");
      regInput.addArrow("ArrowUp");
      regInput.addArrow("ArrowDown");
      regInput.addChar("🔑");
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
