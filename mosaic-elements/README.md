# @mosaic-credentials/elements

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Try%20it%20Online-6366f1?style=for-the-badge&logo=googlechrome&logoColor=white)](https://ecch1ch1.github.io/Mosaic-Credentials/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success)](https://www.npmjs.com/package/@mosaic-credentials/elements)

Drop-in Web Component (`<mosaic-credential-input>`) for creating unbruteforceable, multi-modal authentication secrets directly in web applications.

Works seamlessly in **plain HTML, React, Vue, Svelte, Angular**, or any web framework.

---

## 🚀 Quick Start

### 1. Installation

#### Via npm:
```bash
npm install @mosaic-credentials/elements
```

```javascript
// Import into your JS/TS bundle
import '@mosaic-credentials/elements';
```

#### Via CDN (No Build Tool Required):
```html
<script src="https://cdn.jsdelivr.net/npm/@mosaic-credentials/elements/mosaic-credential-input.js"></script>
```

---

## 💡 Usage

Drop the element into any standard HTML `<form>` just like a regular `<input>`:

```html
<form action="/api/login" method="POST">
  <label for="username">Username</label>
  <input type="text" id="username" name="username" required />

  <label for="pwd">Mosaic Secret</label>
  <mosaic-credential-input 
    id="pwd" 
    name="credential" 
    placeholder="Type secret or drop files here...">
  </mosaic-credential-input>

  <button type="submit">Sign In</button>
</form>
```

When submitted, the form automatically contains the canonical Base64-encoded binary credential under the `name` key (`credential`).

---

## 🎨 Styling & Theming

### Option A: CSS Custom Properties (High-level)
The component uses Shadow DOM for isolation, but provides clean CSS custom properties for styling:

```css
mosaic-credential-input {
  --mosaic-bg: #161822;         /* Background color */
  --mosaic-border: #2d3148;     /* Border color */
  --mosaic-focus: #6366f1;      /* Glow / Focus border */
  --mosaic-text: #f1f5f9;       /* Input text color */
  --mosaic-muted: #94a3b8;      /* Placeholder & secondary text */
  --mosaic-accent: #6366f1;     /* Accent buttons */
  --mosaic-radius: 8px;         /* Corner roundness */
}
```

### Option B: CSS Shadow Parts (`::part()`) for Complete Customization
For 100% fine-grained control over internal DOM elements without modifying the library, target exposed Shadow Parts directly from your external stylesheet:

```css
/* Style the entire wrapper container */
mosaic-credential-input::part(container) {
  border-radius: 12px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
}

/* Style the text/token input row */
mosaic-credential-input::part(input-row) {
  padding: 10px 14px;
}

/* Style individual token badges */
mosaic-credential-input::part(token) {
  font-weight: 600;
  border-radius: 6px;
}

/* Style the native text input */
mosaic-credential-input::part(input) {
  font-family: inherit;
}

/* Style the quick clear (✕) button */
mosaic-credential-input::part(clear-btn) {
  color: #f87171;
}

/* Style the file exactness / provenance notice */
mosaic-credential-input::part(file-note) {
  background: rgba(99, 102, 241, 0.08);
  border-color: rgba(99, 102, 241, 0.2);
}

/* Style the toolbar and indicators */
mosaic-credential-input::part(toolbar) {
  background: transparent;
}
mosaic-credential-input::part(status) {
  font-size: 11px;
}
```

---

## ✕ Quick Clear Button & Reset Peace of Mind

Because Backspace inserts a secret keystroke scalar (`U+0008`) rather than deleting previous elements, `<mosaic-credential-input>` provides an integrated **Quick-Clear button (`✕`)** inside the input row:
* Automatically becomes visible as soon as any content or text is entered.
* Available in both **Visual Mode** and **Secret Mode**.
* Clicking `✕` resets all internal elements, empties the input field, and fires change events so users are 100% confident their sequence has been completely wiped.
* In Secret Mode, pressing `Ctrl+A` / `Cmd+A` followed by Backspace also triggers a full sequence reset.

---

## 📎 File Exactness & Provenance Notice

In Visual Mode, the component displays an informative notice:
> ℹ️ **File Exactness:** Files must be exact byte-for-byte originals. Chat apps (WhatsApp, Messenger) recompress media and strip metadata, which alters the credential.

This helps prevent accidental login failures caused by photo recompression or cloud sync stripping EXIF metadata. In **Secret Mode**, this notice is automatically and completely hidden to preserve full stealth.

---

## 🕵️ Secret / Stealth Mode

When developers want a credential field that visually looks and behaves like a traditional `<input type="password">` (with standard bullet masking and no visible token badges or toolbars), add the `secret-mode` or `stealth` attribute:

```html
<mosaic-credential-input name="password" secret-mode placeholder="Enter password"></mosaic-credential-input>
```

* **Plausible Deniability & Shoulder-Surf Resistance**: Observers see only standard password bullets `••••••`.
* **Secret Backspaces (`U+0008`)**: If a user hits Backspace, a bullet visually disappears from the screen, but the Backspace scalar is secretly preserved in the framed sequence. Anyone observing over the user's shoulder will fail authentication.
* **Integrated Clear (`✕`)**: A subtle reset button allows clearing the input without leaking sequence length.
* **Strictly Portable**: Secret mode automatically enforces portable Canonical PUA keys and disables OS-specific binding.
* **Select-All Reset**: Pressing `Ctrl+A` / `Cmd+A` followed by Backspace completely clears the credential sequence.

---

## 🧩 Programmatic JavaScript API

You can also interact with the element directly via JavaScript:

```javascript
const input = document.querySelector('mosaic-credential-input');

// Add text
input.addText("Pass");

// Add secret Backspace token (U+0008)
input.addBackspace();

// Add binary file / BLOB
input.addBlob(uint8ArrayData, "seed.bin");

// Get Base64 encoded MC v1 wire format
const base64Payload = input.getBase64();

// Compute domain-separated SHA-256 prehash
const prehashBytes = await input.getPrehash();

// Clear input
input.clear();
```

---

## 📄 License

Licensed under the [Mozilla Public License 2.0 (MPL-2.0)](../LICENSE).
