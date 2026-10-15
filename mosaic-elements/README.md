# @mosaic-credentials/elements

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

## 🎨 Styling with CSS Variables

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

---

## 🕵️ Secret / Stealth Mode

When developers want a credential field that visually looks and behaves like a traditional `<input type="password">` (with standard bullet masking and no visible token badges or toolbars), add the `secret-mode` or `stealth` attribute:

```html
<mosaic-credential-input name="password" secret-mode placeholder="Enter password"></mosaic-credential-input>
```

* **Plausible Deniability & Shoulder-Surf Resistance**: Observers see only standard password bullets `••••••`.
* **Secret Backspaces (`U+0008`)**: If a user hits Backspace, a bullet visually disappears from the screen, but the Backspace scalar is secretly preserved in the framed sequence. Anyone observing over the user's shoulder will fail authentication.
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
