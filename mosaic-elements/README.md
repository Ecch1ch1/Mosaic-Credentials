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

Dual-licensed under [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE).
