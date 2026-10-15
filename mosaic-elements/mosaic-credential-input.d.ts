/**
 * TypeScript definitions for <mosaic-credential-input>
 */

export interface MosaicElementChar {
  type: 'CHAR';
  value: number; // Unicode scalar value (e.g. 0x0008 for Backspace)
}

export interface MosaicElementBlob {
  type: 'BLOB';
  value: Uint8Array;
  name: string;
}

export type MosaicElement = MosaicElementChar | MosaicElementBlob;

export interface MosaicChangeEventDetail {
  elementCount: number;
  base64: string;
}

export class MosaicCredentialInput extends HTMLElement {
  static readonly formAssociated: boolean;

  /** Array of current credential elements in sequence */
  elements: MosaicElement[];

  /** Current visual mask state */
  masked: boolean;

  /** Current binding mode: 'portable' (default) or 'os-bound' */
  bindingMode: 'portable' | 'os-bound';

  /** Whether Secret/Stealth Mode is active (mimics a standard password field, strictly portable) */
  secretMode: boolean;

  /** Set the binding mode explicitly */
  setMode(mode: 'portable' | 'os-bound'): void;

  /** Toggle between portable and os-bound modes */
  toggleMode(): void;

  /** Add a directional arrow key (ArrowUp, ArrowDown, ArrowLeft, ArrowRight) */
  addArrow(key: 'ArrowUp' | 'ArrowDown' | 'ArrowLeft' | 'ArrowRight' | string): void;

  /** Add a function key (F1 - F12) */
  addFunctionKey(fKey: string): void;

  /** Add a single character or Unicode code point */
  addChar(char: string | number): void;

  /** Add a text string as individual scalar elements */
  addText(text: string): void;

  /** Insert a secret Backspace token (U+0008) */
  addBackspace(): void;

  /** Add raw binary BLOB (file, image, crypto seed) */
  addBlob(bytes: Uint8Array | ArrayBuffer, name?: string): void;

  /** Delete the most recent element from the sequence */
  deleteLastElement(): void;

  /** Remove an element at a specific index */
  removeElementAt(index: number): void;

  /** Clear all elements and reset input */
  clear(): void;

  /** Toggle visual privacy mask (peek / hide) */
  toggleMask(): void;

  /** Encode the current credential sequence into canonical MC v1 wire format */
  encodeCanonical(): Uint8Array;

  /** Get Base64 encoded canonical wire format string */
  getBase64(): string;

  /** Compute domain-separated SHA-256 prehash (32 bytes) */
  getPrehash(): Promise<Uint8Array>;
}

declare global {
  interface HTMLElementTagNameMap {
    'mosaic-credential-input': MosaicCredentialInput;
  }

  namespace JSX {
    interface IntrinsicElements {
      'mosaic-credential-input': any;
    }
  }
}
