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
}
