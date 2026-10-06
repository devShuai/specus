import { chunkLengthOf } from "./manifest";
import type { Bytes } from "./bytes";

// Received-chunk bitmap (§5): bit i is byte i >> 3, bit i & 7 (least significant first),
// ceil(chunkCount / 8) bytes, unpadded base64url with strict decoding.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP = new Map([...ALPHABET].map((character, index) => [character, index]));

export function base64UrlEncode(bytes: Uint8Array): string {
  let text = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const a = bytes[index];
    const b = index + 1 < bytes.length ? bytes[index + 1] : 0;
    const c = index + 2 < bytes.length ? bytes[index + 2] : 0;
    const triple = (a << 16) | (b << 8) | c;
    text += ALPHABET[(triple >> 18) & 63] + ALPHABET[(triple >> 12) & 63];
    if (index + 1 < bytes.length) text += ALPHABET[(triple >> 6) & 63];
    if (index + 2 < bytes.length) text += ALPHABET[triple & 63];
  }
  return text;
}

/** Strict unpadded base64url: no padding, no foreign characters, zero leftover bits. */
export function base64UrlDecodeStrict(text: string): Bytes | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    return null;
  }
  const out = new Uint8Array(Math.floor((text.length * 6) / 8));
  let buffer = 0;
  let bits = 0;
  let position = 0;
  for (const character of text) {
    buffer = (buffer << 6) | (LOOKUP.get(character) ?? 0);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[position] = (buffer >> bits) & 0xff;
      position += 1;
    }
    buffer &= (1 << bits) - 1;
  }
  if (buffer !== 0) {
    return null;
  }
  return out;
}

export type BitmapError = "BAD_ENCODING" | "BAD_LENGTH" | "TRAILING_BITS";

export class ChunkBitmap {
  readonly chunkCount: number;
  readonly bytes: Bytes;

  constructor(chunkCount: number, bytes?: Uint8Array) {
    this.chunkCount = chunkCount;
    this.bytes = new Uint8Array(Math.ceil(chunkCount / 8));
    if (bytes) {
      this.bytes.set(bytes.subarray(0, this.bytes.length));
    }
  }

  static fromIndexes(chunkCount: number, indexes: Iterable<number>): ChunkBitmap {
    const bitmap = new ChunkBitmap(chunkCount);
    for (const index of indexes) {
      bitmap.set(index);
    }
    return bitmap;
  }

  static decode(chunkCount: number, text: string): ChunkBitmap | BitmapError {
    const raw = base64UrlDecodeStrict(text);
    if (!raw) {
      return "BAD_ENCODING";
    }
    if (raw.length !== Math.ceil(chunkCount / 8)) {
      return "BAD_LENGTH";
    }
    for (let bit = chunkCount; bit < raw.length * 8; bit += 1) {
      if ((raw[bit >> 3] >> (bit & 7)) & 1) {
        return "TRAILING_BITS";
      }
    }
    return new ChunkBitmap(chunkCount, raw);
  }

  has(index: number): boolean {
    return index >= 0 && index < this.chunkCount && ((this.bytes[index >> 3] >> (index & 7)) & 1) === 1;
  }

  set(index: number) {
    if (index < 0 || index >= this.chunkCount) {
      throw new RangeError("chunk index out of range");
    }
    this.bytes[index >> 3] |= 1 << (index & 7);
  }

  clear(index: number) {
    if (index >= 0 && index < this.chunkCount) {
      this.bytes[index >> 3] &= ~(1 << (index & 7));
    }
  }

  clearAll() {
    this.bytes.fill(0);
  }

  count(): number {
    let total = 0;
    for (let index = 0; index < this.chunkCount; index += 1) {
      if (this.has(index)) total += 1;
    }
    return total;
  }

  isComplete(): boolean {
    return this.count() === this.chunkCount;
  }

  indexes(): number[] {
    const out: number[] = [];
    for (let index = 0; index < this.chunkCount; index += 1) {
      if (this.has(index)) out.push(index);
    }
    return out;
  }

  missing(): number[] {
    const out: number[] = [];
    for (let index = 0; index < this.chunkCount; index += 1) {
      if (!this.has(index)) out.push(index);
    }
    return out;
  }

  union(other: ChunkBitmap): ChunkBitmap {
    const merged = new ChunkBitmap(this.chunkCount, this.bytes);
    for (let index = 0; index < merged.bytes.length; index += 1) {
      merged.bytes[index] |= other.bytes[index] ?? 0;
    }
    return merged;
  }

  copy(): ChunkBitmap {
    return new ChunkBitmap(this.chunkCount, this.bytes);
  }

  encode(): string {
    return base64UrlEncode(this.bytes);
  }
}

export interface ResumeProgress {
  firstMissing: number | null;
  resumeOffset: number;
  receivedBytes: number;
  missing: number[];
  complete: boolean;
}

/** Display-only progress; the sender always sends from the bitmap, never from resumeOffset. */
export function resumeProgress(
  manifest: { sizeBytes: number; chunkSize: number; chunkCount: number },
  have: ChunkBitmap,
): ResumeProgress {
  const missing = have.missing();
  const firstMissing = missing.length > 0 ? missing[0] : null;
  let receivedBytes = 0;
  for (const index of have.indexes()) {
    receivedBytes += chunkLengthOf(manifest.sizeBytes, manifest.chunkSize, index);
  }
  return {
    firstMissing,
    resumeOffset: firstMissing === null ? manifest.sizeBytes : firstMissing * manifest.chunkSize,
    receivedBytes,
    missing,
    complete: missing.length === 0,
  };
}
