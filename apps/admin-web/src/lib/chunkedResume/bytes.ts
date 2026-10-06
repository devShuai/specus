/** Byte arrays that WebCrypto, Blob and IndexedDB all accept without a copy. */
export type Bytes = Uint8Array<ArrayBuffer>;

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;

export function isHex32(value: unknown): value is string {
  return typeof value === "string" && HEX32.test(value);
}

export function isHex64(value: unknown): value is string {
  return typeof value === "string" && HEX64.test(value);
}

export function toHex(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) {
    text += byte.toString(16).padStart(2, "0");
  }
  return text;
}

export function fromHex(text: string): Bytes {
  if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) {
    throw new Error("invalid hex");
  }
  const bytes = new Uint8Array(text.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function concatBytes(parts: readonly Uint8Array[]): Bytes {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

/** Copies into a fresh ArrayBuffer-backed array (DataChannel payloads may be views of a larger buffer). */
export function ownedBytes(view: Uint8Array): Bytes {
  const out = new Uint8Array(view.byteLength);
  out.set(view);
  return out;
}

export type Digest = (data: Bytes) => Promise<Bytes>;

/** SHA-256 through WebCrypto only; callers never pass more than one chunk at a time. */
export const sha256: Digest = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-256", data));

export function randomHex128(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}
