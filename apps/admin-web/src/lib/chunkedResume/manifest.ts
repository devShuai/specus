import {
  CHUNK_SIZE_MAX,
  CHUNK_SIZE_MIN,
  MAX_CHUNK_COUNT,
  MAX_RESUMABLE_BYTES,
} from "./constants";
import { concatBytes, fromHex, isHex32, isHex64, sha256, toHex, type Bytes, type Digest } from "./bytes";

/** What the receiver consents to: content and the metadata shown to the user (§3). */
export interface Manifest {
  sizeBytes: number;
  chunkSize: number;
  chunkCount: number;
  fileName: string;
  mimeType: string;
  /** Concatenated 32-byte chunk digests, chunkCount * 32 bytes. */
  hashes: Bytes;
  rootSha256: Bytes;
  manifestDigest: Bytes;
}

export const DEFAULT_FILE_NAME = "attachment";
export const DEFAULT_MIME_TYPE = "application/octet-stream";

const DIGEST_DOMAIN = new TextEncoder().encode("STFR1-manifest\u0000");

export function chunkCountOf(sizeBytes: number, chunkSize: number): number {
  return Math.ceil(sizeBytes / chunkSize);
}

export function chunkLengthOf(sizeBytes: number, chunkSize: number, index: number): number {
  return Math.min(chunkSize, sizeBytes - index * chunkSize);
}

export function chunkHash(hashes: Uint8Array, index: number): Uint8Array {
  return hashes.subarray(index * 32, index * 32 + 32);
}

/** Binary preimage of manifestDigest; integers are big-endian. */
export function manifestPreimage(input: {
  sizeBytes: number;
  chunkSize: number;
  chunkCount: number;
  rootSha256: Uint8Array;
  fileName: string;
  mimeType: string;
}): Bytes {
  const encoder = new TextEncoder();
  const name = encoder.encode(input.fileName);
  const mime = encoder.encode(input.mimeType);
  const numbers = new Uint8Array(16);
  const view = new DataView(numbers.buffer);
  view.setUint32(0, Math.floor(input.sizeBytes / 2 ** 32));
  view.setUint32(4, input.sizeBytes >>> 0);
  view.setUint32(8, input.chunkSize);
  view.setUint32(12, input.chunkCount);
  const nameLength = new Uint8Array(2);
  new DataView(nameLength.buffer).setUint16(0, name.byteLength);
  const mimeLength = new Uint8Array(2);
  new DataView(mimeLength.buffer).setUint16(0, mime.byteLength);
  return concatBytes([DIGEST_DOMAIN, numbers, input.rootSha256, nameLength, name, mimeLength, mime]);
}

/** Builds a manifest from already computed chunk hashes. */
export async function manifestFromHashes(input: {
  sizeBytes: number;
  chunkSize: number;
  fileName: string;
  mimeType: string;
  hashes: Bytes;
}, digest: Digest = sha256): Promise<Manifest> {
  const chunkCount = chunkCountOf(input.sizeBytes, input.chunkSize);
  if (input.hashes.byteLength !== chunkCount * 32) {
    throw new Error("chunk hash list does not match the chunk count");
  }
  const rootSha256 = await digest(input.hashes);
  const manifestDigest = await digest(manifestPreimage({ ...input, chunkCount, rootSha256 }));
  return { ...input, chunkCount, rootSha256, manifestDigest };
}

/** Normalizes what the sender advertises: §3 file name and MIME rules with the existing defaults. */
export function normalizeOfferedName(fileName: string): string {
  // TextEncoder replaces lone surrogates with U+FFFD; decode the encoding so the advertised
  // name and the digested bytes are the same string.
  let name = new TextDecoder().decode(new TextEncoder().encode(fileName || DEFAULT_FILE_NAME));
  name = name.replace(/[\u0000-\u001f\u007f/\\]/g, "_");
  const encoder = new TextEncoder();
  while (encoder.encode(name).byteLength > 1024) {
    name = Array.from(name).slice(0, -1).join("");
  }
  return name || DEFAULT_FILE_NAME;
}

export function normalizeOfferedMimeType(mimeType: string): string {
  return mimeType && mimeType.length <= 255 && /^[\x20-\x7e]+$/.test(mimeType) ? mimeType : DEFAULT_MIME_TYPE;
}

export type OfferErrorCode =
  | "UNSUPPORTED_VERSION"
  | "BAD_TRANSFER_ID"
  | "BAD_SIZE"
  | "TOO_LARGE"
  | "BAD_CHUNK_SIZE"
  | "BAD_CHUNK_COUNT"
  | "TOO_MANY_CHUNKS"
  | "BAD_FILE_NAME"
  | "BAD_MIME_TYPE"
  | "BAD_DIGEST_FORMAT"
  | "MANIFEST_DIGEST_MISMATCH";

export interface ValidOffer {
  transferId: string;
  sizeBytes: number;
  chunkSize: number;
  chunkCount: number;
  fileName: string;
  mimeType: string;
  rootSha256: string;
  manifestDigest: string;
}

export type OfferValidation = { ok: true; offer: ValidOffer } | { ok: false; code: OfferErrorCode };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function validFileName(name: unknown): name is string {
  if (typeof name !== "string") {
    return false;
  }
  const length = new TextEncoder().encode(name).byteLength;
  if (length < 1 || length > 1024) {
    return false;
  }
  for (const character of name) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f || character === "/" || character === "\\") {
      return false;
    }
  }
  return true;
}

function validMimeType(mime: unknown): mime is string {
  return typeof mime === "string" && mime.length >= 1 && mime.length <= 255 && /^[\x20-\x7e]+$/.test(mime);
}

/** Receiver-side validation of a resumable file-meta, in the order and with the codes of §3. */
export async function validateOffer(offer: unknown, digest: Digest = sha256): Promise<OfferValidation> {
  const message = isRecord(offer) ? offer : {};
  const resume = message.resume;
  if (!isRecord(resume) || resume.version !== 1) {
    return { ok: false, code: "UNSUPPORTED_VERSION" };
  }
  if (!isHex32(message.transferId)) {
    return { ok: false, code: "BAD_TRANSFER_ID" };
  }
  const sizeBytes = message.sizeBytes;
  if (!isSafeNonNegativeInteger(sizeBytes)) {
    return { ok: false, code: "BAD_SIZE" };
  }
  if (sizeBytes > MAX_RESUMABLE_BYTES) {
    return { ok: false, code: "TOO_LARGE" };
  }
  const chunkSize = resume.chunkSize;
  if (!isSafeNonNegativeInteger(chunkSize) || chunkSize < CHUNK_SIZE_MIN || chunkSize > CHUNK_SIZE_MAX
    || (chunkSize & (chunkSize - 1)) !== 0) {
    return { ok: false, code: "BAD_CHUNK_SIZE" };
  }
  const chunkCount = resume.chunkCount;
  if (!isSafeNonNegativeInteger(chunkCount) || chunkCount !== chunkCountOf(sizeBytes, chunkSize)) {
    return { ok: false, code: "BAD_CHUNK_COUNT" };
  }
  if (chunkCount > MAX_CHUNK_COUNT) {
    return { ok: false, code: "TOO_MANY_CHUNKS" };
  }
  if (!validFileName(message.fileName)) {
    return { ok: false, code: "BAD_FILE_NAME" };
  }
  if (!validMimeType(message.mimeType)) {
    return { ok: false, code: "BAD_MIME_TYPE" };
  }
  if (!isHex64(resume.rootSha256) || !isHex64(resume.manifestDigest)) {
    return { ok: false, code: "BAD_DIGEST_FORMAT" };
  }
  const expected = await digest(manifestPreimage({
    sizeBytes,
    chunkSize,
    chunkCount,
    rootSha256: fromHex(resume.rootSha256),
    fileName: message.fileName,
    mimeType: message.mimeType,
  }));
  if (toHex(expected) !== resume.manifestDigest) {
    return { ok: false, code: "MANIFEST_DIGEST_MISMATCH" };
  }
  return {
    ok: true,
    offer: {
      transferId: message.transferId,
      sizeBytes,
      chunkSize,
      chunkCount,
      fileName: message.fileName,
      mimeType: message.mimeType,
      rootSha256: resume.rootSha256,
      manifestDigest: resume.manifestDigest,
    },
  };
}

/** The resumable file-meta a sender advertises; sha256 stays null in v1 (§14 item 5). */
export function fileMetaMessage(transferId: string, manifest: Manifest) {
  return {
    kind: "file-meta",
    transferId,
    fileName: manifest.fileName,
    mimeType: manifest.mimeType,
    sizeBytes: manifest.sizeBytes,
    sha256: null,
    resume: {
      version: 1,
      chunkSize: manifest.chunkSize,
      chunkCount: manifest.chunkCount,
      rootSha256: toHex(manifest.rootSha256),
      manifestDigest: toHex(manifest.manifestDigest),
    },
  };
}
