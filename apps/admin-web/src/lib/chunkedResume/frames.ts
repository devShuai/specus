import { FRAME_HEADER_BYTES, FRAME_MAX_BYTES } from "./constants";
import { fromHex, toHex, type Bytes } from "./bytes";

// STFR1 binary frames on the bulk DataChannel (§4). Control messages stay JSON text.

export const FRAME_TYPE_HASHES = 1;
export const FRAME_TYPE_DATA = 2;
const MAGIC = [0x53, 0x54, 0x46, 0x52]; // "STFR"

export type FrameErrorCode =
  | "TRUNCATED"
  | "TOO_LARGE"
  | "BAD_MAGIC"
  | "BAD_VERSION"
  | "BAD_TYPE"
  | "BAD_FLAGS"
  | "LENGTH_MISMATCH"
  | "EMPTY_PAYLOAD"
  | "BAD_HASHES_LAYOUT";

export interface DecodedFrame {
  type: "HASHES" | "DATA";
  transferId: string;
  index: number;
  offset: number;
  payload: Uint8Array;
}

export type FrameDecodeResult = { ok: true; frame: DecodedFrame } | { ok: false; error: FrameErrorCode };

export function encodeFrame(
  type: typeof FRAME_TYPE_HASHES | typeof FRAME_TYPE_DATA,
  transferId: string,
  index: number,
  offset: number,
  payload: Uint8Array,
): ArrayBuffer {
  const frame: Bytes = new Uint8Array(FRAME_HEADER_BYTES + payload.byteLength);
  const view = new DataView(frame.buffer);
  frame.set(MAGIC, 0);
  frame[4] = 1;
  frame[5] = type;
  view.setUint16(6, 0);
  frame.set(fromHex(transferId), 8);
  view.setUint32(24, index);
  view.setUint32(28, offset);
  view.setUint32(32, payload.byteLength);
  frame.set(payload, FRAME_HEADER_BYTES);
  return frame.buffer;
}

/** Decodes one frame with the checks of §4 in their normative order. */
export function decodeFrame(data: ArrayBuffer | Uint8Array): FrameDecodeResult {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  if (bytes.byteLength < FRAME_HEADER_BYTES) {
    return { ok: false, error: "TRUNCATED" };
  }
  if (bytes.byteLength > FRAME_MAX_BYTES) {
    return { ok: false, error: "TOO_LARGE" };
  }
  if (!isFrameMagic(bytes)) {
    return { ok: false, error: "BAD_MAGIC" };
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes[4] !== 1) {
    return { ok: false, error: "BAD_VERSION" };
  }
  const type = bytes[5];
  if (type !== FRAME_TYPE_HASHES && type !== FRAME_TYPE_DATA) {
    return { ok: false, error: "BAD_TYPE" };
  }
  if (view.getUint16(6) !== 0) {
    return { ok: false, error: "BAD_FLAGS" };
  }
  const index = view.getUint32(24);
  const offset = view.getUint32(28);
  const length = view.getUint32(32);
  if (FRAME_HEADER_BYTES + length !== bytes.byteLength) {
    return { ok: false, error: "LENGTH_MISMATCH" };
  }
  if (length === 0) {
    return { ok: false, error: "EMPTY_PAYLOAD" };
  }
  if (type === FRAME_TYPE_HASHES && (offset !== 0 || length % 32 !== 0)) {
    return { ok: false, error: "BAD_HASHES_LAYOUT" };
  }
  return {
    ok: true,
    frame: {
      type: type === FRAME_TYPE_HASHES ? "HASHES" : "DATA",
      transferId: toHex(bytes.subarray(8, 24)),
      index,
      offset,
      payload: bytes.subarray(FRAME_HEADER_BYTES),
    },
  };
}

export function isFrameMagic(bytes: Uint8Array): boolean {
  return bytes.byteLength >= 4 && MAGIC.every((value, index) => bytes[index] === value);
}

/** Largest frame a sender may emit: min(64 KiB, negotiated SCTP maxMessageSize). */
export function maxFrameBytes(maxMessageSize: number | null | undefined): number {
  if (!Number.isFinite(maxMessageSize) || !maxMessageSize || maxMessageSize <= FRAME_HEADER_BYTES + 32) {
    return FRAME_MAX_BYTES;
  }
  return Math.min(FRAME_MAX_BYTES, maxMessageSize);
}

/** HASHES frames covering the whole list; each frame holds whole 32-byte digests. */
export function encodeHashFrames(transferId: string, hashes: Uint8Array, frameBytes: number): ArrayBuffer[] {
  const perFrame = Math.max(1, Math.floor((frameBytes - FRAME_HEADER_BYTES) / 32));
  const count = hashes.byteLength / 32;
  const frames: ArrayBuffer[] = [];
  for (let index = 0; index < count; index += perFrame) {
    const end = Math.min(count, index + perFrame);
    frames.push(encodeFrame(FRAME_TYPE_HASHES, transferId, index, 0, hashes.subarray(index * 32, end * 32)));
  }
  return frames;
}

/** DATA frames for one chunk, contiguous from offset 0 and never crossing the chunk. */
export function encodeChunkFrames(transferId: string, index: number, chunk: Uint8Array, frameBytes: number): ArrayBuffer[] {
  const payloadBytes = Math.max(1, frameBytes - FRAME_HEADER_BYTES);
  const frames: ArrayBuffer[] = [];
  for (let offset = 0; offset < chunk.byteLength; offset += payloadBytes) {
    frames.push(encodeFrame(FRAME_TYPE_DATA, transferId, index, offset,
      chunk.subarray(offset, Math.min(chunk.byteLength, offset + payloadBytes))));
  }
  return frames;
}
