export interface AppPeerMessage {
  messageType: string;
  payload?: unknown;
}

export interface EncodedAppMessage {
  messageId: string;
  frames: ArrayBuffer[];
  acknowledgementRequired: boolean;
}

export interface DecodedAppMessage {
  kind: "message";
  messageId: string;
  message: AppPeerMessage;
  acknowledgementRequired: boolean;
}

export interface DecodedAppAcknowledgement {
  kind: "ack";
  messageId: string;
}

export type DecodedAppFrame = DecodedAppMessage | DecodedAppAcknowledgement;

const APP_MAGIC = [0x53, 0x54, 0x41, 0x50] as const;
const APP_VERSION = 2;
const APP_HEADER_BYTES = 72;
const APP_FLAG_ACK_REQUIRED = 1;
const APP_TYPE_WHITEBOARD = 1;
const APP_TYPE_CLIPBOARD = 2;
const APP_TYPE_DIAGRAM = 3;
const APP_TYPE_ACK = 127;
const BODY_ENCODING_JSON = 0;
const BODY_ENCODING_JSON_BINARY = 1;
const MAX_APP_MESSAGE_BYTES = 8 * 1024 * 1024;
const MAX_REASSEMBLY_BYTES = 16 * 1024 * 1024;
const MAX_REASSEMBLIES = 32;
const MAX_CHUNKS = 2048;
const REASSEMBLY_TIMEOUT_MS = 15_000;
const DEFAULT_FRAME_BYTES = 48 * 1024;

const RELAY_MAGIC = [0x53, 0x54, 0x57, 0x52] as const;
const RELAY_VERSION = 2;
const RELAY_HEADER_BYTES = 14;
const MAX_RELAY_PEER_ID_BYTES = 512;

interface ParsedFrame {
  type: number;
  flags: number;
  messageId: string;
  chunkIndex: number;
  chunkCount: number;
  totalLength: number;
  payload: Uint8Array;
  digest: Uint8Array;
}

interface ReassemblyState {
  type: number;
  flags: number;
  totalLength: number;
  chunkCount: number;
  digest: Uint8Array;
  chunks: Array<Uint8Array | undefined>;
  receivedChunks: number;
  receivedBytes: number;
  expiresAt: number;
}

export class AppMessageReassembler {
  private readonly states = new Map<string, ReassemblyState>();
  private bufferedBytes = 0;

  async push(frame: ArrayBuffer | Uint8Array, now = Date.now()): Promise<DecodedAppFrame | null> {
    this.prune(now);
    const parsed = parseAppFrame(frame);
    if (parsed.type === APP_TYPE_ACK) {
      if (parsed.flags !== 0 || parsed.totalLength !== 0 || parsed.payload.byteLength !== 0
        || parsed.chunkIndex !== 0 || parsed.chunkCount !== 1
        || parsed.digest.some((byte) => byte !== 0)) {
        throw new Error("invalid app acknowledgement frame");
      }
      return { kind: "ack", messageId: parsed.messageId };
    }

    let state = this.states.get(parsed.messageId);
    if (!state) {
      if (this.states.size >= MAX_REASSEMBLIES || this.bufferedBytes + parsed.totalLength > MAX_REASSEMBLY_BYTES) {
        throw new Error("app reassembly budget exceeded");
      }
      state = {
        type: parsed.type,
        flags: parsed.flags,
        totalLength: parsed.totalLength,
        chunkCount: parsed.chunkCount,
        digest: parsed.digest.slice(),
        chunks: new Array(parsed.chunkCount),
        receivedChunks: 0,
        receivedBytes: 0,
        expiresAt: now + REASSEMBLY_TIMEOUT_MS,
      };
      this.states.set(parsed.messageId, state);
      this.bufferedBytes += parsed.totalLength;
    } else if (state.type !== parsed.type || state.flags !== parsed.flags
      || state.totalLength !== parsed.totalLength || state.chunkCount !== parsed.chunkCount
      || !equalBytes(state.digest, parsed.digest)) {
      this.drop(parsed.messageId, state);
      throw new Error("inconsistent app message chunks");
    }

    const previousChunk = state.chunks[parsed.chunkIndex];
    if (previousChunk && !equalBytes(previousChunk, parsed.payload)) {
      this.drop(parsed.messageId, state);
      throw new Error("conflicting duplicate app message chunk");
    }
    if (!previousChunk) {
      if (state.receivedBytes + parsed.payload.byteLength > state.totalLength) {
        this.drop(parsed.messageId, state);
        throw new Error("app message exceeds declared length");
      }
      state.chunks[parsed.chunkIndex] = parsed.payload.slice();
      state.receivedChunks += 1;
      state.receivedBytes += parsed.payload.byteLength;
    }
    state.expiresAt = now + REASSEMBLY_TIMEOUT_MS;
    if (state.receivedChunks !== state.chunkCount) {
      return null;
    }

    this.drop(parsed.messageId, state);
    if (state.receivedBytes !== state.totalLength) {
      throw new Error("app message length mismatch");
    }
    const body = new Uint8Array(state.totalLength);
    let offset = 0;
    for (const chunk of state.chunks) {
      if (!chunk) {
        throw new Error("app message chunk missing");
      }
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const actualDigest = await sha256(body);
    if (!equalBytes(actualDigest, state.digest)) {
      throw new Error("app message digest mismatch");
    }
    return {
      kind: "message",
      messageId: parsed.messageId,
      message: decodeBody(state.type, body),
      acknowledgementRequired: (state.flags & APP_FLAG_ACK_REQUIRED) !== 0,
    };
  }

  clear() {
    this.states.clear();
    this.bufferedBytes = 0;
  }

  private prune(now: number) {
    for (const [messageId, state] of this.states) {
      if (state.expiresAt <= now) {
        this.drop(messageId, state);
      }
    }
  }

  private drop(messageId: string, state: ReassemblyState) {
    if (this.states.delete(messageId)) {
      this.bufferedBytes = Math.max(0, this.bufferedBytes - state.totalLength);
    }
  }
}

export async function encodeAppMessage(message: AppPeerMessage,
  maximumFrameBytes = DEFAULT_FRAME_BYTES): Promise<EncodedAppMessage> {
  const type = wireType(message);
  const body = encodeBody(type, message.payload);
  if (body.byteLength > MAX_APP_MESSAGE_BYTES) {
    throw new Error("app message is too large");
  }
  const payloadPerFrame = Math.max(1, Math.min(DEFAULT_FRAME_BYTES, maximumFrameBytes) - APP_HEADER_BYTES);
  const chunkCount = Math.max(1, Math.ceil(body.byteLength / payloadPerFrame));
  if (chunkCount > MAX_CHUNKS) {
    throw new Error("app message has too many chunks");
  }
  const messageIdBytes = crypto.getRandomValues(new Uint8Array(16));
  const messageId = toHex(messageIdBytes);
  const digest = await sha256(body);
  const acknowledgementRequired = needsAcknowledgement(message);
  const flags = acknowledgementRequired ? APP_FLAG_ACK_REQUIRED : 0;
  const frames: ArrayBuffer[] = [];
  for (let index = 0; index < chunkCount; index += 1) {
    const start = index * payloadPerFrame;
    const payload = body.subarray(start, Math.min(body.byteLength, start + payloadPerFrame));
    frames.push(buildAppFrame(type, flags, messageIdBytes, index, chunkCount, body.byteLength, payload, digest));
  }
  return { messageId, frames, acknowledgementRequired };
}

export function encodeAppAcknowledgement(messageId: string): ArrayBuffer {
  const id = fromHex(messageId, 16);
  return buildAppFrame(APP_TYPE_ACK, 0, id, 0, 1, 0, new Uint8Array(), new Uint8Array(32));
}

export function appMaximumFrameBytes(connection: RTCPeerConnection | null | undefined) {
  const negotiated = connection?.sctp?.maxMessageSize;
  if (!Number.isFinite(negotiated) || !negotiated || negotiated <= APP_HEADER_BYTES) {
    return DEFAULT_FRAME_BYTES;
  }
  return Math.max(APP_HEADER_BYTES + 1, Math.min(DEFAULT_FRAME_BYTES, negotiated));
}

export function encodeRelayAppFrame(targetPeerId: string, sourcePeerId: string,
  appFrame: ArrayBuffer | Uint8Array): ArrayBuffer {
  const target = new TextEncoder().encode(targetPeerId);
  const source = new TextEncoder().encode(sourcePeerId);
  const payload = asBytes(appFrame);
  if (target.byteLength > MAX_RELAY_PEER_ID_BYTES || source.byteLength > MAX_RELAY_PEER_ID_BYTES) {
    throw new Error("relay peer id is too long");
  }
  const result = new Uint8Array(RELAY_HEADER_BYTES + target.byteLength + source.byteLength + payload.byteLength);
  result.set(RELAY_MAGIC, 0);
  const view = new DataView(result.buffer);
  view.setUint8(4, RELAY_VERSION);
  view.setUint8(5, 0);
  view.setUint16(6, target.byteLength);
  view.setUint16(8, source.byteLength);
  view.setUint32(10, payload.byteLength);
  result.set(target, RELAY_HEADER_BYTES);
  result.set(source, RELAY_HEADER_BYTES + target.byteLength);
  result.set(payload, RELAY_HEADER_BYTES + target.byteLength + source.byteLength);
  return result.buffer;
}

export function decodeRelayAppFrame(frame: ArrayBuffer | Uint8Array) {
  const bytes = asBytes(frame);
  if (bytes.byteLength < RELAY_HEADER_BYTES || !hasMagic(bytes, RELAY_MAGIC)) {
    throw new Error("invalid relay app frame");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint8(4) !== RELAY_VERSION || view.getUint8(5) !== 0) {
    throw new Error("unsupported relay app frame");
  }
  const targetLength = view.getUint16(6);
  const sourceLength = view.getUint16(8);
  const payloadLength = view.getUint32(10);
  if (targetLength > MAX_RELAY_PEER_ID_BYTES || sourceLength > MAX_RELAY_PEER_ID_BYTES
    || RELAY_HEADER_BYTES + targetLength + sourceLength + payloadLength !== bytes.byteLength) {
    throw new Error("invalid relay app frame length");
  }
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const targetStart = RELAY_HEADER_BYTES;
  const sourceStart = targetStart + targetLength;
  const payloadStart = sourceStart + sourceLength;
  return {
    targetPeerId: decoder.decode(bytes.subarray(targetStart, sourceStart)),
    sourcePeerId: decoder.decode(bytes.subarray(sourceStart, payloadStart)),
    appFrame: bytes.slice(payloadStart).buffer,
  };
}

function parseAppFrame(frame: ArrayBuffer | Uint8Array): ParsedFrame {
  const bytes = asBytes(frame);
  if (bytes.byteLength < APP_HEADER_BYTES || !hasMagic(bytes, APP_MAGIC)) {
    throw new Error("invalid app frame magic");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint8(4) !== APP_VERSION) {
    throw new Error("unsupported app frame version");
  }
  const type = view.getUint8(5);
  if (![APP_TYPE_WHITEBOARD, APP_TYPE_CLIPBOARD, APP_TYPE_DIAGRAM, APP_TYPE_ACK].includes(type)) {
    throw new Error("unknown app frame type");
  }
  const flags = view.getUint16(6);
  if ((flags & ~APP_FLAG_ACK_REQUIRED) !== 0) {
    throw new Error("unknown app frame flags");
  }
  const messageId = toHex(bytes.subarray(8, 24));
  const chunkIndex = view.getUint32(24);
  const chunkCount = view.getUint32(28);
  const totalLength = view.getUint32(32);
  const payloadLength = view.getUint32(36);
  if (chunkCount < 1 || chunkCount > MAX_CHUNKS || chunkIndex >= chunkCount
    || totalLength > MAX_APP_MESSAGE_BYTES || payloadLength > totalLength
    || APP_HEADER_BYTES + payloadLength !== bytes.byteLength) {
    throw new Error("invalid app frame lengths");
  }
  return {
    type,
    flags,
    messageId,
    chunkIndex,
    chunkCount,
    totalLength,
    payload: bytes.slice(APP_HEADER_BYTES),
    digest: bytes.slice(40, 72),
  };
}

function buildAppFrame(type: number, flags: number, messageId: Uint8Array, chunkIndex: number,
  chunkCount: number, totalLength: number, payload: Uint8Array, digest: Uint8Array): ArrayBuffer {
  const result = new Uint8Array(APP_HEADER_BYTES + payload.byteLength);
  result.set(APP_MAGIC, 0);
  const view = new DataView(result.buffer);
  view.setUint8(4, APP_VERSION);
  view.setUint8(5, type);
  view.setUint16(6, flags);
  result.set(messageId, 8);
  view.setUint32(24, chunkIndex);
  view.setUint32(28, chunkCount);
  view.setUint32(32, totalLength);
  view.setUint32(36, payload.byteLength);
  result.set(digest, 40);
  result.set(payload, APP_HEADER_BYTES);
  return result.buffer;
}

function wireType(message: AppPeerMessage) {
  if (message.messageType === "clipboard") {
    return APP_TYPE_CLIPBOARD;
  }
  if (message.messageType === "whiteboard") {
    const payload = isRecord(message.payload) ? message.payload : null;
    return payload?.type === "STDG2" ? APP_TYPE_DIAGRAM : APP_TYPE_WHITEBOARD;
  }
  throw new Error("unsupported app message type");
}

function encodeBody(type: number, payload: unknown) {
  let metadata = payload;
  let binary: Uint8Array<ArrayBufferLike> = new Uint8Array();
  let encoding = BODY_ENCODING_JSON;
  if (type === APP_TYPE_DIAGRAM && isRecord(payload) && payload.kind === "diagram-update"
    && payload.update instanceof Uint8Array) {
    metadata = { ...payload, update: undefined };
    binary = payload.update;
    encoding = BODY_ENCODING_JSON_BINARY;
  }
  const json = new TextEncoder().encode(JSON.stringify(metadata ?? null));
  const body = new Uint8Array(5 + json.byteLength + binary.byteLength);
  const view = new DataView(body.buffer);
  view.setUint8(0, encoding);
  view.setUint32(1, json.byteLength);
  body.set(json, 5);
  body.set(binary, 5 + json.byteLength);
  return body;
}

function decodeBody(type: number, body: Uint8Array): AppPeerMessage {
  if (body.byteLength < 5) {
    throw new Error("invalid app message body");
  }
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const encoding = view.getUint8(0);
  const metadataLength = view.getUint32(1);
  if (metadataLength > body.byteLength - 5
    || (encoding !== BODY_ENCODING_JSON && encoding !== BODY_ENCODING_JSON_BINARY)) {
    throw new Error("invalid app message metadata length");
  }
  const json = new TextDecoder("utf-8", { fatal: true }).decode(body.subarray(5, 5 + metadataLength));
  let payload: unknown = JSON.parse(json);
  const binary = body.slice(5 + metadataLength);
  if (encoding === BODY_ENCODING_JSON) {
    if (binary.byteLength !== 0) {
      throw new Error("unexpected app message binary payload");
    }
  } else {
    if (type !== APP_TYPE_DIAGRAM || !isRecord(payload) || payload.kind !== "diagram-update"
      || binary.byteLength === 0) {
      throw new Error("invalid diagram binary payload");
    }
    payload = { ...payload, update: binary };
  }
  return {
    messageType: type === APP_TYPE_CLIPBOARD ? "clipboard" : "whiteboard",
    payload,
  };
}

function needsAcknowledgement(message: AppPeerMessage) {
  const payload = isRecord(message.payload) ? message.payload : null;
  if (message.messageType === "clipboard") {
    return true;
  }
  return payload?.type === "STDG2" || payload?.kind === "snapshot"
    || (payload?.kind === "object-upsert" && isRecord(payload.object) && payload.object.kind === "image");
}

async function sha256(value: Uint8Array) {
  const source = new Uint8Array(value.byteLength);
  source.set(value);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", source.buffer));
}

function asBytes(value: ArrayBuffer | Uint8Array) {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function hasMagic(value: Uint8Array, magic: readonly number[]) {
  return magic.every((byte, index) => value[index] === byte);
}

function equalBytes(left: Uint8Array, right: Uint8Array) {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function toHex(value: Uint8Array) {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(value: string, expectedBytes: number) {
  if (!new RegExp(`^[0-9a-f]{${expectedBytes * 2}}$`, "i").test(value)) {
    throw new Error("invalid app message id");
  }
  const result = new Uint8Array(expectedBytes);
  for (let index = 0; index < expectedBytes; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
