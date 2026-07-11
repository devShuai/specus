export const CLIPBOARD_TEXT_MAX_CHARS = 16_384;
export const CLIPBOARD_TEXT_MAX_UTF8_BYTES = 32 * 1024;
export const CLIPBOARD_DISCOVERY_MESSAGE_MAX_CHARS = 64 * 1024;

const CLIPBOARD_PROTOCOL_TYPE = "STCLIP1";
const CLIPBOARD_PAYLOAD_KIND = "text";
const CLIPBOARD_ID_MAX_CHARS = 128;
const CLIPBOARD_PAYLOAD_KEYS = [
  "type",
  "kind",
  "id",
  "sessionId",
  "sequence",
  "text",
  "createdAt",
] as const;

export interface ClipboardSyncPayload {
  type: "STCLIP1";
  kind: "text";
  id: string;
  sessionId: string;
  sequence: number;
  text: string;
  createdAt: number;
}

export interface ClipboardInboundEvent {
  eventId: string;
  sourcePeerId: string;
  payload: ClipboardSyncPayload;
  receivedAt: number;
}

export function createClipboardSessionId() {
  return createCompatibleUuid();
}

export function createClipboardSyncPayload(
  text: string,
  sessionId: string,
  sequence: number,
): ClipboardSyncPayload {
  const payload: ClipboardSyncPayload = {
    type: CLIPBOARD_PROTOCOL_TYPE,
    kind: CLIPBOARD_PAYLOAD_KIND,
    id: createCompatibleUuid(),
    sessionId,
    sequence,
    text,
    createdAt: Date.now(),
  };
  if (!isClipboardSyncPayload(payload)) {
    throw new RangeError("剪贴板同步内容或标识不符合协议限制");
  }
  return payload;
}

export function clipboardSyncEventKey(sourcePeerId: string, payload: ClipboardSyncPayload) {
  return JSON.stringify([sourcePeerId, "clipboard", payload.sessionId, payload.id]);
}

export function serializeClipboardRelayEnvelope(targetPeerId: string, payload: ClipboardSyncPayload) {
  if (!isProtocolId(targetPeerId) || !isClipboardSyncPayload(payload)) {
    throw new RangeError("剪贴板互传目标或内容不符合协议限制");
  }
  const serialized = JSON.stringify({
    type: "clipboard",
    targetPeerId,
    payload,
  });
  if (serialized.length > CLIPBOARD_DISCOVERY_MESSAGE_MAX_CHARS) {
    throw new RangeError("剪贴板内容包含过多转义字符，无法通过互传通道发送");
  }
  return serialized;
}

export function isClipboardSyncPayload(value: unknown): value is ClipboardSyncPayload {
  if (!isPlainRecord(value)) {
    return false;
  }
  const keys = Object.keys(value);
  if (keys.length !== CLIPBOARD_PAYLOAD_KEYS.length
    || !CLIPBOARD_PAYLOAD_KEYS.every((key) => Object.hasOwn(value, key))) {
    return false;
  }
  try {
    return value.type === CLIPBOARD_PROTOCOL_TYPE
      && value.kind === CLIPBOARD_PAYLOAD_KIND
      && isProtocolId(value.id)
      && isProtocolId(value.sessionId)
      && isNonNegativeSafeInteger(value.sequence)
      && typeof value.text === "string"
      && value.text.length > 0
      && isClipboardTextWithinLimits(value.text)
      && isNonNegativeSafeInteger(value.createdAt);
  } catch {
    return false;
  }
}

function isClipboardTextWithinLimits(text: string) {
  return text.length <= CLIPBOARD_TEXT_MAX_CHARS
    && new TextEncoder().encode(text).byteLength <= CLIPBOARD_TEXT_MAX_UTF8_BYTES;
}

function isProtocolId(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= CLIPBOARD_ID_MAX_CHARS
    && value.trim() === value;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function createCompatibleUuid() {
  const cryptoApi = typeof globalThis.crypto === "undefined" ? null : globalThis.crypto;
  if (cryptoApi && typeof cryptoApi.randomUUID === "function") {
    return cryptoApi.randomUUID();
  }

  const bytes = new Uint8Array(16);
  if (cryptoApi && typeof cryptoApi.getRandomValues === "function") {
    cryptoApi.getRandomValues(bytes);
  } else {
    fillLegacyRandomBytes(bytes);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
}

function fillLegacyRandomBytes(bytes: Uint8Array) {
  let seed = Date.now() ^ Math.floor(Math.random() * 0x7fffffff);
  for (let index = 0; index < bytes.length; index += 1) {
    seed = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    seed ^= seed + Math.imul(seed ^ (seed >>> 7), 61 | seed);
    bytes[index] = (seed ^ (seed >>> 14)) & 0xff;
  }
}
