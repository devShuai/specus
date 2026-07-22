export const CLIPBOARD_TEXT_MAX_CHARS = 32_768;
export const CLIPBOARD_TEXT_MAX_UTF8_BYTES = 48 * 1024;
const CLIPBOARD_PROTOCOL_TYPE = "STCLIP2";
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
  "html",
] as const;

export type ClipboardContentKind = "text" | "html" | "link";

export interface ClipboardSyncPayload {
  type: "STCLIP2";
  kind: ClipboardContentKind;
  id: string;
  sessionId: string;
  sequence: number;
  text: string;
  createdAt: number;
  html: string | null;
}

export interface ClipboardInboundEvent {
  eventId: string;
  sourcePeerId: string;
  sourceDisplayName?: string;
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
  content: { kind?: ClipboardContentKind; html?: string | null } = {},
): ClipboardSyncPayload {
  const kind = content.kind ?? CLIPBOARD_PAYLOAD_KIND;
  const common = {
    id: createCompatibleUuid(),
    sessionId,
    sequence,
    text,
    createdAt: Date.now(),
  };
  const payload: ClipboardSyncPayload = {
    type: CLIPBOARD_PROTOCOL_TYPE,
    kind,
    html: kind === "html" ? content.html ?? null : null,
    ...common,
  };
  if (!isClipboardSyncPayload(payload)) {
    throw new RangeError("剪贴板同步内容或标识不符合协议限制");
  }
  return payload;
}

export function clipboardSyncEventKey(sourcePeerId: string, payload: ClipboardSyncPayload) {
  return JSON.stringify([sourcePeerId, "clipboard", payload.sessionId, payload.id]);
}

export function isClipboardSyncPayload(value: unknown): value is ClipboardSyncPayload {
  if (!isPlainRecord(value)) {
    return false;
  }
  const keys = Object.keys(value);
  try {
    if (typeof value.text !== "string") {
      return false;
    }
    const text = value.text;
    const commonValid = isProtocolId(value.id)
      && isProtocolId(value.sessionId)
      && isNonNegativeSafeInteger(value.sequence)
      && text.length > 0
      && isNonNegativeSafeInteger(value.createdAt);
    if (!commonValid) {
      return false;
    }
    if (keys.length !== CLIPBOARD_PAYLOAD_KEYS.length
      || !CLIPBOARD_PAYLOAD_KEYS.every((key) => Object.hasOwn(value, key))) {
      return false;
    }
    if (value.type !== CLIPBOARD_PROTOCOL_TYPE
      || !isClipboardContentKind(value.kind)
      || (typeof value.html !== "string" && value.html !== null)) {
      return false;
    }
    const html = typeof value.html === "string" ? value.html : "";
    return (value.kind === "html" ? html.length > 0 : value.html === null)
      && isClipboardContentWithinLimits(text, html)
      && (value.kind !== "link" || isHttpUrl(text));
  } catch {
    return false;
  }
}

export function clipboardPayloadHtml(payload: ClipboardSyncPayload) {
  return payload.kind === "html"
    ? payload.html ?? ""
    : "";
}

function isClipboardContentWithinLimits(text: string, html: string) {
  return text.length + html.length <= CLIPBOARD_TEXT_MAX_CHARS
    && new TextEncoder().encode(text).byteLength + new TextEncoder().encode(html).byteLength <= CLIPBOARD_TEXT_MAX_UTF8_BYTES;
}

function isClipboardContentKind(value: unknown): value is ClipboardContentKind {
  return value === "text" || value === "html" || value === "link";
}

function isHttpUrl(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
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
