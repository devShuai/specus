import { decodeBase64Bytes, detectImageMime } from "./tcpPayload";

const BASE64_DATA_URL_PATTERN = /^data:([^;,]+)?(?:;[^,]*)?;base64,(.*)$/is;

export function resolveHttpImageDataUrl(content: string, contentType: string | null): string | null {
  const trimmed = content.trim();
  const match = trimmed.match(BASE64_DATA_URL_PATTERN);
  if (!match) {
    return null;
  }

  const payload = match[2].replace(/\s/g, "");
  if (!payload) {
    return null;
  }

  const storedMediaType = normalizeMediaType(match[1]);
  const declaredMediaType = normalizeMediaType(contentType);
  const detectedMediaType = detectImageMime(decodeBase64Prefix(payload));
  const imageMediaType = detectedMediaType
    ?? (storedMediaType?.startsWith("image/") ? storedMediaType : null)
    ?? (declaredMediaType?.startsWith("image/") ? declaredMediaType : null);

  return imageMediaType ? `data:${imageMediaType};base64,${payload}` : null;
}

export function isHttpImageBody(content: string, contentType: string | null): boolean {
  const trimmed = content.trim();
  return normalizeMediaType(contentType)?.startsWith("image/") === true
    || trimmed.startsWith("<svg")
    || resolveHttpImageDataUrl(trimmed, contentType) !== null;
}

function decodeBase64Prefix(payload: string): Uint8Array {
  const prefixLength = Math.min(payload.length, 32);
  const alignedLength = prefixLength - (prefixLength % 4);
  if (alignedLength < 16) {
    return new Uint8Array();
  }
  return decodeBase64Bytes(payload.slice(0, alignedLength));
}

function normalizeMediaType(value: string | null | undefined): string | null {
  const mediaType = value?.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType) ? mediaType : null;
}
