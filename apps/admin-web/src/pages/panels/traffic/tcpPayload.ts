import type { TcpTrafficFrame } from "../../../api/types";

export type TcpPayloadKind = "http" | "json" | "image" | "text" | "binary";

export interface TcpPayloadAnalysis {
  binaryLabel: string;
  bytes: Uint8Array;
  fullAvailable: boolean;
  hexDump: string;
  http: TcpHttpMessage | null;
  imageDataUrl: string | null;
  imageMime: string | null;
  jsonPretty: string | null;
  kind: TcpPayloadKind;
  text: string;
}

export interface TcpHttpMessage {
  body: string;
  headers: TcpHeaderPair[];
  startLine: string;
}

export interface TcpHeaderPair {
  name: string;
  value: string;
}

export function analyzeTcpPayload(row: TcpTrafficFrame): TcpPayloadAnalysis {
  const fullAvailable = Boolean(row.payloadBase64);
  const bytes = fullAvailable ? decodeBase64Bytes(row.payloadBase64) : decodeHexPreview(row.payloadPreviewHex);
  const text = decodeUtf8(bytes);
  const hexDump = bytesToHexDump(bytes);
  const imageMime = detectImageMime(bytes);
  const http = parseTcpHttpMessage(text);
  const jsonPretty = parseTcpJson(text);

  if (http) {
    return tcpAnalysis("http", bytes, text, hexDump, fullAvailable, http, null, null, null, "HTTP");
  }
  if (jsonPretty) {
    return tcpAnalysis("json", bytes, text, hexDump, fullAvailable, null, null, null, jsonPretty, "JSON");
  }
  if (imageMime && fullAvailable) {
    return tcpAnalysis(
      "image",
      bytes,
      text,
      hexDump,
      fullAvailable,
      null,
      imageMime,
      `data:${imageMime};base64,${row.payloadBase64}`,
      null,
      imageMime,
    );
  }
  if (looksLikeTextPayload(bytes)) {
    return tcpAnalysis("text", bytes, text, hexDump, fullAvailable, null, null, null, null, "文本");
  }
  return tcpAnalysis("binary", bytes, text, hexDump, fullAvailable, null, null, null, null, detectBinaryLabel(bytes));
}

export function tcpPayloadKindLabel(kind: TcpPayloadKind): string {
  if (kind === "http") {
    return "HTTP";
  }
  if (kind === "json") {
    return "JSON";
  }
  if (kind === "image") {
    return "图片";
  }
  if (kind === "text") {
    return "文本";
  }
  return "二进制";
}

export function decodeBase64Bytes(base64: string): Uint8Array {
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return new Uint8Array();
  }
}

export function decodeHexPreview(hex: string | null | undefined): Uint8Array {
  const pairs = hex?.match(/[0-9a-fA-F]{2}/g) ?? [];
  const bytes = new Uint8Array(pairs.length);
  pairs.forEach((pair, index) => {
    bytes[index] = Number.parseInt(pair, 16);
  });
  return bytes;
}

export function decodeUtf8(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    return "";
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

export function parseTcpHttpMessage(text: string): TcpHttpMessage | null {
  const startLineMatch = text.match(/^([A-Z]{3,12}\s+\S+\s+HTTP\/\d(?:\.\d)?|HTTP\/\d(?:\.\d)?\s+\d{3}.*)(?:\r?\n|$)/);
  if (!startLineMatch) {
    return null;
  }
  const separatorMatch = /\r?\n\r?\n/.exec(text);
  const headerBlock = separatorMatch ? text.slice(0, separatorMatch.index) : text;
  const body = separatorMatch ? text.slice(separatorMatch.index + separatorMatch[0].length) : "";
  const [startLine, ...headerLines] = headerBlock.split(/\r?\n/);
  const headers = headerLines
    .map((line) => {
      const splitAt = line.indexOf(":");
      if (splitAt <= 0) {
        return null;
      }
      return { name: line.slice(0, splitAt).trim(), value: line.slice(splitAt + 1).trim() };
    })
    .filter((header): header is TcpHeaderPair => header != null);
  return { body, headers, startLine };
}

export function tcpHeaderValue(headers: TcpHeaderPair[], name: string): string | null {
  const target = name.toLowerCase();
  return headers.find((header) => header.name.toLowerCase() === target)?.value ?? null;
}

export function looksLikeTextPayload(bytes: Uint8Array): boolean {
  if (bytes.length === 0) {
    return true;
  }
  const sampleLength = Math.min(bytes.length, 4096);
  let control = 0;
  for (let i = 0; i < sampleLength; i += 1) {
    const value = bytes[i];
    const allowedWhitespace = value === 0x09 || value === 0x0a || value === 0x0d;
    if ((value < 0x20 && !allowedWhitespace) || value === 0x7f) {
      control += 1;
    }
  }
  return control / sampleLength < 0.08;
}

export function bytesToHexDump(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    return "";
  }
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const slice = bytes.slice(offset, offset + 16);
    let hex = "";
    let ascii = "";
    for (let i = 0; i < 16; i += 1) {
      if (i < slice.length) {
        const value = slice[i];
        hex += `${value.toString(16).padStart(2, "0").toUpperCase()} `;
        ascii += value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : ".";
      } else {
        hex += "   ";
        ascii += " ";
      }
      if (i === 7) {
        hex += " ";
      }
    }
    lines.push(`${offset.toString(16).padStart(8, "0").toUpperCase()}  ${hex} |${ascii}|`);
  }
  return lines.join("\n");
}

export function tcpFlowLabel(row: TcpTrafficFrame): string {
  const source = tcpEndpoint(row.sourceAddress, row.sourcePort);
  const destination = tcpEndpoint(row.destinationAddress, row.destinationPort);
  if (source === "-" && destination === "-") {
    return row.remoteAddress || "-";
  }
  return `${source} -> ${destination}`;
}

export function tcpStreamRange(row: TcpTrafficFrame): string {
  const start = row.streamOffset ?? 0;
  const end = row.streamEndOffset ?? start + row.payloadBytes;
  return `${start}-${end}`;
}

export function concatTcpPayloads(frames: TcpTrafficFrame[]): Uint8Array {
  const chunks = frames.map((frame) =>
    frame.payloadBase64 ? decodeBase64Bytes(frame.payloadBase64) : decodeHexPreview(frame.payloadPreviewHex),
  );
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function tcpAnalysis(
  kind: TcpPayloadKind,
  bytes: Uint8Array,
  text: string,
  hexDump: string,
  fullAvailable: boolean,
  http: TcpHttpMessage | null,
  imageMime: string | null,
  imageDataUrl: string | null,
  jsonPretty: string | null,
  binaryLabel: string,
): TcpPayloadAnalysis {
  return { binaryLabel, bytes, fullAvailable, hexDump, http, imageDataUrl, imageMime, jsonPretty, kind, text };
}

export function parseTcpJson(text: string): string | null {
  const trimmed = text.trim();
  if (!/^[\[{]/.test(trimmed)) {
    return null;
  }
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return null;
  }
}

export function detectImageMime(bytes: Uint8Array): string | null {
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
    return "image/png";
  }
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return "image/jpeg";
  }
  if (bytes.length >= 6) {
    const signature = String.fromCharCode(...bytes.slice(0, 6));
    if (signature === "GIF87a" || signature === "GIF89a") {
      return "image/gif";
    }
  }
  if (bytes.length >= 12) {
    const riff = String.fromCharCode(...bytes.slice(0, 4));
    const webp = String.fromCharCode(...bytes.slice(8, 12));
    if (riff === "RIFF" && webp === "WEBP") {
      return "image/webp";
    }
  }
  return null;
}

function detectBinaryLabel(bytes: Uint8Array): string {
  if (bytes.length >= 3 && bytes[0] === 0x16 && bytes[1] === 0x03) {
    return "TLS Handshake";
  }
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return "Gzip";
  }
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b) {
    return "ZIP";
  }
  return "Binary";
}

function tcpEndpoint(address: string | null | undefined, port: number | null | undefined): string {
  if (!address && port == null) {
    return "-";
  }
  if (!address) {
    return `:${port}`;
  }
  return port == null ? address : `${address}:${port}`;
}
