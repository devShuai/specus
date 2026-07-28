import type { WhiteboardObject, WhiteboardPoint, WhiteboardStroke } from "../components/SyncedWhiteboard";
import { MAX_WHITEBOARD_IMAGE_DATA_URL_LENGTH } from "./whiteboardImageCompression";

export const WHITEBOARD_DOCUMENT_FORMAT = "specus-whiteboard";
export const WHITEBOARD_DOCUMENT_VERSION = 1;
export const WHITEBOARD_FILE_EXTENSION = ".stwb";
export const WHITEBOARD_FILE_MIME = "application/vnd.specus.whiteboard";
export const MAX_WHITEBOARD_DOCUMENT_BYTES = 16 * 1024 * 1024;
export const MAX_WHITEBOARD_DOCUMENT_STROKES = 120;
export const MAX_WHITEBOARD_DOCUMENT_POINTS = 900;
export const MAX_WHITEBOARD_DOCUMENT_OBJECTS = 80;

// .stwb 文件头：ASCII "STWB1" + NUL，后跟 gzip 压缩的文档 JSON。
const WHITEBOARD_BINARY_MAGIC = new Uint8Array([0x53, 0x54, 0x57, 0x42, 0x31, 0x00]);
const GZIP_MAGIC_0 = 0x1f;
const GZIP_MAGIC_1 = 0x8b;

const MAX_TEXT_LENGTH = 500;
const MAX_FLOW_LABEL_LENGTH = 120;

export interface WhiteboardDocumentV1 {
  format: typeof WHITEBOARD_DOCUMENT_FORMAT;
  version: typeof WHITEBOARD_DOCUMENT_VERSION;
  exportedAt: string;
  surface: {
    width: number;
    height: number;
  };
  strokes: WhiteboardStroke[];
  objects: WhiteboardObject[];
}

export function createWhiteboardDocument(
  strokes: WhiteboardStroke[],
  objects: WhiteboardObject[],
  surface: { width: number; height: number },
  exportedAt = new Date(),
): WhiteboardDocumentV1 {
  return {
    format: WHITEBOARD_DOCUMENT_FORMAT,
    version: WHITEBOARD_DOCUMENT_VERSION,
    exportedAt: exportedAt.toISOString(),
    surface: {
      width: Math.max(1, Math.round(surface.width)),
      height: Math.max(1, Math.round(surface.height)),
    },
    strokes: strokes.slice(-MAX_WHITEBOARD_DOCUMENT_STROKES).map((stroke) => ({
      ...stroke,
      points: stroke.points.slice(0, MAX_WHITEBOARD_DOCUMENT_POINTS).map((point) => ({ ...point })),
    })),
    objects: objects.slice(-MAX_WHITEBOARD_DOCUMENT_OBJECTS).map(cloneWhiteboardObject),
  };
}

/**
 * 把白板文档编码成 .stwb 二进制：magic 头 + gzip(JSON)。
 * 依赖浏览器/Node 原生 CompressionStream，不可用时抛错由调用方提示。
 */
export async function encodeWhiteboardDocumentBinary(document: WhiteboardDocumentV1): Promise<Uint8Array<ArrayBuffer>> {
  if (typeof CompressionStream === "undefined") {
    throw new Error("当前浏览器不支持压缩导出，请升级浏览器后重试");
  }
  const json = new TextEncoder().encode(JSON.stringify(document));
  const compressed = await readStreamWithLimit(
    new Blob([json]).stream().pipeThrough(new CompressionStream("gzip")),
    MAX_WHITEBOARD_DOCUMENT_BYTES - WHITEBOARD_BINARY_MAGIC.length,
    "白板内容过多，压缩后仍超过 16 MB",
  );
  const bytes = new Uint8Array(WHITEBOARD_BINARY_MAGIC.length + compressed.length);
  bytes.set(WHITEBOARD_BINARY_MAGIC, 0);
  bytes.set(compressed, WHITEBOARD_BINARY_MAGIC.length);
  return bytes;
}

/**
 * 解析白板文件字节：支持 .stwb 二进制（magic + gzip）、裸 gzip，
 * 以及旧版导出的纯 JSON 文本，三者共用同一套内容校验。
 */
export async function decodeWhiteboardDocument(bytes: Uint8Array<ArrayBuffer>): Promise<WhiteboardDocumentV1> {
  if (bytes.length > MAX_WHITEBOARD_DOCUMENT_BYTES) {
    throw new Error("白板文件超过 16 MB，无法导入");
  }
  const payload = hasPrefix(bytes, WHITEBOARD_BINARY_MAGIC)
    ? bytes.subarray(WHITEBOARD_BINARY_MAGIC.length)
    : bytes;
  if (payload.length >= 2 && payload[0] === GZIP_MAGIC_0 && payload[1] === GZIP_MAGIC_1) {
    if (typeof DecompressionStream === "undefined") {
      throw new Error("当前浏览器不支持解压白板文件，请升级浏览器后重试");
    }
    let json: Uint8Array;
    try {
      json = await readStreamWithLimit(
        new Blob([payload]).stream().pipeThrough(new DecompressionStream("gzip")),
        MAX_WHITEBOARD_DOCUMENT_BYTES,
        "白板文件解压后超过 16 MB，无法导入",
      );
    } catch (error) {
      if (error instanceof Error && error.message.includes("16 MB")) {
        throw error;
      }
      throw new Error("白板文件解压失败，文件可能已损坏");
    }
    return parseWhiteboardDocument(new TextDecoder().decode(json));
  }
  return parseWhiteboardDocument(new TextDecoder().decode(bytes));
}

/** 读取整个流并拼接为字节数组；超过 maxBytes 立即中断，避免解压炸弹撑爆内存。 */
async function readStreamWithLimit(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
  limitMessage: string,
): Promise<Uint8Array<ArrayBuffer>> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.length;
      if (total > maxBytes) {
        throw new Error(limitMessage);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return merged;
}

function hasPrefix(bytes: Uint8Array, prefix: Uint8Array): boolean {
  if (bytes.length < prefix.length) {
    return false;
  }
  for (let index = 0; index < prefix.length; index += 1) {
    if (bytes[index] !== prefix[index]) {
      return false;
    }
  }
  return true;
}

export function parseWhiteboardDocument(source: string): WhiteboardDocumentV1 {
  if (source.length > MAX_WHITEBOARD_DOCUMENT_BYTES) {
    throw new Error("白板文件超过 16 MB，无法导入");
  }
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error("白板文件不是有效的 JSON");
  }
  if (!isRecord(value)
    || value.format !== WHITEBOARD_DOCUMENT_FORMAT
    || value.version !== WHITEBOARD_DOCUMENT_VERSION) {
    throw new Error("不支持的白板文件格式或版本");
  }
  if (!isWhiteboardDocument(value)) {
    throw new Error("白板文件包含无效或超出限制的内容");
  }
  return value;
}

export function isWhiteboardStroke(value: unknown, maxPoints = MAX_WHITEBOARD_DOCUMENT_POINTS): value is WhiteboardStroke {
  return isRecord(value)
    && isIdentifier(value.strokeId)
    && isIdentifier(value.sourcePeerId)
    && isColor(value.color)
    && isWidth(value.width)
    && Array.isArray(value.points)
    && value.points.length > 0
    && value.points.length <= maxPoints
    && value.points.every(isPoint)
    && isFiniteNumber(value.updatedAt);
}

export function isWhiteboardObject(value: unknown): value is WhiteboardObject {
  if (!isRecord(value)
    || !isIdentifier(value.objectId)
    || !isIdentifier(value.sourcePeerId)
    || !isUnitNumber(value.x)
    || !isUnitNumber(value.y)
    || !isFiniteNumber(value.width)
    || !isFiniteNumber(value.height)
    || !isColor(value.color)
    || !isWidth(value.strokeWidth)
    || !isFiniteNumber(value.updatedAt)) {
    return false;
  }
  if (value.kind === "shape") {
    if (value.shapeKind !== "rectangle" && value.shapeKind !== "ellipse" && value.shapeKind !== "arrow") {
      return false;
    }
    const endX = value.x + value.width;
    const endY = value.y + value.height;
    return value.width !== 0
      && value.height !== 0
      && endX >= 0
      && endX <= 1
      && endY >= 0
      && endY <= 1
      && (value.shapeKind === "arrow" || (value.width > 0 && value.height > 0));
  }
  if (value.width <= 0 || value.height <= 0 || value.x + value.width > 1 || value.y + value.height > 1) {
    return false;
  }
  if (value.kind === "flow-node") {
    return (value.nodeKind === "start"
        || value.nodeKind === "process"
        || value.nodeKind === "decision"
        || value.nodeKind === "end")
      && typeof value.text === "string"
      && value.text.length > 0
      && value.text.length <= MAX_FLOW_LABEL_LENGTH;
  }
  if (value.kind === "text") {
    return typeof value.text === "string"
      && value.text.length > 0
      && value.text.length <= MAX_TEXT_LENGTH
      && isFiniteNumber(value.fontSize)
      && value.fontSize >= 12
      && value.fontSize <= 64;
  }
  if (value.kind === "image") {
    return typeof value.fileName === "string"
      && value.fileName.length > 0
      && value.fileName.length <= 120
      && typeof value.dataUrl === "string"
      && value.dataUrl.length <= MAX_WHITEBOARD_IMAGE_DATA_URL_LENGTH
      && /^data:image\/jpeg;base64,[a-zA-Z0-9+/=]+$/.test(value.dataUrl);
  }
  return false;
}

function isWhiteboardDocument(value: unknown): value is WhiteboardDocumentV1 {
  return isRecord(value)
    && typeof value.exportedAt === "string"
    && Number.isFinite(Date.parse(value.exportedAt))
    && isRecord(value.surface)
    && isFiniteNumber(value.surface.width)
    && value.surface.width > 0
    && isFiniteNumber(value.surface.height)
    && value.surface.height > 0
    && Array.isArray(value.strokes)
    && value.strokes.length <= MAX_WHITEBOARD_DOCUMENT_STROKES
    && value.strokes.every((stroke) => isWhiteboardStroke(stroke))
    && Array.isArray(value.objects)
    && value.objects.length <= MAX_WHITEBOARD_DOCUMENT_OBJECTS
    && value.objects.every(isWhiteboardObject);
}

function cloneWhiteboardObject(object: WhiteboardObject): WhiteboardObject {
  return object.kind === "image" ? { ...object, dataUrl: object.dataUrl } : { ...object };
}

function isIdentifier(value: unknown) {
  return typeof value === "string" && value.length > 0 && value.length <= 180 && value.trim() === value;
}

function isPoint(value: unknown): value is WhiteboardPoint {
  return isRecord(value) && isUnitNumber(value.x) && isUnitNumber(value.y);
}

function isUnitNumber(value: unknown): value is number {
  return isFiniteNumber(value) && value >= 0 && value <= 1;
}

function isColor(value: unknown): value is string {
  return typeof value === "string" && /^#[0-9a-fA-F]{6}$/.test(value);
}

function isWidth(value: unknown): value is number {
  return isFiniteNumber(value) && value >= 1 && value <= 32;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
