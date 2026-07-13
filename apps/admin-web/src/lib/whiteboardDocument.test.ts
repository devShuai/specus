import { describe, expect, it } from "vitest";
import type { WhiteboardObject, WhiteboardStroke } from "../components/SyncedWhiteboard";
import {
  createWhiteboardDocument,
  decodeWhiteboardDocument,
  encodeWhiteboardDocumentBinary,
  MAX_WHITEBOARD_DOCUMENT_BYTES,
  parseWhiteboardDocument,
  WHITEBOARD_DOCUMENT_FORMAT,
} from "./whiteboardDocument";

const stroke: WhiteboardStroke = {
  strokeId: "stroke-1",
  sourcePeerId: "peer-a",
  color: "#2563eb",
  width: 6,
  points: [{ x: 0.1, y: 0.2 }, { x: 0.3, y: 0.4 }],
  updatedAt: 100,
};

const objectBase = {
  sourcePeerId: "peer-a",
  x: 0.1,
  y: 0.2,
  width: 0.3,
  height: 0.2,
  color: "#2563eb",
  strokeWidth: 3,
  updatedAt: 100,
};

const objects: WhiteboardObject[] = [
  { ...objectBase, objectId: "text-1", kind: "text", text: "导出的文本", fontSize: 22 },
  { ...objectBase, objectId: "shape-1", kind: "shape", shapeKind: "ellipse" },
  { ...objectBase, objectId: "flow-1", kind: "flow-node", nodeKind: "process", text: "处理数据" },
  {
    ...objectBase,
    objectId: "image-1",
    kind: "image",
    fileName: "board.jpg",
    dataUrl: "data:image/jpeg;base64,AA==",
  },
];

describe("whiteboard document", () => {
  it("round-trips editable strokes and every object kind", () => {
    const exported = createWhiteboardDocument(
      [stroke],
      objects,
      { width: 720, height: 1280 },
      new Date("2026-07-11T12:00:00.000Z"),
    );
    const imported = parseWhiteboardDocument(JSON.stringify(exported));

    expect(imported.format).toBe(WHITEBOARD_DOCUMENT_FORMAT);
    expect(imported.exportedAt).toBe("2026-07-11T12:00:00.000Z");
    expect(imported.surface).toEqual({ width: 720, height: 1280 });
    expect(imported.strokes).toEqual([stroke]);
    expect(imported.objects).toEqual(objects);
  });

  it("rejects unsupported versions and invalid board objects", () => {
    const exported = createWhiteboardDocument([stroke], objects, { width: 720, height: 1280 });

    expect(() => parseWhiteboardDocument(JSON.stringify({ ...exported, version: 2 })))
      .toThrow("不支持的白板文件格式或版本");
    expect(() => parseWhiteboardDocument(JSON.stringify({
      ...exported,
      objects: [{ ...objects[0], x: 0.9, width: 0.3 }],
    }))).toThrow("白板文件包含无效或超出限制的内容");
  });

  it("rejects malformed and oversized files", () => {
    expect(() => parseWhiteboardDocument("not-json")).toThrow("白板文件不是有效的 JSON");
    expect(() => parseWhiteboardDocument("x".repeat(MAX_WHITEBOARD_DOCUMENT_BYTES + 1)))
      .toThrow("白板文件超过 16 MB");
  });

  it("round-trips the compressed .stwb binary format", async () => {
    const exported = createWhiteboardDocument(
      [stroke],
      objects,
      { width: 720, height: 1280 },
      new Date("2026-07-11T12:00:00.000Z"),
    );
    const encoded = await encodeWhiteboardDocumentBinary(exported);

    // magic 头 "STWB1\0" + gzip magic
    expect(Array.from(encoded.subarray(0, 6))).toEqual([0x53, 0x54, 0x57, 0x42, 0x31, 0x00]);
    expect(encoded[6]).toBe(0x1f);
    expect(encoded[7]).toBe(0x8b);
    expect(encoded.length).toBeLessThan(JSON.stringify(exported).length);

    const decoded = await decodeWhiteboardDocument(encoded);
    expect(decoded.strokes).toEqual([stroke]);
    expect(decoded.objects).toEqual(objects);
  });

  it("decodes legacy plain-JSON exports and raw gzip payloads", async () => {
    const exported = createWhiteboardDocument([stroke], objects, { width: 720, height: 1280 });
    const legacyJson = new TextEncoder().encode(JSON.stringify(exported));
    const fromLegacy = await decodeWhiteboardDocument(legacyJson);
    expect(fromLegacy.strokes).toEqual(exported.strokes);

    const binary = await encodeWhiteboardDocumentBinary(exported);
    const rawGzip = binary.subarray(6);
    const fromRawGzip = await decodeWhiteboardDocument(rawGzip);
    expect(fromRawGzip.objects).toEqual(exported.objects);
  });

  it("rejects corrupt binary payloads and oversized inputs", async () => {
    const corrupt = new Uint8Array([0x53, 0x54, 0x57, 0x42, 0x31, 0x00, 0x1f, 0x8b, 0x00, 0x01, 0x02]);
    await expect(decodeWhiteboardDocument(corrupt)).rejects.toThrow("白板文件解压失败");

    const oversized = new Uint8Array(MAX_WHITEBOARD_DOCUMENT_BYTES + 1);
    await expect(decodeWhiteboardDocument(oversized)).rejects.toThrow("白板文件超过 16 MB");
  });
});
