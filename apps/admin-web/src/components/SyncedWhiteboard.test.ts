import { describe, expect, it } from "vitest";
import { MAX_WHITEBOARD_IMAGE_DATA_URL_LENGTH } from "../lib/whiteboardImageCompression";
import { createWhiteboardDocument, parseWhiteboardDocument } from "../lib/whiteboardDocument";
import { isWhiteboardPayload } from "./SyncedWhiteboard";

const baseObject = {
  objectId: "peer-object-1",
  sourcePeerId: "peer-a",
  x: 0.1,
  y: 0.2,
  width: 0.3,
  height: 0.2,
  color: "#2563eb",
  strokeWidth: 3,
  updatedAt: 100,
};

describe("isWhiteboardPayload", () => {
  it("accepts synchronized text, shape, flow, and image objects", () => {
    const objects = [
      { ...baseObject, kind: "text", text: "同步文本", fontSize: 22 },
      { ...baseObject, objectId: "peer-shape-1", kind: "shape", shapeKind: "ellipse" },
      {
        ...baseObject,
        objectId: "peer-flow-1",
        kind: "flow-node",
        nodeKind: "decision",
        text: "判断条件",
      },
      {
        ...baseObject,
        objectId: "peer-image-1",
        kind: "image",
        fileName: "board.jpg",
        dataUrl: "data:image/jpeg;base64,AA==",
      },
    ];

    for (const object of objects) {
      expect(isWhiteboardPayload({
        type: "STWB1",
        kind: "object-upsert",
        object,
        createdAt: 101,
      })).toBe(true);
    }
  });

  it("rejects invalid flowchart nodes", () => {
    const payload = (nodeKind: string, text: string) => ({
      type: "STWB1",
      kind: "object-upsert",
      object: { ...baseObject, kind: "flow-node", nodeKind, text },
      createdAt: 105,
    });

    expect(isWhiteboardPayload(payload("database", "保存数据"))).toBe(false);
    expect(isWhiteboardPayload(payload("process", ""))).toBe(false);
    expect(isWhiteboardPayload(payload("process", "A".repeat(121)))).toBe(false);
  });

  it("accepts object removal events", () => {
    expect(isWhiteboardPayload({
      type: "STWB1",
      kind: "remove-object",
      objectId: "peer-object-1",
      createdAt: 102,
    })).toBe(true);
  });

  it("accepts document import snapshot batches", () => {
    expect(isWhiteboardPayload({
      type: "STWB1",
      kind: "snapshot",
      strokes: [{
        strokeId: "import-stroke-1",
        sourcePeerId: "peer-a",
        color: "#2563eb",
        width: 6,
        points: [{ x: 0.1, y: 0.2 }, { x: 0.3, y: 0.4 }],
        updatedAt: 106,
      }],
      createdAt: 107,
    })).toBe(true);
  });

  it("rejects objects outside the normalized board", () => {
    expect(isWhiteboardPayload({
      type: "STWB1",
      kind: "object-upsert",
      object: { ...baseObject, kind: "text", text: "越界", fontSize: 22, x: 0.9, width: 0.3 },
      createdAt: 103,
    })).toBe(false);
  });

  it("rejects unsupported or oversized inline images", () => {
    const payload = (dataUrl: string) => ({
      type: "STWB1",
      kind: "object-upsert",
      object: { ...baseObject, kind: "image", fileName: "board.png", dataUrl },
      createdAt: 104,
    });

    expect(isWhiteboardPayload(payload("data:image/png;base64,AA=="))).toBe(false);
    expect(isWhiteboardPayload(payload("data:image/jpeg;base64," + "A".repeat(MAX_WHITEBOARD_IMAGE_DATA_URL_LENGTH + 1)))).toBe(false);
  });

  it("accepts professional diagram updates and sync requests", () => {
    expect(isWhiteboardPayload({
      type: "STDG2",
      kind: "diagram-update",
      update: new Uint8Array([1, 2, 3]),
      createdAt: 108,
    })).toBe(true);
    expect(isWhiteboardPayload({
      type: "STDG2",
      kind: "diagram-sync-request",
      requestId: "peer-a-sync-1",
      createdAt: 109,
    })).toBe(true);
  });
});

const strokeStartPayload = (extra: Record<string, unknown>) => ({
  type: "STWB1",
  kind: "stroke-start",
  strokeId: "peer-stroke-1",
  color: "#2563eb",
  width: 7,
  point: { x: 0.1, y: 0.2 },
  createdAt: 110,
  ...extra,
});

describe("whiteboard brush styles", () => {
  it("accepts every brush kind and defaults a missing brush to pen", () => {
    for (const brush of ["pen", "marker", "pencil", "brush"]) {
      expect(isWhiteboardPayload(strokeStartPayload({ brush }))).toBe(true);
    }
    // 旧客户端的 stroke-start 不带 brush 字段，仍需通过校验并按钢笔渲染。
    expect(isWhiteboardPayload(strokeStartPayload({}))).toBe(true);
    expect(isWhiteboardPayload(strokeStartPayload({ brush: "spray" }))).toBe(false);
  });

  it("accepts custom colors and the new width presets", () => {
    expect(isWhiteboardPayload(strokeStartPayload({ color: "#12ab34" }))).toBe(true);
    for (const width of [2, 4, 7, 12, 20]) {
      expect(isWhiteboardPayload(strokeStartPayload({ width }))).toBe(true);
    }
  });

  it("keeps brush on snapshot strokes", () => {
    expect(isWhiteboardPayload({
      type: "STWB1",
      kind: "snapshot",
      strokes: [{
        strokeId: "peer-stroke-2",
        sourcePeerId: "peer-a",
        color: "#db2777",
        width: 12,
        brush: "marker",
        points: [{ x: 0.1, y: 0.2 }, { x: 0.3, y: 0.4 }],
        updatedAt: 111,
      }],
      createdAt: 112,
    })).toBe(true);
  });

  it("preserves brush through document export and import", () => {
    const strokes = [{
      strokeId: "stroke-brush",
      sourcePeerId: "peer-a",
      color: "#2563eb",
      width: 7,
      brush: "brush" as const,
      points: [{ x: 0.1, y: 0.2 }],
      updatedAt: 113,
    }, {
      strokeId: "stroke-legacy",
      sourcePeerId: "peer-a",
      color: "#12ab34",
      width: 2,
      points: [{ x: 0.2, y: 0.3 }],
      updatedAt: 114,
    }];
    const exported = createWhiteboardDocument(strokes, [], { width: 720, height: 1280 });
    const imported = parseWhiteboardDocument(JSON.stringify(exported));

    expect(imported.strokes[0].brush).toBe("brush");
    // 旧文件没有 brush 字段，导入后保持缺省（渲染时按钢笔处理）。
    expect(imported.strokes[1].brush).toBeUndefined();
  });
});
