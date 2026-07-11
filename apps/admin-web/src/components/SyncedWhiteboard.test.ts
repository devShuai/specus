import { describe, expect, it } from "vitest";
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
    expect(isWhiteboardPayload(payload("data:image/jpeg;base64," + "A".repeat(49 * 1024)))).toBe(false);
  });
});
