import { describe, expect, it } from "vitest";
import * as Y from "yjs";
import {
  createDiagramDocument,
  decodeDiagramUpdate,
  DIAGRAM_DOCUMENT_FORMAT,
  encodeDiagramUpdate,
  isDiagramPayload,
  MAX_DIAGRAM_DOCUMENT_BYTES,
  parseDiagramDocument,
} from "./diagramDocument";
import type { DiagramEdge, DiagramNode } from "./diagramDocument";

const nodes: DiagramNode[] = [
  {
    id: "node-start",
    kind: "start",
    label: "开始",
    x: 80,
    y: 60,
    width: 120,
    height: 52,
    zIndex: 0,
    style: {
      fillColor: "#dcfce7",
      strokeColor: "#16a34a",
      fontColor: "#172033",
      strokeWidth: 2,
    },
  },
  {
    id: "node-process",
    kind: "process",
    label: "处理请求",
    x: 80,
    y: 180,
    width: 160,
    height: 72,
    zIndex: 1,
    style: {
      fillColor: "#dbeafe",
      strokeColor: "#2563eb",
      fontColor: "#172033",
      strokeWidth: 2,
    },
  },
];

const edges: DiagramEdge[] = [
  {
    id: "edge-1",
    label: "",
    sourceId: "node-start",
    targetId: "node-process",
    sourcePort: "south",
    targetPort: "north",
    zIndex: 0,
    style: {
      strokeColor: "#64748b",
      fontColor: "#334155",
      strokeWidth: 2,
    },
  },
];

describe("diagram document", () => {
  it("round-trips an editable graph document", () => {
    const exported = createDiagramDocument(
      nodes,
      edges,
      { width: 2400, height: 1600, gridSize: 10 },
      new Date("2026-07-12T12:00:00.000Z"),
    );
    const imported = parseDiagramDocument(JSON.stringify(exported));

    expect(imported.format).toBe(DIAGRAM_DOCUMENT_FORMAT);
    expect(imported.exportedAt).toBe("2026-07-12T12:00:00.000Z");
    expect(imported.nodes).toEqual(nodes);
    expect(imported.edges).toEqual(edges);
  });

  it("rejects duplicate ids, invalid geometry, and dangling edges", () => {
    const exported = createDiagramDocument(nodes, edges, { width: 2400, height: 1600, gridSize: 10 });

    expect(() => parseDiagramDocument(JSON.stringify({
      ...exported,
      nodes: [nodes[0], { ...nodes[1], id: nodes[0].id }],
    }))).toThrow("无效、重复或超出限制");
    expect(() => parseDiagramDocument(JSON.stringify({
      ...exported,
      nodes: [{ ...nodes[0], width: 0 }],
      edges: [],
    }))).toThrow("无效、重复或超出限制");
    expect(() => parseDiagramDocument(JSON.stringify({
      ...exported,
      edges: [{ ...edges[0], targetId: "missing" }],
    }))).toThrow("无效、重复或超出限制");
  });

  it("rejects malformed, unsupported, and oversized files", () => {
    expect(() => parseDiagramDocument("not-json")).toThrow("不是有效的 JSON");
    expect(() => parseDiagramDocument(JSON.stringify({ format: DIAGRAM_DOCUMENT_FORMAT, version: 2 })))
      .toThrow("不支持的流程图文件格式或版本");
    expect(() => parseDiagramDocument("x".repeat(MAX_DIAGRAM_DOCUMENT_BYTES + 1)))
      .toThrow("流程图文件超过 2 MB");
  });

  it("encodes Yjs updates for JSON transport", () => {
    const update = new Uint8Array([0, 1, 2, 127, 128, 254, 255]);
    const encoded = encodeDiagramUpdate(update);

    expect(Array.from(decodeDiagramUpdate(encoded))).toEqual(Array.from(update));
    expect(isDiagramPayload({
      type: "STDG1",
      kind: "diagram-update",
      update: encoded,
      createdAt: 1,
    })).toBe(true);
    expect(isDiagramPayload({
      type: "STDG1",
      kind: "diagram-update",
      update: "not base64",
      createdAt: 1,
    })).toBe(false);
  });

  it("validates sync requests", () => {
    expect(isDiagramPayload({
      type: "STDG1",
      kind: "diagram-sync-request",
      requestId: "peer-a-request-1",
      createdAt: 1,
    })).toBe(true);
    expect(isDiagramPayload({
      type: "STDG1",
      kind: "diagram-sync-request",
      requestId: "",
      createdAt: 1,
    })).toBe(false);
  });

  it("converges concurrent object updates through encoded Yjs messages", () => {
    const first = new Y.Doc();
    const second = new Y.Doc();
    first.getMap("nodes").set("node-a", nodes[0]);
    second.getMap("nodes").set("node-b", nodes[1]);

    const firstUpdate = encodeDiagramUpdate(Y.encodeStateAsUpdate(first));
    const secondUpdate = encodeDiagramUpdate(Y.encodeStateAsUpdate(second));
    Y.applyUpdate(first, decodeDiagramUpdate(secondUpdate));
    Y.applyUpdate(second, decodeDiagramUpdate(firstUpdate));

    expect(Array.from(first.getMap("nodes").keys()).sort()).toEqual(["node-a", "node-b"]);
    expect(Array.from(second.getMap("nodes").keys()).sort()).toEqual(["node-a", "node-b"]);
    first.destroy();
    second.destroy();
  });
});
