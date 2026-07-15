import { describe, expect, it } from "vitest";
import * as Y from "yjs";
import {
  createDiagramDocument,
  decodeDiagramUpdate,
  DIAGRAM_DOCUMENT_FORMAT,
  DIAGRAM_NODE_KINDS,
  encodeDiagramUpdate,
  isDiagramPayload,
  MAX_DIAGRAM_DOCUMENT_BYTES,
  MAX_DIAGRAM_EDGES,
  MAX_DIAGRAM_NODES,
  parseDiagramDocument,
} from "./diagramDocument";
import type { DiagramComment, DiagramEdge, DiagramNode } from "./diagramDocument";

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
    waypoints: [{ x: 140, y: 130 }],
    zIndex: 0,
    style: {
      strokeColor: "#64748b",
      fontColor: "#334155",
      strokeWidth: 2,
      edgeType: "orthogonal",
      startArrow: "oval",
      endArrow: "block",
    },
  },
];

describe("diagram document", () => {
  it("accepts every professional palette node kind", () => {
    const paletteNodes = DIAGRAM_NODE_KINDS
      .filter((kind) => kind !== "lane")
      .map((kind, index): DiagramNode => ({
        ...nodes[1],
        id: `palette-${kind}`,
        kind,
        x: (index % 8) * 180,
        y: Math.floor(index / 8) * 110,
        zIndex: index,
      }));
    const exported = createDiagramDocument(paletteNodes, [], { width: 2400, height: 1600, gridSize: 10 });

    expect(parseDiagramDocument(JSON.stringify(exported)).nodes.map((node) => node.kind))
      .toEqual(DIAGRAM_NODE_KINDS.filter((kind) => kind !== "lane"));
  });

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

  it("round-trips the complete inspector style set", () => {
    const styledNode: DiagramNode = {
      ...nodes[1],
      style: {
        ...nodes[1].style,
        fillColor: "none",
        labelBackgroundColor: "#fff7e6",
        linePattern: "dotted",
        dashed: true,
        fontSize: 21,
        fontFamily: "rounded",
        bold: false,
        italic: true,
        underline: true,
        align: "right",
        verticalAlign: "bottom",
        spacing: 18,
        opacity: 72,
        shadow: true,
        rounded: true,
        flipH: true,
        flipV: false,
      },
    };
    const styledEdge: DiagramEdge = {
      ...edges[0],
      style: {
        ...edges[0].style,
        labelBackgroundColor: "none",
        linePattern: "dashed",
        dashed: true,
        startSize: 12,
        endSize: 18,
        fontSize: 16,
        fontFamily: "mono",
        bold: true,
        italic: true,
        underline: true,
        align: "left",
        opacity: 64,
      },
    };
    const exported = createDiagramDocument([styledNode, nodes[0]], [styledEdge], { width: 2400, height: 1600, gridSize: 10 });
    const imported = parseDiagramDocument(JSON.stringify(exported));

    expect(imported.nodes[0]).toEqual(styledNode);
    expect(imported.edges[0]).toEqual(styledEdge);
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
    expect(() => parseDiagramDocument(JSON.stringify({
      ...exported,
      edges: [{ ...edges[0], waypoints: [{ x: Number.NaN, y: 20 }] }],
    }))).toThrow("无效、重复或超出限制");
    expect(() => parseDiagramDocument(JSON.stringify({
      ...exported,
      nodes: [{ ...nodes[0], style: { ...nodes[0].style, fontFamily: "comic", spacing: 90 } }],
      edges: [],
    }))).toThrow("无效、重复或超出限制");
    expect(() => parseDiagramDocument(JSON.stringify({
      ...exported,
      edges: [{ ...edges[0], style: { ...edges[0].style, startSize: 80 } }],
    }))).toThrow("无效、重复或超出限制");
  });

  it("accepts nested containers and rejects invalid or cyclic parents", () => {
    const container: DiagramNode = {
      ...nodes[0],
      id: "container-1",
      kind: "container",
      label: "业务域",
      width: 480,
      height: 320,
    };
    const nested = { ...nodes[1], parentId: container.id };
    const exported = createDiagramDocument([container, nested], [], { width: 2400, height: 1600, gridSize: 10 });

    expect(parseDiagramDocument(JSON.stringify(exported)).nodes[1].parentId).toBe(container.id);
    expect(() => parseDiagramDocument(JSON.stringify({
      ...exported,
      nodes: [container, { ...nested, parentId: "missing" }],
    }))).toThrow("无效、重复或超出限制");
    expect(() => parseDiagramDocument(JSON.stringify({
      ...exported,
      nodes: [{ ...container, parentId: nested.id }, { ...nested, kind: "container" }],
    }))).toThrow("无效、重复或超出限制");

    const pool: DiagramNode = { ...container, id: "pool-1", kind: "swimlane" };
    const lane: DiagramNode = { ...container, id: "lane-1", kind: "lane", parentId: pool.id };
    const laneNode: DiagramNode = { ...nodes[1], parentId: lane.id };
    const swimlaneDocument = createDiagramDocument([pool, lane, laneNode], [], { width: 2400, height: 1600, gridSize: 10 });
    expect(parseDiagramDocument(JSON.stringify(swimlaneDocument)).nodes.map((node) => node.kind))
      .toEqual(["swimlane", "lane", "process"]);
    expect(() => parseDiagramDocument(JSON.stringify({
      ...swimlaneDocument,
      nodes: [container, { ...lane, parentId: container.id }, laneNode],
    }))).toThrow("无效、重复或超出限制");
  });

  it("round-trips multi-page metadata and rejects unknown page references", () => {
    const pages = [
      { id: "page-a", name: "主流程", order: 0 },
      { id: "page-b", name: "异常流程", order: 1 },
    ];
    const pagedNodes = [
      { ...nodes[0], pageId: pages[0].id, locked: true, rotation: 90, style: { ...nodes[0].style, fontSize: 18, italic: true, align: "left" as const } },
      { ...nodes[1], pageId: pages[1].id },
    ];
    const comments: DiagramComment[] = [{ id: "comment-1", pageId: pages[1].id, cellId: pagedNodes[1].id, author: "peer-a", text: "检查异常分支", createdAt: 1_700_000_000_000, resolved: false }];
    const exported = createDiagramDocument(pagedNodes, [], { width: 2400, height: 1600, gridSize: 10 }, new Date(), pages, pages[1].id, comments);
    const imported = parseDiagramDocument(JSON.stringify(exported));

    expect(imported.pages).toEqual(pages);
    expect(imported.activePageId).toBe(pages[1].id);
    expect(imported.nodes).toEqual(pagedNodes);
    expect(imported.comments).toEqual(comments);
    expect(() => parseDiagramDocument(JSON.stringify({
      ...exported,
      nodes: [{ ...pagedNodes[0], pageId: "missing" }],
    }))).toThrow("无效、重复或超出限制");
    expect(() => parseDiagramDocument(JSON.stringify({
      ...exported,
      comments: [{ ...comments[0], pageId: "missing" }],
    }))).toThrow("无效、重复或超出限制");
  });

  it("rejects malformed, unsupported, and oversized files", () => {
    expect(() => parseDiagramDocument("not-json")).toThrow("不是有效的 JSON");
    expect(() => parseDiagramDocument(JSON.stringify({ format: DIAGRAM_DOCUMENT_FORMAT, version: 2 })))
      .toThrow("不支持的流程图文件格式或版本");
    expect(() => parseDiagramDocument("x".repeat(MAX_DIAGRAM_DOCUMENT_BYTES + 1)))
      .toThrow("流程图文件超过 2 MB");
  });

  it("round-trips the maximum supported graph size", () => {
    const largeNodes: DiagramNode[] = Array.from({ length: MAX_DIAGRAM_NODES }, (_, index) => ({
      ...nodes[1],
      id: `node-${index}`,
      label: `节点 ${index}`,
      x: (index % 40) * 180,
      y: Math.floor(index / 40) * 96,
      zIndex: index,
    }));
    const largeEdges: DiagramEdge[] = Array.from({ length: MAX_DIAGRAM_EDGES }, (_, index) => ({
      ...edges[0],
      id: `edge-${index}`,
      sourceId: largeNodes[index % largeNodes.length].id,
      targetId: largeNodes[(index + 1) % largeNodes.length].id,
      zIndex: index,
    }));
    const document = createDiagramDocument(largeNodes, largeEdges, { width: 10000, height: 10000, gridSize: 10 });
    const source = JSON.stringify(document);

    expect(new TextEncoder().encode(source).length).toBeLessThan(MAX_DIAGRAM_DOCUMENT_BYTES);
    const imported = parseDiagramDocument(source);
    expect(imported.nodes).toHaveLength(MAX_DIAGRAM_NODES);
    expect(imported.edges).toHaveLength(MAX_DIAGRAM_EDGES);
  });

  it("preserves a draw.io stencil reference as part of a synchronized node", () => {
    const stencilNode: DiagramNode = {
      ...nodes[1],
      id: "aws-lambda",
      kind: "rectangle",
      stencilName: "mxgraph.aws4.lambda_function",
      stencilLibrary: "aws4.xml",
    };
    const document = createDiagramDocument([stencilNode], [], { width: 2400, height: 1600, gridSize: 10 });

    expect(parseDiagramDocument(JSON.stringify(document)).nodes[0]).toMatchObject({
      stencilName: "mxgraph.aws4.lambda_function",
      stencilLibrary: "aws4.xml",
    });
    expect(() => parseDiagramDocument(JSON.stringify({
      ...document,
      nodes: [{ ...stencilNode, stencilLibrary: "../aws4.xml" }],
    }))).toThrow("包含无效");
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

  it("validates collaborative presence updates", () => {
    expect(isDiagramPayload({
      type: "STDG1",
      kind: "diagram-presence",
      pageId: "page-1",
      selectedIds: ["node-1"],
      cursor: { x: 120, y: 80 },
      createdAt: Date.now(),
    })).toBe(true);
    expect(isDiagramPayload({
      type: "STDG1",
      kind: "diagram-presence",
      pageId: "page-1",
      selectedIds: Array.from({ length: 101 }, (_, index) => `node-${index}`),
      createdAt: Date.now(),
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
