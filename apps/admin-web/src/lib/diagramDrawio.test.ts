import { DOMParser } from "@xmldom/xmldom";
import { deflateRaw } from "pako";
import { describe, expect, it } from "vitest";
import { createDiagramDocument } from "./diagramDocument";
import type { DiagramEdge, DiagramNode } from "./diagramDocument";
import { exportDrawioDocument, inflateRawWithLimit, parseDrawioDocument } from "./diagramDrawio";

const container: DiagramNode = {
  id: "container-1",
  kind: "swimlane",
  label: "订单处理",
  x: 40,
  y: 50,
  width: 520,
  height: 340,
  zIndex: 0,
  swimlaneDirection: "vertical",
  style: { fillColor: "#f8fafc", strokeColor: "#475569", fontColor: "#172033", strokeWidth: 2 },
};

const lane: DiagramNode = {
  ...container,
  id: "lane-1",
  kind: "lane",
  label: "审核组",
  x: 32,
  y: 0,
  width: 180,
  height: 340,
  parentId: container.id,
  swimlaneDirection: undefined,
};

const processNode: DiagramNode = {
  id: "process-1",
  kind: "subprocess",
  label: "校验订单",
  x: 40,
  y: 70,
  width: 160,
  height: 72,
  zIndex: 1,
  parentId: lane.id,
  locked: true,
  rotation: 90,
  style: {
    fillColor: "#dbeafe",
    strokeColor: "#2563eb",
    fontColor: "#172033",
    labelBackgroundColor: "none",
    strokeWidth: 2,
    dashed: true,
    linePattern: "dotted",
    fontSize: 18,
    fontFamily: "rounded",
    bold: false,
    italic: true,
    underline: true,
    align: "left",
    verticalAlign: "bottom",
    spacing: 16,
    opacity: 75,
    shadow: false,
    rounded: true,
    flipH: true,
    flipV: false,
  },
};

const endNode: DiagramNode = {
  ...processNode,
  id: "end-1",
  kind: "end",
  label: "结束",
  x: 300,
  parentId: lane.id,
};

const edge: DiagramEdge = {
  id: "edge-1",
  label: "通过",
  sourceId: processNode.id,
  targetId: endNode.id,
  sourcePort: "east",
  targetPort: "west",
  waypoints: [{ x: 220, y: 150 }, { x: 280, y: 150 }],
  zIndex: 0,
  style: {
    strokeColor: "#64748b",
    fontColor: "#334155",
    strokeWidth: 2,
    edgeType: "elbow",
    startArrow: "oval",
    endArrow: "open",
    startSize: 12,
    endSize: 16,
    linePattern: "dashed",
    dashed: true,
    fontSize: 14,
    fontFamily: "mono",
    bold: true,
    italic: false,
    underline: true,
    align: "right",
    labelBackgroundColor: "none",
    opacity: 50,
  },
};

const parser = new DOMParser() as unknown as globalThis.DOMParser;

describe("draw.io diagram compatibility", () => {
  it("round-trips nested nodes and edge routes through an uncompressed mxfile", () => {
    const document = createDiagramDocument(
      [container, lane, processNode, endNode],
      [edge],
      { width: 2400, height: 1600, gridSize: 10 },
      new Date("2026-07-13T00:00:00.000Z"),
    );
    const xml = exportDrawioDocument(document, "订单流程");
    const imported = parseDrawioDocument(xml, parser);

    expect(xml).toContain('compressed="false"');
    expect(imported.nodes).toEqual(document.nodes);
    expect(imported.edges).toEqual(document.edges);
  });

  it("imports common draw.io styles without shuai-tunnel metadata", () => {
    const xml = `<?xml version="1.0"?><mxGraphModel dx="1200" dy="800" gridSize="10"><root>
      <mxCell id="0"/><mxCell id="1" parent="0"/>
      <mxCell id="n1" value="判断" style="rhombus;fillColor=#fef3c7;strokeColor=#d97706;" vertex="1" parent="1"><mxGeometry x="20" y="30" width="120" height="80" as="geometry"/></mxCell>
      <mxCell id="n2" value="完成" style="ellipse;fillColor=#dcfce7;strokeColor=#16a34a;" vertex="1" parent="1"><mxGeometry x="220" y="30" width="120" height="60" as="geometry"/></mxCell>
      <mxCell id="e1" value="是" style="edgeStyle=orthogonalEdgeStyle;exitX=1;exitY=0.5;entryX=0;entryY=0.5;" edge="1" parent="1" source="n1" target="n2"><mxGeometry relative="1" as="geometry"/></mxCell>
    </root></mxGraphModel>`;
    const imported = parseDrawioDocument(xml, parser);

    expect(imported.nodes.map((node) => node.kind)).toEqual(["decision", "ellipse"]);
    expect(imported.nodes.every((node) => node.style.bold === undefined)).toBe(true);
    expect(imported.edges[0]).toMatchObject({ sourcePort: "east", targetPort: "west" });
  });

  it("does not turn an unspecified bold style into bold during export", () => {
    const regularItalic: DiagramNode = {
      ...processNode,
      id: "regular-italic",
      parentId: undefined,
      style: { ...processNode.style, bold: undefined, italic: true, underline: false },
    };
    const xml = exportDrawioDocument(createDiagramDocument([regularItalic], [], { width: 800, height: 600, gridSize: 10 }));

    expect(xml).toContain("fontStyle=2");
    expect(parseDrawioDocument(xml, parser).nodes[0].style.bold).toBe(false);
  });

  it("preserves the manual input symbol instead of exporting it as a hexagon", () => {
    const manualInput: DiagramNode = {
      ...processNode,
      id: "manual-input",
      kind: "manualInput",
      label: "人工录入",
      parentId: undefined,
    };
    const document = createDiagramDocument([manualInput], [], { width: 1200, height: 800, gridSize: 10 });
    const xml = exportDrawioDocument(document);

    expect(xml).toContain("shape=manualInput");
    expect(xml).not.toContain("shape=hexagon");
    expect(parseDrawioDocument(xml, parser).nodes[0].kind).toBe("manualInput");
  });

  it("round-trips an official draw.io stencil reference", () => {
    const stencilNode: DiagramNode = {
      ...processNode,
      id: "cloud-icon",
      kind: "rectangle",
      stencilName: "mxgraph.aws4.lambda_function",
      stencilLibrary: "aws4.xml",
      parentId: undefined,
    };
    const document = createDiagramDocument([stencilNode], [], { width: 2400, height: 1600, gridSize: 10 });
    const xml = exportDrawioDocument(document);
    const imported = parseDrawioDocument(xml, parser);

    expect(xml).toContain("shape=mxgraph.aws4.lambda_function");
    expect(imported.nodes[0]).toEqual(document.nodes[0]);
  });

  it("exports each application page as a draw.io diagram page", () => {
    const pages = [
      { id: "page-a", name: "页面 A", order: 0 },
      { id: "page-b", name: "页面 B", order: 1 },
    ];
    const document = createDiagramDocument(
      [{ ...processNode, id: "node-a", pageId: pages[0].id, parentId: undefined }, { ...endNode, id: "node-b", pageId: pages[1].id, parentId: undefined }],
      [],
      { width: 2400, height: 1600, gridSize: 10 },
      new Date("2026-07-13T00:00:00.000Z"),
      pages,
      pages[0].id,
    );
    const xml = exportDrawioDocument(document);

    expect(xml.match(/<diagram /g)).toHaveLength(2);
    expect(xml).toContain('name="页面 A"');
    expect(xml).toContain('name="页面 B"');
    const imported = parseDrawioDocument(xml, parser);
    expect(imported.pages).toEqual(pages);
    expect(imported.activePageId).toBe(pages[0].id);
    expect(imported.nodes.map((node) => ({ id: node.id, pageId: node.pageId }))).toEqual([
      { id: "node-a", pageId: pages[0].id },
      { id: "node-b", pageId: pages[1].id },
    ]);
  });

  it("imports compressed pages and remaps repeated cell ids across pages", () => {
    const graphXml = (label: string) => `<mxGraphModel dx="900" dy="600"><root><mxCell id="0"/><mxCell id="1" parent="0"/><mxCell id="n1" value="${label}" style="rounded=1;" vertex="1" parent="1"><mxGeometry x="10" y="20" width="120" height="50" as="geometry"/></mxCell></root></mxGraphModel>`;
    const compress = (value: string) => {
      const compressed = deflateRaw(encodeURIComponent(value));
      let binary = "";
      compressed.forEach((byte) => { binary += String.fromCharCode(byte); });
      return btoa(binary);
    };
    const xml = `<mxfile><diagram id="page-a" name="第一页">${compress(graphXml("节点 A"))}</diagram><diagram id="page-b" name="第二页">${compress(graphXml("节点 B"))}</diagram></mxfile>`;

    const imported = parseDrawioDocument(xml, parser);

    expect(imported.pages?.map((page) => page.name)).toEqual(["第一页", "第二页"]);
    expect(imported.nodes).toHaveLength(2);
    expect(new Set(imported.nodes.map((node) => node.id)).size).toBe(2);
    expect(imported.nodes.map((node) => node.pageId)).toEqual(["page-a", "page-b"]);
  });

  it("decodes the default compressed draw.io diagram payload", () => {
    const graphXml = '<mxGraphModel dx="900" dy="600"><root><mxCell id="0"/><mxCell id="1" parent="0"/><mxCell id="n1" value="开始" style="ellipse;" vertex="1" parent="1"><mxGeometry x="10" y="20" width="120" height="50" as="geometry"/></mxCell></root></mxGraphModel>';
    const compressed = deflateRaw(encodeURIComponent(graphXml));
    let binary = "";
    compressed.forEach((value) => { binary += String.fromCharCode(value); });
    const xml = `<mxfile><diagram>${btoa(binary)}</diagram></mxfile>`;

    expect(parseDrawioDocument(xml, parser).nodes[0].kind).toBe("start");
  });

  it("rejects malformed and damaged draw.io files", () => {
    expect(() => parseDrawioDocument("<mxfile>", parser)).toThrow("不是有效的 XML");
    expect(() => parseDrawioDocument("<mxfile><diagram>bad</diagram></mxfile>", parser))
      .toThrow("压缩图页解码失败");
  });

  it("stops inflating compressed content at the configured output limit", () => {
    const compressed = deflateRaw("x".repeat(4096));
    expect(() => inflateRawWithLimit(compressed, 1024)).toThrow("解压后超过 1 KB");
  });
});
