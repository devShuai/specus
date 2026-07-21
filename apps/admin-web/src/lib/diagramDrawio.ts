import { Inflate } from "pako";
import {
  createDiagramDocument,
  DIAGRAM_NODE_KINDS,
  isDiagramGraphState,
  MAX_DIAGRAM_DOCUMENT_BYTES,
  MAX_DIAGRAM_PAGES,
} from "./diagramDocument";
import type {
  DiagramDocumentV1,
  DiagramArrowType,
  DiagramEdge,
  DiagramEdgeType,
  DiagramFontFamily,
  DiagramLinePattern,
  DiagramNode,
  DiagramNodeKind,
  DiagramPage,
  DiagramPort,
} from "./diagramDocument";

export const DRAWIO_FILE_EXTENSION = ".drawio";
export const DRAWIO_FILE_MIME = "application/vnd.jgraph.mxfile";
const MAX_DRAWIO_SOURCE_BYTES = MAX_DIAGRAM_DOCUMENT_BYTES * 4;
const MAX_DRAWIO_INFLATED_BYTES = MAX_DRAWIO_SOURCE_BYTES * 3;

interface XmlParser {
  parseFromString(source: string, mimeType: string): Document;
}

export function exportDrawioDocument(document: DiagramDocumentV1, pageName = "Page-1") {
  const exportedAt = document.exportedAt || new Date().toISOString();
  const pages = document.pages?.length
    ? document.pages.slice().sort((left, right) => left.order - right.order)
    : [{ id: document.activePageId ?? "page-1", name: pageName, order: 0 }];
  const fallbackPageId = document.activePageId ?? pages[0].id;
  const diagrams = pages.map((page) => {
    const nodes = document.nodes
      .filter((node) => (node.pageId ?? fallbackPageId) === page.id)
      .slice()
      .sort((a, b) => a.zIndex - b.zIndex)
      .map((node) => drawioNodeXml(node))
      .join("");
    const edges = document.edges
      .filter((edge) => (edge.pageId ?? fallbackPageId) === page.id)
      .slice()
      .sort((a, b) => a.zIndex - b.zIndex)
      .map((edge) => drawioEdgeXml(edge))
      .join("");
    return [
      `<diagram id="${escapeXml(page.id)}" name="${escapeXml(page.name)}">`,
      `<mxGraphModel dx="${document.canvas.width}" dy="${document.canvas.height}" grid="1" gridSize="${document.canvas.gridSize}" page="1" pageScale="1" pageWidth="1169" pageHeight="827">`,
      '<root><mxCell id="0"/><mxCell id="1" parent="0"/>',
      nodes,
      edges,
      "</root></mxGraphModel></diagram>",
    ].join("");
  }).join("");
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<mxfile host="shuai-tunnel" modified="${escapeXml(exportedAt)}" compressed="false">`,
    diagrams,
    "</mxfile>",
  ].join("");
}

export function parseDrawioDocument(source: string, parser?: XmlParser): DiagramDocumentV1 {
  if (new TextEncoder().encode(source).length > MAX_DRAWIO_SOURCE_BYTES) {
    throw new Error("draw.io 文件超过 8 MB，无法导入");
  }
  const xmlParser = parser ?? defaultXmlParser();
  const outer = parseXml(source, xmlParser);
  const diagrams = outer.documentElement.tagName === "mxGraphModel"
    ? []
    : Array.from(outer.getElementsByTagName("diagram"));
  if (diagrams.length > MAX_DIAGRAM_PAGES) {
    throw new Error(`draw.io 文件超过 ${MAX_DIAGRAM_PAGES} 个图页，无法导入`);
  }
  const pageIds = new Set<string>();
  const usedCellIds = new Set<string>();
  const pages: DiagramPage[] = [];
  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  const graphModels = diagrams.length > 0
    ? diagrams.map((diagram) => graphModelFromDiagram(diagram, xmlParser))
    : [outer.documentElement];
  if (graphModels.length === 0 || graphModels.some((model) => model.tagName !== "mxGraphModel")) {
    throw new Error("draw.io 文件不包含可识别的图页");
  }
  graphModels.forEach((graphModel, index) => {
    const diagram = diagrams[index];
    const pageId = diagrams.length > 0
      ? uniqueIdentifier(diagram?.getAttribute("id")?.trim() || `page-${index + 1}`, "page", pageIds)
      : undefined;
    if (pageId) {
      pages.push({
        id: pageId,
        name: cleanPageName(diagram?.getAttribute("name"), index),
        order: index,
      });
    }
    const parsed = parseGraphModel(graphModel, graphModels.length > 1 ? pageId : undefined, usedCellIds);
    nodes.push(...parsed.nodes);
    edges.push(...parsed.edges);
  });
  if (!isDiagramGraphState(nodes, edges)) {
    throw new Error("draw.io 文件包含无效的层级、几何或连线数据");
  }
  const firstGraphModel = graphModels[0];
  return createDiagramDocument(nodes, edges, {
    width: Math.max(...graphModels.map((model) => positiveAttribute(model, "dx", 2400))),
    height: Math.max(...graphModels.map((model) => positiveAttribute(model, "dy", 1600))),
    gridSize: boundedNumber(firstGraphModel.getAttribute("gridSize"), 10, 4, 64),
  }, new Date(), pages.length > 1 ? pages : undefined, pages.length > 1 ? pages[0].id : undefined);
}

function parseGraphModel(graphModel: Element, pageId: string | undefined, usedCellIds: Set<string>) {
  const cells = Array.from(graphModel.getElementsByTagName("mxCell"));
  const vertexCells = cells.filter((cell) => cell.getAttribute("vertex") === "1");
  const parentReferences = new Set(vertexCells.map((cell) => cell.getAttribute("parent")).filter(Boolean));
  const localIds = new Set<string>();
  const remappedIds = new Map<string, string>();
  for (const cell of cells.filter((candidate) => candidate.getAttribute("vertex") === "1" || candidate.getAttribute("edge") === "1")) {
    const id = cell.getAttribute("id")?.trim();
    if (!id || localIds.has(id)) {
      throw new Error("draw.io 图页包含缺失或重复的元素 ID");
    }
    localIds.add(id);
    remappedIds.set(id, uniqueIdentifier(id, pageId ?? "cell", usedCellIds));
  }
  const nodes: DiagramNode[] = [];
  for (let index = 0; index < vertexCells.length; index += 1) {
    const cell = vertexCells[index];
    const originalId = cell.getAttribute("id")?.trim();
    const id = originalId ? remappedIds.get(originalId) : undefined;
    const geometry = firstChildElement(cell, "mxGeometry");
    if (!id || !geometry) {
      continue;
    }
    const style = parseStyle(cell.getAttribute("style") ?? "");
    let kind = nodeKindFromStyle(style, cleanLabel(cell.getAttribute("value") ?? ""));
    const stencilName = style.get("shuaiStencil")?.trim();
    const stencilLibrary = style.get("shuaiStencilLibrary")?.trim();
    if (originalId && parentReferences.has(originalId) && kind !== "swimlane" && kind !== "lane") {
      kind = "container";
    }
    nodes.push({
      id,
      kind,
      ...(stencilName && stencilLibrary ? { stencilName, stencilLibrary } : {}),
      label: cleanLabel(cell.getAttribute("value") ?? ""),
      x: finiteAttribute(geometry, "x", 0),
      y: finiteAttribute(geometry, "y", 0),
      width: positiveAttribute(geometry, "width", kind === "container" || kind === "swimlane" || kind === "lane" ? 480 : 160),
      height: positiveAttribute(geometry, "height", kind === "container" || kind === "swimlane" || kind === "lane" ? 320 : 72),
      zIndex: safeInteger(style.get("shuaiZ"), index),
      ...(pageId ? { pageId } : {}),
      parentId: remapReference(normalizeParentId(cell.getAttribute("parent")), remappedIds),
      ...(style.get("shuaiLocked") === "1" ? { locked: true } : {}),
      ...(boundedNumber(style.get("rotation"), 0, -360, 360) !== 0 ? { rotation: boundedNumber(style.get("rotation"), 0, -360, 360) } : {}),
      ...(kind === "swimlane" && style.has("shuaiDirection")
        ? { swimlaneDirection: style.get("shuaiDirection") === "vertical" ? "vertical" as const : "horizontal" as const }
        : {}),
      style: {
        fillColor: styleColor(style.get("fillColor"), kind === "container" || kind === "swimlane" || kind === "lane" ? "#f8fafc" : "#ffffff"),
        strokeColor: styleColor(style.get("strokeColor"), "#475569"),
        fontColor: styleColor(style.get("fontColor"), "#172033"),
        ...(style.has("labelBackgroundColor")
          ? { labelBackgroundColor: styleColor(style.get("labelBackgroundColor"), "none") }
          : {}),
        strokeWidth: boundedNumber(style.get("strokeWidth"), 2, 1, 12),
        ...(style.get("dashed") === "1" ? { dashed: true } : {}),
        ...(linePatternFromDrawioStyle(style) ? { linePattern: linePatternFromDrawioStyle(style) } : {}),
        ...(style.has("fontSize") ? { fontSize: boundedNumber(style.get("fontSize"), 13, 8, 96) } : {}),
        ...(fontFamilyFromDrawioStyle(style) ? { fontFamily: fontFamilyFromDrawioStyle(style) } : {}),
        ...(style.has("fontStyle") ? {
          bold: (safeInteger(style.get("fontStyle"), 1) & 1) === 1,
          italic: (safeInteger(style.get("fontStyle"), 1) & 2) === 2,
        } : {}),
        ...(style.has("shuaiUnderline") || (safeInteger(style.get("fontStyle"), 0) & 4) === 4
          ? { underline: style.has("shuaiUnderline") ? style.get("shuaiUnderline") === "1" : true }
          : {}),
        ...(style.has("shuaiAlign") || style.get("align") === "left" || style.get("align") === "right"
          ? { align: textAlign(style.get("shuaiAlign") ?? style.get("align")) }
          : {}),
        ...(style.has("shuaiVerticalAlign") || style.get("verticalAlign") === "top" || style.get("verticalAlign") === "bottom"
          ? { verticalAlign: verticalAlign(style.get("shuaiVerticalAlign") ?? style.get("verticalAlign")) }
          : {}),
        ...(style.has("spacing") ? { spacing: boundedNumber(style.get("spacing"), 10, 0, 60) } : {}),
        ...(style.has("opacity") ? { opacity: boundedNumber(style.get("opacity"), 100, 10, 100) } : {}),
        ...(style.has("shadow") ? { shadow: style.get("shadow") === "1" } : {}),
        ...(style.has("rounded") ? { rounded: style.get("rounded") === "1" } : {}),
        ...(style.has("flipH") ? { flipH: style.get("flipH") === "1" } : {}),
        ...(style.has("flipV") ? { flipV: style.get("flipV") === "1" } : {}),
      },
    });
  }

  const nodeIds = new Set(nodes.map((node) => node.id));
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  for (const node of nodes) {
    if (!node.parentId || !nodeIds.has(node.parentId)) {
      delete node.parentId;
    }
    if (node.kind === "swimlane" && node.parentId && nodesById.get(node.parentId)?.kind === "swimlane") {
      node.kind = "lane";
      delete node.swimlaneDirection;
    }
  }
  const edges: DiagramEdge[] = [];
  const edgeCells = cells.filter((cell) => cell.getAttribute("edge") === "1");
  for (let index = 0; index < edgeCells.length; index += 1) {
    const cell = edgeCells[index];
    const originalId = cell.getAttribute("id")?.trim();
    const id = originalId ? remappedIds.get(originalId) : undefined;
    const sourceId = remapReference(cell.getAttribute("source")?.trim(), remappedIds);
    const targetId = remapReference(cell.getAttribute("target")?.trim(), remappedIds);
    if (!id || !sourceId || !targetId || !nodeIds.has(sourceId) || !nodeIds.has(targetId)) {
      continue;
    }
    const style = parseStyle(cell.getAttribute("style") ?? "");
    const geometry = firstChildElement(cell, "mxGeometry");
    const points = geometry ? parseWaypoints(geometry) : [];
    edges.push({
      id,
      label: cleanLabel(cell.getAttribute("value") ?? ""),
      sourceId,
      targetId,
      sourcePort: portFromCoordinates(style.get("exitX"), style.get("exitY")),
      targetPort: portFromCoordinates(style.get("entryX"), style.get("entryY")),
      ...(points.length > 0 ? { waypoints: points } : {}),
      zIndex: safeInteger(style.get("shuaiZ"), index),
      ...(pageId ? { pageId } : {}),
      style: {
        strokeColor: styleColor(style.get("strokeColor"), "#64748b"),
        fontColor: styleColor(style.get("fontColor"), "#334155"),
        ...(style.has("labelBackgroundColor")
          ? { labelBackgroundColor: styleColor(style.get("labelBackgroundColor"), "none") }
          : {}),
        strokeWidth: boundedNumber(style.get("strokeWidth"), 2, 1, 12),
        ...(style.get("dashed") === "1" ? { dashed: true } : {}),
        ...(linePatternFromDrawioStyle(style) ? { linePattern: linePatternFromDrawioStyle(style) } : {}),
        edgeType: edgeTypeFromStyle(style),
        startArrow: arrowTypeFromStyle(style.get("startArrow"), "none"),
        endArrow: arrowTypeFromStyle(style.get("endArrow"), "block"),
        ...(style.has("startSize") ? { startSize: boundedNumber(style.get("startSize"), 8, 4, 40) } : {}),
        ...(style.has("endSize") ? { endSize: boundedNumber(style.get("endSize"), 8, 4, 40) } : {}),
        ...(style.has("fontSize") ? { fontSize: boundedNumber(style.get("fontSize"), 12, 8, 96) } : {}),
        ...(fontFamilyFromDrawioStyle(style) ? { fontFamily: fontFamilyFromDrawioStyle(style) } : {}),
        ...(style.has("fontStyle") ? {
          bold: (safeInteger(style.get("fontStyle"), 0) & 1) === 1,
          italic: (safeInteger(style.get("fontStyle"), 0) & 2) === 2,
        } : {}),
        ...(style.has("shuaiUnderline") || (safeInteger(style.get("fontStyle"), 0) & 4) === 4
          ? { underline: style.has("shuaiUnderline") ? style.get("shuaiUnderline") === "1" : true }
          : {}),
        ...(style.has("shuaiAlign") || style.get("align") === "left" || style.get("align") === "right"
          ? { align: textAlign(style.get("shuaiAlign") ?? style.get("align")) }
          : {}),
        ...(style.has("opacity") ? { opacity: boundedNumber(style.get("opacity"), 100, 10, 100) } : {}),
      },
    });
  }
  return { nodes, edges };
}

function drawioNodeXml(node: DiagramNode) {
  const parent = node.parentId ?? "1";
  return `<mxCell id="${escapeXml(node.id)}" value="${escapeXml(node.label)}" style="${escapeXml(nodeStyle(node))}" vertex="1" parent="${escapeXml(parent)}"><mxGeometry x="${node.x}" y="${node.y}" width="${node.width}" height="${node.height}" as="geometry"/></mxCell>`;
}

function drawioEdgeXml(edge: DiagramEdge) {
  const points = edge.waypoints?.length
    ? `<Array as="points">${edge.waypoints.map((point) => `<mxPoint x="${point.x}" y="${point.y}"/>`).join("")}</Array>`
    : "";
  return `<mxCell id="${escapeXml(edge.id)}" value="${escapeXml(edge.label)}" style="${escapeXml(edgeStyle(edge))}" edge="1" parent="1" source="${escapeXml(edge.sourceId)}" target="${escapeXml(edge.targetId)}"><mxGeometry relative="1" as="geometry">${points}</mxGeometry></mxCell>`;
}

function nodeStyle(node: DiagramNode) {
  const shape = node.stencilName ? `shape=${node.stencilName}` : drawioShape(node.kind);
  const style = [
    `shuaiKind=${node.kind}`,
    `shuaiZ=${node.zIndex}`,
    shape,
    "whiteSpace=wrap",
    "html=1",
    `align=${node.style.align ?? "center"}`,
    `verticalAlign=${node.style.verticalAlign ?? "middle"}`,
    `fillColor=${node.style.fillColor}`,
    `strokeColor=${node.style.strokeColor}`,
    `fontColor=${node.style.fontColor}`,
    `strokeWidth=${node.style.strokeWidth}`,
  ];
  if (node.stencilName && node.stencilLibrary) {
    style.push(`shuaiStencil=${node.stencilName}`, `shuaiStencilLibrary=${node.stencilLibrary}`);
  }
  if (node.locked) style.push("shuaiLocked=1");
  if (node.style.fontSize !== undefined) style.push(`fontSize=${node.style.fontSize}`);
  if (node.style.fontFamily !== undefined) style.push(`shuaiFontFamily=${node.style.fontFamily}`, `fontFamily=${drawioFontFamily(node.style.fontFamily)}`);
  if (node.style.bold !== undefined || node.style.italic !== undefined || node.style.underline !== undefined) {
    style.push(`fontStyle=${(node.style.bold === true ? 1 : 0) + (node.style.italic ? 2 : 0) + (node.style.underline ? 4 : 0)}`);
  }
  if (node.style.underline !== undefined) style.push(`shuaiUnderline=${node.style.underline ? 1 : 0}`);
  if (node.style.align !== undefined) style.push(`shuaiAlign=${node.style.align}`, `align=${node.style.align}`);
  if (node.style.verticalAlign !== undefined) style.push(`shuaiVerticalAlign=${node.style.verticalAlign}`, `verticalAlign=${node.style.verticalAlign}`);
  if (node.style.spacing !== undefined) style.push(`spacing=${node.style.spacing}`);
  if (node.style.labelBackgroundColor !== undefined) style.push(`labelBackgroundColor=${node.style.labelBackgroundColor}`);
  if (node.rotation !== undefined) style.push(`rotation=${node.rotation}`);
  if (node.style.opacity !== undefined) style.push(`opacity=${node.style.opacity}`);
  if (node.style.shadow !== undefined) style.push(`shadow=${node.style.shadow ? 1 : 0}`);
  if (node.style.rounded !== undefined) style.push(`rounded=${node.style.rounded ? 1 : 0}`);
  if (node.style.flipH !== undefined) style.push(`flipH=${node.style.flipH ? 1 : 0}`);
  if (node.style.flipV !== undefined) style.push(`flipV=${node.style.flipV ? 1 : 0}`);
  if (node.kind === "swimlane" && node.swimlaneDirection) style.push(`shuaiDirection=${node.swimlaneDirection}`, `horizontal=${node.swimlaneDirection === "vertical" ? 0 : 1}`);
  appendLinePattern(style, node.style.linePattern, node.style.dashed);
  return style.filter(Boolean).join(";") + ";";
}

function edgeStyle(edge: DiagramEdge) {
  const style = [
    `shuaiZ=${edge.zIndex}`,
    drawioEdgeRoute(edge.style.edgeType ?? "orthogonal"),
    "rounded=1",
    `startArrow=${edge.style.startArrow ?? "none"}`,
    `endArrow=${edge.style.endArrow ?? "block"}`,
    `startFill=${edge.style.startArrow === "open" || edge.style.startArrow === "none" ? 0 : 1}`,
    `endFill=${edge.style.endArrow === "open" || edge.style.endArrow === "none" ? 0 : 1}`,
    `strokeColor=${edge.style.strokeColor}`,
    `fontColor=${edge.style.fontColor}`,
    `strokeWidth=${edge.style.strokeWidth}`,
  ];
  if (edge.style.startSize !== undefined) style.push(`startSize=${edge.style.startSize}`);
  if (edge.style.endSize !== undefined) style.push(`endSize=${edge.style.endSize}`);
  if (edge.style.fontSize !== undefined) style.push(`fontSize=${edge.style.fontSize}`);
  if (edge.style.fontFamily !== undefined) style.push(`shuaiFontFamily=${edge.style.fontFamily}`, `fontFamily=${drawioFontFamily(edge.style.fontFamily)}`);
  if (edge.style.bold !== undefined || edge.style.italic !== undefined || edge.style.underline !== undefined) {
    style.push(`fontStyle=${(edge.style.bold ? 1 : 0) + (edge.style.italic ? 2 : 0) + (edge.style.underline ? 4 : 0)}`);
  }
  if (edge.style.underline !== undefined) style.push(`shuaiUnderline=${edge.style.underline ? 1 : 0}`);
  if (edge.style.align !== undefined) style.push(`shuaiAlign=${edge.style.align}`, `align=${edge.style.align}`);
  if (edge.style.labelBackgroundColor !== undefined) style.push(`labelBackgroundColor=${edge.style.labelBackgroundColor}`);
  const source = portCoordinates(edge.sourcePort);
  const target = portCoordinates(edge.targetPort);
  if (source) style.push(`exitX=${source.x}`, `exitY=${source.y}`, "exitPerimeter=1");
  if (target) style.push(`entryX=${target.x}`, `entryY=${target.y}`, "entryPerimeter=1");
  appendLinePattern(style, edge.style.linePattern, edge.style.dashed);
  if (edge.style.opacity !== undefined) style.push(`opacity=${edge.style.opacity}`);
  return style.filter(Boolean).join(";") + ";";
}

function drawioShape(kind: DiagramNodeKind) {
  if (kind === "ellipse" || kind === "circle" || kind === "start" || kind === "end" || kind === "connector" || kind === "umlUseCase" || kind === "erAttribute" || kind === "router") return "ellipse";
  if (kind === "diamond" || kind === "decision" || kind === "bpmnGateway" || kind === "erRelationship") return "rhombus";
  if (kind === "triangle") return "triangle";
  if (kind === "hexagon" || kind === "service") return "shape=hexagon;perimeter=hexagonPerimeter2";
  if (kind === "manualInput") return "shape=manualInput";
  if (kind === "document" || kind === "bpmnDataObject") return "shape=document";
  if (kind === "database") return "shape=cylinder3;boundedLbl=1;backgroundOutline=1;size=15";
  if (kind === "actor") return "shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top";
  if (kind === "note") return "shape=note;size=16";
  if (kind === "subprocess") return "rounded=1;double=1";
  if (kind === "data") return "shape=parallelogram;perimeter=parallelogramPerimeter";
  if (kind === "delay") return "shape=delay";
  if (kind === "cloud") return "shape=cloud";
  if (kind === "swimlane") return "swimlane;horizontal=1;startSize=32;container=1;collapsible=1";
  if (kind === "lane") return "swimlane;horizontal=1;startSize=28;container=1;collapsible=0;recursiveResize=0";
  if (kind === "bpmnEvent" || kind === "umlInterface") return "ellipse;double=1";
  if (kind === "umlClass") return "rounded=0;verticalAlign=top;spacingTop=8";
  if (kind === "umlPackage") return "shape=folder;tabWidth=60;tabHeight=20;tabPosition=left";
  if (kind === "umlComponent") return "shape=component";
  if (kind === "entity") return "rounded=0;verticalAlign=top;spacingTop=8";
  if (kind === "server") return "shape=cylinder3;boundedLbl=1;backgroundOutline=1;size=12";
  if (kind === "queue") return "shape=cylinder3;boundedLbl=1;backgroundOutline=1;size=8;direction=south";
  if (kind === "container") return "rounded=1;container=1;collapsible=1;recursiveResize=0;dashed=1;verticalAlign=top;align=left;spacingTop=8;spacingLeft=8";
  return "rounded=1";
}

function drawioEdgeRoute(type: DiagramEdgeType) {
  if (type === "straight") return "edgeStyle=none";
  if (type === "elbow") return "edgeStyle=elbowEdgeStyle;elbow=horizontal";
  if (type === "curved") return "edgeStyle=orthogonalEdgeStyle;curved=1";
  return "edgeStyle=orthogonalEdgeStyle;orthogonalLoop=1;jettySize=auto";
}

function parseXml(source: string, parser: XmlParser) {
  let document: Document;
  try {
    document = parser.parseFromString(source, "application/xml");
  } catch {
    throw new Error("draw.io 文件不是有效的 XML");
  }
  if (!document.documentElement || document.getElementsByTagName("parsererror").length > 0) {
    throw new Error("draw.io 文件不是有效的 XML");
  }
  return document;
}

function decodeCompressedDiagram(encoded: string) {
  try {
    const binary = atob(encoded.replace(/\s+/g, ""));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    const inflated = inflateRawWithLimit(bytes, MAX_DRAWIO_INFLATED_BYTES);
    const decoded = decodeURIComponent(new TextDecoder().decode(inflated));
    if (new TextEncoder().encode(decoded).length > MAX_DRAWIO_SOURCE_BYTES) {
      throw new Error("draw.io 图页解压后超过 8 MB，已拒绝导入");
    }
    return decoded;
  } catch (error) {
    if (error instanceof Error && error.message.includes("解压后超过")) throw error;
    throw new Error("draw.io 压缩图页解码失败，文件可能已损坏");
  }
}

export function inflateRawWithLimit(bytes: Uint8Array, maximumBytes: number) {
  const chunks: Uint8Array[] = [];
  let outputBytes = 0;
  let exceeded = false;
  const inflater = new Inflate({ raw: true, chunkSize: 64 * 1024 });
  inflater.onData = (chunk) => {
    const value = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
    outputBytes += value.byteLength;
    if (outputBytes > maximumBytes) {
      exceeded = true;
      throw new Error(`draw.io 图页解压后超过 ${formatByteLimit(maximumBytes)}，已拒绝导入`);
    }
    chunks.push(value.slice());
  };
  try {
    const completed = inflater.push(bytes, true);
    if (!completed || inflater.err) throw new Error(inflater.msg || "inflate failed");
  } catch (error) {
    if (exceeded) throw new Error(`draw.io 图页解压后超过 ${formatByteLimit(maximumBytes)}，已拒绝导入`);
    throw error;
  }
  const result = new Uint8Array(outputBytes);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function formatByteLimit(bytes: number) {
  if (bytes % (1024 * 1024) === 0) return `${bytes / 1024 / 1024} MB`;
  if (bytes % 1024 === 0) return `${bytes / 1024} KB`;
  return `${bytes} B`;
}

function graphModelFromDiagram(diagram: Element, parser: XmlParser) {
  const embedded = firstChildElement(diagram, "mxGraphModel");
  if (embedded) {
    return embedded;
  }
  const compressed = diagram.textContent?.trim();
  if (!compressed) {
    throw new Error("draw.io 图页缺少 mxGraphModel");
  }
  const decoded = parseXml(decodeCompressedDiagram(compressed), parser).documentElement;
  if (decoded.tagName !== "mxGraphModel") {
    throw new Error("draw.io 图页缺少 mxGraphModel");
  }
  return decoded;
}

function uniqueIdentifier(preferred: string, namespace: string, used: Set<string>) {
  const normalized = preferred.slice(0, 160) || namespace;
  if (!used.has(normalized)) {
    used.add(normalized);
    return normalized;
  }
  const prefix = `${namespace}-${preferred}`.slice(0, 152) || namespace;
  let sequence = 2;
  let candidate = prefix;
  while (used.has(candidate)) {
    candidate = `${prefix.slice(0, 152)}-${sequence}`;
    sequence += 1;
  }
  used.add(candidate);
  return candidate;
}

function remapReference(value: string | undefined, remappedIds: Map<string, string>) {
  return value ? remappedIds.get(value) : undefined;
}

function cleanPageName(value: string | null | undefined, index: number) {
  const normalized = cleanLabel(value ?? "").replace(/\s+/g, " ").trim();
  return normalized.slice(0, 80) || `页面 ${index + 1}`;
}

function parseStyle(value: string) {
  const result = new Map<string, string>();
  for (const part of value.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) {
      if (part.trim()) result.set("shape", part.trim());
      continue;
    }
    result.set(part.slice(0, separator).trim(), part.slice(separator + 1).trim());
  }
  return result;
}

function nodeKindFromStyle(style: Map<string, string>, label: string): DiagramNodeKind {
  const custom = style.get("shuaiKind");
  if (custom && isNodeKind(custom)) return custom;
  const shape = style.get("shape") ?? "";
  if (style.get("swimlane") === "1" || shape === "swimlane") return "swimlane";
  if (style.get("container") === "1") return "container";
  if (style.get("double") === "1") return "subprocess";
  if (shape === "rhombus") return "decision";
  if (shape === "triangle") return "triangle";
  if (shape === "hexagon") return "hexagon";
  if (shape === "manualInput") return "manualInput";
  if (shape === "document") return "document";
  if (shape === "cylinder" || shape === "cylinder3") return "database";
  if (shape === "umlActor" || shape === "actor") return "actor";
  if (shape === "note") return "note";
  if (shape === "parallelogram") return "data";
  if (shape === "delay") return "delay";
  if (shape === "cloud") return "cloud";
  if (shape === "ellipse" && /^(开始|start)$/i.test(label)) return "start";
  if (shape === "ellipse" && /^(结束|end)$/i.test(label)) return "end";
  if (shape === "ellipse") return "ellipse";
  return "process";
}

function edgeTypeFromStyle(style: Map<string, string>): DiagramEdgeType {
  if (style.get("curved") === "1") return "curved";
  const edgeStyle = style.get("edgeStyle") ?? "";
  if (!edgeStyle || edgeStyle === "none") return "straight";
  if (edgeStyle.includes("elbow")) return "elbow";
  return "orthogonal";
}

function textAlign(value?: string): "left" | "center" | "right" {
  return value === "left" || value === "right" ? value : "center";
}

function verticalAlign(value?: string): "top" | "middle" | "bottom" {
  return value === "top" || value === "bottom" ? value : "middle";
}

function linePatternFromDrawioStyle(style: Map<string, string>): DiagramLinePattern | undefined {
  const custom = style.get("shuaiLinePattern");
  if (custom === "solid" || custom === "dashed" || custom === "dotted") return custom;
  if (style.get("dashed") !== "1") return undefined;
  return /^\s*1(?:\s|$)/.test(style.get("dashPattern") ?? "") ? "dotted" : "dashed";
}

function fontFamilyFromDrawioStyle(style: Map<string, string>): DiagramFontFamily | undefined {
  const custom = style.get("shuaiFontFamily");
  if (custom === "system" || custom === "rounded" || custom === "serif" || custom === "mono") return custom;
  const family = (style.get("fontFamily") ?? "").toLowerCase();
  if (!family) return undefined;
  if (family.includes("mono") || family.includes("menlo") || family.includes("consolas")) return "mono";
  if (family.includes("rounded")) return "rounded";
  if ((family.includes("georgia") || family.includes("times") || family.endsWith("serif")) && !family.includes("sans-serif")) return "serif";
  return "system";
}

function drawioFontFamily(fontFamily: DiagramFontFamily) {
  if (fontFamily === "rounded") return "Arial Rounded MT Bold";
  if (fontFamily === "serif") return "Georgia";
  if (fontFamily === "mono") return "Courier New";
  return "Helvetica";
}

function appendLinePattern(target: string[], pattern?: DiagramLinePattern, dashed?: boolean) {
  const resolved = pattern ?? (dashed ? "dashed" : "solid");
  if (pattern) target.push(`shuaiLinePattern=${resolved}`);
  if (resolved === "solid") return;
  target.push("dashed=1", `dashPattern=${resolved === "dotted" ? "1 4" : "8 4"}`);
}

function arrowTypeFromStyle(value: string | undefined, fallback: DiagramArrowType): DiagramArrowType {
  if (value === "none" || value === "classic" || value === "block" || value === "open" || value === "oval" || value === "diamond") {
    return value;
  }
  return fallback;
}

function parseWaypoints(geometry: Element) {
  const pointsContainer = Array.from(geometry.childNodes).find((child): child is Element => (
    child.nodeType === 1
    && (child as Element).tagName === "Array"
    && (child as Element).getAttribute("as") === "points"
  ));
  if (!pointsContainer) {
    return [];
  }
  return Array.from(pointsContainer.childNodes)
    .filter((child): child is Element => child.nodeType === 1 && (child as Element).tagName === "mxPoint")
    .slice(0, 128)
    .map((point) => ({
      x: finiteAttribute(point, "x", 0),
      y: finiteAttribute(point, "y", 0),
    }));
}

function isNodeKind(value: string): value is DiagramNodeKind {
  return (DIAGRAM_NODE_KINDS as readonly string[]).includes(value);
}

function normalizeParentId(value: string | null) {
  const normalized = value?.trim();
  return normalized && normalized !== "0" && normalized !== "1" ? normalized : undefined;
}

function portFromCoordinates(xValue?: string, yValue?: string): DiagramPort | undefined {
  const x = Number(xValue);
  const y = Number(yValue);
  if (!Number.isFinite(x) || !Number.isFinite(y)) return undefined;
  if (y <= 0.05) return "north";
  if (x >= 0.95) return "east";
  if (y >= 0.95) return "south";
  if (x <= 0.05) return "west";
  return undefined;
}

function portCoordinates(port?: DiagramPort) {
  if (port === "north") return { x: 0.5, y: 0 };
  if (port === "east") return { x: 1, y: 0.5 };
  if (port === "south") return { x: 0.5, y: 1 };
  if (port === "west") return { x: 0, y: 0.5 };
  return undefined;
}

function cleanLabel(value: string) {
  return value
    .replace(/<br\s*\/?\s*>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&")
    .trim()
    .slice(0, 500);
}

function styleColor(value: string | undefined, fallback: string) {
  if (value === "none" || (typeof value === "string" && /^#[0-9a-fA-F]{6}$/.test(value))) return value;
  return fallback;
}

function finiteAttribute(element: Element, name: string, fallback: number) {
  const value = Number(element.getAttribute(name));
  return Number.isFinite(value) ? value : fallback;
}

function positiveAttribute(element: Element, name: string, fallback: number) {
  const value = finiteAttribute(element, name, fallback);
  return value > 0 ? value : fallback;
}

function boundedNumber(value: string | null | undefined, fallback: number, min: number, max: number) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.max(min, Math.min(max, numeric)) : fallback;
}

function safeInteger(value: string | null | undefined, fallback: number) {
  const numeric = Number(value);
  return Number.isSafeInteger(numeric) ? numeric : fallback;
}

function firstChildElement(element: Element, name: string) {
  return Array.from(element.childNodes).find((child): child is Element => (
    child.nodeType === 1 && (child as Element).tagName === name
  ));
}

function defaultXmlParser(): XmlParser {
  if (typeof DOMParser === "undefined") {
    throw new Error("当前环境不支持 XML 解析");
  }
  return new DOMParser();
}

function escapeXml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}
