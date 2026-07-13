export const DIAGRAM_DOCUMENT_FORMAT = "shuai-tunnel-diagram";
export const DIAGRAM_DOCUMENT_VERSION = 1;
export const DIAGRAM_FILE_EXTENSION = ".stdg";
export const DIAGRAM_FILE_MIME = "application/vnd.shuai-tunnel.diagram+json";
export const MAX_DIAGRAM_DOCUMENT_BYTES = 2 * 1024 * 1024;
export const MAX_DIAGRAM_UPDATE_BASE64_LENGTH = 4 * 1024 * 1024;
export const MAX_DIAGRAM_NODES = 1_000;
export const MAX_DIAGRAM_EDGES = 2_000;
export const MAX_DIAGRAM_PAGES = 50;
export const MAX_DIAGRAM_COMMENTS = 2_000;

export const DIAGRAM_NODE_KINDS = [
  "rectangle",
  "roundedRectangle",
  "ellipse",
  "circle",
  "diamond",
  "triangle",
  "hexagon",
  "text",
  "start",
  "process",
  "decision",
  "end",
  "document",
  "database",
  "note",
  "subprocess",
  "data",
  "delay",
  "manualInput",
  "connector",
  "bpmnTask",
  "bpmnEvent",
  "bpmnGateway",
  "bpmnDataObject",
  "actor",
  "umlUseCase",
  "umlClass",
  "umlInterface",
  "umlPackage",
  "umlComponent",
  "entity",
  "erRelationship",
  "erAttribute",
  "server",
  "client",
  "router",
  "firewall",
  "cloud",
  "queue",
  "service",
  "container",
  "swimlane",
  "lane",
] as const;

export type DiagramNodeKind = typeof DIAGRAM_NODE_KINDS[number];

export type DiagramPort = "north" | "east" | "south" | "west";
export type DiagramEdgeType = "orthogonal" | "straight" | "elbow" | "curved";
export type DiagramArrowType = "none" | "classic" | "block" | "open" | "oval" | "diamond";
export type DiagramTextAlign = "left" | "center" | "right";
export type DiagramSwimlaneDirection = "horizontal" | "vertical";

export interface DiagramPoint {
  x: number;
  y: number;
}

export interface DiagramNodeStyle {
  fillColor: string;
  strokeColor: string;
  fontColor: string;
  strokeWidth: number;
  dashed?: boolean;
  fontSize?: number;
  bold?: boolean;
  italic?: boolean;
  align?: DiagramTextAlign;
  opacity?: number;
  shadow?: boolean;
  rounded?: boolean;
}

export interface DiagramEdgeStyle {
  strokeColor: string;
  fontColor: string;
  strokeWidth: number;
  dashed?: boolean;
  edgeType?: DiagramEdgeType;
  startArrow?: DiagramArrowType;
  endArrow?: DiagramArrowType;
  opacity?: number;
}

export interface DiagramNode {
  id: string;
  kind: DiagramNodeKind;
  stencilName?: string;
  stencilLibrary?: string;
  label: string;
  x: number;
  y: number;
  width: number;
  height: number;
  zIndex: number;
  pageId?: string;
  parentId?: string;
  locked?: boolean;
  rotation?: number;
  swimlaneDirection?: DiagramSwimlaneDirection;
  style: DiagramNodeStyle;
}

export interface DiagramEdge {
  id: string;
  label: string;
  sourceId: string;
  targetId: string;
  sourcePort?: DiagramPort;
  targetPort?: DiagramPort;
  waypoints?: DiagramPoint[];
  zIndex: number;
  pageId?: string;
  style: DiagramEdgeStyle;
}

export interface DiagramPage {
  id: string;
  name: string;
  order: number;
}

export interface DiagramComment {
  id: string;
  pageId: string;
  cellId?: string;
  author: string;
  text: string;
  createdAt: number;
  resolved: boolean;
}

export interface DiagramDocumentV1 {
  format: typeof DIAGRAM_DOCUMENT_FORMAT;
  version: typeof DIAGRAM_DOCUMENT_VERSION;
  exportedAt: string;
  canvas: {
    width: number;
    height: number;
    gridSize: number;
  };
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  pages?: DiagramPage[];
  activePageId?: string;
  comments?: DiagramComment[];
}

export type DiagramPayload =
  | {
      type: "STDG1";
      kind: "diagram-update";
      update: string;
      createdAt: number;
    }
  | {
      type: "STDG1";
      kind: "diagram-sync-request";
      requestId: string;
      createdAt: number;
    }
  | {
      type: "STDG1";
      kind: "diagram-presence";
      pageId: string;
      selectedIds: string[];
      cursor?: DiagramPoint;
      createdAt: number;
    };

export function createDiagramDocument(
  nodes: DiagramNode[],
  edges: DiagramEdge[],
  canvas: { width: number; height: number; gridSize: number },
  exportedAt = new Date(),
  pages?: DiagramPage[],
  activePageId?: string,
  comments?: DiagramComment[],
): DiagramDocumentV1 {
  return {
    format: DIAGRAM_DOCUMENT_FORMAT,
    version: DIAGRAM_DOCUMENT_VERSION,
    exportedAt: exportedAt.toISOString(),
    canvas: {
      width: Math.max(1, Math.round(canvas.width)),
      height: Math.max(1, Math.round(canvas.height)),
      gridSize: Math.max(4, Math.min(64, Math.round(canvas.gridSize))),
    },
    nodes: nodes.slice(0, MAX_DIAGRAM_NODES).map(cloneDiagramNode),
    edges: edges.slice(0, MAX_DIAGRAM_EDGES).map(cloneDiagramEdge),
    ...(pages?.length ? { pages: pages.slice(0, MAX_DIAGRAM_PAGES).map((page) => ({ ...page })) } : {}),
    ...(activePageId ? { activePageId } : {}),
    ...(comments?.length ? { comments: comments.slice(0, MAX_DIAGRAM_COMMENTS).map((comment) => ({ ...comment })) } : {}),
  };
}

export function parseDiagramDocument(source: string): DiagramDocumentV1 {
  if (new TextEncoder().encode(source).length > MAX_DIAGRAM_DOCUMENT_BYTES) {
    throw new Error("流程图文件超过 2 MB，无法导入");
  }
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error("流程图文件不是有效的 JSON");
  }
  if (!isRecord(value)
    || value.format !== DIAGRAM_DOCUMENT_FORMAT
    || value.version !== DIAGRAM_DOCUMENT_VERSION) {
    throw new Error("不支持的流程图文件格式或版本");
  }
  if (!isDiagramDocument(value)) {
    throw new Error("流程图文件包含无效、重复或超出限制的内容");
  }
  return value;
}

export function isDiagramPayload(value: unknown): value is DiagramPayload {
  if (!isRecord(value) || value.type !== "STDG1" || !isFiniteNumber(value.createdAt)) {
    return false;
  }
  if (value.kind === "diagram-update") {
    return typeof value.update === "string"
      && value.update.length > 0
      && value.update.length <= MAX_DIAGRAM_UPDATE_BASE64_LENGTH
      && isBase64(value.update);
  }
  if (value.kind === "diagram-sync-request") {
    return isIdentifier(value.requestId);
  }
  if (value.kind === "diagram-presence") {
    return isIdentifier(value.pageId)
      && Array.isArray(value.selectedIds)
      && value.selectedIds.length <= 100
      && value.selectedIds.every(isIdentifier)
      && (value.cursor === undefined || isDiagramPoint(value.cursor));
  }
  return false;
}

export function encodeDiagramUpdate(update: Uint8Array): string {
  let result = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < update.length; offset += chunkSize) {
    const chunk = update.subarray(offset, Math.min(update.length, offset + chunkSize));
    result += String.fromCharCode(...chunk);
  }
  return btoa(result);
}

export function decodeDiagramUpdate(encoded: string): Uint8Array {
  if (encoded.length === 0
    || encoded.length > MAX_DIAGRAM_UPDATE_BASE64_LENGTH
    || !isBase64(encoded)) {
    throw new Error("流程图同步数据格式无效");
  }
  let binary: string;
  try {
    binary = atob(encoded);
  } catch {
    throw new Error("流程图同步数据格式无效");
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function isDiagramDocument(value: unknown): value is DiagramDocumentV1 {
  if (!isRecord(value)
    || typeof value.exportedAt !== "string"
    || !Number.isFinite(Date.parse(value.exportedAt))
    || !isRecord(value.canvas)
    || !isPositiveNumber(value.canvas.width)
    || !isPositiveNumber(value.canvas.height)
    || !isFiniteNumber(value.canvas.gridSize)
    || value.canvas.gridSize < 4
    || value.canvas.gridSize > 64
    || !Array.isArray(value.nodes)
    || !Array.isArray(value.edges)
    || !isDiagramGraphState(value.nodes, value.edges)) {
    return false;
  }

  if (value.comments !== undefined
    && (!Array.isArray(value.comments)
      || value.comments.length > MAX_DIAGRAM_COMMENTS
      || !value.comments.every(isDiagramComment)
      || new Set(value.comments.map((comment) => comment.id)).size !== value.comments.length)) {
    return false;
  }

  if (value.pages !== undefined) {
    if (!Array.isArray(value.pages)
      || value.pages.length === 0
      || value.pages.length > MAX_DIAGRAM_PAGES
      || !value.pages.every(isDiagramPage)) {
      return false;
    }
    const pageIds = new Set(value.pages.map((page) => page.id));
    if (pageIds.size !== value.pages.length
      || (value.activePageId !== undefined && (!isIdentifier(value.activePageId) || !pageIds.has(value.activePageId)))
      || value.nodes.some((node) => node.pageId !== undefined && !pageIds.has(node.pageId))
      || value.edges.some((edge) => edge.pageId !== undefined && !pageIds.has(edge.pageId))
      || (value.comments !== undefined && value.comments.some((comment) => !pageIds.has(comment.pageId)))) {
      return false;
    }
  } else if (value.activePageId !== undefined) {
    return false;
  }

  return true;
}

export function isDiagramGraphState(nodes: unknown[], edges: unknown[]): boolean {
  if (nodes.length > MAX_DIAGRAM_NODES
    || edges.length > MAX_DIAGRAM_EDGES
    || !nodes.every(isDiagramNode)
    || !edges.every(isDiagramEdge)) {
    return false;
  }
  const typedNodes = nodes as DiagramNode[];
  const typedEdges = edges as DiagramEdge[];
  const nodeIds = new Set(typedNodes.map((node) => node.id));
  const nodesById = new Map(typedNodes.map((node) => [node.id, node]));
  const edgeIds = new Set(typedEdges.map((edge) => edge.id));
  if (nodeIds.size !== typedNodes.length || edgeIds.size !== typedEdges.length) {
    return false;
  }
  for (const edge of typedEdges) {
    if (!nodeIds.has(edge.sourceId) || !nodeIds.has(edge.targetId)) {
      return false;
    }
  }
  for (const node of typedNodes) {
    if (!node.parentId) {
      continue;
    }
    const parent = nodesById.get(node.parentId);
    if (!parent
      || parent.id === node.id
      || (parent.kind !== "container" && parent.kind !== "swimlane" && parent.kind !== "lane")
      || (node.kind === "lane" && parent.kind !== "swimlane")) {
      return false;
    }
    const visited = new Set([node.id]);
    let ancestor: DiagramNode | undefined = parent;
    while (ancestor) {
      if (visited.has(ancestor.id)) {
        return false;
      }
      visited.add(ancestor.id);
      ancestor = ancestor.parentId ? nodesById.get(ancestor.parentId) : undefined;
    }
  }
  return true;
}

export function isDiagramNode(value: unknown): value is DiagramNode {
  return isRecord(value)
    && isIdentifier(value.id)
    && isDiagramNodeKind(value.kind)
    && (value.stencilName === undefined || isStencilName(value.stencilName))
    && (value.stencilLibrary === undefined || isStencilLibrary(value.stencilLibrary))
    && ((value.stencilName === undefined) === (value.stencilLibrary === undefined))
    && isLabel(value.label)
    && isFiniteNumber(value.x)
    && isFiniteNumber(value.y)
    && value.x >= -100_000
    && value.y >= -100_000
    && isPositiveNumber(value.width)
    && isPositiveNumber(value.height)
    && value.width <= 100_000
    && value.height <= 100_000
    && Number.isSafeInteger(value.zIndex)
    && (value.pageId === undefined || isIdentifier(value.pageId))
    && (value.parentId === undefined || isIdentifier(value.parentId))
    && (value.locked === undefined || typeof value.locked === "boolean")
    && (value.rotation === undefined || (isFiniteNumber(value.rotation) && value.rotation >= -360 && value.rotation <= 360))
    && (value.swimlaneDirection === undefined || value.swimlaneDirection === "horizontal" || value.swimlaneDirection === "vertical")
    && isNodeStyle(value.style);
}

export function isDiagramEdge(value: unknown): value is DiagramEdge {
  return isRecord(value)
    && isIdentifier(value.id)
    && isLabel(value.label)
    && isIdentifier(value.sourceId)
    && isIdentifier(value.targetId)
    && (value.sourcePort === undefined || isDiagramPort(value.sourcePort))
    && (value.targetPort === undefined || isDiagramPort(value.targetPort))
    && (value.waypoints === undefined || (Array.isArray(value.waypoints)
      && value.waypoints.length <= 128
      && value.waypoints.every(isDiagramPoint)))
    && Number.isSafeInteger(value.zIndex)
    && (value.pageId === undefined || isIdentifier(value.pageId))
    && isEdgeStyle(value.style);
}

function isNodeStyle(value: unknown): value is DiagramNodeStyle {
  return isRecord(value)
    && isColor(value.fillColor)
    && isColor(value.strokeColor)
    && isColor(value.fontColor)
    && isStrokeWidth(value.strokeWidth)
    && (value.dashed === undefined || typeof value.dashed === "boolean")
    && (value.fontSize === undefined || (isFiniteNumber(value.fontSize) && value.fontSize >= 8 && value.fontSize <= 96))
    && (value.bold === undefined || typeof value.bold === "boolean")
    && (value.italic === undefined || typeof value.italic === "boolean")
    && (value.align === undefined || value.align === "left" || value.align === "center" || value.align === "right")
    && (value.opacity === undefined || (isFiniteNumber(value.opacity) && value.opacity >= 10 && value.opacity <= 100))
    && (value.shadow === undefined || typeof value.shadow === "boolean")
    && (value.rounded === undefined || typeof value.rounded === "boolean")
    && value.edgeType === undefined;
}

function isEdgeStyle(value: unknown): value is DiagramEdgeStyle {
  return isRecord(value)
    && isColor(value.strokeColor)
    && isColor(value.fontColor)
    && isStrokeWidth(value.strokeWidth)
    && (value.dashed === undefined || typeof value.dashed === "boolean")
    && (value.edgeType === undefined || isDiagramEdgeType(value.edgeType))
    && (value.startArrow === undefined || isDiagramArrowType(value.startArrow))
    && (value.endArrow === undefined || isDiagramArrowType(value.endArrow))
    && (value.opacity === undefined || (isFiniteNumber(value.opacity) && value.opacity >= 10 && value.opacity <= 100));
}

function cloneDiagramNode(node: DiagramNode): DiagramNode {
  return { ...node, style: { ...node.style } };
}

function cloneDiagramEdge(edge: DiagramEdge): DiagramEdge {
  return {
    ...edge,
    ...(edge.waypoints ? { waypoints: edge.waypoints.map((point) => ({ ...point })) } : {}),
    style: { ...edge.style },
  };
}

function isDiagramNodeKind(value: unknown): value is DiagramNodeKind {
  return typeof value === "string" && (DIAGRAM_NODE_KINDS as readonly string[]).includes(value);
}

function isStencilName(value: unknown): value is string {
  return typeof value === "string"
    && value.length <= 256
    && /^mxgraph\.[a-z0-9_()., -]+$/i.test(value);
}

function isStencilLibrary(value: unknown): value is string {
  return typeof value === "string"
    && value.length <= 256
    && !value.includes("..")
    && /^[a-z0-9_./-]+\.xml$/i.test(value);
}

function isDiagramEdgeType(value: unknown): value is DiagramEdgeType {
  return value === "orthogonal" || value === "straight" || value === "elbow" || value === "curved";
}

function isDiagramArrowType(value: unknown): value is DiagramArrowType {
  return value === "none"
    || value === "classic"
    || value === "block"
    || value === "open"
    || value === "oval"
    || value === "diamond";
}

function isDiagramPoint(value: unknown): value is DiagramPoint {
  return isRecord(value)
    && isFiniteNumber(value.x)
    && isFiniteNumber(value.y)
    && Math.abs(value.x) <= 100_000
    && Math.abs(value.y) <= 100_000;
}

export function isDiagramPage(value: unknown): value is DiagramPage {
  return isRecord(value)
    && isIdentifier(value.id)
    && typeof value.name === "string"
    && value.name.trim().length > 0
    && value.name.length <= 80
    && typeof value.order === "number"
    && Number.isSafeInteger(value.order)
    && value.order >= 0
    && value.order < MAX_DIAGRAM_PAGES;
}

export function isDiagramComment(value: unknown): value is DiagramComment {
  if (!isRecord(value)) return false;
  return isIdentifier(value.id)
    && isIdentifier(value.pageId)
    && (value.cellId === undefined || isIdentifier(value.cellId))
    && typeof value.author === "string" && value.author.length > 0 && value.author.length <= 200
    && typeof value.text === "string" && value.text.length > 0 && value.text.length <= 500
    && isFiniteNumber(value.createdAt)
    && typeof value.resolved === "boolean";
}

function isDiagramPort(value: unknown): value is DiagramPort {
  return value === "north" || value === "east" || value === "south" || value === "west";
}

function isLabel(value: unknown): value is string {
  return typeof value === "string" && value.length <= 500;
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 160;
}

function isColor(value: unknown): value is string {
  return typeof value === "string" && /^#[0-9a-fA-F]{6}$/.test(value);
}

function isStrokeWidth(value: unknown): value is number {
  return isFiniteNumber(value) && value >= 1 && value <= 12;
}

function isPositiveNumber(value: unknown): value is number {
  return isFiniteNumber(value) && value > 0;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isBase64(value: string): boolean {
  return value.length % 4 === 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}
