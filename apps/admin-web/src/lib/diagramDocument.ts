export const DIAGRAM_DOCUMENT_FORMAT = "shuai-tunnel-diagram";
export const DIAGRAM_DOCUMENT_VERSION = 1;
export const DIAGRAM_FILE_EXTENSION = ".stdg";
export const DIAGRAM_FILE_MIME = "application/vnd.shuai-tunnel.diagram+json";
export const MAX_DIAGRAM_DOCUMENT_BYTES = 2 * 1024 * 1024;
export const MAX_DIAGRAM_UPDATE_BASE64_LENGTH = 4 * 1024 * 1024;
export const MAX_DIAGRAM_NODES = 1_000;
export const MAX_DIAGRAM_EDGES = 2_000;

export type DiagramNodeKind =
  | "start"
  | "process"
  | "decision"
  | "end"
  | "document"
  | "database"
  | "actor"
  | "note";

export type DiagramPort = "north" | "east" | "south" | "west";

export interface DiagramNodeStyle {
  fillColor: string;
  strokeColor: string;
  fontColor: string;
  strokeWidth: number;
  dashed?: boolean;
}

export interface DiagramEdgeStyle {
  strokeColor: string;
  fontColor: string;
  strokeWidth: number;
  dashed?: boolean;
}

export interface DiagramNode {
  id: string;
  kind: DiagramNodeKind;
  label: string;
  x: number;
  y: number;
  width: number;
  height: number;
  zIndex: number;
  style: DiagramNodeStyle;
}

export interface DiagramEdge {
  id: string;
  label: string;
  sourceId: string;
  targetId: string;
  sourcePort?: DiagramPort;
  targetPort?: DiagramPort;
  zIndex: number;
  style: DiagramEdgeStyle;
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
    };

export function createDiagramDocument(
  nodes: DiagramNode[],
  edges: DiagramEdge[],
  canvas: { width: number; height: number; gridSize: number },
  exportedAt = new Date(),
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
  const edgeIds = new Set(typedEdges.map((edge) => edge.id));
  if (nodeIds.size !== typedNodes.length || edgeIds.size !== typedEdges.length) {
    return false;
  }
  for (const edge of typedEdges) {
    if (!nodeIds.has(edge.sourceId) || !nodeIds.has(edge.targetId)) {
      return false;
    }
  }
  return true;
}

export function isDiagramNode(value: unknown): value is DiagramNode {
  return isRecord(value)
    && isIdentifier(value.id)
    && isDiagramNodeKind(value.kind)
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
    && Number.isSafeInteger(value.zIndex)
    && isEdgeStyle(value.style);
}

function isNodeStyle(value: unknown): value is DiagramNodeStyle {
  return isRecord(value)
    && isColor(value.fillColor)
    && isColor(value.strokeColor)
    && isColor(value.fontColor)
    && isStrokeWidth(value.strokeWidth)
    && (value.dashed === undefined || typeof value.dashed === "boolean");
}

function isEdgeStyle(value: unknown): value is DiagramEdgeStyle {
  return isRecord(value)
    && isColor(value.strokeColor)
    && isColor(value.fontColor)
    && isStrokeWidth(value.strokeWidth)
    && (value.dashed === undefined || typeof value.dashed === "boolean");
}

function cloneDiagramNode(node: DiagramNode): DiagramNode {
  return { ...node, style: { ...node.style } };
}

function cloneDiagramEdge(edge: DiagramEdge): DiagramEdge {
  return { ...edge, style: { ...edge.style } };
}

function isDiagramNodeKind(value: unknown): value is DiagramNodeKind {
  return value === "start"
    || value === "process"
    || value === "decision"
    || value === "end"
    || value === "document"
    || value === "database"
    || value === "actor"
    || value === "note";
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
