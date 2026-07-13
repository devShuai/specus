import { strFromU8, unzipSync } from "fflate";
import {
  createDiagramDocument,
  isDiagramGraphState,
  MAX_DIAGRAM_EDGES,
  MAX_DIAGRAM_NODES,
  MAX_DIAGRAM_PAGES,
} from "./diagramDocument";
import type { DiagramDocumentV1, DiagramEdge, DiagramNode, DiagramNodeKind, DiagramPage } from "./diagramDocument";

export const VISIO_VSDX_FILE_EXTENSION = ".vsdx";
export const VISIO_VDX_FILE_EXTENSION = ".vdx";
export const VISIO_VDX_MIME = "application/vnd.visio";
const MAX_VISIO_BYTES = 16 * 1024 * 1024;
const PIXELS_PER_INCH = 96;

interface XmlParser {
  parseFromString(source: string, mimeType: string): Document;
}

interface VisioPageSource {
  id: string;
  name: string;
  xml: string;
}

export function parseVisioVsdx(bytes: Uint8Array, parser?: XmlParser): DiagramDocumentV1 {
  if (bytes.byteLength > MAX_VISIO_BYTES) throw new Error("Visio VSDX 文件超过 16 MB，无法导入");
  let archive: Record<string, Uint8Array>;
  try {
    archive = unzipSync(bytes, { filter: (file) => file.name.startsWith("visio/pages/") });
  } catch {
    throw new Error("Visio VSDX 文件损坏或不是有效的 ZIP 文档");
  }
  const xmlParser = parser ?? defaultXmlParser();
  const pageEntries = Object.keys(archive).filter((name) => /^visio\/pages\/page\d+\.xml$/i.test(name)).sort(naturalSort);
  if (pageEntries.length === 0) throw new Error("Visio VSDX 文件不包含可识别的页面");
  const names = pageNames(archive, xmlParser);
  const sources = pageEntries.slice(0, MAX_DIAGRAM_PAGES).map((entry, index) => ({
    id: `page-${index + 1}`,
    name: names[index] ?? `页面 ${index + 1}`,
    xml: strFromU8(archive[entry]),
  }));
  return parseVisioPages(sources, xmlParser);
}

export function parseVisioVdx(source: string, parser?: XmlParser): DiagramDocumentV1 {
  if (new TextEncoder().encode(source).length > MAX_VISIO_BYTES) throw new Error("Visio VDX 文件超过 16 MB，无法导入");
  const xmlParser = parser ?? defaultXmlParser();
  const document = parseXml(source, xmlParser);
  const pages = elementsByLocalName(document, "Page").filter((page) => elementsByLocalName(page, "Shapes").length > 0);
  if (pages.length === 0) throw new Error("Visio VDX 文件不包含可识别的页面");
  return parseVisioPages(pages.slice(0, MAX_DIAGRAM_PAGES).map((page, index) => ({
    id: `page-${index + 1}`,
    name: page.getAttribute("Name") || page.getAttribute("NameU") || `页面 ${index + 1}`,
    xml: new XMLSerializer().serializeToString(page),
  })), xmlParser);
}

export function exportVisioVdx(document: DiagramDocumentV1) {
  const pages = document.pages?.length
    ? document.pages.slice().sort((left, right) => left.order - right.order)
    : [{ id: document.activePageId ?? "page-1", name: "页面 1", order: 0 }];
  const fallbackPageId = document.activePageId ?? pages[0].id;
  const pageXml = pages.map((page, pageIndex) => {
    const nodes = document.nodes.filter((node) => (node.pageId ?? fallbackPageId) === page.id);
    const edges = document.edges.filter((edge) => (edge.pageId ?? fallbackPageId) === page.id);
    const numericIds = new Map(nodes.map((node, index) => [node.id, index + 1]));
    const shapeXml = nodes.map((node) => {
      const width = node.width / PIXELS_PER_INCH;
      const height = node.height / PIXELS_PER_INCH;
      const pinX = (node.x + node.width / 2) / PIXELS_PER_INCH;
      const pinY = (document.canvas.height - node.y - node.height / 2) / PIXELS_PER_INCH;
      return `<Shape ID="${numericIds.get(node.id)}" NameU="${escapeXml(node.kind)}" Type="Shape"><XForm><PinX>${pinX}</PinX><PinY>${pinY}</PinY><Width>${width}</Width><Height>${height}</Height><LocPinX>${width / 2}</LocPinX><LocPinY>${height / 2}</LocPinY></XForm><Text>${escapeXml(node.label)}</Text></Shape>`;
    }).join("");
    const connectorXml: string[] = [];
    const connectXml: string[] = [];
    edges.forEach((edge, edgeIndex) => {
      const source = numericIds.get(edge.sourceId);
      const target = numericIds.get(edge.targetId);
      if (!source || !target) return;
      const connectorId = nodes.length + edgeIndex + 1;
      connectorXml.push(`<Shape ID="${connectorId}" NameU="Dynamic connector" Type="Shape" OneD="1"><Text>${escapeXml(edge.label)}</Text></Shape>`);
      connectXml.push(`<Connect FromSheet="${connectorId}" FromCell="BeginX" ToSheet="${source}" ToCell="PinX"/><Connect FromSheet="${connectorId}" FromCell="EndX" ToSheet="${target}" ToCell="PinX"/>`);
    });
    return `<Page ID="${pageIndex + 1}" Name="${escapeXml(page.name)}"><PageSheet><PageProps><PageWidth>${document.canvas.width / PIXELS_PER_INCH}</PageWidth><PageHeight>${document.canvas.height / PIXELS_PER_INCH}</PageHeight></PageProps></PageSheet><Shapes>${shapeXml}${connectorXml.join("")}</Shapes><Connects>${connectXml.join("")}</Connects></Page>`;
  }).join("");
  return `<?xml version="1.0" encoding="UTF-8"?><VisioDocument xmlns="urn:schemas-microsoft-com:office:visio"><Pages>${pageXml}</Pages></VisioDocument>`;
}

function parseVisioPages(sources: VisioPageSource[], parser: XmlParser) {
  const pages: DiagramPage[] = [];
  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  sources.forEach((source, pageIndex) => {
    const xml = parseXml(source.xml, parser);
    const pageHeight = visioPageHeight(xml) || 11.69;
    const page: DiagramPage = { id: source.id, name: source.name.slice(0, 80), order: pageIndex };
    pages.push(page);
    const shapeElements = elementsByLocalName(xml, "Shape");
    const idMap = new Map<string, string>();
    const connectorIds = new Set<string>();
    for (const shape of shapeElements) {
      const visioId = shape.getAttribute("ID");
      if (!visioId) continue;
      if (shape.getAttribute("OneD") === "1") {
        connectorIds.add(visioId);
        continue;
      }
      if (nodes.length >= MAX_DIAGRAM_NODES) break;
      const width = positiveShapeValue(shape, "Width", 1.8) * PIXELS_PER_INCH;
      const height = positiveShapeValue(shape, "Height", 0.75) * PIXELS_PER_INCH;
      const pinX = shapeValue(shape, "PinX", 1 + (idMap.size % 5) * 2.2);
      const pinY = shapeValue(shape, "PinY", pageHeight - 1 - Math.floor(idMap.size / 5) * 1.4);
      const id = `p${pageIndex + 1}-n${idMap.size + 1}`;
      idMap.set(visioId, id);
      const kind = visioNodeKind(shape);
      nodes.push({
        id,
        kind,
        label: visioShapeText(shape) || shape.getAttribute("Name") || shape.getAttribute("NameU") || `Shape ${visioId}`,
        x: Math.max(0, pinX * PIXELS_PER_INCH - width / 2),
        y: Math.max(0, (pageHeight - pinY) * PIXELS_PER_INCH - height / 2),
        width: Math.max(24, width),
        height: Math.max(24, height),
        zIndex: idMap.size - 1,
        pageId: page.id,
        style: visioNodeStyle(kind),
      });
    }
    const connections = new Map<string, { source?: string; target?: string }>();
    for (const connect of elementsByLocalName(xml, "Connect")) {
      const connectorId = connect.getAttribute("FromSheet");
      const targetId = connect.getAttribute("ToSheet");
      const fromCell = connect.getAttribute("FromCell") ?? "";
      if (!connectorId || !targetId || !connectorIds.has(connectorId)) continue;
      const connection = connections.get(connectorId) ?? {};
      if (/begin/i.test(fromCell)) connection.source = targetId;
      if (/end/i.test(fromCell)) connection.target = targetId;
      connections.set(connectorId, connection);
    }
    for (const [connectorId, connection] of connections) {
      if (edges.length >= MAX_DIAGRAM_EDGES) break;
      const sourceId = connection.source ? idMap.get(connection.source) : undefined;
      const targetId = connection.target ? idMap.get(connection.target) : undefined;
      if (!sourceId || !targetId) continue;
      const connector = shapeElements.find((shape) => shape.getAttribute("ID") === connectorId);
      edges.push({
        id: `p${pageIndex + 1}-e${edges.filter((edge) => edge.pageId === page.id).length + 1}`,
        label: connector ? visioShapeText(connector) : "",
        sourceId,
        targetId,
        zIndex: edges.length,
        pageId: page.id,
        style: { strokeColor: "#64748b", fontColor: "#334155", strokeWidth: 2, edgeType: "orthogonal", startArrow: "none", endArrow: "block" },
      });
    }
  });
  if (!isDiagramGraphState(nodes, edges) || nodes.length === 0) throw new Error("Visio 文档不包含有效的二维图形");
  const width = Math.max(2400, ...nodes.map((node) => node.x + node.width + 100));
  const height = Math.max(1600, ...nodes.map((node) => node.y + node.height + 100));
  return createDiagramDocument(nodes, edges, { width, height, gridSize: 10 }, new Date(), pages, pages[0].id);
}

function pageNames(archive: Record<string, Uint8Array>, parser: XmlParser) {
  const source = archive["visio/pages/pages.xml"];
  if (!source) return [];
  try {
    const document = parseXml(strFromU8(source), parser);
    return elementsByLocalName(document, "Page").map((page, index) => page.getAttribute("Name") || page.getAttribute("NameU") || `页面 ${index + 1}`);
  } catch {
    return [];
  }
}

function visioPageHeight(document: Document) {
  const cell = elementsByLocalName(document, "Cell").find((candidate) => candidate.getAttribute("N") === "PageHeight");
  if (cell) return finiteNumber(cell.getAttribute("V"), 11.69);
  const legacy = elementsByLocalName(document, "PageHeight")[0];
  return finiteNumber(legacy?.textContent, 11.69);
}

function shapeValue(shape: Element, name: string, fallback: number) {
  const cell = elementsByLocalName(shape, "Cell").find((candidate) => candidate.getAttribute("N") === name);
  if (cell) return finiteNumber(cell.getAttribute("V"), fallback);
  const legacy = elementsByLocalName(shape, name)[0];
  return finiteNumber(legacy?.textContent, fallback);
}

function positiveShapeValue(shape: Element, name: string, fallback: number) {
  const value = shapeValue(shape, name, fallback);
  return value > 0 ? value : fallback;
}

function visioShapeText(shape: Element) {
  const text = elementsByLocalName(shape, "Text")[0]?.textContent ?? "";
  return text.replace(/\s+/g, " ").trim().slice(0, 500);
}

function visioNodeKind(shape: Element): DiagramNodeKind {
  const description = `${shape.getAttribute("Name") ?? ""} ${shape.getAttribute("NameU") ?? ""} ${visioShapeText(shape)}`.toLowerCase();
  if (/decision|diamond|gateway/.test(description)) return "decision";
  if (/database|data store|cylinder/.test(description)) return "database";
  if (/actor|person|user/.test(description)) return "actor";
  if (/cloud/.test(description)) return "cloud";
  if (/server|node/.test(description)) return "server";
  if (/queue/.test(description)) return "queue";
  if (/start|terminator/.test(description)) return "start";
  if (/end|stop/.test(description)) return "end";
  if (/document/.test(description)) return "document";
  return "process";
}

function visioNodeStyle(kind: DiagramNodeKind) {
  const special = kind === "decision" ? ["#fef3c7", "#d97706"] : kind === "database" ? ["#dcfce7", "#16a34a"] : ["#dbeafe", "#2563eb"];
  return { fillColor: special[0], strokeColor: special[1], fontColor: "#172033", strokeWidth: 2 };
}

function parseXml(source: string, parser: XmlParser) {
  const document = parser.parseFromString(source, "application/xml");
  if (elementsByLocalName(document, "parsererror").length > 0) throw new Error("Visio XML 内容损坏");
  return document;
}

function defaultXmlParser(): XmlParser {
  if (typeof DOMParser === "undefined") throw new Error("当前环境不支持 XML 解析");
  return new DOMParser();
}

function elementsByLocalName(root: Document | Element, name: string) {
  return Array.from(root.getElementsByTagName("*")).filter((element) => (element.localName || element.tagName.split(":").pop()) === name);
}

function naturalSort(left: string, right: string) {
  return left.localeCompare(right, undefined, { numeric: true });
}

function finiteNumber(value: string | null | undefined, fallback: number) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function escapeXml(value: string) {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}
