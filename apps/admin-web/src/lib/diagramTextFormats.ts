import {
  createDiagramDocument,
  MAX_DIAGRAM_EDGES,
  MAX_DIAGRAM_NODES,
  MAX_DIAGRAM_PAGES,
} from "./diagramDocument";
import type {
  DiagramDocumentV1,
  DiagramEdge,
  DiagramNode,
  DiagramNodeKind,
  DiagramPage,
} from "./diagramDocument";

export const MERMAID_FILE_EXTENSIONS = [".mmd", ".mermaid", ".md"] as const;
export const PLANTUML_FILE_EXTENSIONS = [".puml", ".plantuml", ".pu"] as const;
const CANVAS = { width: 2400, height: 1600, gridSize: 10 };

interface ParsedGraph {
  name: string;
  orientation: "vertical" | "horizontal";
  nodes: Map<string, { label: string; kind: DiagramNodeKind }>;
  edges: Array<{ source: string; target: string; label: string; dashed?: boolean }>;
}

export function exportMermaidDocument(document: DiagramDocumentV1) {
  const pages = documentPages(document);
  const fallbackPageId = document.activePageId ?? pages[0].id;
  return pages.map((page) => {
    const nodes = document.nodes.filter((node) => (node.pageId ?? fallbackPageId) === page.id);
    const edges = document.edges.filter((edge) => (edge.pageId ?? fallbackPageId) === page.id);
    const ids = new Map(nodes.map((node, index) => [node.id, `n${index + 1}`]));
    const lines = ["flowchart TD"];
    nodes.forEach((node) => lines.push(`  ${ids.get(node.id)}${mermaidNodeShape(node)}`));
    edges.forEach((edge) => {
      const source = ids.get(edge.sourceId);
      const target = ids.get(edge.targetId);
      if (!source || !target) return;
      const arrow = edge.style.dashed ? "-.->" : "-->";
      const label = edge.label ? `|"${escapeText(edge.label)}"|` : "";
      lines.push(`  ${source} ${arrow}${label} ${target}`);
    });
    return [`## ${page.name}`, "", "```mermaid", ...lines, "```"].join("\n");
  }).join("\n\n");
}

export function parseMermaidDocument(source: string): DiagramDocumentV1 {
  const blocks = mermaidBlocks(source);
  if (blocks.length === 0 || blocks.length > MAX_DIAGRAM_PAGES) {
    throw new Error("Mermaid 文档不包含可识别的流程图，或图页数量超出限制");
  }
  return graphsToDocument(blocks.map(({ name, body }) => parseMermaidGraph(name, body)));
}

export function exportPlantUmlDocument(document: DiagramDocumentV1) {
  const pages = documentPages(document);
  const fallbackPageId = document.activePageId ?? pages[0].id;
  return pages.map((page) => {
    const nodes = document.nodes.filter((node) => (node.pageId ?? fallbackPageId) === page.id);
    const edges = document.edges.filter((edge) => (edge.pageId ?? fallbackPageId) === page.id);
    const ids = new Map(nodes.map((node, index) => [node.id, `n${index + 1}`]));
    const lines = ["@startuml", `title ${escapePlantUml(page.name)}`, "left to right direction"];
    nodes.forEach((node) => {
      const keyword = plantUmlKeyword(node.kind);
      lines.push(`${keyword} "${escapePlantUml(node.label || node.kind)}" as ${ids.get(node.id)}`);
    });
    edges.forEach((edge) => {
      const source = ids.get(edge.sourceId);
      const target = ids.get(edge.targetId);
      if (source && target) lines.push(`${source} ${edge.style.dashed ? "..>" : "-->"} ${target}${edge.label ? ` : ${escapePlantUml(edge.label)}` : ""}`);
    });
    lines.push("@enduml");
    return lines.join("\n");
  }).join("\n\n");
}

export function parsePlantUmlDocument(source: string): DiagramDocumentV1 {
  const matches = Array.from(source.matchAll(/@startuml(?:\s+[^\n]*)?\s*([\s\S]*?)@enduml/gi));
  const bodies = matches.length > 0 ? matches.map((match) => match[1]) : [source];
  if (bodies.length > MAX_DIAGRAM_PAGES) throw new Error("PlantUML 文档图页数量超出限制");
  const graphs = bodies.map((body, index) => parsePlantUmlGraph(body, index));
  if (graphs.every((graph) => graph.nodes.size === 0)) throw new Error("PlantUML 文档不包含可识别的节点");
  return graphsToDocument(graphs);
}

function parseMermaidGraph(name: string, source: string): ParsedGraph {
  const graph: ParsedGraph = { name, orientation: "vertical", nodes: new Map(), edges: [] };
  const lines = source.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("%%"));
  const header = lines.find((line) => /^(?:flowchart|graph)\s+/i.test(line));
  if (header && /\b(?:LR|RL)\b/i.test(header)) graph.orientation = "horizontal";
  for (const line of lines) {
    if (/^(?:flowchart|graph|subgraph|end)\b/i.test(line) || /^classDef\b/i.test(line) || /^style\b/i.test(line)) continue;
    const edge = line.match(/^(.+?)\s*(-->|---|-.->|==>)\s*(?:\|"?([^|"]*)"?\|\s*)?(.+?)\s*;?$/);
    if (edge) {
      const sourceNode = parseMermaidEndpoint(edge[1]);
      const targetNode = parseMermaidEndpoint(edge[4]);
      if (sourceNode && targetNode) {
        if (sourceNode.explicit || !graph.nodes.has(sourceNode.id)) graph.nodes.set(sourceNode.id, { label: sourceNode.label, kind: sourceNode.kind });
        if (targetNode.explicit || !graph.nodes.has(targetNode.id)) graph.nodes.set(targetNode.id, { label: targetNode.label, kind: targetNode.kind });
        graph.edges.push({ source: sourceNode.id, target: targetNode.id, label: cleanText(edge[3] ?? ""), dashed: edge[2] === "-.->" });
      }
      continue;
    }
    const node = parseMermaidEndpoint(line.replace(/;$/, ""));
    if (node && (node.explicit || !graph.nodes.has(node.id))) graph.nodes.set(node.id, { label: node.label, kind: node.kind });
  }
  if (graph.nodes.size === 0) throw new Error(`Mermaid 图页“${name}”不包含可识别的节点`);
  return graph;
}

function parseMermaidEndpoint(source: string) {
  const value = source.trim();
  const match = value.match(/^([A-Za-z_][\w.-]*)(.*)$/);
  if (!match) return undefined;
  const id = match[1];
  const shape = match[2].trim();
  if (!shape) return { id, label: id, kind: "process" as DiagramNodeKind, explicit: false };
  const label = cleanText(shape.replace(/^\(\[|\]\)$/g, "").replace(/^\[\(|\)\]$/g, "").replace(/^[\[({]+|[\])}]+$/g, ""));
  const kind: DiagramNodeKind = shape.startsWith("{") ? "decision"
    : shape.startsWith("([") ? "start"
      : shape.startsWith("[(") ? "database"
        : "process";
  return { id, label: label || id, kind, explicit: true };
}

function parsePlantUmlGraph(source: string, index: number): ParsedGraph {
  const title = source.match(/^\s*title\s+(.+)$/mi)?.[1]?.trim() || `页面 ${index + 1}`;
  const graph: ParsedGraph = {
    name: cleanText(title),
    orientation: /left\s+to\s+right\s+direction/i.test(source) ? "horizontal" : "vertical",
    nodes: new Map(),
    edges: [],
  };
  const lines = source.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("'") && !line.startsWith("skinparam"));
  let activityIndex = 0;
  let previousActivity: string | undefined;
  for (const line of lines) {
    const declaration = line.match(/^(rectangle|component|database|actor|cloud|queue|usecase|class|entity|node|storage|artifact)\s+(?:"([\s\S]*?)"\s+as\s+([A-Za-z_]\w*)|([A-Za-z_]\w*)(?:\s+as\s+"([\s\S]*?)")?)/i);
    if (declaration) {
      const id = declaration[3] ?? declaration[4];
      const label = cleanText(declaration[2] ?? declaration[5] ?? id);
      graph.nodes.set(id, { label, kind: plantUmlKind(declaration[1]) });
      continue;
    }
    const activity = line.match(/^:([\s\S]+);$/);
    if (activity) {
      const id = `activity_${++activityIndex}`;
      graph.nodes.set(id, { label: cleanText(activity[1]), kind: "process" });
      if (previousActivity) graph.edges.push({ source: previousActivity, target: id, label: "" });
      previousActivity = id;
      continue;
    }
    if (/^(start|stop)$/i.test(line)) {
      const id = `${line.toLowerCase()}_${++activityIndex}`;
      graph.nodes.set(id, { label: line.toLowerCase() === "start" ? "开始" : "结束", kind: line.toLowerCase() === "start" ? "start" : "end" });
      if (previousActivity) graph.edges.push({ source: previousActivity, target: id, label: "" });
      previousActivity = id;
      continue;
    }
    const edge = line.match(/^([A-Za-z_]\w*)\s+([-.=]+(?:>|\|>))\s+([A-Za-z_]\w*)(?:\s*:\s*(.*))?$/);
    if (edge) {
      if (!graph.nodes.has(edge[1])) graph.nodes.set(edge[1], { label: edge[1], kind: "process" });
      if (!graph.nodes.has(edge[3])) graph.nodes.set(edge[3], { label: edge[3], kind: "process" });
      graph.edges.push({ source: edge[1], target: edge[3], label: cleanText(edge[4] ?? ""), dashed: edge[2].includes(".") });
    }
  }
  return graph;
}

function graphsToDocument(graphs: ParsedGraph[]) {
  const pages: DiagramPage[] = [];
  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  graphs.forEach((graph, pageIndex) => {
    const pageId = `page-${pageIndex + 1}`;
    pages.push({ id: pageId, name: graph.name.slice(0, 80) || `页面 ${pageIndex + 1}`, order: pageIndex });
    const nodeEntries = Array.from(graph.nodes.entries());
    const idMap = new Map(nodeEntries.map(([id], nodeIndex) => [id, `p${pageIndex + 1}-n${nodeIndex + 1}`]));
    nodeEntries.slice(0, MAX_DIAGRAM_NODES - nodes.length).forEach(([id, definition], nodeIndex) => {
      const column = graph.orientation === "horizontal" ? nodeIndex : nodeIndex % 4;
      const row = graph.orientation === "horizontal" ? nodeIndex % 4 : Math.floor(nodeIndex / 4);
      const size = nodeSize(definition.kind);
      nodes.push({
        id: idMap.get(id)!, kind: definition.kind, label: definition.label.slice(0, 500),
        x: 80 + column * 240, y: 80 + row * 150, width: size[0], height: size[1], zIndex: nodeIndex, pageId,
        style: nodeStyle(definition.kind),
      });
    });
    graph.edges.slice(0, MAX_DIAGRAM_EDGES - edges.length).forEach((edge, edgeIndex) => {
      const sourceId = idMap.get(edge.source);
      const targetId = idMap.get(edge.target);
      if (!sourceId || !targetId || !nodes.some((node) => node.id === sourceId) || !nodes.some((node) => node.id === targetId)) return;
      edges.push({
        id: `p${pageIndex + 1}-e${edgeIndex + 1}`, label: edge.label.slice(0, 500), sourceId, targetId,
        zIndex: edgeIndex, pageId,
        style: { strokeColor: "#64748b", fontColor: "#334155", strokeWidth: 2, dashed: edge.dashed, edgeType: "orthogonal", startArrow: "none", endArrow: "block" },
      });
    });
  });
  return createDiagramDocument(nodes, edges, CANVAS, new Date(), pages, pages[0].id);
}

function mermaidBlocks(source: string) {
  const blocks: Array<{ name: string; body: string }> = [];
  const expression = /(?:^|\n)(?:##\s+([^\n]+)\s*\n+)?```mermaid\s*\n([\s\S]*?)```/gi;
  for (const match of source.matchAll(expression)) blocks.push({ name: cleanText(match[1] ?? `页面 ${blocks.length + 1}`), body: match[2] });
  if (blocks.length === 0 && /(?:flowchart|graph)\s+(?:TD|TB|BT|LR|RL)/i.test(source)) blocks.push({ name: "页面 1", body: source });
  return blocks;
}

function documentPages(document: DiagramDocumentV1): DiagramPage[] {
  return document.pages?.length ? document.pages.slice().sort((a, b) => a.order - b.order) : [{ id: document.activePageId ?? "page-1", name: "页面 1", order: 0 }];
}

function mermaidNodeShape(node: DiagramNode) {
  const label = `"${escapeText(node.label || node.kind)}"`;
  if (node.kind === "diamond" || node.kind === "decision" || node.kind === "bpmnGateway" || node.kind === "erRelationship") return `{${label}}`;
  if (["ellipse", "circle", "start", "end", "connector", "bpmnEvent", "umlUseCase", "umlInterface", "erAttribute", "router"].includes(node.kind)) return `([${label}])`;
  if (node.kind === "database" || node.kind === "queue") return `[(${label})]`;
  return `[${label}]`;
}

function plantUmlKeyword(kind: DiagramNodeKind) {
  if (kind === "database" || kind === "entity") return "database";
  if (kind === "actor") return "actor";
  if (kind === "cloud") return "cloud";
  if (kind === "queue") return "queue";
  if (kind === "server") return "node";
  if (kind === "umlClass") return "class";
  if (kind === "umlInterface") return "interface";
  if (kind === "umlPackage") return "package";
  if (kind === "umlComponent") return "component";
  return "rectangle";
}

function plantUmlKind(keyword: string): DiagramNodeKind {
  const value = keyword.toLowerCase();
  if (value === "database" || value === "storage") return "database";
  if (value === "actor") return "actor";
  if (value === "cloud") return "cloud";
  if (value === "queue") return "queue";
  if (value === "class") return "umlClass";
  if (value === "interface") return "umlInterface";
  if (value === "package") return "umlPackage";
  if (value === "component") return "umlComponent";
  if (value === "entity") return "entity";
  if (value === "node" || value === "artifact") return "server";
  return "process";
}

function nodeSize(kind: DiagramNodeKind): [number, number] {
  if (["circle", "start", "end", "connector", "bpmnEvent", "umlInterface"].includes(kind)) return [84, 84];
  if (["diamond", "decision", "bpmnGateway", "erRelationship"].includes(kind)) return [110, 110];
  if (kind === "database" || kind === "queue") return [160, 92];
  return [180, 82];
}

function nodeStyle(kind: DiagramNodeKind) {
  const decision = kind === "diamond" || kind === "decision" || kind === "bpmnGateway" || kind === "erRelationship";
  return {
    fillColor: decision ? "#fef3c7" : "#dbeafe",
    strokeColor: decision ? "#d97706" : "#2563eb",
    fontColor: "#172033",
    strokeWidth: 2,
  };
}

function cleanText(value: string) {
  return value.trim().replace(/^['"]|['"]$/g, "").replace(/<br\s*\/?>/gi, "\n").replace(/&quot;/g, '"');
}

function escapeText(value: string) {
  return value.replace(/\\/g, "\\\\").replace(/"/g, "&quot;").replace(/\r?\n/g, "<br/>");
}

function escapePlantUml(value: string) {
  return value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"").replace(/\r?\n/g, "\\n");
}
