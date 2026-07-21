import * as Y from "yjs";
import {
  isDiagramComment,
  isDiagramEdge,
  isDiagramNode,
  isDiagramPage,
  MAX_DIAGRAM_COMMENTS,
  MAX_DIAGRAM_EDGES,
  MAX_DIAGRAM_NODES,
  MAX_DIAGRAM_PAGES,
} from "./diagramDocument";
import type { DiagramComment, DiagramEdge, DiagramNode, DiagramPage } from "./diagramDocument";

const NODES_MAP = "nodes";
const EDGES_MAP = "edges";
const PAGES_MAP = "pages";
const COMMENTS_MAP = "comments";

interface ChangedDiagramKeys {
  nodes: Set<string>;
  edges: Set<string>;
  pages: Set<string>;
  comments: Set<string>;
}

export class DiagramRemoteUpdateValidator {
  private document: Y.Doc;

  constructor(source: Y.Doc) {
    this.document = cloneYDocument(source);
  }

  sync(update: Uint8Array) {
    Y.applyUpdate(this.document, update);
  }

  validate(update: Uint8Array, source: Y.Doc) {
    const changed: ChangedDiagramKeys = {
      nodes: new Set(),
      edges: new Set(),
      pages: new Set(),
      comments: new Set(),
    };
    const nodes = this.document.getMap<DiagramNode>(NODES_MAP);
    const edges = this.document.getMap<DiagramEdge>(EDGES_MAP);
    const pages = this.document.getMap<DiagramPage>(PAGES_MAP);
    const comments = this.document.getMap<DiagramComment>(COMMENTS_MAP);
    const nodeObserver = collectChangedKeys<DiagramNode>(changed.nodes);
    const edgeObserver = collectChangedKeys<DiagramEdge>(changed.edges);
    const pageObserver = collectChangedKeys<DiagramPage>(changed.pages);
    const commentObserver = collectChangedKeys<DiagramComment>(changed.comments);
    nodes.observe(nodeObserver);
    edges.observe(edgeObserver);
    pages.observe(pageObserver);
    comments.observe(commentObserver);
    try {
      Y.applyUpdate(this.document, update);
      if (isValidChangedDiagramState(nodes, edges, pages, comments, changed)) {
        return true;
      }
    } catch {
      // The mirror is rebuilt below so a rejected update cannot poison later validation.
    } finally {
      nodes.unobserve(nodeObserver);
      edges.unobserve(edgeObserver);
      pages.unobserve(pageObserver);
      comments.unobserve(commentObserver);
    }
    this.reset(source);
    return false;
  }

  reset(source: Y.Doc) {
    this.document.destroy();
    this.document = cloneYDocument(source);
  }

  destroy() {
    this.document.destroy();
  }
}

function cloneYDocument(source: Y.Doc) {
  const document = new Y.Doc();
  Y.applyUpdate(document, Y.encodeStateAsUpdate(source));
  return document;
}

function collectChangedKeys<T>(target: Set<string>) {
  return (event: Y.YMapEvent<T>) => {
    event.keysChanged.forEach((key) => target.add(key));
  };
}

function isValidChangedDiagramState(
  nodes: Y.Map<DiagramNode>,
  edges: Y.Map<DiagramEdge>,
  pages: Y.Map<DiagramPage>,
  comments: Y.Map<DiagramComment>,
  changed: ChangedDiagramKeys,
) {
  if (nodes.size > MAX_DIAGRAM_NODES
    || edges.size > MAX_DIAGRAM_EDGES
    || pages.size === 0
    || pages.size > MAX_DIAGRAM_PAGES
    || comments.size > MAX_DIAGRAM_COMMENTS) {
    return false;
  }

  for (const key of changed.pages) {
    const page = pages.get(key);
    if (page !== undefined && (page.id !== key || !isDiagramPage(page))) return false;
  }
  for (const key of changed.nodes) {
    const node = nodes.get(key);
    if (node !== undefined && (node.id !== key || !isDiagramNode(node) || !isValidNodeReference(node, nodes, pages))) {
      return false;
    }
  }
  for (const key of changed.edges) {
    const edge = edges.get(key);
    if (edge !== undefined && (edge.id !== key || !isDiagramEdge(edge) || !isValidEdgeReference(edge, nodes, pages))) {
      return false;
    }
  }
  for (const key of changed.comments) {
    const comment = comments.get(key);
    if (comment !== undefined && (comment.id !== key || !isDiagramComment(comment) || !pages.has(comment.pageId))) {
      return false;
    }
  }

  const changedNode = changed.nodes.size > 0;
  const deletedPage = Array.from(changed.pages).some((key) => !pages.has(key));
  if (changedNode) {
    // A parent kind/page change can invalidate unchanged descendants or connected edges.
    for (const node of nodes.values()) {
      if (!isValidNodeReference(node, nodes, pages)) return false;
    }
    for (const edge of edges.values()) {
      if (!isValidEdgeReference(edge, nodes, pages)) return false;
    }
  }
  if (deletedPage) {
    for (const node of nodes.values()) {
      if (node.pageId && !pages.has(node.pageId)) return false;
    }
    for (const edge of edges.values()) {
      if (edge.pageId && !pages.has(edge.pageId)) return false;
    }
    for (const comment of comments.values()) {
      if (!pages.has(comment.pageId)) return false;
    }
  }
  return true;
}

function isValidNodeReference(node: DiagramNode, nodes: Y.Map<DiagramNode>, pages: Y.Map<DiagramPage>) {
  if (node.pageId && !pages.has(node.pageId)) return false;
  if (!node.parentId) return true;
  const visited = new Set([node.id]);
  let parentId: string | undefined = node.parentId;
  while (parentId) {
    if (visited.has(parentId)) return false;
    visited.add(parentId);
    const parent = nodes.get(parentId);
    if (!parent || (parent.kind !== "container" && parent.kind !== "swimlane" && parent.kind !== "lane")) return false;
    if (node.kind === "lane" && parentId === node.parentId && parent.kind !== "swimlane") return false;
    parentId = parent.parentId;
  }
  return true;
}

function isValidEdgeReference(edge: DiagramEdge, nodes: Y.Map<DiagramNode>, pages: Y.Map<DiagramPage>) {
  if (edge.pageId && !pages.has(edge.pageId)) return false;
  const source = nodes.get(edge.sourceId);
  const target = nodes.get(edge.targetId);
  if (!source || !target) return false;
  if (edge.pageId && (source.pageId && source.pageId !== edge.pageId || target.pageId && target.pageId !== edge.pageId)) {
    return false;
  }
  return true;
}
