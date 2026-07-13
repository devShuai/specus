import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Button, Chip } from "@heroui/react";
import {
  Cell,
  Clipboard,
  ConnectionConstraint,
  Graph,
  HierarchicalLayout,
  InternalEvent,
  Point,
} from "@maxgraph/core";
import type { CellStyle, FitPlugin } from "@maxgraph/core";
import * as Y from "yjs";
import "@maxgraph/core/css/common.css";
import type { WhiteboardInboundEvent } from "./SyncedWhiteboard";
import {
  createDiagramDocument,
  decodeDiagramUpdate,
  DIAGRAM_FILE_EXTENSION,
  DIAGRAM_FILE_MIME,
  encodeDiagramUpdate,
  isDiagramGraphState,
  MAX_DIAGRAM_DOCUMENT_BYTES,
  MAX_DIAGRAM_NODES,
  MAX_DIAGRAM_UPDATE_BASE64_LENGTH,
  parseDiagramDocument,
} from "../lib/diagramDocument";
import type {
  DiagramDocumentV1,
  DiagramEdge,
  DiagramEdgeStyle,
  DiagramNode,
  DiagramNodeKind,
  DiagramNodeStyle,
  DiagramPayload,
  DiagramPort,
} from "../lib/diagramDocument";
import { useTheme } from "../theme/ThemeContext";

interface SyncedDiagramProps {
  boardKey: string;
  peerId: string;
  peerCount: number;
  isConnected: boolean;
  isActive?: boolean;
  events: WhiteboardInboundEvent[];
  onSend: (payload: DiagramPayload) => void;
  onSwitchToWhiteboard: () => void;
}

interface DiagramRuntime {
  graph: Graph;
  destroy: () => void;
}

interface DiagramSelection {
  ids: string[];
  label: string;
  isNode: boolean;
  isEdge: boolean;
  fillColor?: string;
  strokeColor?: string;
  dashed: boolean;
  strokeWidth: number;
}

type DiagramCellStyle = CellStyle & { diagramKind?: DiagramNodeKind };

const GRAPH_ORIGIN = Symbol("diagram-graph");
const IMPORT_ORIGIN = Symbol("diagram-import");
const REMOTE_ORIGIN = Symbol("diagram-remote");
const DIAGRAM_CACHE_LIMIT = 8;
const NODES_MAP = "nodes";
const EDGES_MAP = "edges";
const DIAGRAM_CANVAS = { width: 2_400, height: 1_600, gridSize: 10 };
const EMPTY_SELECTION: DiagramSelection = {
  ids: [],
  label: "",
  isNode: false,
  isEdge: false,
  dashed: false,
  strokeWidth: 2,
};

const PORT_CONSTRAINTS = [
  new ConnectionConstraint(new Point(0.5, 0), true, "north"),
  new ConnectionConstraint(new Point(1, 0.5), true, "east"),
  new ConnectionConstraint(new Point(0.5, 1), true, "south"),
  new ConnectionConstraint(new Point(0, 0.5), true, "west"),
];

const NODE_PALETTE: Array<{ kind: DiagramNodeKind; label: string; detail: string }> = [
  { kind: "start", label: "开始", detail: "起止节点" },
  { kind: "process", label: "处理", detail: "业务步骤" },
  { kind: "decision", label: "判断", detail: "条件分支" },
  { kind: "end", label: "结束", detail: "终止节点" },
  { kind: "document", label: "文档", detail: "输入输出" },
  { kind: "database", label: "数据库", detail: "数据存储" },
  { kind: "actor", label: "参与者", detail: "角色系统" },
  { kind: "note", label: "注释", detail: "补充说明" },
];

const FILL_COLORS = ["#ffffff", "#dbeafe", "#dcfce7", "#fef3c7", "#fce7f3", "#ede9fe"];
const STROKE_COLORS = ["#475569", "#2563eb", "#16a34a", "#d97706", "#db2777", "#7c3aed"];
const diagramStateCache = new Map<string, Uint8Array>();

export function SyncedDiagram({
  boardKey,
  peerId,
  peerCount,
  isConnected,
  isActive = true,
  events,
  onSend,
  onSwitchToWhiteboard,
}: SyncedDiagramProps) {
  const { theme } = useTheme();
  const graphContainerRef = useRef<HTMLDivElement | null>(null);
  const importInputRef = useRef<HTMLInputElement | null>(null);
  const runtimeRef = useRef<DiagramRuntime | null>(null);
  const yDocRef = useRef<Y.Doc | null>(null);
  const nodesMapRef = useRef<Y.Map<DiagramNode> | null>(null);
  const edgesMapRef = useRef<Y.Map<DiagramEdge> | null>(null);
  const undoManagerRef = useRef<Y.UndoManager | null>(null);
  const renderGraphRef = useRef<() => void>(() => undefined);
  const flushGraphRef = useRef<() => void>(() => undefined);
  const graphSyncTimerRef = useRef<number | null>(null);
  const suppressGraphSyncRef = useRef(false);
  const seenEventsRef = useRef(new Set<string>());
  const lastPeerCountRef = useRef(peerCount);
  const onSendRef = useRef(onSend);
  onSendRef.current = onSend;

  const [isExpanded, setIsExpanded] = useState(false);
  const [documentEpoch, setDocumentEpoch] = useState(0);
  const [runtimeEpoch, setRuntimeEpoch] = useState(0);
  const [selection, setSelection] = useState<DiagramSelection>(EMPTY_SELECTION);
  const [nodeCount, setNodeCount] = useState(0);
  const [edgeCount, setEdgeCount] = useState(0);
  const [canUndo, setCanUndo] = useState(false);
  const [canRedo, setCanRedo] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [status, setStatus] = useState("专业流程图已就绪，从左侧插入节点后拖动蓝色端口连线。");

  const refreshUndoState = useCallback(() => {
    const manager = undoManagerRef.current;
    setCanUndo(Boolean(manager?.canUndo()));
    setCanRedo(Boolean(manager?.canRedo()));
  }, []);

  const sendYUpdate = useCallback((update: Uint8Array) => {
    const encoded = encodeDiagramUpdate(update);
    if (encoded.length > MAX_DIAGRAM_UPDATE_BASE64_LENGTH) {
      setStatus("流程图同步数据超过 4 MB，请导出后精简文档再继续协作。");
      return false;
    }
    onSendRef.current({
      type: "STDG1",
      kind: "diagram-update",
      update: encoded,
      createdAt: Date.now(),
    });
    return true;
  }, []);

  const sendFullState = useCallback(() => {
    const document = yDocRef.current;
    if (!document) {
      return false;
    }
    return sendYUpdate(Y.encodeStateAsUpdate(document));
  }, [sendYUpdate]);

  useEffect(() => {
    const document = new Y.Doc();
    const nodes = document.getMap<DiagramNode>(NODES_MAP);
    const edges = document.getMap<DiagramEdge>(EDGES_MAP);
    const undoManager = new Y.UndoManager([nodes, edges], {
      captureTimeout: 420,
      trackedOrigins: new Set([GRAPH_ORIGIN, IMPORT_ORIGIN]),
    });
    yDocRef.current = document;
    nodesMapRef.current = nodes;
    edgesMapRef.current = edges;
    undoManagerRef.current = undoManager;
    seenEventsRef.current.clear();
    lastPeerCountRef.current = 0;
    setSelection(EMPTY_SELECTION);
    setNodeCount(0);
    setEdgeCount(0);
    setCanUndo(false);
    setCanRedo(false);
    const cached = diagramStateCache.get(boardKey);
    let restoredFromCache = false;
    if (cached) {
      try {
        Y.applyUpdate(document, cached, REMOTE_ORIGIN);
        restoredFromCache = nodes.size > 0 || edges.size > 0;
      } catch {
        diagramStateCache.delete(boardKey);
      }
    }
    setStatus(restoredFromCache ? "已恢复当前房间的本地流程图。" : "已切换到新的房间流程图。");

    const handleUpdate = (update: Uint8Array, origin: unknown) => {
      if (origin === REMOTE_ORIGIN) {
        renderGraphRef.current();
        refreshUndoState();
        return;
      }
      if (origin !== GRAPH_ORIGIN) {
        renderGraphRef.current();
      }
      sendYUpdate(update);
      refreshUndoState();
    };
    document.on("update", handleUpdate);
    setDocumentEpoch((value) => value + 1);

    return () => {
      cacheDiagramState(boardKey, Y.encodeStateAsUpdate(document));
      document.off("update", handleUpdate);
      undoManager.destroy();
      document.destroy();
      if (yDocRef.current === document) {
        yDocRef.current = null;
        nodesMapRef.current = null;
        edgesMapRef.current = null;
        undoManagerRef.current = null;
      }
    };
  }, [boardKey, refreshUndoState, sendYUpdate]);

  useEffect(() => {
    const container = graphContainerRef.current;
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    if (!container || !nodes || !edges) {
      return;
    }

    const graph = new Graph(container);
    graph.getDataModel().prefix = `${peerId}-${Math.random().toString(36).slice(2, 9)}-auto-`;
    graph.setConnectable(true);
    graph.setAllowDanglingEdges(false);
    graph.setConnectableEdges(false);
    graph.setMultigraph(false);
    graph.setPanning(true);
    graph.setTooltips(true);
    graph.setGridEnabled(true);
    graph.setGridSize(DIAGRAM_CANVAS.gridSize);
    graph.setCellsEditable(true);
    graph.setCellsResizable(true);
    graph.setCellsBendable(true);
    graph.setHtmlLabels(false);
    graph.setAllowNegativeCoordinates(false);
    graph.centerZoom = true;
    graph.keepSelectionVisibleOnZoom = true;
    graph.getAllConnectionConstraints = (terminal) => (
      terminal?.cell.isVertex() ? PORT_CONSTRAINTS : null
    );

    const readGraph = () => readGraphDocument(graph);
    const syncGraphToDocument = () => {
      if (suppressGraphSyncRef.current) {
        return;
      }
      const currentNodes = nodesMapRef.current;
      const currentEdges = edgesMapRef.current;
      const document = yDocRef.current;
      if (!currentNodes || !currentEdges || !document) {
        return;
      }
      const snapshot = readGraph();
      document.transact(() => {
        replaceYMap(currentNodes, snapshot.nodes);
        replaceYMap(currentEdges, snapshot.edges);
      }, GRAPH_ORIGIN);
      setNodeCount(snapshot.nodes.length);
      setEdgeCount(snapshot.edges.length);
    };
    flushGraphRef.current = syncGraphToDocument;

    const scheduleGraphSync = () => {
      if (suppressGraphSyncRef.current) {
        return;
      }
      if (graphSyncTimerRef.current !== null) {
        window.clearTimeout(graphSyncTimerRef.current);
      }
      graphSyncTimerRef.current = window.setTimeout(() => {
        graphSyncTimerRef.current = null;
        syncGraphToDocument();
      }, 60);
    };

    const renderFromDocument = () => {
      const currentNodes = nodesMapRef.current;
      const currentEdges = edgesMapRef.current;
      if (!currentNodes || !currentEdges) {
        return;
      }
      const selectedIds = new Set(graph.getSelectionCells().map((cell) => cell.getId()).filter(Boolean));
      suppressGraphSyncRef.current = true;
      try {
        graph.batchUpdate(() => {
          const parent = graph.getDefaultParent();
          const existing = [
            ...graph.getChildEdges(parent),
            ...graph.getChildVertices(parent),
          ];
          if (existing.length > 0) {
            graph.removeCells(existing, true);
          }
          const cells = new Map<string, Cell>();
          const nextNodes = Array.from(currentNodes.values()).sort((a, b) => a.zIndex - b.zIndex);
          for (const node of nextNodes) {
            const cell = graph.insertVertex({
              parent,
              id: node.id,
              value: node.label,
              position: [node.x, node.y],
              size: [node.width, node.height],
              style: nodeCellStyle(node),
            });
            cells.set(node.id, cell);
          }
          const nextEdges = Array.from(currentEdges.values()).sort((a, b) => a.zIndex - b.zIndex);
          for (const edge of nextEdges) {
            const source = cells.get(edge.sourceId);
            const target = cells.get(edge.targetId);
            if (!source || !target) {
              continue;
            }
            const edgeCell = graph.insertEdge({
              parent,
              id: edge.id,
              value: edge.label,
              source,
              target,
              style: edgeCellStyle(edge),
            });
            graph.setConnectionConstraint(edgeCell, source, true, constraintForPort(edge.sourcePort));
            graph.setConnectionConstraint(edgeCell, target, false, constraintForPort(edge.targetPort));
            cells.set(edge.id, edgeCell);
          }
          const restoredSelection = Array.from(selectedIds)
            .map((id) => id ? cells.get(id) : undefined)
            .filter((cell): cell is Cell => Boolean(cell));
          if (restoredSelection.length > 0) {
            graph.setSelectionCells(restoredSelection);
          }
        });
      } finally {
        suppressGraphSyncRef.current = false;
      }
      setNodeCount(currentNodes.size);
      setEdgeCount(currentEdges.size);
      updateSelection(graph, setSelection);
    };
    renderGraphRef.current = renderFromDocument;

    const modelListener = () => scheduleGraphSync();
    const selectionListener = () => updateSelection(graph, setSelection);
    graph.getDataModel().addListener(InternalEvent.CHANGE, modelListener);
    graph.getSelectionModel().addListener(InternalEvent.CHANGE, selectionListener);
    const resizeObserver = new ResizeObserver(() => graph.sizeDidChange());
    resizeObserver.observe(container);
    runtimeRef.current = {
      graph,
      destroy: () => {
        resizeObserver.disconnect();
        graph.getDataModel().removeListener(modelListener);
        graph.getSelectionModel().removeListener(selectionListener);
        graph.destroy();
      },
    };
    renderFromDocument();
    setRuntimeEpoch((value) => value + 1);

    return () => {
      if (graphSyncTimerRef.current !== null) {
        window.clearTimeout(graphSyncTimerRef.current);
        graphSyncTimerRef.current = null;
        syncGraphToDocument();
      }
      if (runtimeRef.current?.graph === graph) {
        runtimeRef.current = null;
      }
      renderGraphRef.current = () => undefined;
      flushGraphRef.current = () => undefined;
      resizeObserver.disconnect();
      graph.getDataModel().removeListener(modelListener);
      graph.getSelectionModel().removeListener(selectionListener);
      graph.destroy();
    };
  }, [boardKey, documentEpoch, isExpanded, peerId]);

  useEffect(() => {
    const document = yDocRef.current;
    if (!document) {
      return;
    }
    for (const event of events) {
      if (seenEventsRef.current.has(event.eventId)) {
        continue;
      }
      seenEventsRef.current.add(event.eventId);
      const payload = event.payload;
      if (event.sourcePeerId === peerId || payload.type !== "STDG1") {
        continue;
      }
      if (payload.kind === "diagram-sync-request") {
        if (Date.now() - event.receivedAt < 5_000) {
          window.setTimeout(() => sendFullState(), 80 + Math.floor(Math.random() * 180));
        }
        continue;
      }
      try {
        const update = decodeDiagramUpdate(payload.update);
        if (!isSafeRemoteDiagramUpdate(document, update)) {
          throw new Error("invalid diagram state");
        }
        Y.applyUpdate(document, update, REMOTE_ORIGIN);
        setStatus(`已合并来自 ${event.sourcePeerId} 的流程图更新。`);
      } catch {
        setStatus("收到的流程图同步数据无效，已忽略。");
      }
    }
    if (seenEventsRef.current.size > 1_000) {
      seenEventsRef.current = new Set(Array.from(seenEventsRef.current).slice(-600));
    }
  }, [events, peerId, runtimeEpoch, sendFullState]);

  useEffect(() => {
    if (!isConnected || !yDocRef.current) {
      return;
    }
    const timer = window.setTimeout(() => {
      onSendRef.current({
        type: "STDG1",
        kind: "diagram-sync-request",
        requestId: createDiagramId(peerId, "sync"),
        createdAt: Date.now(),
      });
    }, 160 + Math.floor(Math.random() * 220));
    return () => window.clearTimeout(timer);
  }, [boardKey, documentEpoch, isConnected, peerId]);

  useEffect(() => {
    const previous = lastPeerCountRef.current;
    lastPeerCountRef.current = peerCount;
    if (!isConnected || peerCount <= previous) {
      return;
    }
    const timer = window.setTimeout(() => sendFullState(), 180 + Math.floor(Math.random() * 260));
    return () => window.clearTimeout(timer);
  }, [isConnected, peerCount, sendFullState]);

  const withGraph = useCallback((action: (graph: Graph) => void) => {
    const graph = runtimeRef.current?.graph;
    if (graph) {
      action(graph);
    }
  }, []);

  const switchToWhiteboard = useCallback(() => {
    if (graphSyncTimerRef.current !== null) {
      window.clearTimeout(graphSyncTimerRef.current);
      graphSyncTimerRef.current = null;
    }
    flushGraphRef.current();
    const document = yDocRef.current;
    if (document) {
      cacheDiagramState(boardKey, Y.encodeStateAsUpdate(document));
    }
    onSwitchToWhiteboard();
  }, [boardKey, onSwitchToWhiteboard]);

  const insertNode = useCallback((kind: DiagramNodeKind) => {
    withGraph((graph) => {
      if (graph.getChildVertices(graph.getDefaultParent()).length >= MAX_DIAGRAM_NODES) {
        setStatus("流程图节点已达到 1000 个上限。");
        return;
      }
      const defaults = nodeDefaults(kind);
      const index = graph.getChildVertices(graph.getDefaultParent()).length;
      const scale = graph.getView().getScale();
      const translate = graph.getView().getTranslate();
      const container = graph.container;
      const x = Math.max(20, (container.scrollLeft + container.clientWidth / 2) / scale - translate.x - defaults.width / 2 + (index % 4) * 12);
      const y = Math.max(20, (container.scrollTop + container.clientHeight / 2) / scale - translate.y - defaults.height / 2 + (index % 4) * 12);
      const node: DiagramNode = {
        id: createDiagramId(peerId, kind),
        kind,
        label: defaults.label,
        x,
        y,
        width: defaults.width,
        height: defaults.height,
        zIndex: index,
        style: defaults.style,
      };
      const cell = graph.insertVertex({
        parent: graph.getDefaultParent(),
        id: node.id,
        value: node.label,
        position: [node.x, node.y],
        size: [node.width, node.height],
        style: nodeCellStyle(node),
      });
      graph.setSelectionCell(cell);
      graph.scrollCellToVisible(cell);
      setStatus(`${defaults.label}节点已插入；选中节点后从蓝色端口拖到目标节点即可连线。`);
    });
  }, [peerId, withGraph]);

  const insertTemplate = useCallback(() => {
    withGraph((graph) => {
      if (graph.getChildVertices(graph.getDefaultParent()).length + 4 > MAX_DIAGRAM_NODES) {
        setStatus("节点数量不足以插入模板。");
        return;
      }
      const parent = graph.getDefaultParent();
      const baseX = Math.max(40, graph.container.scrollLeft + 80);
      const baseY = Math.max(40, graph.container.scrollTop + 60);
      const cells: Cell[] = [];
      graph.batchUpdate(() => {
        const definitions: Array<{ kind: DiagramNodeKind; label: string; x: number; y: number }> = [
          { kind: "start", label: "开始", x: baseX + 40, y: baseY },
          { kind: "process", label: "处理请求", x: baseX + 20, y: baseY + 130 },
          { kind: "decision", label: "校验通过？", x: baseX, y: baseY + 270 },
          { kind: "end", label: "结束", x: baseX + 40, y: baseY + 430 },
        ];
        for (const definition of definitions) {
          const defaults = nodeDefaults(definition.kind);
          const node: DiagramNode = {
            id: createDiagramId(peerId, definition.kind),
            kind: definition.kind,
            label: definition.label,
            x: definition.x,
            y: definition.y,
            width: defaults.width,
            height: defaults.height,
            zIndex: cells.length,
            style: defaults.style,
          };
          cells.push(graph.insertVertex({
            parent,
            id: node.id,
            value: node.label,
            position: [node.x, node.y],
            size: [node.width, node.height],
            style: nodeCellStyle(node),
          }));
        }
        for (let index = 0; index < cells.length - 1; index += 1) {
          const edge = graph.insertEdge({
            parent,
            id: createDiagramId(peerId, "edge"),
            value: index === 2 ? "是" : "",
            source: cells[index],
            target: cells[index + 1],
            style: edgeCellStyle({
              id: "template",
              label: "",
              sourceId: "source",
              targetId: "target",
              sourcePort: "south",
              targetPort: "north",
              zIndex: index,
              style: defaultEdgeStyle(),
            }),
          });
          graph.setConnectionConstraint(edge, cells[index], true, constraintForPort("south"));
          graph.setConnectionConstraint(edge, cells[index + 1], false, constraintForPort("north"));
        }
      });
      graph.setSelectionCells(cells);
      graph.getPlugin<FitPlugin>("fit")?.fitCenter({ margin: 32 });
      setStatus("基础审批流程模板已插入，可继续改名、分支和自动布局。");
    });
  }, [peerId, withGraph]);

  const removeSelection = useCallback(() => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells();
      if (cells.length > 0) {
        graph.removeCells(cells, true);
        setStatus(`已删除 ${cells.length} 个选中元素。`);
      }
    });
  }, [withGraph]);

  const copySelection = useCallback(() => {
    withGraph((graph) => {
      if (graph.getSelectionCells().length > 0) {
        Clipboard.copy(graph);
        setStatus("已复制选中元素，可在流程图中粘贴副本。");
      }
    });
  }, [withGraph]);

  const pasteSelection = useCallback(() => {
    withGraph((graph) => {
      const pasted = Clipboard.paste(graph);
      if (pasted && pasted.length > 0) {
        graph.setSelectionCells(pasted);
        setStatus(`已粘贴 ${pasted.length} 个元素。`);
      }
    });
  }, [withGraph]);

  const duplicateSelection = useCallback(() => {
    withGraph((graph) => {
      if (graph.getSelectionCells().length === 0) {
        return;
      }
      Clipboard.copy(graph);
      const pasted = Clipboard.paste(graph);
      if (pasted) {
        graph.setSelectionCells(pasted);
        setStatus("已创建选中元素的副本。");
      }
    });
  }, [withGraph]);

  const runLayout = useCallback((orientation: "north" | "east") => {
    withGraph((graph) => {
      if (graph.getChildVertices(graph.getDefaultParent()).length < 2) {
        setStatus("至少需要两个节点才能自动布局。");
        return;
      }
      const layout = new HierarchicalLayout(graph, orientation);
      layout.intraCellSpacing = 48;
      layout.interRankCellSpacing = 88;
      layout.execute(graph.getDefaultParent());
      graph.getPlugin<FitPlugin>("fit")?.fitCenter({ margin: 32 });
      setStatus(orientation === "north" ? "已按从上到下自动布局。" : "已按从左到右自动布局。");
    });
  }, [withGraph]);

  const alignSelection = useCallback((align: "left" | "center" | "right" | "top" | "middle" | "bottom") => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells().filter((cell) => cell.isVertex());
      if (cells.length < 2) {
        setStatus("至少选择两个节点才能对齐。");
        return;
      }
      graph.alignCells(align, cells);
      setStatus(`已对齐 ${cells.length} 个节点。`);
    });
  }, [withGraph]);

  const updateSelectedStyle = useCallback((key: "fillColor" | "strokeColor" | "dashed" | "strokeWidth", value: string | boolean | number) => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells();
      if (cells.length === 0) {
        return;
      }
      graph.setCellStyles(key, value, cells);
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const commitSelectionLabel = useCallback((label: string) => {
    withGraph((graph) => {
      const cell = graph.getSelectionCell();
      if (!cell || graph.getSelectionCells().length !== 1) {
        return;
      }
      graph.getDataModel().setValue(cell, label.slice(0, 500));
      updateSelection(graph, setSelection);
      setStatus("元素文字已更新。");
    });
  }, [withGraph]);

  const clearDiagram = useCallback(() => {
    withGraph((graph) => {
      const parent = graph.getDefaultParent();
      const cells = [...graph.getChildEdges(parent), ...graph.getChildVertices(parent)];
      if (cells.length === 0 || !window.confirm("确定清空当前流程图吗？此操作可以撤销。")) {
        return;
      }
      graph.removeCells(cells, true);
      setStatus("流程图已清空，可使用撤销恢复。");
    });
  }, [withGraph]);

  const exportDiagram = useCallback(() => {
    const graph = runtimeRef.current?.graph;
    if (!graph) {
      return;
    }
    const snapshot = readGraphDocument(graph);
    const document = createDiagramDocument(snapshot.nodes, snapshot.edges, DIAGRAM_CANVAS);
    const blob = new Blob([JSON.stringify(document, null, 2)], { type: DIAGRAM_FILE_MIME });
    const url = URL.createObjectURL(blob);
    const link = window.document.createElement("a");
    link.href = url;
    link.download = diagramExportFileName(new Date());
    window.document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
    setStatus(`已导出 ${document.nodes.length} 个节点和 ${document.edges.length} 条连线。`);
  }, []);

  const importDiagram = useCallback(async (file: File) => {
    if (file.size > MAX_DIAGRAM_DOCUMENT_BYTES) {
      setStatus("流程图文件超过 2 MB，无法导入。");
      return;
    }
    setIsImporting(true);
    try {
      const imported = parseDiagramDocument(await file.text());
      if ((nodeCount > 0 || edgeCount > 0)
        && !window.confirm("导入将替换当前流程图并同步给房间内设备。是否继续？")) {
        setStatus("已取消导入，当前流程图未变化。");
        return;
      }
      const document = yDocRef.current;
      const nodes = nodesMapRef.current;
      const edges = edgesMapRef.current;
      if (!document || !nodes || !edges) {
        throw new Error("流程图编辑器尚未就绪");
      }
      document.transact(() => {
        nodes.clear();
        edges.clear();
        imported.nodes.forEach((node) => nodes.set(node.id, cloneNode(node)));
        imported.edges.forEach((edge) => edges.set(edge.id, cloneEdge(edge)));
      }, IMPORT_ORIGIN);
      undoManagerRef.current?.clear();
      refreshUndoState();
      setStatus(`已导入 ${imported.nodes.length} 个节点和 ${imported.edges.length} 条连线，并同步到房间。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "流程图导入失败");
    } finally {
      setIsImporting(false);
    }
  }, [edgeCount, nodeCount, refreshUndoState]);

  const handleKeyDown = useCallback((event: React.KeyboardEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (target.closest("input, textarea, [contenteditable='true']")) {
      return;
    }
    const graph = runtimeRef.current?.graph;
    if (!graph) {
      return;
    }
    const modifier = event.metaKey || event.ctrlKey;
    const key = event.key.toLowerCase();
    if (modifier && key === "z") {
      event.preventDefault();
      if (event.shiftKey) {
        undoManagerRef.current?.redo();
      } else {
        undoManagerRef.current?.undo();
      }
      refreshUndoState();
      return;
    }
    if (modifier && key === "y") {
      event.preventDefault();
      undoManagerRef.current?.redo();
      refreshUndoState();
      return;
    }
    if (modifier && key === "c") {
      event.preventDefault();
      copySelection();
      return;
    }
    if (modifier && key === "v") {
      event.preventDefault();
      pasteSelection();
      return;
    }
    if (modifier && key === "d") {
      event.preventDefault();
      duplicateSelection();
      return;
    }
    if (modifier && key === "a") {
      event.preventDefault();
      graph.selectAll();
      return;
    }
    if (event.key === "Delete" || event.key === "Backspace") {
      event.preventDefault();
      removeSelection();
      return;
    }
    if (event.key === "Enter" || event.key === "F2") {
      const cell = graph.getSelectionCell();
      if (cell) {
        event.preventDefault();
        graph.startEditingAtCell(cell);
      }
      return;
    }
    if (event.key.startsWith("Arrow") && graph.getSelectionCells().length > 0) {
      event.preventDefault();
      const distance = event.shiftKey ? 10 : 1;
      const delta = event.key === "ArrowLeft" ? [-distance, 0]
        : event.key === "ArrowRight" ? [distance, 0]
          : event.key === "ArrowUp" ? [0, -distance]
            : [0, distance];
      graph.moveCells(graph.getSelectionCells(), delta[0], delta[1]);
    }
  }, [copySelection, duplicateSelection, pasteSelection, refreshUndoState, removeSelection]);

  const totalPeers = Math.max(1, peerCount + 1);
  const selectedCountLabel = selection.ids.length > 0 ? ` · 已选 ${selection.ids.length}` : "";
  const canvasBackground = theme === "dark" ? "#15181f" : "#f8fafc";
  const gridColor = theme === "dark" ? "rgba(148,163,184,.16)" : "rgba(100,116,139,.16)";

  const diagram = (
    <section
      className={(isExpanded
        ? "fixed inset-0 z-[90] h-[100dvh] overflow-hidden bg-zinc-100 dark:bg-zinc-950"
        : "mt-5 rounded-xl glass glass-border border p-3 sm:p-4") + (isActive ? "" : " hidden")}
      aria-hidden={!isActive}
    >
      <input
        ref={importInputRef}
        type="file"
        accept={`${DIAGRAM_FILE_EXTENSION},application/json,${DIAGRAM_FILE_MIME}`}
        hidden
        onChange={(event) => {
          const file = event.currentTarget.files?.[0];
          event.currentTarget.value = "";
          if (file) {
            void importDiagram(file);
          }
        }}
      />
      {!isExpanded ? (
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-base font-semibold text-zinc-950 dark:text-white">同步白板</h2>
              <div className="flex rounded-lg border border-black/10 bg-black/[0.035] p-0.5 dark:border-white/10 dark:bg-white/[0.05]">
                <button
                  type="button"
                  className="rounded-md px-2.5 py-1 text-tiny font-medium text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white"
                  onClick={switchToWhiteboard}
                >
                  自由白板
                </button>
                <button type="button" className="rounded-md bg-white px-2.5 py-1 text-tiny font-semibold text-cyan-800 shadow-sm dark:bg-zinc-800 dark:text-cyan-200">
                  专业流程图
                </button>
              </div>
              <Chip size="sm" radius="sm" variant="flat" color={isConnected ? "success" : "default"}>
                {isConnected ? "Yjs 实时协同" : "本地编辑"}
              </Chip>
              <Chip size="sm" radius="sm" variant="flat">{totalPeers} 台 · {nodeCount} 节点 · {edgeCount} 连线</Chip>
            </div>
            <div className="mt-1 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
              独立流程图文档，支持端口连线、框选多选、自动布局、撤销重做和导入导出。
            </div>
          </div>
          <Button size="sm" radius="sm" variant="flat" onPress={() => setIsExpanded(true)}>
            全屏流程图
          </Button>
        </div>
      ) : null}

      <div className={isExpanded
        ? "absolute inset-0 flex min-h-0 flex-col overflow-hidden bg-zinc-100 dark:bg-zinc-950"
        : "mt-3 flex min-h-0 flex-col overflow-hidden rounded-xl border border-black/10 bg-white/80 shadow-sm dark:border-white/10 dark:bg-zinc-950/70"}
      >
        <div className="flex shrink-0 items-center gap-1 overflow-x-auto border-b border-black/10 bg-white/90 p-2 dark:border-white/10 dark:bg-zinc-900/95" role="toolbar" aria-label="流程图操作">
          {isExpanded ? (
            <>
              <DiagramToolbarButton label="白板" onClick={() => {
                setIsExpanded(false);
                switchToWhiteboard();
              }} />
              <DiagramToolbarButton label="退出全屏" onClick={() => setIsExpanded(false)} />
              <span className="mx-1 h-7 w-px shrink-0 bg-black/10 dark:bg-white/10" />
            </>
          ) : null}
          <DiagramToolbarButton label="撤销" shortcut="⌘Z" disabled={!canUndo} onClick={() => {
            undoManagerRef.current?.undo();
            refreshUndoState();
          }} />
          <DiagramToolbarButton label="重做" shortcut="⇧⌘Z" disabled={!canRedo} onClick={() => {
            undoManagerRef.current?.redo();
            refreshUndoState();
          }} />
          <DiagramToolbarButton label="复制" shortcut="⌘C" disabled={selection.ids.length === 0} onClick={copySelection} />
          <DiagramToolbarButton label="粘贴" shortcut="⌘V" onClick={pasteSelection} />
          <DiagramToolbarButton label="副本" shortcut="⌘D" disabled={selection.ids.length === 0} onClick={duplicateSelection} />
          <DiagramToolbarButton label="删除" shortcut="Del" danger disabled={selection.ids.length === 0} onClick={removeSelection} />
          <span className="mx-1 h-7 w-px shrink-0 bg-black/10 dark:bg-white/10" />
          <DiagramToolbarButton label="上→下布局" onClick={() => runLayout("north")} />
          <DiagramToolbarButton label="左→右布局" onClick={() => runLayout("east")} />
          <DiagramToolbarButton label="左对齐" disabled={selection.ids.length < 2} onClick={() => alignSelection("left")} />
          <DiagramToolbarButton label="水平居中" disabled={selection.ids.length < 2} onClick={() => alignSelection("center")} />
          <span className="mx-1 h-7 w-px shrink-0 bg-black/10 dark:bg-white/10" />
          <DiagramToolbarButton label="放大" onClick={() => withGraph((graph) => graph.zoomIn())} />
          <DiagramToolbarButton label="缩小" onClick={() => withGraph((graph) => graph.zoomOut())} />
          <DiagramToolbarButton label="适应" onClick={() => withGraph((graph) => graph.getPlugin<FitPlugin>("fit")?.fitCenter({ margin: 28 }))} />
          <DiagramToolbarButton label="100%" onClick={() => withGraph((graph) => graph.zoomActual())} />
          <span className="mx-1 h-7 w-px shrink-0 bg-black/10 dark:bg-white/10" />
          <DiagramToolbarButton label={isImporting ? "导入中" : "导入"} disabled={isImporting} onClick={() => importInputRef.current?.click()} />
          <DiagramToolbarButton label="导出" disabled={nodeCount === 0 && edgeCount === 0} onClick={exportDiagram} />
          <DiagramToolbarButton label="清空" danger disabled={nodeCount === 0 && edgeCount === 0} onClick={clearDiagram} />
        </div>

        <div className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[176px_minmax(0,1fr)_224px]">
          <aside className="flex shrink-0 gap-2 overflow-x-auto border-b border-black/10 bg-white/75 p-2.5 dark:border-white/10 dark:bg-zinc-900/75 lg:flex-col lg:overflow-y-auto lg:border-b-0 lg:border-r">
            <div className="hidden px-1 pb-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-400 lg:block">节点库</div>
            {NODE_PALETTE.map((item) => (
              <button
                key={item.kind}
                type="button"
                className="flex min-w-[112px] shrink-0 items-center gap-2 rounded-lg border border-black/10 bg-white px-2.5 py-2 text-left transition hover:border-cyan-400 hover:bg-cyan-50 dark:border-white/10 dark:bg-white/[0.04] dark:hover:border-cyan-300/50 dark:hover:bg-cyan-300/10 lg:min-w-0"
                onClick={() => insertNode(item.kind)}
              >
                <DiagramNodeGlyph kind={item.kind} />
                <span className="min-w-0">
                  <span className="block text-tiny font-semibold text-zinc-900 dark:text-zinc-100">{item.label}</span>
                  <span className="hidden text-[10px] text-zinc-500 dark:text-zinc-400 lg:block">{item.detail}</span>
                </span>
              </button>
            ))}
            <button
              type="button"
              className="min-w-[132px] shrink-0 rounded-lg border border-dashed border-cyan-400/70 bg-cyan-50 px-3 py-2 text-left text-tiny font-semibold text-cyan-900 hover:bg-cyan-100 dark:border-cyan-300/40 dark:bg-cyan-300/10 dark:text-cyan-100 dark:hover:bg-cyan-300/15 lg:min-w-0"
              onClick={insertTemplate}
            >
              插入审批流程模板
            </button>
          </aside>

          <div
            className="relative min-h-[520px] overflow-hidden lg:min-h-0"
            onKeyDown={handleKeyDown}
            onPointerDown={() => graphContainerRef.current?.focus()}
          >
            <div
              ref={graphContainerRef}
              className="absolute inset-0 overflow-auto outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-400"
              tabIndex={0}
              role="application"
              aria-label="专业流程图画布"
              style={{
                backgroundColor: canvasBackground,
                backgroundImage: `radial-gradient(circle, ${gridColor} 1px, transparent 1px)`,
                backgroundSize: `${DIAGRAM_CANVAS.gridSize * 2}px ${DIAGRAM_CANVAS.gridSize * 2}px`,
              }}
            />
            <div className="pointer-events-none absolute bottom-3 left-3 rounded-md border border-black/10 bg-white/90 px-2.5 py-1 text-[10px] text-zinc-500 shadow-sm backdrop-blur dark:border-white/10 dark:bg-zinc-900/90 dark:text-zinc-400">
              拖动节点边缘端口创建连线 · 双击或 Enter 编辑文字 · 框选空白区域可多选
            </div>
          </div>

          <aside className="overflow-y-auto border-t border-black/10 bg-white/75 p-3 dark:border-white/10 dark:bg-zinc-900/75 lg:border-l lg:border-t-0">
            <div className="flex items-center justify-between gap-2">
              <span className="text-tiny font-semibold text-zinc-900 dark:text-zinc-100">属性</span>
              <span className="text-[10px] text-zinc-400">{selection.ids.length > 0 ? `${selection.ids.length} 个元素` : "未选择"}</span>
            </div>
            {selection.ids.length === 0 ? (
              <div className="mt-3 rounded-lg border border-dashed border-black/10 p-3 text-tiny leading-5 text-zinc-500 dark:border-white/10 dark:text-zinc-400">
                选择节点或连线后，可修改文字、颜色、线型和层级。
              </div>
            ) : (
              <div className="mt-3 space-y-4">
                {selection.ids.length === 1 ? (
                  <label className="block">
                    <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-400">文字</span>
                    <input
                      value={selection.label}
                      maxLength={500}
                      className="mt-1 w-full rounded-md border border-black/10 bg-white px-2.5 py-2 text-tiny text-zinc-900 outline-none focus:border-cyan-400 dark:border-white/10 dark:bg-zinc-950 dark:text-zinc-100"
                      onChange={(event) => setSelection((current) => ({ ...current, label: event.currentTarget.value }))}
                      onBlur={(event) => commitSelectionLabel(event.currentTarget.value)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") {
                          event.currentTarget.blur();
                        }
                      }}
                    />
                  </label>
                ) : null}
                {selection.isNode ? (
                  <ColorPicker label="填充" colors={FILL_COLORS} selected={selection.fillColor} onSelect={(color) => updateSelectedStyle("fillColor", color)} />
                ) : null}
                <ColorPicker label="边框 / 连线" colors={STROKE_COLORS} selected={selection.strokeColor} onSelect={(color) => updateSelectedStyle("strokeColor", color)} />
                <div>
                  <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-400">线条</span>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {[1, 2, 3, 4].map((width) => (
                      <button
                        key={width}
                        type="button"
                        className={`h-8 min-w-8 rounded-md border px-2 text-tiny ${selection.strokeWidth === width
                          ? "border-cyan-400 bg-cyan-50 text-cyan-900 dark:bg-cyan-300/10 dark:text-cyan-100"
                          : "border-black/10 text-zinc-600 dark:border-white/10 dark:text-zinc-300"}`}
                        onClick={() => updateSelectedStyle("strokeWidth", width)}
                      >
                        {width}px
                      </button>
                    ))}
                    <button
                      type="button"
                      aria-pressed={selection.dashed}
                      className={`h-8 rounded-md border px-2.5 text-tiny ${selection.dashed
                        ? "border-cyan-400 bg-cyan-50 text-cyan-900 dark:bg-cyan-300/10 dark:text-cyan-100"
                        : "border-black/10 text-zinc-600 dark:border-white/10 dark:text-zinc-300"}`}
                      onClick={() => updateSelectedStyle("dashed", !selection.dashed)}
                    >
                      虚线
                    </button>
                  </div>
                </div>
                <div>
                  <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-400">层级与对齐</span>
                  <div className="mt-1.5 grid grid-cols-2 gap-1.5">
                    <InspectorAction label="置于顶层" onClick={() => withGraph((graph) => graph.orderCells(false))} />
                    <InspectorAction label="置于底层" onClick={() => withGraph((graph) => graph.orderCells(true))} />
                    <InspectorAction label="顶部对齐" disabled={selection.ids.length < 2} onClick={() => alignSelection("top")} />
                    <InspectorAction label="垂直居中" disabled={selection.ids.length < 2} onClick={() => alignSelection("middle")} />
                  </div>
                </div>
              </div>
            )}
          </aside>
        </div>

        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-black/10 bg-white/90 px-3 py-2 text-tiny text-zinc-500 dark:border-white/10 dark:bg-zinc-900/95 dark:text-zinc-400">
          <span>{status}</span>
          <span className="font-mono text-[10px]">{nodeCount} nodes · {edgeCount} edges{selectedCountLabel}</span>
        </div>
      </div>
    </section>
  );

  return isExpanded ? createPortal(diagram, window.document.body) : diagram;
}

function readGraphDocument(graph: Graph): Pick<DiagramDocumentV1, "nodes" | "edges"> {
  const parent = graph.getDefaultParent();
  const nodes = graph.getChildVertices(parent).flatMap((cell, index): DiagramNode[] => {
    const id = cell.getId();
    const geometry = cell.getGeometry();
    if (!id || !geometry) {
      return [];
    }
    const style = cell.getStyle() as DiagramCellStyle;
    return [{
      id,
      kind: isDiagramNodeKind(style.diagramKind) ? style.diagramKind : "process",
      label: String(cell.getValue() ?? "").slice(0, 500),
      x: geometry.x,
      y: geometry.y,
      width: geometry.width,
      height: geometry.height,
      zIndex: index,
      style: {
        fillColor: styleColor(style.fillColor, "#ffffff"),
        strokeColor: styleColor(style.strokeColor, "#475569"),
        fontColor: styleColor(style.fontColor, "#172033"),
        strokeWidth: styleNumber(style.strokeWidth, 2),
        dashed: Boolean(style.dashed),
      },
    }];
  });
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graph.getChildEdges(parent).flatMap((cell, index): DiagramEdge[] => {
    const id = cell.getId();
    const sourceId = cell.getTerminal(true)?.getId();
    const targetId = cell.getTerminal(false)?.getId();
    if (!id || !sourceId || !targetId || !nodeIds.has(sourceId) || !nodeIds.has(targetId)) {
      return [];
    }
    const style = cell.getStyle();
    return [{
      id,
      label: String(cell.getValue() ?? "").slice(0, 500),
      sourceId,
      targetId,
      sourcePort: portFromStyle(style, true),
      targetPort: portFromStyle(style, false),
      zIndex: index,
      style: {
        strokeColor: styleColor(style.strokeColor, "#64748b"),
        fontColor: styleColor(style.fontColor, "#334155"),
        strokeWidth: styleNumber(style.strokeWidth, 2),
        dashed: Boolean(style.dashed),
      },
    }];
  });
  return { nodes, edges };
}

function replaceYMap<T extends { id: string }>(map: Y.Map<T>, values: T[]) {
  const nextIds = new Set(values.map((value) => value.id));
  for (const key of map.keys()) {
    if (!nextIds.has(key)) {
      map.delete(key);
    }
  }
  for (const value of values) {
    const previous = map.get(value.id);
    if (!previous || JSON.stringify(previous) !== JSON.stringify(value)) {
      map.set(value.id, value);
    }
  }
}

function isSafeRemoteDiagramUpdate(document: Y.Doc, update: Uint8Array) {
  const probe = new Y.Doc();
  try {
    Y.applyUpdate(probe, Y.encodeStateAsUpdate(document));
    Y.applyUpdate(probe, update);
    const nodes = Array.from(probe.getMap<unknown>(NODES_MAP).values());
    const edges = Array.from(probe.getMap<unknown>(EDGES_MAP).values());
    return isDiagramGraphState(nodes, edges);
  } catch {
    return false;
  } finally {
    probe.destroy();
  }
}

function cacheDiagramState(boardKey: string, update: Uint8Array) {
  if (update.length * 4 / 3 > MAX_DIAGRAM_UPDATE_BASE64_LENGTH) {
    return;
  }
  diagramStateCache.delete(boardKey);
  diagramStateCache.set(boardKey, update);
  while (diagramStateCache.size > DIAGRAM_CACHE_LIMIT) {
    const oldestKey = diagramStateCache.keys().next().value;
    if (typeof oldestKey !== "string") {
      break;
    }
    diagramStateCache.delete(oldestKey);
  }
}

function updateSelection(graph: Graph, update: (selection: DiagramSelection) => void) {
  const cells = graph.getSelectionCells();
  if (cells.length === 0) {
    update(EMPTY_SELECTION);
    return;
  }
  const first = cells[0];
  const style = first.getStyle();
  update({
    ids: cells.map((cell) => cell.getId()).filter((id): id is string => Boolean(id)),
    label: cells.length === 1 ? String(first.getValue() ?? "") : "",
    isNode: cells.some((cell) => cell.isVertex()),
    isEdge: cells.some((cell) => cell.isEdge()),
    fillColor: styleColor(style.fillColor, "#ffffff"),
    strokeColor: styleColor(style.strokeColor, "#475569"),
    dashed: Boolean(style.dashed),
    strokeWidth: styleNumber(style.strokeWidth, 2),
  });
}

function nodeCellStyle(node: DiagramNode): DiagramCellStyle {
  const base: DiagramCellStyle = {
    diagramKind: node.kind,
    shape: nodeShape(node.kind),
    rounded: node.kind === "process",
    arcSize: 14,
    whiteSpace: "wrap",
    overflow: "fill",
    align: "center",
    verticalAlign: "middle",
    spacing: 8,
    fontSize: 13,
    fontStyle: 1,
    fillColor: node.style.fillColor,
    strokeColor: node.style.strokeColor,
    fontColor: node.style.fontColor,
    strokeWidth: node.style.strokeWidth,
    dashed: Boolean(node.style.dashed),
    shadow: true,
  };
  if (node.kind === "note") {
    base.align = "left";
    base.verticalAlign = "top";
    base.fontStyle = 0;
  }
  return base;
}

function edgeCellStyle(edge: DiagramEdge): CellStyle {
  const source = portCoordinates(edge.sourcePort);
  const target = portCoordinates(edge.targetPort);
  return {
    edgeStyle: "orthogonalEdgeStyle",
    rounded: true,
    orthogonalLoop: true,
    jettySize: "auto",
    endArrow: "blockThin",
    endFill: true,
    strokeColor: edge.style.strokeColor,
    fontColor: edge.style.fontColor,
    strokeWidth: edge.style.strokeWidth,
    dashed: Boolean(edge.style.dashed),
    labelBackgroundColor: "#ffffff",
    exitX: source?.x,
    exitY: source?.y,
    exitPerimeter: true,
    entryX: target?.x,
    entryY: target?.y,
    entryPerimeter: true,
  };
}

function nodeDefaults(kind: DiagramNodeKind): { label: string; width: number; height: number; style: DiagramNodeStyle } {
  const common = { fontColor: "#172033", strokeWidth: 2 };
  if (kind === "start") {
    return { label: "开始", width: 120, height: 52, style: { ...common, fillColor: "#dcfce7", strokeColor: "#16a34a" } };
  }
  if (kind === "end") {
    return { label: "结束", width: 120, height: 52, style: { ...common, fillColor: "#fee2e2", strokeColor: "#dc2626" } };
  }
  if (kind === "decision") {
    return { label: "判断条件", width: 150, height: 92, style: { ...common, fillColor: "#fef3c7", strokeColor: "#d97706" } };
  }
  if (kind === "database") {
    return { label: "数据库", width: 142, height: 88, style: { ...common, fillColor: "#ede9fe", strokeColor: "#7c3aed" } };
  }
  if (kind === "document") {
    return { label: "文档", width: 150, height: 82, style: { ...common, fillColor: "#dbeafe", strokeColor: "#2563eb" } };
  }
  if (kind === "actor") {
    return { label: "参与者", width: 112, height: 92, style: { ...common, fillColor: "#fce7f3", strokeColor: "#db2777" } };
  }
  if (kind === "note") {
    return { label: "补充说明", width: 170, height: 96, style: { ...common, fillColor: "#fef9c3", strokeColor: "#ca8a04" } };
  }
  return { label: "处理步骤", width: 160, height: 72, style: { ...common, fillColor: "#dbeafe", strokeColor: "#2563eb" } };
}

function defaultEdgeStyle(): DiagramEdgeStyle {
  return { strokeColor: "#64748b", fontColor: "#334155", strokeWidth: 2 };
}

function nodeShape(kind: DiagramNodeKind) {
  if (kind === "start" || kind === "end") return "ellipse";
  if (kind === "decision") return "rhombus";
  if (kind === "document") return "document";
  if (kind === "database") return "cylinder";
  if (kind === "actor") return "actor";
  if (kind === "note") return "note";
  return "rectangle";
}

function portCoordinates(port?: DiagramPort) {
  if (port === "north") return { x: 0.5, y: 0 };
  if (port === "east") return { x: 1, y: 0.5 };
  if (port === "south") return { x: 0.5, y: 1 };
  if (port === "west") return { x: 0, y: 0.5 };
  return undefined;
}

function constraintForPort(port?: DiagramPort) {
  return PORT_CONSTRAINTS.find((constraint) => constraint.name === port) ?? null;
}

function portFromStyle(style: CellStyle, source: boolean): DiagramPort | undefined {
  const x = styleNumber(source ? style.exitX : style.entryX, Number.NaN);
  const y = styleNumber(source ? style.exitY : style.entryY, Number.NaN);
  if (!Number.isFinite(x) || !Number.isFinite(y)) {
    return undefined;
  }
  if (y <= 0.05) return "north";
  if (x >= 0.95) return "east";
  if (y >= 0.95) return "south";
  if (x <= 0.05) return "west";
  return undefined;
}

function styleColor(value: unknown, fallback: string) {
  return typeof value === "string" && /^#[0-9a-fA-F]{6}$/.test(value) ? value : fallback;
}

function styleNumber(value: unknown, fallback: number) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function isDiagramNodeKind(value: unknown): value is DiagramNodeKind {
  return NODE_PALETTE.some((item) => item.kind === value);
}

function cloneNode(node: DiagramNode): DiagramNode {
  return { ...node, style: { ...node.style } };
}

function cloneEdge(edge: DiagramEdge): DiagramEdge {
  return { ...edge, style: { ...edge.style } };
}

function createDiagramId(peerId: string, kind: string) {
  return `${peerId}-${kind}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
}

function diagramExportFileName(date: Date) {
  const timestamp = date.toISOString().replace(/\D/g, "").slice(0, 14);
  return `shuai-tunnel-diagram-${timestamp}${DIAGRAM_FILE_EXTENSION}`;
}

function DiagramToolbarButton({
  label,
  shortcut,
  danger = false,
  disabled = false,
  onClick,
}: {
  label: string;
  shortcut?: string;
  danger?: boolean;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      title={shortcut ? `${label} (${shortcut})` : label}
      className={`flex h-9 shrink-0 items-center gap-1 rounded-md px-2.5 text-tiny font-medium transition disabled:cursor-not-allowed disabled:opacity-35 ${danger
        ? "text-red-600 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-400/10"
        : "text-zinc-700 hover:bg-cyan-50 hover:text-cyan-900 dark:text-zinc-200 dark:hover:bg-cyan-300/10 dark:hover:text-cyan-100"}`}
      onClick={onClick}
    >
      {label}
      {shortcut ? <span className="hidden text-[9px] text-zinc-400 xl:inline">{shortcut}</span> : null}
    </button>
  );
}

function DiagramNodeGlyph({ kind }: { kind: DiagramNodeKind }) {
  const shapeClass = kind === "start" || kind === "end" ? "rounded-full"
    : kind === "decision" ? "rotate-45 rounded-sm"
      : kind === "database" ? "rounded-[50%/20%]"
        : kind === "note" ? "rounded-sm rounded-tr-xl"
          : "rounded-md";
  return (
    <span className={`flex h-7 w-9 shrink-0 items-center justify-center border-2 border-cyan-600 bg-cyan-50 dark:border-cyan-300 dark:bg-cyan-300/10 ${shapeClass}`}>
      {kind === "actor" ? <span className="h-3 w-3 rounded-full border border-current" /> : null}
    </span>
  );
}

function ColorPicker({
  label,
  colors,
  selected,
  onSelect,
}: {
  label: string;
  colors: string[];
  selected?: string;
  onSelect: (color: string) => void;
}) {
  return (
    <div>
      <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-400">{label}</span>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {colors.map((color) => (
          <button
            key={color}
            type="button"
            aria-label={`${label} ${color}`}
            aria-pressed={selected?.toLowerCase() === color.toLowerCase()}
            className={`h-7 w-7 rounded-full border shadow-sm transition ${selected?.toLowerCase() === color.toLowerCase()
              ? "scale-110 border-cyan-500 ring-2 ring-cyan-400/40"
              : "border-black/15 dark:border-white/20"}`}
            style={{ backgroundColor: color }}
            onClick={() => onSelect(color)}
          />
        ))}
      </div>
    </div>
  );
}

function InspectorAction({
  label,
  disabled = false,
  onClick,
}: {
  label: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      className="rounded-md border border-black/10 px-2 py-1.5 text-tiny text-zinc-600 hover:border-cyan-400 hover:text-cyan-800 disabled:opacity-35 dark:border-white/10 dark:text-zinc-300 dark:hover:text-cyan-200"
      onClick={onClick}
    >
      {label}
    </button>
  );
}
