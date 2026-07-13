import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";
import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
} from "@heroui/react";
import {
  Cell,
  Clipboard,
  ConnectionConstraint,
  Graph,
  gestureUtils,
  HierarchicalLayout,
  ImageExport,
  EdgeHandlerConfig,
  HandleConfig,
  InternalEvent,
  Outline,
  Point,
  SelectionHandler,
  StyleDefaultsConfig,
  SvgCanvas2D,
  VertexHandlerConfig,
} from "@maxgraph/core";
import type { CellStyle, FitPlugin } from "@maxgraph/core";
import * as Y from "yjs";
import "@maxgraph/core/css/common.css";
import {
  publicCreateTransferDiagramVersion,
  publicDeleteTransferDiagramVersion,
  publicGetTransferDiagramVersion,
  publicListTransferDiagramVersions,
} from "../api/client";
import type { PublicTransferDiagramVersion, PublicTransferRoomRole } from "../api/types";
import type { WhiteboardInboundEvent } from "./SyncedWhiteboard";
import {
  createDiagramDocument,
  decodeDiagramUpdate,
  DIAGRAM_FILE_EXTENSION,
  DIAGRAM_FILE_MIME,
  encodeDiagramUpdate,
  isDiagramComment,
  isDiagramGraphState,
  isDiagramPage,
  MAX_DIAGRAM_DOCUMENT_BYTES,
  MAX_DIAGRAM_NODES,
  MAX_DIAGRAM_PAGES,
  MAX_DIAGRAM_UPDATE_BASE64_LENGTH,
  parseDiagramDocument,
} from "../lib/diagramDocument";
import type {
  DiagramDocumentV1,
  DiagramArrowType,
  DiagramComment,
  DiagramEdge,
  DiagramEdgeStyle,
  DiagramEdgeType,
  DiagramNode,
  DiagramNodeKind,
  DiagramNodeStyle,
  DiagramPayload,
  DiagramPage,
  DiagramPort,
} from "../lib/diagramDocument";
import {
  DRAWIO_FILE_EXTENSION,
  DRAWIO_FILE_MIME,
  exportDrawioDocument,
  parseDrawioDocument,
} from "../lib/diagramDrawio";
import {
  exportMermaidDocument,
  exportPlantUmlDocument,
  MERMAID_FILE_EXTENSIONS,
  parseMermaidDocument,
  parsePlantUmlDocument,
  PLANTUML_FILE_EXTENSIONS,
} from "../lib/diagramTextFormats";
import {
  exportVisioVdx,
  parseVisioVdx,
  parseVisioVsdx,
  VISIO_VDX_FILE_EXTENSION,
  VISIO_VDX_MIME,
  VISIO_VSDX_FILE_EXTENSION,
} from "../lib/diagramVisio";
import {
  loadDrawioStencilCatalog,
  loadDrawioStencilLibrary,
  renderDrawioStencilPreview,
} from "../lib/drawioStencilCatalog";
import type {
  DrawioStencilCatalog,
  DrawioStencilLibrary,
  DrawioStencilShape,
} from "../lib/drawioStencilCatalog";
import { useTheme } from "../theme/ThemeContext";

VertexHandlerConfig.selectionColor = "#06b6d4";
VertexHandlerConfig.selectionDashed = false;
VertexHandlerConfig.selectionStrokeWidth = 1.5;
EdgeHandlerConfig.selectionColor = "#06b6d4";
EdgeHandlerConfig.selectionDashed = false;
EdgeHandlerConfig.selectionStrokeWidth = 2;
HandleConfig.size = 7;
HandleConfig.fillColor = "#ffffff";
HandleConfig.strokeColor = "#0891b2";
HandleConfig.labelFillColor = "#22d3ee";
StyleDefaultsConfig.shadowColor = "#0f172a";
StyleDefaultsConfig.shadowOpacity = 0.16;
StyleDefaultsConfig.shadowOffsetX = 0;
StyleDefaultsConfig.shadowOffsetY = 4;

interface SyncedDiagramProps {
  boardKey: string;
  roomId: string;
  roomToken: string;
  roomRole: PublicTransferRoomRole;
  peerId: string;
  peerCount: number;
  isConnected: boolean;
  isActive?: boolean;
  events: WhiteboardInboundEvent[];
  onSend: (payload: DiagramPayload) => void;
  onSwitchToWhiteboard?: () => void;
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
  edgeType?: DiagramEdgeType;
  startArrow?: DiagramArrowType;
  endArrow?: DiagramArrowType;
  fontSize?: number;
  bold?: boolean;
  italic?: boolean;
  align?: "left" | "center" | "right";
  locked?: boolean;
  rotation?: number;
  isSwimlane?: boolean;
  isLane?: boolean;
  swimlaneDirection?: "horizontal" | "vertical";
  opacity?: number;
  shadow?: boolean;
  rounded?: boolean;
}

interface DiagramContextMenu {
  x: number;
  y: number;
}

interface RemoteDiagramPresence {
  peerId: string;
  pageId: string;
  selectedIds: string[];
  cursor?: { x: number; y: number };
  updatedAt: number;
}

interface DiagramVersionSnapshot {
  id: string;
  serverId?: number;
  name: string;
  createdAt: number;
  update?: Uint8Array;
  authorPeerId?: string;
  sizeBytes?: number;
}

type DiagramCellStyle = CellStyle & {
  diagramKind?: DiagramNodeKind;
  diagramStencilName?: string;
  diagramStencilLibrary?: string;
  connectable?: boolean;
  collapsible?: boolean;
  recursiveResize?: boolean;
  diagramLocked?: boolean;
};

const GRAPH_ORIGIN = Symbol("diagram-graph");
const IMPORT_ORIGIN = Symbol("diagram-import");
const REMOTE_ORIGIN = Symbol("diagram-remote");
const DIAGRAM_CACHE_LIMIT = 8;
const NODES_MAP = "nodes";
const EDGES_MAP = "edges";
const PAGES_MAP = "pages";
const COMMENTS_MAP = "comments";
const DEFAULT_PAGE_ID = "page-1";
const DIAGRAM_CANVAS = { width: 2_400, height: 1_600, gridSize: 10 };
const MAX_DRAWIO_DOCUMENT_BYTES = 8 * 1024 * 1024;
const STENCIL_PAGE_SIZE = 180;
const STENCIL_SEARCH_LIMIT = 240;
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

const PALETTE_CATEGORIES = ["通用图形", "流程图", "BPMN", "UML", "ER 图", "网络与架构", "容器与泳道"] as const;
type PaletteCategory = typeof PALETTE_CATEGORIES[number];

const NODE_PALETTE: Array<{ kind: DiagramNodeKind; label: string; detail: string; category: PaletteCategory }> = [
  { kind: "rectangle", label: "矩形", detail: "通用容器", category: "通用图形" },
  { kind: "roundedRectangle", label: "圆角矩形", detail: "通用卡片", category: "通用图形" },
  { kind: "ellipse", label: "椭圆", detail: "通用图形", category: "通用图形" },
  { kind: "circle", label: "圆形", detail: "通用图形", category: "通用图形" },
  { kind: "diamond", label: "菱形", detail: "关系判断", category: "通用图形" },
  { kind: "triangle", label: "三角形", detail: "方向标识", category: "通用图形" },
  { kind: "hexagon", label: "六边形", detail: "准备步骤", category: "通用图形" },
  { kind: "text", label: "文本", detail: "无边框文字", category: "通用图形" },
  { kind: "note", label: "便签", detail: "补充说明", category: "通用图形" },

  { kind: "start", label: "开始", detail: "流程起点", category: "流程图" },
  { kind: "process", label: "处理", detail: "业务步骤", category: "流程图" },
  { kind: "decision", label: "判断", detail: "条件分支", category: "流程图" },
  { kind: "end", label: "结束", detail: "流程终点", category: "流程图" },
  { kind: "document", label: "文档", detail: "文档输出", category: "流程图" },
  { kind: "database", label: "数据存储", detail: "数据库", category: "流程图" },
  { kind: "data", label: "输入输出", detail: "数据输入", category: "流程图" },
  { kind: "subprocess", label: "子流程", detail: "预定义过程", category: "流程图" },
  { kind: "delay", label: "延迟", detail: "等待节点", category: "流程图" },
  { kind: "manualInput", label: "手动输入", detail: "人工录入", category: "流程图" },
  { kind: "connector", label: "连接符", detail: "页内连接", category: "流程图" },

  { kind: "bpmnTask", label: "任务", detail: "BPMN Task", category: "BPMN" },
  { kind: "bpmnEvent", label: "事件", detail: "中间事件", category: "BPMN" },
  { kind: "bpmnGateway", label: "网关", detail: "并行或排他", category: "BPMN" },
  { kind: "bpmnDataObject", label: "数据对象", detail: "业务数据", category: "BPMN" },

  { kind: "actor", label: "参与者", detail: "角色或用户", category: "UML" },
  { kind: "umlUseCase", label: "用例", detail: "Use Case", category: "UML" },
  { kind: "umlClass", label: "类", detail: "属性与方法", category: "UML" },
  { kind: "umlInterface", label: "接口", detail: "Interface", category: "UML" },
  { kind: "umlPackage", label: "包", detail: "Package", category: "UML" },
  { kind: "umlComponent", label: "组件", detail: "Component", category: "UML" },

  { kind: "entity", label: "实体", detail: "数据实体", category: "ER 图" },
  { kind: "erRelationship", label: "关系", detail: "实体关系", category: "ER 图" },
  { kind: "erAttribute", label: "属性", detail: "实体属性", category: "ER 图" },

  { kind: "server", label: "服务器", detail: "计算节点", category: "网络与架构" },
  { kind: "client", label: "客户端", detail: "终端设备", category: "网络与架构" },
  { kind: "router", label: "路由器", detail: "网络路由", category: "网络与架构" },
  { kind: "firewall", label: "防火墙", detail: "安全边界", category: "网络与架构" },
  { kind: "cloud", label: "云服务", detail: "外部系统", category: "网络与架构" },
  { kind: "queue", label: "消息队列", detail: "异步通道", category: "网络与架构" },
  { kind: "service", label: "服务", detail: "应用服务", category: "网络与架构" },

  { kind: "container", label: "容器", detail: "分组区域", category: "容器与泳道" },
  { kind: "swimlane", label: "泳池", detail: "职责分区", category: "容器与泳道" },
];

interface StencilPaletteItem {
  id: string;
  kind: "rectangle";
  label: string;
  detail: string;
  stencilName: string;
  stencilLibrary: string;
  width: number;
  height: number;
}

type DraggablePaletteItem = (typeof NODE_PALETTE)[number] | StencilPaletteItem;

interface StencilCollectionItem {
  library: DrawioStencilLibrary;
  shape: DrawioStencilShape;
}

interface StencilCollection {
  id: string;
  name: string;
  group: string;
  libraryCount: number;
  shapeCount: number;
  items: StencilCollectionItem[];
}

const STENCIL_COLLECTION_RULES: Array<{ id: string; name: string; pattern: RegExp }> = [
  { id: "aws", name: "AWS", pattern: /^aws(?:\/|2\/|3$|3d$|4$)/ },
  { id: "gcp", name: "Google Cloud", pattern: /^gcp(?:\/|2$|3$)/ },
  { id: "kubernetes", name: "Kubernetes", pattern: /^kubernetes2?$/ },
  { id: "cisco", name: "Cisco", pattern: /^cisco(?:\/|19$|_safe\/)/ },
  { id: "citrix", name: "Citrix", pattern: /^citrix2?$/ },
  { id: "networks", name: "网络设备", pattern: /^networks2?$/ },
  { id: "rack", name: "机架设备", pattern: /^rack\// },
  { id: "office", name: "Microsoft Office", pattern: /^office\// },
  { id: "mscae", name: "Microsoft Cloud Architecture", pattern: /^mscae\// },
  { id: "veeam", name: "Veeam", pattern: /^veeam\// },
  { id: "electrical", name: "电气工程", pattern: /^electrical\// },
  { id: "pid", name: "P&ID", pattern: /^pid\// },
  { id: "mockup", name: "界面原型", pattern: /^mockup\// },
  { id: "ios", name: "iOS", pattern: /^ios7\// },
  { id: "android", name: "Android", pattern: /^android\// },
  { id: "signs", name: "标志与符号", pattern: /^signs\// },
  { id: "web", name: "Web 图标与 Logo", pattern: /^web(?:icons|logos)$/ },
];

const FILL_COLORS = ["#ffffff", "#eff6ff", "#ecfdf5", "#fffbeb", "#fdf2f8", "#f5f3ff"];
const STROKE_COLORS = ["#64748b", "#3b82f6", "#10b981", "#f59e0b", "#ec4899", "#8b5cf6"];
const diagramStateCache = new Map<string, Uint8Array>();

export function SyncedDiagram({
  boardKey,
  roomId,
  roomToken,
  roomRole,
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
  const outlineContainerRef = useRef<HTMLDivElement | null>(null);
  const paletteElementRefs = useRef(new Map<string, HTMLButtonElement>());
  const draggablePaletteItemsRef = useRef(new Map<string, DraggablePaletteItem>());
  const stencilLibrariesByPathRef = useRef(new Map<string, DrawioStencilLibrary>());
  const loadedStencilLibrariesRef = useRef(new Set<string>());
  const importInputRef = useRef<HTMLInputElement | null>(null);
  const runtimeRef = useRef<DiagramRuntime | null>(null);
  const outlineRef = useRef<Outline | null>(null);
  const formatStyleRef = useRef<{ vertex: boolean; style: CellStyle } | null>(null);
  const lastPresenceSentRef = useRef(0);
  const yDocRef = useRef<Y.Doc | null>(null);
  const nodesMapRef = useRef<Y.Map<DiagramNode> | null>(null);
  const edgesMapRef = useRef<Y.Map<DiagramEdge> | null>(null);
  const pagesMapRef = useRef<Y.Map<DiagramPage> | null>(null);
  const commentsMapRef = useRef<Y.Map<DiagramComment> | null>(null);
  const versionsRef = useRef<DiagramVersionSnapshot[]>([]);
  const undoManagerRef = useRef<Y.UndoManager | null>(null);
  const renderGraphRef = useRef<() => void>(() => undefined);
  const flushGraphRef = useRef<() => void>(() => undefined);
  const graphSyncTimerRef = useRef<number | null>(null);
  const graphRenderFrameRef = useRef<number | null>(null);
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
  const [pages, setPages] = useState<DiagramPage[]>([{ id: DEFAULT_PAGE_ID, name: "页面 1", order: 0 }]);
  const [activePageId, setActivePageId] = useState(DEFAULT_PAGE_ID);
  const [canUndo, setCanUndo] = useState(false);
  const [canRedo, setCanRedo] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [showMinimap, setShowMinimap] = useState(true);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [openPaletteCategories, setOpenPaletteCategories] = useState<Set<PaletteCategory>>(
    () => new Set(["通用图形", "流程图"]),
  );
  const [stencilCatalog, setStencilCatalog] = useState<DrawioStencilCatalog | null>(null);
  const [openStencilGroups, setOpenStencilGroups] = useState<Set<string>>(() => new Set(["general"]));
  const [activeStencilCollectionId, setActiveStencilCollectionId] = useState<string | null>(null);
  const [stencilShapeLimit, setStencilShapeLimit] = useState(STENCIL_PAGE_SIZE);
  const [loadedStencilLibraries, setLoadedStencilLibraries] = useState<Set<string>>(() => new Set());
  const [loadingStencilCollection, setLoadingStencilCollection] = useState<string | null>(null);
  const [compactPanel, setCompactPanel] = useState<"library" | "inspector" | null>(null);
  const [hasCopiedFormat, setHasCopiedFormat] = useState(false);
  const [remotePresences, setRemotePresences] = useState<Record<string, RemoteDiagramPresence>>({});
  const [comments, setComments] = useState<DiagramComment[]>([]);
  const [versions, setVersions] = useState<DiagramVersionSnapshot[]>([]);
  const [localReadOnly, setLocalReadOnly] = useState(false);
  const [isVersionLoading, setIsVersionLoading] = useState(false);
  const [contextMenu, setContextMenu] = useState<DiagramContextMenu | null>(null);
  const [status, setStatus] = useState("专业流程图已就绪，从左侧插入节点后拖动蓝色端口连线。");
  const usesServerVersions = Boolean(roomToken.trim());
  const isRoleReadOnly = roomRole === "VIEWER";
  const isReadOnly = isRoleReadOnly || localReadOnly;

  const stencilSearchResults = useMemo(() => {
    const query = paletteQuery.trim().toLowerCase();
    if (!query || !stencilCatalog) return [];
    const matches: Array<{ library: DrawioStencilLibrary; shape: DrawioStencilShape }> = [];
    for (const library of stencilCatalog.libraries) {
      const libraryMatches = `${library.name} ${library.id}`.toLowerCase().includes(query);
      for (const shape of library.shapes) {
        if (libraryMatches || `${shape.name} ${shape.shape}`.toLowerCase().includes(query)) {
          matches.push({ library, shape });
          if (matches.length >= STENCIL_SEARCH_LIMIT) return matches;
        }
      }
    }
    return matches;
  }, [paletteQuery, stencilCatalog]);

  const stencilCollections = useMemo(
    () => stencilCatalog ? buildStencilCollections(stencilCatalog) : [],
    [stencilCatalog],
  );

  useEffect(() => {
    let active = true;
    void loadDrawioStencilCatalog()
      .then((catalog) => {
        if (!active) return;
        stencilLibrariesByPathRef.current = new Map(catalog.libraries.map((library) => [library.path, library]));
        setStencilCatalog(catalog);
        scheduleDocumentRender();
      })
      .catch((error) => {
        if (active) setStatus(error instanceof Error ? error.message : "draw.io 图形库加载失败");
      });
    return () => {
      active = false;
    };
  }, []);

  const ensureStencilLibraryLoaded = useCallback(async (library: DrawioStencilLibrary) => {
    if (loadedStencilLibrariesRef.current.has(library.path)) return;
    await loadDrawioStencilLibrary(library);
    loadedStencilLibrariesRef.current.add(library.path);
    setLoadedStencilLibraries((current) => {
      if (current.has(library.path)) return current;
      const next = new Set(current);
      next.add(library.path);
      return next;
    });
  }, []);

  const openStencilCollection = useCallback((collection: StencilCollection) => {
    setStencilShapeLimit(STENCIL_PAGE_SIZE);
    setActiveStencilCollectionId((current) => current === collection.id ? null : collection.id);
  }, []);

  useEffect(() => {
    const collection = stencilCollections.find((candidate) => candidate.id === activeStencilCollectionId);
    if (!collection) return;
    const visibleLibraries = Array.from(new Map(
      collection.items
        .slice(0, stencilShapeLimit)
        .map(({ library }) => [library.path, library]),
    ).values()).filter((library) => !loadedStencilLibrariesRef.current.has(library.path));
    if (!visibleLibraries.length) {
      setLoadingStencilCollection((current) => current === collection.id ? null : current);
      return;
    }
    let active = true;
    setLoadingStencilCollection(collection.id);
    void Promise.all(visibleLibraries.map(ensureStencilLibraryLoaded))
      .then(() => {
        if (active) setRuntimeEpoch((value) => value + 1);
      })
      .catch((error) => {
        if (active) setStatus(error instanceof Error ? error.message : `${collection.name} 加载失败`);
      })
      .finally(() => {
        if (active) setLoadingStencilCollection((current) => current === collection.id ? null : current);
      });
    return () => {
      active = false;
    };
  }, [activeStencilCollectionId, ensureStencilLibraryLoaded, stencilCollections, stencilShapeLimit]);

  useEffect(() => {
    if (!paletteQuery.trim() || !stencilSearchResults.length) return;
    const matchingLibraries = Array.from(new Map(
      stencilSearchResults.map(({ library }) => [library.path, library]),
    ).values()).filter((library) => !loadedStencilLibrariesRef.current.has(library.path));
    if (!matchingLibraries.length) return;
    let active = true;
    void Promise.all(matchingLibraries.map(ensureStencilLibraryLoaded))
      .then(() => {
        if (active) setRuntimeEpoch((value) => value + 1);
      })
      .catch((error) => {
        if (active) setStatus(error instanceof Error ? error.message : "搜索图形加载失败");
      });
    return () => {
      active = false;
    };
  }, [ensureStencilLibraryLoaded, paletteQuery, stencilSearchResults]);

  const refreshUndoState = useCallback(() => {
    const manager = undoManagerRef.current;
    setCanUndo(Boolean(manager?.canUndo()));
    setCanRedo(Boolean(manager?.canRedo()));
  }, []);

  const scheduleDocumentRender = useCallback(() => {
    if (graphRenderFrameRef.current !== null) return;
    graphRenderFrameRef.current = window.requestAnimationFrame(() => {
      graphRenderFrameRef.current = null;
      renderGraphRef.current();
    });
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

  const sendPresence = useCallback((cursor?: { x: number; y: number }, force = false) => {
    const now = Date.now();
    if (!force && now - lastPresenceSentRef.current < 80) return;
    lastPresenceSentRef.current = now;
    const graph = runtimeRef.current?.graph;
    onSendRef.current({
      type: "STDG1",
      kind: "diagram-presence",
      pageId: activePageId,
      selectedIds: graph?.getSelectionCells().map((cell) => cell.getId()).filter((id): id is string => Boolean(id)).slice(0, 100) ?? [],
      ...(cursor ? { cursor } : {}),
      createdAt: now,
    });
  }, [activePageId]);

  useEffect(() => {
    const document = new Y.Doc();
    const nodes = document.getMap<DiagramNode>(NODES_MAP);
    const edges = document.getMap<DiagramEdge>(EDGES_MAP);
    const pageMap = document.getMap<DiagramPage>(PAGES_MAP);
    const commentsMap = document.getMap<DiagramComment>(COMMENTS_MAP);
    const undoManager = new Y.UndoManager([nodes, edges, pageMap, commentsMap], {
      captureTimeout: 420,
      trackedOrigins: new Set([GRAPH_ORIGIN, IMPORT_ORIGIN]),
    });
    yDocRef.current = document;
    nodesMapRef.current = nodes;
    edgesMapRef.current = edges;
    pagesMapRef.current = pageMap;
    commentsMapRef.current = commentsMap;
    undoManagerRef.current = undoManager;
    seenEventsRef.current.clear();
    lastPeerCountRef.current = 0;
    setSelection(EMPTY_SELECTION);
    setNodeCount(0);
    setEdgeCount(0);
    setPages([{ id: DEFAULT_PAGE_ID, name: "页面 1", order: 0 }]);
    setActivePageId(DEFAULT_PAGE_ID);
    setComments([]);
    versionsRef.current = [];
    setVersions([]);
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
    if (pageMap.size === 0) {
      pageMap.set(DEFAULT_PAGE_ID, { id: DEFAULT_PAGE_ID, name: "页面 1", order: 0 });
    }
    const refreshPages = () => {
      const nextPages = Array.from(pageMap.values()).sort((left, right) => left.order - right.order);
      setPages(nextPages);
      setComments(Array.from(commentsMap.values()).filter(isDiagramComment).sort((a, b) => a.createdAt - b.createdAt));
      setActivePageId((current) => nextPages.some((page) => page.id === current) ? current : nextPages[0]?.id ?? DEFAULT_PAGE_ID);
    };
    refreshPages();
    setStatus(restoredFromCache ? "已恢复当前房间的本地流程图。" : "已切换到新的房间流程图。");

    const handleUpdate = (update: Uint8Array, origin: unknown) => {
      refreshPages();
      if (origin === REMOTE_ORIGIN) {
        scheduleDocumentRender();
        refreshUndoState();
        return;
      }
      if (origin !== GRAPH_ORIGIN) {
        scheduleDocumentRender();
      }
      sendYUpdate(update);
      refreshUndoState();
    };
    document.on("update", handleUpdate);
    setDocumentEpoch((value) => value + 1);

    return () => {
      if (graphRenderFrameRef.current !== null) {
        window.cancelAnimationFrame(graphRenderFrameRef.current);
        graphRenderFrameRef.current = null;
      }
      cacheDiagramState(boardKey, Y.encodeStateAsUpdate(document));
      document.off("update", handleUpdate);
      undoManager.destroy();
      document.destroy();
      if (yDocRef.current === document) {
        yDocRef.current = null;
        nodesMapRef.current = null;
        edgesMapRef.current = null;
        pagesMapRef.current = null;
        commentsMapRef.current = null;
        undoManagerRef.current = null;
      }
    };
  }, [boardKey, refreshUndoState, scheduleDocumentRender, sendYUpdate]);

  useEffect(() => {
    if (!usesServerVersions) return;
    let active = true;
    setIsVersionLoading(true);
    publicListTransferDiagramVersions(roomId, { roomToken, peerId })
      .then((items) => {
        if (!active) return;
        const snapshots = items.slice().reverse().map(toDiagramVersionSnapshot);
        versionsRef.current = snapshots;
        setVersions(snapshots);
      })
      .catch((error) => {
        if (active) setStatus(error instanceof Error ? error.message : "加载流程图版本失败");
      })
      .finally(() => {
        if (active) setIsVersionLoading(false);
      });
    return () => {
      active = false;
    };
  }, [peerId, roomId, roomToken, usesServerVersions]);

  useEffect(() => {
    const container = graphContainerRef.current;
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    if (!container || !nodes || !edges) {
      return;
    }

    const graph = new Graph(container);
    graph.getDataModel().prefix = `${peerId}-${Math.random().toString(36).slice(2, 9)}-auto-`;
    graph.setConnectable(!isReadOnly);
    graph.setAllowDanglingEdges(false);
    graph.setConnectableEdges(false);
    graph.setMultigraph(false);
    graph.setPanning(true);
    graph.setTooltips(true);
    graph.setGridEnabled(true);
    graph.setGridSize(DIAGRAM_CANVAS.gridSize);
    graph.setCellsEditable(!isReadOnly);
    graph.setCellsResizable(!isReadOnly);
    graph.setCellsBendable(true);
    graph.setDropEnabled(!isReadOnly);
    graph.setSwimlaneNesting(true);
    graph.setExtendParentsOnMove(true);
    graph.setHtmlLabels(false);
    graph.setAllowNegativeCoordinates(false);
    graph.centerZoom = true;
    graph.keepSelectionVisibleOnZoom = true;
    const selectionHandler = graph.getPlugin<SelectionHandler>(SelectionHandler.pluginId);
    if (selectionHandler) {
      selectionHandler.guidesEnabled = true;
    }
    graph.getAllConnectionConstraints = (terminal) => (
      terminal?.cell.isVertex() ? PORT_CONSTRAINTS : null
    );
    const defaultIsValidDropTarget = graph.isValidDropTarget.bind(graph);
    graph.isValidDropTarget = (cell, cells, event) => {
      const kind = (cell.getStyle() as DiagramCellStyle).diagramKind;
      return kind === "container" || kind === "swimlane" || kind === "lane" || defaultIsValidDropTarget(cell, cells, event);
    };
    const defaultIsCellMovable = graph.isCellMovable.bind(graph);
    const defaultIsCellResizable = graph.isCellResizable.bind(graph);
    const defaultIsCellEditable = graph.isCellEditable.bind(graph);
    graph.isCellMovable = (cell) => !isReadOnly && !(cell.getStyle() as DiagramCellStyle).diagramLocked && defaultIsCellMovable(cell);
    graph.isCellResizable = (cell) => !isReadOnly && !(cell.getStyle() as DiagramCellStyle).diagramLocked && defaultIsCellResizable(cell);
    graph.isCellEditable = (cell) => !isReadOnly && !(cell.getStyle() as DiagramCellStyle).diagramLocked && defaultIsCellEditable(cell);

    const readGraph = () => readGraphDocument(graph, activePageId);
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
        replaceYMapForPage(currentNodes, snapshot.nodes, activePageId);
        replaceYMapForPage(currentEdges, snapshot.edges, activePageId);
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
      const missingStencilPaths = new Set(
        Array.from(currentNodes.values())
          .map((node) => node.stencilLibrary)
          .filter((path): path is string => typeof path === "string" && !loadedStencilLibrariesRef.current.has(path)),
      );
      for (const path of missingStencilPaths) {
        const library = stencilLibrariesByPathRef.current.get(path);
        if (library) {
          void ensureStencilLibraryLoaded(library)
            .then(scheduleDocumentRender)
            .catch((error) => setStatus(error instanceof Error ? error.message : `${library.name} 加载失败`));
        }
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
          const nextNodes = Array.from(currentNodes.values())
            .filter((node) => diagramPageId(node.pageId) === activePageId)
            .sort((a, b) => a.zIndex - b.zIndex);
          const optimizeLargeGraph = nextNodes.length >= 400;
          let pendingNodes = [...nextNodes];
          while (pendingNodes.length > 0) {
            const remaining: DiagramNode[] = [];
            for (const node of pendingNodes) {
              const nodeParent = node.parentId ? cells.get(node.parentId) : parent;
              if (!nodeParent) {
                remaining.push(node);
                continue;
              }
              const cell = graph.insertVertex({
                parent: nodeParent,
                id: node.id,
                value: node.label,
                position: [node.x, node.y],
                size: [node.width, node.height],
                style: nodeCellStyle(node, optimizeLargeGraph),
              });
              cell.setConnectable(node.kind !== "container" && node.kind !== "swimlane" && node.kind !== "lane");
              cells.set(node.id, cell);
            }
            if (remaining.length === pendingNodes.length) {
              break;
            }
            pendingNodes = remaining;
          }
          const nextEdges = Array.from(currentEdges.values())
            .filter((edge) => diagramPageId(edge.pageId) === activePageId)
            .sort((a, b) => a.zIndex - b.zIndex);
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
            if (edge.waypoints?.length) {
              const geometry = edgeCell.getGeometry()?.clone();
              if (geometry) {
                geometry.points = edge.waypoints.map((point) => new Point(point.x, point.y));
                graph.getDataModel().setGeometry(edgeCell, geometry);
              }
            }
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
      setNodeCount(Array.from(currentNodes.values()).filter((node) => diagramPageId(node.pageId) === activePageId).length);
      setEdgeCount(Array.from(currentEdges.values()).filter((edge) => diagramPageId(edge.pageId) === activePageId).length);
      graph.setTooltips(currentNodes.size < 400);
      updateSelection(graph, setSelection);
    };
    renderGraphRef.current = renderFromDocument;

    const modelListener = () => scheduleGraphSync();
    const selectionListener = () => {
      updateSelection(graph, setSelection);
      sendPresence(undefined, true);
    };
    const presencePointerListener = (event: PointerEvent) => {
      const rect = container.getBoundingClientRect();
      const scale = graph.getView().scale || 1;
      const translate = graph.getView().translate;
      sendPresence({
        x: (event.clientX - rect.left + container.scrollLeft) / scale - translate.x,
        y: (event.clientY - rect.top + container.scrollTop) / scale - translate.y,
      });
    };
    graph.getDataModel().addListener(InternalEvent.CHANGE, modelListener);
    graph.getSelectionModel().addListener(InternalEvent.CHANGE, selectionListener);
    container.addEventListener("pointermove", presencePointerListener, { passive: true });
    const resizeObserver = new ResizeObserver(() => graph.sizeDidChange());
    resizeObserver.observe(container);
    runtimeRef.current = {
      graph,
      destroy: () => {
        resizeObserver.disconnect();
        graph.getDataModel().removeListener(modelListener);
        graph.getSelectionModel().removeListener(selectionListener);
        container.removeEventListener("pointermove", presencePointerListener);
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
      outlineRef.current?.destroy();
      outlineRef.current = null;
      renderGraphRef.current = () => undefined;
      flushGraphRef.current = () => undefined;
      resizeObserver.disconnect();
      graph.getDataModel().removeListener(modelListener);
      graph.getSelectionModel().removeListener(selectionListener);
      container.removeEventListener("pointermove", presencePointerListener);
      graph.destroy();
    };
  }, [activePageId, boardKey, documentEpoch, ensureStencilLibraryLoaded, isExpanded, isReadOnly, peerId, scheduleDocumentRender, sendPresence]);

  useEffect(() => {
    if (!showMinimap) {
      return;
    }
    const graph = runtimeRef.current?.graph;
    const container = outlineContainerRef.current;
    if (!graph || !container) {
      return;
    }
    const outline = new Outline(graph, container);
    outlineRef.current = outline;
    outline.updateOnPan = true;
    outline.labelsVisible = false;
    outline.update(true);
    return () => {
      if (outlineRef.current === outline) {
        outline.destroy();
        outlineRef.current = null;
      }
    };
  }, [runtimeEpoch, showMinimap]);

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
      if (payload.kind === "diagram-presence") {
        setRemotePresences((current) => ({
          ...current,
          [event.sourcePeerId]: {
            peerId: event.sourcePeerId,
            pageId: payload.pageId,
            selectedIds: payload.selectedIds,
            cursor: payload.cursor,
            updatedAt: event.receivedAt,
          },
        }));
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
    const timer = window.setInterval(() => {
      const cutoff = Date.now() - 15_000;
      setRemotePresences((current) => Object.fromEntries(
        Object.entries(current).filter(([, presence]) => presence.updatedAt >= cutoff),
      ));
    }, 5_000);
    return () => window.clearInterval(timer);
  }, []);

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
    if (!onSwitchToWhiteboard) return;
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

  const addPage = useCallback(() => {
    if (isReadOnly) return;
    const document = yDocRef.current;
    const pageMap = pagesMapRef.current;
    if (!document || !pageMap || pageMap.size >= MAX_DIAGRAM_PAGES) {
      setStatus(`流程图最多支持 ${MAX_DIAGRAM_PAGES} 个页面。`);
      return;
    }
    flushGraphRef.current();
    const id = createDiagramId(peerId, "page");
    const page: DiagramPage = { id, name: `页面 ${pageMap.size + 1}`, order: pageMap.size };
    document.transact(() => pageMap.set(id, page), GRAPH_ORIGIN);
    setActivePageId(id);
    setStatus(`${page.name}已创建。`);
  }, [isReadOnly, peerId]);

  const renamePage = useCallback(() => {
    if (isReadOnly) return;
    const document = yDocRef.current;
    const pageMap = pagesMapRef.current;
    const page = pageMap?.get(activePageId);
    if (!document || !pageMap || !page) {
      return;
    }
    const name = window.prompt("页面名称", page.name)?.trim().slice(0, 80);
    if (!name || name === page.name) {
      return;
    }
    document.transact(() => pageMap.set(page.id, { ...page, name }), GRAPH_ORIGIN);
    setStatus(`页面已重命名为“${name}”。`);
  }, [activePageId, isReadOnly]);

  const duplicatePage = useCallback(() => {
    if (isReadOnly) return;
    flushGraphRef.current();
    const document = yDocRef.current;
    const pageMap = pagesMapRef.current;
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    const sourcePage = pageMap?.get(activePageId);
    if (!document || !pageMap || !nodes || !edges || !sourcePage || pageMap.size >= MAX_DIAGRAM_PAGES) {
      return;
    }
    const sourceNodes = Array.from(nodes.values()).filter((node) => diagramPageId(node.pageId) === activePageId);
    const sourceEdges = Array.from(edges.values()).filter((edge) => diagramPageId(edge.pageId) === activePageId);
    if (nodes.size + sourceNodes.length > MAX_DIAGRAM_NODES) {
      setStatus("复制页面会超过流程图节点数量上限。");
      return;
    }
    const pageId = createDiagramId(peerId, "page");
    const idMap = new Map(sourceNodes.map((node) => [node.id, createDiagramId(peerId, node.kind)]));
    const page: DiagramPage = { id: pageId, name: `${sourcePage.name} 副本`, order: pageMap.size };
    document.transact(() => {
      pageMap.set(page.id, page);
      sourceNodes.forEach((node) => {
        const id = idMap.get(node.id)!;
        nodes.set(id, {
          ...cloneNode(node),
          id,
          pageId,
          ...(node.parentId && idMap.has(node.parentId) ? { parentId: idMap.get(node.parentId)! } : { parentId: undefined }),
        });
      });
      sourceEdges.forEach((edge) => {
        const sourceId = idMap.get(edge.sourceId);
        const targetId = idMap.get(edge.targetId);
        if (sourceId && targetId) {
          const id = createDiagramId(peerId, "edge");
          edges.set(id, { ...cloneEdge(edge), id, pageId, sourceId, targetId });
        }
      });
    }, GRAPH_ORIGIN);
    setActivePageId(pageId);
    setStatus(`已复制页面“${sourcePage.name}”。`);
  }, [activePageId, isReadOnly, peerId]);

  const deletePage = useCallback(() => {
    if (isReadOnly) return;
    const document = yDocRef.current;
    const pageMap = pagesMapRef.current;
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    const commentsMap = commentsMapRef.current;
    const page = pageMap?.get(activePageId);
    if (!document || !pageMap || !nodes || !edges || !commentsMap || !page) {
      return;
    }
    if (pageMap.size <= 1) {
      setStatus("流程图至少需要保留一个页面。可使用清空删除页面内容。");
      return;
    }
    if (!window.confirm(`确定删除页面“${page.name}”及其中全部内容吗？`)) {
      return;
    }
    const nextPage = pages.find((candidate) => candidate.id !== activePageId);
    document.transact(() => {
      for (const [id, node] of nodes.entries()) {
        if (diagramPageId(node.pageId) === activePageId) nodes.delete(id);
      }
      for (const [id, edge] of edges.entries()) {
        if (diagramPageId(edge.pageId) === activePageId) edges.delete(id);
      }
      for (const [id, comment] of commentsMap.entries()) {
        if (comment.pageId === activePageId) commentsMap.delete(id);
      }
      pageMap.delete(activePageId);
    }, GRAPH_ORIGIN);
    setActivePageId(nextPage?.id ?? DEFAULT_PAGE_ID);
    setStatus(`页面“${page.name}”已删除。`);
  }, [activePageId, isReadOnly, pages]);

  const insertNodeIntoGraph = useCallback((
    graph: Graph,
    kind: DiagramNodeKind,
    dropPoint?: Point,
    dropTarget?: Cell | null,
    stencil?: StencilPaletteItem,
  ) => {
    if (isReadOnly) return;
    const currentDocument = readGraphDocument(graph, activePageId);
    if ((nodesMapRef.current?.size ?? currentDocument.nodes.length) >= MAX_DIAGRAM_NODES) {
      setStatus("流程图节点已达到 1000 个上限。");
      return;
    }
    const defaults = stencil ? stencilNodeDefaults(stencil) : nodeDefaults(kind);
    const index = currentDocument.nodes.length;
    const selectedParent = !dropPoint && graph.getSelectionCells().length === 1
      ? graph.getSelectionCell()
      : null;
    const candidateParent = dropTarget ?? selectedParent;
    const candidateKind = candidateParent
      ? (candidateParent.getStyle() as DiagramCellStyle).diagramKind
      : undefined;
    const parent = candidateParent && (candidateKind === "container" || candidateKind === "swimlane" || candidateKind === "lane")
      ? candidateParent
      : graph.getDefaultParent();
    const insideContainer = parent !== graph.getDefaultParent();
    let x: number;
    let y: number;
    if (dropPoint) {
      const parentOrigin = insideContainer ? absoluteCellOrigin(parent) : { x: 0, y: 0 };
      x = graph.snap(Math.max(12, dropPoint.x - parentOrigin.x - defaults.width / 2));
      y = graph.snap(Math.max(insideContainer ? 42 : 12, dropPoint.y - parentOrigin.y - defaults.height / 2));
    } else {
      const scale = graph.getView().getScale();
      const translate = graph.getView().getTranslate();
      const container = graph.container;
      x = insideContainer
        ? 36 + (parent.getChildCount() % 3) * 28
        : Math.max(20, (container.scrollLeft + container.clientWidth / 2) / scale - translate.x - defaults.width / 2 + (index % 4) * 12);
      y = insideContainer
        ? 58 + (parent.getChildCount() % 4) * 26
        : Math.max(20, (container.scrollTop + container.clientHeight / 2) / scale - translate.y - defaults.height / 2 + (index % 4) * 12);
    }
    const node: DiagramNode = {
      id: createDiagramId(peerId, kind),
      kind,
      ...(stencil ? { stencilName: stencil.stencilName, stencilLibrary: stencil.stencilLibrary } : {}),
      label: defaults.label,
      x,
      y,
      width: defaults.width,
      height: defaults.height,
      zIndex: index,
      pageId: activePageId,
      ...(insideContainer && parent.getId() ? { parentId: parent.getId()! } : {}),
      style: defaults.style,
    };
    const cell = graph.insertVertex({
      parent,
      id: node.id,
      value: node.label,
      position: [node.x, node.y],
      size: [node.width, node.height],
      style: nodeCellStyle(node),
    });
    cell.setConnectable(kind !== "container" && kind !== "swimlane" && kind !== "lane");
    graph.setSelectionCell(cell);
    graph.scrollCellToVisible(cell);
    setStatus(`${stencil?.label ?? defaults.label}已插入；移动时会显示智能参考线。`);
  }, [activePageId, isReadOnly, peerId]);

  const insertNode = useCallback((kind: DiagramNodeKind) => {
    withGraph((graph) => insertNodeIntoGraph(graph, kind));
  }, [insertNodeIntoGraph, withGraph]);

  const insertStencilNode = useCallback(async (
    library: DrawioStencilLibrary,
    shape: DrawioStencilShape,
  ) => {
    if (isReadOnly) return;
    try {
      await ensureStencilLibraryLoaded(library);
      const item = stencilPaletteItem(library, shape);
      withGraph((graph) => insertNodeIntoGraph(graph, item.kind, undefined, undefined, item));
    } catch (error) {
      setStatus(error instanceof Error ? error.message : `${library.name} 加载失败`);
    }
  }, [ensureStencilLibraryLoaded, insertNodeIntoGraph, isReadOnly, withGraph]);

  useEffect(() => {
    const graph = runtimeRef.current?.graph;
    if (!graph || isReadOnly) {
      return;
    }
    const sources = Array.from(draggablePaletteItemsRef.current.entries()).flatMap(([id, item]) => {
      const element = paletteElementRefs.current.get(id);
      if (!element) {
        return [];
      }
      const stencil = "stencilName" in item ? item : undefined;
      const defaults = stencil ? stencilNodeDefaults(stencil) : nodeDefaults(item.kind);
      const preview = createNodeDragPreview(item.kind, defaults);
      const source = gestureUtils.makeDraggable(
        element,
        graph,
        (targetGraph, _event, target, x, y) => {
          insertNodeIntoGraph(
            targetGraph as Graph,
            item.kind,
            new Point((x ?? 0) + preview.width / 2, (y ?? 0) + preview.height / 2),
            target,
            stencil,
          );
        },
        preview.element,
        -preview.width / 2,
        -preview.height / 2,
        true,
        true,
        true,
      );
      source.previewOffset = new Point(-preview.width / 2, -preview.height / 2);
      source.dragElementOpacity = 100;
      source.setGuidesEnabled(true);
      return [source];
    });
    return () => {
      sources.forEach((source) => {
        source.setEnabled(false);
        source.reset();
      });
    };
  }, [activeStencilCollectionId, insertNodeIntoGraph, isReadOnly, loadedStencilLibraries, paletteQuery, runtimeEpoch]);

  const insertTemplate = useCallback((template: "approval" | "architecture" | "er" = "approval") => {
    if (isReadOnly) return;
    withGraph((graph) => {
      const templateDefinitions: Record<typeof template, Array<{ kind: DiagramNodeKind; label: string; dx: number; dy: number }>> = {
        approval: [
          { kind: "start", label: "开始", dx: 40, dy: 0 },
          { kind: "process", label: "处理请求", dx: 20, dy: 130 },
          { kind: "decision", label: "校验通过？", dx: 0, dy: 270 },
          { kind: "end", label: "结束", dx: 40, dy: 430 },
        ],
        architecture: [
          { kind: "cloud", label: "公网入口", dx: 0, dy: 0 },
          { kind: "server", label: "API 服务", dx: 240, dy: 0 },
          { kind: "queue", label: "消息队列", dx: 480, dy: 0 },
          { kind: "database", label: "业务数据库", dx: 720, dy: 0 },
        ],
        er: [
          { kind: "entity", label: "User\n────────\nid: UUID\nname: VARCHAR", dx: 0, dy: 0 },
          { kind: "entity", label: "Order\n────────\nid: UUID\nuser_id: UUID", dx: 280, dy: 0 },
          { kind: "entity", label: "OrderItem\n────────\norder_id: UUID\nsku: VARCHAR", dx: 560, dy: 0 },
        ],
      };
      const selectedTemplate = templateDefinitions[template];
      if ((nodesMapRef.current?.size ?? readGraphDocument(graph, activePageId).nodes.length) + selectedTemplate.length > MAX_DIAGRAM_NODES) {
        setStatus("节点数量不足以插入模板。");
        return;
      }
      const parent = graph.getDefaultParent();
      const baseX = Math.max(40, graph.container.scrollLeft + 80);
      const baseY = Math.max(40, graph.container.scrollTop + 60);
      const cells: Cell[] = [];
      graph.batchUpdate(() => {
        for (const definition of selectedTemplate) {
          const defaults = nodeDefaults(definition.kind);
          const node: DiagramNode = {
            id: createDiagramId(peerId, definition.kind),
            kind: definition.kind,
            label: definition.label,
            x: baseX + definition.dx,
            y: baseY + definition.dy,
            width: defaults.width,
            height: defaults.height,
            zIndex: cells.length,
            pageId: activePageId,
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
      const templateName = template === "approval" ? "审批流程" : template === "architecture" ? "系统架构" : "ER 模型";
      setStatus(`${templateName}模板已插入，可继续编辑和自动布局。`);
    });
  }, [activePageId, isReadOnly, peerId, withGraph]);

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

  const groupSelection = useCallback(() => {
    withGraph((graph) => {
      const cells = graph.getCellsForGroup(graph.getSelectionCells().filter((cell) => cell.isVertex()));
      if (cells.length < 2) {
        setStatus("至少选择两个同级节点才能分组。");
        return;
      }
      const defaults = nodeDefaults("container");
      const groupNode: DiagramNode = {
        id: createDiagramId(peerId, "group"),
        kind: "container",
        label: "分组容器",
        x: 0,
        y: 0,
        width: defaults.width,
        height: defaults.height,
        zIndex: 0,
        style: defaults.style,
      };
      const group = new Cell(groupNode.label, null, nodeCellStyle(groupNode));
      group.setId(groupNode.id);
      group.setVertex(true);
      group.setConnectable(false);
      const grouped = graph.groupCells(group, 28, cells);
      graph.setSelectionCell(grouped);
      setStatus(`已把 ${cells.length} 个节点放入分组容器。`);
    });
  }, [peerId, withGraph]);

  const ungroupSelection = useCallback(() => {
    withGraph((graph) => {
      const groups = graph.getSelectionCells().filter((cell) => {
        const kind = (cell.getStyle() as DiagramCellStyle).diagramKind;
        return cell.isVertex() && cell.getChildCount() > 0 && (kind === "container" || kind === "swimlane");
      });
      if (groups.length === 0) {
        setStatus("请选择包含节点的容器或泳道后再取消分组。");
        return;
      }
      const children = graph.ungroupCells(groups);
      graph.setSelectionCells(children);
      setStatus(`已取消 ${groups.length} 个容器分组。`);
    });
  }, [withGraph]);

  const distributeSelection = useCallback((axis: "horizontal" | "vertical") => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells().filter((cell) => cell.isVertex() && cell.getGeometry());
      if (cells.length < 3 || new Set(cells.map((cell) => cell.getParent())).size !== 1) {
        setStatus("等距分布需要至少三个同级节点。");
        return;
      }
      const horizontal = axis === "horizontal";
      const ordered = cells.slice().sort((left, right) => {
        const leftGeometry = left.getGeometry()!;
        const rightGeometry = right.getGeometry()!;
        return horizontal ? leftGeometry.x - rightGeometry.x : leftGeometry.y - rightGeometry.y;
      });
      const first = ordered[0].getGeometry()!;
      const last = ordered[ordered.length - 1].getGeometry()!;
      const start = horizontal ? first.x : first.y;
      const end = horizontal ? last.x + last.width : last.y + last.height;
      const occupied = ordered.reduce((total, cell) => {
        const geometry = cell.getGeometry()!;
        return total + (horizontal ? geometry.width : geometry.height);
      }, 0);
      const gap = (end - start - occupied) / (ordered.length - 1);
      let cursor = start;
      graph.batchUpdate(() => {
        for (const cell of ordered) {
          const geometry = cell.getGeometry()!.clone();
          if (horizontal) geometry.x = cursor;
          else geometry.y = cursor;
          graph.getDataModel().setGeometry(cell, geometry);
          cursor += (horizontal ? geometry.width : geometry.height) + gap;
        }
      });
      setStatus(horizontal ? "已水平等距分布选中节点。" : "已垂直等距分布选中节点。");
    });
  }, [withGraph]);

  const updateEdgeType = useCallback((edgeType: DiagramEdgeType) => {
    withGraph((graph) => {
      const edges = graph.getSelectionCells().filter((cell) => cell.isEdge());
      if (edges.length === 0) {
        return;
      }
      graph.batchUpdate(() => {
        for (const edge of edges) {
          const style = edge.getClonedStyle();
          delete style.edgeStyle;
          delete style.elbow;
          delete style.curved;
          delete style.orthogonalLoop;
          delete style.jettySize;
          Object.assign(style, edgeRoutingStyle(edgeType));
          graph.getDataModel().setStyle(edge, style);
        }
      });
      updateSelection(graph, setSelection);
      setStatus(`已切换 ${edges.length} 条连线的路由样式。`);
    });
  }, [withGraph]);

  const updateArrowType = useCallback((end: "start" | "end", arrow: DiagramArrowType) => {
    withGraph((graph) => {
      const edges = graph.getSelectionCells().filter((cell) => cell.isEdge());
      const arrowKey = end === "start" ? "startArrow" : "endArrow";
      const fillKey = end === "start" ? "startFill" : "endFill";
      graph.batchUpdate(() => {
        graph.setCellStyles(arrowKey, arrow, edges);
        graph.setCellStyles(fillKey, arrow !== "none" && arrow !== "open", edges);
      });
      updateSelection(graph, setSelection);
      setStatus(`已更新 ${edges.length} 条连线的${end === "start" ? "起点" : "终点"}箭头。`);
    });
  }, [withGraph]);

  const addEdgeWaypoint = useCallback(() => {
    withGraph((graph) => {
      const edges = graph.getSelectionCells().filter((cell) => cell.isEdge());
      if (edges.length === 0) {
        return;
      }
      graph.batchUpdate(() => {
        for (const edge of edges) {
          const geometry = edge.getGeometry()?.clone();
          const source = edge.getTerminal(true);
          const target = edge.getTerminal(false);
          if (!geometry || !source || !target) {
            continue;
          }
          const sourceCenter = absoluteCellCenter(source);
          const targetCenter = absoluteCellCenter(target);
          const existing = geometry.points?.slice() ?? [];
          const previous = existing[existing.length - 1] ?? sourceCenter;
          existing.push(new Point(
            graph.snap((previous.x + targetCenter.x) / 2),
            graph.snap((previous.y + targetCenter.y) / 2),
          ));
          geometry.points = existing.slice(0, 128);
          graph.getDataModel().setGeometry(edge, geometry);
        }
      });
      setStatus("已添加可拖动折点；也可按住 Shift 点击连线添加或删除折点。");
    });
  }, [withGraph]);

  const clearEdgeWaypoints = useCallback(() => {
    withGraph((graph) => {
      const edges = graph.getSelectionCells().filter((cell) => cell.isEdge());
      graph.batchUpdate(() => {
        for (const edge of edges) {
          const geometry = edge.getGeometry()?.clone();
          if (geometry) {
            geometry.points = null;
            graph.getDataModel().setGeometry(edge, geometry);
          }
        }
      });
      setStatus(`已清除 ${edges.length} 条连线的手动折点。`);
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

  const updateSelectedStyle = useCallback((key: "fillColor" | "strokeColor" | "dashed" | "strokeWidth" | "opacity" | "shadow" | "rounded", value: string | boolean | number) => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells();
      if (cells.length === 0) {
        return;
      }
      graph.setCellStyles(key, value, cells);
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const copyFormat = useCallback(() => {
    withGraph((graph) => {
      const cell = graph.getSelectionCell();
      if (!cell || graph.getSelectionCells().length !== 1) {
        setStatus("请选择一个元素作为格式来源。");
        return;
      }
      formatStyleRef.current = { vertex: cell.isVertex(), style: cell.getClonedStyle() };
      setHasCopiedFormat(true);
      setStatus("格式已复制，选择同类元素后点击“应用格式”。");
    });
  }, [withGraph]);

  const applyFormat = useCallback(() => {
    withGraph((graph) => {
      const copied = formatStyleRef.current;
      const cells = graph.getSelectionCells().filter((cell) => copied && cell.isVertex() === copied.vertex);
      if (!copied || cells.length === 0) {
        setStatus("请选择与格式来源同类型的元素。");
        return;
      }
      const cosmeticKeys = ["fillColor", "strokeColor", "fontColor", "strokeWidth", "dashed", "fontSize", "fontStyle", "align", "opacity", "shadow", "rounded"] as const;
      graph.batchUpdate(() => cells.forEach((cell) => {
        const style = cell.getClonedStyle();
        cosmeticKeys.forEach((key) => {
          const value = copied.style[key];
          if (value === undefined) delete style[key];
          else style[key] = value as never;
        });
        graph.getDataModel().setStyle(cell, style);
      }));
      updateSelection(graph, setSelection);
      setStatus(`已将格式应用到 ${cells.length} 个元素。`);
    });
  }, [withGraph]);

  const updateNodeFontSize = useCallback((fontSize: number) => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells().filter((cell) => cell.isVertex());
      graph.setCellStyles("fontSize", fontSize, cells);
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const toggleNodeFontStyle = useCallback((mask: 1 | 2) => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells().filter((cell) => cell.isVertex());
      graph.batchUpdate(() => {
        cells.forEach((cell) => {
          const style = cell.getClonedStyle();
          style.fontStyle = styleNumber(style.fontStyle, 0) ^ mask;
          graph.getDataModel().setStyle(cell, style);
        });
      });
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const updateNodeAlign = useCallback((align: "left" | "center" | "right") => {
    withGraph((graph) => {
      graph.setCellStyles("align", align, graph.getSelectionCells().filter((cell) => cell.isVertex()));
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const toggleNodeLock = useCallback(() => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells().filter((cell) => cell.isVertex());
      const nextLocked = !cells.every((cell) => Boolean((cell.getStyle() as DiagramCellStyle).diagramLocked));
      graph.batchUpdate(() => cells.forEach((cell) => {
        graph.getDataModel().setStyle(cell, { ...cell.getStyle(), diagramLocked: nextLocked } as DiagramCellStyle);
      }));
      updateSelection(graph, setSelection);
      setStatus(nextLocked ? `已锁定 ${cells.length} 个节点。` : `已解锁 ${cells.length} 个节点。`);
    });
  }, [withGraph]);

  const rotateNodes = useCallback((degrees: number) => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells().filter((cell) => cell.isVertex());
      graph.batchUpdate(() => {
        cells.forEach((cell) => {
          const style = cell.getClonedStyle();
          style.rotation = normalizeRotation(styleNumber(style.rotation, 0) + degrees);
          graph.getDataModel().setStyle(cell, style);
        });
      });
      updateSelection(graph, setSelection);
      setStatus(`已旋转 ${cells.length} 个节点。`);
    });
  }, [withGraph]);

  const toggleSwimlaneDirection = useCallback(() => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells().filter((cell) => (
        cell.isVertex() && (cell.getStyle() as DiagramCellStyle).diagramKind === "swimlane"
      ));
      graph.batchUpdate(() => {
        cells.forEach((cell) => {
          const lanes = laneChildren(graph, cell);
          const style = cell.getClonedStyle();
          style.horizontal = style.horizontal === false;
          const geometry = cell.getGeometry()?.clone();
          graph.getDataModel().setStyle(cell, style);
          if (geometry) {
            [geometry.width, geometry.height] = [geometry.height, geometry.width];
            graph.getDataModel().setGeometry(cell, geometry);
          }
          layoutLaneCells(graph, cell, lanes);
        });
      });
      updateSelection(graph, setSelection);
      setStatus("已切换泳道方向。");
    });
  }, [withGraph]);

  const addSwimlaneLane = useCallback(() => {
    withGraph((graph) => {
      const pool = graph.getSelectionCell();
      if (!pool || graph.getSelectionCells().length !== 1
        || (pool.getStyle() as DiagramCellStyle).diagramKind !== "swimlane") {
        setStatus("请先选择一个泳池再添加泳道。");
        return;
      }
      const defaults = nodeDefaults("lane");
      let lane: Cell | undefined;
      graph.batchUpdate(() => {
        const insertedLane = graph.insertVertex({
          parent: pool,
          id: createDiagramId(peerId, "lane"),
          value: `泳道 ${laneChildren(graph, pool).length + 1}`,
          position: [0, 0],
          size: [defaults.width, defaults.height],
          style: nodeCellStyle({
            id: "lane-style",
            kind: "lane",
            label: defaults.label,
            x: 0,
            y: 0,
            width: defaults.width,
            height: defaults.height,
            zIndex: 0,
            style: defaults.style,
          }),
        });
        insertedLane.setConnectable(false);
        lane = insertedLane;
        layoutLaneCells(graph, pool);
      });
      if (lane) graph.setSelectionCell(lane);
      updateSelection(graph, setSelection);
      setStatus("已添加泳道，可将节点拖入泳道中。");
    });
  }, [peerId, withGraph]);

  const moveLane = useCallback((offset: -1 | 1) => {
    withGraph((graph) => {
      const lane = graph.getSelectionCell();
      const pool = lane?.getParent();
      if (!lane || !pool || (lane.getStyle() as DiagramCellStyle).diagramKind !== "lane") return;
      const lanes = laneChildren(graph, pool);
      const index = lanes.indexOf(lane);
      const target = lanes[index + offset];
      if (!target) {
        setStatus(offset < 0 ? "当前已经是第一条泳道。" : "当前已经是最后一条泳道。");
        return;
      }
      [lanes[index], lanes[index + offset]] = [target, lane];
      graph.batchUpdate(() => layoutLaneCells(graph, pool, lanes));
      graph.setSelectionCell(lane);
      setStatus(offset < 0 ? "泳道已前移。" : "泳道已后移。");
    });
  }, [withGraph]);

  const removeLane = useCallback(() => {
    withGraph((graph) => {
      const lane = graph.getSelectionCell();
      if (!lane || (lane.getStyle() as DiagramCellStyle).diagramKind !== "lane") return;
      const pool = lane.getParent();
      const childCount = graph.getChildVertices(lane).length;
      const message = childCount > 0
        ? `该泳道包含 ${childCount} 个节点，删除后节点也会删除。是否继续？`
        : "确定删除当前泳道吗？";
      if (!window.confirm(message)) return;
      graph.batchUpdate(() => {
        graph.removeCells([lane], true);
        if (pool) layoutLaneCells(graph, pool);
      });
      updateSelection(graph, setSelection);
      setStatus("泳道已删除。");
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
      const document = yDocRef.current;
      const commentsMap = commentsMapRef.current;
      if (document && commentsMap) {
        document.transact(() => {
          for (const [id, comment] of commentsMap.entries()) {
            if (comment.pageId === activePageId) commentsMap.delete(id);
          }
        }, GRAPH_ORIGIN);
      }
      setStatus("流程图已清空，可使用撤销恢复。");
    });
  }, [activePageId, withGraph]);

  const exportDiagram = useCallback(() => {
    flushGraphRef.current();
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    if (!nodes || !edges) {
      return;
    }
    const document = createDiagramDocument(
      Array.from(nodes.values()),
      Array.from(edges.values()),
      DIAGRAM_CANVAS,
      new Date(),
      pages,
      activePageId,
      comments,
    );
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
  }, [activePageId, comments, pages]);

  const exportDrawio = useCallback(() => {
    flushGraphRef.current();
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    if (!nodes || !edges) {
      return;
    }
    const document = createDiagramDocument(
      Array.from(nodes.values()),
      Array.from(edges.values()),
      DIAGRAM_CANVAS,
      new Date(),
      pages,
      activePageId,
    );
    downloadDiagramFile(
      exportDrawioDocument(document),
      DRAWIO_FILE_MIME,
      diagramExportFileName(new Date(), DRAWIO_FILE_EXTENSION),
    );
    setStatus(`已导出 draw.io 文档：${document.nodes.length} 个节点、${document.edges.length} 条连线。`);
  }, [activePageId, pages]);

  const exportSvg = useCallback(() => {
    const graph = runtimeRef.current?.graph;
    if (!graph) {
      return;
    }
    try {
      const svg = renderGraphSvg(graph, theme === "dark" ? "#15181f" : "#ffffff");
      downloadDiagramFile(svg, "image/svg+xml", diagramExportFileName(new Date(), ".svg"));
      setStatus("已导出可缩放的 SVG 图片。");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "SVG 导出失败");
    }
  }, [theme]);

  const exportPng = useCallback(async () => {
    const graph = runtimeRef.current?.graph;
    if (!graph) {
      return;
    }
    try {
      const background = theme === "dark" ? "#15181f" : "#ffffff";
      const svg = renderGraphSvg(graph, background);
      const png = await svgToPng(svg, 2, background);
      downloadDiagramBlob(png, diagramExportFileName(new Date(), ".png"));
      setStatus("已导出 2 倍分辨率 PNG 图片。");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "PNG 导出失败");
    }
  }, [theme]);

  const exportMermaid = useCallback(() => {
    flushGraphRef.current();
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    if (!nodes || !edges) {
      return;
    }
    const source = exportMermaidDocument(createDiagramDocument(
      Array.from(nodes.values()),
      Array.from(edges.values()),
      DIAGRAM_CANVAS,
      new Date(),
      pages,
      activePageId,
    ));
    downloadDiagramFile(source, "text/markdown;charset=utf-8", diagramExportFileName(new Date(), ".md"));
    setStatus(`已导出包含 ${pages.length} 个页面的 Mermaid 文档。`);
  }, [activePageId, pages]);

  const exportPlantUml = useCallback(() => {
    flushGraphRef.current();
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    if (!nodes || !edges) return;
    const source = exportPlantUmlDocument(createDiagramDocument(Array.from(nodes.values()), Array.from(edges.values()), DIAGRAM_CANVAS, new Date(), pages, activePageId));
    downloadDiagramFile(source, "text/plain;charset=utf-8", diagramExportFileName(new Date(), ".puml"));
    setStatus(`已导出包含 ${pages.length} 个页面的 PlantUML 文档。`);
  }, [activePageId, pages]);

  const exportVisio = useCallback(() => {
    flushGraphRef.current();
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    if (!nodes || !edges) return;
    const source = exportVisioVdx(createDiagramDocument(Array.from(nodes.values()), Array.from(edges.values()), DIAGRAM_CANVAS, new Date(), pages, activePageId));
    downloadDiagramFile(source, VISIO_VDX_MIME, diagramExportFileName(new Date(), VISIO_VDX_FILE_EXTENSION));
    setStatus(`已导出可由 Visio 打开的 VDX 文档，共 ${pages.length} 个页面。`);
  }, [activePageId, pages]);

  const exportPdf = useCallback(async () => {
    flushGraphRef.current();
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    if (!nodes || !edges) {
      return;
    }
    try {
      const orderedPages = pages.slice().sort((left, right) => left.order - right.order);
      if (orderedPages.length === 0 || nodes.size === 0) {
        throw new Error("流程图为空，无法导出 PDF");
      }
      setStatus(`正在生成 ${orderedPages.length} 页 PDF...`);
      const background = theme === "dark" ? "#15181f" : "#ffffff";
      const { jsPDF } = await import("jspdf");
      let pdf: InstanceType<typeof jsPDF> | undefined;
      for (const page of orderedPages) {
        const svg = renderDiagramPageSvg(Array.from(nodes.values()), Array.from(edges.values()), page.id, background);
        const png = await svgToPng(svg, 2, background);
        const dataUrl = await blobToDataUrl(png);
        const dimensions = svgDimensions(svg);
        const orientation = dimensions.width >= dimensions.height ? "landscape" as const : "portrait" as const;
        if (!pdf) {
          pdf = new jsPDF({
            orientation,
            unit: "px",
            format: [dimensions.width, dimensions.height],
            hotfixes: ["px_scaling"],
          });
        } else {
          pdf.addPage([dimensions.width, dimensions.height], orientation);
        }
        pdf.addImage(dataUrl, "PNG", 0, 0, dimensions.width, dimensions.height, undefined, "FAST");
      }
      if (!pdf) {
        throw new Error("没有可导出的流程图页面");
      }
      pdf.setProperties({ title: "shuai-tunnel 流程图", creator: "shuai-tunnel" });
      downloadDiagramBlob(pdf.output("blob"), diagramExportFileName(new Date(), ".pdf"));
      setStatus(`已导出包含 ${orderedPages.length} 个页面的 PDF。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "PDF 导出失败");
    }
  }, [pages, theme]);

  const importDiagram = useCallback(async (file: File) => {
    if (isReadOnly) return;
    const lowerName = file.name.toLowerCase();
    const isDrawioFile = lowerName.endsWith(DRAWIO_FILE_EXTENSION);
    const isVisioFile = lowerName.endsWith(VISIO_VSDX_FILE_EXTENSION) || lowerName.endsWith(VISIO_VDX_FILE_EXTENSION);
    const maximumBytes = isVisioFile ? 16 * 1024 * 1024 : isDrawioFile ? MAX_DRAWIO_DOCUMENT_BYTES : MAX_DIAGRAM_DOCUMENT_BYTES;
    if (file.size > maximumBytes) {
      setStatus(`流程图文件超过 ${isVisioFile ? "16" : isDrawioFile ? "8" : "2"} MB，无法导入。`);
      return;
    }
    setIsImporting(true);
    try {
      let imported: DiagramDocumentV1;
      if (lowerName.endsWith(VISIO_VSDX_FILE_EXTENSION)) {
        imported = parseVisioVsdx(new Uint8Array(await file.arrayBuffer()));
      } else {
        const source = await file.text();
        const trimmed = source.trimStart();
        if (lowerName.endsWith(VISIO_VDX_FILE_EXTENSION) || /<VisioDocument\b/i.test(trimmed)) imported = parseVisioVdx(source);
        else if (MERMAID_FILE_EXTENSIONS.some((extension) => lowerName.endsWith(extension)) || /(?:```mermaid|\bflowchart\s+(?:TD|TB|BT|LR|RL))/i.test(source)) imported = parseMermaidDocument(source);
        else if (PLANTUML_FILE_EXTENSIONS.some((extension) => lowerName.endsWith(extension)) || /@startuml/i.test(source)) imported = parsePlantUmlDocument(source);
        else if (isDrawioFile || /<(?:mxfile|mxGraphModel)\b/i.test(trimmed)) imported = parseDrawioDocument(source);
        else imported = parseDiagramDocument(source);
      }
      if ((nodeCount > 0 || edgeCount > 0)
        && !window.confirm("导入将替换当前流程图并同步给房间内设备。是否继续？")) {
        setStatus("已取消导入，当前流程图未变化。");
        return;
      }
      const document = yDocRef.current;
      const nodes = nodesMapRef.current;
      const edges = edgesMapRef.current;
      const pageMap = pagesMapRef.current;
      const commentsMap = commentsMapRef.current;
      if (!document || !nodes || !edges || !pageMap || !commentsMap) {
        throw new Error("流程图编辑器尚未就绪");
      }
      const importedPages = imported.pages?.length
        ? imported.pages
        : [{ id: DEFAULT_PAGE_ID, name: "页面 1", order: 0 }];
      const importedActivePageId = imported.activePageId && importedPages.some((page) => page.id === imported.activePageId)
        ? imported.activePageId
        : importedPages[0].id;
      document.transact(() => {
        nodes.clear();
        edges.clear();
        pageMap.clear();
        commentsMap.clear();
        importedPages.forEach((page) => pageMap.set(page.id, { ...page }));
        imported.nodes.forEach((node) => nodes.set(node.id, { ...cloneNode(node), pageId: node.pageId ?? importedActivePageId }));
        imported.edges.forEach((edge) => edges.set(edge.id, { ...cloneEdge(edge), pageId: edge.pageId ?? importedActivePageId }));
        imported.comments?.forEach((comment) => commentsMap.set(comment.id, { ...comment }));
      }, IMPORT_ORIGIN);
      setActivePageId(importedActivePageId);
      undoManagerRef.current?.clear();
      refreshUndoState();
      setStatus(`已导入 ${importedPages.length} 个页面、${imported.nodes.length} 个节点和 ${imported.edges.length} 条连线。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "流程图导入失败");
    } finally {
      setIsImporting(false);
    }
  }, [edgeCount, isReadOnly, nodeCount, refreshUndoState]);

  const addComment = useCallback(() => {
    if (isReadOnly) return;
    const text = window.prompt("输入评论内容（最多 500 字）")?.trim();
    const map = commentsMapRef.current;
    const document = yDocRef.current;
    if (!text || !map || !document) return;
    const comment: DiagramComment = {
      id: createDiagramId(peerId, "comment"),
      pageId: activePageId,
      cellId: selection.ids.length === 1 ? selection.ids[0] : undefined,
      author: peerId,
      text: text.slice(0, 500),
      createdAt: Date.now(),
      resolved: false,
    };
    document.transact(() => map.set(comment.id, comment), GRAPH_ORIGIN);
    setStatus(selection.ids.length === 1 ? "已为选中元素添加评论。" : "已为当前页面添加评论。");
  }, [activePageId, isReadOnly, peerId, selection.ids]);

  const toggleComment = useCallback((comment: DiagramComment) => {
    if (isReadOnly) return;
    const document = yDocRef.current;
    const map = commentsMapRef.current;
    if (!document || !map) return;
    document.transact(() => map.set(comment.id, { ...comment, resolved: !comment.resolved }), GRAPH_ORIGIN);
  }, [isReadOnly]);

  const deleteComment = useCallback((commentId: string) => {
    if (isReadOnly) return;
    const document = yDocRef.current;
    const map = commentsMapRef.current;
    if (!document || !map) return;
    document.transact(() => map.delete(commentId), GRAPH_ORIGIN);
  }, [isReadOnly]);

  const focusComment = useCallback((comment: DiagramComment) => {
    if (comment.pageId !== activePageId) {
      flushGraphRef.current();
      setActivePageId(comment.pageId);
    }
    if (!comment.cellId) return;
    window.setTimeout(() => {
      const graph = runtimeRef.current?.graph;
      const cell = graph?.getDataModel().getCell(comment.cellId!);
      if (graph && cell) {
        graph.setSelectionCell(cell);
        graph.scrollCellToVisible(cell);
      }
    }, comment.pageId === activePageId ? 0 : 60);
  }, [activePageId]);

  const createVersion = useCallback(async () => {
    if (isRoleReadOnly) return;
    flushGraphRef.current();
    const document = yDocRef.current;
    if (!document) return;
    const createdAt = Date.now();
    const name = window.prompt("版本名称", `版本 ${versionsRef.current.length + 1}`)?.trim();
    if (!name) return;
    const update = Y.encodeStateAsUpdate(document);
    setIsVersionLoading(true);
    try {
      let snapshot: DiagramVersionSnapshot;
      if (usesServerVersions) {
        const created = await publicCreateTransferDiagramVersion(
          roomId,
          { roomToken, peerId },
          name.slice(0, 80),
          encodeDiagramUpdate(update),
        );
        snapshot = toDiagramVersionSnapshot(created);
        versionsRef.current = [...versionsRef.current.slice(-49), snapshot];
      } else {
        snapshot = {
          id: createDiagramId(peerId, "version"),
          name: name.slice(0, 80),
          createdAt,
          update,
        };
        versionsRef.current = [...versionsRef.current.slice(-19), snapshot];
      }
      setVersions(versionsRef.current);
      setStatus(`已创建版本“${snapshot.name}”。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "创建流程图版本失败");
    } finally {
      setIsVersionLoading(false);
    }
  }, [isRoleReadOnly, peerId, roomId, roomToken, usesServerVersions]);

  const restoreVersion = useCallback(async (snapshot: DiagramVersionSnapshot) => {
    if (isReadOnly || !window.confirm(`恢复到“${snapshot.name}”会替换当前流程图，是否继续？`)) return;
    const document = yDocRef.current;
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    const pageMap = pagesMapRef.current;
    const commentsMap = commentsMapRef.current;
    if (!document || !nodes || !edges || !pageMap || !commentsMap) return;
    const probe = new Y.Doc();
    setIsVersionLoading(true);
    try {
      let update = snapshot.update;
      if (!update && snapshot.serverId !== undefined) {
        const detail = await publicGetTransferDiagramVersion(
          roomId,
          snapshot.serverId,
          { roomToken, peerId },
        );
        update = decodeDiagramUpdate(detail.update);
      }
      if (!update) throw new Error("版本数据不存在");
      Y.applyUpdate(probe, update);
      const nextNodes = Array.from(probe.getMap<DiagramNode>(NODES_MAP).values());
      const nextEdges = Array.from(probe.getMap<DiagramEdge>(EDGES_MAP).values());
      const nextPages = Array.from(probe.getMap<DiagramPage>(PAGES_MAP).values());
      const nextComments = Array.from(probe.getMap<DiagramComment>(COMMENTS_MAP).values()).filter(isDiagramComment);
      if (!isDiagramGraphState(nextNodes, nextEdges) || nextPages.length === 0 || !nextPages.every(isDiagramPage)) {
        throw new Error("版本数据无效");
      }
      document.transact(() => {
        nodes.clear(); edges.clear(); pageMap.clear(); commentsMap.clear();
        nextNodes.forEach((node) => nodes.set(node.id, cloneNode(node)));
        nextEdges.forEach((edge) => edges.set(edge.id, cloneEdge(edge)));
        nextPages.forEach((page) => pageMap.set(page.id, { ...page }));
        nextComments.forEach((comment) => commentsMap.set(comment.id, { ...comment }));
      }, IMPORT_ORIGIN);
      setActivePageId(nextPages[0].id);
      undoManagerRef.current?.clear();
      setStatus(`已恢复版本“${snapshot.name}”。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "版本恢复失败");
    } finally {
      probe.destroy();
      setIsVersionLoading(false);
    }
  }, [isReadOnly, peerId, roomId, roomToken]);

  const deleteVersion = useCallback(async (snapshot: DiagramVersionSnapshot) => {
    if (roomRole !== "OWNER" || snapshot.serverId === undefined) return;
    if (!window.confirm(`删除版本“${snapshot.name}”后无法恢复，是否继续？`)) return;
    setIsVersionLoading(true);
    try {
      await publicDeleteTransferDiagramVersion(roomId, snapshot.serverId, { roomToken, peerId });
      versionsRef.current = versionsRef.current.filter((version) => version.id !== snapshot.id);
      setVersions(versionsRef.current);
      setStatus(`已删除版本“${snapshot.name}”。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "删除流程图版本失败");
    } finally {
      setIsVersionLoading(false);
    }
  }, [peerId, roomId, roomRole, roomToken]);

  const openContextMenu = useCallback((event: React.MouseEvent<HTMLDivElement>) => {
    event.preventDefault();
    const graph = runtimeRef.current?.graph;
    if (!graph) {
      return;
    }
    const point = graph.getPointForEvent(event.nativeEvent);
    const cell = graph.getCellAt(point.x, point.y);
    if (cell && !graph.isCellSelected(cell)) {
      graph.setSelectionCell(cell);
    }
    const bounds = event.currentTarget.getBoundingClientRect();
    setContextMenu({
      x: Math.min(event.clientX - bounds.left, Math.max(8, bounds.width - 176)),
      y: Math.min(event.clientY - bounds.top, Math.max(8, bounds.height - 280)),
    });
    graphContainerRef.current?.focus();
  }, []);

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
    if (modifier && key === "c") {
      event.preventDefault();
      copySelection();
      return;
    }
    if (modifier && key === "a") {
      event.preventDefault();
      graph.selectAll();
      return;
    }
    if (isReadOnly) return;
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
  }, [copySelection, duplicateSelection, isReadOnly, pasteSelection, refreshUndoState, removeSelection]);

  const totalPeers = Math.max(1, peerCount + 1);
  const selectedCountLabel = selection.ids.length > 0 ? ` · 已选 ${selection.ids.length}` : "";
  const activePageName = pages.find((page) => page.id === activePageId)?.name ?? "页面 1";
  const canvasBackground = theme === "dark" ? "#11151d" : "#f5f7fb";
  const gridColor = theme === "dark" ? "rgba(148,163,184,.13)" : "rgba(100,116,139,.14)";

  const diagram = (
    <section
      className={(isExpanded
        ? "fixed inset-0 z-[90] h-[100dvh] overflow-hidden bg-zinc-100 dark:bg-zinc-950"
        : "mt-5 rounded-2xl border border-black/[0.07] bg-zinc-50/70 p-3 shadow-[0_18px_60px_-36px_rgba(15,23,42,0.45)] dark:border-white/[0.08] dark:bg-zinc-950/55 sm:p-4") + (isActive ? "" : " hidden")}
      aria-hidden={!isActive}
    >
      <input
        ref={importInputRef}
        type="file"
        accept={`${DIAGRAM_FILE_EXTENSION},${DRAWIO_FILE_EXTENSION},${VISIO_VSDX_FILE_EXTENSION},${VISIO_VDX_FILE_EXTENSION},.mmd,.mermaid,.md,.puml,.plantuml,.pu,application/json,application/xml,text/xml,${DIAGRAM_FILE_MIME},${DRAWIO_FILE_MIME},${VISIO_VDX_MIME}`}
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
        <div className="flex flex-wrap items-center justify-between gap-4 px-1 pb-1">
          <div className="flex min-w-0 items-center gap-3">
            <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-zinc-950 text-white shadow-sm dark:bg-cyan-300 dark:text-zinc-950">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" viewBox="0 0 24 24" aria-hidden="true">
                <rect x="3" y="4" width="6" height="5" rx="1" /><rect x="15" y="15" width="6" height="5" rx="1" /><path d="M9 6.5h4a3 3 0 0 1 3 3V15M12 12H8a3 3 0 0 0-3 3v1" />
              </svg>
            </div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2.5">
                <div>
                  <h2 className="text-sm font-semibold tracking-tight text-zinc-950 dark:text-white">专业流程图</h2>
                  <p className="mt-0.5 text-[10px] text-zinc-500 dark:text-zinc-400">{activePageName} · 实时协作工作区</p>
                </div>
                {onSwitchToWhiteboard ? (
                  <div className="flex rounded-lg border border-black/[0.07] bg-white/70 p-0.5 shadow-sm dark:border-white/[0.08] dark:bg-white/[0.04]">
                    <button
                      type="button"
                      className="rounded-md px-2.5 py-1 text-[10px] font-medium text-zinc-500 transition hover:bg-black/[0.04] hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/[0.06] dark:hover:text-white"
                      onClick={switchToWhiteboard}
                    >
                      自由白板
                    </button>
                    <button type="button" className="rounded-md bg-zinc-950 px-2.5 py-1 text-[10px] font-semibold text-white shadow-sm dark:bg-cyan-300 dark:text-zinc-950">
                      专业流程图
                    </button>
                  </div>
                ) : null}
                <span className="inline-flex items-center gap-1.5 rounded-full border border-black/[0.06] bg-white/70 px-2 py-1 text-[10px] font-medium text-zinc-600 dark:border-white/[0.08] dark:bg-white/[0.04] dark:text-zinc-300">
                  <span className={`h-1.5 w-1.5 rounded-full ${isConnected ? "bg-emerald-500 shadow-[0_0_0_3px_rgba(16,185,129,0.12)]" : "bg-zinc-400"}`} />
                  {isConnected ? "实时同步" : "本地编辑"}
                </span>
                <span className="hidden text-[10px] text-zinc-400 xl:inline">{totalPeers} 位协作者 · {nodeCount} 个节点 · {edgeCount} 条连线</span>
              </div>
            </div>
          </div>
          <button type="button" className="inline-flex h-9 items-center gap-2 rounded-lg border border-black/[0.08] bg-white px-3 text-tiny font-semibold text-zinc-700 shadow-sm transition hover:-translate-y-px hover:border-cyan-400 hover:text-cyan-800 dark:border-white/[0.1] dark:bg-white/[0.05] dark:text-zinc-200 dark:hover:border-cyan-300/50 dark:hover:text-cyan-100" onClick={() => setIsExpanded(true)}>
            <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 2H2v4M10 2h4v4M6 14H2v-4M10 14h4v-4" /></svg>
            全屏编辑
          </button>
        </div>
      ) : null}

      <div className={isExpanded
        ? "absolute inset-0 flex min-h-0 flex-col overflow-hidden bg-zinc-100 dark:bg-[#090c11]"
        : "mt-3 flex h-[min(78dvh,680px)] min-h-[540px] min-w-0 flex-col overflow-hidden rounded-xl border border-black/[0.09] bg-white shadow-[0_24px_70px_-38px_rgba(15,23,42,0.55)] dark:border-white/[0.09] dark:bg-[#0c1016] sm:h-[680px] md:h-[720px] lg:h-[760px] xl:h-[820px]"}
      >
        <div className="flex shrink-0 flex-nowrap items-center gap-0.5 overflow-x-auto border-b border-black/[0.07] bg-white/95 px-1.5 py-1 backdrop-blur-xl [scrollbar-width:none] dark:border-white/[0.08] dark:bg-[#11161e]/95 sm:px-2 sm:py-1.5" role="toolbar" aria-label="流程图操作">
          <div className="mr-1 flex h-8 shrink-0 items-center gap-2 border-r border-black/[0.07] pr-2 dark:border-white/[0.08] sm:mr-2 sm:pr-3">
            <span className="grid h-6 w-6 place-items-center rounded-md bg-zinc-950 text-white dark:bg-cyan-300 dark:text-zinc-950">
              <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.7" viewBox="0 0 16 16" aria-hidden="true"><rect x="1.5" y="2" width="4" height="3.5" rx=".7" /><rect x="10.5" y="10.5" width="4" height="3.5" rx=".7" /><path d="M5.5 3.7h2.2a2 2 0 0 1 2 2v4.8" /></svg>
            </span>
            <span className="hidden min-w-0 sm:block">
              <span className="block max-w-28 truncate text-[11px] font-semibold text-zinc-800 dark:text-zinc-100">{activePageName}</span>
              <span className="block text-[9px] text-zinc-400">专业流程图</span>
            </span>
          </div>
          {isExpanded ? (
            <>
              {onSwitchToWhiteboard ? (
                <DiagramToolbarButton label="白板" onClick={() => {
                  setIsExpanded(false);
                  switchToWhiteboard();
                }} />
              ) : null}
              <DiagramToolbarButton label="退出全屏" onClick={() => setIsExpanded(false)} />
              <span className="mx-1 h-6 w-px shrink-0 bg-black/[0.07] dark:bg-white/[0.08]" />
            </>
          ) : null}
          <DiagramToolbarButton label={isRoleReadOnly ? "访客只读" : localReadOnly ? "只读预览" : "编辑模式"} disabled={isRoleReadOnly} onClick={() => {
            setLocalReadOnly((value) => !value);
            setContextMenu(null);
            setStatus(isReadOnly ? "已恢复编辑模式。" : "已进入本地只读预览，协作更新仍会继续接收。");
          }} />
          <span className="mx-1 h-6 w-px shrink-0 bg-black/[0.07] dark:bg-white/[0.08]" />
          <DiagramToolbarButton label="撤销" shortcut="⌘Z" disabled={isReadOnly || !canUndo} onClick={() => {
            undoManagerRef.current?.undo();
            refreshUndoState();
          }} />
          <DiagramToolbarButton label="重做" shortcut="⇧⌘Z" disabled={isReadOnly || !canRedo} onClick={() => {
            undoManagerRef.current?.redo();
            refreshUndoState();
          }} />
          <span className="mx-1 h-6 w-px shrink-0 bg-black/[0.07] dark:bg-white/[0.08]" />
          <DiagramToolbarMenu
            label={selection.ids.length > 0 ? `编辑 · ${selection.ids.length}` : "编辑"}
            items={[
              { key: "copy", label: "复制", shortcut: "⌘C", disabled: selection.ids.length === 0 },
              { key: "paste", label: "粘贴", shortcut: "⌘V", disabled: isReadOnly },
              { key: "duplicate", label: "创建副本", shortcut: "⌘D", disabled: isReadOnly || selection.ids.length === 0 },
              { key: "copy-format", label: "复制格式", disabled: selection.ids.length !== 1 },
              { key: "apply-format", label: "应用格式", disabled: isReadOnly || !hasCopiedFormat || selection.ids.length === 0 },
              { key: "delete", label: "删除", shortcut: "Del", disabled: isReadOnly || selection.ids.length === 0, danger: true },
            ]}
            onAction={(key) => {
              if (key === "copy") copySelection();
              else if (key === "paste") pasteSelection();
              else if (key === "duplicate") duplicateSelection();
              else if (key === "copy-format") copyFormat();
              else if (key === "apply-format") applyFormat();
              else if (key === "delete") removeSelection();
            }}
          />
          <DiagramToolbarMenu
            label="排列"
            items={[
              { key: "group", label: "组合", disabled: isReadOnly || selection.ids.length < 2 },
              { key: "ungroup", label: "取消组合", disabled: isReadOnly || !selection.isNode },
              { key: "bring-front", label: "置于顶层", disabled: isReadOnly || selection.ids.length === 0 },
              { key: "send-back", label: "置于底层", disabled: isReadOnly || selection.ids.length === 0 },
              { key: "distribute-horizontal", label: "水平等距分布", disabled: isReadOnly || selection.ids.length < 3 },
              { key: "distribute-vertical", label: "垂直等距分布", disabled: isReadOnly || selection.ids.length < 3 },
              { key: "align-left", label: "左对齐", disabled: isReadOnly || selection.ids.length < 2 },
              { key: "align-center", label: "水平居中", disabled: isReadOnly || selection.ids.length < 2 },
              { key: "align-right", label: "右对齐", disabled: isReadOnly || selection.ids.length < 2 },
              { key: "align-top", label: "顶部对齐", disabled: isReadOnly || selection.ids.length < 2 },
              { key: "align-middle", label: "垂直居中", disabled: isReadOnly || selection.ids.length < 2 },
              { key: "align-bottom", label: "底部对齐", disabled: isReadOnly || selection.ids.length < 2 },
              { key: "layout-north", label: "自动布局：上到下", disabled: isReadOnly },
              { key: "layout-east", label: "自动布局：左到右", disabled: isReadOnly },
            ]}
            onAction={(key) => {
              if (key === "group") groupSelection();
              else if (key === "ungroup") ungroupSelection();
              else if (key === "bring-front") withGraph((graph) => graph.orderCells(false));
              else if (key === "send-back") withGraph((graph) => graph.orderCells(true));
              else if (key === "distribute-horizontal") distributeSelection("horizontal");
              else if (key === "distribute-vertical") distributeSelection("vertical");
              else if (key === "align-left") alignSelection("left");
              else if (key === "align-center") alignSelection("center");
              else if (key === "align-right") alignSelection("right");
              else if (key === "align-top") alignSelection("top");
              else if (key === "align-middle") alignSelection("middle");
              else if (key === "align-bottom") alignSelection("bottom");
              else if (key === "layout-north") runLayout("north");
              else if (key === "layout-east") runLayout("east");
            }}
          />
          <DiagramToolbarMenu
            label="协作"
            items={[
              { key: "comment", label: "添加评论", disabled: isReadOnly },
              { key: "version", label: isVersionLoading ? "版本处理中" : "创建版本", disabled: isRoleReadOnly || isVersionLoading },
            ]}
            onAction={(key) => {
              if (key === "comment") addComment();
              else if (key === "version") void createVersion();
            }}
          />
          <DiagramToolbarMenu
            label="视图"
            items={[
              { key: "zoom-in", label: "放大" },
              { key: "zoom-out", label: "缩小" },
              { key: "fit", label: "适应画布" },
              { key: "actual", label: "实际大小 100%" },
              { key: "minimap", label: showMinimap ? "隐藏小地图" : "显示小地图" },
            ]}
            onAction={(key) => {
              if (key === "zoom-in") withGraph((graph) => graph.zoomIn());
              else if (key === "zoom-out") withGraph((graph) => graph.zoomOut());
              else if (key === "fit") withGraph((graph) => graph.getPlugin<FitPlugin>("fit")?.fitCenter({ margin: 28 }));
              else if (key === "actual") withGraph((graph) => graph.zoomActual());
              else if (key === "minimap") setShowMinimap((value) => !value);
            }}
          />
          <DiagramToolbarMenu
            label="文件"
            items={[
              { key: "import", label: isImporting ? "导入中" : "导入文件", disabled: isReadOnly || isImporting },
              { key: "export-stdg", label: "导出 shuai-tunnel (.stdg)", disabled: nodeCount === 0 && edgeCount === 0 },
              { key: "export-drawio", label: "导出 draw.io", disabled: nodeCount === 0 && edgeCount === 0 },
              { key: "export-svg", label: "导出 SVG", disabled: nodeCount === 0 && edgeCount === 0 },
              { key: "export-png", label: "导出 PNG", disabled: nodeCount === 0 && edgeCount === 0 },
              { key: "export-pdf", label: "导出 PDF", disabled: (nodesMapRef.current?.size ?? 0) === 0 },
              { key: "export-mermaid", label: "导出 Mermaid", disabled: (nodesMapRef.current?.size ?? 0) === 0 },
              { key: "export-plantuml", label: "导出 PlantUML", disabled: (nodesMapRef.current?.size ?? 0) === 0 },
              { key: "export-visio", label: "导出 Visio VDX", disabled: (nodesMapRef.current?.size ?? 0) === 0 },
              { key: "clear", label: "清空当前流程图", disabled: isReadOnly || (nodeCount === 0 && edgeCount === 0), danger: true },
            ]}
            onAction={(key) => {
              if (key === "import") importInputRef.current?.click();
              else if (key === "export-stdg") exportDiagram();
              else if (key === "export-drawio") exportDrawio();
              else if (key === "export-svg") exportSvg();
              else if (key === "export-png") void exportPng();
              else if (key === "export-pdf") void exportPdf();
              else if (key === "export-mermaid") exportMermaid();
              else if (key === "export-plantuml") exportPlantUml();
              else if (key === "export-visio") exportVisio();
              else if (key === "clear") clearDiagram();
            }}
          />
        </div>

        <div className="flex h-10 shrink-0 items-end border-b border-black/[0.07] bg-zinc-50/90 px-2 dark:border-white/[0.08] dark:bg-[#0d1118]" aria-label="流程图页面">
          <div className="flex min-w-0 flex-1 items-end gap-0.5 overflow-x-auto">
            <span className="mb-2 mr-1 shrink-0 px-1 text-[9px] font-semibold uppercase tracking-[0.16em] text-zinc-400">Pages</span>
            {pages.map((page) => (
              <button
                key={page.id}
                type="button"
                aria-pressed={page.id === activePageId}
                className={`relative h-9 shrink-0 rounded-t-lg border border-b-0 px-4 text-[11px] font-medium transition ${page.id === activePageId
                  ? "border-black/[0.08] bg-white text-zinc-900 after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-cyan-500 dark:border-white/[0.1] dark:bg-[#151b24] dark:text-white dark:after:bg-cyan-300"
                  : "border-transparent text-zinc-500 hover:bg-black/[0.035] hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/[0.04] dark:hover:text-zinc-100"}`}
                onClick={() => {
                  if (page.id !== activePageId) {
                    flushGraphRef.current();
                    setActivePageId(page.id);
                    setStatus(`已切换到“${page.name}”。`);
                  }
                }}
                onDoubleClick={!isReadOnly && page.id === activePageId ? renamePage : undefined}
              >
                {page.name}
              </button>
            ))}
          </div>
          <div className="mb-1 ml-2 shrink-0 border-l border-black/[0.07] pl-1.5 dark:border-white/[0.08]">
            <DiagramToolbarMenu
              label={`${pages.length} 页`}
              compact
              placement="bottom-end"
              items={[
                { key: "add", label: "新增页面", disabled: isReadOnly },
                { key: "rename", label: "重命名当前页", disabled: isReadOnly },
                { key: "duplicate", label: "复制当前页", disabled: isReadOnly },
                { key: "delete", label: "删除当前页", disabled: isReadOnly || pages.length <= 1, danger: true },
              ]}
              onAction={(key) => {
                if (key === "add") addPage();
                else if (key === "rename") renamePage();
                else if (key === "duplicate") duplicatePage();
                else if (key === "delete") deletePage();
              }}
            />
          </div>
        </div>

        <div className="flex h-11 shrink-0 items-center justify-between border-b border-black/[0.07] bg-white/95 px-2 dark:border-white/[0.08] dark:bg-[#11161e]/95 lg:hidden">
          <div className="grid grid-cols-3 gap-1 rounded-lg bg-black/[0.035] p-1 dark:bg-white/[0.045]" role="toolbar" aria-label="移动端流程图面板">
            <CompactPanelButton label="图库" active={compactPanel === "library"} onClick={() => setCompactPanel((current) => current === "library" ? null : "library")}>
              <path d="M3 3h4v4H3zM9 3h4v4H9zM3 9h4v4H3zM9 9h4v4H9z" />
            </CompactPanelButton>
            <CompactPanelButton label="画布" active={compactPanel === null} onClick={() => setCompactPanel(null)}>
              <path d="M2.5 3.5h11v9h-11zM5 6h6M5 8.5h4" />
            </CompactPanelButton>
            <CompactPanelButton label="属性" active={compactPanel === "inspector"} onClick={() => setCompactPanel((current) => current === "inspector" ? null : "inspector")}>
              <path d="M3 4h10M3 8h10M3 12h10M6 2.5v3M10 6.5v3M7 10.5v3" />
            </CompactPanelButton>
          </div>
          <span className="min-w-0 truncate pl-2 text-right text-[9px] text-zinc-400">{nodeCount} 节点 · {edgeCount} 连线</span>
        </div>

        <div className="relative grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[268px_minmax(0,1fr)_264px]">
          {compactPanel ? (
            <button
              type="button"
              aria-label="关闭侧边面板"
              className="absolute inset-0 z-20 bg-zinc-950/35 backdrop-blur-[1px] lg:hidden"
              onClick={() => setCompactPanel(null)}
            />
          ) : null}
          <aside className={`${compactPanel === "library" ? "block" : "hidden"} absolute inset-y-0 left-0 z-30 w-[min(86vw,310px)] max-w-full overflow-y-auto border-r border-black/[0.07] bg-zinc-50 p-3 shadow-2xl dark:border-white/[0.08] dark:bg-[#0f141c] lg:static lg:z-auto lg:block lg:w-auto lg:max-w-none lg:shadow-none`}>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-[11px] font-semibold text-zinc-800 dark:text-zinc-100">图形库</div>
                <div className="mt-0.5 text-[9px] text-zinc-400">拖拽或点击添加</div>
              </div>
              <span className="flex items-center gap-1.5">
                <span className="rounded-md bg-black/[0.04] px-1.5 py-0.5 font-mono text-[9px] text-zinc-400 dark:bg-white/[0.05]">{stencilCatalog?.shapeCount ? `${stencilCatalog.shapeCount + NODE_PALETTE.length}` : NODE_PALETTE.length}</span>
                <button type="button" className="grid h-8 w-8 place-items-center rounded-lg text-zinc-400 hover:bg-black/[0.05] hover:text-zinc-700 dark:hover:bg-white/[0.06] dark:hover:text-zinc-100 lg:hidden" aria-label="关闭图形库" onClick={() => setCompactPanel(null)}>
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8M12 4l-8 8" /></svg>
                </button>
              </span>
            </div>
            <label className="relative mt-3 block min-w-0">
              <svg className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4.5" /><path d="m10.5 10.5 3 3" /></svg>
              <input
                value={paletteQuery}
                placeholder="搜索图形"
                aria-label="搜索图形"
                className="h-9 w-full rounded-lg border border-black/[0.07] bg-white pl-8 pr-2.5 text-[11px] text-zinc-800 shadow-sm outline-none transition placeholder:text-zinc-400 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10 dark:border-white/[0.08] dark:bg-white/[0.035] dark:text-zinc-100"
                onChange={(event) => setPaletteQuery(event.currentTarget.value)}
              />
            </label>
            <div className="mt-4 block">
              <div className="text-[9px] font-semibold uppercase tracking-[0.14em] text-zinc-400">快速模板</div>
              <div className="mt-2 grid grid-cols-3 gap-1.5">
                {([['approval', '审批'], ['architecture', '架构'], ['er', 'ER']] as const).map(([id, label]) => (
                  <button
                    key={id}
                    type="button"
                    disabled={isReadOnly}
                    className="group min-w-0 rounded-lg border border-cyan-500/20 bg-cyan-50/70 px-2 py-2 text-center transition hover:border-cyan-500/50 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-35 dark:border-cyan-300/15 dark:bg-cyan-300/[0.06] dark:hover:border-cyan-300/35 dark:hover:bg-cyan-300/[0.1]"
                    onClick={() => {
                      insertTemplate(id);
                      setCompactPanel(null);
                    }}
                  >
                    <span className="block text-[10px] font-semibold text-cyan-800 dark:text-cyan-100">{label}</span>
                    <span className="mt-0.5 block text-[8px] text-cyan-700/60 dark:text-cyan-200/50">模板</span>
                  </button>
                ))}
              </div>
            </div>
            {PALETTE_CATEGORIES.map((category) => {
              const query = paletteQuery.trim().toLowerCase();
              const items = NODE_PALETTE.filter((item) => item.category === category
                && (!query || `${item.label} ${item.detail} ${item.category}`.toLowerCase().includes(query)));
              if (items.length === 0) return null;
              const isCategoryOpen = Boolean(query) || openPaletteCategories.has(category);
              return (
                <div key={category} className="mt-2.5 block border-t border-black/[0.05] pt-2.5 dark:border-white/[0.06]">
                  <button
                    type="button"
                    className="flex h-8 w-full items-center justify-between rounded-md px-1.5 text-left transition hover:bg-black/[0.035] dark:hover:bg-white/[0.04]"
                    aria-expanded={isCategoryOpen}
                    onClick={() => setOpenPaletteCategories((current) => {
                      const next = new Set(current);
                      if (next.has(category)) next.delete(category);
                      else next.add(category);
                      return next;
                    })}
                  >
                    <span className="flex items-center gap-1.5 text-[10px] font-semibold text-zinc-600 dark:text-zinc-300">
                      <svg className={`h-3 w-3 text-zinc-400 transition-transform ${isCategoryOpen ? "rotate-90" : ""}`} fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 16 16" aria-hidden="true"><path d="m6 3 5 5-5 5" /></svg>
                      {category}
                    </span>
                    <span className="font-mono text-[8px] text-zinc-400">{items.length}</span>
                  </button>
                  <div className={`mt-2 grid-cols-3 gap-1 ${isCategoryOpen ? "grid" : "hidden"}`}>
                    {items.map((item) => (
                      <button
                        key={item.kind}
                        ref={(element) => {
                          const id = `builtin:${item.kind}`;
                          if (element) {
                            paletteElementRefs.current.set(id, element);
                            draggablePaletteItemsRef.current.set(id, item);
                          } else {
                            paletteElementRefs.current.delete(id);
                            draggablePaletteItemsRef.current.delete(id);
                          }
                        }}
                        type="button"
                        disabled={isReadOnly}
                        title={`${item.label} · ${item.detail}`}
                        className="group flex min-h-[68px] min-w-0 flex-col items-center gap-1 rounded-lg border border-black/[0.07] bg-white px-1 py-1.5 text-center shadow-[0_1px_1px_rgba(15,23,42,0.03)] transition hover:-translate-y-px hover:border-cyan-400 hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 disabled:cursor-not-allowed disabled:opacity-35 dark:border-white/[0.08] dark:bg-white/[0.035] dark:hover:border-cyan-300/40 dark:hover:bg-cyan-300/[0.06]"
                        onClick={() => {
                          insertNode(item.kind);
                          setCompactPanel(null);
                        }}
                      >
                        <DiagramNodeGlyph kind={item.kind} />
                        <span className="min-w-0 w-full">
                          <span className="block truncate text-[8px] font-semibold text-zinc-800 dark:text-zinc-100">{item.label}</span>
                          <span className="block truncate text-[7px] text-zinc-400">{item.detail}</span>
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
            {paletteQuery.trim() && stencilCatalog ? (
              <div className="mt-3 min-w-0 border-t border-black/[0.05] pt-3 dark:border-white/[0.06]">
                <div className="mb-2 flex items-center justify-between px-1">
                  <span className="text-[10px] font-semibold text-zinc-600 dark:text-zinc-300">draw.io 全库结果</span>
                  <span className="font-mono text-[8px] text-zinc-400">{stencilSearchResults.length}{stencilSearchResults.length === STENCIL_SEARCH_LIMIT ? "+" : ""}</span>
                </div>
                {stencilSearchResults.length ? (
                  <div className="grid grid-cols-3 gap-1">
                    {stencilSearchResults.map(({ library, shape }) => {
                      const item = stencilPaletteItem(library, shape);
                      const dragId = `stencil-search:${shape.id}`;
                      const isLoaded = loadedStencilLibraries.has(library.path);
                      return (
                        <button
                          key={dragId}
                          ref={(element) => {
                            if (element && isLoaded) {
                              paletteElementRefs.current.set(dragId, element);
                              draggablePaletteItemsRef.current.set(dragId, item);
                            } else {
                              paletteElementRefs.current.delete(dragId);
                              draggablePaletteItemsRef.current.delete(dragId);
                            }
                          }}
                          type="button"
                          disabled={isReadOnly}
                          title={`${library.name} / ${shape.name}`}
                          className="group flex min-h-[68px] min-w-0 flex-col items-center justify-center rounded-lg border border-black/[0.07] bg-white px-1 py-1.5 text-center transition hover:-translate-y-px hover:border-cyan-400 hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 disabled:opacity-35 dark:border-white/[0.08] dark:bg-white/[0.035] dark:hover:border-cyan-300/40 dark:hover:bg-cyan-300/[0.06]"
                          onClick={() => {
                            void insertStencilNode(library, shape);
                            setCompactPanel(null);
                          }}
                        >
                          <DrawioStencilGlyph stencilName={shape.shape} loaded={isLoaded} />
                          <span className="mt-1 block w-full truncate text-[8px] font-semibold text-zinc-700 dark:text-zinc-200">{shape.name}</span>
                          <span className="block w-full truncate text-[6.5px] text-zinc-400">{library.name}</span>
                        </button>
                      );
                    })}
                  </div>
                ) : <div className="rounded-lg border border-dashed border-black/10 p-4 text-center text-[10px] text-zinc-400 dark:border-white/10">未找到 draw.io 图形</div>}
              </div>
            ) : null}
            {!paletteQuery.trim() && stencilCatalog ? (
              <div className="mt-3 min-w-0 border-t border-black/[0.05] pt-3 dark:border-white/[0.06]">
                <div className="mb-1 flex items-center justify-between px-1">
                  <span className="text-[9px] font-semibold uppercase tracking-[0.14em] text-zinc-400">draw.io 完整图库</span>
                  <span className="font-mono text-[8px] text-zinc-400">{stencilCollections.length} 类 · {stencilCatalog.libraryCount} 库</span>
                </div>
                {stencilCatalog.groups.map((group) => {
                  const collections = stencilCollections.filter((collection) => collection.group === group.id);
                  if (!collections.length) return null;
                  const isGroupOpen = openStencilGroups.has(group.id);
                  return (
                    <div key={group.id} className="mt-1.5 overflow-hidden rounded-lg border border-black/[0.06] bg-white/60 dark:border-white/[0.07] dark:bg-white/[0.02]">
                      <button
                        type="button"
                        className="flex h-8 w-full items-center justify-between px-2 text-left transition hover:bg-black/[0.03] dark:hover:bg-white/[0.04]"
                        aria-expanded={isGroupOpen}
                        onClick={() => setOpenStencilGroups((current) => {
                          const next = new Set(current);
                          if (next.has(group.id)) next.delete(group.id);
                          else next.add(group.id);
                          return next;
                        })}
                      >
                        <span className="flex min-w-0 items-center gap-1.5 text-[10px] font-semibold text-zinc-700 dark:text-zinc-200">
                          <svg className={`h-3 w-3 shrink-0 text-zinc-400 transition-transform ${isGroupOpen ? "rotate-90" : ""}`} fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 16 16" aria-hidden="true"><path d="m6 3 5 5-5 5" /></svg>
                          <span className="truncate">{group.name}</span>
                        </span>
                        <span className="font-mono text-[8px] text-zinc-400">{collections.length}</span>
                      </button>
                      {isGroupOpen ? (
                        <div className="border-t border-black/[0.05] p-1 dark:border-white/[0.06]">
                          {collections.map((collection) => {
                            const isActive = activeStencilCollectionId === collection.id;
                            const visibleItems = collection.items.slice(0, stencilShapeLimit);
                            return (
                              <div key={collection.id} className="mt-0.5 first:mt-0">
                                <button
                                  type="button"
                                  className={`flex h-7 w-full items-center justify-between rounded-md px-2 text-left transition ${isActive ? "bg-cyan-500/10 text-cyan-800 dark:text-cyan-100" : "text-zinc-600 hover:bg-black/[0.035] dark:text-zinc-300 dark:hover:bg-white/[0.04]"}`}
                                  onClick={() => openStencilCollection(collection)}
                                >
                                  <span className="truncate text-[9px] font-medium">{collection.name}</span>
                                  <span className="ml-2 shrink-0 font-mono text-[7px] text-zinc-400">{loadingStencilCollection === collection.id ? "加载中" : collection.libraryCount > 1 ? `${collection.shapeCount} · ${collection.libraryCount}库` : collection.shapeCount}</span>
                                </button>
                                {isActive ? (
                                  <div className="mt-1.5 grid grid-cols-3 gap-1 px-1 pb-1.5">
                                    {visibleItems.map(({ library, shape }) => {
                                      const item = stencilPaletteItem(library, shape);
                                      const dragId = `stencil:${shape.id}`;
                                      const isLoaded = loadedStencilLibraries.has(library.path);
                                      return (
                                        <button
                                          key={dragId}
                                          ref={(element) => {
                                            if (element && isLoaded) {
                                              paletteElementRefs.current.set(dragId, element);
                                              draggablePaletteItemsRef.current.set(dragId, item);
                                            } else {
                                              paletteElementRefs.current.delete(dragId);
                                              draggablePaletteItemsRef.current.delete(dragId);
                                            }
                                          }}
                                          type="button"
                                          disabled={isReadOnly}
                                          title={`${collection.name} / ${library.name} / ${shape.name}`}
                                          className="group flex min-h-[68px] min-w-0 flex-col items-center justify-center rounded-lg border border-black/[0.07] bg-white px-1 py-1.5 text-center transition hover:-translate-y-px hover:border-cyan-400 hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 disabled:opacity-35 dark:border-white/[0.08] dark:bg-white/[0.035] dark:hover:border-cyan-300/40 dark:hover:bg-cyan-300/[0.06]"
                                          onClick={() => {
                                            void insertStencilNode(library, shape);
                                            setCompactPanel(null);
                                          }}
                                        >
                                          <DrawioStencilGlyph stencilName={shape.shape} loaded={isLoaded} />
                                          <span className="mt-1 block w-full truncate text-[8px] font-semibold text-zinc-700 dark:text-zinc-200">{shape.name}</span>
                                          {collection.libraryCount > 1 ? <span className="block w-full truncate text-[6.5px] text-zinc-400">{library.name}</span> : null}
                                        </button>
                                      );
                                    })}
                                    {collection.shapeCount > stencilShapeLimit ? (
                                      <button type="button" className="col-span-3 rounded-md border border-dashed border-black/10 px-2 py-2 text-[9px] font-medium text-cyan-700 hover:bg-cyan-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 dark:border-white/10 dark:text-cyan-200 dark:hover:bg-cyan-300/10" onClick={() => setStencilShapeLimit((current) => current + STENCIL_PAGE_SIZE)}>
                                        加载更多 · {collection.shapeCount - stencilShapeLimit} 个
                                      </button>
                                    ) : null}
                                  </div>
                                ) : null}
                              </div>
                            );
                          })}
                        </div>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : null}
          </aside>

          <div
            className="relative min-h-0 overflow-hidden bg-zinc-100 dark:bg-[#0b0f15]"
            onKeyDown={handleKeyDown}
            onPointerDown={() => {
              setContextMenu(null);
              graphContainerRef.current?.focus();
            }}
            onContextMenu={openContextMenu}
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
            {Object.values(remotePresences).filter((presence) => presence.pageId === activePageId && presence.cursor).map((presence) => {
              const graph = runtimeRef.current?.graph;
              const container = graphContainerRef.current;
              const scale = graph?.getView().scale ?? 1;
              const translate = graph?.getView().translate ?? new Point();
              const left = ((presence.cursor?.x ?? 0) + translate.x) * scale - (container?.scrollLeft ?? 0);
              const top = ((presence.cursor?.y ?? 0) + translate.y) * scale - (container?.scrollTop ?? 0);
              return (
                <div key={presence.peerId} className="pointer-events-none absolute z-30" style={{ left, top }}>
                  <span className="block h-3 w-3 rotate-45 border-l-2 border-t-2 border-fuchsia-500" />
                  <span className="ml-2 rounded bg-fuchsia-600 px-1.5 py-0.5 text-[9px] font-semibold text-white shadow">{presence.peerId.slice(0, 12)} · {presence.selectedIds.length} selected</span>
                </div>
              );
            })}
            {showMinimap ? (
              <div className="absolute bottom-12 right-3 z-20 hidden h-28 w-40 overflow-hidden rounded-xl border border-black/[0.1] bg-white/95 shadow-[0_12px_35px_-12px_rgba(15,23,42,0.4)] backdrop-blur-xl dark:border-white/[0.12] dark:bg-[#151b24]/95 sm:block sm:h-32 sm:w-48">
                <div ref={outlineContainerRef} className="h-full w-full" aria-label="流程图小地图" />
              </div>
            ) : null}
            <div className="pointer-events-none absolute bottom-3 left-3 hidden items-center gap-2 rounded-lg border border-black/[0.08] bg-white/85 px-2.5 py-1.5 text-[9px] text-zinc-500 shadow-sm backdrop-blur-xl dark:border-white/[0.09] dark:bg-[#151b24]/85 dark:text-zinc-400 sm:flex">
              <span className="grid h-4 w-4 place-items-center rounded bg-cyan-500/10 text-[9px] font-bold text-cyan-700 dark:text-cyan-200">?</span>
              拖入节点 · 移动显示参考线 · Shift 点击连线增删折点
            </div>
            {contextMenu ? (
              <div
                className="absolute z-30 w-44 rounded-lg border border-black/10 bg-white p-1.5 text-tiny text-zinc-700 shadow-xl dark:border-white/10 dark:bg-zinc-900 dark:text-zinc-200"
                style={{ left: contextMenu.x, top: contextMenu.y }}
                role="menu"
                onPointerDown={(event) => event.stopPropagation()}
              >
                <ContextMenuAction label="编辑文字" disabled={isReadOnly || selection.ids.length !== 1} onClick={() => {
                  withGraph((graph) => graph.startEditingAtCell(graph.getSelectionCell()));
                  setContextMenu(null);
                }} />
                <ContextMenuAction label="复制" disabled={selection.ids.length === 0} onClick={() => { copySelection(); setContextMenu(null); }} />
                <ContextMenuAction label="创建副本" disabled={isReadOnly || selection.ids.length === 0} onClick={() => { duplicateSelection(); setContextMenu(null); }} />
                <ContextMenuAction label="组合" disabled={isReadOnly || selection.ids.length < 2} onClick={() => { groupSelection(); setContextMenu(null); }} />
                <ContextMenuAction label="取消组合" disabled={isReadOnly || !selection.isNode} onClick={() => { ungroupSelection(); setContextMenu(null); }} />
                <ContextMenuAction label="置于顶层" disabled={isReadOnly || selection.ids.length === 0} onClick={() => {
                  withGraph((graph) => graph.orderCells(false));
                  setContextMenu(null);
                }} />
                <ContextMenuAction label="置于底层" disabled={isReadOnly || selection.ids.length === 0} onClick={() => {
                  withGraph((graph) => graph.orderCells(true));
                  setContextMenu(null);
                }} />
                <ContextMenuAction label="删除" danger disabled={isReadOnly || selection.ids.length === 0} onClick={() => { removeSelection(); setContextMenu(null); }} />
              </div>
            ) : null}
          </div>

          <aside className={`${compactPanel === "inspector" ? "block" : "hidden"} absolute inset-y-0 right-0 z-30 w-[min(86vw,320px)] max-w-full overflow-y-auto border-l border-black/[0.07] bg-zinc-50 shadow-2xl dark:border-white/[0.08] dark:bg-[#0f141c] lg:static lg:z-auto lg:block lg:w-auto lg:max-w-none lg:shadow-none`}>
            <div className="sticky top-0 z-10 flex h-12 items-center justify-between gap-2 border-b border-black/[0.06] bg-zinc-50/95 px-4 backdrop-blur-xl dark:border-white/[0.07] dark:bg-[#0f141c]/95">
              <span>
                <span className="block text-[11px] font-semibold text-zinc-900 dark:text-zinc-100">设计属性</span>
                <span className="block text-[9px] text-zinc-400">样式与行为</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="rounded-md bg-black/[0.04] px-1.5 py-1 text-[9px] font-medium text-zinc-500 dark:bg-white/[0.05] dark:text-zinc-400">{selection.ids.length > 0 ? `${selection.ids.length} 个元素` : "未选择"}</span>
                <button type="button" className="grid h-8 w-8 place-items-center rounded-lg text-zinc-400 hover:bg-black/[0.05] hover:text-zinc-700 dark:hover:bg-white/[0.06] dark:hover:text-zinc-100 lg:hidden" aria-label="关闭设计属性" onClick={() => setCompactPanel(null)}>
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8M12 4l-8 8" /></svg>
                </button>
              </span>
            </div>
            <div className="p-3.5">
            <fieldset disabled={isReadOnly} className={isReadOnly ? "opacity-60" : undefined}>
            {selection.ids.length === 0 ? (
              <div className="rounded-xl border border-dashed border-black/[0.1] bg-white/60 px-4 py-6 text-center dark:border-white/[0.1] dark:bg-white/[0.025]">
                <div className="mx-auto grid h-9 w-9 place-items-center rounded-xl bg-zinc-100 text-zinc-400 dark:bg-white/[0.05]">
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true"><path d="m3 2 9 5-4 1.5L6.5 13z" /><path d="m9 9 3 4" /></svg>
                </div>
                <div className="mt-3 text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">选择画布元素</div>
                <div className="mt-1 text-[10px] leading-4 text-zinc-400">选中节点或连线后，在这里调整文字、颜色、线型与层级。</div>
              </div>
            ) : (
              <div className="space-y-4">
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
                {selection.isNode ? (
                  <div className="space-y-3">
                    <div>
                      <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-400">文字样式</span>
                      <div className="mt-1.5 grid grid-cols-4 gap-1.5">
                        {[12, 14, 18, 24].map((size) => (
                          <InspectorAction key={size} label={`${size}`} active={selection.fontSize === size} onClick={() => updateNodeFontSize(size)} />
                        ))}
                        <InspectorAction label="粗体" active={selection.bold} onClick={() => toggleNodeFontStyle(1)} />
                        <InspectorAction label="斜体" active={selection.italic} onClick={() => toggleNodeFontStyle(2)} />
                        <InspectorAction label="左对齐" active={selection.align === "left"} onClick={() => updateNodeAlign("left")} />
                        <InspectorAction label="居中" active={selection.align === "center"} onClick={() => updateNodeAlign("center")} />
                        <InspectorAction label="右对齐" active={selection.align === "right"} onClick={() => updateNodeAlign("right")} />
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-400">节点操作</span>
                      <div className="mt-1.5 grid grid-cols-2 gap-1.5">
                        <InspectorAction label={selection.locked ? "解锁节点" : "锁定节点"} active={selection.locked} onClick={toggleNodeLock} />
                        <InspectorAction label="旋转 90°" onClick={() => rotateNodes(90)} />
                        {selection.isSwimlane ? (
                          <>
                            <InspectorAction label="添加泳道" onClick={addSwimlaneLane} />
                            <InspectorAction label={selection.swimlaneDirection === "vertical" ? "改为横向泳道" : "改为纵向泳道"} onClick={toggleSwimlaneDirection} />
                          </>
                        ) : null}
                        {selection.isLane ? (
                          <>
                            <InspectorAction label="泳道前移" onClick={() => moveLane(-1)} />
                            <InspectorAction label="泳道后移" onClick={() => moveLane(1)} />
                            <InspectorAction label="删除泳道" onClick={removeLane} />
                          </>
                        ) : null}
                      </div>
                    </div>
                  </div>
                ) : null}
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
                {selection.isEdge ? (
                  <div className="space-y-3">
                    <div>
                      <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-400">连线路由</span>
                      <div className="mt-1.5 grid grid-cols-2 gap-1.5">
                        {([ ["orthogonal", "正交"], ["straight", "直线"], ["elbow", "折线"], ["curved", "曲线"] ] as const).map(([type, label]) => (
                          <InspectorAction
                            key={type}
                            label={label}
                            active={selection.edgeType === type}
                            onClick={() => updateEdgeType(type)}
                          />
                        ))}
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-400">折点</span>
                      <div className="mt-1.5 grid grid-cols-2 gap-1.5">
                        <InspectorAction label="新增折点" onClick={addEdgeWaypoint} />
                        <InspectorAction label="清除折点" onClick={clearEdgeWaypoints} />
                      </div>
                    </div>
                    <ArrowPicker label="起点箭头" selected={selection.startArrow} onSelect={(arrow) => updateArrowType("start", arrow)} />
                    <ArrowPicker label="终点箭头" selected={selection.endArrow} onSelect={(arrow) => updateArrowType("end", arrow)} />
                  </div>
                ) : null}
                <div>
                  <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-400">高级样式</span>
                  <div className="mt-1.5 grid grid-cols-4 gap-1.5">
                    {[25, 50, 75, 100].map((opacity) => (
                      <InspectorAction key={opacity} label={`${opacity}%`} active={selection.opacity === opacity} onClick={() => updateSelectedStyle("opacity", opacity)} />
                    ))}
                    {selection.isNode ? (
                      <>
                        <InspectorAction label="阴影" active={selection.shadow} onClick={() => updateSelectedStyle("shadow", !selection.shadow)} />
                        <InspectorAction label="圆角" active={selection.rounded} onClick={() => updateSelectedStyle("rounded", !selection.rounded)} />
                      </>
                    ) : null}
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
            </fieldset>
            <div className="mt-5 border-t border-black/10 pt-4 dark:border-white/10">
              <div className="flex items-center justify-between gap-2">
                <span className="text-tiny font-semibold text-zinc-900 dark:text-zinc-100">
                  评论 · {comments.filter((comment) => comment.pageId === activePageId).length}
                </span>
                <button
                  type="button"
                  disabled={isReadOnly}
                  className="rounded-md px-2 py-1 text-[10px] font-semibold text-cyan-700 hover:bg-cyan-50 disabled:opacity-35 dark:text-cyan-200 dark:hover:bg-cyan-300/10"
                  onClick={addComment}
                >
                  + 评论
                </button>
              </div>
              <div className="mt-2 space-y-2">
                {comments.filter((comment) => comment.pageId === activePageId).length === 0 ? (
                  <div className="rounded-md border border-dashed border-black/10 p-2 text-[10px] leading-4 text-zinc-400 dark:border-white/10">
                    选中元素后添加评论，可把讨论定位到具体节点或连线。
                  </div>
                ) : comments.filter((comment) => comment.pageId === activePageId).map((comment) => (
                  <div key={comment.id} className={`rounded-lg border p-2 ${comment.resolved
                    ? "border-black/5 bg-black/[0.02] opacity-60 dark:border-white/5 dark:bg-white/[0.02]"
                    : "border-amber-300/60 bg-amber-50/70 dark:border-amber-300/20 dark:bg-amber-300/[0.06]"}`}>
                    <button type="button" className="block w-full text-left" onClick={() => focusComment(comment)}>
                      <span className="block text-[10px] font-semibold text-zinc-700 dark:text-zinc-200">
                        {comment.author.slice(0, 18)}{comment.cellId ? " · 已关联元素" : " · 页面评论"}
                      </span>
                      <span className="mt-1 block whitespace-pre-wrap break-words text-tiny leading-5 text-zinc-600 dark:text-zinc-300">{comment.text}</span>
                      <span className="mt-1 block text-[9px] text-zinc-400">{new Date(comment.createdAt).toLocaleString()}</span>
                    </button>
                    <div className="mt-1.5 flex gap-1">
                      <button type="button" disabled={isReadOnly} className="rounded px-1.5 py-1 text-[9px] text-cyan-700 hover:bg-cyan-100 disabled:opacity-35 dark:text-cyan-200 dark:hover:bg-cyan-300/10" onClick={() => toggleComment(comment)}>
                        {comment.resolved ? "重新打开" : "标记解决"}
                      </button>
                      <button type="button" disabled={isReadOnly} className="rounded px-1.5 py-1 text-[9px] text-red-500 hover:bg-red-50 disabled:opacity-35 dark:text-red-300 dark:hover:bg-red-400/10" onClick={() => deleteComment(comment.id)}>
                        删除
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="mt-5 border-t border-black/10 pt-4 dark:border-white/10">
              <div className="flex items-center justify-between gap-2">
                <span className="text-tiny font-semibold text-zinc-900 dark:text-zinc-100">版本 · {versions.length}</span>
                <button type="button" disabled={isRoleReadOnly || isVersionLoading} className="rounded-md px-2 py-1 text-[10px] font-semibold text-cyan-700 hover:bg-cyan-50 disabled:opacity-35 dark:text-cyan-200 dark:hover:bg-cyan-300/10" onClick={() => void createVersion()}>+ 快照</button>
              </div>
              <p className="mt-1 text-[9px] leading-4 text-zinc-400">{usesServerVersions ? "版本保存在房间服务端，最多保留 50 个。" : "版本快照保存在本次浏览器会话，最多保留 20 个。"}</p>
              <div className="mt-2 space-y-1.5">
                {versions.slice().reverse().map((version) => (
                  <div key={version.id} className="flex items-center justify-between gap-2 rounded-md border border-black/10 p-2 dark:border-white/10">
                    <span className="min-w-0">
                      <span className="block truncate text-[10px] font-semibold text-zinc-700 dark:text-zinc-200">{version.name}</span>
                      <span className="block text-[9px] text-zinc-400">{new Date(version.createdAt).toLocaleString()}</span>
                    </span>
                    <span className="flex shrink-0 gap-1">
                      <button type="button" disabled={isReadOnly || isVersionLoading} className="rounded px-1.5 py-1 text-[9px] text-cyan-700 hover:bg-cyan-50 disabled:opacity-35 dark:text-cyan-200 dark:hover:bg-cyan-300/10" onClick={() => void restoreVersion(version)}>恢复</button>
                      {roomRole === "OWNER" && version.serverId !== undefined ? (
                        <button type="button" disabled={isVersionLoading} className="rounded px-1.5 py-1 text-[9px] text-red-500 hover:bg-red-50 disabled:opacity-35 dark:text-red-300 dark:hover:bg-red-400/10" onClick={() => void deleteVersion(version)}>删除</button>
                      ) : null}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            </div>
          </aside>
        </div>

        <div className="flex h-8 shrink-0 flex-wrap items-center justify-between gap-2 border-t border-black/[0.07] bg-white/95 px-3 text-[9px] text-zinc-500 dark:border-white/[0.08] dark:bg-[#11161e]/95 dark:text-zinc-400">
          <span className="flex min-w-0 items-center gap-2 truncate"><span className={`h-1.5 w-1.5 shrink-0 rounded-full ${isConnected ? "bg-emerald-500" : "bg-zinc-400"}`} />{status}</span>
          <span className="hidden shrink-0 items-center gap-3 font-mono sm:flex"><span>{activePageName}</span><span>{nodeCount} nodes</span><span>{edgeCount} edges{selectedCountLabel}</span></span>
        </div>
      </div>
    </section>
  );

  return isExpanded ? createPortal(diagram, window.document.body) : diagram;
}

function readGraphDocument(graph: Graph, pageId = DEFAULT_PAGE_ID): Pick<DiagramDocumentV1, "nodes" | "edges"> {
  const root = graph.getDefaultParent();
  const nodes: DiagramNode[] = [];
  const edgeCells: Array<{ cell: Cell; zIndex: number }> = [];
  const visit = (parent: Cell, parentId?: string) => {
    graph.getChildEdges(parent).forEach((cell, zIndex) => edgeCells.push({ cell, zIndex }));
    graph.getChildVertices(parent).forEach((cell, zIndex) => {
      const id = cell.getId();
      const geometry = cell.getGeometry();
      if (!id || !geometry) {
        return;
      }
      const style = cell.getStyle() as DiagramCellStyle;
      const kind = isDiagramNodeKind(style.diagramKind) ? style.diagramKind : "process";
      const fontStyle = styleNumber(style.fontStyle, 0);
      nodes.push({
        id,
        kind,
        ...(style.diagramStencilName && style.diagramStencilLibrary
          ? { stencilName: style.diagramStencilName, stencilLibrary: style.diagramStencilLibrary }
          : {}),
        label: String(cell.getValue() ?? "").slice(0, 500),
        x: geometry.x,
        y: geometry.y,
        width: geometry.width,
        height: geometry.height,
        zIndex,
        pageId,
        ...(parentId ? { parentId } : {}),
        ...(style.diagramLocked ? { locked: true } : {}),
        ...(styleNumber(style.rotation, 0) !== 0 ? { rotation: normalizeRotation(styleNumber(style.rotation, 0)) } : {}),
        ...(kind === "swimlane" ? { swimlaneDirection: style.horizontal === false ? "vertical" : "horizontal" } : {}),
        style: {
          fillColor: styleColor(style.fillColor, "#ffffff"),
          strokeColor: styleColor(style.strokeColor, "#475569"),
          fontColor: styleColor(style.fontColor, "#172033"),
          strokeWidth: styleNumber(style.strokeWidth, 2),
          dashed: Boolean(style.dashed),
          ...(style.opacity !== undefined ? { opacity: styleNumber(style.opacity, 100) } : {}),
          ...(style.shadow !== undefined ? { shadow: Boolean(style.shadow) } : {}),
          ...(style.rounded !== undefined ? { rounded: Boolean(style.rounded) } : {}),
          fontSize: Math.max(8, Math.min(96, styleNumber(style.fontSize, 13))),
          bold: (fontStyle & 1) === 1,
          italic: (fontStyle & 2) === 2,
          align: textAlignFromStyle(style.align),
        },
      });
      visit(cell, id);
    });
  };
  visit(root);
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = edgeCells.flatMap(({ cell, zIndex }): DiagramEdge[] => {
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
      ...(cell.getGeometry()?.points?.length ? {
        waypoints: cell.getGeometry()!.points!.slice(0, 128).map((point) => ({ x: point.x, y: point.y })),
      } : {}),
      zIndex,
      pageId,
      style: {
        strokeColor: styleColor(style.strokeColor, "#64748b"),
        fontColor: styleColor(style.fontColor, "#334155"),
        strokeWidth: styleNumber(style.strokeWidth, 2),
        dashed: Boolean(style.dashed),
        edgeType: edgeTypeFromCellStyle(style),
        startArrow: arrowTypeFromStyle(style.startArrow, "none"),
          endArrow: arrowTypeFromStyle(style.endArrow, "block"),
          ...(style.opacity !== undefined ? { opacity: styleNumber(style.opacity, 100) } : {}),
      },
    }];
  });
  return { nodes, edges };
}

function toDiagramVersionSnapshot(version: PublicTransferDiagramVersion): DiagramVersionSnapshot {
  const parsedCreatedAt = Date.parse(version.createdAt);
  return {
    id: `server-${version.id}`,
    serverId: version.id,
    name: version.name,
    createdAt: Number.isFinite(parsedCreatedAt) ? parsedCreatedAt : Date.now(),
    authorPeerId: version.authorPeerId,
    sizeBytes: version.sizeBytes,
  };
}

function replaceYMapForPage<T extends { id: string; pageId?: string }>(map: Y.Map<T>, values: T[], pageId: string) {
  const nextIds = new Set(values.map((value) => value.id));
  for (const [key, value] of map.entries()) {
    if (diagramPageId(value.pageId) === pageId && !nextIds.has(key)) {
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
    const pages = Array.from(probe.getMap<unknown>(PAGES_MAP).values());
    const comments = Array.from(probe.getMap<unknown>(COMMENTS_MAP).values());
    if (!isDiagramGraphState(nodes, edges) || !pages.every(isDiagramPage) || !comments.every(isDiagramComment)) {
      return false;
    }
    const pageIds = new Set((pages as DiagramPage[]).map((page) => page.id));
    return (nodes as DiagramNode[]).every((node) => !node.pageId || pageIds.has(node.pageId))
      && (edges as DiagramEdge[]).every((edge) => !edge.pageId || pageIds.has(edge.pageId))
      && (comments as DiagramComment[]).every((comment) => pageIds.has(comment.pageId));
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
  const style = first.getStyle() as DiagramCellStyle;
  const fontStyle = styleNumber(style.fontStyle, 0);
  const firstKind = isDiagramNodeKind(style.diagramKind) ? style.diagramKind : undefined;
  update({
    ids: cells.map((cell) => cell.getId()).filter((id): id is string => Boolean(id)),
    label: cells.length === 1 ? String(first.getValue() ?? "") : "",
    isNode: cells.some((cell) => cell.isVertex()),
    isEdge: cells.some((cell) => cell.isEdge()),
    fillColor: styleColor(style.fillColor, "#ffffff"),
    strokeColor: styleColor(style.strokeColor, "#475569"),
    dashed: Boolean(style.dashed),
    strokeWidth: styleNumber(style.strokeWidth, 2),
    edgeType: first.isEdge() ? edgeTypeFromCellStyle(style) : undefined,
    startArrow: first.isEdge() ? arrowTypeFromStyle(style.startArrow, "none") : undefined,
    endArrow: first.isEdge() ? arrowTypeFromStyle(style.endArrow, "block") : undefined,
    fontSize: first.isVertex() ? styleNumber(style.fontSize, 13) : undefined,
    bold: first.isVertex() ? (fontStyle & 1) === 1 : undefined,
    italic: first.isVertex() ? (fontStyle & 2) === 2 : undefined,
    align: first.isVertex() ? textAlignFromStyle(style.align) : undefined,
    locked: first.isVertex() ? Boolean(style.diagramLocked) : undefined,
    rotation: first.isVertex() ? normalizeRotation(styleNumber(style.rotation, 0)) : undefined,
    isSwimlane: firstKind === "swimlane",
    isLane: firstKind === "lane",
    swimlaneDirection: firstKind === "swimlane" ? (style.horizontal === false ? "vertical" : "horizontal") : undefined,
    opacity: styleNumber(style.opacity, 100),
    shadow: Boolean(style.shadow),
    rounded: Boolean(style.rounded),
  });
}

function laneChildren(graph: Graph, pool: Cell) {
  const horizontal = (pool.getStyle() as DiagramCellStyle).horizontal !== false;
  return graph.getChildVertices(pool)
    .filter((cell) => (cell.getStyle() as DiagramCellStyle).diagramKind === "lane")
    .sort((left, right) => {
      const leftGeometry = left.getGeometry();
      const rightGeometry = right.getGeometry();
      return horizontal
        ? (leftGeometry?.y ?? 0) - (rightGeometry?.y ?? 0)
        : (leftGeometry?.x ?? 0) - (rightGeometry?.x ?? 0);
    });
}

function layoutLaneCells(graph: Graph, pool: Cell, orderedLanes = laneChildren(graph, pool)) {
  if (orderedLanes.length === 0) return;
  const poolGeometry = pool.getGeometry()?.clone();
  if (!poolGeometry) return;
  const horizontal = (pool.getStyle() as DiagramCellStyle).horizontal !== false;
  if (horizontal) {
    const width = Math.max(560, poolGeometry.width);
    poolGeometry.width = width;
    poolGeometry.height = 32 + orderedLanes.length * 120;
    orderedLanes.forEach((lane, index) => {
      const geometry = lane.getGeometry()?.clone();
      if (!geometry) return;
      geometry.x = 0;
      geometry.y = 32 + index * 120;
      geometry.width = width;
      geometry.height = 120;
      graph.getDataModel().setGeometry(lane, geometry);
    });
  } else {
    const height = Math.max(300, poolGeometry.height);
    poolGeometry.width = 32 + orderedLanes.length * 180;
    poolGeometry.height = height;
    orderedLanes.forEach((lane, index) => {
      const geometry = lane.getGeometry()?.clone();
      if (!geometry) return;
      geometry.x = 32 + index * 180;
      geometry.y = 0;
      geometry.width = 180;
      geometry.height = height;
      graph.getDataModel().setGeometry(lane, geometry);
    });
  }
  graph.getDataModel().setGeometry(pool, poolGeometry);
}

function nodeCellStyle(node: DiagramNode, optimizeLargeGraph = false): DiagramCellStyle {
  const isContainer = node.kind === "container" || node.kind === "swimlane" || node.kind === "lane";
  const usesRoundedCorners = node.kind === "process"
    || node.kind === "roundedRectangle"
    || node.kind === "subprocess"
    || node.kind === "bpmnTask"
    || node.kind === "umlClass"
    || node.kind === "umlPackage"
    || node.kind === "umlComponent"
    || node.kind === "entity"
    || node.kind === "client"
    || node.kind === "firewall"
    || node.kind === "server"
    || node.kind === "queue";
  const base: DiagramCellStyle = {
    diagramKind: node.kind,
    ...(node.stencilName ? { diagramStencilName: node.stencilName } : {}),
    ...(node.stencilLibrary ? { diagramStencilLibrary: node.stencilLibrary } : {}),
    shape: node.stencilName ?? nodeShape(node.kind),
    absoluteArcSize: true,
    arcSize: 16,
    whiteSpace: "wrap",
    overflow: "hidden",
    align: node.style.align ?? "center",
    verticalAlign: "middle",
    spacing: 10,
    fontFamily: "Inter, ui-sans-serif, system-ui",
    fontSize: node.style.fontSize ?? 13,
    fontStyle: (node.style.bold === false ? 0 : 1) + (node.style.italic ? 2 : 0),
    fillColor: node.style.fillColor,
    gradientColor: isContainer || node.kind === "text" || node.stencilName ? "none" : mixHexColor(node.style.fillColor, "#ffffff", 0.62),
    gradientDirection: "north",
    strokeColor: node.style.strokeColor,
    fontColor: node.style.fontColor,
    strokeWidth: node.style.strokeWidth,
    dashed: Boolean(node.style.dashed),
    shadow: !isContainer && !node.stencilName && !optimizeLargeGraph && (node.style.shadow ?? true),
    opacity: node.style.opacity ?? 100,
    rounded: node.style.rounded ?? usesRoundedCorners,
    rotation: node.rotation ?? 0,
    diagramLocked: Boolean(node.locked),
  };
  if (node.kind === "note") {
    if (node.style.align === undefined) base.align = "left";
    base.verticalAlign = "top";
    if (node.style.bold === undefined && node.style.italic === undefined) base.fontStyle = 0;
  }
  if (node.kind === "text") {
    base.align = node.style.align ?? "left";
    base.fontStyle = node.style.bold ? 1 : 0;
    base.shadow = false;
  }
  if (node.kind === "umlClass" || node.kind === "entity") {
    base.verticalAlign = "top";
    base.spacingTop = 10;
    base.fontFamily = "ui-monospace, SFMono-Regular, Menlo, monospace";
  }
  if (node.kind === "umlPackage") {
    base.align = "left";
    base.verticalAlign = "top";
    base.spacingTop = 14;
    base.spacingLeft = 12;
  }
  if (node.kind === "container" || node.kind === "swimlane" || node.kind === "lane") {
    base.align = "left";
    base.verticalAlign = "top";
    base.spacingTop = node.kind === "swimlane" || node.kind === "lane" ? 8 : 12;
    base.spacingLeft = 10;
    base.connectable = false;
    base.collapsible = true;
    base.recursiveResize = false;
  }
  if (node.kind === "swimlane") {
    base.horizontal = node.swimlaneDirection !== "vertical";
    base.startSize = 32;
    base.swimlaneFillColor = node.style.fillColor;
  }
  if (node.kind === "lane") {
    base.horizontal = true;
    base.startSize = 28;
    base.swimlaneFillColor = node.style.fillColor;
    base.collapsible = false;
  }
  return base;
}

function edgeCellStyle(edge: DiagramEdge): CellStyle {
  const source = portCoordinates(edge.sourcePort);
  const target = portCoordinates(edge.targetPort);
  return {
    ...edgeRoutingStyle(edge.style.edgeType ?? "orthogonal"),
    rounded: true,
    orthogonalLoop: true,
    jettySize: "auto",
    startArrow: edge.style.startArrow ?? "none",
    startFill: edge.style.startArrow !== "open" && edge.style.startArrow !== "none",
    endArrow: edge.style.endArrow ?? "block",
    endFill: edge.style.endArrow !== "open" && edge.style.endArrow !== "none",
    strokeColor: edge.style.strokeColor,
    fontColor: edge.style.fontColor,
    strokeWidth: edge.style.strokeWidth,
    dashed: Boolean(edge.style.dashed),
    opacity: edge.style.opacity ?? 100,
    labelBackgroundColor: "#ffffff",
    exitX: source?.x,
    exitY: source?.y,
    exitPerimeter: true,
    entryX: target?.x,
    entryY: target?.y,
    entryPerimeter: true,
  };
}

function buildStencilCollections(catalog: DrawioStencilCatalog): StencilCollection[] {
  const collections = new Map<string, StencilCollection>();
  for (const library of catalog.libraries) {
    const rule = STENCIL_COLLECTION_RULES.find((candidate) => candidate.pattern.test(library.id));
    const collectionId = rule?.id ?? library.id;
    const key = `${library.group}:${collectionId}`;
    const existing = collections.get(key);
    if (existing) {
      existing.libraryCount += 1;
      existing.shapeCount += library.shapeCount;
      existing.items.push(...library.shapes.map((shape) => ({ library, shape })));
      continue;
    }
    collections.set(key, {
      id: key,
      name: rule?.name ?? library.name,
      group: library.group,
      libraryCount: 1,
      shapeCount: library.shapeCount,
      items: library.shapes.map((shape) => ({ library, shape })),
    });
  }
  return Array.from(collections.values());
}

function stencilPaletteItem(library: DrawioStencilLibrary, shape: DrawioStencilShape): StencilPaletteItem {
  return {
    id: shape.id,
    kind: "rectangle",
    label: shape.name,
    detail: library.name,
    stencilName: shape.shape,
    stencilLibrary: library.path,
    width: shape.width,
    height: shape.height,
  };
}

function stencilNodeDefaults(item: StencilPaletteItem): { label: string; width: number; height: number; style: DiagramNodeStyle } {
  const sourceWidth = Math.max(1, item.width);
  const sourceHeight = Math.max(1, item.height);
  const scale = Math.min(156 / sourceWidth, 108 / sourceHeight);
  return {
    label: "",
    width: Math.max(52, Math.round(sourceWidth * scale)),
    height: Math.max(44, Math.round(sourceHeight * scale)),
    style: {
      fillColor: "#f8fafc",
      strokeColor: "#334155",
      fontColor: "#1e293b",
      strokeWidth: 1.4,
      fontSize: 12,
      bold: false,
      shadow: false,
    },
  };
}

function nodeDefaults(kind: DiagramNodeKind): { label: string; width: number; height: number; style: DiagramNodeStyle } {
  const common = { fontColor: "#1e293b", strokeWidth: 1.5, fontSize: 13 };
  if (kind === "rectangle") {
    return { label: "矩形", width: 168, height: 76, style: { ...common, fillColor: "#ffffff", strokeColor: "#64748b", bold: false } };
  }
  if (kind === "roundedRectangle") {
    return { label: "圆角矩形", width: 168, height: 76, style: { ...common, fillColor: "#f8fafc", strokeColor: "#64748b", rounded: true, bold: false } };
  }
  if (kind === "ellipse") {
    return { label: "椭圆", width: 164, height: 92, style: { ...common, fillColor: "#f8fafc", strokeColor: "#64748b", bold: false } };
  }
  if (kind === "circle") {
    return { label: "圆形", width: 96, height: 96, style: { ...common, fillColor: "#f8fafc", strokeColor: "#64748b", bold: false } };
  }
  if (kind === "diamond") {
    return { label: "菱形", width: 112, height: 112, style: { ...common, fillColor: "#f8fafc", strokeColor: "#64748b", bold: false } };
  }
  if (kind === "triangle") {
    return { label: "三角形", width: 120, height: 104, style: { ...common, fillColor: "#f8fafc", strokeColor: "#64748b", bold: false } };
  }
  if (kind === "hexagon") {
    return { label: "六边形", width: 164, height: 88, style: { ...common, fillColor: "#f8fafc", strokeColor: "#64748b", bold: false } };
  }
  if (kind === "text") {
    return { label: "双击编辑文本", width: 180, height: 52, style: { ...common, fillColor: "none", strokeColor: "none", strokeWidth: 0, bold: false, align: "left", shadow: false } };
  }
  if (kind === "start") {
    return { label: "开始", width: 128, height: 48, style: { ...common, fillColor: "#ecfdf5", strokeColor: "#10b981" } };
  }
  if (kind === "end") {
    return { label: "结束", width: 128, height: 48, style: { ...common, fillColor: "#fff1f2", strokeColor: "#f43f5e" } };
  }
  if (kind === "decision") {
    return { label: "判断条件", width: 148, height: 100, style: { ...common, fillColor: "#fffbeb", strokeColor: "#f59e0b" } };
  }
  if (kind === "database") {
    return { label: "数据库", width: 148, height: 92, style: { ...common, fillColor: "#f5f3ff", strokeColor: "#8b5cf6" } };
  }
  if (kind === "document") {
    return { label: "文档", width: 156, height: 86, style: { ...common, fillColor: "#eff6ff", strokeColor: "#3b82f6" } };
  }
  if (kind === "actor") {
    return { label: "参与者", width: 116, height: 98, style: { ...common, fillColor: "#fdf2f8", strokeColor: "#ec4899" } };
  }
  if (kind === "note") {
    return { label: "补充说明", width: 176, height: 100, style: { ...common, fillColor: "#fefce8", strokeColor: "#eab308" } };
  }
  if (kind === "subprocess") {
    return { label: "子流程", width: 184, height: 76, style: { ...common, fillColor: "#ecfeff", strokeColor: "#06b6d4" } };
  }
  if (kind === "data") {
    return { label: "数据", width: 164, height: 76, style: { ...common, fillColor: "#f0fdf4", strokeColor: "#22c55e" } };
  }
  if (kind === "delay") {
    return { label: "等待", width: 156, height: 76, style: { ...common, fillColor: "#fff7ed", strokeColor: "#f97316" } };
  }
  if (kind === "manualInput") {
    return { label: "手动输入", width: 168, height: 76, style: { ...common, fillColor: "#fff7ed", strokeColor: "#f97316" } };
  }
  if (kind === "connector") {
    return { label: "A", width: 56, height: 56, style: { ...common, fillColor: "#f8fafc", strokeColor: "#64748b" } };
  }
  if (kind === "bpmnTask") {
    return { label: "业务任务", width: 172, height: 72, style: { ...common, fillColor: "#ecfeff", strokeColor: "#06b6d4", rounded: true } };
  }
  if (kind === "cloud") {
    return { label: "云服务", width: 176, height: 96, style: { ...common, fillColor: "#eef2ff", strokeColor: "#6366f1" } };
  }
  if (kind === "container") {
    return { label: "分组容器", width: 480, height: 320, style: { ...common, fillColor: "#f8fafc", strokeColor: "#94a3b8", dashed: true, shadow: false } };
  }
  if (kind === "swimlane") {
    return { label: "职责泳道", width: 560, height: 300, style: { ...common, fillColor: "#f8fafc", strokeColor: "#06b6d4", shadow: false } };
  }
  if (kind === "lane") {
    return { label: "泳道", width: 560, height: 120, style: { ...common, fillColor: "#f8fafc", strokeColor: "#a5f3fc", shadow: false } };
  }
  if (kind === "bpmnEvent") {
    return { label: "中间事件", width: 76, height: 76, style: { ...common, fillColor: "#f0fdfa", strokeColor: "#14b8a6" } };
  }
  if (kind === "bpmnGateway") {
    return { label: "网关", width: 96, height: 96, style: { ...common, fillColor: "#fffbeb", strokeColor: "#f59e0b" } };
  }
  if (kind === "bpmnDataObject") {
    return { label: "数据对象", width: 124, height: 92, style: { ...common, fillColor: "#f0fdfa", strokeColor: "#14b8a6" } };
  }
  if (kind === "umlUseCase") {
    return { label: "用户用例", width: 172, height: 84, style: { ...common, fillColor: "#f8fafc", strokeColor: "#64748b", bold: false } };
  }
  if (kind === "umlClass") {
    return { label: "ClassName\n────────\n+ field: Type\n────────\n+ method()", width: 216, height: 154, style: { ...common, fillColor: "#f8fafc", strokeColor: "#64748b", align: "left" } };
  }
  if (kind === "umlInterface") {
    return { label: "Interface", width: 104, height: 104, style: { ...common, fillColor: "#f8fafc", strokeColor: "#64748b", fontSize: 11, bold: false } };
  }
  if (kind === "umlPackage") {
    return { label: "Package", width: 190, height: 112, style: { ...common, fillColor: "#fffbeb", strokeColor: "#f59e0b", align: "left" } };
  }
  if (kind === "umlComponent") {
    return { label: "Component", width: 190, height: 100, style: { ...common, fillColor: "#eef2ff", strokeColor: "#6366f1" } };
  }
  if (kind === "entity") {
    return { label: "Entity\n────────\nid: UUID\nname: VARCHAR", width: 204, height: 134, style: { ...common, fillColor: "#ecfeff", strokeColor: "#06b6d4", align: "left" } };
  }
  if (kind === "erRelationship") {
    return { label: "关系", width: 132, height: 92, style: { ...common, fillColor: "#f5f3ff", strokeColor: "#8b5cf6" } };
  }
  if (kind === "erAttribute") {
    return { label: "属性", width: 152, height: 72, style: { ...common, fillColor: "#fdf2f8", strokeColor: "#ec4899", bold: false } };
  }
  if (kind === "server") {
    return { label: "应用服务器", width: 156, height: 104, style: { ...common, fillColor: "#eef2ff", strokeColor: "#6366f1" } };
  }
  if (kind === "client") {
    return { label: "客户端", width: 156, height: 88, style: { ...common, fillColor: "#eff6ff", strokeColor: "#3b82f6" } };
  }
  if (kind === "router") {
    return { label: "路由器", width: 128, height: 72, style: { ...common, fillColor: "#ecfeff", strokeColor: "#06b6d4" } };
  }
  if (kind === "firewall") {
    return { label: "防火墙", width: 160, height: 76, style: { ...common, fillColor: "#fff1f2", strokeColor: "#f43f5e" } };
  }
  if (kind === "queue") {
    return { label: "消息队列", width: 164, height: 86, style: { ...common, fillColor: "#fdf2f8", strokeColor: "#ec4899" } };
  }
  if (kind === "service") {
    return { label: "应用服务", width: 168, height: 84, style: { ...common, fillColor: "#ecfdf5", strokeColor: "#10b981" } };
  }
  return { label: "处理步骤", width: 168, height: 68, style: { ...common, fillColor: "#f0f9ff", strokeColor: "#0ea5e9" } };
}

function defaultEdgeStyle(): DiagramEdgeStyle {
  return {
    strokeColor: "#64748b",
    fontColor: "#334155",
    strokeWidth: 2,
    edgeType: "orthogonal",
    startArrow: "none",
    endArrow: "block",
  };
}

function nodeShape(kind: DiagramNodeKind) {
  if (kind === "ellipse" || kind === "circle" || kind === "start" || kind === "end" || kind === "connector" || kind === "umlUseCase" || kind === "erAttribute" || kind === "router") return "ellipse";
  if (kind === "diamond" || kind === "decision" || kind === "bpmnGateway" || kind === "erRelationship") return "rhombus";
  if (kind === "bpmnEvent" || kind === "umlInterface") return "doubleEllipse";
  if (kind === "triangle") return "triangle";
  if (kind === "hexagon" || kind === "manualInput" || kind === "service") return "hexagon";
  if (kind === "database" || kind === "server" || kind === "queue") return "cylinder";
  if (kind === "actor") return "actor";
  if (kind === "cloud") return "cloud";
  if (kind === "swimlane" || kind === "lane") return "swimlane";
  return "rectangle";
}

function mixHexColor(color: string, target: string, amount: number) {
  const parse = (value: string) => {
    const match = /^#([\da-f]{2})([\da-f]{2})([\da-f]{2})$/i.exec(value);
    return match ? [Number.parseInt(match[1], 16), Number.parseInt(match[2], 16), Number.parseInt(match[3], 16)] : null;
  };
  const sourceRgb = parse(color);
  const targetRgb = parse(target);
  if (!sourceRgb || !targetRgb) return target;
  const mixed = sourceRgb.map((channel, index) => Math.round(channel + (targetRgb[index] - channel) * amount));
  return `#${mixed.map((channel) => channel.toString(16).padStart(2, "0")).join("")}`;
}

function createNodeDragPreview(
  kind: DiagramNodeKind,
  defaults: { label: string; width: number; height: number; style: DiagramNodeStyle },
) {
  const scale = Math.min(1, 220 / defaults.width, 150 / defaults.height);
  const width = Math.max(64, Math.round(defaults.width * scale));
  const height = Math.max(48, Math.round(defaults.height * scale));
  const isContainer = kind === "container" || kind === "swimlane" || kind === "lane";
  const element = window.document.createElement("div");
  element.style.width = `${width}px`;
  element.style.height = `${height}px`;
  element.style.boxSizing = "border-box";
  element.style.position = "relative";
  element.style.pointerEvents = "none";
  element.style.opacity = "0.96";
  element.style.filter = "drop-shadow(0 10px 18px rgba(15, 23, 42, .22))";

  const shape = window.document.createElement("div");
  shape.style.position = "absolute";
  shape.style.inset = isContainer ? "2px" : "1px";
  shape.style.boxSizing = "border-box";
  shape.style.background = isContainer
    ? "rgba(248, 250, 252, .9)"
    : `linear-gradient(180deg, ${mixHexColor(defaults.style.fillColor, "#ffffff", 0.72)}, ${defaults.style.fillColor})`;
  shape.style.border = `${Math.max(1, defaults.style.strokeWidth)}px ${defaults.style.dashed ? "dashed" : "solid"} ${defaults.style.strokeColor}`;
  shape.style.borderRadius = "14px";
  shape.style.boxShadow = isContainer ? "none" : "0 6px 16px rgba(15, 23, 42, .12)";

  if (kind === "ellipse" || kind === "circle" || kind === "start" || kind === "end" || kind === "connector" || kind === "bpmnEvent" || kind === "umlUseCase" || kind === "umlInterface" || kind === "erAttribute" || kind === "router") {
    shape.style.borderRadius = "999px";
  } else if (kind === "diamond" || kind === "decision" || kind === "bpmnGateway" || kind === "erRelationship") {
    shape.style.inset = "18%";
    shape.style.borderRadius = "8px";
    shape.style.transform = "rotate(45deg)";
  } else if (kind === "database" || kind === "server" || kind === "queue") {
    shape.style.borderRadius = "50% / 18%";
  } else if (kind === "hexagon" || kind === "manualInput" || kind === "service") {
    shape.style.clipPath = "polygon(14% 0, 86% 0, 100% 50%, 86% 100%, 14% 100%, 0 50%)";
  } else if (kind === "triangle") {
    shape.style.clipPath = "polygon(50% 0, 100% 100%, 0 100%)";
  } else if (kind === "data") {
    shape.style.clipPath = "polygon(14% 0, 100% 0, 86% 100%, 0 100%)";
  } else if (kind === "note") {
    shape.style.clipPath = "polygon(0 0, 82% 0, 100% 22%, 100% 100%, 0 100%)";
  } else if (kind === "cloud") {
    shape.style.borderRadius = "48% 52% 46% 54% / 58% 48% 52% 42%";
  }
  if (kind === "text") {
    shape.style.display = "none";
    element.style.filter = "none";
  }
  element.appendChild(shape);

  if (kind === "swimlane" || kind === "lane") {
    const header = window.document.createElement("div");
    header.style.position = "absolute";
    header.style.inset = "3px 3px auto";
    header.style.height = `${Math.max(22, Math.round(30 * scale))}px`;
    header.style.borderRadius = "11px 11px 4px 4px";
    header.style.background = mixHexColor(defaults.style.strokeColor, "#ffffff", 0.82);
    header.style.borderBottom = `1px solid ${mixHexColor(defaults.style.strokeColor, "#ffffff", 0.45)}`;
    element.appendChild(header);
  }

  const label = window.document.createElement("div");
  label.textContent = defaults.label.split("\n")[0];
  label.style.position = "absolute";
  label.style.inset = isContainer ? "12px auto auto 14px" : "8px";
  label.style.display = "flex";
  label.style.alignItems = "center";
  label.style.justifyContent = isContainer ? "flex-start" : "center";
  label.style.color = defaults.style.fontColor;
  label.style.fontFamily = "Inter, ui-sans-serif, system-ui";
  label.style.fontSize = `${Math.max(10, Math.min(13, Math.round(13 * scale)))}px`;
  label.style.fontWeight = "650";
  label.style.lineHeight = "1.2";
  label.style.textAlign = isContainer ? "left" : "center";
  label.style.whiteSpace = "nowrap";
  element.appendChild(label);

  const dropIndicator = window.document.createElement("div");
  dropIndicator.style.position = "absolute";
  dropIndicator.style.right = "-4px";
  dropIndicator.style.bottom = "-4px";
  dropIndicator.style.width = "12px";
  dropIndicator.style.height = "12px";
  dropIndicator.style.border = "3px solid white";
  dropIndicator.style.borderRadius = "999px";
  dropIndicator.style.background = "#06b6d4";
  dropIndicator.style.boxShadow = "0 2px 6px rgba(8, 145, 178, .35)";
  element.appendChild(dropIndicator);

  return { element, width, height };
}

function edgeRoutingStyle(type: DiagramEdgeType): CellStyle {
  if (type === "straight") return { edgeStyle: "none", curved: false };
  if (type === "elbow") return { edgeStyle: "elbowEdgeStyle", elbow: "horizontal", curved: false };
  if (type === "curved") return { edgeStyle: "orthogonalEdgeStyle", curved: true };
  return { edgeStyle: "orthogonalEdgeStyle", orthogonalLoop: true, jettySize: "auto", curved: false };
}

function edgeTypeFromCellStyle(style: CellStyle): DiagramEdgeType {
  if (style.curved) return "curved";
  if (!style.edgeStyle || style.edgeStyle === "none") return "straight";
  if (String(style.edgeStyle).toLowerCase().includes("elbow")) return "elbow";
  return "orthogonal";
}

function arrowTypeFromStyle(value: unknown, fallback: DiagramArrowType): DiagramArrowType {
  return value === "none" || value === "classic" || value === "block" || value === "open" || value === "oval" || value === "diamond"
    ? value
    : fallback;
}

function diagramPageId(pageId?: string) {
  return pageId ?? DEFAULT_PAGE_ID;
}

function textAlignFromStyle(value: unknown): "left" | "center" | "right" {
  return value === "left" || value === "right" ? value : "center";
}

function normalizeRotation(value: number) {
  return ((Math.round(value) % 360) + 360) % 360;
}

function portCoordinates(port?: DiagramPort) {
  if (port === "north") return { x: 0.5, y: 0 };
  if (port === "east") return { x: 1, y: 0.5 };
  if (port === "south") return { x: 0.5, y: 1 };
  if (port === "west") return { x: 0, y: 0.5 };
  return undefined;
}

function absoluteCellOrigin(cell: Cell) {
  let x = 0;
  let y = 0;
  let current: Cell | null = cell;
  while (current) {
    const geometry = current.getGeometry();
    if (geometry && !geometry.relative) {
      x += geometry.x;
      y += geometry.y;
    }
    current = current.getParent();
  }
  return { x, y };
}

function absoluteCellCenter(cell: Cell) {
  const origin = absoluteCellOrigin(cell);
  const geometry = cell.getGeometry();
  return {
    x: origin.x + (geometry?.width ?? 0) / 2,
    y: origin.y + (geometry?.height ?? 0) / 2,
  };
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
  return value === "lane" || NODE_PALETTE.some((item) => item.kind === value);
}

function cloneNode(node: DiagramNode): DiagramNode {
  return { ...node, style: { ...node.style } };
}

function cloneEdge(edge: DiagramEdge): DiagramEdge {
  return {
    ...edge,
    ...(edge.waypoints ? { waypoints: edge.waypoints.map((point) => ({ ...point })) } : {}),
    style: { ...edge.style },
  };
}

function createDiagramId(peerId: string, kind: string) {
  return `${peerId}-${kind}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
}

function diagramExportFileName(date: Date, extension = DIAGRAM_FILE_EXTENSION) {
  const timestamp = date.toISOString().replace(/\D/g, "").slice(0, 14);
  return `shuai-tunnel-diagram-${timestamp}${extension}`;
}

function downloadDiagramFile(content: string, type: string, fileName: string) {
  downloadDiagramBlob(new Blob([content], { type }), fileName);
}

function downloadDiagramBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = window.document.createElement("a");
  link.href = url;
  link.download = fileName;
  window.document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function renderGraphSvg(graph: Graph, background: string) {
  const bounds = graph.getGraphBounds();
  if (bounds.width <= 0 || bounds.height <= 0) {
    throw new Error("流程图为空，无法导出图片");
  }
  const margin = 24;
  const width = Math.max(1, Math.ceil(bounds.width + margin * 2));
  const height = Math.max(1, Math.ceil(bounds.height + margin * 2));
  const document = window.document.implementation.createDocument("http://www.w3.org/2000/svg", "svg", null);
  const root = document.documentElement as unknown as SVGSVGElement;
  root.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  root.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");
  root.setAttribute("width", String(width));
  root.setAttribute("height", String(height));
  root.setAttribute("viewBox", `0 0 ${width} ${height}`);
  root.setAttribute("version", "1.1");
  const backgroundRect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  backgroundRect.setAttribute("width", "100%");
  backgroundRect.setAttribute("height", "100%");
  backgroundRect.setAttribute("fill", background);
  root.appendChild(backgroundRect);
  const modelRoot = graph.getDataModel().getRoot();
  const state = modelRoot ? graph.getView().getState(modelRoot) : null;
  if (!state) {
    throw new Error("流程图渲染状态尚未就绪");
  }
  const canvas = new SvgCanvas2D(root, true);
  canvas.translate(-bounds.x + margin, -bounds.y + margin);
  new ImageExport().drawState(state, canvas);
  return new XMLSerializer().serializeToString(document);
}

function renderDiagramPageSvg(nodes: DiagramNode[], edges: DiagramEdge[], pageId: string, background: string) {
  const pageNodes = nodes.filter((node) => diagramPageId(node.pageId) === pageId);
  const pageEdges = edges.filter((edge) => diagramPageId(edge.pageId) === pageId);
  if (pageNodes.length === 0) {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="1169" height="827" viewBox="0 0 1169 827"><rect width="100%" height="100%" fill="${background}"/></svg>`;
  }
  const container = window.document.createElement("div");
  container.style.cssText = `position:fixed;left:-100000px;top:0;width:${DIAGRAM_CANVAS.width}px;height:${DIAGRAM_CANVAS.height}px;opacity:0;pointer-events:none;overflow:hidden`;
  window.document.body.appendChild(container);
  const graph = new Graph(container);
  try {
    graph.setHtmlLabels(false);
    graph.setAllowNegativeCoordinates(false);
    graph.batchUpdate(() => {
      const parent = graph.getDefaultParent();
      const cells = new Map<string, Cell>();
      let pendingNodes = pageNodes.slice().sort((left, right) => left.zIndex - right.zIndex);
      while (pendingNodes.length > 0) {
        const remaining: DiagramNode[] = [];
        for (const node of pendingNodes) {
          const nodeParent = node.parentId ? cells.get(node.parentId) : parent;
          if (!nodeParent) {
            remaining.push(node);
            continue;
          }
          const cell = graph.insertVertex({
            parent: nodeParent,
            id: node.id,
            value: node.label,
            position: [node.x, node.y],
            size: [node.width, node.height],
            style: nodeCellStyle(node),
          });
          cells.set(node.id, cell);
        }
        if (remaining.length === pendingNodes.length) {
          throw new Error("流程图页面包含无法解析的容器层级");
        }
        pendingNodes = remaining;
      }
      for (const edge of pageEdges.slice().sort((left, right) => left.zIndex - right.zIndex)) {
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
        if (edge.waypoints?.length) {
          const geometry = edgeCell.getGeometry()?.clone();
          if (geometry) {
            geometry.points = edge.waypoints.map((point) => new Point(point.x, point.y));
            graph.getDataModel().setGeometry(edgeCell, geometry);
          }
        }
        graph.setConnectionConstraint(edgeCell, source, true, constraintForPort(edge.sourcePort));
        graph.setConnectionConstraint(edgeCell, target, false, constraintForPort(edge.targetPort));
      }
    });
    graph.refresh();
    return renderGraphSvg(graph, background);
  } finally {
    graph.destroy();
    container.remove();
  }
}

function svgDimensions(svg: string) {
  const root = new DOMParser().parseFromString(svg, "image/svg+xml").documentElement;
  return {
    width: Math.max(1, Number(root.getAttribute("width")) || 1),
    height: Math.max(1, Number(root.getAttribute("height")) || 1),
  };
}

function blobToDataUrl(blob: Blob) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => typeof reader.result === "string" ? resolve(reader.result) : reject(new Error("图片编码失败"));
    reader.onerror = () => reject(new Error("图片读取失败"));
    reader.readAsDataURL(blob);
  });
}

async function svgToPng(svg: string, requestedScale: number, background: string) {
  const parsed = new DOMParser().parseFromString(svg, "image/svg+xml").documentElement;
  const width = Math.max(1, Number(parsed.getAttribute("width")) || 1);
  const height = Math.max(1, Number(parsed.getAttribute("height")) || 1);
  const scale = Math.min(requestedScale, 8192 / width, 8192 / height);
  const source = URL.createObjectURL(new Blob([svg], { type: "image/svg+xml" }));
  try {
    const image = new Image();
    image.decoding = "async";
    await new Promise<void>((resolve, reject) => {
      image.onload = () => resolve();
      image.onerror = () => reject(new Error("浏览器无法渲染流程图 SVG"));
      image.src = source;
    });
    const canvas = window.document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(width * scale));
    canvas.height = Math.max(1, Math.round(height * scale));
    const context = canvas.getContext("2d");
    if (!context) {
      throw new Error("浏览器不支持 PNG 画布导出");
    }
    context.fillStyle = background;
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    return await new Promise<Blob>((resolve, reject) => {
      canvas.toBlob((blob) => blob ? resolve(blob) : reject(new Error("PNG 编码失败")), "image/png");
    });
  } finally {
    URL.revokeObjectURL(source);
  }
}

interface DiagramToolbarMenuItem {
  key: string;
  label: string;
  shortcut?: string;
  disabled?: boolean;
  danger?: boolean;
}

function CompactPanelButton({
  label,
  active,
  children,
  onClick,
}: {
  label: string;
  active: boolean;
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      className={`flex h-8 min-w-[64px] items-center justify-center gap-1.5 rounded-md px-2 text-[10px] font-semibold transition ${active
        ? "bg-white text-cyan-800 shadow-sm dark:bg-cyan-300 dark:text-zinc-950"
        : "text-zinc-500 hover:bg-white/70 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/[0.06] dark:hover:text-white"}`}
      onClick={onClick}
    >
      <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true">
        {children}
      </svg>
      {label}
    </button>
  );
}

function DiagramToolbarMenu({
  label,
  items,
  compact = false,
  placement = "bottom-start",
  onAction,
}: {
  label: string;
  items: DiagramToolbarMenuItem[];
  compact?: boolean;
  placement?: "bottom-start" | "bottom-end";
  onAction: (key: string) => void;
}) {
  return (
    <Dropdown placement={placement} shouldBlockScroll={false}>
      <DropdownTrigger>
        <button
          type="button"
          className={`flex shrink-0 items-center gap-1.5 rounded-lg text-[11px] font-medium text-zinc-600 transition hover:bg-black/[0.045] hover:text-zinc-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 dark:text-zinc-300 dark:hover:bg-white/[0.06] dark:hover:text-white ${compact ? "h-8 px-2" : "h-8 px-2.5"}`}
          aria-label={`${label}菜单`}
        >
          {label}
          <svg className="h-3 w-3 text-zinc-400" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 16 16" aria-hidden="true">
            <path d="m4 6 4 4 4-4" />
          </svg>
        </button>
      </DropdownTrigger>
      <DropdownMenu
        aria-label={`${label}菜单`}
        items={items}
        disabledKeys={items.filter((item) => item.disabled).map((item) => item.key)}
        onAction={(key) => onAction(String(key))}
      >
        {(item) => (
          <DropdownItem
            key={item.key}
            textValue={item.label}
            color={item.danger ? "danger" : "default"}
            className={item.danger ? "text-danger" : undefined}
            endContent={item.shortcut ? <span className="text-[10px] text-zinc-400">{item.shortcut}</span> : null}
          >
            {item.label}
          </DropdownItem>
        )}
      </DropdownMenu>
    </Dropdown>
  );
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
      className={`flex h-8 shrink-0 items-center gap-1 rounded-lg px-2.5 text-[11px] font-medium transition disabled:cursor-not-allowed disabled:opacity-35 ${danger
        ? "text-red-600 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-400/10"
        : "text-zinc-600 hover:bg-black/[0.045] hover:text-zinc-950 dark:text-zinc-300 dark:hover:bg-white/[0.06] dark:hover:text-white"}`}
      onClick={onClick}
    >
      {label}
      {shortcut ? <span className="hidden text-[9px] text-zinc-400 xl:inline">{shortcut}</span> : null}
    </button>
  );
}

function DrawioStencilGlyph({ stencilName, loaded }: { stencilName: string; loaded: boolean }) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [rendered, setRendered] = useState(false);
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg || !loaded) {
      setRendered(false);
      return;
    }
    try {
      setRendered(renderDrawioStencilPreview(svg, stencilName));
    } catch {
      svg.replaceChildren();
      setRendered(false);
    }
  }, [loaded, stencilName]);
  return (
    <span className="relative flex h-8 w-12 shrink-0 items-center justify-center overflow-hidden rounded-md bg-slate-50 dark:bg-white/[0.04]">
      <svg ref={svgRef} className={`h-full w-full overflow-visible ${rendered ? "block" : "hidden"}`} aria-hidden="true" />
      {!rendered ? <span className="h-5 w-8 rounded border border-cyan-500/60 bg-cyan-50 dark:bg-cyan-300/10" /> : null}
    </span>
  );
}

function DiagramNodeGlyph({ kind }: { kind: DiagramNodeKind }) {
  if (kind === "text") {
    return <span className="flex h-8 w-11 shrink-0 items-center justify-center rounded-md bg-slate-50 text-sm font-semibold text-cyan-700 transition group-hover:bg-cyan-50 dark:bg-white/[0.04] dark:text-cyan-200 dark:group-hover:bg-cyan-300/[0.08]">T</span>;
  }
  const isEllipse = ["ellipse", "circle", "start", "end", "connector", "bpmnEvent", "umlUseCase", "umlInterface", "erAttribute", "router"].includes(kind);
  const isDiamond = ["diamond", "decision", "bpmnGateway", "erRelationship"].includes(kind);
  const clipPath = ["hexagon", "manualInput", "service"].includes(kind)
    ? "polygon(14% 0, 86% 0, 100% 50%, 86% 100%, 14% 100%, 0 50%)"
    : kind === "triangle" ? "polygon(50% 0, 100% 100%, 0 100%)" : undefined;
  const shapeClass = isEllipse ? "rounded-full"
    : isDiamond ? "rotate-45 rounded-sm"
      : kind === "database" || kind === "server" || kind === "queue" ? "rounded-[50%/20%]"
        : kind === "note" ? "rounded-sm rounded-tr-xl"
          : "rounded-md";
  return (
    <span style={clipPath ? { clipPath } : undefined} className={`flex h-8 w-11 shrink-0 items-center justify-center border-[1.5px] border-cyan-600/80 bg-cyan-50 text-cyan-700 shadow-[0_1px_1px_rgba(8,145,178,0.08)] transition group-hover:border-cyan-600 group-hover:bg-cyan-100 dark:border-cyan-300/70 dark:bg-cyan-300/[0.08] dark:text-cyan-200 dark:group-hover:border-cyan-300 ${shapeClass}`}>
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

function ArrowPicker({
  label,
  selected,
  onSelect,
}: {
  label: string;
  selected?: DiagramArrowType;
  onSelect: (arrow: DiagramArrowType) => void;
}) {
  const arrows: Array<[DiagramArrowType, string]> = [
    ["none", "无"],
    ["classic", "经典"],
    ["block", "实心"],
    ["open", "开放"],
    ["oval", "圆点"],
    ["diamond", "菱形"],
  ];
  return (
    <div>
      <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-400">{label}</span>
      <div className="mt-1.5 grid grid-cols-3 gap-1.5">
        {arrows.map(([arrow, text]) => (
          <InspectorAction
            key={arrow}
            label={text}
            active={selected === arrow}
            onClick={() => onSelect(arrow)}
          />
        ))}
      </div>
    </div>
  );
}

function InspectorAction({
  label,
  active = false,
  disabled = false,
  onClick,
}: {
  label: string;
  active?: boolean;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      aria-pressed={active}
      className={`rounded-lg border px-2 py-1.5 text-[10px] font-medium transition hover:border-cyan-400 hover:text-cyan-800 disabled:opacity-35 dark:hover:text-cyan-200 ${active
        ? "border-cyan-400 bg-cyan-50 text-cyan-900 shadow-sm dark:bg-cyan-300/10 dark:text-cyan-100"
        : "border-black/[0.08] bg-white/70 text-zinc-600 dark:border-white/[0.09] dark:bg-white/[0.025] dark:text-zinc-300"}`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function ContextMenuAction({
  label,
  danger = false,
  disabled = false,
  onClick,
}: {
  label: string;
  danger?: boolean;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="menuitem"
      disabled={disabled}
      className={`block w-full rounded-md px-2.5 py-2 text-left transition disabled:opacity-35 ${danger
        ? "text-red-600 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-400/10"
        : "hover:bg-cyan-50 hover:text-cyan-900 dark:hover:bg-cyan-300/10 dark:hover:text-cyan-100"}`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}
