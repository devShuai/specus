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
  Rectangle,
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
  DiagramFontFamily,
  DiagramLinePattern,
  DiagramNode,
  DiagramNodeKind,
  DiagramNodeStyle,
  DiagramPayload,
  DiagramPage,
  DiagramPort,
  DiagramVerticalAlign,
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
import { registerDiagramSemanticShapes, semanticShapeName } from "../lib/diagramSemanticShapes";
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
registerDiagramSemanticShapes();

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
  standalone?: boolean;
  collaborationPanel?: ReactNode;
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
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  fillColor?: string;
  strokeColor?: string;
  fontColor?: string;
  labelBackgroundColor?: string;
  linePattern: DiagramLinePattern;
  strokeWidth: number;
  edgeType?: DiagramEdgeType;
  startArrow?: DiagramArrowType;
  endArrow?: DiagramArrowType;
  startSize?: number;
  endSize?: number;
  fontSize?: number;
  fontFamily?: DiagramFontFamily;
  bold?: boolean;
  italic?: boolean;
  underline?: boolean;
  align?: "left" | "center" | "right";
  verticalAlign?: DiagramVerticalAlign;
  spacing?: number;
  locked?: boolean;
  rotation?: number;
  flipH?: boolean;
  flipV?: boolean;
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

type DiagramEditableStyleKey =
  | "fillColor"
  | "strokeColor"
  | "fontColor"
  | "labelBackgroundColor"
  | "strokeWidth"
  | "opacity"
  | "shadow"
  | "rounded"
  | "fontFamily"
  | "verticalAlign"
  | "spacing"
  | "flipH"
  | "flipV"
  | "startSize"
  | "endSize";

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
const DIAGRAM_CANVAS_GROWTH = { width: 480, height: 320 };
const DIAGRAM_CANVAS_PADDING = { width: 280, height: 220 };
const MAX_DIAGRAM_CANVAS_SIZE = 100_000;
const MAX_DRAWIO_DOCUMENT_BYTES = 8 * 1024 * 1024;
const STENCIL_PAGE_SIZE = 180;
const STENCIL_SEARCH_LIMIT = 240;
const EMPTY_SELECTION: DiagramSelection = {
  ids: [],
  label: "",
  isNode: false,
  isEdge: false,
  linePattern: "solid",
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

const DIAGRAM_FONT_OPTIONS: Array<{ value: DiagramFontFamily; label: string }> = [
  { value: "system", label: "系统字体" },
  { value: "rounded", label: "圆体" },
  { value: "serif", label: "衬线字体" },
  { value: "mono", label: "等宽字体" },
];
const DIAGRAM_ARROW_OPTIONS: Array<{ value: DiagramArrowType; label: string }> = [
  { value: "none", label: "无" },
  { value: "classic", label: "经典" },
  { value: "block", label: "实心" },
  { value: "open", label: "开放" },
  { value: "oval", label: "圆点" },
  { value: "diamond", label: "菱形" },
];

type DiagramTemplateId = "approval" | "architecture" | "er";

interface DiagramTemplateNodeDefinition {
  id: string;
  kind: DiagramNodeKind;
  label: string;
  dx: number;
  dy: number;
  width: number;
  height: number;
  style?: Partial<DiagramNodeStyle>;
}

interface DiagramTemplateEdgeDefinition {
  sourceId: string;
  targetId: string;
  label?: string;
  sourcePort: DiagramPort;
  targetPort: DiagramPort;
  style?: Partial<DiagramEdgeStyle>;
}

interface DiagramTemplateDefinition {
  name: string;
  shortName: string;
  detail: string;
  nodes: DiagramTemplateNodeDefinition[];
  edges: DiagramTemplateEdgeDefinition[];
}

const DIAGRAM_TEMPLATES: Record<DiagramTemplateId, DiagramTemplateDefinition> = {
  approval: {
    name: "发布审批",
    shortName: "流程",
    detail: "发布审批",
    nodes: [
      { id: "start", kind: "start", label: "开始", dx: 38, dy: 0, width: 88, height: 32, style: { fontSize: 11 } },
      { id: "submit", kind: "process", label: "提交发布版本", dx: 20, dy: 58, width: 124, height: 46, style: { fontSize: 11, rounded: true } },
      { id: "review", kind: "decision", label: "审核通过？", dx: 26, dy: 132, width: 112, height: 72, style: { fontSize: 11 } },
      { id: "published", kind: "end", label: "发布完成", dx: 38, dy: 236, width: 88, height: 32, style: { fillColor: "#ecfdf3", strokeColor: "#34c759", fontSize: 11 } },
      { id: "rejected", kind: "end", label: "退回修改", dx: 190, dy: 151, width: 100, height: 34, style: { fillColor: "#fff1f2", strokeColor: "#ff3b30", fontSize: 11, bold: false } },
    ],
    edges: [
      { sourceId: "start", targetId: "submit", sourcePort: "south", targetPort: "north" },
      { sourceId: "submit", targetId: "review", sourcePort: "south", targetPort: "north" },
      { sourceId: "review", targetId: "published", label: "通过", sourcePort: "south", targetPort: "north" },
      { sourceId: "review", targetId: "rejected", label: "退回", sourcePort: "east", targetPort: "west", style: { strokeColor: "#ff3b30" } },
    ],
  },
  architecture: {
    name: "直传架构",
    shortName: "架构",
    detail: "直连与兜底",
    nodes: [
      { id: "sender", kind: "client", label: "发送端", dx: 0, dy: 66, width: 112, height: 52, style: { fontSize: 11, rounded: true } },
      { id: "coordinator", kind: "service", label: "协调服务", dx: 150, dy: 0, width: 124, height: 52, style: { fillColor: "#f5f5f7", strokeColor: "#86868b", fontSize: 11 } },
      { id: "receiver", kind: "client", label: "接收端", dx: 312, dy: 66, width: 112, height: 52, style: { fontSize: 11, rounded: true } },
      { id: "storage", kind: "cloud", label: "对象存储\n失败兜底", dx: 150, dy: 150, width: 124, height: 58, style: { fillColor: "#ecfdf3", strokeColor: "#34c759", fontSize: 10 } },
    ],
    edges: [
      { sourceId: "sender", targetId: "receiver", label: "WebRTC 直传", sourcePort: "east", targetPort: "west", style: { edgeType: "straight" } },
      { sourceId: "sender", targetId: "coordinator", label: "信令", sourcePort: "north", targetPort: "west" },
      { sourceId: "coordinator", targetId: "receiver", label: "协商", sourcePort: "east", targetPort: "north" },
      { sourceId: "sender", targetId: "storage", label: "预签名上传", sourcePort: "south", targetPort: "west", style: { strokeColor: "#34c759" } },
      { sourceId: "storage", targetId: "receiver", label: "临时下载", sourcePort: "east", targetPort: "south", style: { strokeColor: "#34c759" } },
    ],
  },
  er: {
    name: "房间 ER",
    shortName: "ER",
    detail: "房间数据",
    nodes: [
      { id: "room", kind: "entity", label: "Room 房间\n────────\nid: UUID\nname: VARCHAR", dx: 145, dy: 0, width: 142, height: 92, style: { fontSize: 10, spacing: 8 } },
      { id: "member", kind: "entity", label: "Member 成员\n────────\nid: UUID\nroom_id: UUID", dx: 0, dy: 138, width: 142, height: 104, style: { strokeColor: "#34c759", fontSize: 10, spacing: 8 } },
      { id: "transfer", kind: "entity", label: "Transfer 传输\n────────\nid: UUID\nroom_id: UUID", dx: 290, dy: 138, width: 142, height: 104, style: { strokeColor: "#ff9f0a", fontSize: 10, spacing: 8 } },
    ],
    edges: [
      { sourceId: "room", targetId: "member", label: "1 : N", sourcePort: "south", targetPort: "north", style: { strokeColor: "#34c759" } },
      { sourceId: "room", targetId: "transfer", label: "1 : N", sourcePort: "south", targetPort: "north", style: { strokeColor: "#ff9f0a" } },
    ],
  },
};
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
  standalone = false,
  collaborationPanel,
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
  const canvasSizeRef = useRef({ ...DIAGRAM_CANVAS });
  const suppressGraphSyncRef = useRef(false);
  const seenEventsRef = useRef(new Set<string>());
  const lastPeerCountRef = useRef(peerCount);
  const onSendRef = useRef(onSend);
  onSendRef.current = onSend;

  const [isExpanded, setIsExpanded] = useState(false);
  const [showCollaborationPanel, setShowCollaborationPanel] = useState(false);
  const isFullViewport = standalone || isExpanded;
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
  const [inspectorTab, setInspectorTab] = useState<"design" | "comments" | "versions">("design");
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

  useEffect(() => {
    canvasSizeRef.current = { ...DIAGRAM_CANVAS };
  }, [boardKey]);

  useEffect(() => {
    if (!isFullViewport) return;
    const previousOverflow = window.document.body.style.overflow;
    const previousOverscrollBehavior = window.document.body.style.overscrollBehavior;
    window.document.body.style.overflow = "hidden";
    window.document.body.style.overscrollBehavior = "none";
    return () => {
      window.document.body.style.overflow = previousOverflow;
      window.document.body.style.overscrollBehavior = previousOverscrollBehavior;
    };
  }, [isFullViewport]);

  useEffect(() => {
    if (!showCollaborationPanel) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setShowCollaborationPanel(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [showCollaborationPanel]);

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
        if (active) setStatus(error instanceof Error ? error.message : "扩展图形库加载失败");
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
    graph.setMinimumGraphSize(new Rectangle(0, 0, canvasSizeRef.current.width, canvasSizeRef.current.height));
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

    let canvasExpansionFrame: number | null = null;
    const refreshCanvasExtent = () => {
      canvasExpansionFrame = null;
      const parent = graph.getDefaultParent();
      const contentBounds = graph.getBoundingBoxFromGeometry(graph.getChildVertices(parent), true);
      const nextSize = expandedDiagramCanvasSize(
        canvasSizeRef.current,
        contentBounds,
        container.clientWidth,
        container.clientHeight,
        graph.getView().scale,
      );
      const sizeChanged = nextSize.width !== canvasSizeRef.current.width || nextSize.height !== canvasSizeRef.current.height;
      if (sizeChanged) {
        canvasSizeRef.current = { ...nextSize, gridSize: DIAGRAM_CANVAS.gridSize };
      }
      const minimumSize = graph.getMinimumGraphSize();
      if (sizeChanged || minimumSize?.width !== nextSize.width || minimumSize?.height !== nextSize.height) {
        graph.setMinimumGraphSize(new Rectangle(0, 0, nextSize.width, nextSize.height));
      }
      graph.sizeDidChange();
      outlineRef.current?.update(true);
    };
    const scheduleCanvasExpansion = () => {
      if (canvasExpansionFrame !== null) return;
      canvasExpansionFrame = window.requestAnimationFrame(refreshCanvasExtent);
    };

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
      scheduleCanvasExpansion();
    };
    renderGraphRef.current = renderFromDocument;

    const modelListener = () => {
      scheduleGraphSync();
      scheduleCanvasExpansion();
    };
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
    const resizeObserver = new ResizeObserver(scheduleCanvasExpansion);
    resizeObserver.observe(container);
    runtimeRef.current = {
      graph,
      destroy: () => {
        if (canvasExpansionFrame !== null) {
          window.cancelAnimationFrame(canvasExpansionFrame);
          canvasExpansionFrame = null;
        }
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
      if (canvasExpansionFrame !== null) {
        window.cancelAnimationFrame(canvasExpansionFrame);
        canvasExpansionFrame = null;
      }
      renderGraphRef.current = () => undefined;
      flushGraphRef.current = () => undefined;
      resizeObserver.disconnect();
      graph.getDataModel().removeListener(modelListener);
      graph.getSelectionModel().removeListener(selectionListener);
      container.removeEventListener("pointermove", presencePointerListener);
      graph.destroy();
    };
  }, [activePageId, boardKey, documentEpoch, ensureStencilLibraryLoaded, isFullViewport, isReadOnly, peerId, scheduleDocumentRender, sendPresence]);

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
    outline.border = 16;
    outline.setZoomEnabled(false);
    outline.update(true);
    const resizeObserver = new ResizeObserver(() => outline.update(true));
    resizeObserver.observe(container);
    return () => {
      resizeObserver.disconnect();
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

  const insertTemplate = useCallback((templateId: DiagramTemplateId = "approval") => {
    if (isReadOnly) return;
    withGraph((graph) => {
      const template = DIAGRAM_TEMPLATES[templateId];
      const currentNodeCount = nodesMapRef.current?.size ?? readGraphDocument(graph, activePageId).nodes.length;
      if (currentNodeCount + template.nodes.length > MAX_DIAGRAM_NODES) {
        setStatus("节点数量不足以插入模板。");
        return;
      }
      const parent = graph.getDefaultParent();
      const scale = graph.getView().scale || 1;
      const translate = graph.getView().translate;
      const viewportLeft = graph.container.scrollLeft / scale - translate.x;
      const viewportTop = graph.container.scrollTop / scale - translate.y;
      const viewportWidth = graph.container.clientWidth / scale;
      const viewportHeight = graph.container.clientHeight / scale;
      const templateWidth = Math.max(...template.nodes.map((node) => node.dx + node.width));
      const templateHeight = Math.max(...template.nodes.map((node) => node.dy + node.height));
      const baseX = graph.snap(Math.max(40, viewportLeft + Math.max(32, (viewportWidth - templateWidth) / 2)));
      const baseY = graph.snap(Math.max(40, viewportTop + Math.max(32, (viewportHeight - templateHeight) / 2)));
      const cells: Cell[] = [];
      const cellsByTemplateId = new Map<string, Cell>();
      graph.batchUpdate(() => {
        for (const [index, definition] of template.nodes.entries()) {
          const defaults = nodeDefaults(definition.kind);
          const node: DiagramNode = {
            id: createDiagramId(peerId, definition.kind),
            kind: definition.kind,
            label: definition.label,
            x: baseX + definition.dx,
            y: baseY + definition.dy,
            width: definition.width,
            height: definition.height,
            zIndex: currentNodeCount + index,
            pageId: activePageId,
            style: { ...defaults.style, ...definition.style },
          };
          const cell = graph.insertVertex({
            parent,
            id: node.id,
            value: node.label,
            position: [node.x, node.y],
            size: [node.width, node.height],
            style: nodeCellStyle(node),
          });
          cells.push(cell);
          cellsByTemplateId.set(definition.id, cell);
        }
        for (const [index, definition] of template.edges.entries()) {
          const source = cellsByTemplateId.get(definition.sourceId);
          const target = cellsByTemplateId.get(definition.targetId);
          if (!source || !target) continue;
          const style = { ...defaultEdgeStyle(), ...definition.style };
          const edge = graph.insertEdge({
            parent,
            id: createDiagramId(peerId, "edge"),
            value: definition.label ?? "",
            source,
            target,
            style: edgeCellStyle({
              id: "template",
              label: definition.label ?? "",
              sourceId: "source",
              targetId: "target",
              sourcePort: definition.sourcePort,
              targetPort: definition.targetPort,
              zIndex: currentNodeCount + template.nodes.length + index,
              style,
            }),
          });
          graph.setConnectionConstraint(edge, source, true, constraintForPort(definition.sourcePort));
          graph.setConnectionConstraint(edge, target, false, constraintForPort(definition.targetPort));
        }
      });
      graph.setSelectionCells(cells);
      graph.scrollCellToVisible(cells[0], false);
      setStatus(`${template.name}示例已插入，可直接替换文字和关系。`);
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

  const updateSelectedStyle = useCallback((key: DiagramEditableStyleKey, value: string | boolean | number) => {
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
      const cosmeticKeys = [
        "fillColor", "strokeColor", "fontColor", "labelBackgroundColor", "strokeWidth", "dashed", "dashPattern",
        "fontSize", "fontFamily", "fontStyle", "align", "verticalAlign", "spacing", "opacity", "shadow", "rounded",
        "flipH", "flipV", "startSize", "endSize",
      ] as const;
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

  const updateTextFontSize = useCallback((fontSize: number) => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells();
      graph.batchUpdate(() => {
        cells.forEach((cell) => {
          const style = cell.getClonedStyle() as DiagramCellStyle;
          style.fontSize = fontSize;
          graph.getDataModel().setStyle(cell, style);

          if (!cell.isVertex()) return;
          const kind = style.diagramKind;
          if (!kind || !isDiamondLikeKind(kind)) return;
          const geometry = cell.getGeometry()?.clone();
          if (!geometry) return;
          const defaults = nodeDefaults(kind);
          const scale = Math.max(1, fontSize / 14);
          const minimumWidth = Math.round(defaults.width * scale);
          const minimumHeight = Math.round(defaults.height * scale);
          if (geometry.width >= minimumWidth && geometry.height >= minimumHeight) return;
          const nextWidth = Math.max(geometry.width, minimumWidth);
          const nextHeight = Math.max(geometry.height, minimumHeight);
          geometry.x -= (nextWidth - geometry.width) / 2;
          geometry.y -= (nextHeight - geometry.height) / 2;
          geometry.width = nextWidth;
          geometry.height = nextHeight;
          graph.getDataModel().setGeometry(cell, geometry);
        });
      });
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const updateLinePattern = useCallback((pattern: DiagramLinePattern) => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells();
      graph.batchUpdate(() => {
        cells.forEach((cell) => {
          const style = cell.getClonedStyle();
          style.dashed = pattern !== "solid";
          if (pattern === "dotted") style.dashPattern = "1 4";
          else if (pattern === "dashed") style.dashPattern = "8 4";
          else delete style.dashPattern;
          graph.getDataModel().setStyle(cell, style);
        });
      });
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const toggleTextFontStyle = useCallback((mask: 1 | 2 | 4) => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells();
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

  const updateTextAlign = useCallback((align: "left" | "center" | "right") => {
    withGraph((graph) => {
      graph.setCellStyles("align", align, graph.getSelectionCells());
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const updateTextFontFamily = useCallback((fontFamily: DiagramFontFamily) => {
    withGraph((graph) => {
      graph.setCellStyles("fontFamily", diagramFontFamilyCss(fontFamily), graph.getSelectionCells());
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const updateNodeGeometry = useCallback((key: "x" | "y" | "width" | "height", value: number) => {
    withGraph((graph) => {
      const cell = graph.getSelectionCell();
      if (!cell?.isVertex() || graph.getSelectionCells().length !== 1) return;
      const geometry = cell.getGeometry()?.clone();
      if (!geometry) return;
      if (key === "x" || key === "y") geometry[key] = clampNumber(value, -100_000, 100_000);
      else geometry[key] = clampNumber(value, 20, 100_000);
      graph.getDataModel().setGeometry(cell, geometry);
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const updateNodeRotation = useCallback((degrees: number) => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells().filter((cell) => cell.isVertex());
      graph.setCellStyles("rotation", normalizeRotation(degrees), cells);
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
      canvasSizeRef.current,
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
      canvasSizeRef.current,
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
      canvasSizeRef.current,
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
    const source = exportPlantUmlDocument(createDiagramDocument(Array.from(nodes.values()), Array.from(edges.values()), canvasSizeRef.current, new Date(), pages, activePageId));
    downloadDiagramFile(source, "text/plain;charset=utf-8", diagramExportFileName(new Date(), ".puml"));
    setStatus(`已导出包含 ${pages.length} 个页面的 PlantUML 文档。`);
  }, [activePageId, pages]);

  const exportVisio = useCallback(() => {
    flushGraphRef.current();
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    if (!nodes || !edges) return;
    const source = exportVisioVdx(createDiagramDocument(Array.from(nodes.values()), Array.from(edges.values()), canvasSizeRef.current, new Date(), pages, activePageId));
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
      canvasSizeRef.current = {
        width: Math.max(DIAGRAM_CANVAS.width, imported.canvas.width),
        height: Math.max(DIAGRAM_CANVAS.height, imported.canvas.height),
        gridSize: DIAGRAM_CANVAS.gridSize,
      };
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
  const selectionOnlyNodes = selection.isNode && !selection.isEdge;
  const selectionOnlyEdges = selection.isEdge && !selection.isNode;
  const isSingleNode = selectionOnlyNodes && selection.ids.length === 1;
  const activePageName = pages.find((page) => page.id === activePageId)?.name ?? "页面 1";
  const canvasBackground = theme === "dark" ? "#272729" : "#f5f5f7";
  const gridColor = theme === "dark" ? "rgba(255,255,255,.09)" : "rgba(29,29,31,.09)";
  const paletteSearchQuery = paletteQuery.trim().toLowerCase();
  const builtInPaletteResultCount = NODE_PALETTE.filter((item) => !paletteSearchQuery
    || `${item.label} ${item.detail} ${item.category}`.toLowerCase().includes(paletteSearchQuery)).length;
  const libraryResultIsLimited = Boolean(paletteSearchQuery && stencilSearchResults.length === STENCIL_SEARCH_LIMIT);
  const libraryItemCount = paletteSearchQuery
    ? builtInPaletteResultCount + (stencilCatalog ? stencilSearchResults.length : 0)
    : NODE_PALETTE.length + (stencilCatalog?.shapeCount ?? 0);
  const libraryCountLabel = `${libraryItemCount}${libraryResultIsLimited ? "+" : ""}`;
  const librarySummaryLabel = paletteSearchQuery
    ? `${libraryCountLabel} 个匹配`
    : `${PALETTE_CATEGORIES.length + stencilCollections.length} 类 · ${libraryCountLabel} 个图形`;

  const diagram = (
    <section
      className={`diagram-apple ${isFullViewport
        ? "diagram-apple-full fixed inset-0 z-[90] h-[100dvh] overflow-hidden bg-zinc-100 dark:bg-zinc-950"
        : "mt-5 rounded-2xl border border-black/[0.07] bg-zinc-50/70 p-3 shadow-[0_18px_60px_-36px_rgba(15,23,42,0.45)] dark:border-white/[0.08] dark:bg-zinc-950/55 sm:p-4"}${isActive ? "" : " hidden"}`}
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
      {!isFullViewport ? (
        <div className="diagram-apple-intro flex flex-wrap items-center justify-between gap-4 px-1 pb-1">
          <div className="flex min-w-0 items-center gap-3">
            <div className="diagram-apple-intro-icon grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-zinc-950 text-white shadow-sm dark:bg-cyan-300 dark:text-zinc-950">
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
                  <div className="diagram-apple-mode-switch flex rounded-lg border border-black/[0.07] bg-white/70 p-0.5 shadow-sm dark:border-white/[0.08] dark:bg-white/[0.04]">
                    <button
                      type="button"
                      className="diagram-apple-mode-option rounded-md px-2.5 py-1 text-[10px] font-medium text-zinc-500 transition hover:bg-black/[0.04] hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/[0.06] dark:hover:text-white"
                      onClick={switchToWhiteboard}
                    >
                      自由白板
                    </button>
                    <button type="button" className="diagram-apple-mode-option diagram-apple-mode-option-active rounded-md bg-zinc-950 px-2.5 py-1 text-[10px] font-semibold text-white shadow-sm dark:bg-cyan-300 dark:text-zinc-950">
                      专业流程图
                    </button>
                  </div>
                ) : null}
                <span className="diagram-apple-pill inline-flex items-center gap-1.5 rounded-full border border-black/[0.06] bg-white/70 px-2 py-1 text-[10px] font-medium text-zinc-600 dark:border-white/[0.08] dark:bg-white/[0.04] dark:text-zinc-300">
                  <span className={`h-1.5 w-1.5 rounded-full ${isConnected ? "bg-emerald-500 shadow-[0_0_0_3px_rgba(16,185,129,0.12)]" : "bg-zinc-400"}`} />
                  {isConnected ? "实时同步" : "本地编辑"}
                </span>
                <span className="hidden text-[10px] text-zinc-400 xl:inline">{totalPeers} 位协作者 · {nodeCount} 个节点 · {edgeCount} 条连线</span>
              </div>
            </div>
          </div>
          <button type="button" className="diagram-apple-primary-action inline-flex h-9 items-center gap-2 rounded-lg border border-black/[0.08] bg-white px-3 text-tiny font-semibold text-zinc-700 shadow-sm transition hover:-translate-y-px hover:border-cyan-400 hover:text-cyan-800 dark:border-white/[0.1] dark:bg-white/[0.05] dark:text-zinc-200 dark:hover:border-cyan-300/50 dark:hover:text-cyan-100" onClick={() => setIsExpanded(true)}>
            <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 2H2v4M10 2h4v4M6 14H2v-4M10 14h4v-4" /></svg>
            全屏编辑
          </button>
        </div>
      ) : null}

      <div className={isFullViewport
        ? "diagram-apple-shell absolute inset-0 flex min-h-0 flex-col overflow-hidden bg-zinc-100 dark:bg-[#090c11]"
        : "diagram-apple-shell mt-3 flex h-[min(78dvh,680px)] min-h-[540px] min-w-0 flex-col overflow-hidden rounded-xl border border-black/[0.09] bg-white shadow-[0_24px_70px_-38px_rgba(15,23,42,0.55)] dark:border-white/[0.09] dark:bg-[#0c1016] sm:h-[680px] md:h-[720px] lg:h-[760px] xl:h-[820px]"}
      >
        <div className="diagram-apple-toolbar flex shrink-0 flex-nowrap items-center gap-0.5 overflow-x-auto border-b border-black/[0.07] bg-white/95 px-1.5 py-1 backdrop-blur-xl [scrollbar-width:none] dark:border-white/[0.08] dark:bg-[#11161e]/95 sm:px-2 sm:py-1.5" role="toolbar" aria-label="流程图操作">
          <div className="diagram-apple-toolbar-brand mr-1 flex h-8 shrink-0 items-center gap-2 border-r border-black/[0.07] pr-2 dark:border-white/[0.08] sm:mr-2 sm:pr-3">
            <span className="diagram-apple-toolbar-icon grid h-6 w-6 place-items-center rounded-md bg-zinc-950 text-white dark:bg-cyan-300 dark:text-zinc-950">
              <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.7" viewBox="0 0 16 16" aria-hidden="true"><rect x="1.5" y="2" width="4" height="3.5" rx=".7" /><rect x="10.5" y="10.5" width="4" height="3.5" rx=".7" /><path d="M5.5 3.7h2.2a2 2 0 0 1 2 2v4.8" /></svg>
            </span>
            <span className="hidden min-w-0 sm:block">
              <span className="block max-w-28 truncate text-[11px] font-semibold text-zinc-800 dark:text-zinc-100">{activePageName}</span>
              <span className="block text-[9px] text-zinc-400">专业流程图</span>
            </span>
          </div>
          {isFullViewport ? (
            <>
              {onSwitchToWhiteboard ? (
                <DiagramToolbarButton label="白板" onClick={() => {
                  setIsExpanded(false);
                  switchToWhiteboard();
                }} />
              ) : null}
              {!standalone ? <DiagramToolbarButton label="退出全屏" onClick={() => setIsExpanded(false)} /> : null}
              <span className="diagram-apple-separator mx-1 h-6 w-px shrink-0 bg-black/[0.07] dark:bg-white/[0.08]" />
            </>
          ) : null}
          <DiagramToolbarButton label={isRoleReadOnly ? "访客只读" : localReadOnly ? "只读预览" : "编辑模式"} disabled={isRoleReadOnly} onClick={() => {
            setLocalReadOnly((value) => !value);
            setContextMenu(null);
            setStatus(isReadOnly ? "已恢复编辑模式。" : "已进入本地只读预览，协作更新仍会继续接收。");
          }} />
          <span className="diagram-apple-separator mx-1 h-6 w-px shrink-0 bg-black/[0.07] dark:bg-white/[0.08]" />
          <DiagramToolbarButton label="撤销" shortcut="⌘Z" disabled={isReadOnly || !canUndo} onClick={() => {
            undoManagerRef.current?.undo();
            refreshUndoState();
          }} />
          <DiagramToolbarButton label="重做" shortcut="⇧⌘Z" disabled={isReadOnly || !canRedo} onClick={() => {
            undoManagerRef.current?.redo();
            refreshUndoState();
          }} />
          <span className="diagram-apple-separator mx-1 h-6 w-px shrink-0 bg-black/[0.07] dark:bg-white/[0.08]" />
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
              ...(collaborationPanel ? [{ key: "room", label: "房间与协作" }] : []),
              { key: "comment", label: "添加评论", disabled: isReadOnly },
              { key: "version", label: isVersionLoading ? "版本处理中" : "创建版本", disabled: isRoleReadOnly || isVersionLoading },
            ]}
            onAction={(key) => {
              if (key === "room") setShowCollaborationPanel(true);
              else if (key === "comment") {
                setInspectorTab("comments");
                setCompactPanel("inspector");
                addComment();
              } else if (key === "version") {
                setInspectorTab("versions");
                setCompactPanel("inspector");
                void createVersion();
              }
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

        <div className="diagram-apple-pages flex h-10 shrink-0 items-end border-b border-black/[0.07] bg-zinc-50/90 px-2 dark:border-white/[0.08] dark:bg-[#0d1118]" aria-label="流程图页面">
          <div className="flex min-w-0 flex-1 items-end gap-0.5 overflow-x-auto">
            <span className="diagram-apple-section-label mb-2 mr-1 shrink-0 px-1 text-[9px] font-semibold uppercase tracking-[0.16em] text-zinc-400">Pages</span>
            {pages.map((page) => (
              <button
                key={page.id}
                type="button"
                aria-pressed={page.id === activePageId}
                className={`diagram-apple-page-tab relative h-9 shrink-0 rounded-t-lg border border-b-0 px-4 text-[11px] font-medium transition ${page.id === activePageId
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

        <div className="diagram-apple-mobile-panel flex h-11 shrink-0 items-center justify-between border-b border-black/[0.07] bg-white/95 px-2 dark:border-white/[0.08] dark:bg-[#11161e]/95 lg:hidden">
          <div className="diagram-apple-mobile-switch grid grid-cols-3 gap-1 rounded-lg bg-black/[0.035] p-1 dark:bg-white/[0.045]" role="toolbar" aria-label="移动端流程图面板">
            <CompactPanelButton label="图库" active={compactPanel === "library"} onClick={() => setCompactPanel((current) => current === "library" ? null : "library")}>
              <path d="M3 3h4v4H3zM9 3h4v4H9zM3 9h4v4H3zM9 9h4v4H9z" />
            </CompactPanelButton>
            <CompactPanelButton label="画布" active={compactPanel === null} onClick={() => setCompactPanel(null)}>
              <path d="M2.5 3.5h11v9h-11zM5 6h6M5 8.5h4" />
            </CompactPanelButton>
            <CompactPanelButton label="属性" active={compactPanel === "inspector"} onClick={() => setCompactPanel((current) => {
              if (current === "inspector") return null;
              setInspectorTab("design");
              return "inspector";
            })}>
              <path d="M3 4h10M3 8h10M3 12h10M6 2.5v3M10 6.5v3M7 10.5v3" />
            </CompactPanelButton>
          </div>
          <span className="min-w-0 truncate pl-2 text-right text-[9px] text-zinc-400">{nodeCount} 节点 · {edgeCount} 连线</span>
        </div>

        <div className="diagram-apple-workspace relative grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[260px_minmax(0,1fr)_300px]">
          {compactPanel ? (
            <button
              type="button"
              aria-label="关闭侧边面板"
              className="absolute inset-0 z-20 bg-zinc-950/35 backdrop-blur-[1px] lg:hidden"
              onClick={() => setCompactPanel(null)}
            />
          ) : null}
          <aside className={`diagram-apple-library ${compactPanel === "library" ? "block" : "hidden"} absolute inset-y-0 left-0 z-30 w-[min(86vw,310px)] max-w-full overflow-y-auto border-r border-black/[0.07] bg-zinc-50 p-3 shadow-2xl dark:border-white/[0.08] dark:bg-[#0f141c] lg:static lg:z-auto lg:block lg:w-auto lg:max-w-none lg:shadow-none`}>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-[11px] font-semibold text-zinc-800 dark:text-zinc-100">图形库</div>
                <div className="mt-0.5 text-[10px] text-zinc-400">拖拽或点击添加</div>
              </div>
              <span className="flex items-center gap-1.5">
                <span className="rounded-md bg-black/[0.04] px-1.5 py-0.5 font-mono text-[10px] text-zinc-400 dark:bg-white/[0.05]">{libraryCountLabel}</span>
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
                className="diagram-apple-search h-9 w-full rounded-lg border border-black/[0.07] bg-white pl-8 pr-2.5 text-[11px] text-zinc-800 shadow-sm outline-none transition placeholder:text-zinc-400 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10 dark:border-white/[0.08] dark:bg-white/[0.035] dark:text-zinc-100"
                onChange={(event) => setPaletteQuery(event.currentTarget.value)}
              />
            </label>
            <div className="mt-4 block">
              <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-400">快速模板</div>
              <div className="mt-2 grid grid-cols-3 gap-1.5">
                {(Object.entries(DIAGRAM_TEMPLATES) as Array<[DiagramTemplateId, DiagramTemplateDefinition]>).map(([id, template]) => (
                  <button
                    key={id}
                    type="button"
                    disabled={isReadOnly}
                    className="diagram-apple-template-button group min-w-0 rounded-lg border border-cyan-500/20 bg-cyan-50/70 px-2 py-2 text-center transition hover:border-cyan-500/50 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-35 dark:border-cyan-300/15 dark:bg-cyan-300/[0.06] dark:hover:border-cyan-300/35 dark:hover:bg-cyan-300/[0.1]"
                    onClick={() => {
                      insertTemplate(id);
                      setCompactPanel(null);
                    }}
                  >
                    <span className="block text-[11px] font-semibold text-cyan-800 dark:text-cyan-100">{template.shortName}</span>
                    <span className="mt-0.5 block truncate text-[9px] text-cyan-700/60 dark:text-cyan-200/50">{template.detail}</span>
                  </button>
                ))}
              </div>
            </div>
            <div className="mt-3 min-w-0 border-t border-black/[0.05] pt-3 dark:border-white/[0.06]">
              <div className="mb-2 flex items-center justify-between px-1">
                <span className="diagram-apple-section-label text-[10px]">
                  {paletteSearchQuery ? "搜索结果" : "完整图库"}
                </span>
                <span className="font-mono text-[9px] text-zinc-400">{librarySummaryLabel}</span>
              </div>
              {PALETTE_CATEGORIES.map((category) => {
                const items = NODE_PALETTE.filter((item) => item.category === category
                  && (!paletteSearchQuery || `${item.label} ${item.detail} ${item.category}`.toLowerCase().includes(paletteSearchQuery)));
                if (items.length === 0) return null;
                const isCategoryOpen = Boolean(paletteSearchQuery) || openPaletteCategories.has(category);
                return (
                  <div key={category} className="mt-1.5 block overflow-hidden rounded-lg border border-black/[0.06] bg-white/55 dark:border-white/[0.07] dark:bg-white/[0.02]">
                    <button
                      type="button"
                      className="diagram-apple-collapse-row flex h-8 w-full items-center justify-between px-2 text-left transition hover:bg-black/[0.035] dark:hover:bg-white/[0.04]"
                      aria-expanded={isCategoryOpen}
                      onClick={() => setOpenPaletteCategories((current) => {
                        const next = new Set(current);
                        if (next.has(category)) next.delete(category);
                        else next.add(category);
                        return next;
                      })}
                    >
                      <span className="flex min-w-0 items-center gap-1.5 text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">
                        <svg className={`h-3 w-3 shrink-0 text-zinc-400 transition-transform ${isCategoryOpen ? "rotate-90" : ""}`} fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 16 16" aria-hidden="true"><path d="m6 3 5 5-5 5" /></svg>
                        <span className="truncate">{category}</span>
                      </span>
                      <span className="font-mono text-[9px] text-zinc-400">{items.length}</span>
                    </button>
                    <div className={`border-t border-black/[0.05] p-1 dark:border-white/[0.06] ${isCategoryOpen ? "block" : "hidden"}`}>
                      <div className="grid grid-cols-3 gap-1">
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
                            className="diagram-apple-palette-card group flex min-h-[76px] min-w-0 flex-col items-center gap-1 rounded-lg border border-black/[0.07] bg-white px-1 py-1.5 text-center shadow-[0_1px_1px_rgba(15,23,42,0.03)] transition hover:-translate-y-px hover:border-cyan-400 hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 disabled:cursor-not-allowed disabled:opacity-35 dark:border-white/[0.08] dark:bg-white/[0.035] dark:hover:border-cyan-300/40 dark:hover:bg-cyan-300/[0.06]"
                            onClick={() => {
                              insertNode(item.kind);
                              setCompactPanel(null);
                            }}
                          >
                            <DiagramNodeGlyph kind={item.kind} />
                            <span className="min-w-0 w-full">
                              <span className="diagram-apple-palette-label block truncate text-[10px] font-semibold text-zinc-800 dark:text-zinc-100">{item.label}</span>
                              <span className="diagram-apple-palette-detail block truncate text-[9px] text-zinc-400">{item.detail}</span>
                            </span>
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })}
              {paletteSearchQuery && stencilCatalog ? (
                <div className="diagram-apple-collection mt-1.5 overflow-hidden rounded-lg border border-black/[0.06] bg-white/55 dark:border-white/[0.07] dark:bg-white/[0.02]">
                  <div className="flex h-8 items-center justify-between px-2">
                    <span className="truncate text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">更多匹配</span>
                    <span className="font-mono text-[9px] text-zinc-400">{stencilSearchResults.length}{stencilSearchResults.length === STENCIL_SEARCH_LIMIT ? "+" : ""}</span>
                  </div>
                  {stencilSearchResults.length ? (
                    <div className="border-t border-black/[0.05] p-1 dark:border-white/[0.06]">
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
                              className="diagram-apple-palette-card group flex min-h-[76px] min-w-0 flex-col items-center justify-center rounded-lg border border-black/[0.07] bg-white px-1 py-1.5 text-center transition hover:-translate-y-px hover:border-cyan-400 hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 disabled:opacity-35 dark:border-white/[0.08] dark:bg-white/[0.035] dark:hover:border-cyan-300/40 dark:hover:bg-cyan-300/[0.06]"
                              onClick={() => {
                                void insertStencilNode(library, shape);
                                setCompactPanel(null);
                              }}
                            >
                              <DrawioStencilGlyph stencilName={shape.shape} loaded={isLoaded} />
                              <span className="diagram-apple-palette-label mt-1 block w-full truncate text-[10px] font-semibold text-zinc-700 dark:text-zinc-200">{shape.name}</span>
                              <span className="diagram-apple-palette-detail block w-full truncate text-[9px] text-zinc-400">{library.name}</span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  ) : <div className="border-t border-black/[0.05] p-4 text-center text-[10px] text-zinc-400 dark:border-white/[0.06]">未找到匹配图形</div>}
                </div>
              ) : null}
              {!paletteSearchQuery && stencilCatalog ? (
                <>
                  {stencilCatalog.groups.map((group) => {
                    const collections = stencilCollections.filter((collection) => collection.group === group.id);
                    if (!collections.length) return null;
                    const isGroupOpen = openStencilGroups.has(group.id);
                    return (
                      <div key={group.id} className="diagram-apple-collection mt-1.5 overflow-hidden rounded-lg border border-black/[0.06] bg-white/60 dark:border-white/[0.07] dark:bg-white/[0.02]">
                        <button
                          type="button"
                          className="diagram-apple-collapse-row flex h-8 w-full items-center justify-between px-2 text-left transition hover:bg-black/[0.03] dark:hover:bg-white/[0.04]"
                          aria-expanded={isGroupOpen}
                          onClick={() => setOpenStencilGroups((current) => {
                            const next = new Set(current);
                            if (next.has(group.id)) next.delete(group.id);
                            else next.add(group.id);
                            return next;
                          })}
                        >
                          <span className="flex min-w-0 items-center gap-1.5 text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">
                            <svg className={`h-3 w-3 shrink-0 text-zinc-400 transition-transform ${isGroupOpen ? "rotate-90" : ""}`} fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 16 16" aria-hidden="true"><path d="m6 3 5 5-5 5" /></svg>
                            <span className="truncate">{group.name}</span>
                          </span>
                          <span className="font-mono text-[9px] text-zinc-400">{collections.length}</span>
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
                                    className={`diagram-apple-collection-row flex h-8 w-full items-center justify-between rounded-md px-2 text-left transition ${isActive ? "bg-cyan-500/10 text-cyan-800 dark:text-cyan-100" : "text-zinc-600 hover:bg-black/[0.035] dark:text-zinc-300 dark:hover:bg-white/[0.04]"}`}
                                    onClick={() => openStencilCollection(collection)}
                                  >
                                    <span className="truncate text-[10px] font-medium">{collection.name}</span>
                                    <span className="ml-2 shrink-0 font-mono text-[9px] text-zinc-400">{loadingStencilCollection === collection.id ? "加载中" : collection.libraryCount > 1 ? `${collection.shapeCount} · ${collection.libraryCount}库` : collection.shapeCount}</span>
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
                                            className="diagram-apple-palette-card group flex min-h-[76px] min-w-0 flex-col items-center justify-center rounded-lg border border-black/[0.07] bg-white px-1 py-1.5 text-center transition hover:-translate-y-px hover:border-cyan-400 hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 disabled:opacity-35 dark:border-white/[0.08] dark:bg-white/[0.035] dark:hover:border-cyan-300/40 dark:hover:bg-cyan-300/[0.06]"
                                            onClick={() => {
                                              void insertStencilNode(library, shape);
                                              setCompactPanel(null);
                                            }}
                                          >
                                            <DrawioStencilGlyph stencilName={shape.shape} loaded={isLoaded} />
                                            <span className="diagram-apple-palette-label mt-1 block w-full truncate text-[10px] font-semibold text-zinc-700 dark:text-zinc-200">{shape.name}</span>
                                            {collection.libraryCount > 1 ? <span className="diagram-apple-palette-detail block w-full truncate text-[9px] text-zinc-400">{library.name}</span> : null}
                                          </button>
                                        );
                                      })}
                                      {collection.shapeCount > stencilShapeLimit ? (
                                        <button type="button" className="col-span-3 rounded-md border border-dashed border-black/10 px-2 py-2 text-[10px] font-medium text-cyan-700 hover:bg-cyan-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 dark:border-white/10 dark:text-cyan-200 dark:hover:bg-cyan-300/10" onClick={() => setStencilShapeLimit((current) => current + STENCIL_PAGE_SIZE)}>
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
                </>
              ) : null}
              {paletteSearchQuery && builtInPaletteResultCount === 0 && (!stencilCatalog || stencilSearchResults.length === 0) ? (
                <div className="mt-1.5 rounded-lg border border-dashed border-black/10 p-4 text-center text-[10px] text-zinc-400 dark:border-white/10">未找到匹配图形</div>
              ) : null}
            </div>
          </aside>

          <div
            className="diagram-apple-canvas-wrap relative min-h-0 overflow-hidden bg-zinc-100 dark:bg-[#0b0f15]"
            onKeyDown={handleKeyDown}
            onPointerDown={() => {
              setContextMenu(null);
              graphContainerRef.current?.focus();
            }}
            onContextMenu={openContextMenu}
          >
            <div
              ref={graphContainerRef}
              className="diagram-apple-canvas absolute inset-0 overflow-auto outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-400"
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
                <div key={presence.peerId} className="diagram-apple-remote-cursor pointer-events-none absolute z-30" style={{ left, top }}>
                  <span className="block h-3 w-3 rotate-45 border-l-2 border-t-2 border-blue-600" />
                  <span className="ml-2 rounded bg-blue-600 px-1.5 py-0.5 text-[9px] font-semibold text-white shadow">{presence.peerId.slice(0, 12)} · {presence.selectedIds.length} selected</span>
                </div>
              );
            })}
            {showMinimap ? (
              <div className="diagram-apple-minimap absolute bottom-12 right-3 z-20 hidden h-28 w-40 overflow-hidden rounded-xl border border-black/[0.1] bg-white/95 shadow-[0_12px_35px_-12px_rgba(15,23,42,0.4)] backdrop-blur-xl dark:border-white/[0.12] dark:bg-[#151b24]/95 sm:block sm:h-32 sm:w-48">
                <div className="absolute inset-1.5 overflow-hidden rounded-lg">
                  <div ref={outlineContainerRef} className="h-full w-full" aria-label="流程图小地图" />
                </div>
              </div>
            ) : null}
            <div className="diagram-apple-canvas-hint pointer-events-none absolute bottom-3 left-3 hidden items-center gap-2 rounded-lg border border-black/[0.08] bg-white/85 px-2.5 py-1.5 text-[9px] text-zinc-500 shadow-sm backdrop-blur-xl dark:border-white/[0.09] dark:bg-[#151b24]/85 dark:text-zinc-400 sm:flex">
              <span className="grid h-4 w-4 place-items-center rounded bg-cyan-500/10 text-[9px] font-bold text-cyan-700 dark:text-cyan-200">?</span>
              拖入节点 · 移动显示参考线 · Shift 点击连线增删折点
            </div>
            {contextMenu ? (
              <div
                className="diagram-apple-context-menu absolute z-30 w-44 rounded-lg border border-black/10 bg-white p-1.5 text-tiny text-zinc-700 shadow-xl dark:border-white/10 dark:bg-zinc-900 dark:text-zinc-200"
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

          <aside className={`diagram-apple-inspector ${compactPanel === "inspector" ? "block" : "hidden"} absolute inset-y-0 right-0 z-30 w-[min(90vw,340px)] max-w-full overflow-y-auto border-l border-black/[0.07] bg-zinc-50 shadow-2xl dark:border-white/[0.08] dark:bg-[#0f141c] lg:static lg:z-auto lg:block lg:w-auto lg:max-w-none lg:shadow-none`}>
            <div className="diagram-apple-inspector-header sticky top-0 z-10 flex h-12 items-center justify-between gap-2 border-b border-black/[0.06] bg-zinc-50/95 px-4 backdrop-blur-xl dark:border-white/[0.07] dark:bg-[#0f141c]/95">
              <span>
                <span className="block text-[11px] font-semibold text-zinc-900 dark:text-zinc-100">
                  {inspectorTab === "design" ? "设计属性" : inspectorTab === "comments" ? "协作评论" : "版本历史"}
                </span>
                <span className="block text-[9px] text-zinc-400">
                  {inspectorTab === "design" ? "样式、文字与几何" : inspectorTab === "comments" ? "页面与元素讨论" : "快照、恢复与回溯"}
                </span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="rounded-md bg-black/[0.04] px-1.5 py-1 text-[9px] font-medium text-zinc-500 dark:bg-white/[0.05] dark:text-zinc-400">
                  {inspectorTab === "design"
                    ? (selection.ids.length > 0 ? `${selection.ids.length} 个元素` : "未选择")
                    : inspectorTab === "comments"
                      ? `${comments.filter((comment) => comment.pageId === activePageId).length} 条`
                      : `${versions.length} 个`}
                </span>
                <button type="button" className="grid h-8 w-8 place-items-center rounded-lg text-zinc-400 hover:bg-black/[0.05] hover:text-zinc-700 dark:hover:bg-white/[0.06] dark:hover:text-zinc-100 lg:hidden" aria-label="关闭设计属性" onClick={() => setCompactPanel(null)}>
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8M12 4l-8 8" /></svg>
                </button>
              </span>
            </div>
            <div className="sticky top-12 z-10 grid h-10 grid-cols-3 border-b border-black/[0.06] bg-zinc-50/95 px-2 backdrop-blur-xl dark:border-white/[0.07] dark:bg-[#0f141c]/95" role="tablist" aria-label="设计属性模块">
              <InspectorTabButton label="设计" active={inspectorTab === "design"} onClick={() => setInspectorTab("design")} />
              <InspectorTabButton label={`评论 ${comments.filter((comment) => comment.pageId === activePageId).length}`} active={inspectorTab === "comments"} onClick={() => setInspectorTab("comments")} />
              <InspectorTabButton label={`版本 ${versions.length}`} active={inspectorTab === "versions"} onClick={() => setInspectorTab("versions")} />
            </div>
            <div className="p-3.5">
            {inspectorTab === "design" ? <fieldset disabled={isReadOnly} className={isReadOnly ? "opacity-60" : undefined}>
            {selection.ids.length === 0 ? (
              <div className="diagram-apple-empty-state rounded-xl border border-dashed border-black/[0.1] bg-white/60 px-4 py-6 text-center dark:border-white/[0.1] dark:bg-white/[0.025]">
                <div className="mx-auto grid h-9 w-9 place-items-center rounded-xl bg-zinc-100 text-zinc-400 dark:bg-white/[0.05]">
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true"><path d="m3 2 9 5-4 1.5L6.5 13z" /><path d="m9 9 3 4" /></svg>
                </div>
                <div className="mt-3 text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">选择画布元素</div>
                <div className="mt-1 text-[10px] leading-4 text-zinc-400">选中节点或连线后，在这里调整位置、尺寸、文字与外观。</div>
              </div>
            ) : (
              <div className="divide-y divide-black/[0.07] dark:divide-white/[0.08]">
                {selection.ids.length === 1 ? (
                  <InspectorSection title="内容">
                    <label className="block">
                      <span className="sr-only">元素文字</span>
                      <textarea
                        value={selection.label}
                        maxLength={500}
                        rows={3}
                        className="diagram-apple-text-field w-full resize-y rounded-md border border-black/10 bg-white px-2.5 py-2 text-[11px] leading-5 text-zinc-900 outline-none focus:border-cyan-400 dark:border-white/10 dark:bg-zinc-950 dark:text-zinc-100"
                        onChange={(event) => setSelection((current) => ({ ...current, label: event.currentTarget.value }))}
                        onBlur={(event) => commitSelectionLabel(event.currentTarget.value)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) event.currentTarget.blur();
                        }}
                      />
                    </label>
                  </InspectorSection>
                ) : null}

                {isSingleNode ? (
                  <InspectorSection title="位置与尺寸">
                    <div className="grid grid-cols-2 gap-2">
                      <InspectorNumberField label="X" value={selection.x} min={-100000} max={100000} onCommit={(value) => updateNodeGeometry("x", value)} />
                      <InspectorNumberField label="Y" value={selection.y} min={-100000} max={100000} onCommit={(value) => updateNodeGeometry("y", value)} />
                      <InspectorNumberField label="宽度" value={selection.width} min={20} max={100000} onCommit={(value) => updateNodeGeometry("width", value)} />
                      <InspectorNumberField label="高度" value={selection.height} min={20} max={100000} onCommit={(value) => updateNodeGeometry("height", value)} />
                    </div>
                  </InspectorSection>
                ) : null}

                {selectionOnlyNodes ? (
                  <InspectorSection title="变换">
                    <InspectorNumberField label="旋转角度" value={selection.rotation} min={0} max={359} suffix="°" onCommit={updateNodeRotation} />
                    <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2">
                      <InspectorToggle label="锁定" checked={Boolean(selection.locked)} onChange={toggleNodeLock} />
                      <InspectorToggle label="水平翻转" checked={Boolean(selection.flipH)} onChange={() => updateSelectedStyle("flipH", !selection.flipH)} />
                      <InspectorToggle label="垂直翻转" checked={Boolean(selection.flipV)} onChange={() => updateSelectedStyle("flipV", !selection.flipV)} />
                    </div>
                  </InspectorSection>
                ) : null}

                <InspectorSection title="外观">
                  <div className="space-y-2.5">
                    {selectionOnlyNodes ? (
                      <InspectorColorField label="填充颜色" value={selection.fillColor} fallback="#ffffff" allowNone onCommit={(color) => updateSelectedStyle("fillColor", color)} />
                    ) : null}
                    <InspectorColorField label={selectionOnlyEdges ? "连线颜色" : "边框颜色"} value={selection.strokeColor} fallback="#475569" allowNone onCommit={(color) => updateSelectedStyle("strokeColor", color)} />
                    <div className="grid grid-cols-2 gap-2">
                      <InspectorNumberField label="线宽" value={selection.strokeWidth} min={1} max={12} suffix="px" onCommit={(value) => updateSelectedStyle("strokeWidth", value)} />
                      <InspectorSelectField
                        label="线型"
                        value={selection.linePattern}
                        options={[{ value: "solid", label: "实线" }, { value: "dashed", label: "虚线" }, { value: "dotted", label: "点线" }]}
                        onChange={updateLinePattern}
                      />
                    </div>
                    <InspectorRangeField label="整体透明度" value={selection.opacity ?? 100} min={10} max={100} suffix="%" onChange={(value) => updateSelectedStyle("opacity", value)} />
                    {selectionOnlyNodes ? (
                      <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                        <InspectorToggle label="圆角" checked={Boolean(selection.rounded)} onChange={() => updateSelectedStyle("rounded", !selection.rounded)} />
                        <InspectorToggle label="阴影" checked={Boolean(selection.shadow)} onChange={() => updateSelectedStyle("shadow", !selection.shadow)} />
                      </div>
                    ) : null}
                  </div>
                </InspectorSection>

                <InspectorSection title="文字">
                  <div className="space-y-2.5">
                    <div className="grid grid-cols-[minmax(0,1fr)_92px] gap-2">
                      <InspectorSelectField label="字体" value={selection.fontFamily ?? "system"} options={DIAGRAM_FONT_OPTIONS} onChange={updateTextFontFamily} />
                      <InspectorNumberField label="字号" value={selection.fontSize} min={8} max={96} suffix="px" onCommit={updateTextFontSize} />
                    </div>
                    <InspectorColorField label="文字颜色" value={selection.fontColor} fallback="#172033" onCommit={(color) => updateSelectedStyle("fontColor", color)} />
                    <InspectorColorField label="文字背景" value={selection.labelBackgroundColor} fallback="#ffffff" allowNone onCommit={(color) => updateSelectedStyle("labelBackgroundColor", color)} />
                    <div>
                      <InspectorFieldLabel>字形</InspectorFieldLabel>
                      <div className="mt-1 grid grid-cols-3 overflow-hidden rounded-md border border-black/[0.09] dark:border-white/[0.1]" role="toolbar" aria-label="文字字形">
                        <InspectorTextStyleButton label="粗体" glyph="B" active={Boolean(selection.bold)} onClick={() => toggleTextFontStyle(1)} />
                        <InspectorTextStyleButton label="斜体" glyph="I" italic active={Boolean(selection.italic)} onClick={() => toggleTextFontStyle(2)} />
                        <InspectorTextStyleButton label="下划线" glyph="U" underline active={Boolean(selection.underline)} onClick={() => toggleTextFontStyle(4)} />
                      </div>
                    </div>
                    <InspectorSegmentedField
                      label="水平对齐"
                      value={selection.align ?? "center"}
                      options={[{ value: "left", label: "左" }, { value: "center", label: "中" }, { value: "right", label: "右" }]}
                      onChange={updateTextAlign}
                    />
                    {selectionOnlyNodes ? (
                      <>
                        <InspectorSegmentedField
                          label="垂直对齐"
                          value={selection.verticalAlign ?? "middle"}
                          options={[{ value: "top", label: "上" }, { value: "middle", label: "中" }, { value: "bottom", label: "下" }]}
                          onChange={(value) => updateSelectedStyle("verticalAlign", value)}
                        />
                        <InspectorNumberField label="文字内边距" value={selection.spacing} min={0} max={60} suffix="px" onCommit={(value) => updateSelectedStyle("spacing", value)} />
                      </>
                    ) : null}
                  </div>
                </InspectorSection>

                {selectionOnlyNodes && (selection.isSwimlane || selection.isLane) ? (
                  <InspectorSection title="泳道">
                    <div className="grid grid-cols-2 gap-1.5">
                      {selection.isSwimlane ? (
                        <>
                          <InspectorAction label="添加泳道" onClick={addSwimlaneLane} />
                          <InspectorAction label={selection.swimlaneDirection === "vertical" ? "改为横向" : "改为纵向"} onClick={toggleSwimlaneDirection} />
                        </>
                      ) : null}
                      {selection.isLane ? (
                        <>
                          <InspectorAction label="前移" onClick={() => moveLane(-1)} />
                          <InspectorAction label="后移" onClick={() => moveLane(1)} />
                          <InspectorAction label="删除泳道" onClick={removeLane} />
                        </>
                      ) : null}
                    </div>
                  </InspectorSection>
                ) : null}
                {selectionOnlyEdges ? (
                  <InspectorSection title="连接线">
                    <div className="space-y-2.5">
                      <InspectorSelectField
                        label="路由方式"
                        value={selection.edgeType ?? "orthogonal"}
                        options={[{ value: "orthogonal", label: "正交" }, { value: "straight", label: "直线" }, { value: "elbow", label: "折线" }, { value: "curved", label: "曲线" }]}
                        onChange={updateEdgeType}
                      />
                      <div className="grid grid-cols-2 gap-2">
                        <InspectorSelectField
                          label="起点箭头"
                          value={selection.startArrow ?? "none"}
                          options={DIAGRAM_ARROW_OPTIONS}
                          onChange={(arrow) => updateArrowType("start", arrow)}
                        />
                        <InspectorSelectField
                          label="终点箭头"
                          value={selection.endArrow ?? "block"}
                          options={DIAGRAM_ARROW_OPTIONS}
                          onChange={(arrow) => updateArrowType("end", arrow)}
                        />
                        <InspectorNumberField label="起点大小" value={selection.startSize} min={4} max={40} suffix="px" onCommit={(value) => updateSelectedStyle("startSize", value)} />
                        <InspectorNumberField label="终点大小" value={selection.endSize} min={4} max={40} suffix="px" onCommit={(value) => updateSelectedStyle("endSize", value)} />
                      </div>
                      <div className="grid grid-cols-2 gap-1.5 pt-1">
                        <InspectorAction label="新增折点" onClick={addEdgeWaypoint} />
                        <InspectorAction label="清除折点" onClick={clearEdgeWaypoints} />
                      </div>
                    </div>
                  </InspectorSection>
                ) : null}
              </div>
            )}
            </fieldset> : null}
            {inspectorTab === "comments" ? <div>
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
            </div> : null}
            {inspectorTab === "versions" ? <div>
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
            </div> : null}
            </div>
          </aside>
        </div>

        {showCollaborationPanel && collaborationPanel ? (
          <div className="absolute inset-0 z-[70] flex justify-end" role="presentation">
            <button
              type="button"
              className="absolute inset-0 bg-zinc-950/45 backdrop-blur-[2px]"
              aria-label="关闭房间与协作面板"
              onClick={() => setShowCollaborationPanel(false)}
            />
            <aside
              role="dialog"
              aria-modal="true"
              aria-labelledby="diagram-collaboration-title"
              className="diagram-apple-collaboration relative z-10 flex h-full w-full max-w-[440px] flex-col border-l border-black/10 bg-zinc-50 shadow-2xl dark:border-white/10 dark:bg-[#0f141c] sm:w-[min(92vw,440px)]"
            >
              <div className="diagram-apple-collaboration-header flex h-14 shrink-0 items-center justify-between border-b border-black/[0.07] px-4 dark:border-white/[0.08]">
                <div>
                  <h2 id="diagram-collaboration-title" className="text-sm font-semibold text-zinc-950 dark:text-white">房间与协作</h2>
                  <p className="mt-0.5 text-[10px] text-zinc-500 dark:text-zinc-400">管理连接方式、邀请权限与在线成员</p>
                </div>
                <button
                  type="button"
                  className="grid h-9 w-9 place-items-center rounded-lg text-zinc-500 transition hover:bg-black/[0.05] hover:text-zinc-900 dark:hover:bg-white/[0.06] dark:hover:text-white"
                  aria-label="关闭房间与协作面板"
                  onClick={() => setShowCollaborationPanel(false)}
                >
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8M12 4l-8 8" /></svg>
                </button>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto p-4 overscroll-contain">
                {collaborationPanel}
              </div>
            </aside>
          </div>
        ) : null}

        <div className="diagram-apple-status flex h-8 shrink-0 flex-wrap items-center justify-between gap-2 border-t border-black/[0.07] bg-white/95 px-3 text-[9px] text-zinc-500 dark:border-white/[0.08] dark:bg-[#11161e]/95 dark:text-zinc-400">
          <span className="flex min-w-0 items-center gap-2 truncate"><span className={`h-1.5 w-1.5 shrink-0 rounded-full ${isConnected ? "bg-emerald-500" : "bg-zinc-400"}`} />{status}</span>
          <span className="hidden shrink-0 items-center gap-3 font-mono sm:flex"><span>{activePageName}</span><span>{nodeCount} nodes</span><span>{edgeCount} edges{selectedCountLabel}</span></span>
        </div>
      </div>
    </section>
  );

  return isFullViewport ? createPortal(diagram, window.document.body) : diagram;
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
          ...(style.labelBackgroundColor !== undefined
            ? { labelBackgroundColor: styleColor(style.labelBackgroundColor, "none") }
            : {}),
          strokeWidth: styleNumber(style.strokeWidth, 2),
          dashed: Boolean(style.dashed),
          linePattern: linePatternFromStyle(style),
          ...(style.opacity !== undefined ? { opacity: styleNumber(style.opacity, 100) } : {}),
          ...(style.shadow !== undefined ? { shadow: Boolean(style.shadow) } : {}),
          ...(style.rounded !== undefined ? { rounded: Boolean(style.rounded) } : {}),
          ...(style.flipH !== undefined ? { flipH: Boolean(style.flipH) } : {}),
          ...(style.flipV !== undefined ? { flipV: Boolean(style.flipV) } : {}),
          fontSize: Math.max(8, Math.min(96, styleNumber(style.fontSize, 13))),
          fontFamily: diagramFontFamilyFromStyle(style.fontFamily),
          bold: (fontStyle & 1) === 1,
          italic: (fontStyle & 2) === 2,
          underline: (fontStyle & 4) === 4,
          align: textAlignFromStyle(style.align),
          verticalAlign: verticalAlignFromStyle(style.verticalAlign),
          spacing: clampNumber(styleNumber(style.spacing, 10), 0, 60),
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
        ...(style.labelBackgroundColor !== undefined
          ? { labelBackgroundColor: styleColor(style.labelBackgroundColor, "none") }
          : {}),
        strokeWidth: styleNumber(style.strokeWidth, 2),
        dashed: Boolean(style.dashed),
        linePattern: linePatternFromStyle(style),
        edgeType: edgeTypeFromCellStyle(style),
        startArrow: arrowTypeFromStyle(style.startArrow, "none"),
        endArrow: arrowTypeFromStyle(style.endArrow, "block"),
        startSize: clampNumber(styleNumber(style.startSize, 8), 4, 40),
        endSize: clampNumber(styleNumber(style.endSize, 8), 4, 40),
        fontSize: Math.max(8, Math.min(96, styleNumber(style.fontSize, 12))),
        fontFamily: diagramFontFamilyFromStyle(style.fontFamily),
        bold: (styleNumber(style.fontStyle, 0) & 1) === 1,
        italic: (styleNumber(style.fontStyle, 0) & 2) === 2,
        underline: (styleNumber(style.fontStyle, 0) & 4) === 4,
        align: textAlignFromStyle(style.align),
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
  const geometry = first.getGeometry();
  const fontStyle = styleNumber(style.fontStyle, 0);
  const firstKind = isDiagramNodeKind(style.diagramKind) ? style.diagramKind : undefined;
  update({
    ids: cells.map((cell) => cell.getId()).filter((id): id is string => Boolean(id)),
    label: cells.length === 1 ? String(first.getValue() ?? "") : "",
    isNode: cells.some((cell) => cell.isVertex()),
    isEdge: cells.some((cell) => cell.isEdge()),
    x: first.isVertex() ? geometry?.x : undefined,
    y: first.isVertex() ? geometry?.y : undefined,
    width: first.isVertex() ? geometry?.width : undefined,
    height: first.isVertex() ? geometry?.height : undefined,
    fillColor: styleColor(style.fillColor, "#ffffff"),
    strokeColor: styleColor(style.strokeColor, "#475569"),
    fontColor: styleColor(style.fontColor, "#172033"),
    labelBackgroundColor: styleColor(style.labelBackgroundColor, "none"),
    linePattern: linePatternFromStyle(style),
    strokeWidth: styleNumber(style.strokeWidth, 2),
    edgeType: first.isEdge() ? edgeTypeFromCellStyle(style) : undefined,
    startArrow: first.isEdge() ? arrowTypeFromStyle(style.startArrow, "none") : undefined,
    endArrow: first.isEdge() ? arrowTypeFromStyle(style.endArrow, "block") : undefined,
    startSize: first.isEdge() ? styleNumber(style.startSize, 8) : undefined,
    endSize: first.isEdge() ? styleNumber(style.endSize, 8) : undefined,
    fontSize: styleNumber(style.fontSize, first.isEdge() ? 12 : 13),
    fontFamily: diagramFontFamilyFromStyle(style.fontFamily),
    bold: (fontStyle & 1) === 1,
    italic: (fontStyle & 2) === 2,
    underline: (fontStyle & 4) === 4,
    align: textAlignFromStyle(style.align),
    verticalAlign: first.isVertex() ? verticalAlignFromStyle(style.verticalAlign) : undefined,
    spacing: first.isVertex() ? styleNumber(style.spacing, 10) : undefined,
    locked: first.isVertex() ? Boolean(style.diagramLocked) : undefined,
    rotation: first.isVertex() ? normalizeRotation(styleNumber(style.rotation, 0)) : undefined,
    flipH: first.isVertex() ? Boolean(style.flipH) : undefined,
    flipV: first.isVertex() ? Boolean(style.flipV) : undefined,
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

function isDiamondLikeKind(kind: DiagramNodeKind): boolean {
  return kind === "diamond"
    || kind === "decision"
    || kind === "bpmnGateway"
    || kind === "erRelationship";
}

function nodeCellStyle(node: DiagramNode, optimizeLargeGraph = false): DiagramCellStyle {
  const isContainer = node.kind === "container" || node.kind === "swimlane" || node.kind === "lane";
  const isDiamondLike = isDiamondLikeKind(node.kind);
  const defaultFontFamily: DiagramFontFamily = node.kind === "umlClass" || node.kind === "entity" ? "mono" : "system";
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
    verticalAlign: node.style.verticalAlign ?? "middle",
    spacing: node.style.spacing ?? (isDiamondLike ? 22 : 10),
    fontFamily: diagramFontFamilyCss(node.style.fontFamily ?? defaultFontFamily),
    fontSize: node.style.fontSize ?? 13,
    fontStyle: (node.style.bold === false ? 0 : 1) + (node.style.italic ? 2 : 0) + (node.style.underline ? 4 : 0),
    fillColor: node.style.fillColor,
    gradientColor: "none",
    gradientDirection: "north",
    strokeColor: node.style.strokeColor,
    fontColor: node.style.fontColor,
    labelBackgroundColor: node.style.labelBackgroundColor ?? "none",
    strokeWidth: node.style.strokeWidth,
    dashed: node.style.linePattern ? node.style.linePattern !== "solid" : Boolean(node.style.dashed),
    dashPattern: dashPatternForLinePattern(node.style.linePattern),
    shadow: !isContainer && !node.stencilName && !optimizeLargeGraph && Boolean(node.style.shadow),
    opacity: node.style.opacity ?? 100,
    rounded: node.style.rounded ?? usesRoundedCorners,
    rotation: node.rotation ?? 0,
    flipH: Boolean(node.style.flipH),
    flipV: Boolean(node.style.flipV),
    diagramLocked: Boolean(node.locked),
  };
  if (node.kind === "note") {
    if (node.style.align === undefined) base.align = "left";
    if (node.style.verticalAlign === undefined) base.verticalAlign = "top";
    if (node.style.bold === undefined && node.style.italic === undefined) base.fontStyle = 0;
  }
  if (node.kind === "text") {
    base.align = node.style.align ?? "left";
    base.fontStyle = (node.style.bold ? 1 : 0) + (node.style.italic ? 2 : 0) + (node.style.underline ? 4 : 0);
    base.shadow = false;
  }
  if (isDiamondLike) {
    base.spacingLeft = 28;
    base.spacingRight = 28;
    base.spacingTop = 14;
    base.spacingBottom = 14;
  }
  if (node.kind === "umlClass" || node.kind === "entity") {
    if (node.style.verticalAlign === undefined) base.verticalAlign = "top";
    base.spacingTop = 10;
  }
  if (node.kind === "umlPackage") {
    if (node.style.align === undefined) base.align = "left";
    if (node.style.verticalAlign === undefined) base.verticalAlign = "top";
    base.spacingTop = 28;
    base.spacingLeft = 12;
  }
  if (node.kind === "umlComponent") {
    base.spacingLeft = 36;
  }
  if (node.kind === "container" || node.kind === "swimlane" || node.kind === "lane") {
    if (node.style.align === undefined) base.align = "left";
    if (node.style.verticalAlign === undefined) base.verticalAlign = "top";
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
    startSize: edge.style.startSize ?? 8,
    endArrow: edge.style.endArrow ?? "block",
    endFill: edge.style.endArrow !== "open" && edge.style.endArrow !== "none",
    endSize: edge.style.endSize ?? 8,
    strokeColor: edge.style.strokeColor,
    fontColor: edge.style.fontColor,
    fontFamily: diagramFontFamilyCss(edge.style.fontFamily ?? "system"),
    fontSize: edge.style.fontSize ?? 12,
    fontStyle: (edge.style.bold ? 1 : 0) + (edge.style.italic ? 2 : 0) + (edge.style.underline ? 4 : 0),
    align: edge.style.align ?? "center",
    strokeWidth: edge.style.strokeWidth,
    dashed: edge.style.linePattern ? edge.style.linePattern !== "solid" : Boolean(edge.style.dashed),
    dashPattern: dashPatternForLinePattern(edge.style.linePattern),
    opacity: edge.style.opacity ?? 100,
    labelBackgroundColor: edge.style.labelBackgroundColor ?? "#ffffff",
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
      fillColor: "#ffffff",
      strokeColor: "#d2d2d7",
      fontColor: "#1d1d1f",
      strokeWidth: 1.2,
      fontSize: 12,
      bold: false,
      shadow: false,
    },
  };
}

function nodeDefaults(kind: DiagramNodeKind): { label: string; width: number; height: number; style: DiagramNodeStyle } {
  const base: DiagramNodeStyle = {
    fillColor: "#ffffff",
    strokeColor: "#d2d2d7",
    fontColor: "#1d1d1f",
    strokeWidth: 1.2,
    fontSize: 14,
    bold: false,
    shadow: false,
  };
  const style = (overrides: Partial<DiagramNodeStyle> = {}): DiagramNodeStyle => ({ ...base, ...overrides });
  const blue = (overrides: Partial<DiagramNodeStyle> = {}): DiagramNodeStyle => style({
    fillColor: "#e8f2ff",
    strokeColor: "#0066cc",
    bold: true,
    ...overrides,
  });
  const neutral = (overrides: Partial<DiagramNodeStyle> = {}): DiagramNodeStyle => style(overrides);
  const system = (fillColor: string, strokeColor: string, overrides: Partial<DiagramNodeStyle> = {}): DiagramNodeStyle => style({
    fillColor,
    strokeColor,
    ...overrides,
  });
  if (kind === "rectangle") {
    return { label: "矩形", width: 168, height: 76, style: neutral() };
  }
  if (kind === "roundedRectangle") {
    return { label: "圆角矩形", width: 168, height: 76, style: neutral({ fillColor: "#fbfbfd", rounded: true }) };
  }
  if (kind === "ellipse") {
    return { label: "椭圆", width: 164, height: 92, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "circle") {
    return { label: "圆形", width: 96, height: 96, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "diamond") {
    return { label: "菱形", width: 128, height: 128, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "triangle") {
    return { label: "三角形", width: 120, height: 104, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "hexagon") {
    return { label: "六边形", width: 164, height: 88, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "text") {
    return { label: "双击编辑文本", width: 180, height: 52, style: neutral({ fillColor: "none", strokeColor: "none", strokeWidth: 0, align: "left" }) };
  }
  if (kind === "start") {
    return { label: "开始", width: 128, height: 48, style: blue() };
  }
  if (kind === "end") {
    return { label: "结束", width: 128, height: 48, style: blue() };
  }
  if (kind === "decision") {
    return { label: "判断条件", width: 176, height: 112, style: system("#fff7e6", "#ff9f0a", { bold: true }) };
  }
  if (kind === "database") {
    return { label: "数据库", width: 148, height: 92, style: neutral({ fillColor: "#fbfbfd", strokeColor: "#86868b" }) };
  }
  if (kind === "document") {
    return { label: "文档", width: 156, height: 86, style: blue({ bold: false }) };
  }
  if (kind === "actor") {
    return { label: "参与者", width: 116, height: 98, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "note") {
    return { label: "补充说明", width: 176, height: 100, style: system("#fff7e6", "#d2d2d7", { align: "left" }) };
  }
  if (kind === "subprocess") {
    return { label: "子流程", width: 184, height: 76, style: blue() };
  }
  if (kind === "data") {
    return { label: "数据", width: 164, height: 76, style: blue({ bold: false }) };
  }
  if (kind === "delay") {
    return { label: "等待", width: 156, height: 76, style: system("#fff7e6", "#ff9f0a") };
  }
  if (kind === "manualInput") {
    return { label: "手动输入", width: 168, height: 76, style: system("#fff7e6", "#ff9f0a") };
  }
  if (kind === "connector") {
    return { label: "A", width: 56, height: 56, style: blue({ fontSize: 12 }) };
  }
  if (kind === "bpmnTask") {
    return { label: "业务任务", width: 172, height: 72, style: blue({ rounded: true }) };
  }
  if (kind === "cloud") {
    return { label: "云服务", width: 176, height: 96, style: blue({ bold: false }) };
  }
  if (kind === "container") {
    return { label: "分组容器", width: 480, height: 320, style: neutral({ fillColor: "#f5f5f7", strokeColor: "#86868b", dashed: true }) };
  }
  if (kind === "swimlane") {
    return { label: "职责泳道", width: 560, height: 300, style: neutral({ fillColor: "#f5f5f7", strokeColor: "#0066cc" }) };
  }
  if (kind === "lane") {
    return { label: "泳道", width: 560, height: 120, style: neutral({ fillColor: "#fbfbfd", strokeColor: "#d2d2d7" }) };
  }
  if (kind === "bpmnEvent") {
    return { label: "中间事件", width: 76, height: 76, style: blue() };
  }
  if (kind === "bpmnGateway") {
    return { label: "网关", width: 112, height: 112, style: system("#fff7e6", "#ff9f0a", { bold: true }) };
  }
  if (kind === "bpmnDataObject") {
    return { label: "数据对象", width: 124, height: 92, style: blue({ bold: false }) };
  }
  if (kind === "umlUseCase") {
    return { label: "用户用例", width: 172, height: 84, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "umlClass") {
    return { label: "ClassName\n────────\n+ field: Type\n────────\n+ method()", width: 216, height: 154, style: neutral({ fillColor: "#fbfbfd", align: "left" }) };
  }
  if (kind === "umlInterface") {
    return { label: "Interface", width: 104, height: 104, style: neutral({ fillColor: "#fbfbfd", fontSize: 11 }) };
  }
  if (kind === "umlPackage") {
    return { label: "Package", width: 190, height: 112, style: neutral({ fillColor: "#f5f5f7", align: "left" }) };
  }
  if (kind === "umlComponent") {
    return { label: "Component", width: 190, height: 100, style: blue({ bold: false }) };
  }
  if (kind === "entity") {
    return { label: "Entity\n────────\nid: UUID\nname: VARCHAR", width: 204, height: 134, style: neutral({ fillColor: "#fbfbfd", align: "left" }) };
  }
  if (kind === "erRelationship") {
    return { label: "关系", width: 152, height: 104, style: blue({ bold: false }) };
  }
  if (kind === "erAttribute") {
    return { label: "属性", width: 152, height: 72, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "server") {
    return { label: "应用服务器", width: 156, height: 104, style: blue({ bold: false }) };
  }
  if (kind === "client") {
    return { label: "客户端", width: 156, height: 88, style: blue({ bold: false }) };
  }
  if (kind === "router") {
    return { label: "路由器", width: 128, height: 72, style: blue({ bold: false }) };
  }
  if (kind === "firewall") {
    return { label: "防火墙", width: 160, height: 76, style: system("#fff1f2", "#ff3b30", { bold: true }) };
  }
  if (kind === "queue") {
    return { label: "消息队列", width: 164, height: 86, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "service") {
    return { label: "应用服务", width: 168, height: 84, style: system("#ecfdf5", "#34c759", { bold: true }) };
  }
  return { label: "处理步骤", width: 168, height: 68, style: blue() };
}

function defaultEdgeStyle(): DiagramEdgeStyle {
  return {
    strokeColor: "#0066cc",
    fontColor: "#1d1d1f",
    strokeWidth: 1.8,
    edgeType: "orthogonal",
    startArrow: "none",
    endArrow: "block",
  };
}

function nodeShape(kind: DiagramNodeKind) {
  const semanticShape = semanticShapeName(kind);
  if (semanticShape) return semanticShape;
  if (kind === "ellipse" || kind === "circle" || kind === "start" || kind === "end" || kind === "connector" || kind === "umlUseCase" || kind === "erAttribute" || kind === "router") return "ellipse";
  if (kind === "diamond" || kind === "decision" || kind === "bpmnGateway" || kind === "erRelationship") return "rhombus";
  if (kind === "bpmnEvent" || kind === "umlInterface") return "doubleEllipse";
  if (kind === "triangle") return "triangle";
  if (kind === "hexagon" || kind === "service") return "hexagon";
  if (kind === "database") return "cylinder";
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
  element.style.filter = "none";

  const shape = window.document.createElement("div");
  shape.style.position = "absolute";
  shape.style.inset = isContainer ? "2px" : "1px";
  shape.style.boxSizing = "border-box";
  shape.style.background = isContainer
    ? "#f5f5f7"
    : defaults.style.fillColor;
  shape.style.border = `${Math.max(1, defaults.style.strokeWidth)}px ${defaults.style.dashed ? "dashed" : "solid"} ${defaults.style.strokeColor}`;
  shape.style.borderRadius = "14px";
  shape.style.boxShadow = "none";

  if (kind === "ellipse" || kind === "circle" || kind === "start" || kind === "end" || kind === "connector" || kind === "bpmnEvent" || kind === "umlUseCase" || kind === "umlInterface" || kind === "erAttribute" || kind === "router") {
    shape.style.borderRadius = "999px";
  } else if (kind === "diamond" || kind === "decision" || kind === "bpmnGateway" || kind === "erRelationship") {
    shape.style.inset = "18%";
    shape.style.borderRadius = "8px";
    shape.style.transform = "rotate(45deg)";
  } else if (kind === "database") {
    shape.style.borderRadius = "50% / 18%";
  } else if (kind === "hexagon" || kind === "service") {
    shape.style.clipPath = "polygon(14% 0, 86% 0, 100% 50%, 86% 100%, 14% 100%, 0 50%)";
  } else if (kind === "triangle") {
    shape.style.clipPath = "polygon(50% 0, 100% 100%, 0 100%)";
  } else if (kind === "data") {
    shape.style.clipPath = "polygon(14% 0, 100% 0, 86% 100%, 0 100%)";
  } else if (kind === "manualInput") {
    shape.style.clipPath = "polygon(0 20%, 100% 0, 100% 100%, 0 100%)";
  } else if (kind === "note" || kind === "bpmnDataObject") {
    shape.style.clipPath = "polygon(0 0, 82% 0, 100% 22%, 100% 100%, 0 100%)";
  } else if (kind === "delay") {
    shape.style.borderRadius = "0 999px 999px 0";
  } else if (kind === "umlPackage") {
    shape.style.clipPath = "polygon(0 0, 42% 0, 42% 18%, 100% 18%, 100% 100%, 0 100%)";
  } else if (kind === "cloud") {
    shape.style.borderRadius = "48% 52% 46% 54% / 58% 48% 52% 42%";
  }
  if (kind === "text") {
    shape.style.display = "none";
    element.style.filter = "none";
  }
  element.appendChild(shape);

  if (kind === "subprocess" || kind === "server" || kind === "firewall" || kind === "umlClass" || kind === "entity") {
    const overlay = window.document.createElement("div");
    overlay.style.position = "absolute";
    overlay.style.inset = "1px";
    overlay.style.pointerEvents = "none";
    if (kind === "subprocess") {
      overlay.style.borderLeft = `2px solid ${defaults.style.strokeColor}`;
      overlay.style.borderRight = `2px solid ${defaults.style.strokeColor}`;
      overlay.style.marginInline = "10px";
    } else {
      overlay.style.background = `linear-gradient(to bottom, transparent 31%, ${defaults.style.strokeColor} 31%, ${defaults.style.strokeColor} 33%, transparent 33%, transparent 67%, ${defaults.style.strokeColor} 67%, ${defaults.style.strokeColor} 69%, transparent 69%)`;
    }
    element.appendChild(overlay);
  }

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
  label.style.fontFamily = "system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif";
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
  return value === "none" || (typeof value === "string" && /^#[0-9a-fA-F]{6}$/.test(value)) ? value : fallback;
}

function styleNumber(value: unknown, fallback: number) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function clampNumber(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, Number.isFinite(value) ? value : min));
}

function expandedDiagramCanvasSize(
  current: { width: number; height: number },
  contentBounds: Rectangle | null,
  viewportWidth: number,
  viewportHeight: number,
  scale: number,
) {
  const safeScale = Math.max(1, Number.isFinite(scale) ? scale : 1);
  const contentRight = contentBounds ? Math.max(0, contentBounds.x + contentBounds.width) : 0;
  const contentBottom = contentBounds ? Math.max(0, contentBounds.y + contentBounds.height) : 0;
  const targetWidth = Math.max(
    DIAGRAM_CANVAS.width,
    current.width,
    viewportWidth / safeScale,
    contentRight + DIAGRAM_CANVAS_PADDING.width,
  );
  const targetHeight = Math.max(
    DIAGRAM_CANVAS.height,
    current.height,
    viewportHeight / safeScale,
    contentBottom + DIAGRAM_CANVAS_PADDING.height,
  );
  return {
    width: Math.min(MAX_DIAGRAM_CANVAS_SIZE, Math.ceil(targetWidth / DIAGRAM_CANVAS_GROWTH.width) * DIAGRAM_CANVAS_GROWTH.width),
    height: Math.min(MAX_DIAGRAM_CANVAS_SIZE, Math.ceil(targetHeight / DIAGRAM_CANVAS_GROWTH.height) * DIAGRAM_CANVAS_GROWTH.height),
  };
}

function linePatternFromStyle(style: CellStyle): DiagramLinePattern {
  if (!style.dashed) return "solid";
  return typeof style.dashPattern === "string" && /^\s*1(?:\s|$)/.test(style.dashPattern) ? "dotted" : "dashed";
}

function dashPatternForLinePattern(pattern?: DiagramLinePattern) {
  if (pattern === "dotted") return "1 4";
  if (pattern === "dashed") return "8 4";
  return undefined;
}

function diagramFontFamilyCss(fontFamily: DiagramFontFamily) {
  if (fontFamily === "rounded") return "ui-rounded, SF Pro Rounded, system-ui, sans-serif";
  if (fontFamily === "serif") return "Georgia, Times New Roman, serif";
  if (fontFamily === "mono") return "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
  return "system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif";
}

function diagramFontFamilyFromStyle(value: unknown): DiagramFontFamily {
  if (typeof value !== "string") return "system";
  const normalized = value.toLowerCase();
  if (normalized.includes("mono") || normalized.includes("menlo") || normalized.includes("consolas")) return "mono";
  if (normalized.includes("rounded")) return "rounded";
  if ((normalized.includes("georgia") || normalized.includes("times") || normalized.endsWith("serif"))
    && !normalized.includes("sans-serif")) return "serif";
  return "system";
}

function verticalAlignFromStyle(value: unknown): DiagramVerticalAlign {
  return value === "top" || value === "bottom" ? value : "middle";
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
      className={`diagram-apple-compact-button flex h-8 min-w-[64px] items-center justify-center gap-1.5 rounded-md px-2 text-[10px] font-semibold transition ${active
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
          className={`diagram-apple-toolbar-menu flex shrink-0 items-center gap-1.5 rounded-lg text-[11px] font-medium text-zinc-600 transition hover:bg-black/[0.045] hover:text-zinc-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 dark:text-zinc-300 dark:hover:bg-white/[0.06] dark:hover:text-white ${compact ? "h-8 px-2" : "h-8 px-2.5"}`}
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
      className={`diagram-apple-toolbar-button flex h-8 shrink-0 items-center gap-1 rounded-lg px-2.5 text-[11px] font-medium transition disabled:cursor-not-allowed disabled:opacity-35 ${danger
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
    <span className="diagram-apple-stencil-glyph relative flex h-8 w-12 shrink-0 items-center justify-center overflow-hidden rounded-md bg-slate-50 dark:bg-white/[0.04]">
      <svg ref={svgRef} className={`h-full w-full overflow-visible ${rendered ? "block" : "hidden"}`} aria-hidden="true" />
      {!rendered ? <span className="h-5 w-8 rounded border border-cyan-500/60 bg-cyan-50 dark:bg-cyan-300/10" /> : null}
    </span>
  );
}

function DiagramNodeGlyph({ kind }: { kind: DiagramNodeKind }) {
  if (kind === "text") {
    return <span className="diagram-apple-node-glyph flex h-8 w-11 shrink-0 items-center justify-center rounded-md bg-slate-50 text-sm font-semibold text-cyan-700 transition group-hover:bg-cyan-50 dark:bg-white/[0.04] dark:text-cyan-200 dark:group-hover:bg-cyan-300/[0.08]">T</span>;
  }
  let shape: ReactNode;
  if (kind === "rectangle") {
    shape = <rect x="2" y="4" width="44" height="28" />;
  } else if (kind === "roundedRectangle") {
    shape = <rect x="2" y="4" width="44" height="28" rx="7" />;
  } else if (kind === "ellipse" || kind === "umlUseCase" || kind === "erAttribute") {
    shape = <ellipse cx="24" cy="18" rx="22" ry="14" />;
  } else if (kind === "circle" || kind === "connector") {
    shape = <circle cx="24" cy="18" r="15" />;
  } else if (kind === "start" || kind === "end") {
    shape = <rect x="2" y="7" width="44" height="22" rx="11" />;
  } else if (isDiamondLikeKind(kind)) {
    shape = <path d="M24 2 46 18 24 34 2 18Z" />;
  } else if (kind === "triangle") {
    shape = <path d="M24 2 45 33H3Z" />;
  } else if (kind === "hexagon" || kind === "service") {
    shape = <path d="M10 3h28l8 15-8 15H10L2 18Z" />;
  } else if (kind === "document") {
    shape = <path d="M3 3h42v25c-8-5-14 6-23 1-7-4-12-1-19 2Z" />;
  } else if (kind === "database") {
    shape = (
      <>
        <path d="M5 8c0-4 38-4 38 0v20c0 4-38 4-38 0Z" />
        <ellipse cx="24" cy="8" rx="19" ry="5" fill="none" />
      </>
    );
  } else if (kind === "data") {
    shape = <path d="M9 3h37l-7 30H2Z" />;
  } else if (kind === "subprocess") {
    shape = (
      <>
        <rect x="2" y="4" width="44" height="28" rx="5" />
        <path d="M9 4v28M39 4v28" fill="none" />
      </>
    );
  } else if (kind === "delay") {
    shape = <path d="M3 3h20c14 0 22 6 22 15s-8 15-22 15H3Z" />;
  } else if (kind === "manualInput") {
    shape = <path d="m3 9 42-6v30H3Z" />;
  } else if (kind === "note" || kind === "bpmnDataObject") {
    shape = (
      <>
        <path d="M4 2h30l10 10v22H4Z" />
        <path d="M34 2v10h10" fill="none" />
      </>
    );
  } else if (kind === "bpmnTask" || kind === "process") {
    shape = <rect x="2" y="4" width="44" height="28" rx={kind === "bpmnTask" ? 7 : 3} />;
  } else if (kind === "bpmnEvent" || kind === "umlInterface") {
    shape = (
      <>
        <circle cx="24" cy="18" r="15" />
        <circle cx="24" cy="18" r="11" fill="none" />
      </>
    );
  } else if (kind === "actor") {
    shape = (
      <>
        <circle cx="24" cy="9" r="6" />
        <path d="M9 33c1-10 6-15 15-15s14 5 15 15Z" />
      </>
    );
  } else if (kind === "umlClass") {
    shape = (
      <>
        <rect x="3" y="2" width="42" height="32" rx="2" />
        <path d="M3 12h42M3 24h42" fill="none" />
      </>
    );
  } else if (kind === "umlPackage") {
    shape = <path d="M3 4h17v6h25v23H3Z" />;
  } else if (kind === "umlComponent") {
    shape = (
      <>
        <rect x="4" y="4" width="40" height="28" rx="4" />
        <rect x="8" y="10" width="11" height="6" rx="1" />
        <rect x="8" y="21" width="11" height="6" rx="1" />
      </>
    );
  } else if (kind === "entity") {
    shape = (
      <>
        <rect x="3" y="3" width="42" height="30" rx="2" />
        <path d="M3 13h42" fill="none" />
      </>
    );
  } else if (kind === "server") {
    shape = (
      <>
        <rect x="5" y="3" width="38" height="30" rx="4" />
        <path d="M5 13h38M5 23h38" fill="none" />
        <circle cx="37" cy="8" r="1.5" fill="currentColor" stroke="none" />
        <circle cx="37" cy="28" r="1.5" fill="currentColor" stroke="none" />
      </>
    );
  } else if (kind === "client") {
    shape = (
      <>
        <rect x="4" y="3" width="40" height="23" rx="4" />
        <path d="M24 26v5M17 32h14" fill="none" />
      </>
    );
  } else if (kind === "router") {
    shape = <ellipse cx="24" cy="18" rx="21" ry="13" />;
  } else if (kind === "firewall") {
    shape = (
      <>
        <rect x="3" y="4" width="42" height="28" />
        <path d="M3 12h42M3 24h42M14 4v8M33 4v8M22 24v8M39 24v8" fill="none" />
      </>
    );
  } else if (kind === "cloud") {
    shape = <path d="M13 30C4 30 1 22 7 17c-2-7 6-12 12-8 5-8 17-5 18 3 10 0 12 14 4 18Z" />;
  } else if (kind === "queue") {
    shape = (
      <>
        <path d="M10 4h28c10 0 10 28 0 28H10C0 32 0 4 10 4Z" />
        <path d="M10 4c8 0 8 28 0 28" fill="none" />
      </>
    );
  } else if (kind === "container") {
    shape = <rect x="2" y="3" width="44" height="30" rx="4" strokeDasharray="4 3" />;
  } else if (kind === "swimlane" || kind === "lane") {
    shape = (
      <>
        <rect x="2" y="3" width="44" height="30" rx="4" />
        <path d="M2 12h44" fill="none" />
      </>
    );
  } else {
    shape = <rect x="2" y="4" width="44" height="28" rx="4" />;
  }
  return (
    <span className="diagram-apple-node-glyph flex h-8 w-11 shrink-0 items-center justify-center text-cyan-700 transition dark:text-cyan-200" aria-hidden="true">
      <svg className="h-full w-full overflow-visible" viewBox="0 0 48 36">
        <g fill="var(--diagram-apple-glyph-fill)" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6">
          {shape}
        </g>
      </svg>
    </span>
  );
}

function InspectorTabButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      className={`relative text-[10px] font-semibold transition ${active
        ? "text-[var(--diagram-apple-blue)] after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-[var(--diagram-apple-blue)]"
        : "text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100"}`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function InspectorSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="py-4 first:pt-0 last:pb-0">
      <h3 className="diagram-apple-field-label text-[10px] font-semibold text-zinc-500 dark:text-zinc-300">{title}</h3>
      <div className="mt-2.5">{children}</div>
    </section>
  );
}

function InspectorFieldLabel({ children }: { children: ReactNode }) {
  return <span className="diagram-apple-field-label block text-[9px] font-medium text-zinc-500 dark:text-zinc-400">{children}</span>;
}

function InspectorNumberField({
  label,
  value,
  min,
  max,
  step = 1,
  suffix,
  onCommit,
}: {
  label: string;
  value?: number;
  min: number;
  max: number;
  step?: number;
  suffix?: string;
  onCommit: (value: number) => void;
}) {
  const formattedValue = value === undefined ? "" : String(Math.round(value * 100) / 100);
  const [draft, setDraft] = useState(formattedValue);
  useEffect(() => setDraft(formattedValue), [formattedValue]);
  const commit = () => {
    const parsed = Number(draft);
    if (!Number.isFinite(parsed)) {
      setDraft(formattedValue);
      return;
    }
    const next = clampNumber(parsed, min, max);
    setDraft(String(next));
    onCommit(next);
  };
  return (
    <label className="block min-w-0">
      <InspectorFieldLabel>{label}</InspectorFieldLabel>
      <span className="mt-1 flex h-8 items-center rounded-md border border-black/[0.09] bg-white focus-within:border-[var(--diagram-apple-blue)] dark:border-white/[0.1] dark:bg-zinc-950">
        <input
          type="number"
          value={draft}
          min={min}
          max={max}
          step={step}
          className="min-w-0 flex-1 bg-transparent px-2 text-[11px] text-zinc-800 outline-none dark:text-zinc-100"
          onChange={(event) => setDraft(event.currentTarget.value)}
          onBlur={commit}
          onKeyDown={(event) => {
            if (event.key === "Enter") event.currentTarget.blur();
            if (event.key === "Escape") {
              setDraft(formattedValue);
              event.currentTarget.blur();
            }
          }}
        />
        {suffix ? <span className="pr-2 text-[9px] text-zinc-400">{suffix}</span> : null}
      </span>
    </label>
  );
}

function InspectorSelectField<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: ReadonlyArray<{ value: T; label: string }>;
  onChange: (value: T) => void;
}) {
  return (
    <label className="block min-w-0">
      <InspectorFieldLabel>{label}</InspectorFieldLabel>
      <select
        value={value}
        className="mt-1 h-8 w-full rounded-md border border-black/[0.09] bg-white px-2 text-[11px] text-zinc-800 outline-none focus:border-[var(--diagram-apple-blue)] dark:border-white/[0.1] dark:bg-zinc-950 dark:text-zinc-100"
        onChange={(event) => onChange(event.currentTarget.value as T)}
      >
        {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
      </select>
    </label>
  );
}

function InspectorColorField({
  label,
  value,
  fallback,
  allowNone = false,
  onCommit,
}: {
  label: string;
  value?: string;
  fallback: string;
  allowNone?: boolean;
  onCommit: (value: string) => void;
}) {
  const displayValue = value === "none" ? "none" : colorPickerValue(value, fallback);
  const [draft, setDraft] = useState(displayValue);
  useEffect(() => setDraft(displayValue), [displayValue]);
  const pickerValue = value === "none" ? colorPickerValue(fallback, "#000000") : colorPickerValue(value, fallback);
  const commit = () => {
    const normalized = draft.trim().toLowerCase();
    if (allowNone && normalized === "none") {
      setDraft("none");
      onCommit("none");
      return;
    }
    if (/^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i.test(normalized)) {
      const color = colorPickerValue(normalized, fallback);
      setDraft(color);
      onCommit(color);
      return;
    }
    setDraft(displayValue);
  };
  return (
    <div>
      <InspectorFieldLabel>{label}</InspectorFieldLabel>
      <div className="mt-1 flex h-8 items-center gap-1.5">
        <label
          className="relative h-8 w-10 shrink-0 cursor-pointer overflow-hidden rounded-md border border-black/[0.12] shadow-sm focus-within:ring-2 focus-within:ring-[var(--diagram-apple-blue)] dark:border-white/[0.14]"
          title={`选择${label}`}
          style={value === "none" ? { background: "linear-gradient(135deg,#fff 0 44%,#ef4444 45% 55%,#fff 56% 100%)" } : { backgroundColor: pickerValue }}
        >
          <input
            type="color"
            value={pickerValue}
            aria-label={`选择${label}`}
            className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
            onChange={(event) => {
              setDraft(event.currentTarget.value);
              onCommit(event.currentTarget.value);
            }}
          />
        </label>
        <input
          value={draft}
          inputMode="text"
          aria-label={`${label}色值`}
          className="h-8 min-w-0 flex-1 rounded-md border border-black/[0.09] bg-white px-2 font-mono text-[10px] uppercase text-zinc-700 outline-none focus:border-[var(--diagram-apple-blue)] dark:border-white/[0.1] dark:bg-zinc-950 dark:text-zinc-200"
          onChange={(event) => setDraft(event.currentTarget.value)}
          onBlur={commit}
          onKeyDown={(event) => {
            if (event.key === "Enter") event.currentTarget.blur();
            if (event.key === "Escape") {
              setDraft(displayValue);
              event.currentTarget.blur();
            }
          }}
        />
        {allowNone ? (
          <button
            type="button"
            aria-pressed={value === "none"}
            className={`h-8 shrink-0 rounded-md px-2 text-[10px] font-medium transition ${value === "none"
              ? "bg-[var(--diagram-apple-blue)] text-white dark:text-zinc-950"
              : "text-zinc-500 hover:bg-black/[0.05] dark:text-zinc-400 dark:hover:bg-white/[0.06]"}`}
            onClick={() => {
              const next = value === "none" ? fallback : "none";
              setDraft(next);
              onCommit(next);
            }}
          >
            无
          </button>
        ) : null}
      </div>
    </div>
  );
}

function InspectorRangeField({
  label,
  value,
  min,
  max,
  suffix,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  suffix?: string;
  onChange: (value: number) => void;
}) {
  return (
    <label className="block">
      <span className="flex items-center justify-between">
        <InspectorFieldLabel>{label}</InspectorFieldLabel>
        <span className="text-[10px] tabular-nums text-zinc-500 dark:text-zinc-400">{value}{suffix}</span>
      </span>
      <input
        type="range"
        value={value}
        min={min}
        max={max}
        className="mt-1 h-5 w-full accent-[var(--diagram-apple-blue)]"
        onChange={(event) => onChange(Number(event.currentTarget.value))}
      />
    </label>
  );
}

function InspectorToggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: () => void }) {
  return (
    <button type="button" role="switch" aria-checked={checked} className="flex h-7 items-center justify-between gap-2 text-left text-[10px] font-medium text-zinc-600 dark:text-zinc-300" onClick={onChange}>
      <span>{label}</span>
      <span className={`relative h-5 w-9 shrink-0 rounded-full transition ${checked ? "bg-[var(--diagram-apple-blue)]" : "bg-zinc-300 dark:bg-zinc-700"}`} aria-hidden>
        <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow-sm transition-transform ${checked ? "translate-x-[18px] dark:bg-zinc-950" : "translate-x-0.5"}`} />
      </span>
    </button>
  );
}

function InspectorTextStyleButton({
  label,
  glyph,
  active,
  italic = false,
  underline = false,
  onClick,
}: {
  label: string;
  glyph: string;
  active: boolean;
  italic?: boolean;
  underline?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      aria-pressed={active}
      className={`h-8 border-r border-black/[0.08] text-[12px] transition last:border-r-0 dark:border-white/[0.08] ${active
        ? "bg-[var(--diagram-apple-blue)] text-white dark:text-zinc-950"
        : "bg-white text-zinc-600 hover:bg-black/[0.04] dark:bg-zinc-950 dark:text-zinc-300 dark:hover:bg-white/[0.05]"}`}
      style={{ fontStyle: italic ? "italic" : undefined, textDecoration: underline ? "underline" : undefined, fontWeight: glyph === "B" ? 700 : undefined }}
      onClick={onClick}
    >
      {glyph}
    </button>
  );
}

function InspectorSegmentedField<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: ReadonlyArray<{ value: T; label: string }>;
  onChange: (value: T) => void;
}) {
  return (
    <div>
      <InspectorFieldLabel>{label}</InspectorFieldLabel>
      <div className="mt-1 grid overflow-hidden rounded-md border border-black/[0.09] dark:border-white/[0.1]" style={{ gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))` }}>
        {options.map((option) => (
          <button
            key={option.value}
            type="button"
            aria-pressed={value === option.value}
            className={`h-8 border-r border-black/[0.08] text-[10px] font-medium transition last:border-r-0 dark:border-white/[0.08] ${value === option.value
              ? "bg-[var(--diagram-apple-blue)] text-white dark:text-zinc-950"
              : "bg-white text-zinc-600 hover:bg-black/[0.04] dark:bg-zinc-950 dark:text-zinc-300 dark:hover:bg-white/[0.05]"}`}
            onClick={() => onChange(option.value)}
          >
            {option.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function colorPickerValue(value: string | undefined, fallback: string): string {
  const source = value?.trim() ?? "";
  if (/^#[0-9a-f]{6}$/i.test(source)) return source.toLowerCase();
  if (/^#[0-9a-f]{3}$/i.test(source)) {
    const [red, green, blue] = source.slice(1).split("");
    return `#${red}${red}${green}${green}${blue}${blue}`.toLowerCase();
  }
  return /^#[0-9a-f]{6}$/i.test(fallback) ? fallback.toLowerCase() : "#000000";
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
      className={`diagram-apple-inspector-action rounded-lg border px-2 py-1.5 text-[10px] font-medium transition hover:border-cyan-400 hover:text-cyan-800 disabled:opacity-35 dark:hover:text-cyan-200 ${active
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
      className={`diagram-apple-context-action block w-full rounded-md px-2.5 py-2 text-left transition disabled:opacity-35 ${danger
        ? "text-red-600 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-400/10"
        : "hover:bg-cyan-50 hover:text-cyan-900 dark:hover:bg-cyan-300/10 dark:hover:text-cyan-100"}`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}
