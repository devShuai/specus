import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties, PointerEvent as ReactPointerEvent, ReactNode } from "react";
import { createPortal } from "react-dom";
import {
  Button,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
} from "@heroui/react";
import {
  Cell,
  Clipboard,
  ConnectionHandler,
  Graph,
  Geometry,
  getDefaultPlugins,
  gestureUtils,
  HierarchicalLayout,
  ImageBox,
  ImageExport,
  InternalEvent,
  Outline,
  Point,
  Rectangle,
  RubberBandHandler,
  SelectionCellsHandler,
  SelectionHandler,
  SvgCanvas2D,
  VertexHandler,
} from "@maxgraph/core";
import type {
  CellState,
  CellStyle,
  FitPlugin,
} from "@maxgraph/core";
import { Star } from "lucide-react";
import * as Y from "yjs";
import "@maxgraph/core/css/common.css";
import {
  adminApi,
  publicCreateTransferDiagramVersion,
  publicDeleteTransferDiagramVersion,
  publicGetTransferDiagramVersion,
  publicListTransferDiagramVersions,
} from "../api/client";
import type {
  PublicTransferDiagramVersion,
  PublicTransferRoomRole,
  UserDiagramDocument,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
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
  MAX_DIAGRAM_COMMENTS,
  MAX_DIAGRAM_DOCUMENT_BYTES,
  MAX_DIAGRAM_EDGES,
  MAX_DIAGRAM_NODES,
  MAX_DIAGRAM_PAGES,
  MAX_DIAGRAM_UPDATE_BASE64_LENGTH,
  MAX_DIAGRAM_BINARY_UPDATE_BYTES,
  parseDiagramDocument,
} from "../lib/diagramDocument";
import type {
  DiagramDocumentV1,
  DiagramArrowType,
  DiagramComment,
  DiagramEdge,
  DiagramEdgeType,
  DiagramFontFamily,
  DiagramLinePattern,
  DiagramNode,
  DiagramNodeKind,
  DiagramPayload,
  DiagramPage,
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
import { preserveTouchTap } from "../lib/diagramPointerInput";
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
import { DiagramRemoteUpdateValidator } from "../lib/diagramYjsValidation";
import { useTheme } from "../theme/ThemeContext";
import { PublicToolsMenu } from "./PublicToolsMenu";
import {
  buildStencilCollections,
  createNodeDragPreview,
  defaultEdgeStyle,
  edgeCellStyle,
  edgeRoutingStyle,
  edgeTypeFromCellStyle,
  isDiamondLikeKind,
  nodeCellStyle,
  nodeDefaults,
  stencilNodeDefaults,
  stencilPaletteItem,
  diagramFontFamilyCss,
  diagramFontFamilyFromStyle,
  linePatternFromStyle,
  textAlignFromStyle,
  verticalAlignFromStyle,
  arrowTypeFromStyle,
} from "./diagram/graphStyles";
import {
  CUBIC_CONTROL_DEFAULTS,
  DIAGRAM_CUBIC_EDGE_SHAPE,
  DIAGRAM_ROTATION_HANDLE_ACCENT,
  DIAGRAM_ROTATION_HANDLE_FILL,
  DiagramCubicEdgeHandler,
  DiagramVertexHandler,
} from "./diagram/graphShapes";
import {
  absoluteCellCenter,
  absoluteCellOrigin,
  clampNumber,
  constraintForPort,
  cubicControlPointsFromStyle,
  cubicControlStyleFromPoints,
  defaultCubicControlPoints,
  edgeWaypointsForGraph,
  normalizeRotation,
  portFromStyle,
  styleColor,
  styleNumber,
} from "./diagram/graphGeometry";
import {
  DiagramAccountDialog,
  DiagramCloudDocumentsDialog,
  DiagramEditorDialog,
  formatDiagramTimestamp,
} from "./diagram/dialogs";
import type {
  DiagramCellStyle,
  DiagramDialogRequest,
  DiagramDialogResult,
  DiagramStatusTone,
} from "./diagram/types";
import {
  DIAGRAM_ARROW_OPTIONS,
  DIAGRAM_FONT_OPTIONS,
  DIAGRAM_TEMPLATES,
  NODE_PALETTE,
  PALETTE_CATEGORIES,
  PORT_CONSTRAINTS,
  isDiagramNodeKind,
} from "./diagram/paletteCatalog";
import type {
  DiagramTemplateDefinition,
  DiagramTemplateId,
  DraggablePaletteItem,
  PaletteCategory,
  StencilCollection,
  StencilPaletteItem,
} from "./diagram/paletteCatalog";
import {
  readDiagramBooleanPreference,
  readDiagramNodeKindList,
  readDiagramPanelWidth,
  writeDiagramBooleanPreference,
  writeDiagramNodeKindList,
  writeDiagramPanelWidth,
} from "./diagram/preferences";

export interface DiagramEmbedApi {
  getSnapshot: () => string;
  loadSnapshot: (encoded: string) => void;
  exportSvg: () => string;
  exportPng: () => Promise<Blob>;
}

interface SyncedDiagramProps {
  boardKey: string;
  roomId: string;
  roomToken: string;
  roomRole: PublicTransferRoomRole;
  peerId: string;
  peerCount: number;
  peerDisplayNames?: Record<string, string>;
  isConnected: boolean;
  isActive?: boolean;
  events: WhiteboardInboundEvent[];
  onSend: (payload: DiagramPayload) => boolean | Promise<boolean>;
  onSwitchToWhiteboard?: () => void;
  standalone?: boolean;
  collaborationPanel?: ReactNode;
  onEmbedApiChange?: (api: DiagramEmbedApi | null) => void;
  onLocalChange?: () => void;
}

interface DiagramRuntime {
  graph: Graph;
  destroy: () => void;
}

interface DiagramSelection {
  count: number;
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
  lockedCount: number;
  editableCount: number;
  mixedFields: Array<keyof DiagramSelection>;
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

interface RemoteSelectionMarker {
  key: string;
  peerId: string;
  left: number;
  top: number;
  width: number;
  height: number;
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


const GRAPH_ORIGIN = Symbol("diagram-graph");
const IMPORT_ORIGIN = Symbol("diagram-import");
const REMOTE_ORIGIN = Symbol("diagram-remote");
const DIAGRAM_CACHE_LIMIT = 8;
const DIAGRAM_SESSION_VERSION_PREFIX = "specus-diagram-session-versions:";
const MAX_DIAGRAM_SESSION_VERSIONS = 20;
const MAX_DIAGRAM_SESSION_VERSION_STORAGE_BYTES = 4 * 1024 * 1024;
const NODES_MAP = "nodes";
const EDGES_MAP = "edges";
const PAGES_MAP = "pages";
const COMMENTS_MAP = "comments";
const DEFAULT_PAGE_ID = "page-1";
const DIAGRAM_CANVAS = { width: 2_400, height: 1_600, gridSize: 10 };
const DIAGRAM_CANVAS_GROWTH = { width: 480, height: 320 };
const DIAGRAM_CANVAS_PADDING = { width: 280, height: 220 };
const DIAGRAM_CANVAS_VIEWPORT_INSET = 2;
const MAX_DIAGRAM_CANVAS_SIZE = 100_000;
const DIAGRAM_PORT_IMAGE = `data:image/svg+xml,${encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 12 12"><circle cx="6" cy="6" r="4.5" fill="#fff" stroke="#0066cc" stroke-width="2"/></svg>')}`;
const SELECTION_TOOLBAR_SIZE = { width: 176, height: 36, gap: 12, inset: 8 };
const MAX_DRAWIO_DOCUMENT_BYTES = 8 * 1024 * 1024;
const STENCIL_PAGE_SIZE = 180;
const STENCIL_SEARCH_LIMIT = 240;
const EMPTY_SELECTION: DiagramSelection = {
  count: 0,
  ids: [],
  label: "",
  isNode: false,
  isEdge: false,
  linePattern: "solid",
  strokeWidth: 2,
  lockedCount: 0,
  editableCount: 0,
  mixedFields: [],
};

const diagramStateCache = new Map<string, Uint8Array>();

export function SyncedDiagram({
  boardKey,
  roomId,
  roomToken,
  roomRole,
  peerId,
  peerCount,
  peerDisplayNames = {},
  isConnected,
  isActive = true,
  events,
  onSend,
  onSwitchToWhiteboard,
  standalone = false,
  collaborationPanel,
  onEmbedApiChange,
  onLocalChange,
}: SyncedDiagramProps) {
  const {
    theme,
    setTheme,
    userOverride: hasThemeOverride,
    resetToSystem,
  } = useTheme();
  const {
    ready: authReady,
    authed,
    profile,
    logout,
  } = useAuth();
  const graphContainerRef = useRef<HTMLDivElement | null>(null);
  const rootSectionRef = useRef<HTMLElement | null>(null);
  const contextMenuRef = useRef<HTMLDivElement | null>(null);
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
  const remoteUpdateValidatorRef = useRef<DiagramRemoteUpdateValidator | null>(null);
  const versionsRef = useRef<DiagramVersionSnapshot[]>([]);
  const cloudDocumentRef = useRef<UserDiagramDocument | null>(null);
  const cloudChangeSequenceRef = useRef(0);
  const undoManagerRef = useRef<Y.UndoManager | null>(null);
  const renderGraphRef = useRef<() => void>(() => undefined);
  const flushGraphRef = useRef<() => void>(() => undefined);
  const graphSyncTimerRef = useRef<number | null>(null);
  const graphRenderFrameRef = useRef<number | null>(null);
  const syncRetryTimerRef = useRef<number | null>(null);
  const syncRetryAttemptRef = useRef(0);
  const syncDeliveryFailedRef = useRef(false);
  const retryFullStateRef = useRef<() => void>(() => undefined);
  const canvasSizeRef = useRef({ ...DIAGRAM_CANVAS });
  const suppressGraphSyncRef = useRef(false);
  const seenEventsRef = useRef(new Set<string>());
  const lastPeerCountRef = useRef(peerCount);
  const dialogSequenceRef = useRef(0);
  const dialogResolverRef = useRef<((result: DiagramDialogResult) => void) | null>(null);
  const onSendRef = useRef(onSend);
  onSendRef.current = onSend;
  const onLocalChangeRef = useRef(onLocalChange);
  onLocalChangeRef.current = onLocalChange;
  const isReadOnlyRef = useRef(false);
  const connectionModeRef = useRef(false);
  const minimapManuallySetRef = useRef(readDiagramBooleanPreference("diagram-minimap-visible") !== null);
  const allowUnsavedNavigationRef = useRef(false);

  const [isExpanded, setIsExpanded] = useState(false);
  const [showCollaborationPanel, setShowCollaborationPanel] = useState(false);
  const isFullViewport = standalone || isExpanded;
  const [documentEpoch, setDocumentEpoch] = useState(0);
  const [runtimeEpoch, setRuntimeEpoch] = useState(0);
  const [viewEpoch, setViewEpoch] = useState(0);
  const [selection, setSelection] = useState<DiagramSelection>(EMPTY_SELECTION);
  const [nodeCount, setNodeCount] = useState(0);
  const [edgeCount, setEdgeCount] = useState(0);
  const [pages, setPages] = useState<DiagramPage[]>([{ id: DEFAULT_PAGE_ID, name: "页面 1", order: 0 }]);
  const [activePageId, setActivePageId] = useState(DEFAULT_PAGE_ID);
  const [canUndo, setCanUndo] = useState(false);
  const [canRedo, setCanRedo] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [showMinimap, setShowMinimap] = useState(() => readDiagramBooleanPreference("diagram-minimap-visible") ?? false);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [paletteView, setPaletteView] = useState<"common" | "recent" | "favorites" | "all">("common");
  const [recentNodeKinds, setRecentNodeKinds] = useState<DiagramNodeKind[]>(() => readDiagramNodeKindList("diagram-recent-node-kinds"));
  const [favoriteNodeKinds, setFavoriteNodeKinds] = useState<DiagramNodeKind[]>(() => readDiagramNodeKindList("diagram-favorite-node-kinds"));
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
  const [isLibraryVisible, setIsLibraryVisible] = useState(() => readDiagramBooleanPreference("diagram-library-visible") ?? true);
  const [isInspectorVisible, setIsInspectorVisible] = useState(() => readDiagramBooleanPreference("diagram-inspector-visible") ?? false);
  // 网格吸附默认开启（10px），但需要可关闭：贴合边界或做像素级微调时，
  // 强制吸附会让元素无法停在网格之间的位置。
  const [gridSnapEnabled, setGridSnapEnabled] = useState(() => readDiagramBooleanPreference("diagram-grid-snap") ?? true);
  const gridSnapEnabledRef = useRef(gridSnapEnabled);
  const [libraryWidth, setLibraryWidth] = useState(() => readDiagramPanelWidth("diagram-library-width", 260, 220, 380));
  const [inspectorWidth, setInspectorWidth] = useState(() => readDiagramPanelWidth("diagram-inspector-width", 300, 260, 420));
  const [inspectorPinned, setInspectorPinned] = useState(() => readDiagramBooleanPreference("diagram-inspector-pinned") ?? false);
  const [interactionMode, setInteractionMode] = useState<"select" | "connect">("select");
  const [inspectorSheetExpanded, setInspectorSheetExpanded] = useState(false);
  const [showMobileHelp, setShowMobileHelp] = useState(() => (
    typeof window !== "undefined" && sessionStorage.getItem("diagram-mobile-help-dismissed") !== "1"
  ));
  const [localDocumentName, setLocalDocumentName] = useState("未命名流程图");
  const [templatePreviewId, setTemplatePreviewId] = useState<DiagramTemplateId | null>(null);
  const [pendingTemplateInsertion, setPendingTemplateInsertion] = useState<{ templateId: DiagramTemplateId; pageId: string } | null>(null);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [inspectorTab, setInspectorTab] = useState<"design" | "comments" | "versions">("design");
  const [hasCopiedFormat, setHasCopiedFormat] = useState(false);
  const [remotePresences, setRemotePresences] = useState<Record<string, RemoteDiagramPresence>>({});
  const [comments, setComments] = useState<DiagramComment[]>([]);
  const [versions, setVersions] = useState<DiagramVersionSnapshot[]>([]);
  const [localReadOnly, setLocalReadOnly] = useState(false);
  const [isVersionLoading, setIsVersionLoading] = useState(false);
  const [cloudDocument, setCloudDocument] = useState<UserDiagramDocument | null>(null);
  const [cloudDocuments, setCloudDocuments] = useState<UserDiagramDocument[]>([]);
  const [cloudDirty, setCloudDirty] = useState(false);
  const [cloudDialog, setCloudDialog] = useState<"login" | "documents" | null>(null);
  const [isCloudBusy, setIsCloudBusy] = useState(false);
  const [contextMenu, setContextMenu] = useState<DiagramContextMenu | null>(null);
  const [dialogRequest, setDialogRequest] = useState<DiagramDialogRequest | null>(null);
  const [status, setStatusMessage] = useState("专业流程图已就绪，从左侧插入节点后拖动蓝色端口连线。");
  const [statusTone, setStatusTone] = useState<DiagramStatusTone>("info");
  const usesServerVersions = Boolean(roomToken.trim());
  const isRoleReadOnly = roomRole === "VIEWER";
  const isReadOnly = isRoleReadOnly || localReadOnly;
  isReadOnlyRef.current = isReadOnly;
  connectionModeRef.current = interactionMode === "connect" && !isReadOnly;

  useEffect(() => {
    if (selection.count > 0) {
      setIsInspectorVisible(true);
      if (window.matchMedia("(max-width: 1280px)").matches) setIsLibraryVisible(false);
    } else if (!inspectorPinned && inspectorTab === "design") {
      setIsInspectorVisible(false);
    }
  }, [inspectorPinned, inspectorTab, selection.count]);

  useEffect(() => {
    const compactWorkspace = window.matchMedia("(max-width: 1280px)");
    const preserveCanvasSpace = () => {
      if (compactWorkspace.matches && selection.count > 0 && isInspectorVisible) {
        setIsLibraryVisible(false);
      }
    };
    preserveCanvasSpace();
    compactWorkspace.addEventListener("change", preserveCanvasSpace);
    return () => compactWorkspace.removeEventListener("change", preserveCanvasSpace);
  }, [isInspectorVisible, selection.count]);

  useEffect(() => {
    if (compactPanel !== "inspector" || inspectorSheetExpanded || selection.ids.length === 0) return;
    if (!window.matchMedia("(max-width: 1023px)").matches) return;
    const frame = window.requestAnimationFrame(() => {
      const graph = runtimeRef.current?.graph;
      const container = graphContainerRef.current;
      const cell = graph?.getDataModel().getCell(selection.ids[0]);
      const state = cell ? graph?.getView().getState(cell) : null;
      if (!container || !state) return;
      const visibleBottom = container.clientHeight * 0.52;
      const viewportTop = state.y - container.scrollTop;
      const viewportBottom = viewportTop + state.height;
      if (viewportBottom > visibleBottom - 20) {
        container.scrollTop += viewportBottom - visibleBottom + 20;
      } else if (viewportTop < 20) {
        container.scrollTop = Math.max(0, container.scrollTop + viewportTop - 20);
      }
    });
    return () => window.cancelAnimationFrame(frame);
  }, [compactPanel, inspectorSheetExpanded, selection.ids]);

  useEffect(() => {
    if (minimapManuallySetRef.current) return;
    setShowMinimap(nodeCount >= 12 || edgeCount >= 16);
  }, [edgeCount, nodeCount]);

  useEffect(() => {
    writeDiagramBooleanPreference("diagram-library-visible", isLibraryVisible);
  }, [isLibraryVisible]);

  useEffect(() => {
    writeDiagramBooleanPreference("diagram-inspector-visible", isInspectorVisible);
  }, [isInspectorVisible]);

  useEffect(() => {
    // graph 在独立 effect 中创建，初始化时读 ref 取当前值，避免把 graph 重建绑到该开关上。
    gridSnapEnabledRef.current = gridSnapEnabled;
    writeDiagramBooleanPreference("diagram-grid-snap", gridSnapEnabled);
    runtimeRef.current?.graph?.setGridEnabled(gridSnapEnabled);
  }, [gridSnapEnabled]);

  useEffect(() => {
    writeDiagramBooleanPreference("diagram-inspector-pinned", inspectorPinned);
  }, [inspectorPinned]);

  useEffect(() => {
    if (!cloudDirty) return;
    const protectUnsavedCloudChanges = (event: BeforeUnloadEvent) => {
      if (allowUnsavedNavigationRef.current) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", protectUnsavedCloudChanges);
    return () => window.removeEventListener("beforeunload", protectUnsavedCloudChanges);
  }, [cloudDirty]);

  const setStatus = useCallback((message: string, tone = inferDiagramStatusTone(message)) => {
    setStatusMessage(message);
    setStatusTone(tone);
  }, []);

  const openEditorDialog = useCallback((request: Omit<DiagramDialogRequest, "id">) => (
    new Promise<DiagramDialogResult>((resolve) => {
      dialogResolverRef.current?.(null);
      dialogResolverRef.current = resolve;
      dialogSequenceRef.current += 1;
      setDialogRequest({ ...request, id: dialogSequenceRef.current });
    })
  ), []);

  const resolveEditorDialog = useCallback((result: DiagramDialogResult) => {
    const resolve = dialogResolverRef.current;
    dialogResolverRef.current = null;
    setDialogRequest(null);
    resolve?.(result);
  }, []);

  const requestConfirmation = useCallback(async (
    request: Omit<DiagramDialogRequest, "id" | "kind">,
  ) => (await openEditorDialog({ ...request, kind: "confirm" })) === true, [openEditorDialog]);

  const requestText = useCallback(async (
    request: Omit<DiagramDialogRequest, "id" | "kind">,
  ) => {
    const result = await openEditorDialog({ ...request, kind: "text" });
    return typeof result === "string" ? result : null;
  }, [openEditorDialog]);

  useEffect(() => {
    if (!cloudDirty) return;
    const guardUnsavedNavigation = (event: MouseEvent) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const target = event.target instanceof Element ? event.target.closest<HTMLAnchorElement>("a[href]") : null;
      if (!target || target.target === "_blank" || target.hasAttribute("download")) return;
      const destination = new URL(target.href, window.location.href);
      if (destination.href === window.location.href) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      void requestConfirmation({
        title: "离开未保存的流程图？",
        message: "当前云端文件还有未保存修改。离开后，这些修改不会写入云端。",
        confirmLabel: "仍然离开",
        tone: "danger",
      }).then((confirmed) => {
        if (!confirmed) return;
        allowUnsavedNavigationRef.current = true;
        window.location.assign(destination.href);
        window.setTimeout(() => {
          allowUnsavedNavigationRef.current = false;
        }, 1000);
      });
    };
    document.addEventListener("click", guardUnsavedNavigation, true);
    return () => document.removeEventListener("click", guardUnsavedNavigation, true);
  }, [cloudDirty, requestConfirmation]);

  const selectCloudDocument = useCallback((document: UserDiagramDocument | null, dirty = false) => {
    cloudDocumentRef.current = document;
    setCloudDocument(document);
    setCloudDirty(dirty);
  }, []);

  useEffect(() => {
    if (authed) return;
    selectCloudDocument(null);
    setCloudDocuments([]);
    if (cloudDialog === "documents") setCloudDialog(null);
  }, [authed, cloudDialog, selectCloudDocument]);

  useEffect(() => () => {
    dialogResolverRef.current?.(null);
    dialogResolverRef.current = null;
  }, []);

  useEffect(() => {
    canvasSizeRef.current = { ...DIAGRAM_CANVAS };
  }, [boardKey]);

  useLayoutEffect(() => {
    if (!isFullViewport || !isActive || standalone) return;
    const root = window.document.documentElement;
    const body = window.document.body;
    const previousRootOverflow = root.style.overflow;
    const previousScrollbarGutter = root.style.getPropertyValue("scrollbar-gutter");
    const previousBodyOverflow = body.style.overflow;
    const previousOverscrollBehavior = body.style.overscrollBehavior;
    root.style.overflow = "hidden";
    root.style.setProperty("scrollbar-gutter", "auto");
    body.style.overflow = "hidden";
    body.style.overscrollBehavior = "none";
    return () => {
      root.style.overflow = previousRootOverflow;
      if (previousScrollbarGutter) root.style.setProperty("scrollbar-gutter", previousScrollbarGutter);
      else root.style.removeProperty("scrollbar-gutter");
      body.style.overflow = previousBodyOverflow;
      body.style.overscrollBehavior = previousOverscrollBehavior;
    };
  }, [isActive, isFullViewport, standalone]);

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
        if (active) setStatus(error instanceof Error ? error.message : "扩展图形库加载失败", "error");
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
        if (active) setStatus(error instanceof Error ? error.message : `${collection.name} 加载失败`, "error");
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
        if (active) setStatus(error instanceof Error ? error.message : "搜索图形加载失败", "error");
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

  const performHistoryAction = useCallback((action: "undo" | "redo") => {
    flushGraphRef.current();
    const manager = undoManagerRef.current;
    const available = action === "undo" ? manager?.canUndo() : manager?.canRedo();
    if (!manager || !available) {
      setStatus(action === "undo" ? "当前没有可撤销的操作。" : "当前没有可重做的操作。");
      return;
    }
    const before = diagramPageFingerprints(
      nodesMapRef.current,
      edgesMapRef.current,
      pagesMapRef.current,
      commentsMapRef.current,
    );
    if (action === "undo") manager.undo();
    else manager.redo();
    const after = diagramPageFingerprints(
      nodesMapRef.current,
      edgesMapRef.current,
      pagesMapRef.current,
      commentsMapRef.current,
    );
    const affectedPages = changedFingerprintKeys(before, after);
    const visibleAffectedPage = affectedPages.find((pageId) => pagesMapRef.current?.has(pageId));
    if (visibleAffectedPage && visibleAffectedPage !== activePageId) {
      setActivePageId(visibleAffectedPage);
      const pageName = pagesMapRef.current?.get(visibleAffectedPage)?.name ?? "其他页面";
      setStatus(`${action === "undo" ? "已撤销" : "已重做"}“${pageName}”中的操作，并已切换到受影响页面。`);
    } else {
      setStatus(action === "undo" ? "已撤销上一步操作。" : "已重做上一步操作。");
    }
    refreshUndoState();
  }, [activePageId, refreshUndoState]);

  const scheduleDocumentRender = useCallback(() => {
    if (graphRenderFrameRef.current !== null) return;
    graphRenderFrameRef.current = window.requestAnimationFrame(() => {
      graphRenderFrameRef.current = null;
      renderGraphRef.current();
    });
  }, []);

  const cancelPendingGraphSync = useCallback(() => {
    if (graphSyncTimerRef.current === null) return false;
    window.clearTimeout(graphSyncTimerRef.current);
    graphSyncTimerRef.current = null;
    return true;
  }, []);

  const flushPendingGraphSync = useCallback(() => {
    if (!cancelPendingGraphSync()) return false;
    flushGraphRef.current();
    return true;
  }, [cancelPendingGraphSync]);

  const clearSyncRetry = useCallback(() => {
    if (syncRetryTimerRef.current !== null) {
      window.clearTimeout(syncRetryTimerRef.current);
      syncRetryTimerRef.current = null;
    }
    syncRetryAttemptRef.current = 0;
  }, []);

  const handleDiagramDelivery = useCallback((delivered: boolean, fullState: boolean) => {
    if (delivered) {
      if (fullState && syncDeliveryFailedRef.current) {
        syncDeliveryFailedRef.current = false;
        clearSyncRetry();
        setStatus("流程图同步已恢复，完整状态已重新发送。");
      }
      return;
    }
    syncDeliveryFailedRef.current = true;
    setStatus("流程图同步中断，正在重新连接并重发完整状态。");
    if (syncRetryTimerRef.current !== null) return;
    const delay = Math.min(15_000, 1_000 * 2 ** Math.min(syncRetryAttemptRef.current, 4));
    syncRetryAttemptRef.current += 1;
    syncRetryTimerRef.current = window.setTimeout(() => {
      syncRetryTimerRef.current = null;
      retryFullStateRef.current();
    }, delay);
  }, [clearSyncRetry]);

  const sendYUpdate = useCallback((update: Uint8Array, fullState = false) => {
    if (update.byteLength > MAX_DIAGRAM_BINARY_UPDATE_BYTES) {
      setStatus("流程图同步数据超过 4 MB，请导出后精简文档再继续协作。");
      return false;
    }
    try {
      const delivery = onSendRef.current({
        type: "STDG2",
        kind: "diagram-update",
        update,
        createdAt: Date.now(),
      });
      void Promise.resolve(delivery).then(
        (delivered) => handleDiagramDelivery(delivered, fullState),
        () => handleDiagramDelivery(false, fullState),
      );
    } catch {
      handleDiagramDelivery(false, fullState);
    }
    return true;
  }, [handleDiagramDelivery]);

  const sendFullState = useCallback(() => {
    const document = yDocRef.current;
    if (!document) {
      return false;
    }
    return sendYUpdate(Y.encodeStateAsUpdate(document), true);
  }, [sendYUpdate]);
  retryFullStateRef.current = () => {
    sendFullState();
  };

  useEffect(() => () => clearSyncRetry(), [clearSyncRetry]);

  const sendPresence = useCallback((cursor?: { x: number; y: number }, force = false) => {
    const now = Date.now();
    if (!force && now - lastPresenceSentRef.current < 80) return;
    lastPresenceSentRef.current = now;
    const graph = runtimeRef.current?.graph;
    onSendRef.current({
      type: "STDG2",
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
    cloudChangeSequenceRef.current = 0;
    setSelection(EMPTY_SELECTION);
    selectCloudDocument(null);
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
    const remoteUpdateValidator = new DiagramRemoteUpdateValidator(document);
    remoteUpdateValidatorRef.current = remoteUpdateValidator;
    const refreshPages = () => {
      const nextPages = Array.from(pageMap.values()).sort((left, right) => left.order - right.order);
      const nextComments = Array.from(commentsMap.values()).filter(isDiagramComment).sort((a, b) => a.createdAt - b.createdAt);
      setPages((current) => diagramRecordsEqual(current, nextPages) ? current : nextPages);
      setComments((current) => diagramRecordsEqual(current, nextComments) ? current : nextComments);
      setActivePageId((current) => nextPages.some((page) => page.id === current) ? current : nextPages[0]?.id ?? DEFAULT_PAGE_ID);
    };
    refreshPages();
    setStatus(restoredFromCache ? "已恢复当前房间的本地流程图。" : "已切换到新的房间流程图。");

    const handleUpdate = (update: Uint8Array, origin: unknown, _source: Y.Doc, transaction: Y.Transaction) => {
      if (origin !== REMOTE_ORIGIN) {
        try {
          remoteUpdateValidator.sync(update);
        } catch {
          remoteUpdateValidator.reset(document);
        }
      }
      const changedTypes = transaction.changedParentTypes as Map<unknown, unknown>;
      if (changedTypes.has(pageMap) || changedTypes.has(commentsMap)) {
        refreshPages();
      }
      cloudChangeSequenceRef.current += 1;
      if (cloudDocumentRef.current) {
        setCloudDirty(true);
      }
      if (origin === REMOTE_ORIGIN) {
        scheduleDocumentRender();
        refreshUndoState();
        return;
      }
      if (origin !== GRAPH_ORIGIN) {
        scheduleDocumentRender();
      }
      onLocalChangeRef.current?.();
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
      remoteUpdateValidator.destroy();
      document.destroy();
      if (yDocRef.current === document) {
        yDocRef.current = null;
        nodesMapRef.current = null;
        edgesMapRef.current = null;
        pagesMapRef.current = null;
        commentsMapRef.current = null;
        undoManagerRef.current = null;
        remoteUpdateValidatorRef.current = null;
      }
    };
  }, [boardKey, refreshUndoState, scheduleDocumentRender, selectCloudDocument, sendYUpdate]);

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
        if (active) setStatus(error instanceof Error ? error.message : "加载流程图版本失败", "error");
      })
      .finally(() => {
        if (active) setIsVersionLoading(false);
      });
    return () => {
      active = false;
    };
  }, [peerId, roomId, roomToken, usesServerVersions]);

  useEffect(() => {
    if (usesServerVersions) return;
    const snapshots = readSessionDiagramVersions(boardKey);
    versionsRef.current = snapshots;
    setVersions(snapshots);
  }, [boardKey, usesServerVersions]);

  useEffect(() => {
    const container = graphContainerRef.current;
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    if (!container || !nodes || !edges) {
      return;
    }

    const graph = new Graph(container, undefined, [...getDefaultPlugins(), RubberBandHandler]);
    graph.getDataModel().prefix = `${peerId}-${Math.random().toString(36).slice(2, 9)}-auto-`;
    graph.setConnectable(!isReadOnlyRef.current);
    graph.setAllowDanglingEdges(false);
    graph.setConnectableEdges(false);
    graph.setMultigraph(false);
    graph.setPanning(true);
    graph.setTooltips(true);
    graph.setGridEnabled(gridSnapEnabledRef.current);
    graph.setGridSize(DIAGRAM_CANVAS.gridSize);
    graph.setCellsEditable(!isReadOnlyRef.current);
    graph.setCellsResizable(!isReadOnlyRef.current);
    graph.setCellsBendable(true);
    graph.setDropEnabled(!isReadOnlyRef.current);
    graph.setSwimlaneNesting(true);
    graph.setExtendParentsOnMove(true);
    graph.setHtmlLabels(false);
    graph.setAllowNegativeCoordinates(false);
    graph.centerZoom = true;
    graph.keepSelectionVisibleOnZoom = true;
    const initialCanvasSize = expandedDiagramCanvasSize(
      canvasSizeRef.current,
      null,
      container.clientWidth,
      container.clientHeight,
      1,
    );
    canvasSizeRef.current = { ...initialCanvasSize, gridSize: DIAGRAM_CANVAS.gridSize };
    graph.setMinimumGraphSize(new Rectangle(0, 0, initialCanvasSize.width, initialCanvasSize.height));
    const rubberBandHandler = graph.getPlugin<RubberBandHandler>(RubberBandHandler.pluginId);
    if (rubberBandHandler) {
      rubberBandHandler.defaultOpacity = 14;
      rubberBandHandler.fadeOut = true;
    }
    const connectionHandler = graph.getPlugin<ConnectionHandler>(ConnectionHandler.pluginId);
    if (connectionHandler) {
      const defaultInsertEdge = connectionHandler.insertEdge.bind(connectionHandler);
      connectionHandler.insertEdge = (parent, id, value, source, target, style) => {
        const edgeId = id || createDiagramId(peerId, "edge");
        const defaults = defaultEdgeStyle();
        const nextStyle = edgeCellStyle({
          id: edgeId,
          label: String(value ?? ""),
          sourceId: source?.getId() ?? "",
          targetId: target?.getId() ?? "",
          zIndex: graph.getChildEdges(parent).length,
          pageId: activePageId,
          style: defaults,
        }, source ?? undefined, target ?? undefined);
        return defaultInsertEdge(parent, edgeId, value, source, target, { ...nextStyle, ...style });
      };
      const defaultIsConnectableCell = connectionHandler.isConnectableCell.bind(connectionHandler);
      connectionHandler.isConnectableCell = (cell) => Boolean(connectionHandler.first) && defaultIsConnectableCell(cell);
      connectionHandler.isStartEvent = () => Boolean(
        connectionHandler.constraintHandler.currentFocus
        && connectionHandler.constraintHandler.currentConstraint,
      );
      const defaultValidateConnection = connectionHandler.validateConnection.bind(connectionHandler);
      connectionHandler.validateConnection = (source, target) => {
        if (!connectionHandler.sourceConstraint || !connectionHandler.constraintHandler.currentConstraint) {
          return "";
        }
        return defaultValidateConnection(source, target);
      };
      connectionHandler.cursorConnect = "crosshair";
      connectionHandler.livePreview = true;
      connectionHandler.movePreviewAway = true;
      connectionHandler.outlineConnect = false;
      const constraintHandler = connectionHandler.constraintHandler;
      constraintHandler.pointImage = new ImageBox(DIAGRAM_PORT_IMAGE, 16, 16);
      const defaultConstraintTolerance = constraintHandler.getTolerance.bind(constraintHandler);
      constraintHandler.getTolerance = (event) => Math.max(connectionModeRef.current ? 22 : 12, defaultConstraintTolerance(event));
      const defaultSetConstraintFocus = constraintHandler.setFocus.bind(constraintHandler);
      constraintHandler.setFocus = (event, state, source) => {
        defaultSetConstraintFocus(event, state, source);
        constraintHandler.focusIcons.forEach((icon) => {
          icon.node.style.cursor = "crosshair";
        });
      };
    }
    const defaultGetCursorForCell = graph.getCursorForCell.bind(graph);
    graph.getCursorForCell = (cell) => (
      cell.isVertex() && graph.isCellMovable(cell) ? "grab" : defaultGetCursorForCell(cell)
    );
    const defaultCreateHandler = graph.createHandler.bind(graph);
    graph.createHandler = (state) => {
      const handler = state.cell.isEdge() && edgeTypeFromCellStyle(state.style) === "curved"
        ? new DiagramCubicEdgeHandler(state)
        : state.cell.isVertex()
          ? new DiagramVertexHandler(state)
          : defaultCreateHandler(state);
      if (
        handler instanceof DiagramVertexHandler
        && !isReadOnlyRef.current
        && !(state.style as DiagramCellStyle).diagramLocked
      ) {
        handler.ensureRotationHandle();
      }
      if (handler instanceof VertexHandler && handler.sizers.length >= 8) {
        const resizeHandle = handler.sizers[7];
        const rotationHandle = handler.rotationShape;
        handler.sizers.forEach((sizer) => {
          if (sizer !== resizeHandle && sizer !== rotationHandle) sizer.destroy();
        });
        handler.sizers = rotationHandle ? [resizeHandle, rotationHandle] : [resizeHandle];
        handler.labelShape = null;
        handler.singleSizer = true;
        if (handler instanceof DiagramVertexHandler) handler.rotateSingleSizer = true;
        handler.manageSizers = false;
        handler.livePreview = true;
        handler.movePreviewToFront = true;
        handler.rotationHandleVSpacing = -23;
        handler.tolerance = 4;
        if (rotationHandle) {
          rotationHandle.fill = DIAGRAM_ROTATION_HANDLE_FILL;
          rotationHandle.stroke = DIAGRAM_ROTATION_HANDLE_ACCENT;
          rotationHandle.strokeWidth = 0;
          rotationHandle.setCursor("grab");
        }
        handler.redraw();
      }
      return handler;
    };
    const selectionHandler = graph.getPlugin<SelectionHandler>(SelectionHandler.pluginId);
    if (selectionHandler) {
      selectionHandler.guidesEnabled = true;
    }
    graph.getAllConnectionConstraints = (terminal) => (
      terminal?.cell.isVertex() ? PORT_CONSTRAINTS : null
    );
    const defaultIsValidConnection = graph.isValidConnection.bind(graph);
    graph.isValidConnection = (source, target) => {
      if ((edgesMapRef.current?.size ?? 0) >= MAX_DIAGRAM_EDGES) {
        setStatus(`流程图连线已达到 ${MAX_DIAGRAM_EDGES} 条上限。`);
        return false;
      }
      return defaultIsValidConnection(source, target);
    };
    const defaultIsValidDropTarget = graph.isValidDropTarget.bind(graph);
    graph.isValidDropTarget = (cell, cells, event) => {
      const kind = (cell.getStyle() as DiagramCellStyle).diagramKind;
      return kind === "container" || kind === "swimlane" || kind === "lane" || defaultIsValidDropTarget(cell, cells, event);
    };
    const defaultIsCellMovable = graph.isCellMovable.bind(graph);
    const defaultIsCellResizable = graph.isCellResizable.bind(graph);
    const defaultIsCellRotatable = graph.isCellRotatable.bind(graph);
    const defaultIsCellEditable = graph.isCellEditable.bind(graph);
    const defaultIsCellDeletable = graph.isCellDeletable.bind(graph);
    graph.isCellMovable = (cell) => !isReadOnlyRef.current && !(cell.getStyle() as DiagramCellStyle).diagramLocked && defaultIsCellMovable(cell);
    graph.isCellResizable = (cell) => !isReadOnlyRef.current && !(cell.getStyle() as DiagramCellStyle).diagramLocked && defaultIsCellResizable(cell);
    graph.isCellRotatable = (cell) => graph.getSelectionCount() === 1
      && !isReadOnlyRef.current
      && !(cell.getStyle() as DiagramCellStyle).diagramLocked
      && defaultIsCellRotatable(cell);
    graph.isCellEditable = (cell) => !isReadOnlyRef.current && !(cell.getStyle() as DiagramCellStyle).diagramLocked && defaultIsCellEditable(cell);
    graph.isCellDeletable = (cell) => !isReadOnlyRef.current && !isDiagramCellLocked(cell) && defaultIsCellDeletable(cell);

    let canvasExpansionFrame: number | null = null;
    let viewRefreshFrame: number | null = null;
    const scheduleViewRefresh = () => {
      if (viewRefreshFrame !== null) return;
      viewRefreshFrame = window.requestAnimationFrame(() => {
        viewRefreshFrame = null;
        setViewEpoch((value) => value + 1);
      });
    };
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
      const minimumSizeChanged = sizeChanged
        || minimumSize?.width !== nextSize.width
        || minimumSize?.height !== nextSize.height;
      if (minimumSizeChanged) {
        graph.setMinimumGraphSize(new Rectangle(0, 0, nextSize.width, nextSize.height));
        graph.sizeDidChange();
        outlineRef.current?.update(true);
      }
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
      const currentPages = pagesMapRef.current;
      const document = yDocRef.current;
      if (!currentNodes || !currentEdges || !currentPages || !document || !currentPages.has(activePageId)) {
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
      const nextNodes = Array.from(currentNodes.values())
        .filter((node) => diagramPageId(node.pageId) === activePageId)
        .sort((a, b) => a.zIndex - b.zIndex);
      const nextEdges = Array.from(currentEdges.values())
        .filter((edge) => diagramPageId(edge.pageId) === activePageId)
        .sort((a, b) => a.zIndex - b.zIndex);
      const missingStencilPaths = new Set(
        nextNodes
          .map((node) => node.stencilLibrary)
          .filter((path): path is string => typeof path === "string" && !loadedStencilLibrariesRef.current.has(path)),
      );
      for (const path of missingStencilPaths) {
        const library = stencilLibrariesByPathRef.current.get(path);
        if (library) {
          void ensureStencilLibraryLoaded(library)
            .then(scheduleDocumentRender)
            .catch((error) => setStatus(error instanceof Error ? error.message : `${library.name} 加载失败`, "error"));
        }
      }
      const selectedIds = new Set(graph.getSelectionCells().map((cell) => cell.getId()).filter(Boolean));
      suppressGraphSyncRef.current = true;
      try {
        graph.batchUpdate(() => {
          const parent = graph.getDefaultParent();
          const existingVertices = descendantVertices(graph, parent);
          const existingEdges = graph.getChildEdges(parent);
          const cells = new Map<string, Cell>();
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
              const existing = graph.getDataModel().getCell(node.id);
              const desiredStyle = nodeCellStyle(node, optimizeLargeGraph);
              const cell = existing?.isVertex() ? existing : graph.insertVertex({
                  parent: nodeParent,
                  id: node.id,
                  value: node.label,
                  position: [node.x, node.y],
                  size: [node.width, node.height],
                  style: desiredStyle,
                });
              if (cell.getParent() !== nodeParent) graph.addCell(cell, nodeParent);
              if (String(cell.getValue() ?? "") !== node.label) graph.getDataModel().setValue(cell, node.label);
              const geometry = cell.getGeometry();
              if (!geometry || geometry.x !== node.x || geometry.y !== node.y
                || geometry.width !== node.width || geometry.height !== node.height) {
                const nextGeometry = geometry?.clone() ?? new Geometry(node.x, node.y, node.width, node.height);
                nextGeometry.x = node.x;
                nextGeometry.y = node.y;
                nextGeometry.width = node.width;
                nextGeometry.height = node.height;
                graph.getDataModel().setGeometry(cell, nextGeometry);
              }
              if (!cellStylesEqual(cell.getStyle(), desiredStyle)) {
                graph.getDataModel().setStyle(cell, desiredStyle);
              }
              cell.setConnectable(node.kind !== "container" && node.kind !== "swimlane" && node.kind !== "lane");
              cells.set(node.id, cell);
            }
            if (remaining.length === pendingNodes.length) {
              break;
            }
            pendingNodes = remaining;
          }
          for (const edge of nextEdges) {
            const source = cells.get(edge.sourceId);
            const target = cells.get(edge.targetId);
            if (!source || !target) {
              continue;
            }
            const desiredStyle = edgeCellStyle(edge, source, target);
            const existing = graph.getDataModel().getCell(edge.id);
            const edgeCell = existing?.isEdge() ? existing : graph.insertEdge({
                parent,
                id: edge.id,
                value: edge.label,
                source,
                target,
                style: desiredStyle,
              });
            if (edgeCell.getParent() !== parent) graph.addCell(edgeCell, parent, null, source, target);
            else {
              if (edgeCell.getTerminal(true) !== source) graph.getDataModel().setTerminal(edgeCell, source, true);
              if (edgeCell.getTerminal(false) !== target) graph.getDataModel().setTerminal(edgeCell, target, false);
            }
            if (String(edgeCell.getValue() ?? "") !== edge.label) graph.getDataModel().setValue(edgeCell, edge.label);
            if (!cellStylesEqual(edgeCell.getStyle(), desiredStyle)) graph.getDataModel().setStyle(edgeCell, desiredStyle);
            const waypoints = edgeWaypointsForGraph(edge);
            const geometry = edgeCell.getGeometry();
            if (geometry && !diagramPointsEqual(geometry.points, waypoints)) {
              const nextGeometry = geometry.clone();
              nextGeometry.points = waypoints?.length ? waypoints : null;
              graph.getDataModel().setGeometry(edgeCell, nextGeometry);
            }
            graph.setConnectionConstraint(edgeCell, source, true, constraintForPort(edge.sourcePort));
            graph.setConnectionConstraint(edgeCell, target, false, constraintForPort(edge.targetPort));
            cells.set(edge.id, edgeCell);
          }
          const desiredEdgeIds = new Set(nextEdges.map((edge) => edge.id));
          const staleEdges = existingEdges.filter((cell) => !desiredEdgeIds.has(cell.getId() ?? ""));
          if (staleEdges.length > 0) graph.removeCells(staleEdges, true);
          const desiredNodeIds = new Set(nextNodes.map((node) => node.id));
          const staleVertices = existingVertices.filter((cell) => !desiredNodeIds.has(cell.getId() ?? ""));
          const staleVertexSet = new Set(staleVertices);
          const staleRoots = staleVertices.filter((cell) => !cell.getParent() || !staleVertexSet.has(cell.getParent()!));
          if (staleRoots.length > 0) graph.removeCells(staleRoots, true);
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
      setNodeCount(nextNodes.length);
      setEdgeCount(nextEdges.length);
      graph.setTooltips(currentNodes.size < 400);
      updateSelection(graph, setSelection);
      scheduleCanvasExpansion();
    };
    renderGraphRef.current = renderFromDocument;

    const modelListener = () => {
      scheduleGraphSync();
      scheduleCanvasExpansion();
      updateSelection(graph, setSelection);
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
    graph.getView().addListener(InternalEvent.SCALE, scheduleViewRefresh);
    graph.getView().addListener(InternalEvent.TRANSLATE, scheduleViewRefresh);
    graph.getView().addListener(InternalEvent.SCALE_AND_TRANSLATE, scheduleViewRefresh);
    container.addEventListener("pointermove", presencePointerListener, { passive: true });
    container.addEventListener("scroll", scheduleViewRefresh, { passive: true });
    const wheelZoomListener = (event: WheelEvent) => {
      if (!event.ctrlKey && !event.metaKey) return;
      event.preventDefault();
      if (event.deltaY < 0) graph.zoomIn();
      else if (event.deltaY > 0) graph.zoomOut();
      scheduleViewRefresh();
    };
    container.addEventListener("wheel", wheelZoomListener, { passive: false });
    const resizeObserver = new ResizeObserver(() => {
      scheduleCanvasExpansion();
      scheduleViewRefresh();
    });
    resizeObserver.observe(container);
    runtimeRef.current = {
      graph,
      destroy: () => {
        if (canvasExpansionFrame !== null) {
          window.cancelAnimationFrame(canvasExpansionFrame);
          canvasExpansionFrame = null;
        }
        if (viewRefreshFrame !== null) {
          window.cancelAnimationFrame(viewRefreshFrame);
          viewRefreshFrame = null;
        }
        resizeObserver.disconnect();
        graph.getDataModel().removeListener(modelListener);
        graph.getSelectionModel().removeListener(selectionListener);
        graph.getView().removeListener(scheduleViewRefresh);
        container.removeEventListener("pointermove", presencePointerListener);
        container.removeEventListener("scroll", scheduleViewRefresh);
        container.removeEventListener("wheel", wheelZoomListener);
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
      if (viewRefreshFrame !== null) {
        window.cancelAnimationFrame(viewRefreshFrame);
        viewRefreshFrame = null;
      }
      renderGraphRef.current = () => undefined;
      flushGraphRef.current = () => undefined;
      resizeObserver.disconnect();
      graph.getDataModel().removeListener(modelListener);
      graph.getSelectionModel().removeListener(selectionListener);
      graph.getView().removeListener(scheduleViewRefresh);
      container.removeEventListener("pointermove", presencePointerListener);
      container.removeEventListener("scroll", scheduleViewRefresh);
      container.removeEventListener("wheel", wheelZoomListener);
      graph.destroy();
    };
  }, [activePageId, boardKey, documentEpoch, ensureStencilLibraryLoaded, peerId, scheduleDocumentRender, sendPresence]);

  useEffect(() => {
    const graph = runtimeRef.current?.graph;
    if (!graph) return;
    if (isReadOnly && interactionMode === "connect") setInteractionMode("select");
    graph.setConnectable(!isReadOnly);
    graph.setCellsEditable(!isReadOnly);
    graph.setCellsResizable(!isReadOnly);
    graph.setDropEnabled(!isReadOnly);
    recreateSelectionHandlers(graph, graph.getSelectionCells());
  }, [interactionMode, isReadOnly, runtimeEpoch]);

  useEffect(() => {
    const graph = runtimeRef.current?.graph;
    if (!graph) return;
    const connectionHandler = graph.getPlugin<ConnectionHandler>(ConnectionHandler.pluginId);
    if (connectionHandler) connectionHandler.outlineConnect = false;
    graph.container.dataset.interactionMode = interactionMode;
    if (interactionMode === "connect") {
      graph.clearSelection();
    }
  }, [interactionMode, runtimeEpoch]);

  useEffect(() => {
    const graph = runtimeRef.current?.graph;
    if (!graph) return;
    const curvedEdges = graph.getChildEdges(graph.getDefaultParent())
      .filter((edge) => edgeTypeFromCellStyle(edge.getStyle()) === "curved");
    if (curvedEdges.length === 0) return;
    graph.batchUpdate(() => {
      for (const edge of curvedEdges) {
        const style = edge.getClonedStyle() as DiagramCellStyle;
        const geometry = edge.getGeometry()?.clone();
        const source = edge.getTerminal(true);
        const target = edge.getTerminal(false);
        if (!geometry || !source || !target) continue;
        const existing = geometry.points ?? [];
        const currentControls = {
          diagramCubicControl1T: style.diagramCubicControl1T,
          diagramCubicControl1N: style.diagramCubicControl1N,
          diagramCubicControl2T: style.diagramCubicControl2T,
          diagramCubicControl2N: style.diagramCubicControl2N,
        };
        const hasCurrentControls = Object.values(currentControls).every((value) => (
          typeof value === "number" && Number.isFinite(value)
        ));
        if (style.shape === DIAGRAM_CUBIC_EDGE_SHAPE && hasCurrentControls && existing.length === 0) {
          continue;
        }
        Object.assign(style, edgeRoutingStyle("curved"));
        if (hasCurrentControls) {
          Object.assign(style, currentControls);
        } else if (existing.length >= 2) {
          Object.assign(style, cubicControlStyleFromPoints(
            absoluteCellCenter(source),
            absoluteCellCenter(target),
            [existing[0], existing[existing.length - 1]],
          ));
        }
        geometry.points = null;
        graph.getDataModel().setStyle(edge, style);
        graph.getDataModel().setGeometry(edge, geometry);
      }
    });
    recreateSelectionHandlers(graph, curvedEdges);
  }, [runtimeEpoch]);

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
    // 默认布局把内容锚在左上角，蓝色视口框的描边会压在容器边缘、被小地图外框
    // 裁掉。居中并保证四周至少 border/2 的边距，视口框才能完整可见。
    outline.getOutlineOffset = (scale = 1) => {
      const source = outline.source;
      const host = outline.outline?.container;
      if (!source?.container || !host || scale <= 0) return new Point(0, 0);
      const sourceScale = source.view.scale;
      const scaledGraphBounds = outline.getSourceGraphBounds();
      const union = new Rectangle(
        scaledGraphBounds.x / sourceScale + source.panDx,
        scaledGraphBounds.y / sourceScale + source.panDy,
        scaledGraphBounds.width / sourceScale,
        scaledGraphBounds.height / sourceScale,
      );
      union.add(new Rectangle(0, 0, source.container.clientWidth / sourceScale, source.container.clientHeight / sourceScale));
      const size = outline.getSourceContainerSize();
      const completeWidth = Math.max(size.width / sourceScale, union.width);
      const completeHeight = Math.max(size.height / sourceScale, union.height);
      const marginX = Math.max(outline.border / 2, (host.clientWidth - completeWidth * scale) / 2);
      const marginY = Math.max(outline.border / 2, (host.clientHeight - completeHeight * scale) / 2);
      return new Point(marginX / scale, marginY / scale);
    };
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
      if (event.sourcePeerId === peerId || payload.type !== "STDG2") {
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
        const update = payload.update;
        flushPendingGraphSync();
        const validator = remoteUpdateValidatorRef.current;
        if (!validator || !validator.validate(update, document)) {
          throw new Error("invalid diagram state");
        }
        Y.applyUpdate(document, update, REMOTE_ORIGIN);
      } catch {
        remoteUpdateValidatorRef.current?.reset(document);
        setStatus("收到的流程图同步数据无效，已忽略。");
      }
    }
    if (seenEventsRef.current.size > 1_000) {
      seenEventsRef.current = new Set(Array.from(seenEventsRef.current).slice(-600));
    }
  }, [events, flushPendingGraphSync, peerId, runtimeEpoch, sendFullState]);

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
        type: "STDG2",
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

  const toggleConnectionMode = useCallback(() => {
    if (isReadOnly) {
      setStatus("当前为只读模式，不能创建连线。");
      return;
    }
    setInteractionMode((current) => {
      const next = current === "connect" ? "select" : "connect";
      setStatus(next === "connect"
        ? "连线模式已开启：从节点的蓝色连接点拖向目标节点的连接点。"
        : "已切回选择模式，可移动和框选元素。");
      return next;
    });
    setCompactPanel(null);
  }, [isReadOnly, setStatus]);

  const switchToWhiteboard = useCallback(async () => {
    if (!onSwitchToWhiteboard) return;
    if (cloudDirty && !await requestConfirmation({
      title: "切换到白板？",
      message: "当前云端文件还有未保存修改，切换后这些修改仍只保留在当前房间。",
      confirmLabel: "仍然切换",
      tone: "danger",
    })) return;
    cancelPendingGraphSync();
    flushGraphRef.current();
    const document = yDocRef.current;
    if (document) {
      cacheDiagramState(boardKey, Y.encodeStateAsUpdate(document));
    }
    onSwitchToWhiteboard();
  }, [boardKey, cancelPendingGraphSync, cloudDirty, onSwitchToWhiteboard, requestConfirmation]);

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
    const page: DiagramPage = { id, name: `页面 ${pageMap.size + 1}`, order: nextDiagramPageOrder(pageMap) };
    document.transact(() => pageMap.set(id, page), GRAPH_ORIGIN);
    setActivePageId(id);
    setStatus(`${page.name}已创建。`);
    return id;
  }, [isReadOnly, peerId]);

  const renamePage = useCallback(async () => {
    if (isReadOnly) return;
    const document = yDocRef.current;
    const pageMap = pagesMapRef.current;
    const page = pageMap?.get(activePageId);
    if (!document || !pageMap || !page) {
      return;
    }
    const name = (await requestText({
      title: "重命名页面",
      message: "页面名称会同步给当前房间内的协作者。",
      inputLabel: "页面名称",
      initialValue: page.name,
      maxLength: 80,
      confirmLabel: "保存",
    }))?.trim().slice(0, 80);
    if (!name || name === page.name) {
      return;
    }
    document.transact(() => pageMap.set(page.id, { ...page, name }), GRAPH_ORIGIN);
    setStatus(`页面已重命名为“${name}”。`);
  }, [activePageId, isReadOnly, requestText]);

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
    if (edges.size + sourceEdges.length > MAX_DIAGRAM_EDGES) {
      setStatus("复制页面会超过流程图连线数量上限。");
      return;
    }
    const pageId = createDiagramId(peerId, "page");
    const idMap = new Map(sourceNodes.map((node) => [node.id, createDiagramId(peerId, node.kind)]));
    const page: DiagramPage = { id: pageId, name: `${sourcePage.name} 副本`, order: nextDiagramPageOrder(pageMap) };
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

  const deletePage = useCallback(async () => {
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
    if (!await requestConfirmation({
      title: "删除页面",
      message: `“${page.name}”中的模块、连线和评论都会一并删除。`,
      confirmLabel: "删除页面",
      tone: "danger",
    })) {
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
  }, [activePageId, isReadOnly, pages, requestConfirmation]);

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
    setRecentNodeKinds((current) => {
      const next = [kind, ...current.filter((item) => item !== kind)].slice(0, 12);
      writeDiagramNodeKindList("diagram-recent-node-kinds", next);
      return next;
    });
  }, [insertNodeIntoGraph, withGraph]);

  const toggleFavoriteNodeKind = useCallback((kind: DiagramNodeKind) => {
    setFavoriteNodeKinds((current) => {
      const next = current.includes(kind)
        ? current.filter((item) => item !== kind)
        : [kind, ...current].slice(0, 24);
      writeDiagramNodeKindList("diagram-favorite-node-kinds", next);
      return next;
    });
  }, []);

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
      setStatus(error instanceof Error ? error.message : `${library.name} 加载失败`, "error");
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
      source.mouseDown = preserveTouchTap(source.mouseDown.bind(source));
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

  const insertTemplate = useCallback((templateId: DiagramTemplateId = "approval", anchor?: Point, targetPageId = activePageId) => {
    if (isReadOnly) return;
    withGraph((graph) => {
      const template = DIAGRAM_TEMPLATES[templateId];
      const currentNodeCount = nodesMapRef.current?.size ?? readGraphDocument(graph, targetPageId).nodes.length;
      if (currentNodeCount + template.nodes.length > MAX_DIAGRAM_NODES) {
        setStatus("节点数量不足以插入模板。");
        return;
      }
      const currentEdgeCount = edgesMapRef.current?.size ?? 0;
      if (currentEdgeCount + template.edges.length > MAX_DIAGRAM_EDGES) {
        setStatus("连线数量不足以插入模板。");
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
      const preferredX = graph.snap(Math.max(40, anchor ? anchor.x - templateWidth / 2 : viewportLeft + Math.max(32, (viewportWidth - templateWidth) / 2)));
      const preferredY = graph.snap(Math.max(40, anchor ? anchor.y - templateHeight / 2 : viewportTop + Math.max(32, (viewportHeight - templateHeight) / 2)));
      const placement = findAvailableTemplatePlacement(
        graph.getChildVertices(parent)
          .map((cell) => cell.getGeometry())
          .filter((geometry): geometry is Geometry => Boolean(geometry))
          .map((geometry) => new Rectangle(geometry.x, geometry.y, geometry.width, geometry.height)),
        new Rectangle(preferredX, preferredY, templateWidth, templateHeight),
        (value) => graph.snap(value),
      );
      const baseX = placement.x;
      const baseY = placement.y;
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
            pageId: targetPageId,
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
              pageId: targetPageId,
              style,
            }, source, target),
          });
          graph.setConnectionConstraint(edge, source, true, constraintForPort(definition.sourcePort));
          graph.setConnectionConstraint(edge, target, false, constraintForPort(definition.targetPort));
        }
      });
      graph.setSelectionCells(cells);
      graph.scrollCellToVisible(cells[0], false);
      setStatus(`${template.name}示例已插入${placement.shifted ? "，为避免覆盖已有内容已自动调整位置" : ""}。`);
    });
  }, [activePageId, isReadOnly, peerId, withGraph]);

  useEffect(() => {
    if (!pendingTemplateInsertion || pendingTemplateInsertion.pageId !== activePageId) return;
    insertTemplate(pendingTemplateInsertion.templateId, undefined, pendingTemplateInsertion.pageId);
    setPendingTemplateInsertion(null);
  }, [activePageId, insertTemplate, pendingTemplateInsertion]);

  const removeSelection = useCallback(() => {
    withGraph((graph) => {
      const selected = graph.getSelectionCells();
      const cells = graph.getDeletableCells(selected);
      if (cells.length > 0) {
        graph.removeCells(cells, true);
        const skipped = selected.length - cells.length;
        setStatus(skipped > 0
          ? `已删除 ${cells.length} 个元素，跳过 ${skipped} 个锁定元素。`
          : `已删除 ${cells.length} 个选中元素。`);
      } else if (selected.length > 0) {
        setStatus("选中元素已锁定，请先解锁后再删除。");
      }
    });
  }, [withGraph]);

  const copySelection = useCallback(() => {
    withGraph((graph) => {
      const cells = graph.getSelectionCells();
      if (cells.length > 0) {
        Clipboard.copy(graph);
        const plainText = cells
          .map((cell) => String(cell.getValue() ?? "").trim())
          .filter(Boolean)
          .join("\n") || `${cells.length} 个流程图元素`;
        if (navigator.clipboard?.writeText) {
          void navigator.clipboard.writeText(plainText).then(
            () => setStatus("已复制选中元素，并写入系统剪贴板。"),
            () => setStatus("已复制到流程图剪贴板；浏览器未授予系统剪贴板权限。", "info"),
          );
        } else {
          setStatus("已复制到流程图剪贴板；当前浏览器不支持系统剪贴板写入。", "info");
        }
      }
    });
  }, [withGraph]);

  const pasteSelection = useCallback(() => {
    withGraph((graph) => {
      const pasted = Clipboard.paste(graph);
      if (pasted && pasted.length > 0) {
        graph.setSelectionCells(pasted);
        setStatus(`已粘贴 ${pasted.length} 个元素。`);
      } else {
        setStatus("流程图剪贴板为空，请先复制或剪切元素。");
      }
    });
  }, [withGraph]);

  const cutSelection = useCallback(() => {
    withGraph((graph) => {
      const selected = graph.getSelectionCells();
      const cells = graph.getDeletableCells(selected);
      if (cells.length === 0) {
        setStatus(selected.length > 0 ? "选中元素已锁定，无法剪切。" : "请先选择要剪切的元素。");
        return;
      }
      Clipboard.cut(graph, cells);
      const skipped = selected.length - cells.length;
      setStatus(skipped > 0
        ? `已剪切 ${cells.length} 个元素，跳过 ${skipped} 个锁定元素。`
        : `已剪切 ${cells.length} 个元素。`);
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
      const cells = graph.getCellsForGroup(graph.getMovableCells(graph.getSelectionCells().filter((cell) => cell.isVertex())));
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
      const groups = graph.getMovableCells(graph.getSelectionCells()).filter((cell) => {
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
      const cells = graph.getMovableCells(graph.getSelectionCells()).filter((cell) => cell.isVertex() && cell.getGeometry());
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
          const style = edge.getClonedStyle() as DiagramCellStyle;
          delete style.edgeStyle;
          delete style.elbow;
          delete style.curved;
          delete style.orthogonalLoop;
          delete style.jettySize;
          delete style.noEdgeStyle;
          if (style.shape === DIAGRAM_CUBIC_EDGE_SHAPE) delete style.shape;
          delete style.diagramCubicControl1T;
          delete style.diagramCubicControl1N;
          delete style.diagramCubicControl2T;
          delete style.diagramCubicControl2N;
          Object.assign(style, edgeRoutingStyle(edgeType));
          if (edgeType === "curved") {
            const geometry = edge.getGeometry()?.clone();
            const source = edge.getTerminal(true);
            const target = edge.getTerminal(false);
            if (geometry && source && target) {
              const existing = geometry.points ?? [];
              const controls = existing.length >= 2
                ? [existing[0], existing[existing.length - 1]]
                : defaultCubicControlPoints(graph, source, target);
              Object.assign(style, cubicControlStyleFromPoints(
                absoluteCellCenter(source),
                absoluteCellCenter(target),
                controls,
              ));
              geometry.points = null;
              graph.getDataModel().setGeometry(edge, geometry);
            }
          }
          graph.getDataModel().setStyle(edge, style);
        }
      });
      recreateSelectionHandlers(graph, edges);
      updateSelection(graph, setSelection);
      setStatus(edgeType === "curved"
        ? `已切换 ${edges.length} 条连线为三阶贝塞尔曲线。`
        : `已切换 ${edges.length} 条连线的路由样式。`);
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
          if (edgeTypeFromCellStyle(edge.getStyle()) === "curved") {
            const style = edge.getClonedStyle() as DiagramCellStyle;
            Object.assign(style, cubicControlStyleFromPoints(
              sourceCenter,
              targetCenter,
              defaultCubicControlPoints(graph, source, target),
            ));
            geometry.points = null;
            graph.getDataModel().setStyle(edge, style);
            graph.getDataModel().setGeometry(edge, geometry);
            continue;
          }
          const previous = existing[existing.length - 1] ?? sourceCenter;
          existing.push(new Point(
            graph.snap((previous.x + targetCenter.x) / 2),
            graph.snap((previous.y + targetCenter.y) / 2),
          ));
          geometry.points = existing.slice(0, 128);
          graph.getDataModel().setGeometry(edge, geometry);
        }
      });
      setStatus(edges.every((edge) => edgeTypeFromCellStyle(edge.getStyle()) === "curved")
        ? "已重置三阶贝塞尔的两个控制点。"
        : "已添加可拖动折点；也可按住 Shift 点击连线添加或删除折点。");
    });
  }, [withGraph]);

  const clearEdgeWaypoints = useCallback(() => {
    withGraph((graph) => {
      const edges = graph.getSelectionCells().filter((cell) => cell.isEdge());
      graph.batchUpdate(() => {
        for (const edge of edges) {
          const geometry = edge.getGeometry()?.clone();
          if (edgeTypeFromCellStyle(edge.getStyle()) === "curved") {
            const style = edge.getClonedStyle() as DiagramCellStyle;
            style.diagramCubicControl1T = CUBIC_CONTROL_DEFAULTS.control1T;
            style.diagramCubicControl1N = 0;
            style.diagramCubicControl2T = CUBIC_CONTROL_DEFAULTS.control2T;
            style.diagramCubicControl2N = 0;
            graph.getDataModel().setStyle(edge, style);
          }
          if (geometry) {
            geometry.points = null;
            graph.getDataModel().setGeometry(edge, geometry);
          }
        }
      });
      setStatus(`已清除 ${edges.length} 条连线的控制点。`);
    });
  }, [withGraph]);

  const runLayout = useCallback((orientation: "north" | "east") => {
    withGraph((graph) => {
      const pageVertices = graph.getChildVertices(graph.getDefaultParent());
      if (pageVertices.some(isDiagramCellLocked)) {
        setStatus("当前页面包含锁定节点，请先解锁后再自动布局。");
        return;
      }
      if (pageVertices.length < 2) {
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
      const cells = graph.getMovableCells(graph.getSelectionCells()).filter((cell) => cell.isVertex());
      if (cells.length < 2) {
        setStatus("至少选择两个节点才能对齐。");
        return;
      }
      graph.alignCells(align, cells);
      setStatus(`已对齐 ${cells.length} 个节点。`);
    });
  }, [withGraph]);

  const orderSelection = useCallback((back: boolean) => {
    withGraph((graph) => {
      const selected = graph.getSelectionCells();
      const cells = graph.getMovableCells(selected);
      if (cells.length === 0) {
        setStatus("选中元素已锁定，请先解锁后再调整层级。");
        return;
      }
      graph.orderCells(back, cells);
      const skipped = selected.length - cells.length;
      setStatus(skipped > 0
        ? `已调整 ${cells.length} 个元素的层级，跳过 ${skipped} 个锁定元素。`
        : (back ? "已置于底层。" : "已置于顶层。"));
    });
  }, [withGraph]);

  const updateSelectedStyle = useCallback((key: DiagramEditableStyleKey, value: string | boolean | number) => {
    withGraph((graph) => {
      const cells = editableSelectionCells(graph);
      if (cells.length === 0) {
        setStatus("选中元素已锁定，请先解锁后再修改属性。");
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
      const cells = editableSelectionCells(graph).filter((cell) => copied && cell.isVertex() === copied.vertex);
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
      const cells = editableSelectionCells(graph);
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
      const cells = editableSelectionCells(graph);
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
      const cells = editableSelectionCells(graph);
      const field = mask === 1 ? "bold" : mask === 2 ? "italic" : "underline";
      const forceOn = selection.mixedFields.includes(field);
      graph.batchUpdate(() => {
        cells.forEach((cell) => {
          const style = cell.getClonedStyle();
          const current = styleNumber(style.fontStyle, 0);
          style.fontStyle = forceOn ? current | mask : current ^ mask;
          graph.getDataModel().setStyle(cell, style);
        });
      });
      updateSelection(graph, setSelection);
    });
  }, [selection.mixedFields, withGraph]);

  const updateTextAlign = useCallback((align: "left" | "center" | "right") => {
    withGraph((graph) => {
      graph.setCellStyles("align", align, editableSelectionCells(graph));
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const updateTextFontFamily = useCallback((fontFamily: DiagramFontFamily) => {
    withGraph((graph) => {
      graph.setCellStyles("fontFamily", diagramFontFamilyCss(fontFamily), editableSelectionCells(graph));
      updateSelection(graph, setSelection);
    });
  }, [withGraph]);

  const updateNodeGeometry = useCallback((key: "x" | "y" | "width" | "height", value: number) => {
    withGraph((graph) => {
      const cell = graph.getSelectionCell();
      if (!cell?.isVertex() || graph.getSelectionCells().length !== 1 || isDiagramCellLocked(cell)) return;
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
      const cells = graph.getMovableCells(graph.getSelectionCells()).filter((cell) => cell.isVertex());
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
      const cells = graph.getMovableCells(graph.getSelectionCells()).filter((cell) => (
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
        || isDiagramCellLocked(pool)
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
      if (!lane || !pool || isDiagramCellLocked(lane) || (lane.getStyle() as DiagramCellStyle).diagramKind !== "lane") return;
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

  const removeLane = useCallback(async () => {
    const currentGraph = runtimeRef.current?.graph;
    const selectedLane = currentGraph?.getSelectionCell();
    const laneId = selectedLane?.getId();
    if (!currentGraph || !selectedLane || !laneId
      || isDiagramCellLocked(selectedLane)
      || (selectedLane.getStyle() as DiagramCellStyle).diagramKind !== "lane") return;
    const childCount = currentGraph.getChildVertices(selectedLane).length;
    if (!await requestConfirmation({
      title: "删除泳道",
      message: childCount > 0
        ? `该泳道包含 ${childCount} 个模块，删除泳道会同时删除这些模块。`
        : "当前泳道将从流程图中移除。",
      confirmLabel: "删除泳道",
      tone: "danger",
    })) return;
    withGraph((graph) => {
      const lane = graph.getDataModel().getCell(laneId);
      if (!lane || (lane.getStyle() as DiagramCellStyle).diagramKind !== "lane") return;
      const pool = lane.getParent();
      graph.batchUpdate(() => {
        graph.removeCells([lane], true);
        if (pool) layoutLaneCells(graph, pool);
      });
      updateSelection(graph, setSelection);
      setStatus("泳道已删除。");
    });
  }, [requestConfirmation, withGraph]);

  const commitSelectionLabel = useCallback((label: string) => {
    withGraph((graph) => {
      const cell = graph.getSelectionCell();
      if (!cell || graph.getSelectionCells().length !== 1 || !graph.isCellEditable(cell)) {
        return;
      }
      graph.getDataModel().setValue(cell, label.slice(0, 500));
      updateSelection(graph, setSelection);
      setStatus("元素文字已更新。");
    });
  }, [withGraph]);

  const clearDiagram = useCallback(async () => {
    const currentGraph = runtimeRef.current?.graph;
    const currentParent = currentGraph?.getDefaultParent();
    const currentCells = currentGraph && currentParent
      ? [...currentGraph.getChildEdges(currentParent), ...currentGraph.getChildVertices(currentParent)]
      : [];
    if (currentCells.length === 0 || !await requestConfirmation({
      title: "清空当前页面",
      message: "当前页面中的全部模块、连线和评论都会被清除。此操作可以撤销。",
      confirmLabel: "清空页面",
      tone: "danger",
    })) return;
    withGraph((graph) => {
      const parent = graph.getDefaultParent();
      const selectedCells = [...graph.getChildEdges(parent), ...graph.getChildVertices(parent)];
      const cells = graph.getDeletableCells(selectedCells);
      if (cells.length === 0) return;
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
      const skipped = selectedCells.length - cells.length;
      setStatus(skipped > 0
        ? `已清空可删除内容，保留 ${skipped} 个锁定元素。`
        : "流程图已清空，可使用撤销恢复。");
    });
  }, [activePageId, requestConfirmation, withGraph]);

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
      setStatus(error instanceof Error ? error.message : "SVG 导出失败", "error");
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
      setStatus(error instanceof Error ? error.message : "PNG 导出失败", "error");
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
      pdf.setProperties({ title: "specus 流程图", creator: "specus" });
      downloadDiagramBlob(pdf.output("blob"), diagramExportFileName(new Date(), ".pdf"));
      setStatus(`已导出包含 ${orderedPages.length} 个页面的 PDF。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "PDF 导出失败", "error");
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
        && !await requestConfirmation({
          title: "替换当前流程图",
          message: `导入“${file.name}”会替换当前流程图，并立即同步给房间内设备。`,
          confirmLabel: "导入并替换",
          tone: "danger",
        })) {
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
      cancelPendingGraphSync();
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
      if (!cloudDocumentRef.current) {
        setLocalDocumentName(file.name.replace(/\.[^.]+$/, "").trim() || file.name);
      }
      undoManagerRef.current?.clear();
      refreshUndoState();
      setStatus(`已导入 ${importedPages.length} 个页面、${imported.nodes.length} 个节点和 ${imported.edges.length} 条连线。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "流程图导入失败", "error");
    } finally {
      setIsImporting(false);
    }
  }, [cancelPendingGraphSync, edgeCount, isReadOnly, nodeCount, refreshUndoState, requestConfirmation]);

  const addComment = useCallback(async () => {
    if (isReadOnly) return;
    if ((commentsMapRef.current?.size ?? 0) >= MAX_DIAGRAM_COMMENTS) {
      setStatus(`流程图评论已达到 ${MAX_DIAGRAM_COMMENTS} 条上限。`);
      return;
    }
    const text = (await requestText({
      title: selection.count === 1 ? "评论选中元素" : "评论当前页面",
      message: selection.count === 1
        ? "评论会关联到选中的模块或连线，其他协作者可快速定位。"
        : "未选中单个元素，本条评论会关联到当前页面。",
      inputLabel: "评论内容",
      placeholder: "写下问题、建议或待确认事项",
      maxLength: 500,
      multiline: true,
      confirmLabel: "添加评论",
    }))?.trim();
    const map = commentsMapRef.current;
    const document = yDocRef.current;
    if (!text || !map || !document) return;
    const comment: DiagramComment = {
      id: createDiagramId(peerId, "comment"),
      pageId: activePageId,
      cellId: selection.count === 1 ? selection.ids[0] : undefined,
      author: peerId,
      text: text.slice(0, 500),
      createdAt: Date.now(),
      resolved: false,
    };
    document.transact(() => map.set(comment.id, comment), GRAPH_ORIGIN);
    setStatus(selection.count === 1 ? "已为选中元素添加评论。" : "已为当前页面添加评论。");
  }, [activePageId, isReadOnly, peerId, requestText, selection.count, selection.ids]);

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
    if (!pagesMapRef.current?.has(comment.pageId)) {
      setStatus("评论关联的页面已被删除，无法定位。");
      return;
    }
    if (comment.pageId !== activePageId) {
      flushGraphRef.current();
      setActivePageId(comment.pageId);
    }
    if (!comment.cellId) {
      setStatus("已定位到评论所在页面。", "success");
      return;
    }
    window.setTimeout(() => {
      const graph = runtimeRef.current?.graph;
      const cell = graph?.getDataModel().getCell(comment.cellId!);
      if (graph && cell) {
        graph.setSelectionCell(cell);
        graph.scrollCellToVisible(cell);
        setStatus("已定位到评论关联的元素。", "success");
      } else {
        setStatus("评论关联的元素已被删除，无法定位。");
      }
    }, comment.pageId === activePageId ? 0 : 60);
  }, [activePageId]);

  const replaceDiagramWithUpdate = useCallback((update: Uint8Array) => {
    const document = yDocRef.current;
    const nodes = nodesMapRef.current;
    const edges = edgesMapRef.current;
    const pageMap = pagesMapRef.current;
    const commentsMap = commentsMapRef.current;
    if (!document || !nodes || !edges || !pageMap || !commentsMap) {
      throw new Error("流程图尚未就绪");
    }
    cancelPendingGraphSync();
    const probe = new Y.Doc();
    try {
      Y.applyUpdate(probe, update);
      const nextNodes = Array.from(probe.getMap<DiagramNode>(NODES_MAP).values());
      const nextEdges = Array.from(probe.getMap<DiagramEdge>(EDGES_MAP).values());
      const nextPages = Array.from(probe.getMap<DiagramPage>(PAGES_MAP).values());
      const nextComments = Array.from(probe.getMap<DiagramComment>(COMMENTS_MAP).values()).filter(isDiagramComment);
      if (!isDiagramGraphState(nextNodes, nextEdges) || nextPages.length === 0 || !nextPages.every(isDiagramPage)) {
        throw new Error("流程图数据无效");
      }
      document.transact(() => {
        nodes.clear();
        edges.clear();
        pageMap.clear();
        commentsMap.clear();
        nextNodes.forEach((node) => nodes.set(node.id, cloneNode(node)));
        nextEdges.forEach((edge) => edges.set(edge.id, cloneEdge(edge)));
        nextPages.forEach((page) => pageMap.set(page.id, { ...page }));
        nextComments.forEach((comment) => commentsMap.set(comment.id, { ...comment }));
      }, IMPORT_ORIGIN);
      setActivePageId(nextPages[0].id);
      undoManagerRef.current?.clear();
    } finally {
      probe.destroy();
    }
  }, [cancelPendingGraphSync]);

  const createVersion = useCallback(async () => {
    if (isRoleReadOnly) return;
    const createdAt = Date.now();
    const name = (await requestText({
      title: "创建版本快照",
      message: "保存当前全部页面，之后可从版本列表恢复。",
      inputLabel: "版本名称",
      initialValue: `版本 ${versionsRef.current.length + 1}`,
      maxLength: 80,
      confirmLabel: "创建快照",
    }))?.trim();
    if (!name) return;
    flushGraphRef.current();
    const document = yDocRef.current;
    if (!document) return;
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
        versionsRef.current = writeSessionDiagramVersions(
          boardKey,
          [...versionsRef.current.slice(-(MAX_DIAGRAM_SESSION_VERSIONS - 1)), snapshot],
        );
        if (!versionsRef.current.some((version) => version.id === snapshot.id)) {
          throw new Error("版本快照超过浏览器会话存储配额，请删除内容或使用服务端版本。");
        }
      }
      setVersions(versionsRef.current);
      setStatus(`已创建版本“${snapshot.name}”。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "创建流程图版本失败", "error");
    } finally {
      setIsVersionLoading(false);
    }
  }, [boardKey, isRoleReadOnly, peerId, requestText, roomId, roomToken, usesServerVersions]);

  const restoreVersion = useCallback(async (snapshot: DiagramVersionSnapshot) => {
    if (isReadOnly || !await requestConfirmation({
      title: "恢复流程图版本",
      message: `恢复到“${snapshot.name}”会替换当前流程图中的全部页面。`,
      confirmLabel: "恢复版本",
      tone: "danger",
    })) return;
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
      replaceDiagramWithUpdate(update);
      setStatus(`已恢复版本“${snapshot.name}”。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "版本恢复失败", "error");
    } finally {
      setIsVersionLoading(false);
    }
  }, [isReadOnly, peerId, replaceDiagramWithUpdate, requestConfirmation, roomId, roomToken]);

  const deleteVersion = useCallback(async (snapshot: DiagramVersionSnapshot) => {
    if (roomRole !== "OWNER" || snapshot.serverId === undefined) return;
    if (!await requestConfirmation({
      title: "删除版本快照",
      message: `“${snapshot.name}”删除后无法恢复。`,
      confirmLabel: "删除版本",
      tone: "danger",
    })) return;
    setIsVersionLoading(true);
    try {
      await publicDeleteTransferDiagramVersion(roomId, snapshot.serverId, { roomToken, peerId });
      versionsRef.current = versionsRef.current.filter((version) => version.id !== snapshot.id);
      setVersions(versionsRef.current);
      setStatus(`已删除版本“${snapshot.name}”。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "删除流程图版本失败", "error");
    } finally {
      setIsVersionLoading(false);
    }
  }, [peerId, requestConfirmation, roomId, roomRole, roomToken]);

  const encodeCurrentCloudSnapshot = useCallback(() => {
    cancelPendingGraphSync();
    flushGraphRef.current();
    const document = yDocRef.current;
    if (!document) throw new Error("流程图尚未就绪");
    const update = encodeDiagramUpdate(Y.encodeStateAsUpdate(document));
    if (update.length > MAX_DIAGRAM_UPDATE_BASE64_LENGTH) {
      throw new Error("流程图超过 3 MB 云端保存限制，请导出后精简文档");
    }
    return update;
  }, [cancelPendingGraphSync]);

  useEffect(() => {
    if (!onEmbedApiChange) return;
    const resolveGraph = () => {
      const graph = runtimeRef.current?.graph;
      if (!graph) throw new Error("流程图尚未就绪");
      return graph;
    };
    const background = theme === "dark" ? "#15181f" : "#ffffff";
    onEmbedApiChange({
      getSnapshot: () => {
        flushGraphRef.current();
        const document = yDocRef.current;
        if (!document) throw new Error("流程图尚未就绪");
        return encodeDiagramUpdate(Y.encodeStateAsUpdate(document));
      },
      loadSnapshot: (encoded) => replaceDiagramWithUpdate(decodeDiagramUpdate(encoded)),
      exportSvg: () => renderGraphSvg(resolveGraph(), background),
      exportPng: () => svgToPng(renderGraphSvg(resolveGraph(), background), 2, background),
    });
    return () => onEmbedApiChange(null);
  }, [onEmbedApiChange, replaceDiagramWithUpdate, theme]);

  const refreshCloudDocuments = useCallback(async () => {
    if (!authed) return;
    setIsCloudBusy(true);
    try {
      setCloudDocuments(await adminApi.listDiagrams());
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "读取云端流程图失败", "error");
    } finally {
      setIsCloudBusy(false);
    }
  }, [authed]);

  useEffect(() => {
    if (cloudDialog === "documents" && authed) {
      void refreshCloudDocuments();
    }
  }, [authed, cloudDialog, refreshCloudDocuments]);

  const saveDiagramAsCloud = useCallback(async () => {
    if (!authed) {
      setCloudDialog("login");
      setStatus("登录后可将当前流程图保存到云端。");
      return;
    }
    const current = cloudDocumentRef.current;
    const name = (await requestText({
      title: current ? "另存为云端文件" : "保存到云端",
      message: "输入在账号文件列表中显示的名称。",
      inputLabel: "文件名称",
      initialValue: current ? `${current.name} 副本` : localDocumentName,
      maxLength: 120,
      confirmLabel: "保存",
    }))?.trim();
    if (!name) return;
    setIsCloudBusy(true);
    try {
      const update = encodeCurrentCloudSnapshot();
      const savedSequence = cloudChangeSequenceRef.current;
      const created = await adminApi.createDiagram({
        name: name.slice(0, 120),
        update,
      });
      const hasNewChanges = cloudChangeSequenceRef.current !== savedSequence;
      selectCloudDocument(created, hasNewChanges);
      setCloudDocuments((documents) => [created, ...documents.filter((item) => item.id !== created.id)]);
      setStatus(hasNewChanges
        ? `“${created.name}”已保存；保存期间的新修改尚未保存。`
        : `“${created.name}”已保存到云端。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "保存云端流程图失败", "error");
    } finally {
      setIsCloudBusy(false);
    }
  }, [authed, encodeCurrentCloudSnapshot, localDocumentName, requestText, selectCloudDocument]);

  const saveDiagramToCloud = useCallback(async () => {
    if (!authed) {
      setCloudDialog("login");
      setStatus("登录后可将当前流程图保存到云端。");
      return;
    }
    const current = cloudDocumentRef.current;
    if (!current) {
      await saveDiagramAsCloud();
      return;
    }
    setIsCloudBusy(true);
    try {
      const update = encodeCurrentCloudSnapshot();
      const savedSequence = cloudChangeSequenceRef.current;
      const saved = await adminApi.updateDiagram(current.id, {
        name: current.name,
        update,
        revision: current.revision,
      });
      const hasNewChanges = cloudChangeSequenceRef.current !== savedSequence;
      selectCloudDocument(saved, hasNewChanges);
      setCloudDocuments((documents) => [saved, ...documents.filter((item) => item.id !== saved.id)]);
      setStatus(hasNewChanges
        ? `“${saved.name}”已保存；保存期间的新修改尚未保存。`
        : `“${saved.name}”已保存。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "保存云端流程图失败", "error");
    } finally {
      setIsCloudBusy(false);
    }
  }, [authed, encodeCurrentCloudSnapshot, saveDiagramAsCloud, selectCloudDocument]);

  const renameDiagramDocument = useCallback(async () => {
    const current = cloudDocumentRef.current;
    const previousName = current?.name ?? localDocumentName;
    const name = (await requestText({
      title: "重命名流程图",
      message: current ? "新名称会与当前内容一起保存到云端。" : "名称会保留在当前编辑会话中，登录后可保存到云端。",
      inputLabel: "流程图名称",
      initialValue: previousName,
      maxLength: 120,
      confirmLabel: "保存名称",
    }))?.trim().slice(0, 120);
    if (!name || name === previousName) return;
    if (!current || !authed) {
      setLocalDocumentName(name);
      setStatus(`流程图已重命名为“${name}”。`);
      return;
    }
    setIsCloudBusy(true);
    try {
      const update = encodeCurrentCloudSnapshot();
      const savedSequence = cloudChangeSequenceRef.current;
      const saved = await adminApi.updateDiagram(current.id, {
        name,
        update,
        revision: current.revision,
      });
      const hasNewChanges = cloudChangeSequenceRef.current !== savedSequence;
      selectCloudDocument(saved, hasNewChanges);
      setCloudDocuments((documents) => [saved, ...documents.filter((item) => item.id !== saved.id)]);
      setStatus(`流程图已重命名为“${saved.name}”并保存。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "重命名流程图失败", "error");
    } finally {
      setIsCloudBusy(false);
    }
  }, [authed, encodeCurrentCloudSnapshot, localDocumentName, requestText, selectCloudDocument]);

  const openCloudDocument = useCallback(async (item: UserDiagramDocument) => {
    if (isReadOnly) {
      setStatus("请先切换到编辑模式再打开云端文件。");
      return;
    }
    if ((nodeCount > 0 || edgeCount > 0) && !await requestConfirmation({
      title: "打开云端文件",
      message: `打开“${item.name}”会替换当前画布中的全部页面。`,
      confirmLabel: "打开文件",
      tone: "danger",
    })) return;
    setIsCloudBusy(true);
    try {
      const detail = await adminApi.getDiagram(item.id);
      replaceDiagramWithUpdate(decodeDiagramUpdate(detail.update));
      selectCloudDocument(detail.document);
      setCloudDocuments((documents) => documents.map((document) => (
        document.id === detail.document.id ? detail.document : document
      )));
      setCloudDialog(null);
      setStatus(`已打开云端文件“${detail.document.name}”。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "打开云端流程图失败", "error");
    } finally {
      setIsCloudBusy(false);
    }
  }, [edgeCount, isReadOnly, nodeCount, replaceDiagramWithUpdate, requestConfirmation, selectCloudDocument]);

  const deleteCloudDocument = useCallback(async (item: UserDiagramDocument) => {
    if (!await requestConfirmation({
      title: "删除云端文件",
      message: `“${item.name}”删除后无法恢复。`,
      confirmLabel: "删除文件",
      tone: "danger",
    })) return;
    setIsCloudBusy(true);
    try {
      await adminApi.deleteDiagram(item.id);
      setCloudDocuments((documents) => documents.filter((document) => document.id !== item.id));
      if (cloudDocumentRef.current?.id === item.id) selectCloudDocument(null);
      setStatus(`已删除云端文件“${item.name}”。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "删除云端流程图失败", "error");
    } finally {
      setIsCloudBusy(false);
    }
  }, [requestConfirmation, selectCloudDocument]);

  const openCloudDocuments = useCallback(() => {
    setCloudDialog(authed ? "documents" : "login");
  }, [authed]);

  const logoutFromDiagram = useCallback(async () => {
    if (cloudDirty && !await requestConfirmation({
      title: "退出账号",
      message: "当前云端文件有尚未保存的修改。",
      confirmLabel: "退出账号",
      tone: "danger",
    })) return;
    logout();
    setStatus("已退出账号，当前画布仍可继续本地编辑。");
  }, [cloudDirty, logout, requestConfirmation]);

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
    } else if (!cell) {
      graph.clearSelection();
    }
    const menuWidth = 184;
    const menuHeight = 360;
    setContextMenu({
      x: Math.max(8, Math.min(event.clientX, window.innerWidth - menuWidth - 8)),
      y: Math.max(8, Math.min(event.clientY, window.innerHeight - menuHeight - 8)),
    });
  }, []);

  useEffect(() => {
    if (!contextMenu) return;
    const frame = window.requestAnimationFrame(() => {
      contextMenuRef.current?.querySelector<HTMLButtonElement>("button:not(:disabled)")?.focus();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [contextMenu]);

  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    const target = event.target as HTMLElement;
    if (target.closest("input, textarea, select, [contenteditable='true'], [role='dialog'], [role='menu']")) {
      return;
    }
    const graph = runtimeRef.current?.graph;
    if (!graph) {
      return;
    }
    // 内嵌模式下编辑器只是页面的一部分：焦点不在编辑器内时，不响应会改动内容或
    // 接管选区的快捷键，避免在页面其它位置操作时误删画布元素。
    const editorHasFocus = isFullViewport
      || (rootSectionRef.current?.contains(document.activeElement) ?? false);
    const modifier = event.metaKey || event.ctrlKey;
    const key = event.key.toLowerCase();
    const isScopedShortcut = event.key === "Delete" || event.key === "Backspace"
      || (modifier && ["a", "z", "y", "x", "v", "d", "c"].includes(key))
      || event.key === "Enter" || event.key === "F2"
      || event.key.startsWith("Arrow");
    if (isScopedShortcut && !editorHasFocus) {
      return;
    }
    if (event.key === "Escape") {
      if (showCollaborationPanel) setShowCollaborationPanel(false);
      else if (contextMenu) setContextMenu(null);
      else if (compactPanel) setCompactPanel(null);
      else if (graph.getSelectionCount() > 0) graph.clearSelection();
      else if (isExpanded && !standalone) setIsExpanded(false);
      else return;
      event.preventDefault();
      return;
    }
    if (modifier && (key === "=" || key === "+")) {
      event.preventDefault();
      graph.zoomIn();
      setViewEpoch((value) => value + 1);
      return;
    }
    if (modifier && key === "-") {
      event.preventDefault();
      graph.zoomOut();
      setViewEpoch((value) => value + 1);
      return;
    }
    if (modifier && key === "0") {
      event.preventDefault();
      graph.zoomActual();
      setViewEpoch((value) => value + 1);
      return;
    }
    if (event.shiftKey && event.code === "Digit1") {
      event.preventDefault();
      graph.getPlugin<FitPlugin>("fit")?.fitCenter({ margin: 28 });
      setViewEpoch((value) => value + 1);
      return;
    }
    if (modifier && key === "s") {
      event.preventDefault();
      void saveDiagramToCloud();
      return;
    }
    if (modifier && key === "c") {
      if (graph.getSelectionCount() === 0) return;
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
      performHistoryAction(event.shiftKey ? "redo" : "undo");
      return;
    }
    if (modifier && key === "y") {
      event.preventDefault();
      performHistoryAction("redo");
      return;
    }
    if (modifier && key === "x") {
      event.preventDefault();
      cutSelection();
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
      if (cell && graph.isCellEditable(cell)) {
        event.preventDefault();
        graph.startEditingAtCell(cell);
      }
      return;
    }
    if (event.key.startsWith("Arrow") && graph.getSelectionCells().length > 0) {
      event.preventDefault();
      const movable = graph.getMovableCells(graph.getSelectionCells());
      if (movable.length === 0) {
        setStatus("选中元素已锁定，请先解锁后再移动。");
        return;
      }
      const distance = event.shiftKey ? 10 : 1;
      const delta = event.key === "ArrowLeft" ? [-distance, 0]
        : event.key === "ArrowRight" ? [distance, 0]
          : event.key === "ArrowUp" ? [0, -distance]
            : [0, distance];
      graph.moveCells(movable, delta[0], delta[1]);
    }
  }, [compactPanel, contextMenu, copySelection, cutSelection, duplicateSelection, isExpanded, isReadOnly, pasteSelection, performHistoryAction, removeSelection, saveDiagramToCloud, showCollaborationPanel, standalone]);

  useEffect(() => {
    if (!isActive) return;
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown, isActive]);

  const remoteSelectionMarkers = useMemo(() => {
    const graph = runtimeRef.current?.graph;
    const container = graphContainerRef.current;
    if (!graph || !container) return [];
    const markers: RemoteSelectionMarker[] = [];
    for (const presence of Object.values(remotePresences)) {
      if (presence.pageId !== activePageId) continue;
      for (const cellId of presence.selectedIds.slice(0, 100)) {
        const cell = graph.getDataModel().getCell(cellId);
        const state = cell ? graph.getView().getState(cell) : null;
        if (!state) continue;
        markers.push({
          key: `${presence.peerId}:${cellId}`,
          peerId: presence.peerId,
          left: state.x - container.scrollLeft - 3,
          top: state.y - container.scrollTop - 3,
          width: Math.max(8, state.width) + 6,
          height: Math.max(8, state.height) + 6,
        });
      }
    }
    return markers;
  }, [activePageId, remotePresences, viewEpoch]);

  const selectionToolbarPosition = useMemo(() => {
    const graph = runtimeRef.current?.graph;
    const container = graphContainerRef.current;
    if (!graph || !container || selection.ids.length === 0) return null;
    const states = selection.ids
      .map((id) => graph.getDataModel().getCell(id))
      .map((cell) => cell ? graph.getView().getState(cell) : null)
      .filter((state): state is CellState => Boolean(state));
    if (states.length === 0) return null;
    const leftEdge = Math.min(...states.map((state) => state.x)) - container.scrollLeft;
    const rightEdge = Math.max(...states.map((state) => state.x + state.width)) - container.scrollLeft;
    const topEdge = Math.min(...states.map((state) => state.y)) - container.scrollTop;
    const bottomEdge = Math.max(...states.map((state) => state.y + state.height)) - container.scrollTop;
    const { width, height, gap, inset } = SELECTION_TOOLBAR_SIZE;
    const maxLeft = Math.max(inset, container.clientWidth - width - inset);
    const maxTop = Math.max(inset, container.clientHeight - height - inset);
    const centeredLeft = clampNumber((leftEdge + rightEdge - width) / 2, inset, maxLeft);
    const centeredTop = clampNumber((topEdge + bottomEdge - height) / 2, inset, maxTop);
    const isSingleVertex = states.length === 1 && states[0].cell.isVertex();

    if (isSingleVertex) {
      if (rightEdge + gap + width <= container.clientWidth - inset) {
        return { left: rightEdge + gap, top: centeredTop };
      }
      if (leftEdge - gap - width >= inset) {
        return { left: leftEdge - gap - width, top: centeredTop };
      }
      if (bottomEdge + gap + height <= container.clientHeight - inset) {
        return { left: centeredLeft, top: bottomEdge + gap };
      }
    }

    const aboveTop = topEdge - gap - height;
    if (aboveTop >= inset) return { left: centeredLeft, top: aboveTop };
    return { left: centeredLeft, top: clampNumber(bottomEdge + gap, inset, maxTop) };
  }, [selection.ids, viewEpoch]);

  const totalPeers = Math.max(1, peerCount + 1);
  const documentDisplayName = cloudDocument?.name ?? localDocumentName;
  const permissionStatusLabel = isRoleReadOnly ? "访客只读" : localReadOnly ? "只读预览" : "可编辑";
  const collaborationStatusLabel = isConnected ? `${totalPeers} 人已同步` : peerCount > 0 ? "协作中断" : "仅本地";
  const storageStatusLabel = !authed ? "临时文档" : !cloudDocument ? "尚未保存云端" : cloudDirty ? "云端未保存" : "云端已保存";
  const visibleCollaborators = Object.values(remotePresences).slice(0, 3);
  const usesCommandKey = /Mac|iPhone|iPad|iPod/i.test(navigator.platform || navigator.userAgent);
  const modifierLabel = usesCommandKey ? "⌘" : "Ctrl+";
  const undoShortcut = `${modifierLabel}Z`;
  const redoShortcut = usesCommandKey ? "⇧⌘Z" : "Ctrl+Shift+Z";
  const cloudMenuLabel = !authReady
    ? "账号"
    : !authed
      ? "登录保存"
      : cloudDocument
        ? `${cloudDocument.name.length > 12 ? `${cloudDocument.name.slice(0, 12)}…` : cloudDocument.name}${cloudDirty ? " · 未保存" : ""}`
        : `账号 · ${profile?.username ?? "已登录"}`;
  const selectedCountLabel = selection.count > 0 ? ` · 已选 ${selection.count}` : "";
  const selectionOnlyNodes = selection.isNode && !selection.isEdge;
  const selectionOnlyEdges = selection.isEdge && !selection.isNode;
  const isSingleNode = selectionOnlyNodes && selection.count === 1;
  const inspectorPreferenceScope = selectionOnlyEdges
    ? "edge"
    : selection.isSwimlane ? "swimlane" : selection.isLane ? "lane" : selection.count > 1 ? "multi-node" : "node";
  const activePageName = pages.find((page) => page.id === activePageId)?.name ?? "页面 1";
  const canvasBackground = "var(--diagram-apple-canvas)";
  const gridColor = theme === "dark" ? "rgba(255,255,255,.09)" : "rgba(29,29,31,.09)";
  const currentGraph = runtimeRef.current?.graph;
  const currentViewScale = currentGraph?.getView().scale ?? 1;
  const currentViewTranslate = currentGraph?.getView().translate ?? new Point();
  const currentContainer = graphContainerRef.current;
  const gridStep = Math.max(4, DIAGRAM_CANVAS.gridSize * currentViewScale);
  const gridOffsetX = currentViewTranslate.x * currentViewScale - (currentContainer?.scrollLeft ?? 0);
  const gridOffsetY = currentViewTranslate.y * currentViewScale - (currentContainer?.scrollTop ?? 0);
  const paletteSearchQuery = paletteQuery.trim().toLowerCase();
  const paletteVisibleBuiltInItems = NODE_PALETTE.filter((item) => {
    if (paletteSearchQuery) {
      return `${item.label} ${item.detail} ${item.category}`.toLowerCase().includes(paletteSearchQuery);
    }
    if (paletteView === "recent") return recentNodeKinds.includes(item.kind);
    if (paletteView === "favorites") return favoriteNodeKinds.includes(item.kind);
    if (paletteView === "common") return (
      (item.category === "通用图形" || item.category === "流程图")
      && NODE_PALETTE.filter((candidate) => candidate.category === "通用图形" || candidate.category === "流程图").indexOf(item) < 16
    );
    return true;
  }).sort((left, right) => {
    const order = paletteView === "recent" ? recentNodeKinds : paletteView === "favorites" ? favoriteNodeKinds : null;
    return order ? order.indexOf(left.kind) - order.indexOf(right.kind) : 0;
  });
  const builtInPaletteResultCount = paletteVisibleBuiltInItems.length;
  const libraryResultIsLimited = Boolean(paletteSearchQuery && stencilSearchResults.length === STENCIL_SEARCH_LIMIT);
  const libraryItemCount = paletteSearchQuery
    ? builtInPaletteResultCount + (stencilCatalog ? stencilSearchResults.length : 0)
    : builtInPaletteResultCount + (paletteView === "all" ? stencilCatalog?.shapeCount ?? 0 : 0);
  const libraryCountLabel = `${libraryItemCount}${libraryResultIsLimited ? "+" : ""}`;
  const librarySummaryLabel = paletteSearchQuery
    ? `${libraryCountLabel} 个匹配`
    : paletteView === "all"
      ? `${PALETTE_CATEGORIES.length + stencilCollections.length} 类 · ${libraryCountLabel} 个图形`
      : `${libraryCountLabel} 个图形`;
  const statusDotClass = statusTone === "error"
    ? "bg-[var(--diagram-apple-danger)]"
    : statusTone === "success"
      ? "bg-[var(--diagram-apple-success)]"
      : isConnected ? "bg-[var(--diagram-apple-success)]" : "bg-zinc-400";
  const toggleInspectorVisibility = () => {
    const nextVisible = !isInspectorVisible;
    setIsInspectorVisible(nextVisible);
    setInspectorPinned(nextVisible);
    setCompactPanel(nextVisible && !window.matchMedia("(min-width: 1024px)").matches ? "inspector" : null);
    if (nextVisible) setInspectorTab("design");
  };
  const beginPanelResize = (
    panel: "library" | "inspector",
    event: ReactPointerEvent<HTMLButtonElement>,
  ) => {
    if (!window.matchMedia("(min-width: 1024px)").matches) return;
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = panel === "library" ? libraryWidth : inspectorWidth;
    let latestWidth = startWidth;
    const move = (pointerEvent: PointerEvent) => {
      const delta = panel === "library" ? pointerEvent.clientX - startX : startX - pointerEvent.clientX;
      const min = panel === "library" ? 220 : 260;
      const max = panel === "library" ? 380 : 420;
      const next = clampNumber(startWidth + delta, min, max);
      latestWidth = next;
      if (panel === "library") setLibraryWidth(next);
      else setInspectorWidth(next);
    };
    const finish = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", finish);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      writeDiagramPanelWidth(`diagram-${panel}-width`, latestWidth);
    };
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", finish, { once: true });
  };

  const diagram = (
    <section
      ref={rootSectionRef}
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
            <div className="diagram-apple-intro-icon grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-zinc-950 text-white shadow-sm dark:bg-[var(--diagram-apple-blue)] dark:text-zinc-950">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" viewBox="0 0 24 24" aria-hidden="true">
                <rect x="3" y="4" width="6" height="5" rx="1" /><rect x="15" y="15" width="6" height="5" rx="1" /><path d="M9 6.5h4a3 3 0 0 1 3 3V15M12 12H8a3 3 0 0 0-3 3v1" />
              </svg>
            </div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2.5">
                <div>
                  <h2 className="text-sm font-semibold text-zinc-950 dark:text-white">专业流程图</h2>
                  <p className="mt-0.5 text-[11px] text-zinc-500 dark:text-zinc-400">{activePageName} · 实时协作工作区</p>
                </div>
                {onSwitchToWhiteboard ? (
                  <div className="diagram-apple-mode-switch flex rounded-lg border border-black/[0.07] bg-white/70 p-0.5 shadow-sm dark:border-white/[0.08] dark:bg-white/[0.04]">
                    <button
                      type="button"
                      className="diagram-apple-mode-option rounded-md px-2.5 py-1 text-[11px] font-medium text-zinc-500 transition hover:bg-black/[0.04] hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/[0.06] dark:hover:text-white"
                      onClick={switchToWhiteboard}
                    >
                      自由白板
                    </button>
                    <button type="button" className="diagram-apple-mode-option diagram-apple-mode-option-active rounded-md bg-zinc-950 px-2.5 py-1 text-[11px] font-semibold text-white shadow-sm dark:bg-[var(--diagram-apple-blue)] dark:text-zinc-950">
                      专业流程图
                    </button>
                  </div>
                ) : null}
                <span className="diagram-apple-pill inline-flex items-center gap-1.5 rounded-md border border-black/[0.06] bg-white/70 px-2 py-1 text-[11px] font-medium text-zinc-600 dark:border-white/[0.08] dark:bg-white/[0.04] dark:text-zinc-300">
                  <span className={`h-1.5 w-1.5 rounded-full ${isConnected ? "bg-[var(--diagram-apple-success)] shadow-[0_0_0_3px_var(--diagram-apple-success-soft)]" : "bg-zinc-400"}`} />
                  {isConnected ? "实时同步" : "本地编辑"}
                </span>
                <span className="hidden text-[11px] text-zinc-400 xl:inline">{totalPeers} 位协作者 · {nodeCount} 个节点 · {edgeCount} 条连线</span>
              </div>
            </div>
          </div>
          <button type="button" className="diagram-apple-primary-action inline-flex h-9 items-center gap-2 rounded-lg border border-black/[0.08] bg-white px-3 text-tiny font-semibold text-zinc-700 shadow-sm transition hover:-translate-y-px hover:border-[var(--diagram-apple-blue)] hover:text-[var(--diagram-apple-blue)] dark:border-white/[0.1] dark:bg-white/[0.05] dark:text-zinc-200" onClick={() => setIsExpanded(true)}>
            <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 2H2v4M10 2h4v4M6 14H2v-4M10 14h4v-4" /></svg>
            全屏编辑
          </button>
        </div>
      ) : null}

      <div className={isFullViewport
        ? "diagram-apple-shell absolute inset-0 flex min-h-0 flex-col overflow-hidden bg-[var(--diagram-apple-page)]"
        : "diagram-apple-shell mt-3 flex h-[clamp(320px,78dvh,680px)] min-h-0 min-w-0 flex-col overflow-hidden rounded-xl border border-[var(--diagram-apple-line-strong)] bg-[var(--diagram-apple-surface)] shadow-[0_24px_70px_-38px_rgba(15,23,42,0.55)]"}
      >
        <div className="diagram-apple-titlebar diagram-apple-topbar relative z-40 flex h-11 shrink-0 items-center gap-1 border-b border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface)] px-2 backdrop-blur-xl">
          <div className="flex min-w-0 flex-1 items-center gap-1.5">
            <a
              href="/"
              className="diagram-apple-icon-control grid h-8 w-8 shrink-0 place-items-center rounded-full text-zinc-500 transition hover:bg-black/[0.045] hover:text-zinc-950 focus-visible:outline-none dark:text-zinc-300 dark:hover:bg-white/[0.06] dark:hover:text-white"
              aria-label="返回控制台"
              title="返回控制台"
            >
              <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true">
                <path d="m9.5 3-5 5 5 5M5 8h7" />
              </svg>
            </a>
            <div className="diagram-apple-toolbar-brand flex h-8 min-w-0 flex-1 items-center gap-2 overflow-hidden">
              <span className="diagram-apple-toolbar-icon hidden h-6 w-6 shrink-0 place-items-center rounded-md bg-zinc-950 text-white dark:bg-[var(--diagram-apple-blue)] dark:text-zinc-950 sm:grid">
                <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.7" viewBox="0 0 16 16" aria-hidden="true"><rect x="1.5" y="2" width="4" height="3.5" rx=".7" /><rect x="10.5" y="10.5" width="4" height="3.5" rx=".7" /><path d="M5.5 3.7h2.2a2 2 0 0 1 2 2v4.8" /></svg>
              </span>
              <span className="min-w-0 flex-1">
                <button
                  type="button"
                  className="block w-full truncate text-left text-[11px] font-semibold leading-4 text-zinc-800 hover:text-[var(--diagram-apple-blue)] dark:text-zinc-100"
                  title="点击重命名流程图"
                  onClick={() => void renameDiagramDocument()}
                >
                  {documentDisplayName}
                </button>
                <span
                  className={`block truncate text-[11px] leading-4 ${cloudDirty ? "text-amber-600 dark:text-amber-300" : "text-zinc-400"}`}
                  title={`${storageStatusLabel} · ${collaborationStatusLabel} · ${permissionStatusLabel}`}
                >
                  <span className="sm:hidden">{storageStatusLabel} · {collaborationStatusLabel} · {permissionStatusLabel}</span>
                  <span className="hidden sm:inline">{storageStatusLabel}</span>
                </span>
              </span>
            </div>
          </div>
          <div className="diagram-apple-toolbar hidden h-full min-w-0 flex-1 flex-nowrap items-center gap-0.5 px-1 py-0 backdrop-blur-xl sm:flex sm:px-1.5" role="toolbar" aria-label="流程图操作">
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
          <DiagramToolbarButton
            label={interactionMode === "connect" ? "退出连线" : "连线"}
            active={interactionMode === "connect"}
            disabled={isReadOnly}
            onClick={toggleConnectionMode}
          />
          <span className="diagram-apple-separator mx-1 h-6 w-px shrink-0 bg-black/[0.07] dark:bg-white/[0.08]" />
          <DiagramToolbarMenu
            label={selection.count > 0 ? `编辑 · ${selection.count}` : "编辑"}
            items={[
              { key: "undo", label: "撤销", section: "历史", shortcut: undoShortcut, disabled: isReadOnly || !canUndo },
              { key: "redo", label: "重做", shortcut: redoShortcut, disabled: isReadOnly || !canRedo },
              { key: "copy", label: "复制", section: "剪贴板", shortcut: `${modifierLabel}C`, disabled: selection.count === 0 },
              { key: "cut", label: "剪切", shortcut: `${modifierLabel}X`, disabled: isReadOnly || selection.count === 0 || selection.lockedCount === selection.count },
              { key: "paste", label: "粘贴", shortcut: `${modifierLabel}V`, disabled: isReadOnly },
              { key: "duplicate", label: "创建副本", section: "元素", shortcut: `${modifierLabel}D`, disabled: isReadOnly || selection.count === 0 },
              { key: "copy-format", label: "复制格式", section: "样式", disabled: selection.count !== 1 },
              { key: "apply-format", label: "应用格式", disabled: isReadOnly || !hasCopiedFormat || selection.count === 0 },
              { key: "delete", label: "删除", section: "危险操作", shortcut: "Del", disabled: isReadOnly || selection.count === 0, danger: true },
            ]}
            onAction={(key) => {
              if (key === "undo") performHistoryAction("undo");
              else if (key === "redo") performHistoryAction("redo");
              else if (key === "copy") copySelection();
              else if (key === "cut") cutSelection();
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
              { key: "group", label: "组合", section: "结构", disabled: isReadOnly || selection.count < 2 },
              { key: "ungroup", label: "取消组合", disabled: isReadOnly || !selection.isNode },
              { key: "bring-front", label: "置于顶层", section: "层级", disabled: isReadOnly || selection.count === 0 },
              { key: "send-back", label: "置于底层", disabled: isReadOnly || selection.count === 0 },
              { key: "distribute-horizontal", label: "水平等距分布", section: "分布", disabled: isReadOnly || selection.count < 3 },
              { key: "distribute-vertical", label: "垂直等距分布", disabled: isReadOnly || selection.count < 3 },
              { key: "align-left", label: "左对齐", section: "对齐", disabled: isReadOnly || selection.count < 2 },
              { key: "align-center", label: "水平居中", disabled: isReadOnly || selection.count < 2 },
              { key: "align-right", label: "右对齐", disabled: isReadOnly || selection.count < 2 },
              { key: "align-top", label: "顶部对齐", disabled: isReadOnly || selection.count < 2 },
              { key: "align-middle", label: "垂直居中", disabled: isReadOnly || selection.count < 2 },
              { key: "align-bottom", label: "底部对齐", disabled: isReadOnly || selection.count < 2 },
              { key: "layout-north", label: "上到下", section: "自动布局", disabled: isReadOnly },
              { key: "layout-east", label: "左到右", disabled: isReadOnly },
            ]}
            onAction={(key) => {
              if (key === "group") groupSelection();
              else if (key === "ungroup") ungroupSelection();
              else if (key === "bring-front") orderSelection(false);
              else if (key === "send-back") orderSelection(true);
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
                setIsInspectorVisible(true);
                setCompactPanel("inspector");
                addComment();
              } else if (key === "version") {
                setInspectorTab("versions");
                setIsInspectorVisible(true);
                setCompactPanel("inspector");
                void createVersion();
              }
            }}
          />
          <DiagramToolbarMenu
            label="视图"
            items={[
              { key: "zoom-in", label: "放大", shortcut: `${modifierLabel}+` },
              { key: "zoom-out", label: "缩小", shortcut: `${modifierLabel}-` },
              { key: "fit", label: "适应画布", shortcut: "Shift+1" },
              { key: "actual", label: "实际大小 100%", shortcut: `${modifierLabel}0` },
              { key: "minimap", label: showMinimap ? "隐藏小地图" : "显示小地图" },
              { key: "grid-snap", label: "对齐到网格", selected: gridSnapEnabled },
              { key: "inspector", label: isInspectorVisible ? "隐藏设计属性" : "显示设计属性", selected: isInspectorVisible },
              { key: "theme-system", label: "主题：跟随系统", selected: !hasThemeOverride },
              { key: "theme-light", label: "主题：浅色模式", selected: hasThemeOverride && theme === "light" },
              { key: "theme-dark", label: "主题：深色模式", selected: hasThemeOverride && theme === "dark" },
            ]}
            onAction={(key) => {
              if (key === "zoom-in") withGraph((graph) => graph.zoomIn());
              else if (key === "zoom-out") withGraph((graph) => graph.zoomOut());
              else if (key === "fit") withGraph((graph) => graph.getPlugin<FitPlugin>("fit")?.fitCenter({ margin: 28 }));
              else if (key === "actual") withGraph((graph) => graph.zoomActual());
              else if (key === "minimap") {
                minimapManuallySetRef.current = true;
                setShowMinimap((value) => {
                  const next = !value;
                  writeDiagramBooleanPreference("diagram-minimap-visible", next);
                  return next;
                });
              }
              else if (key === "grid-snap") {
                setGridSnapEnabled((value) => {
                  const next = !value;
                  setStatus(next ? "已开启对齐到网格。" : "已关闭对齐到网格，可自由微调位置。", "info");
                  return next;
                });
              }
              else if (key === "inspector") toggleInspectorVisibility();
              else if (key === "theme-system") resetToSystem();
              else if (key === "theme-light") setTheme("light");
              else if (key === "theme-dark") setTheme("dark");
            }}
          />
          <DiagramToolbarMenu
            label="文件"
            items={[
              { key: "import", label: isImporting ? "导入中" : "导入文件", section: "导入", disabled: isReadOnly || isImporting },
              { key: "export-png", label: "快速导出 PNG", section: "导出", disabled: nodeCount === 0 && edgeCount === 0 },
              { key: "export-more", label: "更多导出格式…", disabled: nodeCount === 0 && edgeCount === 0 },
              { key: "clear", label: "清空当前流程图", section: "危险操作", disabled: isReadOnly || (nodeCount === 0 && edgeCount === 0), danger: true },
            ]}
            onAction={(key) => {
              if (key === "import") importInputRef.current?.click();
              else if (key === "export-png") void exportPng();
              else if (key === "export-more") setExportDialogOpen(true);
              else if (key === "clear") clearDiagram();
            }}
          />
          </div>
          <div className="flex shrink-0 items-center justify-end gap-0.5 sm:hidden" role="toolbar" aria-label="移动端流程图操作">
            <DiagramToolbarButton
              label={interactionMode === "connect" ? "选择" : "连线"}
              active={interactionMode === "connect"}
              disabled={isReadOnly}
              onClick={toggleConnectionMode}
            />
            <DiagramToolbarMenu
              label="更多"
              compact
              placement="bottom-end"
              items={[
                { key: "undo", label: "编辑 · 撤销", shortcut: undoShortcut, disabled: isReadOnly || !canUndo },
                { key: "redo", label: "编辑 · 重做", shortcut: redoShortcut, disabled: isReadOnly || !canRedo },
                { key: "fit", label: "视图 · 适应画布" },
                { key: "actual", label: "视图 · 实际大小" },
                { key: "inspector", label: "视图 · 设计属性" },
                ...(collaborationPanel ? [{ key: "room", label: "协作 · 房间与成员" }] : []),
                { key: "comment", label: "协作 · 添加评论", disabled: isReadOnly },
                { key: "import", label: "文件 · 导入", disabled: isReadOnly || isImporting },
                { key: "export-png", label: "文件 · 导出 PNG", disabled: nodeCount === 0 && edgeCount === 0 },
                { key: "export-svg", label: "文件 · 导出 SVG", disabled: nodeCount === 0 && edgeCount === 0 },
                { key: "help", label: "帮助 · 触控与连线" },
              ]}
              onAction={(key) => {
                if (key === "undo") performHistoryAction("undo");
                else if (key === "redo") performHistoryAction("redo");
                else if (key === "fit") withGraph((graph) => graph.getPlugin<FitPlugin>("fit")?.fitCenter({ margin: 20 }));
                else if (key === "actual") withGraph((graph) => graph.zoomActual());
                else if (key === "inspector") {
                  setIsInspectorVisible(true);
                  setCompactPanel("inspector");
                } else if (key === "room") setShowCollaborationPanel(true);
                else if (key === "comment") {
                  setInspectorTab("comments");
                  setIsInspectorVisible(true);
                  setCompactPanel("inspector");
                  addComment();
                } else if (key === "import") importInputRef.current?.click();
                else if (key === "export-png") void exportPng();
                else if (key === "export-svg") exportSvg();
                else if (key === "help") setShowMobileHelp(true);
              }}
            />
          </div>
          <div className="flex shrink-0 items-center gap-0.5">
            {collaborationPanel ? (
              <button
                type="button"
                className="mr-1 hidden h-8 items-center rounded-md px-1.5 hover:bg-black/[0.04] dark:hover:bg-white/[0.05] md:flex"
                aria-label={`打开协作面板，${collaborationStatusLabel}`}
                title={collaborationStatusLabel}
                onClick={() => setShowCollaborationPanel(true)}
              >
                <span className="flex -space-x-1.5">
                  <span className="grid h-6 w-6 place-items-center rounded-full border-2 border-[var(--diagram-apple-surface)] bg-zinc-700 text-[10px] font-semibold text-white">我</span>
                  {visibleCollaborators.map((presence) => {
                    const displayName = peerDisplayNames[presence.peerId]?.trim() || "协";
                    return (
                      <span key={presence.peerId} className="grid h-6 w-6 place-items-center rounded-full border-2 border-[var(--diagram-apple-surface)] text-[10px] font-semibold text-white" style={{ backgroundColor: diagramPresenceColors(presence.peerId).solid }} title={displayName}>
                        {displayName.slice(0, 1)}
                      </span>
                    );
                  })}
                </span>
                <span className="ml-1.5 text-[11px] text-zinc-500 dark:text-zinc-400">{totalPeers}</span>
              </button>
            ) : null}
            <div className="mr-1 hidden items-center gap-1.5 text-[11px] text-zinc-500 dark:text-zinc-400 xl:flex" aria-label="流程图状态">
              <span>{permissionStatusLabel}</span>
              <span aria-hidden>·</span>
              <span className={isConnected ? "text-emerald-600 dark:text-emerald-300" : undefined}>{collaborationStatusLabel}</span>
              <span aria-hidden>·</span>
              <span className={cloudDirty ? "text-amber-600 dark:text-amber-300" : undefined}>{storageStatusLabel}</span>
            </div>
            <span className="mx-0.5 h-6 w-px shrink-0 bg-black/[0.07] dark:bg-white/[0.08]" />
            {standalone ? <PublicToolsMenu active="diagram" className="diagram-apple-icon-control" /> : null}
            <DiagramToolbarMenu
              label={cloudMenuLabel}
              mobileLabel={authed ? "账号" : "登录"}
              compact
              placement="bottom-end"
              items={!authReady
                ? [{ key: "auth-loading", label: "正在读取账号", disabled: true }]
                : authed
                  ? [
                      { key: "cloud-save", label: cloudDocument ? "保存到云端" : "保存为云端文件", shortcut: `${modifierLabel}S`, disabled: isCloudBusy },
                      { key: "cloud-save-as", label: "另存为云端文件", disabled: isCloudBusy },
                      { key: "cloud-files", label: "我的云端文件", disabled: isCloudBusy },
                      { key: "logout", label: "退出账号", danger: true },
                    ]
                  : [{ key: "login", label: "登录账号" }]}
              onAction={(key) => {
                if (key === "login") setCloudDialog("login");
                else if (key === "cloud-save") void saveDiagramToCloud();
                else if (key === "cloud-save-as") void saveDiagramAsCloud();
                else if (key === "cloud-files") openCloudDocuments();
                else if (key === "logout") void logoutFromDiagram();
              }}
            />
          </div>
          <span className="diagram-apple-separator ml-1 hidden h-6 w-px shrink-0 bg-black/[0.07] dark:bg-white/[0.08] lg:block" />
          <button
            type="button"
            aria-label={isLibraryVisible ? "隐藏图形库" : "显示图形库"}
            aria-pressed={isLibraryVisible}
            title={isLibraryVisible ? "隐藏图形库" : "显示图形库"}
            className="diagram-apple-icon-control hidden shrink-0 place-items-center lg:grid"
            onClick={() => setIsLibraryVisible((visible) => !visible)}
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true"><rect x="1.75" y="2.25" width="12.5" height="11.5" rx="2" /><path d="M6 2.5v11M3.3 5h1.2M3.3 8h1.2M3.3 11h1.2" /></svg>
          </button>
          <button
            type="button"
            aria-label={isInspectorVisible ? "隐藏设计属性" : "显示设计属性"}
            aria-pressed={isInspectorVisible}
            title={isInspectorVisible ? "隐藏设计属性" : "显示设计属性"}
            className="diagram-apple-icon-control hidden shrink-0 place-items-center lg:grid"
            onClick={toggleInspectorVisibility}
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true">
              <rect x="1.75" y="2.25" width="12.5" height="11.5" rx="2" />
              <path d="M10 2.5v11M11.7 5h.8M11.7 8h.8M11.7 11h.8" />
            </svg>
          </button>
        </div>

        <div className="diagram-apple-mobile-panel flex h-11 shrink-0 items-center justify-between border-b border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface)] px-2 lg:hidden">
          <div className="diagram-apple-mobile-switch grid grid-cols-3 gap-1 rounded-lg bg-black/[0.035] p-1 dark:bg-white/[0.045]" role="toolbar" aria-label="移动端流程图面板">
            <CompactPanelButton label="图库" active={compactPanel === "library"} onClick={() => setCompactPanel((current) => current === "library" ? null : "library")}>
              <path d="M3 3h4v4H3zM9 3h4v4H9zM3 9h4v4H3zM9 9h4v4H9z" />
            </CompactPanelButton>
            <CompactPanelButton label="画布" active={compactPanel === null} onClick={() => setCompactPanel(null)}>
              <path d="M2.5 3.5h11v9h-11zM5 6h6M5 8.5h4" />
            </CompactPanelButton>
            <CompactPanelButton label="属性" active={compactPanel === "inspector"} onClick={() => {
              setIsInspectorVisible(true);
              setCompactPanel((current) => {
                if (current === "inspector") return null;
                setInspectorTab("design");
                return "inspector";
              });
            }}>
              <path d="M3 4h10M3 8h10M3 12h10M6 2.5v3M10 6.5v3M7 10.5v3" />
            </CompactPanelButton>
          </div>
          <span className="min-w-0 truncate pl-2 text-right text-[11px] text-zinc-500 dark:text-zinc-400">{nodeCount} 节点 · {edgeCount} 连线</span>
        </div>

        <div className={`diagram-apple-workspace relative grid min-h-0 flex-1 grid-cols-1 transition-[grid-template-columns] duration-200 ease-out motion-reduce:transition-none ${
          isLibraryVisible && isInspectorVisible
            ? "lg:grid-cols-[var(--diagram-library-width)_minmax(0,1fr)_var(--diagram-inspector-width)]"
            : isLibraryVisible
              ? "lg:grid-cols-[var(--diagram-library-width)_minmax(0,1fr)]"
              : isInspectorVisible
                ? "lg:grid-cols-[minmax(0,1fr)_var(--diagram-inspector-width)]"
                : "lg:grid-cols-[minmax(0,1fr)]"
        }`} style={{
          "--diagram-library-width": `${libraryWidth}px`,
          "--diagram-inspector-width": `${inspectorWidth}px`,
        } as CSSProperties}>
          {compactPanel ? (
            <button
              type="button"
              aria-label="关闭侧边面板"
              className="absolute inset-0 z-20 bg-zinc-950/35 backdrop-blur-[1px] lg:hidden"
              onClick={() => setCompactPanel(null)}
            />
          ) : null}
          <aside className={`diagram-apple-library ${compactPanel === "library" ? "block" : "hidden"} absolute inset-y-0 left-0 z-30 w-[min(86vw,260px)] max-w-full overflow-y-auto border-r border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface-soft)] p-3 shadow-2xl lg:relative lg:z-auto lg:w-auto lg:max-w-none lg:shadow-none ${isLibraryVisible ? "lg:block" : "lg:hidden"}`}>
            <button type="button" tabIndex={-1} aria-label="调整图形库宽度" className="absolute -right-1 top-0 z-20 hidden h-full w-2 cursor-col-resize touch-none lg:block" onPointerDown={(event) => beginPanelResize("library", event)} />
            <div className="flex items-center justify-between">
              <div>
                <div className="text-[11px] font-semibold text-zinc-800 dark:text-zinc-100">图形库</div>
                <div className="mt-0.5 text-[11px] text-zinc-400">拖拽或点击添加</div>
              </div>
              <span className="flex items-center gap-1.5">
                <span className="diagram-apple-count-badge">{libraryCountLabel}</span>
                <button type="button" className="grid h-11 w-11 place-items-center rounded-lg text-zinc-400 hover:bg-black/[0.05] hover:text-zinc-700 dark:hover:bg-white/[0.06] dark:hover:text-zinc-100 lg:hidden" aria-label="关闭图形库" onClick={() => setCompactPanel(null)}>
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
                className="diagram-apple-search h-9 w-full rounded-lg border border-black/[0.07] bg-white pl-8 pr-2.5 text-[11px] text-zinc-800 shadow-sm outline-none transition placeholder:text-zinc-400 focus:border-[var(--diagram-apple-blue)] focus:ring-2 focus:ring-[var(--diagram-apple-blue-soft)] dark:border-white/[0.08] dark:bg-white/[0.035] dark:text-zinc-100"
                onChange={(event) => setPaletteQuery(event.currentTarget.value)}
              />
            </label>
            {!paletteSearchQuery ? (
              <div className="mt-2 grid grid-cols-4 gap-1 rounded-md bg-black/[0.035] p-1 dark:bg-white/[0.045]" role="tablist" aria-label="图形库视图">
                {([
                  ["common", "常用"],
                  ["recent", "最近"],
                  ["favorites", "收藏"],
                  ["all", "全部"],
                ] as const).map(([view, label]) => (
                  <button
                    key={view}
                    type="button"
                    role="tab"
                    aria-selected={paletteView === view}
                    className={`min-h-11 rounded px-1 text-[11px] font-medium sm:min-h-8 ${paletteView === view ? "bg-white text-[var(--diagram-apple-blue)] shadow-sm dark:bg-white/[0.08]" : "text-zinc-500 dark:text-zinc-400"}`}
                    onClick={() => setPaletteView(view)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            ) : null}
            {!paletteSearchQuery && paletteView === "common" ? <div className="mt-4 block">
              <div className="text-[11px] font-semibold uppercase text-zinc-400">快速模板</div>
              <div className="mt-2 grid grid-cols-3 gap-1.5">
                {(Object.entries(DIAGRAM_TEMPLATES) as Array<[DiagramTemplateId, DiagramTemplateDefinition]>).map(([id, template]) => (
                  <button
                    key={id}
                    type="button"
                    disabled={isReadOnly}
                    className="diagram-apple-template-button group min-w-0 rounded-lg border border-[color-mix(in_srgb,var(--diagram-apple-blue)_20%,transparent)] bg-[var(--diagram-apple-blue-soft)] px-2 py-2 text-center transition hover:border-[var(--diagram-apple-blue)] disabled:cursor-not-allowed disabled:opacity-35"
                    onClick={() => {
                      setTemplatePreviewId(id);
                    }}
                  >
                    <DiagramTemplateThumbnail template={template} />
                    <span className="block text-[11px] font-semibold text-[var(--diagram-apple-blue)]">{template.shortName}</span>
                    <span className="mt-0.5 block truncate text-[11px] text-[var(--diagram-apple-muted)]">{template.detail}</span>
                  </button>
                ))}
              </div>
            </div> : null}
            <div className="mt-3 min-w-0 border-t border-black/[0.05] pt-3 dark:border-white/[0.06]">
              <div className="mb-2 flex items-center justify-between px-1">
                <span className="diagram-apple-section-label text-[11px]">
                  {paletteSearchQuery ? "搜索结果" : "完整图库"}
                </span>
                <span className="font-mono text-[11px] text-zinc-400">{librarySummaryLabel}</span>
              </div>
              {PALETTE_CATEGORIES.map((category) => {
                const items = paletteVisibleBuiltInItems.filter((item) => item.category === category);
                if (items.length === 0) return null;
                const isCategoryOpen = Boolean(paletteSearchQuery) || paletteView !== "all" || openPaletteCategories.has(category);
                return (
                  <div key={category} className="mt-1.5 block overflow-hidden rounded-lg border border-black/[0.06] bg-white/55 dark:border-white/[0.07] dark:bg-white/[0.02]">
                    <button
                      type="button"
                      className="diagram-apple-collapse-row flex min-h-11 w-full items-center justify-between px-2 text-left transition hover:bg-black/[0.035] dark:hover:bg-white/[0.04] sm:min-h-8"
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
                      <span className="font-mono text-[11px] text-zinc-400">{items.length}</span>
                    </button>
                    <div className={`border-t border-black/[0.05] p-1 dark:border-white/[0.06] ${isCategoryOpen ? "block" : "hidden"}`}>
                      <div className="grid grid-cols-3 gap-1">
                        {items.map((item) => {
                          const favorite = favoriteNodeKinds.includes(item.kind);
                          return (
                            <div key={item.kind} className="relative min-w-0">
                              <button
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
                                className="diagram-apple-palette-card group flex min-h-[76px] w-full min-w-0 flex-col items-center gap-1 rounded-md border border-black/[0.07] bg-white px-1 py-1.5 text-center shadow-[0_1px_1px_rgba(15,23,42,0.03)] transition hover:-translate-y-px hover:border-[var(--diagram-apple-blue)] hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--diagram-apple-blue)]/50 disabled:cursor-not-allowed disabled:opacity-35 dark:border-white/[0.08] dark:bg-white/[0.035] dark:hover:bg-[var(--diagram-apple-blue-soft)]"
                                onClick={() => {
                                  insertNode(item.kind);
                                  setCompactPanel(null);
                                }}
                              >
                                <DiagramNodeGlyph kind={item.kind} />
                                <span className="min-w-0 w-full">
                                  <span className="diagram-apple-palette-label block truncate text-[11px] font-semibold text-zinc-800 dark:text-zinc-100">{item.label}</span>
                                  <span className="diagram-apple-palette-detail block truncate text-[11px] text-zinc-400">{item.detail}</span>
                                </span>
                              </button>
                              <button
                                type="button"
                                className={`absolute right-1 top-1 z-[1] grid h-5 w-5 place-items-center rounded-[5px] transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--diagram-apple-blue)]/50 ${favorite ? "bg-white/90 text-amber-500 shadow-sm dark:bg-zinc-900/90" : "text-zinc-300 hover:bg-white/90 hover:text-amber-500 dark:text-zinc-600 dark:hover:bg-zinc-900/90"}`}
                                aria-label={favorite ? `取消收藏${item.label}` : `收藏${item.label}`}
                                aria-pressed={favorite}
                                title={favorite ? "取消收藏" : "收藏"}
                                onClick={() => toggleFavoriteNodeKind(item.kind)}
                              >
                                <Star className="h-3 w-3" fill={favorite ? "currentColor" : "none"} strokeWidth={1.8} aria-hidden="true" />
                              </button>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                );
              })}
              {!paletteSearchQuery && builtInPaletteResultCount === 0 && paletteView !== "all" ? (
                <div className="rounded-md border border-dashed border-black/10 p-4 text-center text-[11px] leading-5 text-zinc-400 dark:border-white/10">
                  {paletteView === "recent" ? "添加过的图形会出现在这里。" : "点击图形右上角的星标即可收藏。"}
                </div>
              ) : null}
              {paletteSearchQuery && stencilCatalog ? (
                <div className="diagram-apple-collection mt-1.5 overflow-hidden rounded-lg border border-black/[0.06] bg-white/55 dark:border-white/[0.07] dark:bg-white/[0.02]">
                  <div className="flex h-8 items-center justify-between px-2">
                    <span className="truncate text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">更多匹配</span>
                    <span className="font-mono text-[11px] text-zinc-400">{stencilSearchResults.length}{stencilSearchResults.length === STENCIL_SEARCH_LIMIT ? "+" : ""}</span>
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
                              className="diagram-apple-palette-card group flex min-h-[76px] min-w-0 flex-col items-center justify-center rounded-lg border border-black/[0.07] bg-white px-1 py-1.5 text-center transition hover:-translate-y-px hover:border-[var(--diagram-apple-blue)] hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--diagram-apple-blue)]/50 disabled:opacity-35 dark:border-white/[0.08] dark:bg-white/[0.035] dark:hover:bg-[var(--diagram-apple-blue-soft)]"
                              onClick={() => {
                                void insertStencilNode(library, shape);
                                setCompactPanel(null);
                              }}
                            >
                              <DrawioStencilGlyph stencilName={shape.shape} loaded={isLoaded} />
                              <span className="diagram-apple-palette-label mt-1 block w-full truncate text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">{shape.name}</span>
                              <span className="diagram-apple-palette-detail block w-full truncate text-[11px] text-zinc-400">{library.name}</span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  ) : null}
                </div>
              ) : null}
              {!paletteSearchQuery && paletteView === "all" && stencilCatalog ? (
                <>
                  {stencilCatalog.groups.map((group) => {
                    const collections = stencilCollections.filter((collection) => collection.group === group.id);
                    if (!collections.length) return null;
                    const isGroupOpen = openStencilGroups.has(group.id);
                    return (
                      <div key={group.id} className="diagram-apple-collection mt-1.5 overflow-hidden rounded-lg border border-black/[0.06] bg-white/60 dark:border-white/[0.07] dark:bg-white/[0.02]">
                        <button
                          type="button"
                          className="diagram-apple-collapse-row flex min-h-11 w-full items-center justify-between px-2 text-left transition hover:bg-black/[0.03] dark:hover:bg-white/[0.04] sm:min-h-8"
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
                          <span className="font-mono text-[11px] text-zinc-400">{collections.length}</span>
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
                                    className={`diagram-apple-collection-row flex min-h-11 w-full items-center justify-between rounded-md px-2 text-left transition sm:min-h-8 ${isActive ? "bg-[var(--diagram-apple-blue-soft)] text-[var(--diagram-apple-blue)]" : "text-zinc-600 hover:bg-black/[0.035] dark:text-zinc-300 dark:hover:bg-white/[0.04]"}`}
                                    onClick={() => openStencilCollection(collection)}
                                  >
                                    <span className="truncate text-[11px] font-medium">{collection.name}</span>
                                    <span className="ml-2 shrink-0 font-mono text-[11px] text-zinc-400">{loadingStencilCollection === collection.id ? "加载中" : collection.libraryCount > 1 ? `${collection.shapeCount} · ${collection.libraryCount}库` : collection.shapeCount}</span>
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
                                            className="diagram-apple-palette-card group flex min-h-[76px] min-w-0 flex-col items-center justify-center rounded-lg border border-black/[0.07] bg-white px-1 py-1.5 text-center transition hover:-translate-y-px hover:border-[var(--diagram-apple-blue)] hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--diagram-apple-blue)]/50 disabled:opacity-35 dark:border-white/[0.08] dark:bg-white/[0.035] dark:hover:bg-[var(--diagram-apple-blue-soft)]"
                                            onClick={() => {
                                              void insertStencilNode(library, shape);
                                              setCompactPanel(null);
                                            }}
                                          >
                                            <DrawioStencilGlyph stencilName={shape.shape} loaded={isLoaded} />
                                            <span className="diagram-apple-palette-label mt-1 block w-full truncate text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">{shape.name}</span>
                                            {collection.libraryCount > 1 ? <span className="diagram-apple-palette-detail block w-full truncate text-[11px] text-zinc-400">{library.name}</span> : null}
                                          </button>
                                        );
                                      })}
                                      {collection.shapeCount > stencilShapeLimit ? (
                                        <button type="button" className="col-span-3 rounded-md border border-dashed border-black/10 px-2 py-2 text-[11px] font-medium text-[var(--diagram-apple-blue)] hover:bg-[var(--diagram-apple-blue-soft)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--diagram-apple-blue)]/50 dark:border-white/10" onClick={() => setStencilShapeLimit((current) => current + STENCIL_PAGE_SIZE)}>
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
                <div className="mt-1.5 rounded-lg border border-dashed border-black/10 p-4 text-center text-[11px] text-zinc-400 dark:border-white/10">未找到匹配图形</div>
              ) : null}
            </div>
          </aside>

          <div
            className="diagram-apple-canvas-wrap relative min-h-0 overflow-hidden bg-[var(--diagram-apple-page)]"
            onPointerDown={() => {
              setContextMenu(null);
              graphContainerRef.current?.focus();
            }}
            onContextMenu={openContextMenu}
          >
            <div
              ref={graphContainerRef}
              data-view-epoch={viewEpoch}
              className="diagram-apple-canvas absolute inset-0 overflow-auto outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--diagram-apple-blue)]"
              tabIndex={0}
              role="application"
              aria-label="专业流程图画布"
              style={{
                backgroundColor: canvasBackground,
                backgroundImage: `radial-gradient(circle, ${gridColor} 1px, transparent 1px)`,
                backgroundPosition: `${gridOffsetX}px ${gridOffsetY}px`,
                backgroundSize: `${gridStep}px ${gridStep}px`,
              }}
            />
            {nodeCount === 0 && edgeCount === 0 && !isReadOnly ? (
              <div className="pointer-events-none absolute inset-0 z-10 grid place-items-center px-4">
                <div className="pointer-events-auto w-full max-w-sm rounded-lg border border-[var(--diagram-apple-line-strong)] bg-[var(--diagram-apple-surface)] p-4 text-center shadow-xl">
                  <h2 className="text-sm font-semibold text-zinc-950 dark:text-white">开始创建流程图</h2>
                  <p className="mt-1 text-[11px] leading-5 text-zinc-500 dark:text-zinc-400">从一个节点开始，使用示例模板，或导入已有文件。</p>
                  <div className="mt-3 grid grid-cols-3 gap-2">
                    <button type="button" className="min-h-11 rounded-md border border-[var(--diagram-apple-line)] px-2 text-[11px] font-semibold text-zinc-700 hover:border-[var(--diagram-apple-blue)] hover:text-[var(--diagram-apple-blue)] dark:text-zinc-200" onClick={() => insertNode("process")}>空白开始</button>
                    <button type="button" className="min-h-11 rounded-md bg-[var(--diagram-apple-blue)] px-2 text-[11px] font-semibold text-white dark:text-zinc-950" onClick={() => setTemplatePreviewId("approval")}>流程模板</button>
                    <button type="button" className="min-h-11 rounded-md border border-[var(--diagram-apple-line)] px-2 text-[11px] font-semibold text-zinc-700 hover:border-[var(--diagram-apple-blue)] hover:text-[var(--diagram-apple-blue)] dark:text-zinc-200" onClick={() => importInputRef.current?.click()}>导入文件</button>
                  </div>
                </div>
              </div>
            ) : null}
            {statusTone === "error" ? (
              <div
                className="absolute left-1/2 top-3 z-40 flex w-[min(92%,560px)] -translate-x-1/2 items-start gap-2 rounded-lg border border-[color-mix(in_srgb,var(--diagram-apple-danger)_28%,transparent)] bg-[var(--diagram-apple-surface)] px-3 py-2.5 text-[11px] leading-5 text-[var(--diagram-apple-danger)] shadow-lg"
                role="alert"
              >
                <span className="mt-1 h-2 w-2 shrink-0 rounded-full bg-[var(--diagram-apple-danger)]" aria-hidden="true" />
                <span className="min-w-0 flex-1">{status}</span>
                <button type="button" className="grid h-5 w-5 shrink-0 place-items-center rounded text-current hover:bg-[var(--diagram-apple-danger-soft)]" aria-label="关闭错误提示" onClick={() => setStatusTone("info")}>
                  <svg className="h-3 w-3" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8M12 4l-8 8" /></svg>
                </button>
              </div>
            ) : null}
            {remoteSelectionMarkers.map((marker) => {
              const colors = diagramPresenceColors(marker.peerId);
              return (
                <div
                  key={marker.key}
                  className="pointer-events-none absolute z-20 rounded-[5px] border-2"
                  style={{
                    left: marker.left,
                    top: marker.top,
                    width: marker.width,
                    height: marker.height,
                    borderColor: colors.solid,
                    backgroundColor: colors.soft,
                  }}
                  aria-hidden="true"
                />
              );
            })}
            {Object.values(remotePresences).filter((presence) => presence.pageId === activePageId && presence.cursor).map((presence) => {
              const graph = runtimeRef.current?.graph;
              const container = graphContainerRef.current;
              const scale = graph?.getView().scale ?? 1;
              const translate = graph?.getView().translate ?? new Point();
              const left = ((presence.cursor?.x ?? 0) + translate.x) * scale - (container?.scrollLeft ?? 0);
              const top = ((presence.cursor?.y ?? 0) + translate.y) * scale - (container?.scrollTop ?? 0);
              const colors = diagramPresenceColors(presence.peerId);
              const displayName = peerDisplayNames[presence.peerId]?.trim() || "协作者";
              return (
                <div key={presence.peerId} className="diagram-apple-remote-cursor pointer-events-none absolute z-30" style={{ left, top }}>
                  <span className="block h-3 w-3 rotate-45 border-l-2 border-t-2" style={{ borderColor: colors.solid }} />
                  <span className="ml-2 rounded px-1.5 py-0.5 text-[11px] font-semibold text-white shadow" style={{ backgroundColor: colors.solid }}>
                    {displayName}{presence.selectedIds.length > 0 ? ` · 已选 ${presence.selectedIds.length}` : ""}
                  </span>
                </div>
              );
            })}
            {selectionToolbarPosition && selection.count > 0 ? (
              <div
                className="absolute z-30 hidden h-9 w-44 items-center justify-center gap-1 rounded-md border border-[var(--diagram-apple-line-strong)] bg-[var(--diagram-apple-surface)] p-1 shadow-lg sm:flex"
                style={selectionToolbarPosition}
                role="toolbar"
                aria-label="选中元素快捷操作"
                onPointerDown={(event) => event.stopPropagation()}
              >
                <label
                  className={`relative grid h-7 w-9 place-items-center rounded ${selectionOnlyNodes && !isReadOnly ? "cursor-pointer hover:bg-[var(--diagram-apple-blue-soft)]" : "cursor-not-allowed opacity-35"}`}
                  title={selection.mixedFields.includes("fillColor") ? "填充颜色（混合）" : "填充颜色"}
                  aria-label={selection.mixedFields.includes("fillColor") ? "填充颜色（混合）" : "填充颜色"}
                  style={selection.mixedFields.includes("fillColor")
                    ? { background: "linear-gradient(135deg,#e4e4e7 25%,#fff 25% 50%,#e4e4e7 50% 75%,#fff 75%)", backgroundSize: "8px 8px" }
                    : undefined}
                >
                  <span
                    className="h-4 w-4 rounded border border-black/15 dark:border-white/20"
                    style={{ backgroundColor: selection.fillColor === "none" ? "transparent" : colorPickerValue(selection.fillColor, "#ffffff") }}
                    aria-hidden="true"
                  />
                  <input
                    type="color"
                    value={colorPickerValue(selection.fillColor, "#ffffff")}
                    disabled={!selectionOnlyNodes || isReadOnly}
                    className="absolute inset-0 h-full w-full cursor-pointer opacity-0 disabled:cursor-not-allowed"
                    onChange={(event) => updateSelectedStyle("fillColor", event.currentTarget.value)}
                  />
                </label>
                <button
                  type="button"
                  className={`grid h-7 w-9 place-items-center rounded transition ${interactionMode === "connect" ? "bg-[var(--diagram-apple-blue-soft)] text-[var(--diagram-apple-blue)]" : "text-zinc-500 hover:bg-black/[0.05] dark:text-zinc-300 dark:hover:bg-white/[0.06]"}`}
                  disabled={!selectionOnlyNodes || isReadOnly}
                  title={interactionMode === "connect" ? "退出连线模式" : "连接节点"}
                  aria-label={interactionMode === "connect" ? "退出连线模式" : "连接节点"}
                  aria-pressed={interactionMode === "connect"}
                  onClick={toggleConnectionMode}
                >
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" viewBox="0 0 16 16" aria-hidden="true"><circle cx="3" cy="8" r="1.5" /><circle cx="13" cy="8" r="1.5" /><path d="M4.5 8h7" /></svg>
                </button>
                <button
                  type="button"
                  className="grid h-7 w-9 place-items-center rounded text-zinc-500 transition hover:bg-black/[0.05] disabled:opacity-35 dark:text-zinc-300 dark:hover:bg-white/[0.06]"
                  disabled={isReadOnly}
                  title="创建副本"
                  aria-label="创建副本"
                  onClick={duplicateSelection}
                >
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinejoin="round" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true"><rect x="5" y="5" width="8" height="8" rx="1.5" /><path d="M3 10.5H2.5A1.5 1.5 0 0 1 1 9V2.5A1.5 1.5 0 0 1 2.5 1H9a1.5 1.5 0 0 1 1.5 1.5V3" /></svg>
                </button>
                <button
                  type="button"
                  className="grid h-7 w-9 place-items-center rounded text-zinc-500 transition hover:bg-black/[0.05] disabled:opacity-35 dark:text-zinc-300 dark:hover:bg-white/[0.06]"
                  disabled={!selectionOnlyNodes || isReadOnly}
                  title={selection.locked ? "解锁节点" : "锁定节点"}
                  aria-label={selection.locked ? "解锁节点" : "锁定节点"}
                  onClick={toggleNodeLock}
                >
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true"><rect x="3" y="7" width="10" height="7" rx="2" /><path d={selection.locked ? "M5.5 7V5a2.5 2.5 0 0 1 5 0v2" : "M10.5 7V5a2.5 2.5 0 0 0-5 0"} /></svg>
                </button>
              </div>
            ) : null}
            {showMinimap ? (
              <div className="diagram-apple-minimap absolute bottom-12 right-3 z-20 hidden h-28 w-40 overflow-hidden rounded-xl border border-[var(--diagram-apple-line-strong)] bg-[var(--diagram-apple-surface)] shadow-[0_12px_35px_-12px_rgba(15,23,42,0.4)] backdrop-blur-xl sm:block sm:h-32 sm:w-48">
                <div className="absolute inset-1.5 overflow-hidden rounded-lg">
                  <div ref={outlineContainerRef} className="h-full w-full" aria-label="流程图小地图" />
                </div>
              </div>
            ) : null}
            <div className="diagram-apple-canvas-hint pointer-events-none absolute bottom-3 left-3 hidden items-center gap-2 rounded-lg border border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface)] px-2.5 py-1.5 text-[11px] text-zinc-500 shadow-sm backdrop-blur-xl dark:text-zinc-400 sm:flex">
              <span className="grid h-4 w-4 place-items-center rounded bg-[var(--diagram-apple-blue-soft)] text-[11px] font-bold text-[var(--diagram-apple-blue)]">?</span>
              Ctrl+Shift 拖动画布 · Ctrl+滚轮缩放 · Shift 点击连线增删折点
            </div>
            {interactionMode === "connect" ? (
              <div className="pointer-events-none absolute left-1/2 top-3 z-20 -translate-x-1/2 rounded-md border border-[var(--diagram-apple-blue)]/30 bg-[var(--diagram-apple-surface)] px-3 py-1.5 text-[11px] font-semibold text-[var(--diagram-apple-blue)] shadow-sm">
                连线模式：从蓝色连接点拖到另一个连接点
              </div>
            ) : null}
            {showMobileHelp ? (
              <div className="absolute inset-x-3 bottom-3 z-30 rounded-lg border border-[var(--diagram-apple-line-strong)] bg-[var(--diagram-apple-surface)] p-3 text-[11px] leading-5 text-zinc-600 shadow-xl dark:text-zinc-300 sm:hidden">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-semibold text-zinc-900 dark:text-white">触控操作</div>
                    <div className="mt-1">单指拖动画布，双指缩放；用“图库”添加图形，切到“连线”后连接节点，选择模式下从空白区域拖动可框选。</div>
                  </div>
                  <button
                    type="button"
                    className="grid h-11 w-11 shrink-0 place-items-center rounded-md text-zinc-500 hover:bg-black/[0.05] dark:hover:bg-white/[0.06]"
                    aria-label="关闭触控帮助"
                    onClick={() => {
                      setShowMobileHelp(false);
                      sessionStorage.setItem("diagram-mobile-help-dismissed", "1");
                    }}
                  >
                    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8M12 4l-8 8" /></svg>
                  </button>
                </div>
              </div>
            ) : null}
            {contextMenu ? createPortal(
              <div
                ref={contextMenuRef}
                className="diagram-apple-context-menu fixed z-[160] max-h-[calc(100dvh-16px)] w-44 overflow-y-auto rounded-lg border border-black/10 bg-white p-1.5 text-tiny text-zinc-700 shadow-xl dark:border-white/10 dark:bg-zinc-900 dark:text-zinc-200"
                style={{ left: contextMenu.x, top: contextMenu.y }}
                role="menu"
                tabIndex={-1}
                onPointerDown={(event) => event.stopPropagation()}
                onKeyDown={(event) => {
                  if (event.key === "Escape") {
                    event.preventDefault();
                    setContextMenu(null);
                    graphContainerRef.current?.focus();
                  }
                }}
              >
                <ContextMenuAction label="编辑文字" disabled={isReadOnly || selection.count !== 1} onClick={() => {
                  withGraph((graph) => graph.startEditingAtCell(graph.getSelectionCell()));
                  setContextMenu(null);
                }} />
                <ContextMenuAction label="复制" disabled={selection.count === 0} onClick={() => { copySelection(); setContextMenu(null); }} />
                <ContextMenuAction label="剪切" disabled={isReadOnly || selection.count === 0 || selection.lockedCount === selection.count} onClick={() => { cutSelection(); setContextMenu(null); }} />
                <ContextMenuAction label="创建副本" disabled={isReadOnly || selection.count === 0} onClick={() => { duplicateSelection(); setContextMenu(null); }} />
                <ContextMenuAction label="组合" disabled={isReadOnly || selection.count < 2} onClick={() => { groupSelection(); setContextMenu(null); }} />
                <ContextMenuAction label="取消组合" disabled={isReadOnly || !selection.isNode} onClick={() => { ungroupSelection(); setContextMenu(null); }} />
                <ContextMenuAction label="置于顶层" disabled={isReadOnly || selection.count === 0} onClick={() => {
                  orderSelection(false);
                  setContextMenu(null);
                }} />
                <ContextMenuAction label="置于底层" disabled={isReadOnly || selection.count === 0} onClick={() => {
                  orderSelection(true);
                  setContextMenu(null);
                }} />
                <ContextMenuAction label="删除" danger disabled={isReadOnly || selection.count === 0} onClick={() => { removeSelection(); setContextMenu(null); }} />
              </div>,
              window.document.body,
            ) : null}
          </div>

          <aside className={`diagram-apple-inspector ${compactPanel === "inspector" ? "block" : "hidden"} absolute inset-x-0 bottom-0 z-30 w-full ${inspectorSheetExpanded ? "h-[85%]" : "h-[45%] min-h-[280px]"} overflow-y-auto rounded-t-xl border-t border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface-soft)] shadow-2xl transition-[height] ${isInspectorVisible ? "lg:relative lg:z-auto lg:block lg:h-auto lg:min-h-0 lg:w-auto lg:max-w-none lg:rounded-none lg:border-l lg:border-t-0 lg:shadow-none" : "lg:hidden"}`}>
            <button type="button" tabIndex={-1} aria-label="调整设计属性宽度" className="absolute -left-1 top-0 z-20 hidden h-full w-2 cursor-col-resize touch-none lg:block" onPointerDown={(event) => beginPanelResize("inspector", event)} />
            <div className="diagram-apple-inspector-header sticky top-0 z-10 flex h-12 items-center justify-between gap-2 border-b border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface-soft)] px-4 backdrop-blur-xl">
              <span>
                <span className="block text-[11px] font-semibold text-zinc-900 dark:text-zinc-100">
                  {inspectorTab === "design" ? "设计属性" : inspectorTab === "comments" ? "协作评论" : "版本历史"}
                </span>
                <span className="block text-[11px] text-zinc-500 dark:text-zinc-400">
                  {inspectorTab === "design" ? "样式、文字与几何" : inspectorTab === "comments" ? "页面与元素讨论" : "快照、恢复与回溯"}
                </span>
              </span>
              <span className="flex items-center gap-1.5">
                <button
                  type="button"
                  className="diagram-apple-icon-control grid h-11 w-11 place-items-center rounded-md text-zinc-400 hover:bg-black/[0.05] hover:text-zinc-700 dark:hover:bg-white/[0.06] dark:hover:text-zinc-100 lg:hidden"
                  aria-label={inspectorSheetExpanded ? "收起属性面板" : "展开属性面板"}
                  title={inspectorSheetExpanded ? "收起属性面板" : "展开属性面板"}
                  onClick={() => setInspectorSheetExpanded((expanded) => !expanded)}
                >
                  <svg className={`h-4 w-4 transition-transform ${inspectorSheetExpanded ? "rotate-180" : ""}`} fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m3 10 5-5 5 5" /></svg>
                </button>
                <span className="diagram-apple-count-badge">
                  {inspectorTab === "design"
                    ? (selection.count > 0 ? `${selection.count} 个元素` : "未选择")
                    : inspectorTab === "comments"
                      ? `${comments.filter((comment) => comment.pageId === activePageId).length} 条`
                      : `${versions.length} 个`}
                </span>
                <button
                  type="button"
                  className="diagram-apple-icon-control grid h-11 w-11 place-items-center rounded-md text-zinc-400 hover:bg-black/[0.05] hover:text-zinc-700 dark:hover:bg-white/[0.06] dark:hover:text-zinc-100 lg:h-8 lg:w-8"
                  aria-label="隐藏设计栏"
                  title="隐藏设计栏"
                  onClick={toggleInspectorVisibility}
                >
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8M12 4l-8 8" /></svg>
                </button>
              </span>
            </div>
            <div className="sticky top-12 z-10 grid h-10 grid-cols-3 border-b border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface-soft)] px-2 backdrop-blur-xl" role="tablist" aria-label="设计属性模块">
              <InspectorTabButton label="设计" active={inspectorTab === "design"} onClick={() => setInspectorTab("design")} />
              <InspectorTabButton label={`评论 ${comments.filter((comment) => comment.pageId === activePageId).length}`} active={inspectorTab === "comments"} onClick={() => setInspectorTab("comments")} />
              <InspectorTabButton label={`版本 ${versions.length}`} active={inspectorTab === "versions"} onClick={() => setInspectorTab("versions")} />
            </div>
            <div className="p-3.5">
            {inspectorTab === "design" ? <div>
            {selectionOnlyNodes && selection.count > 0 ? (
              <div className="mb-3 rounded-lg border border-black/[0.07] bg-white/70 px-2.5 py-1.5 dark:border-white/[0.08] dark:bg-white/[0.025]">
                <InspectorToggle
                  label={selection.mixedFields.includes("locked") ? "部分节点已锁定" : selection.locked ? "节点已锁定" : "锁定节点"}
                  checked={Boolean(selection.locked)}
                  mixed={selection.mixedFields.includes("locked")}
                  disabled={isReadOnly}
                  onChange={toggleNodeLock}
                />
                {selection.lockedCount > 0 ? (
                  <p className="pb-1 text-[11px] leading-4 text-zinc-500 dark:text-zinc-400">
                    已选 {selection.count} 个，其中 {selection.lockedCount} 个受保护；属性修改仅应用到 {selection.editableCount} 个未锁定元素。
                  </p>
                ) : null}
              </div>
            ) : null}
            <fieldset disabled={isReadOnly || (selection.count > 0 && selection.editableCount === 0)} className={isReadOnly || (selection.count > 0 && selection.editableCount === 0) ? "opacity-60" : undefined}>
            {selection.count === 0 ? (
              <div className="diagram-apple-empty-state rounded-xl border border-dashed border-black/[0.1] bg-white/60 px-4 py-6 text-center dark:border-white/[0.1] dark:bg-white/[0.025]">
                <div className="mx-auto grid h-9 w-9 place-items-center rounded-xl bg-zinc-100 text-zinc-400 dark:bg-white/[0.05]">
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true"><path d="m3 2 9 5-4 1.5L6.5 13z" /><path d="m9 9 3 4" /></svg>
                </div>
                <div className="mt-3 text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">选择画布元素</div>
                <div className="mt-1 text-[11px] leading-4 text-zinc-400">选中节点或连线后，在这里调整位置、尺寸、文字与外观。</div>
              </div>
            ) : (
              <div className="divide-y divide-black/[0.07] dark:divide-white/[0.08]">
                {selection.count === 1 ? (
                  <InspectorSection title="内容" preferenceScope={inspectorPreferenceScope}>
                    <InspectorTextArea
                      selectionKey={selection.ids[0] ?? ""}
                      value={selection.label}
                      onCommit={commitSelectionLabel}
                    />
                  </InspectorSection>
                ) : null}

                {isSingleNode ? (
                  <InspectorSection title="位置与尺寸" preferenceScope={inspectorPreferenceScope}>
                    <div className="grid grid-cols-2 gap-2">
                      <InspectorNumberField label="X" value={selection.x} min={-100000} max={100000} onCommit={(value) => updateNodeGeometry("x", value)} />
                      <InspectorNumberField label="Y" value={selection.y} min={-100000} max={100000} onCommit={(value) => updateNodeGeometry("y", value)} />
                      <InspectorNumberField label="宽度" value={selection.width} min={20} max={100000} onCommit={(value) => updateNodeGeometry("width", value)} />
                      <InspectorNumberField label="高度" value={selection.height} min={20} max={100000} onCommit={(value) => updateNodeGeometry("height", value)} />
                    </div>
                  </InspectorSection>
                ) : null}

                {selectionOnlyNodes ? (
                  <InspectorSection title="变换" preferenceScope={inspectorPreferenceScope}>
                    <InspectorNumberField label="旋转角度" value={selection.rotation} mixed={selection.mixedFields.includes("rotation")} min={0} max={359} suffix="°" onCommit={updateNodeRotation} />
                    <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2">
                      <InspectorToggle label="水平翻转" checked={Boolean(selection.flipH)} mixed={selection.mixedFields.includes("flipH")} onChange={() => updateSelectedStyle("flipH", !selection.flipH)} />
                      <InspectorToggle label="垂直翻转" checked={Boolean(selection.flipV)} mixed={selection.mixedFields.includes("flipV")} onChange={() => updateSelectedStyle("flipV", !selection.flipV)} />
                    </div>
                  </InspectorSection>
                ) : null}

                <InspectorSection title="外观" preferenceScope={inspectorPreferenceScope}>
                  <div className="space-y-2.5">
                    {selectionOnlyNodes ? (
                      <InspectorColorField label="填充颜色" value={selection.fillColor} mixed={selection.mixedFields.includes("fillColor")} fallback="#ffffff" allowNone onCommit={(color) => updateSelectedStyle("fillColor", color)} />
                    ) : null}
                    <InspectorColorField label={selectionOnlyEdges ? "连线颜色" : "边框颜色"} value={selection.strokeColor} mixed={selection.mixedFields.includes("strokeColor")} fallback="#475569" allowNone onCommit={(color) => updateSelectedStyle("strokeColor", color)} />
                    <div className="grid grid-cols-2 gap-2">
                      <InspectorNumberField label="线宽" value={selection.strokeWidth} mixed={selection.mixedFields.includes("strokeWidth")} min={1} max={12} suffix="px" onCommit={(value) => updateSelectedStyle("strokeWidth", value)} />
                      <InspectorSelectField
                        label="线型"
                        value={selection.linePattern}
                        mixed={selection.mixedFields.includes("linePattern")}
                        options={[{ value: "solid", label: "实线" }, { value: "dashed", label: "虚线" }, { value: "dotted", label: "点线" }]}
                        onChange={updateLinePattern}
                      />
                    </div>
                    <InspectorRangeField label="整体透明度" value={selection.opacity ?? 100} mixed={selection.mixedFields.includes("opacity")} min={10} max={100} suffix="%" onChange={(value) => updateSelectedStyle("opacity", value)} />
                    {selectionOnlyNodes ? (
                      <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                        <InspectorToggle label="圆角" checked={Boolean(selection.rounded)} mixed={selection.mixedFields.includes("rounded")} onChange={() => updateSelectedStyle("rounded", !selection.rounded)} />
                        <InspectorToggle label="阴影" checked={Boolean(selection.shadow)} mixed={selection.mixedFields.includes("shadow")} onChange={() => updateSelectedStyle("shadow", !selection.shadow)} />
                      </div>
                    ) : null}
                  </div>
                </InspectorSection>

                <InspectorSection title="文字" preferenceScope={inspectorPreferenceScope}>
                  <div className="space-y-2.5">
                    <div className="grid grid-cols-[minmax(0,1fr)_92px] gap-2">
                      <InspectorSelectField label="字体" value={selection.fontFamily ?? "system"} mixed={selection.mixedFields.includes("fontFamily")} options={DIAGRAM_FONT_OPTIONS} onChange={updateTextFontFamily} />
                      <InspectorNumberField label="字号" value={selection.fontSize} mixed={selection.mixedFields.includes("fontSize")} min={8} max={96} suffix="px" onCommit={updateTextFontSize} />
                    </div>
                    <InspectorColorField label="文字颜色" value={selection.fontColor} mixed={selection.mixedFields.includes("fontColor")} fallback="#172033" onCommit={(color) => updateSelectedStyle("fontColor", color)} />
                    <InspectorColorField label="文字背景" value={selection.labelBackgroundColor} mixed={selection.mixedFields.includes("labelBackgroundColor")} fallback="#ffffff" allowNone onCommit={(color) => updateSelectedStyle("labelBackgroundColor", color)} />
                    <div>
                      <InspectorFieldLabel>字形</InspectorFieldLabel>
                      <div className="mt-1 grid grid-cols-3 overflow-hidden rounded-md border border-black/[0.09] dark:border-white/[0.1]" role="toolbar" aria-label="文字字形">
                        <InspectorTextStyleButton label="粗体" glyph="B" active={Boolean(selection.bold)} mixed={selection.mixedFields.includes("bold")} onClick={() => toggleTextFontStyle(1)} />
                        <InspectorTextStyleButton label="斜体" glyph="I" italic active={Boolean(selection.italic)} mixed={selection.mixedFields.includes("italic")} onClick={() => toggleTextFontStyle(2)} />
                        <InspectorTextStyleButton label="下划线" glyph="U" underline active={Boolean(selection.underline)} mixed={selection.mixedFields.includes("underline")} onClick={() => toggleTextFontStyle(4)} />
                      </div>
                    </div>
                    <InspectorSegmentedField
                      label="水平对齐"
                      value={selection.align ?? "center"}
                      mixed={selection.mixedFields.includes("align")}
                      options={[{ value: "left", label: "左" }, { value: "center", label: "中" }, { value: "right", label: "右" }]}
                      onChange={updateTextAlign}
                    />
                    {selectionOnlyNodes ? (
                      <>
                        <InspectorSegmentedField
                          label="垂直对齐"
                          value={selection.verticalAlign ?? "middle"}
                          mixed={selection.mixedFields.includes("verticalAlign")}
                          options={[{ value: "top", label: "上" }, { value: "middle", label: "中" }, { value: "bottom", label: "下" }]}
                          onChange={(value) => updateSelectedStyle("verticalAlign", value)}
                        />
                        <InspectorNumberField label="文字内边距" value={selection.spacing} mixed={selection.mixedFields.includes("spacing")} min={0} max={60} suffix="px" onCommit={(value) => updateSelectedStyle("spacing", value)} />
                      </>
                    ) : null}
                  </div>
                </InspectorSection>

                {selectionOnlyNodes && (selection.isSwimlane || selection.isLane) ? (
                  <InspectorSection title="泳道" preferenceScope={inspectorPreferenceScope}>
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
                  <InspectorSection title="连接线" preferenceScope={inspectorPreferenceScope}>
                    <div className="space-y-2.5">
                      <InspectorSelectField
                        label="路由方式"
                        value={selection.edgeType ?? "orthogonal"}
                        mixed={selection.mixedFields.includes("edgeType")}
                        options={[{ value: "orthogonal", label: "正交" }, { value: "straight", label: "直线" }, { value: "elbow", label: "折线" }, { value: "curved", label: "三阶贝塞尔" }]}
                        onChange={updateEdgeType}
                      />
                      <div className="grid grid-cols-2 gap-2">
                        <InspectorSelectField
                          label="起点箭头"
                          value={selection.startArrow ?? "none"}
                          mixed={selection.mixedFields.includes("startArrow")}
                          options={DIAGRAM_ARROW_OPTIONS}
                          onChange={(arrow) => updateArrowType("start", arrow)}
                        />
                        <InspectorSelectField
                          label="终点箭头"
                          value={selection.endArrow ?? "block"}
                          mixed={selection.mixedFields.includes("endArrow")}
                          options={DIAGRAM_ARROW_OPTIONS}
                          onChange={(arrow) => updateArrowType("end", arrow)}
                        />
                        <InspectorNumberField label="起点大小" value={selection.startSize} mixed={selection.mixedFields.includes("startSize")} min={4} max={40} suffix="px" onCommit={(value) => updateSelectedStyle("startSize", value)} />
                        <InspectorNumberField label="终点大小" value={selection.endSize} mixed={selection.mixedFields.includes("endSize")} min={4} max={40} suffix="px" onCommit={(value) => updateSelectedStyle("endSize", value)} />
                      </div>
                      <div className="grid grid-cols-2 gap-1.5 pt-1">
                        <InspectorAction label={selection.edgeType === "curved" ? "重置控制点" : "新增折点"} onClick={addEdgeWaypoint} />
                        <InspectorAction label={selection.edgeType === "curved" ? "拉直曲线" : "清除折点"} onClick={clearEdgeWaypoints} />
                      </div>
                    </div>
                  </InspectorSection>
                ) : null}
              </div>
            )}
            </fieldset>
            </div> : null}
            {inspectorTab === "comments" ? <div>
              <div className="flex justify-end">
                <button
                  type="button"
                  disabled={isReadOnly}
                  className="rounded-md px-2 py-1 text-[11px] font-semibold text-[var(--diagram-apple-blue)] hover:bg-[var(--diagram-apple-blue-soft)] disabled:opacity-35"
                  onClick={addComment}
                >
                  + 评论
                </button>
              </div>
              <div className="mt-2 space-y-2">
                {comments.filter((comment) => comment.pageId === activePageId).length === 0 ? (
                  <div className="rounded-md border border-dashed border-black/10 p-2 text-[11px] leading-4 text-zinc-400 dark:border-white/10">
                    选中元素后添加评论，可把讨论定位到具体节点或连线。
                  </div>
                ) : comments.filter((comment) => comment.pageId === activePageId).map((comment) => (
                  <div key={comment.id} className={`rounded-lg border p-2 ${comment.resolved
                    ? "border-black/5 bg-black/[0.02] opacity-60 dark:border-white/5 dark:bg-white/[0.02]"
                    : "border-amber-300/60 bg-amber-50/70 dark:border-amber-300/20 dark:bg-amber-300/[0.06]"}`}>
                    <button type="button" className="block w-full text-left" onClick={() => focusComment(comment)}>
                      <span className="block text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">
                        {comment.author === peerId ? "我" : peerDisplayNames[comment.author]?.trim() || "协作者"}{comment.cellId ? " · 已关联元素" : " · 页面评论"}
                      </span>
                      <span className="mt-1 block whitespace-pre-wrap break-words text-tiny leading-5 text-zinc-600 dark:text-zinc-300">{comment.text}</span>
                      <span className="mt-1 block text-[11px] text-zinc-500 dark:text-zinc-400">{formatDiagramTimestamp(comment.createdAt)}</span>
                    </button>
                    <div className="mt-1.5 flex gap-1">
                      <button type="button" disabled={isReadOnly} className="rounded px-1.5 py-1 text-[11px] text-[var(--diagram-apple-blue)] hover:bg-[var(--diagram-apple-blue-soft)] disabled:opacity-35" onClick={() => toggleComment(comment)}>
                        {comment.resolved ? "重新打开" : "标记解决"}
                      </button>
                      <button type="button" disabled={isReadOnly} className="rounded px-1.5 py-1 text-[11px] text-[var(--diagram-apple-danger)] hover:bg-[var(--diagram-apple-danger-soft)] disabled:opacity-35" onClick={() => deleteComment(comment.id)}>
                        删除
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div> : null}
            {inspectorTab === "versions" ? <div>
              <div className="flex justify-end">
                <button type="button" disabled={isRoleReadOnly || isVersionLoading} className="rounded-md px-2 py-1 text-[11px] font-semibold text-[var(--diagram-apple-blue)] hover:bg-[var(--diagram-apple-blue-soft)] disabled:opacity-35" onClick={() => void createVersion()}>+ 快照</button>
              </div>
              <p className="mt-1 text-[11px] leading-4 text-zinc-500 dark:text-zinc-400">{usesServerVersions ? "版本保存在房间服务端，最多保留 50 个。" : "版本快照保存在本次浏览器会话，最多保留 20 个。"}</p>
              <div className="mt-2 space-y-1.5">
                {versions.length === 0 ? (
                  <div className="rounded-md border border-dashed border-black/10 p-3 text-center text-[11px] leading-4 text-zinc-500 dark:border-white/10 dark:text-zinc-400">
                    暂无版本快照
                  </div>
                ) : versions.slice().reverse().map((version) => (
                  <div key={version.id} className="flex items-center justify-between gap-2 rounded-md border border-black/10 p-2 dark:border-white/10">
                    <span className="min-w-0">
                      <span className="block truncate text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">{version.name}</span>
                      <span className="block text-[11px] text-zinc-500 dark:text-zinc-400">{formatDiagramTimestamp(version.createdAt)}</span>
                    </span>
                    <span className="flex shrink-0 gap-1">
                      <button type="button" disabled={isReadOnly || isVersionLoading} className="rounded px-1.5 py-1 text-[11px] text-[var(--diagram-apple-blue)] hover:bg-[var(--diagram-apple-blue-soft)] disabled:opacity-35" onClick={() => void restoreVersion(version)}>恢复</button>
                      {roomRole === "OWNER" && version.serverId !== undefined ? (
                        <button type="button" disabled={isVersionLoading} className="rounded px-1.5 py-1 text-[11px] text-[var(--diagram-apple-danger)] hover:bg-[var(--diagram-apple-danger-soft)] disabled:opacity-35" onClick={() => void deleteVersion(version)}>删除</button>
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
              className="diagram-apple-collaboration relative z-10 flex h-full w-full max-w-[420px] flex-col border-l border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface-soft)] shadow-2xl sm:w-[min(92vw,420px)]"
            >
              <div className="diagram-apple-collaboration-header flex h-12 shrink-0 items-center justify-between border-b border-black/[0.07] px-3.5 dark:border-white/[0.08]">
                <div>
                  <h2 id="diagram-collaboration-title" className="text-sm font-semibold text-zinc-950 dark:text-white">房间与协作</h2>
                  <p className="text-[11px] text-zinc-500 dark:text-zinc-400">房间、邀请与在线成员</p>
                </div>
                <button
                  type="button"
                  className="diagram-apple-icon-control grid h-8 w-8 place-items-center text-zinc-500 transition"
                  aria-label="关闭房间与协作面板"
                  onClick={() => setShowCollaborationPanel(false)}
                >
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8M12 4l-8 8" /></svg>
                </button>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto px-3.5 py-3 overscroll-contain">
                {collaborationPanel}
              </div>
            </aside>
          </div>
        ) : null}

        <DiagramAccountDialog
          isOpen={cloudDialog === "login"}
          onClose={() => setCloudDialog(null)}
          onLoggedIn={() => {
            setCloudDialog(null);
            setStatus("已登录，现在可以保存到云端。");
          }}
        />

        <DiagramCloudDocumentsDialog
          isOpen={cloudDialog === "documents"}
          busy={isCloudBusy}
          currentId={cloudDocument?.id ?? null}
          documents={cloudDocuments}
          onClose={() => setCloudDialog(null)}
          onDelete={(item) => void deleteCloudDocument(item)}
          onOpen={(item) => void openCloudDocument(item)}
          onRefresh={() => void refreshCloudDocuments()}
          onSaveAs={() => {
            setCloudDialog(null);
            void saveDiagramAsCloud();
          }}
        />

        <Modal
          isOpen={templatePreviewId !== null}
          size="sm"
          backdrop="blur"
          onOpenChange={(open) => { if (!open) setTemplatePreviewId(null); }}
          classNames={{
            wrapper: "!z-[220] px-4 py-6",
            backdrop: "!z-[210] bg-zinc-950/40 backdrop-blur-[6px] dark:bg-black/65",
            base: "diagram-apple-dialog overflow-hidden rounded-2xl border shadow-2xl",
          }}
        >
          <ModalContent>
            {(onClose) => {
              const templateId = templatePreviewId ?? "approval";
              const template = DIAGRAM_TEMPLATES[templateId];
              return (
                <>
                  <ModalHeader>{template.name}</ModalHeader>
                  <ModalBody>
                    <div className="rounded-lg border border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-blue-soft)] p-4">
                      <DiagramTemplateThumbnail template={template} />
                    </div>
                    <p className="text-[12px] leading-5 text-zinc-500 dark:text-zinc-400">
                      {template.detail} · {template.nodes.length} 个节点，{template.edges.length} 条连线。插入当前页时会自动避开已有内容。
                    </p>
                  </ModalBody>
                  <ModalFooter className="flex-wrap">
                    <Button variant="light" radius="sm" onPress={onClose}>取消</Button>
                    <Button
                      variant="flat"
                      radius="sm"
                      isDisabled={pages.length >= MAX_DIAGRAM_PAGES}
                      onPress={() => {
                        const pageId = addPage();
                        if (!pageId) return;
                        setPendingTemplateInsertion({ templateId, pageId });
                        onClose();
                      }}
                    >
                      新页面插入
                    </Button>
                    <Button
                      color="primary"
                      radius="sm"
                      onPress={() => {
                        insertTemplate(templateId);
                        onClose();
                        setCompactPanel(null);
                      }}
                    >
                      插入当前页
                    </Button>
                  </ModalFooter>
                </>
              );
            }}
          </ModalContent>
        </Modal>

        <Modal
          isOpen={exportDialogOpen}
          size="md"
          backdrop="blur"
          onOpenChange={setExportDialogOpen}
          classNames={{
            wrapper: "!z-[220] px-4 py-6",
            backdrop: "!z-[210] bg-zinc-950/40 backdrop-blur-[6px] dark:bg-black/65",
            base: "diagram-apple-dialog overflow-hidden rounded-2xl border shadow-2xl",
          }}
        >
          <ModalContent>
            {(onClose) => (
              <>
                <ModalHeader>导出流程图</ModalHeader>
                <ModalBody>
                  <p className="text-[12px] leading-5 text-zinc-500 dark:text-zinc-400">选择适合后续编辑、演示或代码协作的格式。</p>
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                    {([
                      ["stdg", "specus", "保留完整编辑信息"],
                      ["drawio", "draw.io", "继续在 draw.io 编辑"],
                      ["svg", "SVG", "矢量图片"],
                      ["pdf", "PDF", "多页面分享"],
                      ["mermaid", "Mermaid", "文本图表"],
                      ["plantuml", "PlantUML", "代码化流程图"],
                      ["visio", "Visio VDX", "导入 Visio"],
                    ] as const).map(([format, label, detail]) => (
                      <button
                        key={format}
                        type="button"
                        className="min-h-16 rounded-md border border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface)] p-2.5 text-left transition hover:border-[var(--diagram-apple-blue)] hover:bg-[var(--diagram-apple-blue-soft)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--diagram-apple-blue)]"
                        onClick={() => {
                          if (format === "stdg") exportDiagram();
                          else if (format === "drawio") exportDrawio();
                          else if (format === "svg") exportSvg();
                          else if (format === "pdf") void exportPdf();
                          else if (format === "mermaid") exportMermaid();
                          else if (format === "plantuml") exportPlantUml();
                          else exportVisio();
                          onClose();
                        }}
                      >
                        <span className="block text-[12px] font-semibold text-zinc-900 dark:text-white">{label}</span>
                        <span className="mt-1 block text-[11px] leading-4 text-zinc-500 dark:text-zinc-400">{detail}</span>
                      </button>
                    ))}
                  </div>
                </ModalBody>
                <ModalFooter>
                  <Button variant="light" radius="sm" onPress={onClose}>取消</Button>
                </ModalFooter>
              </>
            )}
          </ModalContent>
        </Modal>

        {dialogRequest ? (
          <DiagramEditorDialog
            key={dialogRequest.id}
            request={dialogRequest}
            onResolve={resolveEditorDialog}
          />
        ) : null}

        <div className="diagram-apple-footer flex h-12 shrink-0 items-center gap-2 border-t border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface)] px-2 text-[11px] text-zinc-500 backdrop-blur-xl dark:text-zinc-400 sm:h-9">
          <div className="diagram-apple-pages diagram-apple-pages-bottom flex min-w-0 flex-[1_1_48%] items-center" aria-label="流程图页面">
            <span className="diagram-apple-section-label mr-1 hidden shrink-0 px-1 text-[11px] font-semibold text-zinc-500 sm:inline">页面</span>
            <div className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto [scrollbar-width:none]">
              {pages.map((page) => (
                <button
                  key={page.id}
                  type="button"
                  aria-pressed={page.id === activePageId}
                  className={`diagram-apple-page-tab relative h-11 max-w-44 shrink-0 truncate rounded-md border px-3 text-[11px] font-medium transition sm:h-7 ${page.id === activePageId
                    ? "border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface)] text-[var(--diagram-apple-ink)]"
                    : "border-transparent text-zinc-500 hover:bg-black/[0.035] hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/[0.04] dark:hover:text-zinc-100"}`}
                  title={page.name}
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
            <button
              type="button"
              disabled={isReadOnly || pages.length >= MAX_DIAGRAM_PAGES}
              className="ml-1 grid h-11 w-11 shrink-0 place-items-center rounded-md text-lg text-zinc-500 transition hover:bg-black/[0.045] hover:text-[var(--diagram-apple-blue)] disabled:opacity-35 dark:hover:bg-white/[0.06] sm:h-7 sm:w-7"
              aria-label="新增页面"
              title="新增页面"
              onClick={addPage}
            >
              +
            </button>
            <div className="ml-1 shrink-0 border-l border-black/[0.07] pl-1 dark:border-white/[0.08]">
              <DiagramToolbarMenu
                label={`${pages.length} 页`}
                compact
                placement="top-end"
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
          <span className="hidden h-5 w-px shrink-0 bg-black/[0.07] dark:bg-white/[0.08] md:block" />
          <span className={`diagram-apple-status flex min-w-0 flex-1 items-center gap-2 truncate text-[11px] ${statusTone === "error" ? "text-[var(--diagram-apple-danger)]" : statusTone === "success" ? "text-[var(--diagram-apple-success)]" : ""}`} aria-live="polite">
            <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${statusDotClass}`} />
            <span className="truncate" title={status}>{status}</span>
          </span>
          <span className="hidden shrink-0 items-center gap-3 font-mono lg:flex"><span>{activePageName}</span><span>{nodeCount} 节点</span><span>{edgeCount} 连线{selectedCountLabel}</span></span>
        </div>
      </div>
    </section>
  );

  return diagram;
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
    const sourceCell = cell.getTerminal(true);
    const targetCell = cell.getTerminal(false);
    const sourceId = sourceCell?.getId();
    const targetId = targetCell?.getId();
    if (!id || !sourceId || !targetId || !nodeIds.has(sourceId) || !nodeIds.has(targetId)) {
      return [];
    }
    const style = cell.getStyle() as DiagramCellStyle;
    const edgeType = edgeTypeFromCellStyle(style);
    const controlPoints = edgeType === "curved" && sourceCell && targetCell
      ? cubicControlPointsFromStyle(
        new Point(absoluteCellCenter(sourceCell).x, absoluteCellCenter(sourceCell).y),
        new Point(absoluteCellCenter(targetCell).x, absoluteCellCenter(targetCell).y),
        style,
      )
      : cell.getGeometry()?.points?.slice(0, 128) ?? [];
    return [{
      id,
      label: String(cell.getValue() ?? "").slice(0, 500),
      sourceId,
      targetId,
      sourcePort: portFromStyle(style, true),
      targetPort: portFromStyle(style, false),
      ...(controlPoints.length ? {
        waypoints: controlPoints.map((point) => ({ x: point.x, y: point.y })),
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
        edgeType,
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

function sessionDiagramVersionKey(boardKey: string) {
  return `${DIAGRAM_SESSION_VERSION_PREFIX}${encodeURIComponent(boardKey)}`;
}

function readSessionDiagramVersions(boardKey: string): DiagramVersionSnapshot[] {
  try {
    const raw = window.sessionStorage.getItem(sessionDiagramVersionKey(boardKey));
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const snapshots: DiagramVersionSnapshot[] = [];
    for (const item of parsed.slice(-MAX_DIAGRAM_SESSION_VERSIONS)) {
      if (!item || typeof item !== "object") continue;
      const candidate = item as Record<string, unknown>;
      if (typeof candidate.id !== "string"
        || typeof candidate.name !== "string"
        || typeof candidate.createdAt !== "number"
        || typeof candidate.update !== "string"
        || candidate.update.length > MAX_DIAGRAM_UPDATE_BASE64_LENGTH) continue;
      try {
        snapshots.push({
          id: candidate.id,
          name: candidate.name.slice(0, 80),
          createdAt: candidate.createdAt,
          update: decodeDiagramUpdate(candidate.update),
        });
      } catch {
        // Ignore one damaged session snapshot without losing the remaining history.
      }
    }
    return snapshots;
  } catch {
    return [];
  }
}

function writeSessionDiagramVersions(boardKey: string, snapshots: DiagramVersionSnapshot[]) {
  let candidates = snapshots
    .filter((snapshot): snapshot is DiagramVersionSnapshot & { update: Uint8Array } => Boolean(snapshot.update))
    .slice(-MAX_DIAGRAM_SESSION_VERSIONS);
  const key = sessionDiagramVersionKey(boardKey);
  while (candidates.length > 0) {
    const serialized = JSON.stringify(candidates.map((snapshot) => ({
      id: snapshot.id,
      name: snapshot.name,
      createdAt: snapshot.createdAt,
      update: encodeDiagramUpdate(snapshot.update),
    })));
    if (serialized.length * 2 <= MAX_DIAGRAM_SESSION_VERSION_STORAGE_BYTES) {
      try {
        window.sessionStorage.setItem(key, serialized);
        return candidates;
      } catch {
        // Browser quotas vary; remove the oldest snapshot and try the newest set again.
      }
    }
    candidates = candidates.slice(1);
  }
  try {
    window.sessionStorage.removeItem(key);
  } catch {
    // Session storage can be disabled by browser privacy settings.
  }
  return [];
}

function diagramPageFingerprints(
  nodes: Y.Map<DiagramNode> | null,
  edges: Y.Map<DiagramEdge> | null,
  pages: Y.Map<DiagramPage> | null,
  comments: Y.Map<DiagramComment> | null,
) {
  const pageIds = new Set<string>();
  pages?.forEach((page) => pageIds.add(page.id));
  nodes?.forEach((node) => pageIds.add(diagramPageId(node.pageId)));
  edges?.forEach((edge) => pageIds.add(diagramPageId(edge.pageId)));
  comments?.forEach((comment) => pageIds.add(comment.pageId));
  const fingerprints = new Map<string, string>();
  const sortedValues = <T extends { id: string }>(values: Iterable<T>) => (
    Array.from(values).sort((left, right) => left.id.localeCompare(right.id))
  );
  for (const pageId of pageIds) {
    fingerprints.set(pageId, JSON.stringify({
      page: pages?.get(pageId) ?? null,
      nodes: sortedValues(Array.from(nodes?.values() ?? []).filter((node) => diagramPageId(node.pageId) === pageId)),
      edges: sortedValues(Array.from(edges?.values() ?? []).filter((edge) => diagramPageId(edge.pageId) === pageId)),
      comments: sortedValues(Array.from(comments?.values() ?? []).filter((comment) => comment.pageId === pageId)),
    }));
  }
  return fingerprints;
}

function changedFingerprintKeys(before: Map<string, string>, after: Map<string, string>) {
  return Array.from(new Set([...before.keys(), ...after.keys()]))
    .filter((key) => before.get(key) !== after.get(key));
}

function diagramRecordsEqual<T>(left: T[], right: T[]) {
  return left.length === right.length
    && left.every((value, index) => JSON.stringify(value) === JSON.stringify(right[index]));
}

/**
 * 仅作兜底：从文案推断语气。调用点应显式传入 tone，尤其是错误路径——
 * 浏览器与第三方库抛出的 Error 常带英文 message（Failed to fetch 等），
 * 匹配不到中文关键词就会退化成中性色，让真实失败看起来像普通提示。
 *
 * 约束类引导语（"至少需要两个节点"等）刻意不归为 error：它们是正常操作反馈，
 * 用告警色会稀释真错误的信号价值。
 */
function inferDiagramStatusTone(message: string): DiagramStatusTone {
  if (/失败|错误|无效|中断|超过|无法|为空|不存在/.test(message)) return "error";
  if (/^(已|流程图已|同步已恢复|页面.+已|.+已创建)/.test(message)) return "success";
  return "info";
}

function diagramPresenceColors(peerId: string) {
  let hash = 0;
  for (let index = 0; index < peerId.length; index += 1) {
    hash = Math.imul(hash ^ peerId.charCodeAt(index), 16_777_619);
  }
  const hue = Math.abs(hash) % 360;
  return {
    solid: `hsl(${hue} 68% 43%)`,
    soft: `hsl(${hue} 76% 52% / 0.12)`,
  };
}

function findAvailableTemplatePlacement(
  occupied: Rectangle[],
  preferred: Rectangle,
  snap: (value: number) => number,
) {
  const overlaps = (candidate: Rectangle) => occupied.some((item) => (
    candidate.x < item.x + item.width + 24
    && candidate.x + candidate.width + 24 > item.x
    && candidate.y < item.y + item.height + 24
    && candidate.y + candidate.height + 24 > item.y
  ));
  if (!overlaps(preferred)) return { x: preferred.x, y: preferred.y, shifted: false };
  const stepX = Math.max(120, Math.min(320, preferred.width * 0.55));
  const stepY = Math.max(100, Math.min(240, preferred.height * 0.45));
  for (let radius = 1; radius <= 8; radius += 1) {
    for (let row = -radius; row <= radius; row += 1) {
      for (let column = -radius; column <= radius; column += 1) {
        if (Math.max(Math.abs(row), Math.abs(column)) !== radius) continue;
        const candidate = new Rectangle(
          Math.max(40, snap(preferred.x + column * stepX)),
          Math.max(40, snap(preferred.y + row * stepY)),
          preferred.width,
          preferred.height,
        );
        if (!overlaps(candidate)) return { x: candidate.x, y: candidate.y, shifted: true };
      }
    }
  }
  return { x: preferred.x, y: preferred.y, shifted: false };
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
  const selectedVertices = cells.filter((cell) => cell.isVertex());
  const selectedEdges = cells.filter((cell) => cell.isEdge());
  const lockedCount = selectedVertices.filter(isDiagramCellLocked).length;
  const mixedFields = new Set<keyof DiagramSelection>();
  const markMixed = (field: keyof DiagramSelection, candidates: Cell[], read: (cell: Cell) => unknown) => {
    if (candidates.length < 2) return;
    const value = read(candidates[0]);
    if (candidates.slice(1).some((cell) => !Object.is(read(cell), value))) mixedFields.add(field);
  };
  const cellStyle = (cell: Cell) => cell.getStyle() as DiagramCellStyle;
  const cellFontStyle = (cell: Cell) => styleNumber(cellStyle(cell).fontStyle, 0);

  markMixed("fillColor", selectedVertices, (cell) => styleColor(cellStyle(cell).fillColor, "#ffffff"));
  markMixed("strokeColor", cells, (cell) => styleColor(cellStyle(cell).strokeColor, "#475569"));
  markMixed("fontColor", cells, (cell) => styleColor(cellStyle(cell).fontColor, "#172033"));
  markMixed("labelBackgroundColor", cells, (cell) => styleColor(cellStyle(cell).labelBackgroundColor, "none"));
  markMixed("linePattern", cells, (cell) => linePatternFromStyle(cellStyle(cell)));
  markMixed("strokeWidth", cells, (cell) => styleNumber(cellStyle(cell).strokeWidth, 2));
  markMixed("fontSize", cells, (cell) => styleNumber(cellStyle(cell).fontSize, cell.isEdge() ? 12 : 13));
  markMixed("fontFamily", cells, (cell) => diagramFontFamilyFromStyle(cellStyle(cell).fontFamily));
  markMixed("bold", cells, (cell) => (cellFontStyle(cell) & 1) === 1);
  markMixed("italic", cells, (cell) => (cellFontStyle(cell) & 2) === 2);
  markMixed("underline", cells, (cell) => (cellFontStyle(cell) & 4) === 4);
  markMixed("align", cells, (cell) => textAlignFromStyle(cellStyle(cell).align));
  markMixed("verticalAlign", selectedVertices, (cell) => verticalAlignFromStyle(cellStyle(cell).verticalAlign));
  markMixed("spacing", selectedVertices, (cell) => styleNumber(cellStyle(cell).spacing, 10));
  markMixed("rotation", selectedVertices, (cell) => normalizeRotation(styleNumber(cellStyle(cell).rotation, 0)));
  markMixed("flipH", selectedVertices, (cell) => Boolean(cellStyle(cell).flipH));
  markMixed("flipV", selectedVertices, (cell) => Boolean(cellStyle(cell).flipV));
  markMixed("opacity", cells, (cell) => styleNumber(cellStyle(cell).opacity, 100));
  markMixed("shadow", selectedVertices, (cell) => Boolean(cellStyle(cell).shadow));
  markMixed("rounded", selectedVertices, (cell) => Boolean(cellStyle(cell).rounded));
  markMixed("edgeType", selectedEdges, (cell) => edgeTypeFromCellStyle(cellStyle(cell)));
  markMixed("startArrow", selectedEdges, (cell) => arrowTypeFromStyle(cellStyle(cell).startArrow, "none"));
  markMixed("endArrow", selectedEdges, (cell) => arrowTypeFromStyle(cellStyle(cell).endArrow, "block"));
  markMixed("startSize", selectedEdges, (cell) => styleNumber(cellStyle(cell).startSize, 8));
  markMixed("endSize", selectedEdges, (cell) => styleNumber(cellStyle(cell).endSize, 8));
  if (lockedCount > 0 && lockedCount < selectedVertices.length) mixedFields.add("locked");

  update({
    count: cells.length,
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
    locked: selectedVertices.length > 0 ? lockedCount === selectedVertices.length : undefined,
    lockedCount,
    editableCount: cells.length - lockedCount,
    mixedFields: Array.from(mixedFields),
    rotation: first.isVertex() ? normalizeRotation(styleNumber(style.rotation, 0)) : undefined,
    flipH: first.isVertex() ? Boolean(style.flipH) : undefined,
    flipV: first.isVertex() ? Boolean(style.flipV) : undefined,
    isSwimlane: selectedVertices.length > 0 && selectedVertices.every((cell) => cellStyle(cell).diagramKind === "swimlane"),
    isLane: selectedVertices.length > 0 && selectedVertices.every((cell) => cellStyle(cell).diagramKind === "lane"),
    swimlaneDirection: firstKind === "swimlane" ? (style.horizontal === false ? "vertical" : "horizontal") : undefined,
    opacity: styleNumber(style.opacity, 100),
    shadow: Boolean(style.shadow),
    rounded: Boolean(style.rounded),
  });
}

function isDiagramCellLocked(cell: Cell) {
  return cell.isVertex() && Boolean((cell.getStyle() as DiagramCellStyle).diagramLocked);
}

function editableSelectionCells(graph: Graph) {
  return graph.getSelectionCells().filter((cell) => !isDiagramCellLocked(cell));
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

function recreateSelectionHandlers(graph: Graph, cells: Cell[]) {
  const selectionCellsHandler = graph.getPlugin<SelectionCellsHandler>(SelectionCellsHandler.pluginId);
  if (!selectionCellsHandler) return;
  for (const cell of cells) {
    graph.getView().invalidate(cell);
  }
  graph.getView().validate();
  for (const cell of cells) {
    if (!graph.isCellSelected(cell)) continue;
    const state = graph.getView().getState(cell);
    if (state) selectionCellsHandler.updateHandler(state);
  }
}

function descendantVertices(graph: Graph, parent: Cell) {
  const descendants: Cell[] = [];
  const visit = (current: Cell) => {
    for (const child of graph.getChildVertices(current)) {
      descendants.push(child);
      visit(child);
    }
  };
  visit(parent);
  return descendants;
}

function cellStylesEqual(left: CellStyle, right: CellStyle) {
  const leftRecord = left as Record<string, unknown>;
  const rightRecord = right as Record<string, unknown>;
  const keys = new Set([...Object.keys(leftRecord), ...Object.keys(rightRecord)]);
  for (const key of keys) {
    if (leftRecord[key] !== rightRecord[key]) return false;
  }
  return true;
}

function diagramPointsEqual(left?: Point[] | null, right?: Point[] | null) {
  if (!left?.length && !right?.length) return true;
  if (!left || !right || left.length !== right.length) return false;
  return left.every((point, index) => point.x === right[index].x && point.y === right[index].y);
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
  return `specus-diagram-${timestamp}${extension}`;
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
          style: edgeCellStyle(edge, source, target),
        });
        const waypoints = edgeWaypointsForGraph(edge);
        if (waypoints?.length) {
          const geometry = edgeCell.getGeometry()?.clone();
          if (geometry) {
            geometry.points = waypoints;
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
  section?: string;
  shortcut?: string;
  disabled?: boolean;
  danger?: boolean;
  selected?: boolean;
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
      className={`diagram-apple-compact-button flex h-11 min-w-[64px] items-center justify-center gap-1.5 rounded-md px-2 text-[11px] font-semibold transition ${active
        ? "bg-white text-[var(--diagram-apple-blue)] shadow-sm dark:bg-[var(--diagram-apple-blue)] dark:text-zinc-950"
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
  mobileLabel,
  placement = "bottom-start",
  onAction,
}: {
  label: string;
  items: DiagramToolbarMenuItem[];
  compact?: boolean;
  mobileLabel?: string;
  placement?: "bottom-start" | "bottom-end" | "top-end";
  onAction: (key: string) => void;
}) {
  return (
    <Dropdown
      placement={placement}
      shouldBlockScroll={false}
      classNames={{
        content: "diagram-apple-context-menu min-w-48 rounded-lg border p-1.5 shadow-xl",
      }}
    >
      <DropdownTrigger>
        <button
          type="button"
          className={`diagram-apple-toolbar-menu flex h-11 shrink-0 items-center gap-1.5 rounded-md text-[11px] font-medium text-zinc-600 transition hover:bg-black/[0.045] hover:text-zinc-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--diagram-apple-blue)] dark:text-zinc-300 dark:hover:bg-white/[0.06] dark:hover:text-white sm:h-8 ${compact ? "px-2" : "px-2.5"}`}
          aria-label={`${label}菜单`}
        >
          <span className={mobileLabel ? "hidden sm:inline" : undefined}>{label}</span>
          {mobileLabel ? <span className="sm:hidden">{mobileLabel}</span> : null}
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
            className={`rounded-md px-2.5 py-2 text-[11px] data-[hover=true]:bg-[var(--diagram-apple-blue-soft)] data-[hover=true]:text-[var(--diagram-apple-blue)] ${item.danger ? "text-[var(--diagram-apple-danger)]" : "text-[var(--diagram-apple-ink)]"}`}
            endContent={item.selected ? (
              <svg className="h-3.5 w-3.5 text-primary" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 16 16" aria-hidden="true">
                <path d="m3 8 3 3 7-7" />
              </svg>
            ) : item.shortcut ? <span className="text-[11px] text-zinc-400">{item.shortcut}</span> : null}
          >
            <span className="min-w-0">
              {item.section ? <span className="mb-1 block text-[11px] font-semibold uppercase text-zinc-400">{item.section}</span> : null}
              <span className="block">{item.label}</span>
            </span>
          </DropdownItem>
        )}
      </DropdownMenu>
    </Dropdown>
  );
}

function DiagramToolbarButton({
  label,
  shortcut,
  active = false,
  danger = false,
  disabled = false,
  onClick,
}: {
  label: string;
  shortcut?: string;
  active?: boolean;
  danger?: boolean;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      title={shortcut ? `${label} (${shortcut})` : label}
      aria-pressed={active}
      className={`diagram-apple-toolbar-button flex h-11 shrink-0 items-center gap-1 rounded-md px-2.5 text-[11px] font-medium transition sm:h-8 disabled:cursor-not-allowed disabled:opacity-35 ${danger
        ? "text-[var(--diagram-apple-danger)] hover:bg-[var(--diagram-apple-danger-soft)]"
        : active
          ? "bg-[var(--diagram-apple-blue-soft)] text-[var(--diagram-apple-blue)]"
          : "text-zinc-600 hover:bg-black/[0.045] hover:text-zinc-950 dark:text-zinc-300 dark:hover:bg-white/[0.06] dark:hover:text-white"}`}
      onClick={onClick}
    >
      {label}
      {shortcut ? <span className="hidden text-[11px] text-zinc-400 xl:inline">{shortcut}</span> : null}
    </button>
  );
}

function DrawioStencilGlyph({ stencilName, loaded }: { stencilName: string; loaded: boolean }) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [rendered, setRendered] = useState(false);
  const { theme } = useTheme();
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg || !loaded) {
      setRendered(false);
      return;
    }
    // Resolve the shared diagram tokens so the stencil preview matches the built-in node glyphs
    // and stays legible in both themes (a fixed dark stroke disappeared on the dark panel).
    const tokens = getComputedStyle(svg);
    const stroke = tokens.getPropertyValue("--diagram-apple-blue").trim()
      || (theme === "dark" ? "#2997ff" : "#0066cc");
    const fill = tokens.getPropertyValue("--diagram-apple-glyph-fill").trim()
      || (theme === "dark" ? "#20364d" : "#e8f2ff");
    try {
      setRendered(renderDrawioStencilPreview(svg, stencilName, { stroke, fill }));
    } catch {
      svg.replaceChildren();
      setRendered(false);
    }
  }, [loaded, stencilName, theme]);
  return (
    <span className="diagram-apple-stencil-glyph relative flex h-8 w-12 shrink-0 items-center justify-center overflow-hidden rounded-md bg-slate-50 dark:bg-white/[0.04]">
      <svg ref={svgRef} className={`h-full w-full overflow-visible ${rendered ? "block" : "hidden"}`} aria-hidden="true" />
      {!rendered ? <span className="h-5 w-8 rounded border border-[var(--diagram-apple-blue)] bg-[var(--diagram-apple-blue-soft)]" /> : null}
    </span>
  );
}

function DiagramTemplateThumbnail({ template }: { template: DiagramTemplateDefinition }) {
  const width = Math.max(...template.nodes.map((node) => node.dx + node.width), 1);
  const height = Math.max(...template.nodes.map((node) => node.dy + node.height), 1);
  const nodeById = new Map(template.nodes.map((node) => [node.id, node]));
  return (
    <svg className="mx-auto mb-1.5 h-12 w-full text-[var(--diagram-apple-blue)]" viewBox={`-6 -6 ${width + 12} ${height + 12}`} aria-hidden="true">
      {template.edges.map((edge, index) => {
        const source = nodeById.get(edge.sourceId);
        const target = nodeById.get(edge.targetId);
        if (!source || !target) return null;
        return (
          <line
            key={`${edge.sourceId}-${edge.targetId}-${index}`}
            x1={source.dx + source.width / 2}
            y1={source.dy + source.height / 2}
            x2={target.dx + target.width / 2}
            y2={target.dy + target.height / 2}
            stroke="currentColor"
            strokeOpacity=".45"
            strokeWidth="4"
          />
        );
      })}
      {template.nodes.map((node) => {
        if (node.kind === "decision" || node.kind === "diamond") {
          const centerX = node.dx + node.width / 2;
          const centerY = node.dy + node.height / 2;
          return <rect key={node.id} x={centerX - node.width * 0.34} y={centerY - node.height * 0.34} width={node.width * 0.68} height={node.height * 0.68} rx="4" transform={`rotate(45 ${centerX} ${centerY})`} fill="currentColor" fillOpacity=".16" stroke="currentColor" strokeWidth="3" />;
        }
        if (node.kind === "start" || node.kind === "end" || node.kind === "ellipse" || node.kind === "circle") {
          return <ellipse key={node.id} cx={node.dx + node.width / 2} cy={node.dy + node.height / 2} rx={node.width / 2} ry={node.height / 2} fill="currentColor" fillOpacity=".16" stroke="currentColor" strokeWidth="3" />;
        }
        return <rect key={node.id} x={node.dx} y={node.dy} width={node.width} height={node.height} rx="9" fill="currentColor" fillOpacity=".16" stroke="currentColor" strokeWidth="3" />;
      })}
    </svg>
  );
}

function DiagramNodeGlyph({ kind }: { kind: DiagramNodeKind }) {
  if (kind === "text") {
    return <span className="diagram-apple-node-glyph flex h-8 w-11 shrink-0 items-center justify-center rounded-md bg-slate-50 text-sm font-semibold text-[var(--diagram-apple-blue)] transition group-hover:bg-[var(--diagram-apple-blue-soft)] dark:bg-white/[0.04]">T</span>;
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
    <span className="diagram-apple-node-glyph flex h-8 w-11 shrink-0 items-center justify-center text-[var(--diagram-apple-blue)] transition" aria-hidden="true">
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
      className={`relative min-h-11 text-[11px] font-semibold transition sm:min-h-8 ${active
        ? "text-[var(--diagram-apple-blue)] after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-[var(--diagram-apple-blue)]"
        : "text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100"}`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function InspectorSection({
  title,
  children,
  defaultOpen,
  preferenceScope = "default",
}: {
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
  preferenceScope?: string;
}) {
  const initiallyOpen = defaultOpen ?? (title === "内容" || title === "外观" || title === "连接线");
  const preferenceKey = `diagram-inspector-section:${preferenceScope}:${title}`;
  const [open, setOpen] = useState(() => readDiagramBooleanPreference(preferenceKey) ?? initiallyOpen);
  useEffect(() => {
    setOpen(readDiagramBooleanPreference(preferenceKey) ?? initiallyOpen);
  }, [initiallyOpen, preferenceKey]);
  return (
    <details
      className="group py-3 first:pt-0 last:pb-0"
      open={open}
      onToggle={(event) => {
        const next = event.currentTarget.open;
        setOpen(next);
        writeDiagramBooleanPreference(preferenceKey, next);
      }}
    >
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-2 rounded px-1 text-[11px] font-semibold text-zinc-600 outline-none hover:bg-black/[0.035] focus-visible:ring-2 focus-visible:ring-[var(--diagram-apple-blue)] dark:text-zinc-300 dark:hover:bg-white/[0.045] sm:min-h-8 [&::-webkit-details-marker]:hidden">
        <span className="diagram-apple-field-label">{title}</span>
        <svg className="h-3.5 w-3.5 transition-transform group-open:rotate-180" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4" /></svg>
      </summary>
      <div className="mt-2 px-1">{children}</div>
    </details>
  );
}

function InspectorFieldLabel({ children }: { children: ReactNode }) {
  return <span className="diagram-apple-field-label block text-[11px] font-medium text-zinc-500 dark:text-zinc-400">{children}</span>;
}

function InspectorTextArea({
  selectionKey,
  value,
  onCommit,
}: {
  selectionKey: string;
  value: string;
  onCommit: (value: string) => void;
}) {
  const [draft, setDraft] = useState(value);
  const editingRef = useRef(false);
  const selectionKeyRef = useRef(selectionKey);
  useEffect(() => {
    if (selectionKeyRef.current !== selectionKey) {
      selectionKeyRef.current = selectionKey;
      editingRef.current = false;
      setDraft(value);
    } else if (!editingRef.current) {
      setDraft(value);
    }
  }, [selectionKey, value]);
  return (
    <label className="block">
      <span className="sr-only">元素文字</span>
      <textarea
        value={draft}
        maxLength={500}
        rows={3}
        className="diagram-apple-text-field w-full resize-y rounded-md border border-black/10 bg-white px-2.5 py-2 text-[11px] leading-5 text-zinc-900 outline-none focus:border-[var(--diagram-apple-blue)] dark:border-white/10 dark:bg-zinc-950 dark:text-zinc-100"
        onFocus={() => { editingRef.current = true; }}
        onChange={(event) => setDraft(event.currentTarget.value)}
        onBlur={(event) => {
          editingRef.current = false;
          onCommit(event.currentTarget.value);
        }}
        onKeyDown={(event) => {
          if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) event.currentTarget.blur();
          if (event.key === "Escape") {
            setDraft(value);
            event.currentTarget.blur();
          }
        }}
      />
    </label>
  );
}

function InspectorNumberField({
  label,
  value,
  mixed = false,
  min,
  max,
  step = 1,
  suffix,
  onCommit,
}: {
  label: string;
  value?: number;
  mixed?: boolean;
  min: number;
  max: number;
  step?: number;
  suffix?: string;
  onCommit: (value: number) => void;
}) {
  const formattedValue = mixed || value === undefined ? "" : String(Math.round(value * 100) / 100);
  const [draft, setDraft] = useState(formattedValue);
  const editingRef = useRef(false);
  useEffect(() => {
    if (!editingRef.current) setDraft(formattedValue);
  }, [formattedValue]);
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
          placeholder={mixed ? "混合" : undefined}
          min={min}
          max={max}
          step={step}
          className="min-w-0 flex-1 bg-transparent px-2 text-[11px] text-zinc-800 outline-none dark:text-zinc-100"
          onFocus={(event) => {
            editingRef.current = true;
            event.currentTarget.select();
          }}
          onChange={(event) => setDraft(event.currentTarget.value)}
          onBlur={() => {
            editingRef.current = false;
            commit();
          }}
          onKeyDown={(event) => {
            if (event.key === "Enter") event.currentTarget.blur();
            if (event.key === "Escape") {
              setDraft(formattedValue);
              event.currentTarget.blur();
            }
          }}
        />
        {suffix ? <span className="pr-2 text-[11px] text-zinc-400">{suffix}</span> : null}
      </span>
    </label>
  );
}

function InspectorSelectField<T extends string>({
  label,
  value,
  mixed = false,
  options,
  onChange,
}: {
  label: string;
  value: T;
  mixed?: boolean;
  options: ReadonlyArray<{ value: T; label: string }>;
  onChange: (value: T) => void;
}) {
  return (
    <label className="block min-w-0">
      <InspectorFieldLabel>{label}</InspectorFieldLabel>
      <select
        value={mixed ? "" : value}
        className="mt-1 h-8 w-full rounded-md border border-black/[0.09] bg-white px-2 text-[11px] text-zinc-800 outline-none focus:border-[var(--diagram-apple-blue)] dark:border-white/[0.1] dark:bg-zinc-950 dark:text-zinc-100"
        onChange={(event) => onChange(event.currentTarget.value as T)}
      >
        {mixed ? <option value="" disabled>混合</option> : null}
        {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
      </select>
    </label>
  );
}

function InspectorColorField({
  label,
  value,
  mixed = false,
  fallback,
  allowNone = false,
  onCommit,
}: {
  label: string;
  value?: string;
  mixed?: boolean;
  fallback: string;
  allowNone?: boolean;
  onCommit: (value: string) => void;
}) {
  const displayValue = mixed ? "" : value === "none" ? "none" : colorPickerValue(value, fallback);
  const [draft, setDraft] = useState(displayValue);
  const editingRef = useRef(false);
  useEffect(() => {
    if (!editingRef.current) setDraft(displayValue);
  }, [displayValue]);
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
          style={mixed
            ? { background: "linear-gradient(135deg,#e4e4e7 25%,#fff 25% 50%,#e4e4e7 50% 75%,#fff 75%)", backgroundSize: "8px 8px" }
            : value === "none" ? { background: "linear-gradient(135deg,#fff 0 44%,#ef4444 45% 55%,#fff 56% 100%)" } : { backgroundColor: pickerValue }}
        >
          <input
            type="color"
            value={pickerValue}
            aria-label={`选择${label}`}
            className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
            onFocus={() => { editingRef.current = true; }}
            onBlur={() => { editingRef.current = false; }}
            onChange={(event) => {
              setDraft(event.currentTarget.value);
              onCommit(event.currentTarget.value);
            }}
          />
        </label>
        <input
          value={draft}
          placeholder={mixed ? "混合" : undefined}
          inputMode="text"
          aria-label={`${label}色值`}
          className="h-8 min-w-0 flex-1 rounded-md border border-black/[0.09] bg-white px-2 font-mono text-[11px] uppercase text-zinc-700 outline-none focus:border-[var(--diagram-apple-blue)] dark:border-white/[0.1] dark:bg-zinc-950 dark:text-zinc-200"
          onFocus={(event) => {
            editingRef.current = true;
            event.currentTarget.select();
          }}
          onChange={(event) => setDraft(event.currentTarget.value)}
          onBlur={() => {
            editingRef.current = false;
            commit();
          }}
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
            className={`h-8 shrink-0 rounded-md px-2 text-[11px] font-medium transition ${value === "none"
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
  mixed = false,
  min,
  max,
  suffix,
  onChange,
}: {
  label: string;
  value: number;
  mixed?: boolean;
  min: number;
  max: number;
  suffix?: string;
  onChange: (value: number) => void;
}) {
  return (
    <label className="block">
      <span className="flex items-center justify-between">
        <InspectorFieldLabel>{label}</InspectorFieldLabel>
        <span className="text-[11px] tabular-nums text-zinc-500 dark:text-zinc-400">{mixed ? "混合" : `${value}${suffix ?? ""}`}</span>
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

function InspectorToggle({
  label,
  checked,
  mixed = false,
  disabled = false,
  onChange,
}: {
  label: string;
  checked: boolean;
  mixed?: boolean;
  disabled?: boolean;
  onChange: () => void;
}) {
  return (
    <button type="button" role="switch" aria-checked={mixed ? "mixed" : checked} disabled={disabled} className="flex min-h-8 w-full items-center justify-between gap-2 text-left text-[11px] font-medium text-zinc-600 disabled:cursor-not-allowed disabled:opacity-45 dark:text-zinc-300" onClick={onChange}>
      <span>{label}</span>
      <span className={`relative h-5 w-9 shrink-0 rounded-full transition ${checked && !mixed ? "bg-[var(--diagram-apple-blue)]" : mixed ? "bg-zinc-400 dark:bg-zinc-600" : "bg-zinc-300 dark:bg-zinc-700"}`} aria-hidden>
        {mixed ? <span className="absolute left-2 top-[9px] h-0.5 w-5 rounded bg-white" /> : (
          <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow-sm transition-transform ${checked ? "translate-x-[18px] dark:bg-zinc-950" : "translate-x-0.5"}`} />
        )}
      </span>
    </button>
  );
}

function InspectorTextStyleButton({
  label,
  glyph,
  active,
  mixed = false,
  italic = false,
  underline = false,
  onClick,
}: {
  label: string;
  glyph: string;
  active: boolean;
  mixed?: boolean;
  italic?: boolean;
  underline?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      aria-pressed={mixed ? "mixed" : active}
      className={`h-8 border-r border-black/[0.08] text-[12px] transition last:border-r-0 dark:border-white/[0.08] ${mixed
        ? "bg-zinc-100 text-zinc-500 [background-image:linear-gradient(135deg,transparent_45%,rgba(113,113,122,.3)_46%,rgba(113,113,122,.3)_54%,transparent_55%)] dark:bg-zinc-900 dark:text-zinc-400"
        : active
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
  mixed = false,
  options,
  onChange,
}: {
  label: string;
  value: T;
  mixed?: boolean;
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
            aria-pressed={!mixed && value === option.value}
            className={`h-8 border-r border-black/[0.08] text-[11px] font-medium transition last:border-r-0 dark:border-white/[0.08] ${!mixed && value === option.value
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
      className={`diagram-apple-inspector-action rounded-lg border px-2 py-1.5 text-[11px] font-medium transition hover:border-[var(--diagram-apple-blue)] hover:text-[var(--diagram-apple-blue)] disabled:opacity-35 ${active
        ? "border-[var(--diagram-apple-blue)] bg-[var(--diagram-apple-blue-soft)] text-[var(--diagram-apple-blue)] shadow-sm"
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
        ? "text-[var(--diagram-apple-danger)] hover:bg-[var(--diagram-apple-danger-soft)]"
        : "hover:bg-[var(--diagram-apple-blue-soft)] hover:text-[var(--diagram-apple-blue)]"}`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function diagramPageId(pageId?: string) {
  return pageId ?? DEFAULT_PAGE_ID;
}

function nextDiagramPageOrder(pages: Y.Map<DiagramPage>) {
  let maximum = -1;
  pages.forEach((page) => {
    maximum = Math.max(maximum, page.order);
  });
  return maximum + 1;
}

function expandedDiagramCanvasSize(
  current: { width: number; height: number },
  contentBounds: Rectangle | null,
  viewportWidth: number,
  viewportHeight: number,
  scale: number,
) {
  const safeScale = Math.max(0.05, Number.isFinite(scale) ? scale : 1);
  const viewportCanvasWidth = Math.max(1, (viewportWidth - DIAGRAM_CANVAS_VIEWPORT_INSET) / safeScale);
  const viewportCanvasHeight = Math.max(1, (viewportHeight - DIAGRAM_CANVAS_VIEWPORT_INSET) / safeScale);
  const contentRight = contentBounds ? Math.max(0, contentBounds.x + contentBounds.width) : 0;
  const contentBottom = contentBounds ? Math.max(0, contentBounds.y + contentBounds.height) : 0;
  const requiredWidth = contentBounds ? contentRight + DIAGRAM_CANVAS_PADDING.width : 0;
  const requiredHeight = contentBounds ? contentBottom + DIAGRAM_CANVAS_PADDING.height : 0;
  const targetWidth = requiredWidth <= viewportCanvasWidth
    ? viewportCanvasWidth
    : Math.ceil(Math.max(current.width, requiredWidth) / DIAGRAM_CANVAS_GROWTH.width) * DIAGRAM_CANVAS_GROWTH.width;
  const targetHeight = requiredHeight <= viewportCanvasHeight
    ? viewportCanvasHeight
    : Math.ceil(Math.max(current.height, requiredHeight) / DIAGRAM_CANVAS_GROWTH.height) * DIAGRAM_CANVAS_GROWTH.height;
  return {
    width: Math.min(MAX_DIAGRAM_CANVAS_SIZE, targetWidth),
    height: Math.min(MAX_DIAGRAM_CANVAS_SIZE, targetHeight),
  };
}
