import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import type {
  ChangeEvent,
  ClipboardEvent as ReactClipboardEvent,
  DragEvent as ReactDragEvent,
  ReactNode,
} from "react";
import { Button, Chip, Input, Modal, ModalBody, ModalContent, ModalHeader, Progress, Switch } from "@heroui/react";
import { AppLogo } from "../components/AppLogo";
import { ThemeToggleButton } from "../components/ThemeToggleButton";
import { PublicToolsMenu } from "../components/PublicToolsMenu";
import { HeroRuntime } from "../components/HeroRuntime";
import { SyncedClipboard } from "../components/SyncedClipboard";
import { SyncedWhiteboard, isWhiteboardPayload } from "../components/SyncedWhiteboard";
import type { WhiteboardInboundEvent, WhiteboardPayload } from "../components/SyncedWhiteboard";
import {
  fetchPublicTransferIceConfig,
  publicCreateTransferRoomAccessToken,
  publicCompleteAttachment,
  publicListTransferRoomAccessTokens,
  publicPresignAttachmentDownload,
  publicPresignAttachmentUpload,
  publicRevokeTransferRoomAccessToken,
} from "../api/client";
import type {
  AttachmentPresignUploadResponse,
  PublicTransferCreatedAccessToken,
  PublicTransferIceConfig,
  PublicTransferRoomAccessToken,
  PublicTransferRoomRole,
  TransferAttachment,
} from "../api/types";
import { usePageSeo } from "../lib/seo";
import { createQrMatrix } from "../lib/qr";
import { sha256Blob } from "../lib/sha256";
import { effectiveMimeType, mediaKind, previewKindLabel, shortMimeLabel } from "../lib/transferPreview";
import {
  MAX_TRANSFER_ROOM_NAME_LENGTH,
  MAX_TRANSFER_ROOM_TOKEN_LENGTH,
  resolveTransferNetworkMode,
  validateTransferRoomSettings,
  type TransferNetworkMode,
  type TransferRoomSettingsErrors,
} from "../lib/transferRoom";
import { sendWhiteboardWithFallback } from "../lib/whiteboardTransport";
import {
  clipboardSyncEventKey,
  isClipboardSyncPayload,
  serializeClipboardRelayEnvelope,
  type ClipboardInboundEvent,
  type ClipboardSyncPayload,
} from "../lib/clipboardSync";
import {
  DEFAULT_DIRECT_MEMORY_LIMIT_BYTES,
  receivingTransferKey,
  useDirectTransfer,
  type DirectPendingTransfer,
  type DirectReceivingTransfer,
  type DirectTransferSignalPayload,
} from "../hooks/useDirectTransfer";

const LazySyncedDiagram = lazy(() =>
  import("../components/SyncedDiagram").then((module) => ({ default: module.SyncedDiagram })),
);

type UploadState = "idle" | "connecting" | "waiting" | "direct" | "presigning" | "uploading" | "completing" | "done" | "failed";
type TransferToolMode = "files" | "clipboard" | "whiteboard";
export type PublicTransferWorkspace = "transfer" | "diagram";
const TRANSFER_TOOL_MODES: TransferToolMode[] = ["files", "clipboard", "whiteboard"];

interface UploadRecord {
  file: File;
  previewUrl: string;
  presign: AttachmentPresignUploadResponse | null;
  attachment: TransferAttachment;
  downloadUrl: string | null;
  downloadExpiresAt: string | null;
  direct: boolean;
}

interface DiscoveryPeer {
  peerId: string;
  displayName: string;
  publicAddress: string;
  connectedAt: string;
  roomRole?: PublicTransferRoomRole;
}

interface IncomingAttachment {
  sourcePeerId: string;
  attachment: TransferAttachment;
  objectId: string;
  downloadUrl: string | null;
  downloadExpiresAt: string | null;
  direct?: boolean;
  previewUrl?: string;
  blob?: Blob;
  downloading?: boolean;
  downloadProgress?: number;
  downloadError?: string | null;
}

interface PreviewTarget {
  fileName: string;
  mimeType?: string | null;
  url?: string | null;
  blob?: Blob | null;
  sizeBytes?: number;
}

interface TransferProgressStore {
  getSnapshot: () => number;
  set: (value: number) => void;
  subscribe: (listener: () => void) => () => void;
}

interface FileTransferTask {
  id: number;
  roomEpoch: number;
  roomGeneration: number;
  networkMode: TransferNetworkMode;
  roomId: string;
  roomToken: string;
  targetPeerId: string;
  abortController: AbortController;
}

interface WhiteboardTransportRetryState {
  directAfter: number;
  turnAfter: number;
}

class FileTransferRoomChangedError extends Error {
  constructor() {
    super("房间已变化，本次文件发送已取消");
    this.name = "FileTransferRoomChangedError";
  }
}

const INCOMING_ITEM_LIMIT = 20;
const DIRECT_MEMORY_LIMIT_BYTES = DEFAULT_DIRECT_MEMORY_LIMIT_BYTES;
const STREAM_DOWNLOAD_THRESHOLD_BYTES = 64 * 1024 * 1024;
const AUTO_PREVIEW_LIMIT_BYTES = 8 * 1024 * 1024;
const CLIPBOARD_EVENT_LIMIT = 20;
const CLIPBOARD_SEEN_EVENT_LIMIT = 200;
const CLIPBOARD_SEQUENCE_STATE_LIMIT = 200;
const CLIPBOARD_SEEN_EVENT_TTL_MS = 10 * 60 * 1000;
const WHITEBOARD_DIRECT_TIMEOUT_MS = 2500;
const WHITEBOARD_TURN_TIMEOUT_MS = 5000;
const WHITEBOARD_TRANSPORT_RETRY_MS = 15_000;

export function PublicTransferPage() {
  return <PublicTransferWorkspacePage workspace="transfer" />;
}

export function PublicTransferWorkspacePage({ workspace }: { workspace: PublicTransferWorkspace }) {
  return (
    <HeroRuntime>
      <PublicTransferPageContent workspace={workspace} />
    </HeroRuntime>
  );
}

function PublicTransferPageContent({ workspace }: { workspace: PublicTransferWorkspace }) {
  const discoverySocketRef = useRef<WebSocket | null>(null);
  const loadedSharedAttachmentRef = useRef("");
  const directPreviewUrlsRef = useRef<Set<string>>(new Set());
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const fileDragDepthRef = useRef(0);
  const uploadInFlightRef = useRef<FileTransferTask | null>(null);
  const fileTransferTaskSequenceRef = useRef(0);
  const clipboardSeenEventsRef = useRef<Map<string, number>>(new Map());
  const clipboardHighestSequencesRef = useRef<Map<string, { sequence: number; seenAt: number }>>(new Map());
  const whiteboardSendQueuesRef = useRef<Map<string, Promise<void>>>(new Map());
  const whiteboardTransportRetryRef = useRef<Map<string, WhiteboardTransportRetryState>>(new Map());
  const currentRoomPeerIdsRef = useRef<Set<string>>(new Set());
  const currentRoomPeerRolesRef = useRef<Map<string, PublicTransferRoomRole>>(new Map());
  const roomEpochRef = useRef(0);
  const roomGenerationRef = useRef(0);
  const [peerId] = useState(() => loadOrCreatePeerId());
  const [roomGeneration, setRoomGeneration] = useState(0);
  const [networkMode, setNetworkMode] = useState<TransferNetworkMode>(() => readInitialNetworkMode());
  const [roomId, setRoomId] = useState(() => readInitialRoomId());
  const [roomToken, setRoomToken] = useState(() => loadOrCreateRoomToken(readInitialRoomToken()));
  const [roomIdDraft, setRoomIdDraft] = useState(roomId);
  const [roomTokenDraft, setRoomTokenDraft] = useState(roomToken);
  const [roomRole, setRoomRole] = useState<PublicTransferRoomRole | null>(null);
  const [roomAccessTokens, setRoomAccessTokens] = useState<PublicTransferRoomAccessToken[]>([]);
  const [createdRoomAccess, setCreatedRoomAccess] = useState<PublicTransferCreatedAccessToken | null>(null);
  const [roomAccessLoading, setRoomAccessLoading] = useState(false);
  const [roomSettingsErrors, setRoomSettingsErrors] = useState<TransferRoomSettingsErrors>({});
  const [receiveConfirmationRequired, setReceiveConfirmationRequired] = useState(() => loadReceiveConfirmationRequired());
  const [qrVisible, setQrVisible] = useState(false);
  const [sharedAttachmentId] = useState(() => readInitialSharedAttachmentId());
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [selectedPeerId, setSelectedPeerId] = useState("");
  const [peers, setPeers] = useState<DiscoveryPeer[]>([]);
  const [incoming, setIncoming] = useState<IncomingAttachment[]>([]);
  const [state, setState] = useState<UploadState>("idle");
  const progressStore = useMemo(() => createTransferProgressStore(), []);
  const setProgress = useCallback((value: number) => progressStore.set(value), [progressStore]);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [record, setRecord] = useState<UploadRecord | null>(null);
  const [previewTarget, setPreviewTarget] = useState<PreviewTarget | null>(null);
  const [iceConfig, setIceConfig] = useState<PublicTransferIceConfig | null>(null);
  const [isFileDragActive, setFileDragActive] = useState(false);
  const [activeTool, setActiveTool] = useState<TransferToolMode>("files");
  const [clipboardFocusRequest, setClipboardFocusRequest] = useState(0);
  const [clipboardSyncEnabled, setClipboardSyncEnabled] = useState(false);
  const [clipboardEvents, setClipboardEvents] = useState<ClipboardInboundEvent[]>([]);
  const [whiteboardEvents, setWhiteboardEvents] = useState<WhiteboardInboundEvent[]>([]);
  const isDiagramWorkspace = workspace === "diagram";

  usePageSeo({
    title: isDiagramWorkspace ? "专业流程图 · shuai-tunnel" : "互传 · shuai-tunnel",
    description: isDiagramWorkspace
      ? "支持实时协作、draw.io 图形库、多页文档和多格式导入导出的专业流程图工具。"
      : "打开同一个房间链接，在电脑和手机之间互传文件、同步剪贴板和共享白板。",
    canonical: `https://tunnel.devshuai.com/#/${workspace}`,
  });
  const isInternetMode = networkMode === "internet";
  const effectiveRoomRole: PublicTransferRoomRole = isInternetMode ? roomRole ?? "VIEWER" : "EDITOR";
  const isRoomReadOnly = isInternetMode && effectiveRoomRole === "VIEWER";
  const transferRoomScopeKey = `${networkMode}:${normalizeRoomId(roomId)}:${isInternetMode ? roomToken.trim() : "lan"}:${roomGeneration}`;

  const isFileTransferTaskCurrent = (task: FileTransferTask) => uploadInFlightRef.current === task
    && roomEpochRef.current === task.roomEpoch
    && roomGenerationRef.current === task.roomGeneration
    && !task.abortController.signal.aborted;

  const assertFileTransferTaskCurrent = (task: FileTransferTask) => {
    if (!isFileTransferTaskCurrent(task)) {
      throw new FileTransferRoomChangedError();
    }
  };

  const rememberPreviewUrl = (url?: string | null) => {
    if (url?.startsWith("blob:")) {
      directPreviewUrlsRef.current.add(url);
    }
  };

  const revokePreviewUrl = (url?: string | null) => {
    if (url?.startsWith("blob:") && directPreviewUrlsRef.current.delete(url)) {
      URL.revokeObjectURL(url);
    }
  };

  const releaseIncomingItem = (item: IncomingAttachment) => {
    revokePreviewUrl(item.previewUrl);
    if (item.downloadUrl !== item.previewUrl) {
      revokePreviewUrl(item.downloadUrl);
    }
  };

  const limitIncomingItems = (items: IncomingAttachment[]) => {
    const kept = items.slice(0, INCOMING_ITEM_LIMIT);
    for (const item of items.slice(INCOMING_ITEM_LIMIT)) {
      releaseIncomingItem(item);
    }
    return kept;
  };

  const clearIncomingItems = () => {
    setIncoming((items) => {
      items.forEach(releaseIncomingItem);
      return [];
    });
  };

  const sendDiscoverySignal = useCallback((targetPeerId: string, payload: DirectTransferSignalPayload) => {
    const socket = discoverySocketRef.current;
    if (!targetPeerId || !socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error("发现通道不可用");
    }
    socket.send(JSON.stringify({
      type: "signal",
      targetPeerId,
      payload,
    }));
  }, []);

  const pushWhiteboardEvent = useCallback((sourcePeerId: string, payload: WhiteboardPayload) => {
    if (!sourcePeerId
      || sourcePeerId === peerId
      || !currentRoomPeerIdsRef.current.has(sourcePeerId)
      || currentRoomPeerRolesRef.current.get(sourcePeerId) === "VIEWER") {
      return;
    }
    const eventId = whiteboardEventKey(sourcePeerId, payload);
    setWhiteboardEvents((items) => [
      ...items.slice(-299),
      {
        eventId,
        sourcePeerId,
        payload,
        receivedAt: Date.now(),
      },
    ]);
  }, [peerId]);

  const pushClipboardEvent = useCallback((sourcePeerId: string, payload: ClipboardSyncPayload) => {
    if (!sourcePeerId
      || sourcePeerId === peerId
      || !currentRoomPeerIdsRef.current.has(sourcePeerId)
      || currentRoomPeerRolesRef.current.get(sourcePeerId) === "VIEWER") {
      return;
    }
    const receivedAt = Date.now();
    const eventId = clipboardSyncEventKey(sourcePeerId, payload);
    const seenEvents = clipboardSeenEventsRef.current;
    for (const [seenEventId, seenAt] of seenEvents) {
      if (receivedAt - seenAt > CLIPBOARD_SEEN_EVENT_TTL_MS) {
        seenEvents.delete(seenEventId);
      }
    }
    if (seenEvents.has(eventId)) {
      return;
    }
    seenEvents.set(eventId, receivedAt);
    while (seenEvents.size > CLIPBOARD_SEEN_EVENT_LIMIT) {
      const oldestEventId = seenEvents.keys().next().value as string | undefined;
      if (!oldestEventId) {
        break;
      }
      seenEvents.delete(oldestEventId);
    }

    const sequenceStates = clipboardHighestSequencesRef.current;
    for (const [seenSequenceKey, state] of sequenceStates) {
      if (receivedAt - state.seenAt > CLIPBOARD_SEEN_EVENT_TTL_MS) {
        sequenceStates.delete(seenSequenceKey);
      }
    }
    const sequenceKey = JSON.stringify([sourcePeerId, payload.sessionId]);
    const highestSequence = sequenceStates.get(sequenceKey)?.sequence ?? -1;
    if (payload.sequence <= highestSequence) {
      return;
    }
    sequenceStates.delete(sequenceKey);
    sequenceStates.set(sequenceKey, { sequence: payload.sequence, seenAt: receivedAt });
    while (sequenceStates.size > CLIPBOARD_SEQUENCE_STATE_LIMIT) {
      const oldestSequenceKey = sequenceStates.keys().next().value as string | undefined;
      if (!oldestSequenceKey) {
        break;
      }
      sequenceStates.delete(oldestSequenceKey);
    }
    setClipboardEvents((items) => [
      ...items.slice(-(CLIPBOARD_EVENT_LIMIT - 1)),
      {
        eventId,
        sourcePeerId,
        payload,
        receivedAt,
      },
    ]);
  }, [peerId]);

  const {
    pendingTransfers,
    receivingTransfers,
    sendDirect,
    sendPeerMessage,
    isPeerMessageTransportReady,
    handleSignal,
    acceptIncomingTransfer,
    rejectIncomingTransfer,
    invalidateConnections,
  } = useDirectTransfer({
    selfPeerId: peerId,
    connectionScopeKey: transferRoomScopeKey,
    iceConfig,
    peers,
    directMemoryLimitBytes: DIRECT_MEMORY_LIMIT_BYTES,
    receiveConfirmationRequired,
    preconnectPeerChannels: true,
    sendSignal: sendDiscoverySignal,
    canReceiveFromPeer: (sourcePeerId) => currentRoomPeerRolesRef.current.get(sourcePeerId) !== "VIEWER",
    onPeerMessage: (sourcePeerId, message) => {
      if (message.messageType === "whiteboard" && isWhiteboardPayload(message.payload)) {
        pushWhiteboardEvent(sourcePeerId, message.payload);
      } else if (message.messageType === "clipboard" && isClipboardSyncPayload(message.payload)) {
        pushClipboardEvent(sourcePeerId, message.payload);
      }
    },
    onIncoming: (item) => {
      setIncoming((items) => limitIncomingItems([item, ...items]));
    },
    onPreviewUrl: rememberPreviewUrl,
    onStateChange: (nextState) => setState(nextState),
    onProgress: setProgress,
    onError: setError,
  });

  useEffect(() => {
    let active = true;
    void fetchPublicTransferIceConfig().then((config) => {
      if (active) {
        setIceConfig(config);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (receiveConfirmationRequired) {
      return;
    }
    pendingTransfers.forEach((item) => {
      acceptIncomingTransfer(item.sourcePeerId, item.transferId);
    });
  }, [acceptIncomingTransfer, pendingTransfers, receiveConfirmationRequired]);

  useEffect(() => {
    sessionStorage.setItem("public-transfer-room-id", roomId || "nearby");
  }, [roomId]);

  useEffect(() => {
    if (!isInternetMode || !sharedAttachmentId || !roomToken.trim()) {
      return;
    }
    const loadKey = `${sharedAttachmentId}:${roomToken}`;
    if (loadedSharedAttachmentRef.current === loadKey) {
      return;
    }
    loadedSharedAttachmentRef.current = loadKey;
    let active = true;
    void publicPresignAttachmentDownload(sharedAttachmentId, { roomToken })
      .then((response) => {
        if (!active) {
          return;
        }
        setIncoming((items) => limitIncomingItems([
          {
            sourcePeerId: "shared-link",
            attachment: response.attachment,
            objectId: response.objectId,
            downloadUrl: response.downloadUrl,
            downloadExpiresAt: response.expiresAt,
          },
          ...items.filter((item) => item.attachment.attachmentId !== response.attachment.attachmentId),
        ]));
        setNotice(`已打开共享文件：${response.attachment.fileName}`);
      })
      .catch((err) => {
        if (active) {
          loadedSharedAttachmentRef.current = "";
          setError(err instanceof Error ? err.message : "打开共享文件失败");
        }
      });
    return () => {
      active = false;
    };
  }, [isInternetMode, roomToken, sharedAttachmentId]);

  useEffect(() => {
    let active = true;
    let reconnectTimer: number | null = null;
    let heartbeatTimer: number | null = null;
    let reconnectAttempt = 0;
    let lastPongAt = Date.now();
    setRoomRole(isInternetMode ? null : "EDITOR");

    const clearHeartbeat = () => {
      if (heartbeatTimer !== null) {
        window.clearInterval(heartbeatTimer);
        heartbeatTimer = null;
      }
    };

    const startHeartbeat = (socket: WebSocket) => {
      clearHeartbeat();
      heartbeatTimer = window.setInterval(() => {
        if (!active || discoverySocketRef.current !== socket) {
          return;
        }
        if (socket.readyState !== WebSocket.OPEN) {
          return;
        }
        if (Date.now() - lastPongAt > 75_000) {
          socket.close();
          return;
        }
        socket.send(JSON.stringify({ type: "ping", ts: Date.now() }));
      }, 25_000);
    };

    const handleMessage = (event: MessageEvent) => {
      try {
        const message = JSON.parse(String(event.data)) as {
          type?: string;
          error?: string;
          sourcePeerId?: string;
          targetPeerId?: string;
          peers?: DiscoveryPeer[];
          roomRole?: PublicTransferRoomRole;
          payload?: unknown;
        };
        if (message.type === "pong") {
          lastPongAt = Date.now();
        } else if (message.type === "hello" && message.roomRole) {
          setRoomRole(message.roomRole);
        } else if (message.type === "error" && message.error) {
          setError(message.error);
        } else if (message.type === "roster" && Array.isArray(message.peers)) {
          const visiblePeers = message.peers.filter((peer) => peer.peerId !== peerId);
          currentRoomPeerIdsRef.current = new Set(visiblePeers.map((peer) => peer.peerId));
          currentRoomPeerRolesRef.current = new Map(
            visiblePeers.flatMap((peer) => peer.roomRole ? [[peer.peerId, peer.roomRole] as const] : []),
          );
          setPeers(visiblePeers);
          setSelectedPeerId((current) => current && visiblePeers.some((peer) => peer.peerId === current) ? current : visiblePeers[0]?.peerId ?? "");
        } else if (message.type === "attachment"
          && message.sourcePeerId
          && message.targetPeerId === peerId
          && currentRoomPeerIdsRef.current.has(message.sourcePeerId)
          && currentRoomPeerRolesRef.current.get(message.sourcePeerId) !== "VIEWER") {
          const attachmentPayload = message.payload;
          if (isAttachmentDiscoveryPayload(attachmentPayload)) {
            setIncoming((items) => limitIncomingItems([
              {
                sourcePeerId: message.sourcePeerId ?? "peer",
                attachment: attachmentPayload.attachment,
                objectId: attachmentPayload.objectId ?? attachmentPayload.attachment.objectId,
                downloadUrl: null,
                downloadExpiresAt: null,
              },
              ...items,
            ]));
          }
        } else if (message.type === "whiteboard"
          && message.sourcePeerId
          && message.targetPeerId === peerId
          && isWhiteboardPayload(message.payload)) {
          pushWhiteboardEvent(message.sourcePeerId, message.payload);
        } else if (message.type === "clipboard"
          && message.sourcePeerId
          && message.targetPeerId === peerId
          && isClipboardSyncPayload(message.payload)) {
          pushClipboardEvent(message.sourcePeerId, message.payload);
        } else if (message.type === "signal"
          && message.sourcePeerId
          && message.targetPeerId === peerId
          && currentRoomPeerIdsRef.current.has(message.sourcePeerId)
          && message.payload) {
          void handleSignal(message.sourcePeerId, message.payload as DirectTransferSignalPayload).catch(() => {
            // The room or peer can change while an asynchronous SDP operation is in flight.
          });
        }
      } catch {
        // Ignore malformed discovery messages; the page can keep working through manual copy.
      }
    };

    const connect = () => {
      if (!active) {
        return;
      }
      const url = discoveryWebSocketUrl(roomId, peerId, isInternetMode ? roomToken : "", peerId);
      const socket = new WebSocket(url);
      discoverySocketRef.current = socket;
      socket.onopen = () => {
        if (!active || discoverySocketRef.current !== socket) {
          socket.close();
          return;
        }
        reconnectAttempt = 0;
        lastPongAt = Date.now();
        startHeartbeat(socket);
      };
      socket.onmessage = (event) => {
        if (!active || discoverySocketRef.current !== socket) {
          return;
        }
        handleMessage(event);
      };
      socket.onerror = () => {
        socket.close();
      };
      socket.onclose = () => {
        if (discoverySocketRef.current !== socket) {
          return;
        }
        discoverySocketRef.current = null;
        clearHeartbeat();
        if (!active) {
          return;
        }
        const delayMs = Math.min(1000 * (2 ** Math.min(reconnectAttempt, 4)), 10000);
        reconnectAttempt += 1;
        reconnectTimer = window.setTimeout(connect, delayMs);
      };
    };

    connect();

    return () => {
      active = false;
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
      }
      clearHeartbeat();
      const socket = discoverySocketRef.current;
      if (socket) {
        discoverySocketRef.current = null;
        socket.close();
      }
    };
  }, [handleSignal, isInternetMode, peerId, pushClipboardEvent, pushWhiteboardEvent, roomId, roomToken]);

  useEffect(() => {
    if (!isInternetMode || roomRole !== "OWNER") {
      setRoomAccessTokens([]);
      setCreatedRoomAccess(null);
      return;
    }
    let active = true;
    setRoomAccessLoading(true);
    publicListTransferRoomAccessTokens(roomId, { roomToken, peerId })
      .then((items) => {
        if (active) setRoomAccessTokens(items);
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : "加载房间邀请失败");
      })
      .finally(() => {
        if (active) setRoomAccessLoading(false);
      });
    return () => {
      active = false;
    };
  }, [isInternetMode, peerId, roomId, roomRole, roomToken]);

  useEffect(() => {
    return () => {
      if (record?.previewUrl) {
        URL.revokeObjectURL(record.previewUrl);
      }
    };
  }, [record?.previewUrl]);

  useEffect(() => () => {
    const activeFileTransfer = uploadInFlightRef.current;
    if (activeFileTransfer) {
      uploadInFlightRef.current = null;
      activeFileTransfer.abortController.abort();
    }
    for (const url of directPreviewUrlsRef.current) {
      URL.revokeObjectURL(url);
    }
    directPreviewUrlsRef.current.clear();
  }, []);

  const roomJoinUrl = useMemo(
    () => roomShareUrl(roomId, roomToken, networkMode, `/${workspace}`),
    [networkMode, roomId, roomToken, workspace],
  );
  const selectedPeer = useMemo(
    () => peers.find((peer) => peer.peerId === selectedPeerId) ?? null,
    [peers, selectedPeerId],
  );
  const selectedFilesSize = useMemo(
    () => selectedFiles.reduce((total, file) => total + file.size, 0),
    [selectedFiles],
  );
  const selectedFileTitle = selectedFiles.length === 0
    ? "尚未选择文件"
    : selectedFiles.length === 1
      ? selectedFiles[0].name
      : `${selectedFiles.length} 个文件`;
  const selectedFileDetail = selectedFiles.length === 0
    ? selectedPeer
      ? `将发送给 ${selectedPeer.displayName || selectedPeer.peerId}`
      : isInternetMode
        ? "未选择对方时会先生成分享链接"
        : "内网模式需先选择在线设备"
    : selectedFiles.length === 1
      ? `${formatBytes(selectedFiles[0].size)} · ${selectedFiles[0].type || "未知类型"}`
      : `${formatBytes(selectedFilesSize)} · 批量顺序发送`;
  const isTransferBusy = state === "connecting"
    || state === "waiting"
    || state === "direct"
    || state === "presigning"
    || state === "uploading"
    || state === "completing";
  const fileDropzoneTitle = isFileDragActive
    ? "松开即可发送"
    : isTransferBusy
      ? "文件正在发送"
      : "粘贴文件、拖到这里，或点击选择";
  const fileDropzoneDetail = selectedFiles.length > 0
    ? `${selectedFileTitle} · ${selectedFileDetail}`
    : selectedPeer
      ? `选择后立即发送给 ${selectedPeer.displayName || selectedPeer.peerId}`
      : isInternetMode
        ? "选择后立即上传并生成分享链接"
        : "请先从设备列表选择一台内网设备";
  const fileActivityCount = incoming.length + receivingTransfers.length + pendingTransfers.length;

  const resetTransferRoomState = (preserveCompletedFile = false) => {
    roomEpochRef.current += 1;
    roomGenerationRef.current += 1;
    setRoomGeneration(roomGenerationRef.current);
    const activeFileTransfer = uploadInFlightRef.current;
    if (activeFileTransfer) {
      uploadInFlightRef.current = null;
      activeFileTransfer.abortController.abort();
    }
    invalidateConnections();
    const socket = discoverySocketRef.current;
    if (socket) {
      discoverySocketRef.current = null;
      socket.close();
    }
    currentRoomPeerIdsRef.current.clear();
    currentRoomPeerRolesRef.current.clear();
    clipboardSeenEventsRef.current.clear();
    clipboardHighestSequencesRef.current.clear();
    whiteboardSendQueuesRef.current.clear();
    whiteboardTransportRetryRef.current.clear();
    setClipboardEvents([]);
    setWhiteboardEvents([]);
    setClipboardSyncEnabled(false);
    setPeers([]);
    setSelectedPeerId("");
    setSelectedFiles([]);
    fileDragDepthRef.current = 0;
    setFileDragActive(false);
    setProgress(0);
    setState("idle");
    if (!preserveCompletedFile) {
      setRecord((current) => {
        if (current?.previewUrl) {
          URL.revokeObjectURL(current.previewUrl);
        }
        return null;
      });
    }
  };

  const updateRoomIdDraft = (value: string) => {
    setRoomIdDraft(value);
    setRoomSettingsErrors((current) => ({ ...current, roomId: undefined }));
  };

  const updateRoomTokenDraft = (value: string) => {
    setRoomTokenDraft(value);
    setRoomSettingsErrors((current) => ({ ...current, roomToken: undefined }));
  };

  const updateNetworkMode = (nextMode: TransferNetworkMode) => {
    if (nextMode === networkMode) {
      return;
    }
    let nextToken = roomToken.trim();
    if (nextMode === "internet"
      && validateTransferRoomSettings(roomId, nextToken).errors.roomToken) {
      nextToken = createRoomToken();
    }

    resetTransferRoomState();
    clearIncomingItems();
    setNetworkMode(nextMode);
    setRoomToken(nextToken);
    setRoomTokenDraft(nextToken);
    setRoomSettingsErrors({});
    setQrVisible(false);
    if (nextToken) {
      sessionStorage.setItem("public-transfer-room-token", nextToken);
    }
    window.history.replaceState({}, "", roomShareUrl(roomId, nextToken, nextMode));
    setNotice(nextMode === "lan"
      ? "已切换到内网模式，仅使用设备直连"
      : "已切换到外网模式，将启用 Token 房间和中继兜底");
    setError(null);
  };

  const applyRoomSettings = () => {
    const validation = validateTransferRoomSettings(roomIdDraft, roomTokenDraft, {
      roomTokenRequired: isInternetMode,
    });
    if (validation.errors.roomId || validation.errors.roomToken) {
      setRoomSettingsErrors(validation.errors);
      setNotice(null);
      return;
    }

    const nextToken = isInternetMode ? validation.roomToken : roomToken;
    const changed = validation.roomId !== roomId
      || (isInternetMode && nextToken !== roomToken);
    if (changed) {
      resetTransferRoomState();
      clearIncomingItems();
    }
    setRoomId(validation.roomId);
    setRoomToken(nextToken);
    setRoomIdDraft(validation.roomId);
    setRoomTokenDraft(nextToken);
    setRoomSettingsErrors({});
    if (nextToken) {
      sessionStorage.setItem("public-transfer-room-token", nextToken);
    }
    window.history.replaceState({}, "", roomShareUrl(validation.roomId, nextToken, networkMode));
    setNotice(changed ? "房间设置已应用" : "房间设置没有变化");
    setError(null);
  };

  const resetRoomSettingsDraft = () => {
    setRoomIdDraft(roomId);
    setRoomTokenDraft(roomToken);
    setRoomSettingsErrors({});
  };

  const updateReceiveConfirmationRequired = (value: boolean) => {
    setReceiveConfirmationRequired(value);
    sessionStorage.setItem("public-transfer-receive-confirmation", value ? "true" : "false");
  };

  const createNewRoom = () => {
    const nextRoom = `room-${createRoomToken().slice(0, 8)}`;
    const nextToken = createRoomToken();
    resetTransferRoomState();
    setRoomId(nextRoom);
    setRoomToken(nextToken);
    setRoomIdDraft(nextRoom);
    setRoomTokenDraft(nextToken);
    setRoomSettingsErrors({});
    sessionStorage.setItem("public-transfer-room-token", nextToken);
    clearIncomingItems();
    window.history.replaceState({}, "", roomShareUrl(nextRoom, nextToken, networkMode));
    setNotice("已创建新房间");
    setError(null);
  };

  const copyRoomLink = async () => {
    try {
      await copyText(roomShareUrl(roomId, roomToken, networkMode));
      setNotice(isInternetMode ? "外网房间链接已复制" : "内网房间链接已复制");
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "复制房间链接失败");
    }
  };

  const shareRoom = async () => {
    const url = roomShareUrl(roomId, roomToken, networkMode);
    try {
      await shareOrCopy(
        {
          title: isDiagramWorkspace ? "加入 shuai-tunnel 流程图房间" : "加入 shuai-tunnel 互传房间",
          text: `${isInternetMode ? "外网" : "内网"}房间：${roomId || "nearby"}`,
          url,
        },
        url,
      );
      setNotice(canUseSystemShare() ? "已打开系统分享" : "房间链接已复制");
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "分享房间失败");
    }
  };

  const showRoomQr = () => {
    setQrVisible(true);
    setNotice(isInternetMode
      ? "二维码已生成，扫码加入外网 Token 房间"
      : "二维码已生成，请使用同一内网设备扫码");
    setError(null);
  };

  const createRoomAccess = async (role: "EDITOR" | "VIEWER") => {
    const defaultLabel = role === "EDITOR" ? "编辑者邀请" : "只读访客邀请";
    const label = window.prompt("邀请名称", defaultLabel)?.trim();
    if (!label) return;
    setRoomAccessLoading(true);
    try {
      const created = await publicCreateTransferRoomAccessToken(
        roomId,
        { roomToken, peerId },
        role,
        label,
      );
      setCreatedRoomAccess(created);
      setRoomAccessTokens((items) => [created.access, ...items]);
      setNotice(`已创建${role === "EDITOR" ? "编辑者" : "只读访客"}邀请，请立即复制链接。`);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "创建房间邀请失败");
    } finally {
      setRoomAccessLoading(false);
    }
  };

  const revokeRoomAccess = async (access: PublicTransferRoomAccessToken) => {
    if (!window.confirm(`撤销“${access.label}”后，该邀请将在下次连接时失效，是否继续？`)) return;
    setRoomAccessLoading(true);
    try {
      const revoked = await publicRevokeTransferRoomAccessToken(roomId, access.id, { roomToken, peerId });
      setRoomAccessTokens((items) => items.map((item) => item.id === revoked.id ? revoked : item));
      if (createdRoomAccess?.access.id === revoked.id) setCreatedRoomAccess(null);
      setNotice("邀请已撤销");
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "撤销房间邀请失败");
    } finally {
      setRoomAccessLoading(false);
    }
  };

  const copyCreatedRoomAccessLink = async () => {
    if (!createdRoomAccess) return;
    try {
      await copyText(roomShareUrl(roomId, createdRoomAccess.token, "internet"));
      setNotice("邀请链接已复制");
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "复制邀请链接失败");
    }
  };

  const shareRecordFile = async () => {
    if (!record) {
      return;
    }
    try {
      if (record.direct) {
        const fileShareData = {
          title: record.attachment.fileName,
          text: "shuai-tunnel 直连文件",
          files: [record.file],
        };
        if (canShareFiles(fileShareData)) {
          await navigator.share(fileShareData);
          setNotice("已打开系统文件分享");
        } else {
          await copyText(roomShareUrl(roomId, roomToken, networkMode));
          setNotice("直连文件只在当前会话内可用；已复制房间链接");
        }
      } else {
        const url = fileShareUrl(record.attachment, roomId, roomToken);
        await shareOrCopy(
          {
            title: `接收 ${record.attachment.fileName}`,
            text: `${record.attachment.fileName} · ${formatBytes(record.attachment.sizeBytes)}`,
            url,
          },
          url,
        );
        setNotice(canUseSystemShare() ? "已打开系统分享" : "文件链接已复制");
      }
      setError(null);
    } catch (err) {
      if (isShareCancelled(err)) {
        return;
      }
      setError(err instanceof Error ? err.message : "分享文件失败");
    }
  };

  const copyRecordFileLink = async () => {
    if (!record) {
      return;
    }
    try {
      await copyText(record.direct
        ? roomShareUrl(roomId, roomToken, networkMode)
        : fileShareUrl(record.attachment, roomId, roomToken));
      setNotice(record.direct ? "已复制房间链接" : "文件链接已复制");
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "复制文件链接失败");
    }
  };

  const shareIncomingFile = async (item: IncomingAttachment) => {
    try {
      if (item.direct) {
        await copyText(roomShareUrl(roomId, roomToken, networkMode));
        setNotice("直连文件只在当前会话内可用；已复制房间链接");
      } else {
        const url = fileShareUrl(item.attachment, roomId, roomToken);
        await shareOrCopy(
          {
            title: `接收 ${item.attachment.fileName}`,
            text: `${item.attachment.fileName} · ${formatBytes(item.attachment.sizeBytes)}`,
            url,
          },
          url,
        );
        setNotice(canUseSystemShare() ? "已打开系统分享" : "文件链接已复制");
      }
      setError(null);
    } catch (err) {
      if (isShareCancelled(err)) {
        return;
      }
      setError(err instanceof Error ? err.message : "分享文件失败");
    }
  };

  const uploadFiles = async (files: File[], task: FileTransferTask) => {
    assertFileTransferTaskCurrent(task);
    if (files.length === 0) {
      setError("请选择要发送的文件");
      return;
    }
    if (task.networkMode === "lan" && !task.targetPeerId) {
      setState("failed");
      setError("内网模式请先选择一台在线设备");
      return;
    }
    if (task.networkMode === "internet" && !task.roomToken.trim()) {
      setError("请输入房间口令");
      return;
    }

    setProgress(0);
    setError(null);
    setNotice(null);
    if (record?.previewUrl) {
      URL.revokeObjectURL(record.previewUrl);
    }
    setRecord(null);

    for (let index = 0; index < files.length; index += 1) {
      assertFileTransferTaskCurrent(task);
      const file = files[index];
      if (files.length > 1) {
        setNotice(`正在发送 ${index + 1}/${files.length}：${file.name || "attachment"}`);
      }
      if (task.targetPeerId && typeof RTCPeerConnection !== "undefined") {
        try {
          const direct = await sendDirect(
            task.targetPeerId,
            file,
            task.networkMode === "lan" ? "direct" : "auto",
            task.abortController.signal,
          );
          if (!isFileTransferTaskCurrent(task)) {
            URL.revokeObjectURL(direct.previewUrl);
            throw new FileTransferRoomChangedError();
          }
          setRecord({
            file,
            previewUrl: direct.previewUrl,
            presign: null,
            attachment: direct.attachment,
            downloadUrl: null,
            downloadExpiresAt: null,
            direct: true,
          });
          setState("done");
          continue;
        } catch (err) {
          assertFileTransferTaskCurrent(task);
          const directError = err instanceof Error ? err.message : "unknown";
          if (directError.includes("拒绝接收")) {
            setError(directError);
            setState("failed");
            continue;
          }
          if (task.networkMode === "internet") {
            setError(`直接发送未完成，正在改用分享链接：${directError}`);
          }
        }
      }
      if (task.networkMode === "lan") {
        setState("failed");
        setError("内网模式仅允许设备直连，本次未上传云端；可检查设备连接或切换到外网模式");
        continue;
      }
      assertFileTransferTaskCurrent(task);
      await uploadViaOss(file, task);
    }
    assertFileTransferTaskCurrent(task);
    if (files.length > 1) {
      setNotice(`已处理 ${files.length} 个文件`);
    }
  };

  const acceptFiles = (files: File[]) => {
    if (isRoomReadOnly) {
      setError("当前为只读访客，不能向房间发送文件");
      return;
    }
    if (files.length === 0) {
      return;
    }
    if (uploadInFlightRef.current) {
      setError("当前文件仍在发送，请稍后再添加");
      return;
    }
    const task: FileTransferTask = {
      id: fileTransferTaskSequenceRef.current += 1,
      roomEpoch: roomEpochRef.current,
      roomGeneration,
      networkMode,
      roomId,
      roomToken,
      targetPeerId: selectedPeerId,
      abortController: new AbortController(),
    };
    uploadInFlightRef.current = task;
    setSelectedFiles(files);
    void uploadFiles(files, task)
      .catch((err) => {
        if (err instanceof FileTransferRoomChangedError) {
          return;
        }
        if (!isFileTransferTaskCurrent(task)) {
          return;
        }
        setState("failed");
        setError(err instanceof Error ? err.message : "上传失败");
      })
      .finally(() => {
        if (uploadInFlightRef.current === task) {
          uploadInFlightRef.current = null;
        }
      });
  };

  const openFilePicker = () => {
    if (isRoomReadOnly) {
      setError("当前为只读访客，不能向房间发送文件");
      return;
    }
    if (uploadInFlightRef.current || isTransferBusy) {
      setError("当前文件仍在发送，请稍后再添加");
      return;
    }
    fileInputRef.current?.click();
  };

  const handleFileInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.currentTarget.files ?? []);
    event.currentTarget.value = "";
    acceptFiles(files);
  };

  const handleFileDragEnter = (event: ReactDragEvent<HTMLButtonElement>) => {
    event.preventDefault();
    if (!hasDraggedFiles(event.dataTransfer)) {
      return;
    }
    fileDragDepthRef.current += 1;
    if (!uploadInFlightRef.current) {
      setFileDragActive(true);
    }
  };

  const handleFileDragOver = (event: ReactDragEvent<HTMLButtonElement>) => {
    event.preventDefault();
    if (hasDraggedFiles(event.dataTransfer)) {
      event.dataTransfer.dropEffect = "copy";
    }
  };

  const handleFileDragLeave = (event: ReactDragEvent<HTMLButtonElement>) => {
    event.preventDefault();
    fileDragDepthRef.current = Math.max(0, fileDragDepthRef.current - 1);
    if (fileDragDepthRef.current === 0) {
      setFileDragActive(false);
    }
  };

  const handleFileDrop = (event: ReactDragEvent<HTMLButtonElement>) => {
    event.preventDefault();
    fileDragDepthRef.current = 0;
    setFileDragActive(false);
    const files = Array.from(event.dataTransfer.files ?? []);
    if (files.length === 0) {
      setError("没有检测到可发送的文件");
      return;
    }
    acceptFiles(files);
  };

  const handlePagePaste = (event: ReactClipboardEvent<HTMLElement>) => {
    if (isDiagramWorkspace || activeTool !== "files") {
      return;
    }
    if (isEditablePasteTarget(event.target)) {
      return;
    }
    const files = filesFromClipboard(event.clipboardData);
    if (files.length === 0) {
      return;
    }
    event.preventDefault();
    acceptFiles(files);
  };

  const uploadViaOss = async (file: File, task: FileTransferTask) => {
    assertFileTransferTaskCurrent(task);
    setState("presigning");
    setProgress(0);
    try {
      const mimeType = effectiveMimeType(file.name || "attachment", file.type);
      const sha256 = await sha256Blob(file, task.abortController.signal);
      assertFileTransferTaskCurrent(task);
      const presign = await publicPresignAttachmentUpload({
        fileName: file.name || "attachment",
        mimeType,
        sizeBytes: file.size,
        sha256,
        roomId: task.roomId,
        roomToken: task.roomToken,
      });
      assertFileTransferTaskCurrent(task);

      setState("uploading");
      await putObject(
        presign.uploadUrl,
        file,
        presign.uploadHeaders,
        (value) => {
          if (isFileTransferTaskCurrent(task)) {
            setProgress(value);
          }
        },
        task.abortController.signal,
      );
      assertFileTransferTaskCurrent(task);

      setState("completing");
      const attachment = await publicCompleteAttachment(presign.attachmentId, { roomToken: task.roomToken });
      assertFileTransferTaskCurrent(task);
      publishAttachmentEnvelope(task, presign.objectId, attachment);
      setRecord({
        file,
        previewUrl: URL.createObjectURL(file),
        presign,
        attachment,
        downloadUrl: null,
        downloadExpiresAt: null,
        direct: false,
      });
      setState("done");
    } catch (err) {
      if (err instanceof FileTransferRoomChangedError || !isFileTransferTaskCurrent(task)) {
        throw new FileTransferRoomChangedError();
      }
      setState("failed");
      setError(err instanceof Error ? err.message : "上传失败");
    }
  };

  const downloadRecordFile = async () => {
    if (!record) {
      return;
    }
    try {
      if (record.direct) {
        downloadBlob(record.file, record.attachment.fileName);
        setNotice(`已保存：${record.attachment.fileName}`);
        setError(null);
        return;
      }
      const response = record.downloadUrl
        ? { downloadUrl: record.downloadUrl, downloadHeaders: {}, expiresAt: record.downloadExpiresAt ?? "" }
        : await publicPresignAttachmentDownload(record.attachment.attachmentId, { roomToken });
      if (!record.downloadUrl && !record.direct && "attachment" in response) {
        setRecord({
          ...record,
          downloadUrl: response.downloadUrl,
          downloadExpiresAt: response.expiresAt,
        });
      }
      if (record.attachment.sizeBytes > STREAM_DOWNLOAD_THRESHOLD_BYTES && !hasRequestHeaders(response.downloadHeaders)) {
        triggerUrlDownload(response.downloadUrl, record.attachment.fileName);
        setNotice(`已开始下载：${record.attachment.fileName}`);
        setError(null);
        return;
      }
      await saveUrlAs(response.downloadUrl, record.attachment.fileName, response.downloadHeaders);
      setNotice(`已保存：${record.attachment.fileName}`);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "保存文件失败");
    }
  };

  const downloadIncoming = async (item: IncomingAttachment) => {
    const key = incomingItemKey(item);
    try {
      setIncomingDownloadState(key, { downloading: true, downloadProgress: 0, downloadError: null });
      if (item.direct) {
        if (item.blob) {
          downloadBlob(item.blob, item.attachment.fileName);
        } else if (item.downloadUrl || item.previewUrl) {
          triggerUrlDownload(item.downloadUrl || item.previewUrl || "", item.attachment.fileName);
        } else {
          throw new Error("直连文件缓存不可用");
        }
        setIncomingDownloadState(key, { downloading: false, downloadProgress: 100, downloadError: null });
        setNotice(`已保存：${item.attachment.fileName}`);
        setError(null);
        return;
      }
      const response = item.downloadUrl
        ? { downloadUrl: item.downloadUrl, downloadHeaders: {}, expiresAt: item.downloadExpiresAt ?? "" }
        : await publicPresignAttachmentDownload(item.attachment.attachmentId, { roomToken });
      if (!response.downloadUrl) {
        throw new Error("下载地址不可用");
      }
      setIncoming((items) => items.map((current) => incomingItemKey(current) === key
        ? { ...current, downloadUrl: response.downloadUrl, downloadExpiresAt: response.expiresAt }
        : current));
      if (item.attachment.sizeBytes > STREAM_DOWNLOAD_THRESHOLD_BYTES && !hasRequestHeaders(response.downloadHeaders)) {
        triggerUrlDownload(response.downloadUrl, item.attachment.fileName);
        setIncomingDownloadState(key, { downloading: false, downloadProgress: 100, downloadError: null });
        setNotice(`已开始下载：${item.attachment.fileName}`);
        setError(null);
        return;
      }
      const blob = await saveUrlAs(response.downloadUrl, item.attachment.fileName, response.downloadHeaders, (value) => {
        setIncomingDownloadState(key, { downloading: true, downloadProgress: value, downloadError: null });
      });
      const previewUrl = URL.createObjectURL(blob);
      rememberPreviewUrl(previewUrl);
      setIncoming((items) => items.map((current) => {
        if (incomingItemKey(current) !== key) {
          return current;
        }
        revokePreviewUrl(current.previewUrl);
        return { ...current, downloadUrl: response.downloadUrl, downloadExpiresAt: response.expiresAt, previewUrl, blob };
      }));
      setIncomingDownloadState(key, { downloading: false, downloadProgress: 100, downloadError: null });
      setNotice(`已保存：${item.attachment.fileName}`);
      setError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : "保存文件失败";
      setIncomingDownloadState(key, { downloading: false, downloadError: message });
      setError(message);
    }
  };

  const setIncomingDownloadState = (
    key: string,
    patch: Pick<IncomingAttachment, "downloading" | "downloadProgress" | "downloadError">,
  ) => {
    setIncoming((items) => items.map((current) => incomingItemKey(current) === key ? { ...current, ...patch } : current));
  };

  const publishAttachmentEnvelope = (task: FileTransferTask, objectId: string, attachment: TransferAttachment) => {
    const socket = discoverySocketRef.current;
    if (!isFileTransferTaskCurrent(task)
      || !task.targetPeerId
      || !currentRoomPeerIdsRef.current.has(task.targetPeerId)
      || !socket
      || socket.readyState !== WebSocket.OPEN) {
      return false;
    }
    socket.send(JSON.stringify({
      type: "attachment",
      targetPeerId: task.targetPeerId,
      payload: {
        type: "STMSG2",
        messageType: "attachment",
        objectId,
        attachment,
      },
    }));
    return true;
  };

  const publishWhiteboardEnvelope = useCallback((targetPeerId: string, payload: WhiteboardPayload, expectedRoomEpoch: number) => {
    const socket = discoverySocketRef.current;
    if (roomEpochRef.current !== expectedRoomEpoch
      || !currentRoomPeerIdsRef.current.has(targetPeerId)
      || !targetPeerId
      || !socket
      || socket.readyState !== WebSocket.OPEN) {
      return false;
    }
    try {
      const serialized = JSON.stringify({
        type: "whiteboard",
        targetPeerId,
        payload,
      });
      // 服务端 discovery 通道单消息上限 64K 字符，超限会导致整条发现连接被服务端关闭。
      if (serialized.length > 63 * 1024) {
        return false;
      }
      socket.send(serialized);
      return true;
    } catch {
      return false;
    }
  }, []);

  const sendWhiteboardPayload = useCallback((payload: WhiteboardPayload) => {
    if (isRoomReadOnly) return;
    if (peers.length === 0) {
      return;
    }
    const sendRoomEpoch = roomEpochRef.current;
    for (const peer of peers) {
      const targetPeerId = peer.peerId;
      // Keep payloads ordered while avoiding a new ICE negotiation for every stroke after a path fails.
      const queueKey = JSON.stringify([sendRoomEpoch, targetPeerId]);
      const previous = whiteboardSendQueuesRef.current.get(queueKey) ?? Promise.resolve();
      const task = previous.catch(() => undefined).then(async () => {
        const isTargetCurrent = () => roomEpochRef.current === sendRoomEpoch
          && currentRoomPeerIdsRef.current.has(targetPeerId);
        if (!isTargetCurrent()) {
          return;
        }
        const retryState = whiteboardTransportRetryRef.current.get(queueKey) ?? {
          directAfter: 0,
          turnAfter: 0,
        };
        const message = { messageType: "whiteboard", payload };
        const sendDirectMessage = async () => {
          if (!isTargetCurrent()) {
            return false;
          }
          if (Date.now() < retryState.directAfter
            && !isPeerMessageTransportReady(targetPeerId, "direct")) {
            return false;
          }
          const sent = await sendPeerMessage(
            targetPeerId,
            message,
            WHITEBOARD_DIRECT_TIMEOUT_MS,
            "direct",
          );
          retryState.directAfter = sent ? 0 : Date.now() + WHITEBOARD_TRANSPORT_RETRY_MS;
          return sent;
        };

        if (networkMode === "lan") {
          await sendDirectMessage();
          if (isTargetCurrent()) {
            whiteboardTransportRetryRef.current.set(queueKey, retryState);
          }
          return;
        }

        await sendWhiteboardWithFallback({
          direct: sendDirectMessage,
          turn: async () => {
            if (!isTargetCurrent()) {
              return false;
            }
            if (Date.now() < retryState.turnAfter
              && !isPeerMessageTransportReady(targetPeerId, "relay")) {
              return false;
            }
            const sent = await sendPeerMessage(
              targetPeerId,
              message,
              WHITEBOARD_TURN_TIMEOUT_MS,
              "relay",
            );
            retryState.turnAfter = sent ? 0 : Date.now() + WHITEBOARD_TRANSPORT_RETRY_MS;
            return sent;
          },
          websocket: () => publishWhiteboardEnvelope(targetPeerId, payload, sendRoomEpoch),
        });

        if (isTargetCurrent()) {
          whiteboardTransportRetryRef.current.set(queueKey, retryState);
        }
      });
      const settled = task.catch(() => undefined);
      whiteboardSendQueuesRef.current.set(queueKey, settled);
      void settled.finally(() => {
        if (whiteboardSendQueuesRef.current.get(queueKey) === settled) {
          whiteboardSendQueuesRef.current.delete(queueKey);
        }
      });
    }
  }, [isPeerMessageTransportReady, isRoomReadOnly, networkMode, peers, publishWhiteboardEnvelope, sendPeerMessage]);

  const publishClipboardEnvelope = useCallback((targetPeerId: string, serializedEnvelope: string, expectedRoomEpoch: number) => {
    const socket = discoverySocketRef.current;
    if (roomEpochRef.current !== expectedRoomEpoch
      || !currentRoomPeerIdsRef.current.has(targetPeerId)
      || !targetPeerId
      || !socket
      || socket.readyState !== WebSocket.OPEN) {
      return false;
    }
    socket.send(serializedEnvelope);
    return true;
  }, []);

  const sendClipboardPayload = useCallback(async (payload: ClipboardSyncPayload) => {
    if (isRoomReadOnly) {
      throw new Error("当前为只读访客，不能同步剪贴板");
    }
    const target = peers.find((peer) => peer.peerId === selectedPeerId);
    if (!target) {
      throw new Error("请选择一台在线设备后再同步剪贴板");
    }
    const sendRoomEpoch = roomEpochRef.current;
    const sentDirect = await sendPeerMessage(
      target.peerId,
      { messageType: "clipboard", payload },
      1600,
      networkMode === "lan" ? "direct" : "auto",
    );
    if (roomEpochRef.current !== sendRoomEpoch || !currentRoomPeerIdsRef.current.has(target.peerId)) {
      throw new Error("房间或目标设备已变化，本次剪贴板同步已取消");
    }
    if (sentDirect) {
      return;
    }
    if (networkMode === "lan") {
      throw new Error("内网模式仅允许设备直连；请检查设备连接或切换到外网模式");
    }
    const serializedEnvelope = serializeClipboardRelayEnvelope(target.peerId, payload);
    if (!publishClipboardEnvelope(target.peerId, serializedEnvelope, sendRoomEpoch)) {
      throw new Error("互传通道暂时不可用，请确认对方仍在线");
    }
  }, [isRoomReadOnly, networkMode, peers, publishClipboardEnvelope, selectedPeerId, sendPeerMessage]);

  const selectTransferTool = useCallback((mode: TransferToolMode, focusContent = false) => {
    setActiveTool(mode);
    if (mode === "clipboard" && focusContent) {
      setClipboardFocusRequest((value) => value + 1);
    }
  }, []);

  return (
    <main
      className="landing-shell relative min-h-screen overflow-x-hidden text-zinc-950 dark:text-white"
      onPaste={handlePagePaste}
    >
      <div className="landing-grid" aria-hidden="true" />
      <div className="landing-scanline" aria-hidden="true" />

      <header className="relative z-10 mx-auto flex w-full max-w-[1480px] items-center justify-between gap-3 px-4 py-4 sm:px-8 sm:py-5">
        <AppLogo label="shuai-tunnel" subtitle={isDiagramWorkspace ? "专业流程图" : "互传"} markClassName="h-8 w-8 sm:h-9 sm:w-9" />
        <div className="flex shrink-0 items-center gap-2">
          <PublicToolsMenu active={workspace} />
          <ThemeToggleButton className="glass-chip text-zinc-950 dark:text-white" />
          <Button as="a" href="/" radius="sm" variant="flat" className="glass-chip text-zinc-950 dark:text-white">
            控制台
          </Button>
        </div>
      </header>

      <section
        className={`relative z-10 mx-auto grid w-full max-w-[1480px] gap-5 px-4 pb-10 sm:px-8 sm:pb-14 ${
          isDiagramWorkspace || activeTool === "whiteboard" ? "xl:grid-cols-1" : "xl:grid-cols-[minmax(0,1fr)_320px]"
        }`}
      >
        <div className="min-w-0 rounded-xl glass glass-border border p-4 shadow-sm sm:p-6">
          <div className="flex flex-col gap-2">
            <div className="text-tiny font-semibold uppercase tracking-[0.18em] text-cyan-700 dark:text-cyan-200">
              {isDiagramWorkspace ? "工具 · 专业流程图" : "工具 · 互传"}
            </div>
            <h1 className="text-display-md font-semibold sm:text-display-lg">
              {isDiagramWorkspace ? "专业流程图协作工作区" : "文件、剪贴板和白板，一处互传"}
            </h1>
            <p className="max-w-2xl text-small leading-6 text-zinc-700 dark:text-zinc-300">
              {isDiagramWorkspace
                ? "创建独立流程图房间，使用完整 draw.io 图形分类、多页画布和专业编辑工具与其他设备实时协作。"
                : "邀请对方加入后，可切换文件传输、剪贴板同步和同步白板。手机和电脑都可以直接打开这个页面。"}
            </p>
          </div>

          <div className="mt-4 rounded-lg border border-black/10 bg-white/40 p-2 dark:border-white/10 dark:bg-white/[0.035]">
            <div className="flex items-center justify-between gap-3 px-1 pb-2">
              <div className="text-small font-semibold text-zinc-900 dark:text-white">{isDiagramWorkspace ? "协作网络" : "传输网络"}</div>
              <Chip size="sm" radius="sm" variant="flat" color={isInternetMode ? "secondary" : "success"}>
                {isInternetMode ? "外网模式" : "内网模式 · 默认"}
              </Chip>
            </div>
            <div className="grid gap-2 sm:grid-cols-2" role="radiogroup" aria-label="传输网络模式">
              <NetworkModeButton
                mode="lan"
                activeMode={networkMode}
                label="内网"
                detail="同一网络发现，仅设备直连，不上传云端"
                onSelect={updateNetworkMode}
              />
              <NetworkModeButton
                mode="internet"
                activeMode={networkMode}
                label="外网"
                detail="Token 隔离，直连优先并允许中继与云端兜底"
                onSelect={updateNetworkMode}
              />
            </div>
          </div>

          <div className="mt-3 flex flex-col gap-3 rounded-lg border border-cyan-500/20 bg-cyan-50/70 p-3 dark:border-cyan-300/20 dark:bg-cyan-400/10 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <div className="text-small font-semibold text-cyan-950 dark:text-cyan-100">
                {isInternetMode ? "邀请外网设备加入" : "连接同一内网设备"}
              </div>
              <div className="mt-1">
                <Chip size="sm" radius="sm" variant="flat" color={effectiveRoomRole === "OWNER" ? "primary" : effectiveRoomRole === "EDITOR" ? "success" : "default"}>
                  {effectiveRoomRole === "OWNER" ? "房主" : effectiveRoomRole === "EDITOR" ? "可编辑" : "只读访客"}
                </Chip>
              </div>
              <div className="mt-1 text-tiny leading-5 text-cyan-800/80 dark:text-cyan-100/70">
                {isInternetMode
                  ? "邀请链接包含房间 Token，设备可从不同网络加入。"
                  : "设备需使用同一内网或公网出口；邀请链接不包含 Token。"}
              </div>
              <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5 text-tiny text-cyan-800/80 dark:text-cyan-100/70">
                <span>我的名称</span>
                <button
                  type="button"
                  className="max-w-full truncate rounded glass-chip px-1.5 py-0.5 font-mono underline-offset-2 hover:underline"
                  onClick={() => void copyText(peerId).then(() => setNotice("客户端名称已复制")).catch((err) => setError(err instanceof Error ? err.message : "复制客户端名称失败"))}
                >
                  {peerId}
                </button>
              </div>
            </div>
            <div className="grid w-full grid-cols-2 gap-2 sm:flex sm:w-auto sm:shrink-0 sm:flex-wrap">
              <Button color="primary" radius="sm" variant="flat" className="w-full sm:w-auto" onPress={() => void shareRoom()}>
                邀请设备
              </Button>
              <Button color={qrVisible ? "default" : "secondary"} radius="sm" variant="flat" className="w-full sm:w-auto" onPress={() => qrVisible ? setQrVisible(false) : showRoomQr()}>
                {qrVisible ? "收起二维码" : "手机扫码"}
              </Button>
              <Button radius="sm" variant="flat" className="w-full sm:w-auto" onPress={() => void copyRoomLink()}>
                复制链接
              </Button>
              <Button radius="sm" variant="flat" className="w-full sm:w-auto" onPress={createNewRoom}>
                新房间
              </Button>
            </div>
          </div>

          <details className="mt-3 rounded-lg glass glass-border border p-3 text-small">
            <summary className="cursor-pointer font-medium text-zinc-900 dark:text-white">房间设置</summary>
            <div className="mt-3 grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <Input
                label="房间名"
                radius="sm"
                variant="bordered"
                value={roomIdDraft}
                onValueChange={updateRoomIdDraft}
                maxLength={MAX_TRANSFER_ROOM_NAME_LENGTH}
                isInvalid={Boolean(roomSettingsErrors.roomId)}
                errorMessage={roomSettingsErrors.roomId}
              />
              <Input
                label="房间 Token"
                radius="sm"
                variant="bordered"
                value={roomTokenDraft}
                onValueChange={updateRoomTokenDraft}
                maxLength={MAX_TRANSFER_ROOM_TOKEN_LENGTH}
                isDisabled={!isInternetMode}
                isInvalid={Boolean(roomSettingsErrors.roomToken)}
                errorMessage={roomSettingsErrors.roomToken}
                description={isInternetMode ? "外网设备凭此 Token 加入隔离房间" : "内网模式不发送 Token"}
                endContent={
                  <Button size="sm" variant="light" isDisabled={!isInternetMode} onPress={() => {
                    const next = createRoomToken();
                    updateRoomTokenDraft(next);
                  }}>
                    生成
                  </Button>
                }
              />
            </div>
            <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
                {isInternetMode
                  ? "编辑不会中断当前连接，点击应用后切换房间。Token 会包含在外网邀请链接中。"
                  : "内网房间按房间名和网络出口隔离，仅应用房间名；Token 不参与发现。"}
              </div>
              <div className="flex shrink-0 gap-2">
                <Button size="sm" radius="sm" variant="light" onPress={resetRoomSettingsDraft}>
                  恢复
                </Button>
                <Button size="sm" radius="sm" color="primary" variant="flat" onPress={applyRoomSettings}>
                  应用设置
                </Button>
              </div>
            </div>
            {isInternetMode && roomRole === "OWNER" ? (
              <div className="mt-3 rounded-lg border border-violet-500/20 bg-violet-50/60 p-3 dark:border-violet-300/20 dark:bg-violet-400/10">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-small font-medium text-zinc-900 dark:text-white">角色邀请</div>
                    <div className="mt-1 text-tiny text-zinc-500 dark:text-zinc-400">邀请 Token 仅保存哈希；明文链接只在创建时显示。</div>
                  </div>
                  <div className="flex gap-2">
                    <Button size="sm" radius="sm" variant="flat" isLoading={roomAccessLoading} onPress={() => void createRoomAccess("EDITOR")}>邀请编辑者</Button>
                    <Button size="sm" radius="sm" variant="flat" isLoading={roomAccessLoading} onPress={() => void createRoomAccess("VIEWER")}>邀请访客</Button>
                  </div>
                </div>
                {createdRoomAccess ? (
                  <div className="mt-3 flex flex-col gap-2 rounded-md border border-amber-500/25 bg-amber-50/80 p-2.5 dark:border-amber-300/20 dark:bg-amber-300/10 sm:flex-row sm:items-center sm:justify-between">
                    <span className="min-w-0 text-tiny text-amber-900 dark:text-amber-100">{createdRoomAccess.access.label} · 明文 Token 离开页面后无法再次查看</span>
                    <Button size="sm" radius="sm" color="warning" variant="flat" onPress={() => void copyCreatedRoomAccessLink()}>复制邀请链接</Button>
                  </div>
                ) : null}
                <div className="mt-3 space-y-1.5">
                  {roomAccessTokens.length === 0 ? (
                    <div className="text-tiny text-zinc-400">{roomAccessLoading ? "正在加载邀请…" : "暂无角色邀请"}</div>
                  ) : roomAccessTokens.map((access) => (
                    <div key={access.id} className="flex items-center justify-between gap-2 rounded-md border border-black/10 bg-white/60 px-2.5 py-2 dark:border-white/10 dark:bg-black/10">
                      <div className="min-w-0">
                        <div className="truncate text-tiny font-medium text-zinc-800 dark:text-zinc-200">{access.label}</div>
                        <div className="mt-0.5 text-[10px] text-zinc-400">{access.role === "EDITOR" ? "可编辑" : "只读"} · {access.revokedAt ? "已撤销" : new Date(access.createdAt).toLocaleString()}</div>
                      </div>
                      <Button size="sm" radius="sm" color="danger" variant="light" isDisabled={Boolean(access.revokedAt) || roomAccessLoading} onPress={() => void revokeRoomAccess(access)}>{access.revokedAt ? "已撤销" : "撤销"}</Button>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            {!isDiagramWorkspace ? <div className="mt-3 rounded-lg glass glass-border border p-3">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="text-small font-medium text-zinc-900 dark:text-white">接收前确认</div>
                  <div className="mt-1 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
                    默认关闭，房间内设备发来的直连文件会自动开始接收。
                  </div>
                </div>
                <Switch
                  size="sm"
                  isSelected={receiveConfirmationRequired}
                  onValueChange={updateReceiveConfirmationRequired}
                >
                  {receiveConfirmationRequired ? "手动确认" : "直接接收"}
                </Switch>
              </div>
            </div> : null}
          </details>

          {qrVisible && (
            <div className="mt-3 flex flex-col gap-3 rounded-lg glass border border-cyan-500/20 p-3 dark:border-cyan-300/20 sm:flex-row sm:items-center">
              <RoomQrCode value={roomJoinUrl} />
              <div className="min-w-0 flex-1">
                <div className="text-small font-semibold text-zinc-900 dark:text-white">
                  扫码加入当前{isInternetMode ? "外网" : "内网"}房间
                </div>
                <div className="mt-1 text-tiny leading-5 text-zinc-600 dark:text-zinc-300">
                  {isInternetMode
                    ? "手机打开后会自动带上房间和 Token，可从其它网络加入。"
                    : "手机需连接同一内网；链接只携带房间名，不包含 Token。"}
                </div>
                <div className="mt-2 break-all rounded bg-zinc-950/5 px-2 py-1 font-mono text-tiny text-zinc-700 dark:bg-white/10 dark:text-zinc-200 sm:truncate">
                  {roomJoinUrl}
                </div>
                <div className="mt-2 flex flex-wrap gap-2">
                  <Button size="sm" radius="sm" variant="flat" onPress={() => void copyText(roomJoinUrl).then(() => setNotice("二维码链接已复制")).catch((err) => setError(err instanceof Error ? err.message : "复制二维码链接失败"))}>
                    复制二维码链接
                  </Button>
                  <Button size="sm" radius="sm" variant="light" onPress={() => void shareRoom()}>
                    系统分享
                  </Button>
                </div>
              </div>
            </div>
          )}

          {!isDiagramWorkspace ? <>
          <div className="mt-5 grid grid-cols-3 gap-1.5 rounded-lg border border-black/10 bg-white/45 p-1 dark:border-white/10 dark:bg-white/[0.04]" role="tablist" aria-label="互传功能切换">
            <ToolModeButton
              mode="files"
              activeMode={activeTool}
              label="文件传输"
              detail={fileActivityCount > 0 ? `${fileActivityCount} 项` : "发送和接收"}
              onSelect={selectTransferTool}
            />
            <ToolModeButton
              mode="clipboard"
              activeMode={activeTool}
              label="同步剪贴板"
              detail={clipboardSyncEnabled ? "已开启" : clipboardEvents.length > 0 ? "有新内容" : "定向同步"}
              onSelect={selectTransferTool}
            />
            <ToolModeButton
              mode="whiteboard"
              activeMode={activeTool}
              label="同步白板"
              detail={peers.length > 0 ? `${peers.length + 1} 台` : "本地绘制"}
              onSelect={selectTransferTool}
            />
          </div>

          <div
            id="transfer-panel-files"
            role="tabpanel"
            aria-labelledby="transfer-tab-files"
            hidden={activeTool !== "files"}
          >
            <input
              ref={fileInputRef}
              id="public-transfer-file-input"
              type="file"
              multiple
              hidden
              disabled={isRoomReadOnly}
              tabIndex={-1}
              onChange={handleFileInputChange}
            />
            <button
              type="button"
              data-testid="public-transfer-file-dropzone"
              aria-label="粘贴文件、拖到这里，或点击选择；选择后立即发送"
              aria-describedby="public-transfer-file-dropzone-detail"
              aria-busy={isTransferBusy}
              aria-disabled={isTransferBusy || isRoomReadOnly}
              disabled={isRoomReadOnly}
              onClick={openFilePicker}
              onDragEnter={handleFileDragEnter}
              onDragOver={handleFileDragOver}
              onDragLeave={handleFileDragLeave}
              onDrop={handleFileDrop}
              className={`group relative mt-5 flex min-h-44 w-full flex-col items-center justify-center overflow-hidden rounded-xl border-2 border-dashed px-5 py-8 text-center outline-none transition duration-200 motion-reduce:transition-none ${
                isFileDragActive
                  ? "border-cyan-400 bg-cyan-50/90 shadow-[inset_0_0_0_1px_rgba(34,211,238,0.18),0_18px_50px_-32px_rgba(8,145,178,0.8)] dark:border-cyan-300 dark:bg-cyan-300/10"
                  : isTransferBusy
                    ? "cursor-wait border-cyan-400/45 bg-cyan-50/55 dark:border-cyan-300/30 dark:bg-cyan-300/[0.07]"
                    : "cursor-pointer border-zinc-300 bg-white/35 hover:border-cyan-500/55 hover:bg-cyan-50/55 focus-visible:border-cyan-500 focus-visible:ring-4 focus-visible:ring-cyan-500/15 dark:border-white/15 dark:bg-white/[0.035] dark:hover:border-cyan-300/50 dark:hover:bg-cyan-300/[0.07] dark:focus-visible:border-cyan-300"
              }`}
            >
              <span aria-hidden="true" className="absolute left-3 top-3 h-4 w-4 border-l border-t border-cyan-500/35 dark:border-cyan-300/30" />
              <span aria-hidden="true" className="absolute right-3 top-3 h-4 w-4 border-r border-t border-cyan-500/35 dark:border-cyan-300/30" />
              <span aria-hidden="true" className="absolute bottom-3 left-3 h-4 w-4 border-b border-l border-cyan-500/35 dark:border-cyan-300/30" />
              <span aria-hidden="true" className="absolute bottom-3 right-3 h-4 w-4 border-b border-r border-cyan-500/35 dark:border-cyan-300/30" />
              <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2.5 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-cyan-800 dark:border-cyan-300/20 dark:bg-cyan-300/10 dark:text-cyan-100">
                {isFileDragActive ? "Drop to send" : "Paste · Drop · Click"}
              </span>
              <span className="mt-3 text-base font-semibold text-zinc-950 dark:text-white">
                {fileDropzoneTitle}
              </span>
              <span
                id="public-transfer-file-dropzone-detail"
                aria-live="polite"
                className="mt-1.5 w-full min-w-0 max-w-xl [overflow-wrap:anywhere] text-tiny leading-5 text-zinc-500 dark:text-zinc-400"
              >
                {fileDropzoneDetail}
              </span>
            </button>
          </div>

          {state !== "idle" && (
            <div className={activeTool === "files" ? "mt-4" : "hidden"} aria-hidden={activeTool !== "files"}>
              <TransferProgress state={state} store={progressStore} />
            </div>
          )}
          </> : null}

          {notice && (
            <div className="mt-4 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-small text-emerald-800 dark:border-emerald-400/30 dark:bg-emerald-500/10 dark:text-emerald-100">
              {notice}
            </div>
          )}

          {error && (
            <div className="mt-4 rounded-lg border border-rose-300 bg-rose-50 px-3 py-2 text-small text-rose-700 dark:border-rose-400/30 dark:bg-rose-500/10 dark:text-rose-100">
              {error}
            </div>
          )}

          {!isDiagramWorkspace ? <>
          <SyncedClipboard
            syncKey={transferRoomScopeKey}
            isActive={activeTool === "clipboard"}
            focusRequest={clipboardFocusRequest}
            isEnabled={clipboardSyncEnabled && !isRoomReadOnly}
            peerCount={peers.length}
            targetPeerId={selectedPeer?.peerId ?? ""}
            targetPeerLabel={selectedPeer?.displayName || selectedPeer?.peerId || ""}
            events={clipboardEvents}
            onEnabledChange={(enabled) => setClipboardSyncEnabled(isRoomReadOnly ? false : enabled)}
            onSend={sendClipboardPayload}
          />

          <div
            id="transfer-panel-whiteboard"
            role="tabpanel"
            aria-labelledby="transfer-tab-whiteboard"
            hidden={activeTool !== "whiteboard"}
          >
            <SyncedWhiteboard
              boardKey={transferRoomScopeKey}
              roomRole={effectiveRoomRole}
              peerId={peerId}
              peerCount={peers.length}
              isConnected={peers.length > 0}
              isActive={activeTool === "whiteboard"}
              events={whiteboardEvents}
              onSend={sendWhiteboardPayload}
            />
          </div>

          <div className={activeTool === "files" ? "" : "hidden"} aria-hidden={activeTool !== "files"}>
            <IncomingFilesPanel
              pendingTransfers={pendingTransfers}
              receivingTransfers={receivingTransfers}
              incoming={incoming}
              onAcceptDirect={(item) => acceptIncomingTransfer(item.sourcePeerId, item.transferId)}
              onRejectDirect={(item) => rejectIncomingTransfer(item.sourcePeerId, item.transferId)}
              onShare={shareIncomingFile}
              onDownload={downloadIncoming}
              onPreview={setPreviewTarget}
            />

            {record && (
              <div className="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1fr)_260px]">
                <div className="rounded-lg glass glass-border border p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-base font-semibold text-zinc-950 dark:text-white">
                        {record.direct ? "已发送给对方" : selectedPeer ? "已通知对方接收" : "分享链接已准备好"}
                      </div>
                      <div className="mt-1 truncate text-small font-medium text-zinc-700 dark:text-zinc-200">{record.attachment.fileName}</div>
                      <div className="mt-1 text-tiny text-zinc-500 dark:text-zinc-400">
                        {formatBytes(record.attachment.sizeBytes)} · {record.direct ? "当前会话可直接保存" : "同房间成员可下载 · 可复制链接发给别人"}
                      </div>
                    </div>
                    <Chip size="sm" color="success" variant="flat">
                      完成
                    </Chip>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Button radius="sm" color="primary" variant="flat" onPress={() => void shareRecordFile()}>
                      分享
                    </Button>
                    <Button radius="sm" variant="flat" onPress={() => void copyRecordFileLink()}>
                      复制链接
                    </Button>
                    <Button radius="sm" color="success" onPress={() => void downloadRecordFile()}>
                      保存到本机
                    </Button>
                  </div>
                </div>
                <Preview record={record} onPreview={setPreviewTarget} />
              </div>
            )}
          </div>
          </> : (
            <Suspense fallback={<DiagramWorkspaceLoading />}>
              <LazySyncedDiagram
                boardKey={transferRoomScopeKey}
                roomId={roomId}
                roomToken={isInternetMode ? roomToken : ""}
                roomRole={effectiveRoomRole}
                peerId={peerId}
                peerCount={peers.length}
                isConnected={peers.length > 0}
                events={whiteboardEvents}
                onSend={sendWhiteboardPayload}
              />
            </Suspense>
          )}
        </div>

        {!isDiagramWorkspace ? <aside className={`${activeTool === "whiteboard" ? "hidden" : ""} min-w-0 rounded-xl glass glass-border border p-4 shadow-sm sm:p-5 xl:sticky xl:top-5 xl:self-start`}>
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold">发送给谁</h2>
              <div className="mt-1 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
                {isInternetMode
                  ? "对方打开外网邀请链接后，点一下名字再发送。"
                  : "同一内网设备进入相同房间后，点一下名字再发送。"}
              </div>
            </div>
            <Chip size="sm" radius="sm" variant="flat" color={peers.length > 0 ? "primary" : "default"}>
              {peers.length} 台
            </Chip>
          </div>
          <div className="mt-3 flex flex-col gap-2">
            {peers.length === 0 ? (
              <div className="rounded-lg glass glass-border border p-3 text-small text-zinc-500 dark:text-zinc-400">
                {isInternetMode
                  ? "还没有其它设备。发送邀请链接或二维码，对方打开后会出现在这里。"
                  : "还没有发现内网设备。请确认设备处于同一网络并进入相同房间。"}
              </div>
            ) : peers.map((peer) => (
              <button
                key={peer.peerId}
                type="button"
                onClick={() => setSelectedPeerId(peer.peerId)}
                className={`rounded-lg border px-3 py-2 text-left text-small transition-colors ${
                  selectedPeerId === peer.peerId
                    ? "border-cyan-400 bg-cyan-50 text-cyan-900 dark:border-cyan-300/40 dark:bg-cyan-400/10 dark:text-cyan-100"
                    : "glass glass-border text-zinc-700 hover:border-black/20 dark:text-zinc-200"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="min-w-0 truncate font-medium">{peer.displayName || peer.peerId}</div>
                  {selectedPeerId === peer.peerId && (
                    <span className="shrink-0 rounded bg-cyan-500/15 px-1.5 py-0.5 text-[10px] font-medium text-cyan-700 dark:text-cyan-100">
                      已选
                    </span>
                  )}
                </div>
                <div className="mt-0.5 truncate font-mono text-tiny opacity-70">{peer.peerId}</div>
              </button>
            ))}
          </div>

          <TransferFaq iceConfig={iceConfig} networkMode={networkMode} />
        </aside> : null}
      </section>
      <PreviewModal target={previewTarget} onClose={() => setPreviewTarget(null)} />
    </main>
  );
}

function NetworkModeButton({
  mode,
  activeMode,
  label,
  detail,
  onSelect,
}: {
  mode: TransferNetworkMode;
  activeMode: TransferNetworkMode;
  label: string;
  detail: string;
  onSelect: (mode: TransferNetworkMode) => void;
}) {
  const active = mode === activeMode;
  return (
    <button
      type="button"
      role="radio"
      aria-checked={active}
      className={`rounded-md border px-3 py-2.5 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 ${
        active
          ? "border-cyan-400 bg-cyan-50 text-cyan-950 shadow-sm dark:border-cyan-300/40 dark:bg-cyan-300/10 dark:text-cyan-100"
          : "border-black/10 bg-white/45 text-zinc-700 hover:border-cyan-400/50 hover:bg-cyan-50/60 dark:border-white/10 dark:bg-white/[0.035] dark:text-zinc-300 dark:hover:bg-cyan-300/[0.07]"
      }`}
      onClick={() => onSelect(mode)}
    >
      <span className="flex items-center justify-between gap-2 text-small font-semibold">
        {label}
        {active && <span className="text-[10px] uppercase tracking-wider text-cyan-700 dark:text-cyan-200">当前</span>}
      </span>
      <span className="mt-1 block text-tiny leading-5 text-zinc-500 dark:text-zinc-400">{detail}</span>
    </button>
  );
}

function DiagramWorkspaceLoading() {
  return (
    <section className="mt-5 grid min-h-[520px] place-items-center rounded-2xl border border-black/[0.07] bg-zinc-50/70 dark:border-white/[0.08] dark:bg-zinc-950/55">
      <div className="flex flex-col items-center gap-3 text-center">
        <span className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-500/25 border-t-cyan-500" aria-hidden="true" />
        <span className="text-small font-semibold text-zinc-900 dark:text-white">正在加载专业流程图工具</span>
      </div>
    </section>
  );
}

function ToolModeButton({
  mode,
  activeMode,
  label,
  detail,
  onSelect,
}: {
  mode: TransferToolMode;
  activeMode: TransferToolMode;
  label: string;
  detail: string;
  onSelect: (mode: TransferToolMode, focusContent?: boolean) => void;
}) {
  const active = mode === activeMode;
  const selectAndFocus = (nextMode: TransferToolMode) => {
    onSelect(nextMode, false);
    window.requestAnimationFrame(() => document.getElementById(`transfer-tab-${nextMode}`)?.focus());
  };
  return (
    <button
      id={`transfer-tab-${mode}`}
      type="button"
      role="tab"
      aria-selected={active}
      aria-controls={`transfer-panel-${mode}`}
      tabIndex={active ? 0 : -1}
      className={`min-w-0 rounded-md px-3 py-2 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 ${
        active
          ? "bg-cyan-500 text-white shadow-sm dark:bg-cyan-400 dark:text-zinc-950"
          : "text-zinc-600 hover:bg-cyan-50 hover:text-cyan-900 dark:text-zinc-300 dark:hover:bg-cyan-300/10 dark:hover:text-cyan-100"
      }`}
      onClick={() => onSelect(mode, true)}
      onKeyDown={(event) => {
        const currentIndex = TRANSFER_TOOL_MODES.indexOf(mode);
        let nextMode: TransferToolMode | null = null;
        if (event.key === "ArrowRight") {
          nextMode = TRANSFER_TOOL_MODES[(currentIndex + 1) % TRANSFER_TOOL_MODES.length];
        } else if (event.key === "ArrowLeft") {
          nextMode = TRANSFER_TOOL_MODES[(currentIndex - 1 + TRANSFER_TOOL_MODES.length) % TRANSFER_TOOL_MODES.length];
        } else if (event.key === "Home") {
          nextMode = TRANSFER_TOOL_MODES[0];
        } else if (event.key === "End") {
          nextMode = TRANSFER_TOOL_MODES[TRANSFER_TOOL_MODES.length - 1];
        }
        if (nextMode) {
          event.preventDefault();
          selectAndFocus(nextMode);
        }
      }}
    >
      <span className="block truncate text-small font-semibold">{label}</span>
      <span className={`mt-0.5 block truncate text-[11px] ${active ? "text-white/80 dark:text-zinc-950/70" : "text-zinc-500 dark:text-zinc-400"}`}>
        {detail}
      </span>
    </button>
  );
}

function IncomingFilesPanel({
  pendingTransfers,
  receivingTransfers,
  incoming,
  onAcceptDirect,
  onRejectDirect,
  onShare,
  onDownload,
  onPreview,
}: {
  pendingTransfers: DirectPendingTransfer[];
  receivingTransfers: DirectReceivingTransfer[];
  incoming: IncomingAttachment[];
  onAcceptDirect: (item: DirectPendingTransfer) => void;
  onRejectDirect: (item: DirectPendingTransfer) => void;
  onShare: (item: IncomingAttachment) => Promise<void>;
  onDownload: (item: IncomingAttachment) => Promise<void>;
  onPreview: (target: PreviewTarget) => void;
}) {
  const hasPending = pendingTransfers.length > 0;
  const hasReceiving = receivingTransfers.length > 0;
  const hasIncoming = incoming.length > 0;

  return (
    <section className="mt-5 rounded-lg glass glass-border border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold text-zinc-950 dark:text-white">收到的文件</h2>
          <div className="mt-1 text-tiny text-zinc-500 dark:text-zinc-400">
            接收进度、预览和保存入口会显示在这里。
          </div>
        </div>
        <Chip size="sm" radius="sm" variant="flat" color={hasIncoming || hasReceiving || hasPending ? "primary" : "default"}>
          {incoming.length + receivingTransfers.length + pendingTransfers.length} 项
        </Chip>
      </div>

      {hasPending && (
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          {pendingTransfers.map((item) => (
            <div key={receivingTransferKey(item)} className="rounded-lg border border-amber-300 bg-amber-50/80 p-3 dark:border-amber-300/25 dark:bg-amber-300/10">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate text-small font-semibold text-amber-950 dark:text-amber-100">{item.fileName}</div>
                  <div className="mt-1 text-tiny text-amber-800/75 dark:text-amber-100/70">
                    来自 {item.sourcePeerId} · {formatBytes(item.sizeBytes)}
                  </div>
                </div>
                <Chip size="sm" radius="sm" color="warning" variant="flat">
                  待确认
                </Chip>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2">
                <Button size="sm" radius="sm" color="primary" onPress={() => onAcceptDirect(item)}>
                  接收
                </Button>
                <Button size="sm" radius="sm" variant="flat" onPress={() => onRejectDirect(item)}>
                  拒绝
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {hasReceiving && (
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          {receivingTransfers.map((item) => {
            const percent = transferProgress(item.receivedBytes, item.sizeBytes);
            return (
              <div key={receivingTransferKey(item)} className="rounded-lg border border-cyan-400/30 bg-cyan-50/70 p-3 dark:border-cyan-300/20 dark:bg-cyan-400/10">
                <div className="truncate text-small font-medium text-cyan-950 dark:text-cyan-100">{item.fileName}</div>
                <div className="mt-1 text-tiny text-cyan-800/75 dark:text-cyan-100/70">
                  来自 {item.sourcePeerId} · {formatBytes(item.receivedBytes)} / {formatBytes(item.sizeBytes)}
                </div>
                <Progress className="mt-2" aria-label={`${item.fileName} 接收进度`} color="primary" size="sm" value={percent} />
              </div>
            );
          })}
        </div>
      )}

      <div className="mt-3 grid gap-3 md:grid-cols-2">
        {!hasIncoming && !hasPending && !hasReceiving ? (
          <div className="rounded-lg glass border border-dashed glass-border p-4 text-small text-zinc-500 dark:text-zinc-400 md:col-span-2">
            暂无附件消息。对方发送文件后会出现在这里。
          </div>
        ) : incoming.map((item) => {
          const previewUrl = item.previewUrl || item.downloadUrl;
          return (
            <div key={incomingItemKey(item)} className="rounded-lg glass glass-border border p-3">
              <div className="truncate text-small font-medium">{item.attachment.fileName}</div>
              <div className="mt-1 text-tiny text-zinc-500">
                来自 {item.sourcePeerId} · {formatBytes(item.attachment.sizeBytes)}{item.direct ? " · direct" : ""}
              </div>
              {(previewUrl || item.direct) && (
                <FilePreview
                  fileName={item.attachment.fileName}
                  mimeType={item.attachment.mimeType}
                  url={previewUrl}
                  blob={item.blob}
                  sizeBytes={item.attachment.sizeBytes}
                  compact
                  onPreview={onPreview}
                />
              )}
              <div className="mt-2 flex gap-2">
                <Button size="sm" radius="sm" variant="flat" onPress={() => void onShare(item)}>
                  分享
                </Button>
                <Button
                  size="sm"
                  radius="sm"
                  color="success"
                  variant={item.downloadUrl || item.direct ? "solid" : "flat"}
                  isLoading={item.downloading}
                  onPress={() => void onDownload(item)}
                >
                  {item.direct ? "保存" : "下载"}
                </Button>
              </div>
              {item.downloading && (
                <Progress className="mt-2" aria-label={`${item.attachment.fileName} 下载进度`} color="success" size="sm" value={item.downloadProgress ?? 0} />
              )}
              {item.downloadError && (
                <div className="mt-2 text-tiny text-rose-600 dark:text-rose-200">{item.downloadError}</div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

function TransferProgress({ state, store }: { state: UploadState; store: TransferProgressStore }) {
  const progress = useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
  return (
    <>
      <Progress
        aria-label="上传进度"
        value={state === "done" ? 100 : progress}
        color={state === "failed" ? "danger" : "primary"}
        size="sm"
      />
      <div className="mt-2 text-tiny text-zinc-500 dark:text-zinc-400">
        {stateLabel(state, progress)}
      </div>
    </>
  );
}

function Preview({ record, onPreview }: { record: UploadRecord; onPreview: (target: PreviewTarget) => void }) {
  return (
    <FilePreview
      fileName={record.attachment.fileName}
      mimeType={record.attachment.mimeType}
      url={record.previewUrl}
      blob={record.file}
      sizeBytes={record.attachment.sizeBytes}
      onPreview={onPreview}
    />
  );
}

function PreviewModal({ target, onClose }: { target: PreviewTarget | null; onClose: () => void }) {
  const kind = mediaKind(target?.fileName ?? "", target?.mimeType ?? null);
  const mimeType = target ? effectiveMimeType(target.fileName, target.mimeType) : "";

  return (
    <Modal isOpen={Boolean(target)} onClose={onClose} size="5xl" scrollBehavior="inside">
      <ModalContent className="max-w-[min(96vw,1480px)]">
        {target && (
          <>
            <ModalHeader className="flex min-w-0 flex-col gap-2 pr-12">
              <div className="min-w-0 truncate text-base font-semibold sm:text-lg">{target.fileName}</div>
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <Chip color="primary" size="sm" variant="flat">
                  {previewKindLabel(kind)}
                </Chip>
                <span className="min-w-0 break-all font-mono text-tiny font-normal text-default-500">
                  {mimeType}
                </span>
              </div>
            </ModalHeader>
            <ModalBody className="overflow-y-auto px-4 pb-4">
              <FilePreview
                fileName={target.fileName}
                mimeType={target.mimeType}
                url={target.url}
                blob={target.blob}
                sizeBytes={target.sizeBytes}
                expanded
              />
            </ModalBody>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}

function FilePreview({
  fileName,
  mimeType,
  url,
  blob,
  sizeBytes,
  compact = false,
  expanded = false,
  onPreview,
}: {
  fileName: string;
  mimeType?: string | null;
  url?: string | null;
  blob?: Blob | null;
  sizeBytes?: number;
  compact?: boolean;
  expanded?: boolean;
  onPreview?: (target: PreviewTarget) => void;
}) {
  const kind = mediaKind(fileName, mimeType);
  const previewSizeBytes = sizeBytes ?? blob?.size ?? 0;
  const [previewFailed, setPreviewFailed] = useState(false);
  useEffect(() => {
    setPreviewFailed(false);
  }, [fileName, mimeType, url, blob]);
  const canOpenPreview = Boolean(onPreview && !expanded && (url || blob));
  const previewAction = canOpenPreview ? (
    <div className="mt-2 flex justify-end">
      <Button
        size="sm"
        radius="sm"
        variant="flat"
        className="h-8"
        aria-label={`放大预览 ${fileName}`}
        onPress={() => onPreview?.({ fileName, mimeType, url, blob, sizeBytes: previewSizeBytes })}
      >
        {compact ? "放大" : "放大预览"}
      </Button>
    </div>
  ) : null;
  const frameClass = compact
    ? "mt-2 overflow-hidden rounded border border-black/10 bg-zinc-950/5 dark:border-white/10 dark:bg-white/[0.03]"
    : "overflow-hidden rounded-lg border border-black/10 bg-zinc-950/5 dark:border-white/10 dark:bg-white/[0.03]";
  const mediaClass = expanded
    ? "max-h-[70dvh] w-full object-contain"
    : compact
      ? "max-h-44 w-full object-contain"
      : "h-64 w-full object-contain";
  const documentClass = expanded
    ? "h-[70dvh] w-full"
    : compact
      ? "h-44 w-full"
      : "h-80 w-full";
  const fallbackClass = expanded
    ? "flex min-h-[45dvh] flex-col items-center justify-center rounded-lg glass glass-border border p-4 text-center"
    : compact
      ? "mt-2 flex min-h-28 flex-col items-center justify-center rounded glass glass-border border p-3 text-center"
      : "flex h-64 flex-col items-center justify-center rounded-lg glass glass-border border p-4 text-center";

  const deferHeavyPreview = !expanded
    && Boolean(onPreview)
    && previewSizeBytes > AUTO_PREVIEW_LIMIT_BYTES
    && (kind === "image" || kind === "pdf");
  if (deferHeavyPreview) {
    return (
      <>
        <div className={fallbackClass}>
          <div className={`${compact ? "text-2xl" : "text-4xl"} font-semibold text-zinc-300 dark:text-white/20`}>{previewKindLabel(kind)}</div>
          <div className="mt-3 max-w-full truncate text-small font-medium">{fileName}</div>
          <div className="mt-1 text-tiny text-zinc-500">文件较大，已暂停自动预览以保持页面流畅</div>
        </div>
        {previewAction}
      </>
    );
  }

  if (url && kind === "image" && !previewFailed) {
    return (
      <>
        <div className={frameClass}>
          <img src={url} alt={fileName} className={mediaClass} onError={() => setPreviewFailed(true)} />
        </div>
        {previewAction}
      </>
    );
  }
  if (url && kind === "video" && !previewFailed) {
    return (
      <>
        <div className={`${frameClass} bg-zinc-950`}>
          <video src={url} controls preload="metadata" className={mediaClass} onError={() => setPreviewFailed(true)} />
        </div>
        {previewAction}
      </>
    );
  }
  if (url && kind === "audio" && !previewFailed) {
    return (
      <>
        <div className={fallbackClass}>
          <div className="text-2xl font-semibold text-zinc-300 dark:text-white/20">AUDIO</div>
          <div className="mt-2 max-w-full truncate text-small font-medium">{fileName}</div>
          <audio src={url} controls preload="metadata" className="mt-3 w-full" onError={() => setPreviewFailed(true)} />
        </div>
        {previewAction}
      </>
    );
  }
  if (url && kind === "pdf" && !previewFailed) {
    return (
      <>
        <div className={`${frameClass} bg-white`}>
          <object data={url} type="application/pdf" className={documentClass} onError={() => setPreviewFailed(true)}>
            <div className="flex h-full items-center justify-center p-3 text-small text-zinc-500">PDF 预览不可用</div>
          </object>
        </div>
        {previewAction}
      </>
    );
  }
  if (kind === "text" && blob) {
    return (
      <>
        <TextFilePreview fileName={fileName} mimeType={mimeType} blob={blob} compact={compact} expanded={expanded} />
        {previewAction}
      </>
    );
  }
  return (
    <>
      <div className={fallbackClass}>
        <div className={`${compact ? "text-2xl" : "text-4xl"} font-semibold text-zinc-300 dark:text-white/20`}>{previewKindLabel(kind)}</div>
        <div className="mt-3 max-w-full truncate text-small font-medium">{fileName}</div>
        <div className="mt-1 text-tiny text-zinc-500">{effectiveMimeType(fileName, mimeType)}</div>
      </div>
      {previewAction}
    </>
  );
}

function TextFilePreview({
  fileName,
  mimeType,
  blob,
  compact,
  expanded,
}: {
  fileName: string;
  mimeType?: string | null;
  blob: Blob;
  compact: boolean;
  expanded: boolean;
}) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const maxPreviewBytes = 96 * 1024;
    void blob.slice(0, maxPreviewBytes).text()
      .then((value) => {
        if (active) {
          setText(value);
          setError(null);
        }
      })
      .catch((err) => {
        if (active) {
          setText("");
          setError(err instanceof Error ? err.message : "文本预览失败");
        }
      });
    return () => {
      active = false;
    };
  }, [blob]);

  return (
    <div className={`${compact ? "mt-2" : ""} overflow-hidden rounded border border-black/10 bg-zinc-950 text-zinc-100 dark:border-white/10`}>
      <div className="flex items-center justify-between gap-2 border-b border-white/10 px-3 py-2">
        <span className="min-w-0 truncate text-tiny font-medium">{fileName}</span>
        <span className="shrink-0 text-[10px] uppercase text-zinc-400">{shortMimeLabel(effectiveMimeType(fileName, mimeType))}</span>
      </div>
      <pre className={`${expanded ? "h-[68dvh]" : compact ? "max-h-44" : "h-80"} overflow-auto whitespace-pre-wrap break-words p-3 font-mono text-[11px] leading-5`}>
        {error || text || "正在读取预览..."}
      </pre>
    </div>
  );
}

function TransferFaq({
  iceConfig,
  networkMode,
}: {
  iceConfig: PublicTransferIceConfig | null;
  networkMode: TransferNetworkMode;
}) {
  const isInternetMode = networkMode === "internet";
  const routeLabel = iceConfig?.turnAuthRequired ? "备用通道已启用" : "备用通道检测中";

  return (
    <section className="mt-6 rounded-lg glass glass-border border p-3">
      <h2 className="text-base font-semibold text-zinc-950 dark:text-white">常见问题</h2>
      <div className="mt-2 divide-y divide-black/10 dark:divide-white/10">
        <FaqItem title="怎么把手机加进来？">
          点“手机扫码”，用手机相机扫二维码。{isInternetMode ? "外网模式允许手机使用其它网络。" : "内网模式要求手机连接同一网络。"}
        </FaqItem>
        <FaqItem title="找不到对方怎么办？">
          {isInternetMode
            ? "先发送邀请链接；确认双方使用相同房间名和 Token。"
            : "确认双方处于同一内网或公网出口，并使用相同房间名。"}
        </FaqItem>
        <FaqItem title="没有选对方也能发送吗？">
          {isInternetMode
            ? "可以。页面会上传文件并生成短期分享链接。"
            : "不可以。内网模式不会上传云端，必须先选择一台在线设备。"}
        </FaqItem>
        <FaqItem title="文件会怎么传？">
          {isInternetMode
            ? "优先设备直传；失败时会使用临时安全链接完成传输。"
            : "只通过设备间 WebRTC 直连传输；失败后不会使用 TURN 或上传云端。"}
        </FaqItem>
        <FaqItem title="剪贴板为什么有时需要点一下复制？">
          浏览器可能阻止网页在后台改写系统剪贴板。内容仍会保留在页面里，点击“复制到本机”即可完成写入。
        </FaqItem>
        <FaqItem title="谁能看到我发的文件？">
          {isInternetMode
            ? "云端分享文件可由持有房间 Token 和文件链接的人下载；点选设备直传时不进入房间共享。"
            : "文件只发送给你点选的内网设备，不创建云端副本或公开下载链接。"}
        </FaqItem>
        <FaqItem title="更多说明">
          {isInternetMode
            ? `外网房间通过 Token 隔离，文件地址短期有效。当前状态：${routeLabel}。`
            : "内网模式仍使用服务端完成设备发现和 WebRTC 信令，但文件、剪贴板和白板数据只走设备直连。"}
        </FaqItem>
      </div>
    </section>
  );
}

function FaqItem({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details className="group py-2">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-small font-medium text-zinc-800 dark:text-zinc-100">
        <span>{title}</span>
        <span className="shrink-0 text-lg leading-none text-zinc-400 transition-transform group-open:rotate-45">+</span>
      </summary>
      <div className="mt-2 text-tiny leading-5 text-zinc-600 dark:text-zinc-300">
        {children}
      </div>
    </details>
  );
}

function RoomQrCode({ value }: { value: string }) {
  const qr = useMemo(() => {
    try {
      return { matrix: createQrMatrix(value), error: null as string | null };
    } catch (err) {
      return { matrix: null, error: err instanceof Error ? err.message : "二维码生成失败" };
    }
  }, [value]);

  if (!qr.matrix) {
    return (
      <div className="mx-auto flex h-36 w-36 shrink-0 items-center justify-center rounded-md border border-dashed border-zinc-300 bg-white p-3 text-center text-tiny text-zinc-500 sm:mx-0">
        {qr.error}
      </div>
    );
  }

  const quietZone = 4;
  const viewSize = qr.matrix.length + quietZone * 2;
  const darkPath = qr.matrix
    .flatMap((row, y) => row.map((dark, x) => dark ? `M${x + quietZone},${y + quietZone}h1v1h-1z` : ""))
    .filter(Boolean)
    .join("");

  return (
    <svg
      className="mx-auto h-36 w-36 shrink-0 rounded-md bg-white p-2 shadow-sm ring-1 ring-black/10 sm:mx-0"
      viewBox={`0 0 ${viewSize} ${viewSize}`}
      role="img"
      aria-label="当前房间二维码"
      shapeRendering="crispEdges"
    >
      <title>当前房间二维码</title>
      <rect width={viewSize} height={viewSize} fill="#ffffff" />
      <path d={darkPath} fill="#111827" />
    </svg>
  );
}

function putObject(
  url: string,
  file: File,
  headers: Record<string, string>,
  onProgress: (value: number) => void,
  signal?: AbortSignal,
): Promise<void> {
  const reportProgress = createProgressReporter(onProgress);
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    let settled = false;
    const cleanup = () => signal?.removeEventListener("abort", abortUpload);
    const finish = (callback: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback();
    };
    const abortUpload = () => {
      xhr.abort();
      finish(() => reject(new Error("文件发送已取消")));
    };
    xhr.open("PUT", url, true);
    for (const [key, value] of Object.entries(headers)) {
      xhr.setRequestHeader(key, value);
    }
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        reportProgress(Math.round((event.loaded / event.total) * 100));
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        reportProgress(100, true);
        finish(resolve);
      } else {
        finish(() => reject(new Error(`文件发送失败：HTTP ${xhr.status}`)));
      }
    };
    xhr.onerror = () => finish(() => reject(new Error("文件发送失败，请检查网络后重试")));
    xhr.onabort = () => finish(() => reject(new Error("文件发送已取消")));
    signal?.addEventListener("abort", abortUpload, { once: true });
    if (signal?.aborted) {
      abortUpload();
      return;
    }
    xhr.send(file);
  });
}

function createProgressReporter(onProgress: (value: number) => void, minIntervalMs = 200) {
  let lastAt = 0;
  let lastValue = -1;
  return (value: number, force = false) => {
    const nextValue = Math.max(0, Math.min(100, Math.round(value)));
    const now = Date.now();
    if (force || nextValue === 0 || nextValue === 100 || (nextValue !== lastValue && now - lastAt >= minIntervalMs)) {
      lastAt = now;
      lastValue = nextValue;
      onProgress(nextValue);
    }
  };
}

function createTransferProgressStore(): TransferProgressStore {
  let value = 0;
  const listeners = new Set<() => void>();
  return {
    getSnapshot: () => value,
    set: (nextValue) => {
      const normalized = Math.max(0, Math.min(100, Math.round(nextValue)));
      if (normalized === value) {
        return;
      }
      value = normalized;
      listeners.forEach((listener) => listener());
    },
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

function hasRequestHeaders(headers: Record<string, string>) {
  return Object.keys(headers).length > 0;
}

function stateLabel(state: UploadState, progress: number) {
  switch (state) {
    case "connecting":
      return "正在连接对方设备";
    case "waiting":
      return "等待对方确认接收";
    case "direct":
      return `正在直接发送：${progress}%`;
    case "presigning":
      return "正在准备分享链接";
    case "uploading":
      return `正在发送文件：${progress}%`;
    case "completing":
      return "正在整理接收信息";
    case "done":
      return "发送完成";
    case "failed":
      return "发送失败";
    default:
      return "";
  }
}

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

function transferProgress(doneBytes: number, totalBytes: number) {
  if (!Number.isFinite(doneBytes) || !Number.isFinite(totalBytes) || totalBytes <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round((doneBytes / totalBytes) * 100)));
}

function incomingItemKey(item: IncomingAttachment) {
  return `${item.sourcePeerId}:${item.attachment.attachmentId}:${item.objectId}`;
}

function isAttachmentDiscoveryPayload(value: unknown): value is { objectId?: string; attachment: TransferAttachment } {
  if (!isPlainRecord(value)) {
    return false;
  }
  const attachment = value.attachment;
  if (!isPlainRecord(attachment)) {
    return false;
  }
  return typeof attachment.fileName === "string"
    && typeof attachment.objectId === "string"
    && typeof attachment.sizeBytes === "number";
}

function whiteboardEventKey(sourcePeerId: string, payload: WhiteboardPayload) {
  if (payload.type === "STDG1") {
    if (payload.kind === "diagram-update") {
      return `${sourcePeerId}:diagram-update:${payload.createdAt}:${payload.update.length}:${payload.update.slice(0, 20)}`;
    }
    if (payload.kind === "diagram-presence") {
      return `${sourcePeerId}:diagram-presence:${payload.createdAt}`;
    }
    return `${sourcePeerId}:diagram-sync:${payload.requestId}:${payload.createdAt}`;
  }
  if (payload.kind === "stroke-start") {
    return `${sourcePeerId}:start:${payload.strokeId}:${payload.createdAt}:${payload.point.x}:${payload.point.y}`;
  }
  if (payload.kind === "stroke-points" || payload.kind === "stroke-end") {
    const first = payload.points[0];
    const last = payload.points[payload.points.length - 1];
    return [
      sourcePeerId,
      payload.kind,
      payload.strokeId,
      payload.createdAt,
      payload.points.length,
      first ? `${first.x}:${first.y}` : "empty",
      last ? `${last.x}:${last.y}` : "empty",
    ].join(":");
  }
  if (payload.kind === "remove-stroke") {
    return `${sourcePeerId}:remove:${payload.strokeId}:${payload.createdAt}`;
  }
  if (payload.kind === "object-upsert") {
    return `${sourcePeerId}:object:${payload.object.objectId}:${payload.object.updatedAt}:${payload.createdAt}`;
  }
  if (payload.kind === "remove-object") {
    return `${sourcePeerId}:remove-object:${payload.objectId}:${payload.createdAt}`;
  }
  if (payload.kind === "clear") {
    return `${sourcePeerId}:clear:${payload.clearId}:${payload.createdAt}`;
  }
  if (payload.kind === "snapshot") {
    return `${sourcePeerId}:snapshot:${payload.createdAt}:${payload.strokes.length}`;
  }
  return `${sourcePeerId}:whiteboard:${payload.createdAt}`;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

async function saveUrlAs(
  url: string,
  fileName: string,
  headers: Record<string, string> = {},
  onProgress?: (value: number) => void,
): Promise<Blob> {
  const reportProgress = onProgress ? createProgressReporter(onProgress) : null;
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`下载失败：HTTP ${response.status}`);
  }
  const contentLength = Number(response.headers.get("Content-Length") || 0);
  const chunks: BlobPart[] = [];
  let received = 0;
  if (response.body) {
    const reader = response.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (value) {
        const copy = new Uint8Array(value.byteLength);
        copy.set(value);
        chunks.push(copy.buffer);
        received += value.byteLength;
        reportProgress?.(contentLength > 0 ? transferProgress(received, contentLength) : 0);
      }
    }
  } else {
    const buffer = await response.arrayBuffer();
    chunks.push(buffer);
    received = buffer.byteLength;
  }
  const blob = new Blob(chunks, {
    type: response.headers.get("Content-Type") || "application/octet-stream",
  });
  downloadBlob(blob, fileName);
  reportProgress?.(100, true);
  return blob;
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  triggerUrlDownload(url, fileName);
  window.setTimeout(() => URL.revokeObjectURL(url), 30000);
}

function triggerUrlDownload(url: string, fileName: string) {
  const link = document.createElement("a");
  link.href = url;
  link.download = normalizeDownloadName(fileName);
  link.rel = "noreferrer";
  document.body.appendChild(link);
  link.click();
  link.remove();
}

function normalizeDownloadName(fileName: string) {
  const text = fileName.trim().replace(/[\\/:*?"<>|]+/g, "_");
  return text || "attachment";
}

function loadOrCreateRoomToken(preferred?: string | null) {
  if (preferred) {
    sessionStorage.setItem("public-transfer-room-token", preferred);
    return preferred;
  }
  const existing = sessionStorage.getItem("public-transfer-room-token");
  if (existing) {
    return existing;
  }
  const next = createRoomToken();
  sessionStorage.setItem("public-transfer-room-token", next);
  return next;
}

function loadReceiveConfirmationRequired() {
  return sessionStorage.getItem("public-transfer-receive-confirmation") === "true";
}

function readInitialNetworkMode(): TransferNetworkMode {
  const params = readTransferParams();
  const mode = params.get("mode") || params.get("networkMode");
  const token = params.get("token") || params.get("roomToken");
  return resolveTransferNetworkMode(mode, token);
}

function readInitialRoomId() {
  const params = readTransferParams();
  const room = params.get("room") || params.get("roomId") || sessionStorage.getItem("public-transfer-room-id");
  return normalizeRoomId(room);
}

function readInitialRoomToken() {
  const params = readTransferParams();
  return params.get("token") || params.get("roomToken") || null;
}

function readInitialSharedAttachmentId() {
  const params = readTransferParams();
  const value = params.get("attachmentId") || params.get("file");
  const id = Number(value);
  return Number.isFinite(id) && id > 0 ? id : null;
}

function readTransferParams() {
  const params = new URLSearchParams(window.location.search);
  const queryStart = window.location.hash.indexOf("?");
  if (queryStart >= 0) {
    const hashParams = new URLSearchParams(window.location.hash.slice(queryStart + 1).split("#", 1)[0]);
    hashParams.forEach((value, key) => {
      if (!params.has(key)) {
        params.set(key, value);
      }
    });
  }
  return params;
}

function normalizeRoomId(value: string | null) {
  const text = value?.trim();
  if (!text) {
    return "nearby";
  }
  return text.length > 120 ? text.substring(0, 120) : text;
}

function roomShareUrl(
  roomId: string,
  roomToken: string,
  networkMode: TransferNetworkMode,
  workspacePath = activeWorkspacePath(),
) {
  const url = new URL(workspacePath, window.location.origin);
  url.searchParams.set("mode", networkMode);
  url.searchParams.set("room", normalizeRoomId(roomId));
  if (networkMode === "internet" && roomToken.trim()) {
    url.searchParams.set("token", roomToken.trim());
  }
  return url.toString();
}

function fileShareUrl(attachment: TransferAttachment, roomId: string, roomToken: string) {
  const url = new URL(roomShareUrl(roomId, roomToken, "internet", "/transfer"));
  url.searchParams.set("attachmentId", String(attachment.attachmentId));
  return url.toString();
}

function activeWorkspacePath() {
  const hashRoute = window.location.hash.replace(/^#\/?/, "").split(/[/?#]/, 1)[0];
  const pathRoute = window.location.pathname.replace(/^\/+/, "").split(/[/?#]/, 1)[0];
  return hashRoute === "diagram" || pathRoute === "diagram" ? "/diagram" : "/transfer";
}

function hasDraggedFiles(dataTransfer: DataTransfer) {
  return Array.from(dataTransfer.types ?? []).includes("Files");
}

function filesFromClipboard(dataTransfer: DataTransfer) {
  const itemFiles = Array.from(dataTransfer.items ?? [])
    .filter((item) => item.kind === "file")
    .map((item) => item.getAsFile())
    .filter((file): file is File => file !== null);
  return itemFiles.length > 0 ? itemFiles : Array.from(dataTransfer.files ?? []);
}

function isEditablePasteTarget(target: EventTarget | null) {
  if (!(target instanceof HTMLElement)) {
    return false;
  }
  return target.matches("input, textarea, select, [contenteditable='true'], [role='textbox']")
    || Boolean(target.closest("[contenteditable='true'], [role='textbox']"));
}

async function copyText(value: string) {
  if (!navigator.clipboard?.writeText) {
    throw new Error("当前浏览器不允许自动复制");
  }
  await navigator.clipboard.writeText(value);
}

async function shareOrCopy(data: ShareData, fallbackText: string) {
  if (navigator.share) {
    await navigator.share(data);
    return;
  }
  await copyText(fallbackText);
}

function canUseSystemShare() {
  return typeof navigator.share === "function";
}

function canShareFiles(data: ShareData) {
  return typeof navigator.share === "function"
    && typeof navigator.canShare === "function"
    && navigator.canShare(data);
}

function isShareCancelled(error: unknown) {
  return error instanceof DOMException && error.name === "AbortError";
}

function createRoomToken() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function loadOrCreatePeerId() {
  const existing = sessionStorage.getItem("public-transfer-peer-id");
  if (existing) {
    return existing;
  }
  const next = `web-${createRoomToken().slice(0, 10)}`;
  sessionStorage.setItem("public-transfer-peer-id", next);
  return next;
}

function discoveryWebSocketUrl(roomId: string, peerId: string, roomToken: string, displayName: string) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const params = new URLSearchParams({
    roomId: roomId || "nearby",
    peerId,
    displayName: displayName || peerId,
  });
  if (roomToken.trim()) {
    params.set("roomToken", roomToken.trim());
  }
  return `${protocol}//${window.location.host}/ws/public-transfer/discovery?${params.toString()}`;
}
