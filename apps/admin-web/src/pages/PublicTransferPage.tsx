import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import type {
  ChangeEvent,
  ClipboardEvent as ReactClipboardEvent,
  DragEvent as ReactDragEvent,
  ReactNode,
} from "react";
import {
  Button,
  Chip,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Progress,
  Switch,
} from "@heroui/react";
import { AppLogo } from "../components/AppLogo";
import { useAuth } from "../auth/AuthContext";
import { UserMenuButton } from "../components/UserMenuButton";
import { PublicToolsMenu } from "../components/PublicToolsMenu";
import { HeroRuntime } from "../components/HeroRuntime";
import { ConfirmModal } from "../components/ConfirmModal";
import { SyncedClipboard } from "../components/SyncedClipboard";
import { SyncedWhiteboard, isWhiteboardPayload } from "../components/SyncedWhiteboard";
import type { WhiteboardInboundEvent, WhiteboardPayload } from "../components/SyncedWhiteboard";
import {
  fetchPublicTransferIceConfig,
  publicCheckTransferClientNameAvailability,
  publicCreateTransferWebSocketTicket,
  publicCreateTransferRoomAccessToken,
  publicCreateTransferPairingCode,
  publicCompleteAttachment,
  publicListTransferRoomAccessTokens,
  publicPresignAttachmentDownload,
  publicPresignAttachmentUpload,
  publicRedeemTransferPairingCode,
  publicRevokeTransferRoomAccessToken,
} from "../api/client";
import type {
  AttachmentPresignUploadResponse,
  PublicTransferCreatedAccessToken,
  PublicTransferIceConfig,
  PublicTransferPairingCode,
  PublicTransferRoomAccessToken,
  PublicTransferRoomRole,
  TransferAttachment,
} from "../api/types";
import { usePageSeo } from "../lib/seo";
import { createQrMatrix } from "../lib/qr";
import {
  buildTransferInviteUrl,
  buildTransferNavigationUrl,
  buildTransferPairingUrl,
  normalizeTransferPairingCode,
  selectSafeTransferInviteToken,
} from "../lib/transferInvite";
import { sha256Blob } from "../lib/sha256";
import { effectiveMimeType, mediaKind, previewKindLabel, shortMimeLabel } from "../lib/transferPreview";
import {
  MAX_TRANSFER_ROOM_NAME_LENGTH,
  MAX_TRANSFER_ROOM_TOKEN_LENGTH,
  localizeTransferDiscoveryError,
  resolveTransferPeerSelection,
  resolveTransferNetworkMode,
  validateTransferRoomSettings,
  type TransferNetworkMode,
  type TransferRoomSettingsErrors,
} from "../lib/transferRoom";
import { sendWhiteboardWithFallback } from "../lib/whiteboardTransport";
import { decodeLegacyPeerDisplayName } from "../lib/peerDisplayName";
import {
  clipboardSyncEventKey,
  isClipboardSyncPayload,
  type ClipboardInboundEvent,
  type ClipboardSyncPayload,
} from "../lib/clipboardSync";
import { decodeRelayAppFrame, encodeRelayAppFrame } from "../lib/appMessageProtocol";
import { turnCredentialRefreshDelayMs } from "../lib/directPeerTransport";
import {
  DEFAULT_DIRECT_MEMORY_LIMIT_BYTES,
  receivingTransferKey,
  useDirectTransfer,
  type DirectPendingTransfer,
  type DirectReceivingTransfer,
  type DirectTransferResult,
  type DirectTransferSignalPayload,
  type PeerTransportPath,
} from "../hooks/useDirectTransfer";

const LazySyncedDiagram = lazy(() =>
  import("../components/SyncedDiagram").then((module) => ({ default: module.SyncedDiagram })),
);

type UploadState = "idle" | "connecting" | "waiting" | "direct" | "presigning" | "uploading" | "completing" | "done" | "failed";
type TransferToolMode = "files" | "clipboard" | "whiteboard";
type ClientNameStatus = "idle" | "checking" | "available" | "unavailable" | "error";
type DiscoveryStatus = "connecting" | "online" | "reconnecting" | "offline" | "name-conflict" | "permission-denied";
type OutgoingTransferStatus = "queued" | "connecting" | "sending" | "completed" | "failed" | "cancelled";
type TransferInviteRole = Exclude<PublicTransferRoomRole, "OWNER">;
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
  activityId: string;
  roomEpoch: number;
  roomGeneration: number;
  networkMode: TransferNetworkMode;
  roomId: string;
  roomToken: string;
  targetPeerId: string;
  ossFallbackAllowed: boolean;
  abortController: AbortController;
}

interface QueuedFileTransfer {
  activityId: string;
  file: File;
  roomEpoch: number;
  roomGeneration: number;
  networkMode: TransferNetworkMode;
  roomId: string;
  roomToken: string;
  targetPeerId: string;
  targetPeerLabel: string;
  ossFallbackAllowed: boolean;
}

interface OutgoingTransferActivity {
  id: string;
  file: File;
  fileName: string;
  sizeBytes: number;
  targetPeerId: string;
  targetPeerLabel: string;
  status: OutgoingTransferStatus;
  progress: number;
  transferredBytes: number;
  speedBytesPerSecond: number;
  etaSeconds: number | null;
  transport?: "peer" | "relay" | "cloud";
  error?: string;
  createdAt: number;
  completedAt?: number;
  unread: boolean;
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
const MAX_TRANSFER_CLIENT_NAME_LENGTH = 120;
const TRANSFER_CLIENT_NAME_STORAGE_KEY = "public-transfer-client-name";
const TRANSFER_PEER_ID_STORAGE_KEY = "public-transfer-peer-id";
const TRANSFER_PEER_LEASE_PREFIX = "public-transfer-peer-lease:";
const TRANSFER_PEER_LEASE_TTL_MS = 15_000;
const TRANSFER_PEER_LEASE_REFRESH_MS = 5_000;
const QUICK_INVITE_TTL_SECONDS = 24 * 60 * 60;
const TRANSFER_TOOL_STORAGE_KEY = "public-transfer-active-tool";
const TRANSFER_ACTIVITY_LIMIT = 40;

function readInitialTransferTool(): TransferToolMode {
  const stored = sessionStorage.getItem(TRANSFER_TOOL_STORAGE_KEY);
  return stored === "files" || stored === "clipboard" || stored === "whiteboard" ? stored : "files";
}

function isDiscoveryPermissionError(message: string): boolean {
  return /无权|权限|只读|forbidden|unauthorized|token|口令/i.test(message);
}

function userFacingTransferError(message: string): string {
  const normalized = message.trim();
  if (!normalized) return "发送未完成，请检查双方网络后重试";
  if (/拒绝接收|取消了接收/.test(normalized)) return "对方拒绝接收";
  if (/未确认接收|未确认完成|timeout|timed out|超时/i.test(normalized)) {
    return "等待对方响应超时，请确认对方页面仍然打开后重试";
  }
  if (/TURN|relay|Direct|WebRTC|ICE/i.test(normalized)) {
    return "设备连接未建立，请检查双方网络后重试";
  }
  if (/OSS|presign|object storage/i.test(normalized)) {
    return "云端接力暂时不可用，请稍后重试";
  }
  return normalized;
}

type TransferPeerIdentity = {
  peerId: string;
  leaseOwner: string;
};

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
  const { ready: authReady, authed, openLogin } = useAuth();
  const discoverySocketRef = useRef<WebSocket | null>(null);
  const rosterRevisionRef = useRef(0);
  const loadedSharedAttachmentRef = useRef("");
  const directPreviewUrlsRef = useRef<Set<string>>(new Set());
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const fileDragDepthRef = useRef(0);
  const uploadInFlightRef = useRef<FileTransferTask | null>(null);
  const queuedFileTransfersRef = useRef<QueuedFileTransfer[]>([]);
  const runQueuedTransfersRef = useRef<() => void>(() => undefined);
  const cancelledActivityIdsRef = useRef<Set<string>>(new Set());
  const activeOutgoingActivityIdRef = useRef("");
  const activityProgressSampleRef = useRef<{ activityId: string; at: number; bytes: number } | null>(null);
  const fileTransferTaskSequenceRef = useRef(0);
  const transferActivitySequenceRef = useRef(0);
  const clipboardSeenEventsRef = useRef<Map<string, number>>(new Map());
  const clipboardHighestSequencesRef = useRef<Map<string, { sequence: number; seenAt: number }>>(new Map());
  const whiteboardSendQueuesRef = useRef<Map<string, Promise<void>>>(new Map());
  const whiteboardTransportRetryRef = useRef<Map<string, WhiteboardTransportRetryState>>(new Map());
  const currentRoomPeerIdsRef = useRef<Set<string>>(new Set());
  const currentRoomPeerRolesRef = useRef<Map<string, PublicTransferRoomRole>>(new Map());
  const currentRoomPeerNamesRef = useRef<Map<string, string>>(new Map());
  const roomEpochRef = useRef(0);
  const roomGenerationRef = useRef(0);
  const roomAccessSecretsRef = useRef<Map<string, PublicTransferCreatedAccessToken>>(new Map());
  const roomAccessCreationRef = useRef<Map<string, Promise<PublicTransferCreatedAccessToken>>>(new Map());
  const pairingCodeCreationRef = useRef<Map<string, Promise<PublicTransferPairingCode>>>(new Map());
  const createdRoomAccessContextRef = useRef("");
  const pairingCodeContextRef = useRef("");
  const initialPairingCodeRef = useRef<string | null>(readInitialPairingCode());
  const [peerIdentity] = useState(() => claimTransferPeerIdentity());
  const peerId = peerIdentity.peerId;
  const [displayName, setDisplayName] = useState(() => loadTransferClientName(peerId));
  const [displayNameDraft, setDisplayNameDraft] = useState(displayName);
  const [clientNameStatus, setClientNameStatus] = useState<ClientNameStatus>("available");
  const [clientNameSaving, setClientNameSaving] = useState(false);
  const [clientNameConnectionGeneration, setClientNameConnectionGeneration] = useState(0);
  const [roomSettingsOpen, setRoomSettingsOpen] = useState(false);
  const [roomGeneration, setRoomGeneration] = useState(0);
  const [networkMode, setNetworkMode] = useState<TransferNetworkMode>(() => readInitialNetworkMode());
  const [networkModeTransitionId, setNetworkModeTransitionId] = useState(0);
  const [roomId, setRoomId] = useState(() => readInitialRoomId());
  const [roomToken, setRoomToken] = useState(() => loadOrCreateRoomToken(readInitialRoomToken()));
  const [roomIdDraft, setRoomIdDraft] = useState(roomId);
  const [roomTokenDraft, setRoomTokenDraft] = useState(roomToken);
  const [roomRole, setRoomRole] = useState<PublicTransferRoomRole | null>(null);
  const [roomInviteRole, setRoomInviteRole] = useState<TransferInviteRole>("EDITOR");
  const [roomAccessTokens, setRoomAccessTokens] = useState<PublicTransferRoomAccessToken[]>([]);
  const [createdRoomAccess, setCreatedRoomAccess] = useState<PublicTransferCreatedAccessToken | null>(null);
  const [roomAccessLoading, setRoomAccessLoading] = useState(false);
  const [roomSettingsErrors, setRoomSettingsErrors] = useState<TransferRoomSettingsErrors>({});
  const [receiveConfirmationRequired, setReceiveConfirmationRequired] = useState(() => loadReceiveConfirmationRequired());
  const [qrVisible, setQrVisible] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [pairingCode, setPairingCode] = useState<PublicTransferPairingCode | null>(null);
  const [pairingCodeLoading, setPairingCodeLoading] = useState(false);
  const [pairingCodeDraft, setPairingCodeDraft] = useState("");
  const [pairingCodeRedeeming, setPairingCodeRedeeming] = useState(false);
  const [sharedAttachmentId] = useState(() => readInitialSharedAttachmentId());
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [selectedPeerId, setSelectedPeerId] = useState("");
  const [peers, setPeers] = useState<DiscoveryPeer[]>([]);
  const [incoming, setIncoming] = useState<IncomingAttachment[]>([]);
  const [state, setState] = useState<UploadState>("idle");
  const [outgoingActivities, setOutgoingActivities] = useState<OutgoingTransferActivity[]>([]);
  const [activityCenterOpen, setActivityCenterOpen] = useState(false);
  const [lastViewedFileInboxSignature, setLastViewedFileInboxSignature] = useState("");
  const progressStore = useMemo(() => createTransferProgressStore(), []);
  const setProgress = useCallback((value: number) => progressStore.set(value), [progressStore]);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [discoveryErrorRaw, setDiscoveryError] = useState<string | null>(null);
  const discoveryError = discoveryErrorRaw ? localizeTransferDiscoveryError(discoveryErrorRaw) : null;
  const discoveryErrorDetail = discoveryErrorRaw && discoveryErrorRaw !== discoveryError ? discoveryErrorRaw : null;
  const [discoveryStatus, setDiscoveryStatus] = useState<DiscoveryStatus>("connecting");
  const [transferInterruptAction, setTransferInterruptAction] = useState<{
    title: string;
    description: string;
    action: () => void;
  } | null>(null);
  const [inviteLabelRole, setInviteLabelRole] = useState<TransferInviteRole | null>(null);
  const [inviteLabelDraft, setInviteLabelDraft] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<PublicTransferRoomAccessToken | null>(null);
  const [record, setRecord] = useState<UploadRecord | null>(null);
  const [previewTarget, setPreviewTarget] = useState<PreviewTarget | null>(null);
  const [iceConfig, setIceConfig] = useState<PublicTransferIceConfig | null>(null);
  const [isFileDragActive, setFileDragActive] = useState(false);
  const [activeTool, setActiveTool] = useState<TransferToolMode>(() => readInitialTransferTool());
  const [clipboardFocusRequest, setClipboardFocusRequest] = useState(0);
  const [clipboardHasDraft, setClipboardHasDraft] = useState(false);
  const [whiteboardHasDraft, setWhiteboardHasDraft] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [clipboardEvents, setClipboardEvents] = useState<ClipboardInboundEvent[]>([]);
  const [whiteboardEvents, setWhiteboardEvents] = useState<WhiteboardInboundEvent[]>([]);
  const [diagramEvents, setDiagramEvents] = useState<WhiteboardInboundEvent[]>([]);
  const isDiagramWorkspace = workspace === "diagram";
  const selectedPeerIdRef = useRef(selectedPeerId);
  const discoveryStatusRef = useRef(discoveryStatus);
  selectedPeerIdRef.current = selectedPeerId;
  discoveryStatusRef.current = discoveryStatus;

  useEffect(() => {
    if (!notice) {
      return undefined;
    }
    const timer = window.setTimeout(() => setNotice(null), 5000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    if (state !== "done") {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      setState((current) => current === "done" ? "idle" : current);
    }, 4000);
    return () => window.clearTimeout(timer);
  }, [state]);

  useEffect(() => {
    sessionStorage.setItem(TRANSFER_TOOL_STORAGE_KEY, activeTool);
  }, [activeTool]);

  useEffect(() => {
    if (sharedAttachmentId) {
      setActiveTool("files");
    }
  }, [sharedAttachmentId]);

  useEffect(() => progressStore.subscribe(() => {
    const activityId = activeOutgoingActivityIdRef.current;
    if (!activityId) return;
    const progress = Math.max(0, Math.min(100, progressStore.getSnapshot()));
    const now = Date.now();
    setOutgoingActivities((activities) => activities.map((activity) => {
      if (activity.id !== activityId || activity.status === "cancelled") return activity;
      const transferredBytes = Math.min(activity.sizeBytes, Math.round(activity.sizeBytes * progress / 100));
      const previous = activityProgressSampleRef.current;
      let speedBytesPerSecond = activity.speedBytesPerSecond;
      if (!previous || previous.activityId !== activityId) {
        activityProgressSampleRef.current = { activityId, at: now, bytes: transferredBytes };
      } else if (now - previous.at >= 500 && transferredBytes >= previous.bytes) {
        const sampleSpeed = (transferredBytes - previous.bytes) * 1000 / Math.max(1, now - previous.at);
        speedBytesPerSecond = speedBytesPerSecond > 0
          ? speedBytesPerSecond * 0.65 + sampleSpeed * 0.35
          : sampleSpeed;
        activityProgressSampleRef.current = { activityId, at: now, bytes: transferredBytes };
      }
      const remainingBytes = Math.max(0, activity.sizeBytes - transferredBytes);
      return {
        ...activity,
        status: progress > 0 ? "sending" : activity.status,
        progress,
        transferredBytes,
        speedBytesPerSecond,
        etaSeconds: speedBytesPerSecond > 0 ? Math.ceil(remainingBytes / speedBytesPerSecond) : null,
      };
    }));
  }), [progressStore]);

  useEffect(() => maintainTransferPeerIdentityLease(peerIdentity), [peerIdentity]);

  useEffect(() => {
    if (networkModeTransitionId === 0) {
      return undefined;
    }
    const transitionId = networkModeTransitionId;
    const timer = window.setTimeout(() => {
      setNetworkModeTransitionId((current) => current === transitionId ? 0 : current);
    }, 650);
    return () => window.clearTimeout(timer);
  }, [networkModeTransitionId]);

  usePageSeo({
    title: isDiagramWorkspace ? "专业流程图 · shuai-tunnel" : "互传 · shuai-tunnel",
    description: isDiagramWorkspace
      ? "支持实时协作、draw.io 图形库、多页文档和多格式导入导出的专业流程图工具。"
      : "打开同一个房间链接，在电脑和手机之间互传文件、同步剪贴板和共享白板。",
    canonical: `https://tunnel.devshuai.com/#/${workspace}`,
  });
  const isInternetMode = networkMode === "internet";
  const ossFallbackEnabled = authReady && authed;
  const effectiveRoomRole: PublicTransferRoomRole = isInternetMode ? roomRole ?? "VIEWER" : "EDITOR";
  const isRoomReadOnly = isInternetMode && effectiveRoomRole === "VIEWER";
  const inviteRequestContext = `${normalizeRoomId(roomId)}\u0000${roomToken.trim()}`;
  const inviteRequestContextRef = useRef(inviteRequestContext);
  const roomInviteRoleRef = useRef(roomInviteRole);
  inviteRequestContextRef.current = inviteRequestContext;
  roomInviteRoleRef.current = roomInviteRole;
  const transferRoomScopeKey = `${networkMode}:${normalizeRoomId(roomId)}:${isInternetMode ? roomToken.trim() : "lan"}:${roomGeneration}`;
  const diagramPeerDisplayNames = useMemo(() => Object.fromEntries(
    peers.map((peer) => [peer.peerId, discoveryPeerDisplayName(peer)]),
  ), [peers]);
  const normalizedDisplayNameDraft = displayNameDraft.trim();
  const clientNameLocalError = !normalizedDisplayNameDraft
    ? "客户端名称不能为空"
    : normalizedDisplayNameDraft.length > MAX_TRANSFER_CLIENT_NAME_LENGTH
      ? `客户端名称不能超过 ${MAX_TRANSFER_CLIENT_NAME_LENGTH} 个字符`
      : /[\u0000-\u001f\u007f-\u009f]/.test(normalizedDisplayNameDraft)
        ? "客户端名称不能包含控制字符"
        : "";

  useEffect(() => {
    window.history.replaceState({}, "", buildTransferNavigationUrl({
      origin: window.location.origin,
      workspacePath: `/${workspace}`,
      networkMode,
      roomId,
    }));
  }, [networkMode, roomId, workspace]);

  useEffect(() => {
    roomAccessSecretsRef.current.clear();
    roomAccessCreationRef.current.clear();
    pairingCodeCreationRef.current.clear();
    createdRoomAccessContextRef.current = "";
    pairingCodeContextRef.current = "";
    setCreatedRoomAccess(null);
    setRoomAccessLoading(false);
    setPairingCode(null);
    setPairingCodeLoading(false);
    setInviteError(null);
  }, [roomId, roomToken]);

  useEffect(() => {
    if (clientNameLocalError) {
      setClientNameStatus("idle");
      return;
    }
    if (normalizedDisplayNameDraft === displayName) {
      setClientNameStatus("available");
      return;
    }

    let active = true;
    setClientNameStatus("checking");
    const timer = window.setTimeout(() => {
      void publicCheckTransferClientNameAvailability(normalizedDisplayNameDraft, peerId)
        .then((result) => {
          if (active) {
            setClientNameStatus(result.available ? "available" : "unavailable");
          }
        })
        .catch(() => {
          if (active) {
            setClientNameStatus("error");
          }
        });
    }, 300);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [clientNameLocalError, displayName, normalizedDisplayNameDraft, peerId]);

  const applyClientName = async () => {
    if (clientNameLocalError) {
      return false;
    }
    setClientNameSaving(true);
    try {
      const result = await publicCheckTransferClientNameAvailability(normalizedDisplayNameDraft, peerId);
      if (!result.available) {
        setClientNameStatus("unavailable");
        return false;
      }
      storeTransferClientName(peerId, result.clientName);
      setDisplayNameDraft(result.clientName);
      setDisplayName(result.clientName);
      setClientNameConnectionGeneration((generation) => generation + 1);
      setClientNameStatus("available");
      setError(null);
      setNotice("客户端名称已更新");
      return true;
    } catch (err) {
      setClientNameStatus("error");
      setError(err instanceof Error ? err.message : "客户端名称校验失败");
      return false;
    } finally {
      setClientNameSaving(false);
    }
  };

  const retryDiscoveryConnection = () => {
    setDiscoveryError(null);
    setDiscoveryStatus("connecting");
    setClientNameConnectionGeneration((generation) => generation + 1);
  };

  const updateOutgoingActivity = useCallback((
    activityId: string,
    update: Partial<OutgoingTransferActivity> | ((activity: OutgoingTransferActivity) => Partial<OutgoingTransferActivity>),
  ) => {
    setOutgoingActivities((activities) => activities.map((activity) => {
      if (activity.id !== activityId) return activity;
      return { ...activity, ...(typeof update === "function" ? update(activity) : update) };
    }));
  }, []);

  const completeOutgoingActivity = useCallback((
    activityId: string,
    transport: OutgoingTransferActivity["transport"],
  ) => {
    updateOutgoingActivity(activityId, (activity) => ({
      status: "completed",
      progress: 100,
      transport,
      transferredBytes: activity.sizeBytes,
      speedBytesPerSecond: 0,
      etaSeconds: 0,
      completedAt: Date.now(),
      unread: true,
      error: undefined,
    }));
  }, [updateOutgoingActivity]);

  const failOutgoingActivity = useCallback((activityId: string, message: string) => {
    updateOutgoingActivity(activityId, {
      status: "failed",
      completedAt: Date.now(),
      unread: true,
      error: userFacingTransferError(message),
      etaSeconds: null,
    });
  }, [updateOutgoingActivity]);

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
    if (items.length > INCOMING_ITEM_LIMIT) {
      setNotice(`收到的文件较多，仅保留最新 ${INCOMING_ITEM_LIMIT} 条`);
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
    const event = {
      eventId,
      sourcePeerId,
      payload,
      receivedAt: Date.now(),
    };
    if (payload.type === "STDG2") {
      setDiagramEvents((items) => [...items.slice(-999), event]);
    } else {
      setWhiteboardEvents((items) => [...items.slice(-299), event]);
    }
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
        sourceDisplayName: currentRoomPeerNamesRef.current.get(sourcePeerId) ?? "未命名设备",
        payload,
        receivedAt,
      },
    ]);
  }, [peerId]);

  const {
    pendingTransfers,
    receivingTransfers,
    peerTransportPaths,
    sendDirect,
    sendPeerMessage,
    sendRelayPeerMessage,
    handleRelayPeerFrame,
    isPeerMessageTransportReady,
    handleSignal,
    acceptIncomingTransfer,
    rejectIncomingTransfer,
    cancelIncomingTransfer,
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
    onStateChange: (nextState) => {
      setState(nextState);
      const activityId = activeOutgoingActivityIdRef.current;
      if (activityId) {
        updateOutgoingActivity(activityId, {
          status: nextState === "connecting" || nextState === "waiting" ? "connecting" : "sending",
        });
      }
    },
    onProgress: setProgress,
    onError: (message) => setError(userFacingTransferError(message)),
  });

  useEffect(() => {
    let active = true;
    let refreshTimer: number | null = null;
    let refreshInFlight = false;
    const scheduleRefresh = async () => {
      if (!active || refreshInFlight) {
        return;
      }
      refreshInFlight = true;
      const config = await fetchPublicTransferIceConfig();
      refreshInFlight = false;
      if (!active) {
        return;
      }
      const transferActive = uploadInFlightRef.current !== null;
      if (config && !transferActive) {
        setIceConfig(config);
      }
      refreshTimer = window.setTimeout(
        () => void scheduleRefresh(),
        transferActive ? 30_000 : turnCredentialRefreshDelayMs(config),
      );
    };
    const refreshWhenVisible = () => {
      if (document.visibilityState !== "visible") {
        return;
      }
      if (refreshTimer !== null) {
        window.clearTimeout(refreshTimer);
        refreshTimer = null;
      }
      void scheduleRefresh();
    };
    void scheduleRefresh();
    document.addEventListener("visibilitychange", refreshWhenVisible);
    window.addEventListener("online", refreshWhenVisible);
    return () => {
      active = false;
      if (refreshTimer !== null) {
        window.clearTimeout(refreshTimer);
      }
      document.removeEventListener("visibilitychange", refreshWhenVisible);
      window.removeEventListener("online", refreshWhenVisible);
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
    if (!isInternetMode || !sharedAttachmentId || !roomToken.trim() || !authReady) {
      return;
    }
    if (!authed) {
      setError("该文件使用云端存储，请登录后下载");
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
  }, [authReady, authed, isInternetMode, roomToken, sharedAttachmentId]);

  useEffect(() => {
    let active = true;
    let reconnectTimer: number | null = null;
    let heartbeatTimer: number | null = null;
    let reconnectAttempt = 0;
    let reconnectBlocked = false;
    let lastPongAt = Date.now();
    rosterRevisionRef.current = 0;
    setRoomRole(isInternetMode ? null : "EDITOR");
    setDiscoveryStatus("connecting");

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
      if (typeof event.data !== "string") {
        const read = event.data instanceof ArrayBuffer
          ? Promise.resolve(event.data)
          : event.data instanceof Blob
            ? event.data.arrayBuffer()
            : Promise.reject(new Error("unsupported websocket payload"));
        void read.then((buffer) => {
          const routed = decodeRelayAppFrame(buffer);
          if (routed.targetPeerId !== peerId || !routed.sourcePeerId
            || !currentRoomPeerIdsRef.current.has(routed.sourcePeerId)) {
            return;
          }
          return handleRelayPeerFrame(routed.sourcePeerId, routed.appFrame, (targetPeerId, reply) => {
            const socket = discoverySocketRef.current;
            if (socket?.readyState === WebSocket.OPEN) {
              socket.send(encodeRelayAppFrame(targetPeerId, "", reply));
            }
          });
        }).catch(() => {
          // Invalid binary relay frames are isolated from the discovery control channel.
        });
        return;
      }
      try {
        const message = JSON.parse(event.data) as {
          type?: string;
          error?: string;
          sourcePeerId?: string;
          targetPeerId?: string;
          peers?: DiscoveryPeer[];
          rosterRevision?: number;
          roomRole?: PublicTransferRoomRole;
          payload?: unknown;
        };
        if (message.type === "pong") {
          lastPongAt = Date.now();
        } else if (message.type === "hello") {
          setClientNameStatus("available");
          setDiscoveryError(null);
          if (message.roomRole) {
            setRoomRole(message.roomRole);
          }
          if (Number.isSafeInteger(message.rosterRevision) && (message.rosterRevision ?? 0) >= 0) {
            rosterRevisionRef.current = Math.max(rosterRevisionRef.current, message.rosterRevision ?? 0);
          }
        } else if (message.type === "error" && message.error) {
          if (message.error === "client name is already in use") {
            reconnectBlocked = true;
            setClientNameStatus("unavailable");
            setDiscoveryStatus("name-conflict");
            setDiscoveryError("客户端名称已被其他在线设备使用，请修改后重试");
          } else if (message.error === "client name is required"
            || message.error === "client name is too long"
            || message.error === "client name contains invalid characters") {
            reconnectBlocked = true;
            setClientNameStatus("error");
            setDiscoveryStatus("name-conflict");
            setDiscoveryError("客户端名称无效，请修改后重试");
          } else {
            const localized = localizeTransferDiscoveryError(message.error);
            const permissionDenied = isDiscoveryPermissionError(localized);
            if (permissionDenied) {
              reconnectBlocked = true;
              setDiscoveryStatus("permission-denied");
            }
            setDiscoveryError(message.error);
          }
        } else if (message.type === "roster" && Array.isArray(message.peers)) {
          const revision = Number.isSafeInteger(message.rosterRevision) && (message.rosterRevision ?? 0) >= 0
            ? message.rosterRevision ?? 0
            : 0;
          if (revision > 0 && revision < rosterRevisionRef.current) {
            return;
          }
          rosterRevisionRef.current = Math.max(rosterRevisionRef.current, revision);
          const visiblePeers = message.peers.filter((peer) => peer.peerId !== peerId);
          currentRoomPeerIdsRef.current = new Set(visiblePeers.map((peer) => peer.peerId));
          currentRoomPeerRolesRef.current = new Map(
            visiblePeers.flatMap((peer) => peer.roomRole ? [[peer.peerId, peer.roomRole] as const] : []),
          );
          currentRoomPeerNamesRef.current = new Map(
            visiblePeers.map((peer) => [peer.peerId, discoveryPeerDisplayName(peer)]),
          );
          setPeers(visiblePeers);
          if (!isDiagramWorkspace) {
            const currentSelectedPeerId = selectedPeerIdRef.current;
            const nextSelectedPeerId = resolveTransferPeerSelection(
              currentSelectedPeerId,
              visiblePeers.map((peer) => peer.peerId),
            );
            if (nextSelectedPeerId !== currentSelectedPeerId) {
              selectedPeerIdRef.current = nextSelectedPeerId;
              setSelectedPeerId(nextSelectedPeerId);
              const nextPeer = visiblePeers.find((peer) => peer.peerId === nextSelectedPeerId);
              if (currentSelectedPeerId && nextPeer) {
                setNotice(`原设备已离线，已切换到 ${discoveryPeerDisplayName(nextPeer)}`);
              } else if (currentSelectedPeerId) {
                setNotice("原设备已离线，当前没有可发送设备");
              } else if (nextPeer) {
                setNotice(`已默认选择 ${discoveryPeerDisplayName(nextPeer)}`);
              }
            }
          }
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

    const scheduleReconnect = () => {
      if (!active || reconnectBlocked) {
        return;
      }
      setDiscoveryStatus(reconnectAttempt >= 4 ? "offline" : "reconnecting");
      const delayMs = Math.min(1000 * (2 ** Math.min(reconnectAttempt, 4)), 10000);
      reconnectAttempt += 1;
      reconnectTimer = window.setTimeout(() => void connect(), delayMs);
    };

    async function connect() {
      if (!active) {
        return;
      }
      setDiscoveryStatus(reconnectAttempt > 0 ? "reconnecting" : "connecting");
      let ticket: string;
      try {
        const issued = await publicCreateTransferWebSocketTicket({
          roomId,
          peerId,
          roomToken: isInternetMode ? roomToken : "",
          displayName,
        });
        ticket = issued.ticket;
      } catch (ticketError) {
        if (active) {
          const rawMessage = ticketError instanceof Error ? ticketError.message : "建立房间连接失败";
          const localized = localizeTransferDiscoveryError(rawMessage);
          if (isDiscoveryPermissionError(localized)) {
            reconnectBlocked = true;
            setDiscoveryStatus("permission-denied");
          } else {
            setDiscoveryStatus(reconnectAttempt >= 4 ? "offline" : "reconnecting");
          }
          setDiscoveryError(rawMessage);
          scheduleReconnect();
        }
        return;
      }
      if (!active) {
        return;
      }
      const url = discoveryWebSocketUrl(ticket);
      const socket = new WebSocket(url);
      socket.binaryType = "arraybuffer";
      discoverySocketRef.current = socket;
      socket.onopen = () => {
        if (!active || discoverySocketRef.current !== socket) {
          socket.close();
          return;
        }
        reconnectAttempt = 0;
        lastPongAt = Date.now();
        setDiscoveryStatus("online");
        setDiscoveryError(null);
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
        scheduleReconnect();
      };
    }

    void connect();

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
  }, [clientNameConnectionGeneration, displayName, handleRelayPeerFrame, handleSignal, isDiagramWorkspace, isInternetMode, peerId, pushClipboardEvent, pushWhiteboardEvent, roomId, roomToken]);

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

  const safeRoomInviteToken = useMemo(() => selectSafeTransferInviteToken({
    networkMode,
    currentRole: roomRole,
    currentRoomToken: roomToken,
    explicitInvite: createdRoomAccess
      && createdRoomAccessContextRef.current === inviteRequestContext
      && createdRoomAccess.access.role === roomInviteRole
      && isRoomAccessUsable(createdRoomAccess)
      ? { role: createdRoomAccess.access.role, token: createdRoomAccess.token }
      : undefined,
  }), [createdRoomAccess, inviteRequestContext, networkMode, roomInviteRole, roomRole, roomToken]);
  const roomJoinUrl = useMemo(() => buildTransferInviteUrl({
    origin: window.location.origin,
    workspacePath: `/${workspace}`,
    networkMode,
    roomId,
    token: safeRoomInviteToken,
  }), [networkMode, roomId, safeRoomInviteToken, workspace]);
  const pairingJoinUrl = useMemo(() => pairingCode
    && pairingCodeContextRef.current === inviteRequestContext
    && pairingCode.role === roomInviteRole
    && isPairingCodeUsable(pairingCode)
    ? buildTransferPairingUrl({
      origin: window.location.origin,
      workspacePath: `/${workspace}`,
      code: pairingCode.code,
    })
    : null, [inviteRequestContext, pairingCode, roomInviteRole, workspace]);
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
      ? `将发送给 ${discoveryPeerDisplayName(selectedPeer)}`
      : isInternetMode
        ? ossFallbackEnabled
          ? "未选择对方时会上传并生成分享链接"
          : "匿名模式需先选择在线设备"
        : "附近模式需先选择在线设备"
    : selectedFiles.length === 1
      ? `${formatBytes(selectedFiles[0].size)} · ${selectedFiles[0].type || "未知类型"}`
      : `${formatBytes(selectedFilesSize)} · 批量顺序发送`;
  const isTransferBusy = state === "connecting"
    || state === "waiting"
    || state === "direct"
    || state === "presigning"
    || state === "uploading"
    || state === "completing";
  const selectTransferPeer = (peer: DiscoveryPeer) => {
    const currentPeerId = selectedPeerIdRef.current;
    if (currentPeerId === peer.peerId) {
      return;
    }
    const currentPeer = peers.find((item) => item.peerId === currentPeerId);
    selectedPeerIdRef.current = peer.peerId;
    setSelectedPeerId(peer.peerId);
    setNotice(currentPeer
      ? `发送目标已从 ${discoveryPeerDisplayName(currentPeer)} 切换为 ${discoveryPeerDisplayName(peer)}`
      : `已选择 ${discoveryPeerDisplayName(peer)}`);
  };
  const fileTargetRequired = networkMode === "lan" || !ossFallbackEnabled;
  const fileDropzoneTitle = isFileDragActive
    ? "松开即可发送"
    : fileTargetRequired && !selectedPeer
      ? peers.length === 0 ? "先邀请接收设备" : "先选择接收设备"
      : isTransferBusy
        ? "继续添加文件"
        : "选择或拖入文件";
  const fileDropzoneDetail = selectedFiles.length > 0
    ? `${selectedFileTitle} · ${selectedFileDetail}`
    : selectedPeer
      ? `选择后立即发送给 ${discoveryPeerDisplayName(selectedPeer)}`
      : isInternetMode
        ? ossFallbackEnabled
          ? "未选择设备时会生成短期分享链接"
          : "匿名使用需要先选择在线设备"
        : peers.length === 0 ? "邀请同一网络中的设备加入房间" : "从设备列表选择接收方";
  const fileActivityCount = outgoingActivities.length + incoming.length + receivingTransfers.length + pendingTransfers.length;
  const fileInboxSignature = useMemo(() => {
    const keys = new Set<string>();
    pendingTransfers.forEach((item) => keys.add(`direct:${receivingTransferKey(item)}`));
    receivingTransfers.forEach((item) => keys.add(`direct:${receivingTransferKey(item)}`));
    incoming.forEach((item) => keys.add(`received:${item.sourcePeerId}:${item.attachment.attachmentId}`));
    return Array.from(keys).sort().join("|");
  }, [incoming, pendingTransfers, receivingTransfers]);
  useEffect(() => {
    if (activeTool === "files") setLastViewedFileInboxSignature(fileInboxSignature);
  }, [activeTool, fileInboxSignature]);
  const activeOutgoingCount = outgoingActivities.filter((activity) => (
    activity.status === "queued" || activity.status === "connecting" || activity.status === "sending"
  )).length;
  const activeOutgoingActivity = outgoingActivities.find((activity) => (
    activity.status === "connecting" || activity.status === "sending"
  )) ?? outgoingActivities.find((activity) => activity.status === "queued") ?? null;
  const unreadIncomingFileCount = activeTool !== "files"
    && fileInboxSignature !== lastViewedFileInboxSignature
    ? incoming.length + receivingTransfers.length + pendingTransfers.length
    : 0;
  const unreadFileActivityCount = outgoingActivities.filter((activity) => activity.unread).length
    + unreadIncomingFileCount;
  const hasRecoverableRoomContent = isTransferBusy
    || activeOutgoingCount > 0
    || selectedFiles.length > 0
    || incoming.length > 0
    || receivingTransfers.length > 0
    || pendingTransfers.length > 0
    || Boolean(record)
    || clipboardHasDraft
    || whiteboardHasDraft;

  const requestRoomContextChange = (
    title: string,
    description: string,
    action: () => void,
  ) => {
    if (!hasRecoverableRoomContent) {
      action();
      return;
    }
    setTransferInterruptAction({
      title,
      description: `${description} 剪贴板和白板草稿会保留在当前房间，重新进入后可恢复。`,
      action,
    });
  };

  const resetTransferRoomState = (preserveCompletedFile = false) => {
    roomEpochRef.current += 1;
    roomGenerationRef.current += 1;
    setRoomGeneration(roomGenerationRef.current);
    const activeFileTransfer = uploadInFlightRef.current;
    if (activeFileTransfer) {
      updateOutgoingActivity(activeFileTransfer.activityId, {
        status: "cancelled",
        completedAt: Date.now(),
        unread: true,
        error: "房间已切换",
      });
      uploadInFlightRef.current = null;
      activeFileTransfer.abortController.abort();
    }
    const queuedActivityIds = queuedFileTransfersRef.current.map((item) => item.activityId);
    queuedFileTransfersRef.current = [];
    if (queuedActivityIds.length > 0) {
      setOutgoingActivities((activities) => activities.map((activity) => (
        queuedActivityIds.includes(activity.id)
          ? { ...activity, status: "cancelled", completedAt: Date.now(), unread: true, error: "房间已切换" }
          : activity
      )));
    }
    activeOutgoingActivityIdRef.current = "";
    activityProgressSampleRef.current = null;
    invalidateConnections();
    const socket = discoverySocketRef.current;
    if (socket) {
      discoverySocketRef.current = null;
      socket.close();
    }
    currentRoomPeerIdsRef.current.clear();
    currentRoomPeerRolesRef.current.clear();
    currentRoomPeerNamesRef.current.clear();
    clipboardSeenEventsRef.current.clear();
    clipboardHighestSequencesRef.current.clear();
    whiteboardSendQueuesRef.current.clear();
    whiteboardTransportRetryRef.current.clear();
    setClipboardEvents([]);
    setWhiteboardEvents([]);
    setDiagramEvents([]);
    setPeers([]);
    selectedPeerIdRef.current = "";
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
    requestRoomContextChange(
      "切换连接范围？",
      isTransferBusy ? "正在发送的文件会被取消。" : "当前房间连接和未保存的接收文件会暂时离开。",
      () => applyNetworkMode(nextMode),
    );
  };

  const applyNetworkMode = (nextMode: TransferNetworkMode) => {
    let nextToken = roomToken.trim();
    if (nextMode === "internet"
      && validateTransferRoomSettings(roomId, nextToken).errors.roomToken) {
      nextToken = createRoomToken();
    }

    resetTransferRoomState();
    clearIncomingItems();
    setNetworkMode(nextMode);
    setNetworkModeTransitionId((current) => current + 1);
    setRoomToken(nextToken);
    setRoomTokenDraft(nextToken);
    setRoomSettingsErrors({});
    setQrVisible(false);
    if (nextToken) {
      sessionStorage.setItem("public-transfer-room-token", nextToken);
    }
    window.history.replaceState({}, "", buildTransferNavigationUrl({
      origin: window.location.origin,
      workspacePath: `/${workspace}`,
      networkMode: nextMode,
      roomId,
    }));
    setNotice(nextMode === "lan"
      ? "已切换到附近模式，仅使用设备点对点传输"
      : "已切换到远程模式，可使用中继和云端接力");
    setDiscoveryError(null);
    setError(null);
  };

  const commitRoomSettings = (validation: ReturnType<typeof validateTransferRoomSettings>) => {
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
    window.history.replaceState({}, "", buildTransferNavigationUrl({
      origin: window.location.origin,
      workspacePath: `/${workspace}`,
      networkMode,
      roomId: validation.roomId,
    }));
    setRoomSettingsOpen(false);
    setNotice(changed ? "房间设置已保存" : "房间设置没有变化");
    setDiscoveryError(null);
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

    const changed = validation.roomId !== roomId
      || (isInternetMode && validation.roomToken !== roomToken);
    if (changed) {
      requestRoomContextChange(
        "保存并切换房间？",
        isTransferBusy ? "正在发送的文件会被取消。" : "当前连接和未保存的接收文件会暂时离开。",
        () => commitRoomSettings(validation),
      );
      return;
    }
    commitRoomSettings(validation);
  };

  const saveRoomSettings = async () => {
    if (normalizedDisplayNameDraft !== displayName) {
      const saved = await applyClientName();
      if (!saved) return;
    }
    applyRoomSettings();
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
    requestRoomContextChange(
      "创建新房间？",
      isTransferBusy ? "正在发送的文件会被取消。" : "当前连接和未保存的接收文件会暂时离开。",
      applyNewRoom,
    );
  };

  const applyNewRoom = () => {
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
    window.history.replaceState({}, "", buildTransferNavigationUrl({
      origin: window.location.origin,
      workspacePath: `/${workspace}`,
      networkMode,
      roomId: nextRoom,
    }));
    setNotice("已创建新房间");
    setRoomSettingsOpen(false);
    setDiscoveryError(null);
    setError(null);
  };

  const issueRoomAccess = async (
    role: TransferInviteRole,
    label: string,
    force = false,
  ): Promise<PublicTransferCreatedAccessToken> => {
    if (!isInternetMode || roomRole !== "OWNER") {
      throw new Error(roomRole === null ? "正在确认房间权限，请稍候" : "只有房主可以生成安全邀请");
    }
    const requestContext = inviteRequestContext;
    const requestKey = `${requestContext}\u0000${role}`;
    const cached = roomAccessSecretsRef.current.get(requestKey);
    if (!force && cached && isRoomAccessUsable(cached)) {
      if (roomInviteRoleRef.current === role) {
        createdRoomAccessContextRef.current = requestContext;
        setCreatedRoomAccess(cached);
        setRoomAccessLoading(false);
      }
      return cached;
    }
    const pending = roomAccessCreationRef.current.get(requestKey);
    if (!force && pending) {
      if (roomInviteRoleRef.current === role) setRoomAccessLoading(true);
      return pending;
    }

    if (roomInviteRoleRef.current === role) setRoomAccessLoading(true);
    const request = publicCreateTransferRoomAccessToken(
      roomId,
      { roomToken, peerId },
      role,
      label,
      QUICK_INVITE_TTL_SECONDS,
    );
    roomAccessCreationRef.current.set(requestKey, request);
    try {
      const created = await request;
      if (inviteRequestContextRef.current !== requestContext) {
        throw new Error("房间已切换，请重新生成邀请");
      }
      roomAccessSecretsRef.current.set(requestKey, created);
      if (roomInviteRoleRef.current === role) {
        createdRoomAccessContextRef.current = requestContext;
        setCreatedRoomAccess(created);
      }
      setRoomAccessTokens((items) => [created.access, ...items.filter((item) => item.id !== created.access.id)]);
      return created;
    } finally {
      if (roomAccessCreationRef.current.get(requestKey) === request) {
        roomAccessCreationRef.current.delete(requestKey);
        if (inviteRequestContextRef.current === requestContext && roomInviteRoleRef.current === role) {
          setRoomAccessLoading(false);
        }
      }
    }
  };

  const issuePairingCode = async (role: TransferInviteRole, force = false) => {
    if (!isInternetMode || roomRole !== "OWNER") {
      throw new Error(roomRole === null ? "正在确认房间权限，请稍候" : "只有房主可以生成配对码");
    }
    const requestContext = inviteRequestContext;
    const requestKey = `${requestContext}\u0000${role}`;
    if (!force
      && pairingCodeContextRef.current === requestContext
      && pairingCode?.role === role
      && isPairingCodeUsable(pairingCode)) {
      if (roomInviteRoleRef.current === role) setPairingCodeLoading(false);
      return pairingCode;
    }
    const pending = pairingCodeCreationRef.current.get(requestKey);
    if (!force && pending) {
      if (roomInviteRoleRef.current === role) setPairingCodeLoading(true);
      return pending;
    }

    if (roomInviteRoleRef.current === role) setPairingCodeLoading(true);
    const request = publicCreateTransferPairingCode(
      roomId,
      { roomToken, peerId },
      role,
      role === "EDITOR" ? "临时编辑配对" : "临时只读配对",
      1,
    );
    pairingCodeCreationRef.current.set(requestKey, request);
    try {
      const created = await request;
      if (inviteRequestContextRef.current !== requestContext) {
        throw new Error("房间已切换，请重新生成配对码");
      }
      if (roomInviteRoleRef.current === role) {
        pairingCodeContextRef.current = requestContext;
        setPairingCode(created);
      }
      return created;
    } finally {
      if (pairingCodeCreationRef.current.get(requestKey) === request) {
        pairingCodeCreationRef.current.delete(requestKey);
        if (inviteRequestContextRef.current === requestContext && roomInviteRoleRef.current === role) {
          setPairingCodeLoading(false);
        }
      }
    }
  };

  const resolveSafeRoomInviteUrl = async (role = roomInviteRole) => {
    if (!isInternetMode) {
      return buildTransferInviteUrl({
        origin: window.location.origin,
        workspacePath: `/${workspace}`,
        networkMode,
        roomId,
      });
    }
    const created = await issueRoomAccess(
      role,
      role === "EDITOR" ? "24 小时编辑邀请" : "24 小时只读邀请",
    );
    return buildTransferInviteUrl({
      origin: window.location.origin,
      workspacePath: `/${workspace}`,
      networkMode,
      roomId,
      token: created.token,
    });
  };

  const prepareSecureInvite = async (role = roomInviteRole) => {
    if (!isInternetMode) return;
    setInviteError(null);
    try {
      await Promise.all([
        issueRoomAccess(role, role === "EDITOR" ? "24 小时编辑邀请" : "24 小时只读邀请"),
        issuePairingCode(role),
      ]);
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : "准备邀请失败");
    }
  };

  const openInvitePanel = () => {
    setInviteError(null);
    setInviteOpen(true);
  };

  const copyRoomLink = async () => {
    try {
      const url = await resolveSafeRoomInviteUrl();
      if (!url) throw new Error("安全邀请尚未生成");
      await copyText(url);
      setNotice(isInternetMode ? "24 小时限权邀请已复制" : "附近房间链接已复制");
      setError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : "复制房间链接失败";
      setInviteError(message);
      setError(message);
    }
  };

  const shareRoom = async () => {
    try {
      const url = await resolveSafeRoomInviteUrl();
      if (!url) throw new Error("安全邀请尚未生成");
      await shareOrCopy(
        {
          title: isDiagramWorkspace ? "加入 shuai-tunnel 流程图房间" : "加入 shuai-tunnel 互传房间",
          text: `${isInternetMode ? "远程" : "附近"}房间：${transferRoomDisplayName(roomId)}`,
          url,
        },
        url,
      );
      setNotice(canUseSystemShare() ? "已打开系统分享" : "安全邀请已复制");
      setError(null);
    } catch (err) {
      if (isShareCancelled(err)) return;
      const message = err instanceof Error ? err.message : "分享房间失败";
      setInviteError(message);
      setError(message);
    }
  };

  const showRoomQr = () => {
    setQrVisible(true);
    setNotice(isInternetMode
      ? "正在生成一次性扫码邀请"
      : "二维码已生成，请使用同一网络中的设备扫码");
    setError(null);
    if (isInternetMode) void prepareSecureInvite();
  };

  const createRoomAccess = (role: "EDITOR" | "VIEWER") => {
    setInviteLabelDraft(role === "EDITOR" ? "编辑者邀请" : "只读访客邀请");
    setInviteLabelRole(role);
  };

  const confirmCreateRoomAccess = async () => {
    const role = inviteLabelRole;
    const label = inviteLabelDraft.trim();
    if (!role || !label) return;
    setInviteLabelRole(null);
    try {
      await issueRoomAccess(role, label, true);
      setNotice(`已创建 24 小时${role === "EDITOR" ? "编辑者" : "只读访客"}邀请，请立即复制链接。`);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "创建房间邀请失败");
    }
  };

  const revokeRoomAccess = (access: PublicTransferRoomAccessToken) => {
    setRevokeTarget(access);
  };

  const confirmRevokeRoomAccess = async () => {
    const access = revokeTarget;
    if (!access) return;
    setRoomAccessLoading(true);
    try {
      const revoked = await publicRevokeTransferRoomAccessToken(roomId, access.id, { roomToken, peerId });
      setRoomAccessTokens((items) => items.map((item) => item.id === revoked.id ? revoked : item));
      if (createdRoomAccess?.access.id === revoked.id) {
        createdRoomAccessContextRef.current = "";
        setCreatedRoomAccess(null);
      }
      const requestKey = `${inviteRequestContext}\u0000${access.role}`;
      const cached = roomAccessSecretsRef.current.get(requestKey);
      if (cached?.access.id === revoked.id) roomAccessSecretsRef.current.delete(requestKey);
      setNotice("邀请已撤销");
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "撤销房间邀请失败");
    } finally {
      setRoomAccessLoading(false);
    }
  };

  const copyCreatedRoomAccessLink = async () => {
    if (!createdRoomAccess || !isRoomAccessUsable(createdRoomAccess)) return;
    try {
      const url = buildTransferInviteUrl({
        origin: window.location.origin,
        workspacePath: `/${workspace}`,
        networkMode: "internet",
        roomId,
        token: createdRoomAccess.token,
      });
      if (!url) throw new Error("邀请已失效，请重新生成");
      await copyText(url);
      setNotice("邀请链接已复制");
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "复制邀请链接失败");
    }
  };

  const regeneratePairingCode = async () => {
    setInviteError(null);
    try {
      await issuePairingCode(roomInviteRole, true);
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : "生成配对码失败");
    }
  };

  const regenerateSecureInvite = async () => {
    if (!isInternetMode) return;
    setInviteError(null);
    try {
      await Promise.all([
        issueRoomAccess(
          roomInviteRole,
          roomInviteRole === "EDITOR" ? "24 小时编辑邀请" : "24 小时只读邀请",
          true,
        ),
        issuePairingCode(roomInviteRole, true),
      ]);
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : "重新生成邀请失败");
    }
  };

  const redeemPairingCode = async (rawCode = pairingCodeDraft) => {
    const normalizedCode = normalizeTransferPairingCode(rawCode);
    if (!normalizedCode) {
      setInviteError("请输入完整的 8 位配对码");
      return;
    }
    setPairingCodeRedeeming(true);
    setInviteError(null);
    try {
      const redeemed = await publicRedeemTransferPairingCode(normalizedCode, peerId);
      const applyRedeemedRoom = () => {
        resetTransferRoomState();
        clearIncomingItems();
        setNetworkMode("internet");
        setNetworkModeTransitionId((current) => current + 1);
        setRoomId(redeemed.roomId);
        setRoomToken(redeemed.roomToken);
        setRoomIdDraft(redeemed.roomId);
        setRoomTokenDraft(redeemed.roomToken);
        setRoomRole(redeemed.role);
        setRoomSettingsErrors({});
        setPairingCodeDraft("");
        sessionStorage.setItem("public-transfer-room-id", redeemed.roomId);
        sessionStorage.setItem("public-transfer-room-token", redeemed.roomToken);
        window.history.replaceState({}, "", buildTransferNavigationUrl({
          origin: window.location.origin,
          workspacePath: `/${workspace}`,
          networkMode: "internet",
          roomId: redeemed.roomId,
        }));
        setInviteOpen(false);
        setNotice(`配对成功，已以${redeemed.role === "EDITOR" ? "可编辑" : "只读"}身份加入 ${redeemed.roomId}`);
        setDiscoveryError(null);
        setError(null);
      };
      if (hasRecoverableRoomContent) {
        setTransferInterruptAction({
          title: "加入新的远程房间？",
          description: "当前房间内容会保留为本地草稿，正在传输的文件将取消。",
          action: applyRedeemedRoom,
        });
      } else {
        applyRedeemedRoom();
      }
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : "配对码无效或已过期");
      setPairingCodeDraft(formatPairingCode(normalizedCode));
      setInviteOpen(true);
    } finally {
      setPairingCodeRedeeming(false);
    }
  };

  useEffect(() => {
    const initialCode = initialPairingCodeRef.current;
    if (!initialCode) return;
    initialPairingCodeRef.current = null;
    void redeemPairingCode(initialCode);
  }, []);

  useEffect(() => {
    if (!inviteOpen || !isInternetMode || roomRole !== "OWNER") return;
    void prepareSecureInvite(roomInviteRole);
  }, [inviteOpen, isInternetMode, roomId, roomInviteRole, roomRole, roomToken]);

  const resolveSafeFileShareUrl = async (attachment: TransferAttachment) => {
    const created = await issueRoomAccess("VIEWER", "24 小时文件查看邀请");
    return fileShareUrl(attachment, roomId, created.token);
  };

  const shareRecordFile = async () => {
    if (!record) {
      return;
    }
    if (!record.direct && !ossFallbackEnabled) {
      setError("登录后才可分享云端文件");
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
          const url = await resolveSafeRoomInviteUrl("EDITOR");
          if (!url) throw new Error("安全邀请尚未生成");
          await copyText(url);
          setNotice("直连文件只在当前会话内可用；已复制房间链接");
        }
      } else {
        const url = await resolveSafeFileShareUrl(record.attachment);
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

  const shareIncomingFile = async (item: IncomingAttachment) => {
    if (!item.direct && !ossFallbackEnabled) {
      setError("登录后才可分享云端文件");
      return;
    }
    try {
      if (item.direct) {
        const url = await resolveSafeRoomInviteUrl("EDITOR");
        if (!url) throw new Error("安全邀请尚未生成");
        await copyText(url);
        setNotice("直连文件只在当前会话内可用；已复制房间链接");
      } else {
        const url = await resolveSafeFileShareUrl(item.attachment);
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

  const markTransferDone = () => {
    // 成功路径统一清场：去掉过渡 notice（如"正在切换 TURN 中继"）和残留 error。
    setError(null);
    setNotice(null);
    setState("done");
  };

  const uploadFiles = async (files: File[], task: FileTransferTask) => {
    assertFileTransferTaskCurrent(task);
    if (files.length === 0) {
      setError("请选择要发送的文件");
      return;
    }
    if (task.networkMode === "lan" && !task.targetPeerId) {
      setState("failed");
      const message = "请先选择一台在线设备";
      setError(message);
      failOutgoingActivity(task.activityId, message);
      return;
    }
    if (!task.ossFallbackAllowed && !task.targetPeerId) {
      setState("failed");
      const message = "请先选择一台在线设备";
      setError(message);
      failOutgoingActivity(task.activityId, message);
      return;
    }
    if (task.networkMode === "internet" && !task.roomToken.trim()) {
      const message = "请先在房间设置中填写口令";
      setError(message);
      failOutgoingActivity(task.activityId, message);
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
      let peerTransferError = "";
      updateOutgoingActivity(task.activityId, { status: "connecting", error: undefined });
      if (task.targetPeerId && typeof RTCPeerConnection !== "undefined") {
        let peerResult: DirectTransferResult | null = null;
        let peerTransferRejected = false;
        let peerTransferFatal = false;
        const transportModes = task.networkMode === "lan"
          ? (["direct"] as const)
          : (["direct", "relay"] as const);
        for (const transportMode of transportModes) {
          try {
            peerResult = await sendDirect(
              task.targetPeerId,
              file,
              transportMode,
              task.abortController.signal,
            );
            break;
          } catch (err) {
            assertFileTransferTaskCurrent(task);
            const message = err instanceof Error ? err.message : "unknown";
            peerTransferError = transportMode === "relay"
              ? `备用通道失败：${message}`
              : `点对点连接失败：${message}`;
            if (message.includes("未确认接收") || message.includes("未确认完成")) {
              // 等待确认超时不进入 transport 降级循环，避免等待翻倍。
              peerTransferError = "对方 2 分钟内未确认，请提醒对方查看页面";
              peerTransferFatal = true;
              break;
            }
            if (message.includes("拒绝接收") || message.includes("取消了接收")) {
              peerTransferRejected = true;
              break;
            }
            if (transportMode === "direct" && task.networkMode === "internet") {
              setNotice("点对点连接未建立，正在尝试备用通道");
            }
          }
        }
        if (peerResult) {
          if (!isFileTransferTaskCurrent(task)) {
            URL.revokeObjectURL(peerResult.previewUrl);
            throw new FileTransferRoomChangedError();
          }
          setRecord({
            file,
            previewUrl: peerResult.previewUrl,
            presign: null,
            attachment: peerResult.attachment,
            downloadUrl: null,
            downloadExpiresAt: null,
            direct: true,
          });
          markTransferDone();
          completeOutgoingActivity(
            task.activityId,
            peerTransportPaths[task.targetPeerId] === "turn" ? "relay" : "peer",
          );
          continue;
        }
        if (peerTransferRejected || peerTransferFatal) {
          const message = userFacingTransferError(peerTransferError);
          setError(message);
          setState("failed");
          failOutgoingActivity(task.activityId, message);
          continue;
        }
        if (task.networkMode === "internet") {
          if (!task.ossFallbackAllowed) {
            setState("failed");
            const message = "设备连接未建立；登录后可使用云端接力";
            setError(message);
            failOutgoingActivity(task.activityId, message);
            continue;
          }
          setNotice("设备连接未建立，正在改用云端接力");
        }
      }
      if (task.networkMode === "lan") {
        setState("failed");
        const message = "附近传输未完成，请检查双方网络后重试";
        setError(message);
        failOutgoingActivity(task.activityId, message);
        continue;
      }
      if (!task.ossFallbackAllowed) {
        setState("failed");
        const message = "设备连接未建立，请检查双方网络后重试";
        setError(message);
        failOutgoingActivity(task.activityId, message);
        continue;
      }
      assertFileTransferTaskCurrent(task);
      await uploadViaOss(file, task);
    }
    assertFileTransferTaskCurrent(task);
  };

  const cancelTransfer = () => {
    const task = uploadInFlightRef.current;
    if (!task) {
      return;
    }
    cancelledActivityIdsRef.current.add(task.activityId);
    updateOutgoingActivity(task.activityId, {
      status: "cancelled",
      completedAt: Date.now(),
      unread: true,
      error: "已取消",
    });
    uploadInFlightRef.current = null;
    activeOutgoingActivityIdRef.current = "";
    task.abortController.abort();
    setProgress(0);
    setError(null);
    setState("idle");
    setNotice("已取消发送");
    window.setTimeout(() => runQueuedTransfersRef.current(), 0);
  };

  const retryFailedTransfer = () => {
    const failed = outgoingActivities.find((activity) => activity.status === "failed");
    if (failed) retryOutgoingActivity(failed);
  };

  const acceptFiles = (files: File[]) => {
    if (isRoomReadOnly) {
      setError("当前为只读访客，不能向房间发送文件");
      return;
    }
    if (files.length === 0) {
      return;
    }
    const targetRequired = networkMode === "lan" || !ossFallbackEnabled;
    if (targetRequired && !selectedPeer) {
      setActiveTool("files");
      setError(peers.length === 0 ? "还没有可接收的设备，请先邀请对方加入" : "请先选择接收设备");
      return;
    }
    if (discoveryStatus !== "online" && (targetRequired || selectedPeer)) {
      setDiscoveryError("房间连接尚未恢复，恢复后即可发送");
      return;
    }

    const now = Date.now();
    const targetPeerLabel = selectedPeer ? discoveryPeerDisplayName(selectedPeer) : "分享链接";
    const queueItems = files.map((file) => {
      const activityId = `outgoing-${peerId}-${now}-${transferActivitySequenceRef.current += 1}`;
      return {
        activity: {
          id: activityId,
          file,
          fileName: file.name || "attachment",
          sizeBytes: file.size,
          targetPeerId: selectedPeerId,
          targetPeerLabel,
          status: "queued" as const,
          progress: 0,
          transferredBytes: 0,
          speedBytesPerSecond: 0,
          etaSeconds: null,
          createdAt: now,
          unread: false,
        },
        queued: {
          activityId,
          file,
          roomEpoch: roomEpochRef.current,
          roomGeneration: roomGenerationRef.current,
          networkMode,
          roomId,
          roomToken,
          targetPeerId: selectedPeerId,
          targetPeerLabel,
          ossFallbackAllowed: ossFallbackEnabled,
        } satisfies QueuedFileTransfer,
      };
    });
    queuedFileTransfersRef.current.push(...queueItems.map((item) => item.queued));
    setOutgoingActivities((activities) => (
      [...queueItems.map((item) => item.activity), ...activities].slice(0, TRANSFER_ACTIVITY_LIMIT)
    ));
    setSelectedFiles(files);
    setError(null);
    setNotice(files.length > 1 ? `已加入 ${files.length} 个发送任务` : null);
    if (files.length > 1) setActivityCenterOpen(true);
    runQueuedTransfersRef.current();
  };

  const openFilePicker = () => {
    if (isRoomReadOnly) {
      setError("当前为只读访客，不能向房间发送文件");
      return;
    }
    const targetRequired = networkMode === "lan" || !ossFallbackEnabled;
    if (targetRequired && !selectedPeer) {
      setError(peers.length === 0 ? "还没有可接收的设备，请先邀请对方加入" : "请先选择接收设备");
      return;
    }
    if (discoveryStatus !== "online" && (targetRequired || selectedPeer)) {
      setDiscoveryError("房间连接尚未恢复，恢复后即可发送");
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
    if (!task.ossFallbackAllowed) {
      throw new Error("登录后才可使用云端接力");
    }
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
      markTransferDone();
      completeOutgoingActivity(task.activityId, "cloud");
    } catch (err) {
      if (err instanceof FileTransferRoomChangedError || !isFileTransferTaskCurrent(task)) {
        throw new FileTransferRoomChangedError();
      }
      setState("failed");
      const message = userFacingTransferError(err instanceof Error ? err.message : "上传失败");
      setError(message);
      failOutgoingActivity(task.activityId, message);
      throw err;
    }
  };

  const runNextQueuedTransfer = () => {
    if (uploadInFlightRef.current) return;

    let queued = queuedFileTransfersRef.current.shift();
    while (queued && cancelledActivityIdsRef.current.has(queued.activityId)) {
      queued = queuedFileTransfersRef.current.shift();
    }
    if (!queued) {
      activeOutgoingActivityIdRef.current = "";
      activityProgressSampleRef.current = null;
      if (state !== "failed" && state !== "done") setState("idle");
      return;
    }

    if (queued.roomEpoch !== roomEpochRef.current || queued.roomGeneration !== roomGenerationRef.current) {
      updateOutgoingActivity(queued.activityId, {
        status: "cancelled",
        completedAt: Date.now(),
        unread: true,
        error: "房间已切换",
      });
      window.setTimeout(runNextQueuedTransfer, 0);
      return;
    }

    const task: FileTransferTask = {
      id: fileTransferTaskSequenceRef.current += 1,
      activityId: queued.activityId,
      roomEpoch: queued.roomEpoch,
      roomGeneration: queued.roomGeneration,
      networkMode: queued.networkMode,
      roomId: queued.roomId,
      roomToken: queued.roomToken,
      targetPeerId: queued.targetPeerId,
      ossFallbackAllowed: queued.ossFallbackAllowed,
      abortController: new AbortController(),
    };
    uploadInFlightRef.current = task;
    activeOutgoingActivityIdRef.current = task.activityId;
    activityProgressSampleRef.current = { activityId: task.activityId, at: Date.now(), bytes: 0 };
    updateOutgoingActivity(task.activityId, { status: "connecting", error: undefined });
    setState("connecting");

    void uploadFiles([queued.file], task)
      .catch((err) => {
        if (err instanceof FileTransferRoomChangedError || cancelledActivityIdsRef.current.has(task.activityId)) {
          return;
        }
        const message = userFacingTransferError(err instanceof Error ? err.message : "发送未完成");
        setState("failed");
        setError(message);
        failOutgoingActivity(task.activityId, message);
      })
      .finally(() => {
        if (uploadInFlightRef.current === task) uploadInFlightRef.current = null;
        if (activeOutgoingActivityIdRef.current === task.activityId) activeOutgoingActivityIdRef.current = "";
        activityProgressSampleRef.current = null;
        window.setTimeout(() => runQueuedTransfersRef.current(), 0);
      });
  };
  runQueuedTransfersRef.current = runNextQueuedTransfer;

  const retryOutgoingActivity = (activity: OutgoingTransferActivity) => {
    if (activity.status !== "failed" && activity.status !== "cancelled") return;
    const peerStillAvailable = !activity.targetPeerId || peers.some((peer) => peer.peerId === activity.targetPeerId);
    if (activity.targetPeerId && !peerStillAvailable) {
      setError("原接收设备已离线。任务目标不会自动更换，请等待对方上线或重新选择文件发送");
      return;
    }
    cancelledActivityIdsRef.current.delete(activity.id);
    updateOutgoingActivity(activity.id, {
      status: "queued",
      progress: 0,
      transferredBytes: 0,
      speedBytesPerSecond: 0,
      etaSeconds: null,
      transport: undefined,
      error: undefined,
      completedAt: undefined,
      unread: false,
    });
    queuedFileTransfersRef.current.push({
      activityId: activity.id,
      file: activity.file,
      roomEpoch: roomEpochRef.current,
      roomGeneration: roomGenerationRef.current,
      networkMode,
      roomId,
      roomToken,
      targetPeerId: activity.targetPeerId,
      targetPeerLabel: activity.targetPeerLabel,
      ossFallbackAllowed: ossFallbackEnabled,
    });
    setError(null);
    setActivityCenterOpen(true);
    runQueuedTransfersRef.current();
  };

  const cancelOutgoingActivity = (activityId: string) => {
    cancelledActivityIdsRef.current.add(activityId);
    queuedFileTransfersRef.current = queuedFileTransfersRef.current.filter((item) => item.activityId !== activityId);
    const activeTask = uploadInFlightRef.current;
    if (activeTask?.activityId === activityId) {
      uploadInFlightRef.current = null;
      activeOutgoingActivityIdRef.current = "";
      activeTask.abortController.abort();
      setProgress(0);
      setState("idle");
      window.setTimeout(() => runQueuedTransfersRef.current(), 0);
    }
    updateOutgoingActivity(activityId, {
      status: "cancelled",
      completedAt: Date.now(),
      unread: true,
      error: "已取消",
    });
  };

  const downloadRecordFile = async () => {
    if (!record) {
      return;
    }
    if (!record.direct && !ossFallbackEnabled) {
      setError("登录后才可下载云端文件");
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
      setRecord((current) => current?.attachment.attachmentId === record.attachment.attachmentId
        ? { ...current, downloadUrl: null, downloadExpiresAt: null }
        : current);
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
    if (!item.direct && !ossFallbackEnabled) {
      setError("登录后才可下载云端文件");
      return;
    }
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
      if (item.blob) {
        // 之前已下载过，直接复用本地 blob，不再走网络。
        downloadBlob(item.blob, item.attachment.fileName);
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
        ? { ...current, downloadUrl: null, downloadExpiresAt: null }
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
        return { ...current, downloadUrl: null, downloadExpiresAt: null, previewUrl, blob };
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

  const sendRelayFrame = useCallback((targetPeerId: string, frame: ArrayBuffer, expectedRoomEpoch: number) => {
    const socket = discoverySocketRef.current;
    if (roomEpochRef.current !== expectedRoomEpoch
      || !currentRoomPeerIdsRef.current.has(targetPeerId)
      || !targetPeerId
      || !socket
      || socket.readyState !== WebSocket.OPEN) {
      throw new Error("discovery channel unavailable");
    }
    socket.send(encodeRelayAppFrame(targetPeerId, "", frame));
  }, []);

  const sendWhiteboardPayload = useCallback((payload: WhiteboardPayload) => {
    if (isRoomReadOnly) return Promise.resolve(false);
    if (peers.length === 0) {
      return Promise.resolve(true);
    }
    const sendRoomEpoch = roomEpochRef.current;
    const deliveries: Array<Promise<boolean>> = [];
    for (const peer of peers) {
      const targetPeerId = peer.peerId;
      // Keep payloads ordered while avoiding a new ICE negotiation for every stroke after a path fails.
      const queueKey = JSON.stringify([sendRoomEpoch, targetPeerId]);
      const previous = whiteboardSendQueuesRef.current.get(queueKey) ?? Promise.resolve();
      const task = previous.catch(() => undefined).then(async () => {
        const isTargetCurrent = () => roomEpochRef.current === sendRoomEpoch
          && currentRoomPeerIdsRef.current.has(targetPeerId);
        if (!isTargetCurrent()) {
          return true;
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
          const sent = await sendDirectMessage();
          if (isTargetCurrent()) {
            whiteboardTransportRetryRef.current.set(queueKey, retryState);
          }
          return sent || !isTargetCurrent();
        }

        const transport = await sendWhiteboardWithFallback({
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
          websocket: () => sendRelayPeerMessage(targetPeerId, message,
            (frame) => sendRelayFrame(targetPeerId, frame, sendRoomEpoch)),
        });

        if (isTargetCurrent()) {
          whiteboardTransportRetryRef.current.set(queueKey, retryState);
        }
        return transport !== null || !isTargetCurrent();
      });
      const delivery = task.catch(() => false);
      const queued = delivery.then(() => undefined);
      deliveries.push(delivery);
      whiteboardSendQueuesRef.current.set(queueKey, queued);
      void queued.finally(() => {
        if (whiteboardSendQueuesRef.current.get(queueKey) === queued) {
          whiteboardSendQueuesRef.current.delete(queueKey);
        }
      });
    }
    return Promise.all(deliveries).then((results) => results.every(Boolean));
  }, [isPeerMessageTransportReady, isRoomReadOnly, networkMode, peers, sendPeerMessage, sendRelayFrame, sendRelayPeerMessage]);

  const sendClipboardPayload = useCallback(async (payload: ClipboardSyncPayload) => {
    if (isRoomReadOnly) {
      throw new Error("当前为只读访客，不能同步剪贴板");
    }
    if (discoveryStatusRef.current !== "online") {
      throw new Error("房间连接正在重连，恢复后再发送");
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
      throw new Error("附近模式仅允许设备直连；请检查设备连接或切换到远程模式");
    }
    const sentRelay = await sendRelayPeerMessage(target.peerId,
      { messageType: "clipboard", payload },
      (frame) => sendRelayFrame(target.peerId, frame, sendRoomEpoch));
    if (!sentRelay) {
      throw new Error("互传通道暂时不可用，请确认对方仍在线");
    }
  }, [isRoomReadOnly, networkMode, peers, selectedPeerId, sendPeerMessage, sendRelayFrame, sendRelayPeerMessage]);

  const selectTransferTool = useCallback((mode: TransferToolMode, focusContent = false) => {
    setActiveTool(mode);
    if (mode === "files") {
      setOutgoingActivities((activities) => activities.map((activity) => (
        activity.unread ? { ...activity, unread: false } : activity
      )));
    }
    if (mode === "clipboard" && focusContent) {
      setClipboardFocusRequest((value) => value + 1);
    }
  }, []);

  const sharedModals = (
    <>
      <ConfirmModal
        isOpen={transferInterruptAction !== null}
        onClose={() => setTransferInterruptAction(null)}
        onConfirm={() => transferInterruptAction?.action()}
        title={transferInterruptAction?.title ?? ""}
        description={transferInterruptAction?.description}
        confirmLabel="继续"
        danger
      />
      <ConfirmModal
        isOpen={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={confirmRevokeRoomAccess}
        title="撤销邀请？"
        description={revokeTarget ? `撤销“${revokeTarget.label}”后，该邀请将在下次连接时失效。` : undefined}
        confirmLabel="撤销"
        danger
      />
      <Modal isOpen={inviteLabelRole !== null} onClose={() => setInviteLabelRole(null)} size="sm" placement="center">
        <ModalContent>
          <ModalHeader className="text-base">邀请名称</ModalHeader>
          <ModalBody>
            <Input
              autoFocus
              label="名称"
              radius="sm"
              variant="bordered"
              value={inviteLabelDraft}
              onValueChange={setInviteLabelDraft}
              maxLength={MAX_TRANSFER_ROOM_NAME_LENGTH}
              onKeyDown={(event) => {
                if (event.key === "Enter" && inviteLabelDraft.trim()) {
                  void confirmCreateRoomAccess();
                }
              }}
            />
          </ModalBody>
          <ModalFooter>
            <Button variant="flat" onPress={() => setInviteLabelRole(null)}>取消</Button>
            <Button color="primary" isDisabled={!inviteLabelDraft.trim()} onPress={() => void confirmCreateRoomAccess()}>
              创建邀请
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </>
  );

  if (isDiagramWorkspace) {
    const collaborationRoleLabel = effectiveRoomRole === "OWNER" ? "房主" : effectiveRoomRole === "EDITOR" ? "可编辑" : "只读";
    const collaboratorCount = peers.length + 1;
    const collaborationPanel = (
      <div className="diagram-collaboration-panel text-zinc-950 dark:text-white">
        <section className="diagram-collaboration-overview" aria-label="当前协作状态">
          <div className="flex min-w-0 items-center gap-2.5">
            <span
              className={`diagram-collaboration-status-dot ${discoveryStatus === "online" ? "is-connected" : ""}`}
              aria-hidden="true"
            />
            <div className="min-w-0">
              <div className="flex min-w-0 items-center gap-2">
                <strong className="truncate text-[13px] font-semibold">{roomId}</strong>
                <span className="diagram-collaboration-role">{collaborationRoleLabel}</span>
              </div>
              <div className="mt-0.5 truncate text-[10px] text-zinc-500 dark:text-zinc-400">
                {isInternetMode ? "远程协作房间" : "附近协作房间"} · {discoveryStatus === "reconnecting" ? "连接重连中" : discoveryStatus === "connecting" ? "正在连接" : peers.length > 0 ? "协作者在线" : "等待协作者加入"}
              </div>
            </div>
          </div>
          <span className="diagram-collaboration-count">{collaboratorCount} 人</span>
        </section>

        <section className="diagram-collaboration-section">
          <div className="diagram-collaboration-section-heading">
            <h3>连接与房间</h3>
            <span>{isInternetMode ? "远程" : "附近"}</span>
          </div>
          <div className="diagram-collaboration-network" role="radiogroup" aria-label="流程图协作网络模式">
            {([
              ["lan", "附近", "同网协作"],
              ["internet", "远程", "跨网协作"],
            ] as const).map(([mode, label, detail]) => {
              const active = networkMode === mode;
              return (
                <button
                  key={mode}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  className={active ? "is-active" : ""}
                  onClick={() => updateNetworkMode(mode)}
                >
                  <span>{label}</span>
                  <small>{detail}</small>
                </button>
              );
            })}
          </div>
          <div className="mt-2.5 space-y-2.5">
            <div className="diagram-collaboration-client-name">
              <ClientNameSettings
                compact
                inputId="diagram-client-name-input"
                value={displayNameDraft}
                onValueChange={setDisplayNameDraft}
                status={clientNameStatus}
                localError={clientNameLocalError}
                isSaving={clientNameSaving}
                onApply={() => void applyClientName()}
              />
            </div>
            <Input
              className="diagram-collaboration-input-root"
              classNames={{ inputWrapper: "diagram-collaboration-input" }}
              size="sm"
              label="房间名"
              radius="sm"
              variant="bordered"
              value={roomIdDraft}
              onValueChange={updateRoomIdDraft}
              maxLength={MAX_TRANSFER_ROOM_NAME_LENGTH}
              isInvalid={Boolean(roomSettingsErrors.roomId)}
              errorMessage={roomSettingsErrors.roomId}
            />
            {isInternetMode ? (
              <Input
                className="diagram-collaboration-input-root"
                classNames={{ inputWrapper: "diagram-collaboration-input" }}
                size="sm"
                label="房间 Token"
                radius="sm"
                variant="bordered"
                value={roomTokenDraft}
                onValueChange={updateRoomTokenDraft}
                maxLength={MAX_TRANSFER_ROOM_TOKEN_LENGTH}
                isInvalid={Boolean(roomSettingsErrors.roomToken)}
                errorMessage={roomSettingsErrors.roomToken}
                endContent={
                  <Button className="diagram-collaboration-inline-action" size="sm" variant="light" onPress={() => updateRoomTokenDraft(createRoomToken())}>
                    生成
                  </Button>
                }
              />
            ) : null}
            {isInternetMode ? (
              <div className="diagram-collaboration-permissions">
                <RoomPermissionSetting
                  compact
                  context="diagram"
                  networkMode={networkMode}
                  currentRole={effectiveRoomRole}
                  inviteRole={roomInviteRole}
                  canManage={roomRole === "OWNER"}
                  isLoading={roomAccessLoading}
                  onInviteRoleChange={setRoomInviteRole}
                  onCreateInvite={() => void createRoomAccess(roomInviteRole)}
                />
              </div>
            ) : null}
          </div>
          <div className="mt-2.5 flex justify-end gap-1.5">
            <Button className="diagram-collaboration-action" size="sm" radius="sm" variant="light" onPress={resetRoomSettingsDraft}>恢复</Button>
            <Button className="diagram-collaboration-action is-primary" size="sm" radius="sm" color="primary" variant="flat" onPress={applyRoomSettings}>应用设置</Button>
          </div>
        </section>

        <section className="diagram-collaboration-section">
          <div className="diagram-collaboration-section-heading">
            <h3>邀请协作者</h3>
            <span>{isInternetMode ? "可跨网络加入" : "限同一网络"}</span>
          </div>
          <div className="mt-2 grid grid-cols-4 gap-1.5">
            <Button className="diagram-collaboration-action is-primary" size="sm" color="primary" radius="sm" variant="flat" onPress={() => void shareRoom()}>分享</Button>
            <Button className="diagram-collaboration-action" size="sm" radius="sm" variant="flat" onPress={() => void copyRoomLink()}>复制链接</Button>
            <Button className={`diagram-collaboration-action ${qrVisible ? "is-active" : ""}`} size="sm" radius="sm" variant="flat" onPress={() => qrVisible ? setQrVisible(false) : showRoomQr()}>
              {qrVisible ? "收起二维码" : "二维码"}
            </Button>
            <Button className="diagram-collaboration-action" size="sm" radius="sm" variant="flat" onPress={createNewRoom}>新房间</Button>
          </div>
          {qrVisible ? (
            <div className="diagram-collaboration-qr mt-2.5">
              {(isInternetMode ? pairingJoinUrl : roomJoinUrl) ? (
                <>
                  <RoomQrCode value={(isInternetMode ? pairingJoinUrl : roomJoinUrl) as string} />
                  <div className="mt-2 break-all text-center font-mono text-[9px] leading-4 text-zinc-500 dark:text-zinc-400">
                    {isInternetMode ? "5 分钟一次性扫码邀请" : roomJoinUrl}
                  </div>
                </>
              ) : (
                <div className="py-6 text-center text-tiny text-zinc-400">正在生成安全二维码…</div>
              )}
            </div>
          ) : null}
        </section>

        {isInternetMode && roomRole === "OWNER" ? (
          <section className="diagram-collaboration-section">
            <div className="diagram-collaboration-section-heading">
              <h3>权限链接</h3>
              <span>{roomAccessTokens.length} 个</span>
            </div>
            {createdRoomAccess ? (
              <div className="diagram-collaboration-created-access mt-2">
                <span className="min-w-0 truncate">{createdRoomAccess.access.label} · Token 仅显示一次</span>
                <Button className="diagram-collaboration-action shrink-0" size="sm" radius="sm" variant="flat" onPress={() => void copyCreatedRoomAccessLink()}>复制</Button>
              </div>
            ) : null}
            <div className="diagram-collaboration-access-list mt-1.5">
              {roomAccessTokens.length === 0 ? (
                <div className="py-2 text-tiny text-zinc-400">{roomAccessLoading ? "正在加载邀请…" : "暂无权限链接"}</div>
              ) : roomAccessTokens.map((access) => (
                <div key={access.id} className="diagram-collaboration-access-row">
                  <div className="min-w-0">
                    <div className="truncate text-tiny font-medium">{access.label}</div>
                    <div className="mt-0.5 text-[10px] text-zinc-400">{access.role === "EDITOR" ? "可编辑" : "只读"} · {access.revokedAt ? "已撤销" : isAccessTokenExpired(access) ? "已过期" : access.expiresAt ? formatInviteExpiry(access.expiresAt) : "长期有效"}</div>
                  </div>
                  <Button className="diagram-collaboration-action shrink-0" size="sm" radius="sm" color="danger" variant="light" isDisabled={Boolean(access.revokedAt) || roomAccessLoading} onPress={() => void revokeRoomAccess(access)}>
                    {access.revokedAt ? "已撤销" : "撤销"}
                  </Button>
                </div>
              ))}
            </div>
          </section>
        ) : null}

        <section className="diagram-collaboration-section">
          <div className="diagram-collaboration-section-heading">
            <h3>在线成员</h3>
            <span>{collaboratorCount} 人</span>
          </div>
          <div className="diagram-collaboration-members mt-1.5">
            <div className="diagram-collaboration-member is-current">
              <span className="diagram-collaboration-avatar">我</span>
              <div className="min-w-0 flex-1">
                <div className="truncate text-tiny font-medium">{displayName}</div>
                <div className="text-[10px] text-zinc-500 dark:text-zinc-400">当前设备</div>
              </div>
              <span className="diagram-collaboration-online-dot" aria-label="在线" />
            </div>
            {peers.map((peer) => (
              <div key={peer.peerId} className="diagram-collaboration-member">
                <span className="diagram-collaboration-avatar">{discoveryPeerDisplayName(peer).slice(0, 1).toUpperCase()}</span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-tiny font-medium">{discoveryPeerDisplayName(peer)}</div>
                  <div className="text-[10px] text-zinc-500 dark:text-zinc-400">协作者</div>
                </div>
                <span className="diagram-collaboration-online-dot" aria-label="在线" />
              </div>
            ))}
            {peers.length === 0 ? <div className="py-2 text-center text-[10px] text-zinc-400">暂无其他协作者</div> : null}
          </div>
        </section>

        {notice ? <div className="diagram-collaboration-feedback is-success">{notice}</div> : null}
        {error ? <div className="diagram-collaboration-feedback is-error">{error}</div> : null}
      </div>
    );

    return (
      <main className="h-[100dvh] overflow-hidden bg-zinc-100 text-zinc-950 dark:bg-zinc-950 dark:text-white">
        <Suspense fallback={<DiagramWorkspaceLoading fullscreen />}>
          <LazySyncedDiagram
            standalone
            collaborationPanel={collaborationPanel}
            boardKey={transferRoomScopeKey}
            roomId={roomId}
            roomToken={isInternetMode ? roomToken : ""}
            roomRole={effectiveRoomRole}
            peerId={peerId}
            peerCount={peers.length}
            peerDisplayNames={diagramPeerDisplayNames}
            isConnected={peers.length > 0}
            events={diagramEvents}
            onSend={sendWhiteboardPayload}
          />
        </Suspense>
        {sharedModals}
      </main>
    );
  }

  return (
    <main
      className="app-apple-tool transfer-mode-shell relative min-h-screen overflow-x-hidden text-zinc-950 dark:text-white"
      data-network-mode={networkMode}
      onPaste={handlePagePaste}
    >
      {networkModeTransitionId > 0 ? (
        <div key={networkModeTransitionId} className="transfer-mode-transition" aria-hidden="true" />
      ) : null}
      <header className="app-apple-tool-header relative z-40 mx-auto flex w-full max-w-[1480px] items-center justify-between gap-3 px-4 py-4 sm:px-8 sm:py-5">
        <AppLogo className="min-w-0 flex-1" label="shuai-tunnel" subtitle={isDiagramWorkspace ? "专业流程图" : "互传"} markClassName="h-8 w-8 sm:h-9 sm:w-9" />
        <div className="public-header-actions flex shrink-0 items-center gap-2">
          <PublicToolsMenu active={workspace} />
          <UserMenuButton className="public-header-theme-button" />
        </div>
      </header>

      <section
        className={`app-apple-tool-content relative z-10 mx-auto grid w-full max-w-[1480px] gap-5 px-4 pb-10 sm:px-8 sm:pb-14 ${
          isDiagramWorkspace ? "xl:grid-cols-1" : "xl:grid-cols-[minmax(0,1fr)_320px]"
        }`}
      >
        <div className="app-apple-tool-workspace min-w-0 p-1 sm:p-2">
          <div className="flex items-center justify-between gap-3">
            <h1 className="text-xl font-semibold text-zinc-950 dark:text-white sm:text-2xl">互传</h1>
            <Button size="sm" radius="sm" variant="light" className="transfer-touch-action" onPress={() => setHelpOpen(true)}>使用帮助</Button>
          </div>

          <section className="app-apple-tool-surface transfer-room-hub mt-3 p-3">
            <div className="transfer-room-compact flex flex-wrap items-center gap-3">
              <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
                <span className="text-tiny font-medium text-zinc-500 dark:text-zinc-400">房间</span>
                <strong className="max-w-44 truncate text-base text-zinc-950 dark:text-white">{transferRoomDisplayName(roomId)}</strong>
                <Chip size="sm" radius="sm" variant="flat" color={effectiveRoomRole === "OWNER" ? "primary" : effectiveRoomRole === "EDITOR" ? "success" : "default"}>
                  {effectiveRoomRole === "OWNER" ? "房主" : effectiveRoomRole === "EDITOR" ? "可编辑" : "只读"}
                </Chip>
                <button
                  type="button"
                  className="max-w-48 truncate rounded px-1.5 py-1 font-mono text-tiny text-zinc-500 hover:bg-black/5 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/10 dark:hover:text-white max-sm:min-h-11"
                  title="点击复制设备名称"
                  onClick={() => void copyText(displayName).then(() => setNotice("客户端名称已复制")).catch((err) => setError(err instanceof Error ? err.message : "复制客户端名称失败"))}
                >
                  {displayName}
                </button>
                <Chip
                  size="sm"
                  radius="sm"
                  variant="flat"
                  color={discoveryStatus === "online" ? "success" : discoveryStatus === "reconnecting" ? "warning" : discoveryStatus === "permission-denied" || discoveryStatus === "name-conflict" ? "danger" : "default"}
                >
                  {discoveryStatusLabel(discoveryStatus)}
                </Chip>
                <Popover placement="bottom-start">
                  <PopoverTrigger>
                    <Button
                      size="sm"
                      radius="sm"
                      variant="flat"
                      color={ossFallbackEnabled ? "success" : "default"}
                      className="h-6 min-w-0 gap-1 px-2 text-tiny max-sm:min-h-11"
                      aria-label="传输兜底方式说明"
                    >
                      {!authReady ? "账号检测中" : ossFallbackEnabled ? "云端接力可用" : "仅设备连接"}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="max-w-64 px-3 py-2">
                    <div className="text-tiny font-semibold">
                      {ossFallbackEnabled ? "云端接力已启用" : "仅使用设备连接"}
                    </div>
                    <p className="mt-1 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
                      {ossFallbackEnabled
                        ? "文件优先直接发送给设备；连接失败时改用登录账号的短期云端链接。"
                        : "匿名使用不会上传云端；登录后可启用短期云端接力。"}
                    </p>
                  </PopoverContent>
                </Popover>
              </div>
              <div className="transfer-room-controls flex shrink-0 items-center gap-2">
                <NetworkModeToggle activeMode={networkMode} onSelect={updateNetworkMode} />
                {!isDiagramWorkspace ? (
                  <Button isIconOnly size="sm" radius="sm" variant="light" className="min-h-11 min-w-11 sm:min-h-8 sm:min-w-8" aria-label="打开帮助" title="帮助" onPress={() => setHelpOpen(true)}>
                    ?
                  </Button>
                ) : null}
                <Button size="sm" radius="sm" color="primary" variant="flat" className="min-h-11 sm:min-h-8" onPress={openInvitePanel}>
                  邀请 / 加入
                </Button>
                <Button
                  size="sm"
                  radius="sm"
                  variant="light"
                  className="min-h-11 sm:min-h-8"
                  onPress={() => {
                    resetRoomSettingsDraft();
                    setRoomSettingsOpen(true);
                  }}
                >
                  设置
                </Button>
              </div>
            </div>

            {discoveryStatus !== "online" || discoveryError ? (
              <div
                className={`mt-3 flex flex-col gap-2 rounded-md border px-3 py-2 text-small sm:flex-row sm:items-center sm:justify-between ${
                  discoveryStatus === "permission-denied" || discoveryStatus === "name-conflict"
                    ? "border-rose-300 bg-rose-50 text-rose-800 dark:border-rose-400/25 dark:bg-rose-500/10 dark:text-rose-100"
                    : "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-400/25 dark:bg-amber-500/10 dark:text-amber-100"
                }`}
                role={discoveryStatus === "permission-denied" || discoveryStatus === "name-conflict" ? "alert" : "status"}
              >
                <span className="min-w-0 [overflow-wrap:anywhere]">
                  {discoveryError || discoveryStatusDescription(discoveryStatus)}
                </span>
                <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                  <Button size="sm" radius="sm" variant="flat" className="transfer-touch-action" onPress={retryDiscoveryConnection}>重试连接</Button>
                  <Button size="sm" radius="sm" variant="light" className="transfer-touch-action" onPress={() => setRoomSettingsOpen(true)}>检查设置</Button>
                  {discoveryErrorDetail ? (
                    <Popover placement="bottom-end">
                      <PopoverTrigger>
                        <Button size="sm" radius="sm" variant="light" className="transfer-touch-action">查看详情</Button>
                      </PopoverTrigger>
                      <PopoverContent className="max-w-[min(88vw,420px)] px-3 py-2">
                        <div>
                          <div className="text-tiny font-semibold text-zinc-800 dark:text-zinc-100">连接诊断信息</div>
                          <code className="mt-1 block break-all text-[11px] leading-5 text-zinc-500 dark:text-zinc-400">{discoveryErrorDetail}</code>
                        </div>
                      </PopoverContent>
                    </Popover>
                  ) : null}
                </div>
              </div>
            ) : null}

          <div className="transfer-room-tools mt-3 grid grid-cols-3 gap-1 border-t border-black/10 pt-2.5 dark:border-white/10" role="tablist" aria-label="互传功能切换">
            <ToolModeButton
              mode="clipboard"
              activeMode={activeTool}
              label="同步剪贴板"
              detail={clipboardEvents.length > 0 ? "有新内容" : "粘贴即发送"}
              onSelect={selectTransferTool}
            />
            <ToolModeButton
              mode="files"
              activeMode={activeTool}
              label="文件传输"
              detail={fileActivityCount > 0 ? `${fileActivityCount} 项` : "发送和接收"}
              unreadCount={unreadFileActivityCount}
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
          </section>

          {!isDiagramWorkspace && (activeOutgoingActivity || receivingTransfers.length > 0 || pendingTransfers.length > 0) ? (
            <button
              type="button"
              className="mt-3 flex w-full items-center gap-3 rounded-md border border-primary-300/70 bg-primary-50/75 px-3 py-2 text-left shadow-sm transition hover:bg-primary-100/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 dark:border-primary-300/20 dark:bg-primary-300/[0.07] dark:hover:bg-primary-300/[0.11]"
              onClick={() => {
                setActivityCenterOpen(true);
                setOutgoingActivities((activities) => activities.map((activity) => ({ ...activity, unread: false })));
              }}
            >
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded bg-primary-600 text-small font-semibold text-white" aria-hidden>
                {activeOutgoingCount + receivingTransfers.length + pendingTransfers.length}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-small font-semibold text-zinc-950 dark:text-white">
                  {activeOutgoingActivity
                    ? `${transferActivityStatusLabel(activeOutgoingActivity.status)}：${activeOutgoingActivity.fileName}`
                    : receivingTransfers.length > 0 ? `正在接收 ${receivingTransfers.length} 个文件` : "有文件等待接收"}
                </span>
                <span className="mt-0.5 block truncate text-tiny text-zinc-500 dark:text-zinc-400">
                  {activeOutgoingActivity
                    ? `${Math.round(activeOutgoingActivity.progress)}% · ${activeOutgoingCount} 个发送任务`
                    : "点击查看传输任务"}
                </span>
              </span>
              {activeOutgoingActivity ? (
                <span className="w-24 shrink-0 sm:w-36">
                  <Progress size="sm" aria-label={`${activeOutgoingActivity.fileName} 发送进度`} value={activeOutgoingActivity.progress} />
                </span>
              ) : null}
              <span className="shrink-0 text-tiny font-medium text-primary-700 dark:text-primary-300">查看</span>
            </button>
          ) : null}

          {!isDiagramWorkspace && activeTool !== "whiteboard" ? (
            <div className="mt-3 xl:hidden">
              <div className="mb-1.5 text-tiny text-zinc-500 dark:text-zinc-400">发送给</div>
              <div className="flex gap-1.5 overflow-x-auto pb-1" role="radiogroup" aria-label="发送目标设备">
                {peers.length === 0 ? (
                  <button
                    type="button"
                    className="app-apple-tool-peer min-h-11 shrink-0 px-3 py-2 text-left text-tiny"
                    onClick={openInvitePanel}
                  >
                    邀请设备加入
                  </button>
                ) : peers.map((peer) => {
                  const selected = selectedPeerId === peer.peerId;
                  return (
                    <button
                      key={peer.peerId}
                      type="button"
                      role="radio"
                      aria-checked={selected}
                      onClick={() => selectTransferPeer(peer)}
                      className={`app-apple-tool-peer min-h-11 shrink-0 rounded-md px-3 py-1.5 text-tiny transition-colors ${selected ? "is-selected" : ""}`}
                    >
                      {discoveryPeerDisplayName(peer)}
                    </button>
                  );
                })}
              </div>
            </div>
          ) : null}

          {!isDiagramWorkspace ? <>
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
              aria-label={fileDropzoneTitle}
              aria-describedby="public-transfer-file-dropzone-detail"
              aria-busy={isTransferBusy}
              aria-disabled={isRoomReadOnly}
              disabled={isRoomReadOnly}
              onClick={openFilePicker}
              onDragEnter={handleFileDragEnter}
              onDragOver={handleFileDragOver}
              onDragLeave={handleFileDragLeave}
              onDrop={handleFileDrop}
              className={`app-apple-tool-dropzone transfer-file-stage group relative mt-4 flex min-h-[320px] w-full flex-col items-center justify-center overflow-hidden px-5 py-10 text-center outline-none transition duration-200 motion-reduce:transition-none sm:min-h-[360px] ${
                isFileDragActive ? "is-active" : isTransferBusy ? "is-busy" : ""
              }`}
            >
              <span className="transfer-file-add" aria-hidden="true">+</span>
              <span className="app-apple-tool-kicker px-2.5 py-1 text-[10px] font-semibold">
                {isFileDragActive ? "松开发送" : "点击 · 拖入 · 粘贴"}
              </span>
              <span className="mt-4 text-xl font-semibold text-zinc-950 dark:text-white">
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
            <div className={activeTool === "whiteboard" ? "hidden" : "mt-4"} aria-hidden={activeTool === "whiteboard"}>
              <TransferProgress
                state={state}
                store={progressStore}
                transportPath={
                  uploadInFlightRef.current?.targetPeerId
                    ? peerTransportPaths[uploadInFlightRef.current.targetPeerId]
                    : undefined
                }
                busy={isTransferBusy}
                onCancel={cancelTransfer}
              />
            </div>
          )}
          </> : null}

          {notice && (
            <div
              role="status"
              aria-live="polite"
              className="mt-4 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-small text-emerald-800 dark:border-emerald-400/30 dark:bg-emerald-500/10 dark:text-emerald-100"
            >
              {notice}
            </div>
          )}

          {error && (
            <div
              role="alert"
              className="mt-4 flex items-start justify-between gap-2 rounded-lg border border-rose-300 bg-rose-50 px-3 py-2 text-small text-rose-700 dark:border-rose-400/30 dark:bg-rose-500/10 dark:text-rose-100"
            >
              <span className="min-w-0 [overflow-wrap:anywhere]">{error}</span>
              <span className="flex shrink-0 items-center gap-1">
                {state === "failed" && selectedFiles.length > 0 ? (
                  <Button size="sm" radius="sm" color="danger" variant="flat" onPress={retryFailedTransfer}>
                    重试
                  </Button>
                ) : null}
                <button
                  type="button"
                  aria-label="关闭错误提示"
                  className="grid h-6 w-6 place-items-center rounded text-rose-500 transition hover:bg-rose-500/10 hover:text-rose-700 dark:text-rose-200 dark:hover:text-rose-50"
                  onClick={() => setError(null)}
                >
                  <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                    <path d="M6 6l12 12M18 6L6 18" />
                  </svg>
                </button>
              </span>
            </div>
          )}

          {!isDiagramWorkspace ? <>
          <SyncedClipboard
            syncKey={transferRoomScopeKey}
            isActive={activeTool === "clipboard"}
            focusRequest={clipboardFocusRequest}
            canSend={!isRoomReadOnly}
            fileTargetRequired={networkMode === "lan" || !ossFallbackEnabled}
            targetPeerId={selectedPeer?.peerId ?? ""}
            targetPeerLabel={selectedPeer ? discoveryPeerDisplayName(selectedPeer) : ""}
            events={clipboardEvents}
            onSend={sendClipboardPayload}
            onFiles={acceptFiles}
            onDraftStateChange={setClipboardHasDraft}
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
              onDraftStateChange={setWhiteboardHasDraft}
            />
          </div>

          <div className={activeTool === "whiteboard" ? "hidden" : ""} aria-hidden={activeTool === "whiteboard"}>
            <IncomingFilesPanel
              pendingTransfers={pendingTransfers}
              receivingTransfers={receivingTransfers}
              peerTransportPaths={peerTransportPaths}
              peerDisplayNames={diagramPeerDisplayNames}
              incoming={incoming}
              cloudTransferEnabled={ossFallbackEnabled}
              onAcceptDirect={(item) => acceptIncomingTransfer(item.sourcePeerId, item.transferId)}
              onRejectDirect={(item) => rejectIncomingTransfer(item.sourcePeerId, item.transferId)}
              onCancelReceiving={(item) => {
                cancelIncomingTransfer(item.sourcePeerId, item.transferId);
                setNotice("已取消接收");
              }}
              onShare={shareIncomingFile}
              onDownload={downloadIncoming}
              onLogin={openLogin}
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
                        {formatBytes(record.attachment.sizeBytes)} · {record.direct ? "当前会话可直接保存" : "同房间成员可下载"}
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      <Button
                        isIconOnly
                        size="sm"
                        radius="sm"
                        color="primary"
                        variant="flat"
                        aria-label="分享"
                        title="分享"
                        onPress={() => void shareRecordFile()}
                      >
                        <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="18" cy="5" r="3" />
                          <circle cx="6" cy="12" r="3" />
                          <circle cx="18" cy="19" r="3" />
                          <path d="m8.6 13.5 6.8 4M15.4 6.5l-6.8 4" />
                        </svg>
                      </Button>
                      <Button
                        isIconOnly
                        size="sm"
                        radius="sm"
                        color="success"
                        variant="flat"
                        aria-label="保存到本机"
                        title="保存到本机"
                        onPress={() => void downloadRecordFile()}
                      >
                        <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M12 4v11m0 0 4-4m-4 4-4-4M4.5 19.5h15" />
                        </svg>
                      </Button>
                      <Chip size="sm" color="success" variant="flat">
                        完成
                      </Chip>
                    </div>
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
                peerDisplayNames={diagramPeerDisplayNames}
                isConnected={peers.length > 0}
                events={diagramEvents}
                onSend={sendWhiteboardPayload}
              />
            </Suspense>
          )}
        </div>

        {!isDiagramWorkspace ? <aside className="min-w-0 p-4 sm:p-5 xl:sticky xl:top-5 xl:self-start">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold">发送给谁</h2>
              <div className="mt-1 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
                {isInternetMode
                  ? "对方打开远程邀请后会默认选中首台设备，也可以点名字切换。"
                  : "发现设备后会默认选中第一台，也可以点名字切换。"}
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
                  : "还没有发现附近设备。请确认设备处于同一网络并进入相同房间。"}
              </div>
            ) : peers.map((peer) => (
              <button
                key={peer.peerId}
                type="button"
                onClick={() => selectTransferPeer(peer)}
                className={`app-apple-tool-peer px-3 py-2 text-left text-small transition-colors ${selectedPeerId === peer.peerId ? "is-selected" : ""}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="min-w-0 truncate font-medium">{discoveryPeerDisplayName(peer)}</div>
                  <div className="flex shrink-0 items-center gap-1">
                    {peerTransportPaths[peer.peerId] && (
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                          peerTransportPaths[peer.peerId] === "turn"
                            ? "bg-amber-500/15 text-amber-700 dark:text-amber-200"
                            : "bg-emerald-500/15 text-emerald-700 dark:text-emerald-200"
                        }`}
                      >
                        {transportPathLabel(peerTransportPaths[peer.peerId])}
                      </span>
                    )}
                    {selectedPeerId === peer.peerId && (
                      <span className="rounded bg-cyan-500/15 px-1.5 py-0.5 text-[10px] font-medium text-cyan-700 dark:text-cyan-100">
                        已选
                      </span>
                    )}
                  </div>
                </div>
              </button>
            ))}
          </div>
        </aside> : null}
      </section>
      <TransferInviteModal
        isOpen={inviteOpen}
        onClose={() => setInviteOpen(false)}
        networkMode={networkMode}
        roomId={roomId}
        currentRole={roomRole}
        inviteRole={roomInviteRole}
        onInviteRoleChange={setRoomInviteRole}
        inviteUrl={roomJoinUrl}
        qrUrl={isInternetMode ? pairingJoinUrl : roomJoinUrl}
        accessExpiresAt={createdRoomAccess?.access.role === roomInviteRole
          ? createdRoomAccess.access.expiresAt
          : null}
        pairingCode={pairingCode?.role === roomInviteRole ? pairingCode : null}
        isPreparing={roomAccessLoading || pairingCodeLoading}
        isPairingCodeLoading={pairingCodeLoading}
        error={inviteError}
        canUseSystemShare={canUseSystemShare()}
        onShare={() => void shareRoom()}
        onCopy={() => void copyRoomLink()}
        onRegenerate={() => void regenerateSecureInvite()}
        onRegeneratePairing={() => void regeneratePairingCode()}
        pairingCodeDraft={pairingCodeDraft}
        onPairingCodeDraftChange={setPairingCodeDraft}
        isRedeeming={pairingCodeRedeeming}
        onRedeem={() => void redeemPairingCode()}
      />
      <Modal
        isOpen={roomSettingsOpen}
        size="2xl"
        scrollBehavior="inside"
        onOpenChange={(open) => {
          setRoomSettingsOpen(open);
          if (!open) resetRoomSettingsDraft();
        }}
      >
        <ModalContent className="transfer-room-settings-modal">
          {(onClose) => (
            <>
              <ModalHeader className="flex items-center justify-between gap-3">
                <span>房间设置</span>
                <Chip size="sm" radius="sm" variant="flat">{isInternetMode ? "远程房间" : "附近房间"}</Chip>
              </ModalHeader>
              <ModalBody className="gap-5 pb-5">
                <section className="grid gap-3 sm:grid-cols-2">
                  <div className="sm:col-span-2">
                    <h3 className="mb-2 text-small font-semibold text-zinc-900 dark:text-white">设备与房间</h3>
                    <ClientNameSettings
                      hideAction
                      inputId="transfer-client-name-input"
                      value={displayNameDraft}
                      onValueChange={setDisplayNameDraft}
                      status={clientNameStatus}
                      localError={clientNameLocalError}
                      isSaving={clientNameSaving}
                      onApply={() => void saveRoomSettings()}
                    />
                  </div>
                  <Input
                    label="房间名称"
                    radius="sm"
                    variant="bordered"
                    value={roomIdDraft}
                    onValueChange={updateRoomIdDraft}
                    maxLength={MAX_TRANSFER_ROOM_NAME_LENGTH}
                    isInvalid={Boolean(roomSettingsErrors.roomId)}
                    errorMessage={roomSettingsErrors.roomId}
                  />
                  {isInternetMode ? (
                    <Input
                      label="房间口令"
                      radius="sm"
                      variant="bordered"
                      value={roomTokenDraft}
                      onValueChange={updateRoomTokenDraft}
                      maxLength={MAX_TRANSFER_ROOM_TOKEN_LENGTH}
                      isInvalid={Boolean(roomSettingsErrors.roomToken)}
                      errorMessage={roomSettingsErrors.roomToken}
                      endContent={(
                        <Button size="sm" variant="light" onPress={() => updateRoomTokenDraft(createRoomToken())}>生成</Button>
                      )}
                    />
                  ) : (
                    <div className="rounded-md border border-black/[0.07] bg-black/[0.018] px-3 py-2.5 text-small text-zinc-600 dark:border-white/[0.08] dark:bg-white/[0.025] dark:text-zinc-300">
                      附近房间会发现同一网络中的设备，不需要口令。
                    </div>
                  )}
                </section>

                {!isDiagramWorkspace ? (
                  <section className="flex items-center justify-between gap-4 border-t border-black/[0.07] pt-4 dark:border-white/[0.08]">
                    <div>
                      <h3 className="text-small font-semibold text-zinc-900 dark:text-white">接收前确认</h3>
                      <p className="mt-1 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
                        {receiveConfirmationRequired ? "收到文件后由你确认是否接收。" : "收到文件后立即开始接收。"}
                      </p>
                    </div>
                    <Switch
                      size="sm"
                      aria-label="切换接收前确认"
                      isSelected={receiveConfirmationRequired}
                      onValueChange={updateReceiveConfirmationRequired}
                    />
                  </section>
                ) : null}

                {isInternetMode ? (
                  <section className="border-t border-black/[0.07] pt-4 dark:border-white/[0.08]">
                    <RoomPermissionSetting
                      networkMode={networkMode}
                      currentRole={effectiveRoomRole}
                      inviteRole={roomInviteRole}
                      canManage={roomRole === "OWNER"}
                      isLoading={roomAccessLoading}
                      onInviteRoleChange={setRoomInviteRole}
                      onCreateInvite={() => void createRoomAccess(roomInviteRole)}
                    />
                  </section>
                ) : null}

                {isInternetMode && roomRole === "OWNER" ? (
                  <section className="border-t border-black/[0.07] pt-4 dark:border-white/[0.08]">
                    <div className="flex items-center justify-between gap-3">
                      <h3 className="text-small font-semibold text-zinc-900 dark:text-white">邀请记录</h3>
                      <Chip size="sm" radius="sm" variant="flat">{roomAccessTokens.length}</Chip>
                    </div>
                    {createdRoomAccess ? (
                      <div className="mt-2 flex items-center justify-between gap-3 rounded-md border border-amber-500/25 bg-amber-50/80 px-3 py-2 dark:border-amber-300/20 dark:bg-amber-300/10">
                        <span className="min-w-0 truncate text-tiny text-amber-900 dark:text-amber-100">{createdRoomAccess.access.label} · 链接仅显示一次</span>
                        <Button size="sm" radius="sm" color="warning" variant="flat" onPress={() => void copyCreatedRoomAccessLink()}>复制</Button>
                      </div>
                    ) : null}
                    <div className="mt-2 grid gap-2 sm:grid-cols-2">
                      {roomAccessTokens.length === 0 ? (
                        <div className="text-tiny text-zinc-400">{roomAccessLoading ? "正在加载邀请…" : "暂无邀请记录"}</div>
                      ) : roomAccessTokens.map((access) => (
                        <div key={access.id} className="flex min-h-11 items-center justify-between gap-2 rounded-md border border-black/[0.07] px-3 py-2 dark:border-white/[0.08]">
                          <div className="min-w-0">
                            <div className="truncate text-tiny font-medium text-zinc-800 dark:text-zinc-200">{access.label}</div>
                            <div className="truncate text-[11px] text-zinc-400">{access.role === "EDITOR" ? "可编辑" : "只读"} · {access.revokedAt ? "已撤销" : isAccessTokenExpired(access) ? "已过期" : access.expiresAt ? formatInviteExpiry(access.expiresAt) : new Date(access.createdAt).toLocaleString()}</div>
                          </div>
                          <Button size="sm" radius="sm" color="danger" variant="light" isDisabled={Boolean(access.revokedAt) || roomAccessLoading} onPress={() => void revokeRoomAccess(access)}>{access.revokedAt ? "已撤销" : "撤销"}</Button>
                        </div>
                      ))}
                    </div>
                  </section>
                ) : null}
              </ModalBody>
              <ModalFooter className="justify-between">
                <Button color="danger" variant="light" radius="sm" onPress={createNewRoom}>创建新房间</Button>
                <div className="flex items-center gap-2">
                  <Button variant="light" radius="sm" onPress={onClose}>取消</Button>
                  <Button
                    color="primary"
                    radius="sm"
                    isLoading={clientNameSaving}
                    isDisabled={Boolean(clientNameLocalError) || clientNameStatus === "checking" || clientNameStatus === "unavailable"}
                    onPress={() => void saveRoomSettings()}
                  >
                    保存设置
                  </Button>
                </div>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>

      <Modal
        isOpen={activityCenterOpen}
        size="2xl"
        scrollBehavior="inside"
        onOpenChange={(open) => {
          setActivityCenterOpen(open);
          if (open) {
            setOutgoingActivities((activities) => activities.map((activity) => ({ ...activity, unread: false })));
          }
        }}
      >
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader className="flex items-center justify-between gap-3">
                <span>传输任务</span>
                <Chip size="sm" radius="sm" variant="flat">
                  {activeOutgoingCount + receivingTransfers.length + pendingTransfers.length} 个进行中
                </Chip>
              </ModalHeader>
              <ModalBody className="gap-5 pb-5">
                <TransferActivityList
                  outgoing={outgoingActivities}
                  pending={pendingTransfers}
                  receiving={receivingTransfers}
                  peerDisplayNames={diagramPeerDisplayNames}
                  onCancel={cancelOutgoingActivity}
                  onRetry={retryOutgoingActivity}
                  onAccept={(item) => acceptIncomingTransfer(item.sourcePeerId, item.transferId)}
                  onReject={(item) => rejectIncomingTransfer(item.sourcePeerId, item.transferId)}
                  onCancelReceiving={(item) => cancelIncomingTransfer(item.sourcePeerId, item.transferId)}
                />
              </ModalBody>
              <ModalFooter>
                <Button
                  variant="light"
                  radius="sm"
                  onPress={() => setOutgoingActivities((activities) => activities.filter((activity) => (
                    activity.status === "queued" || activity.status === "connecting" || activity.status === "sending"
                  )))}
                >
                  清理已完成
                </Button>
                <Button color="primary" radius="sm" onPress={onClose}>完成</Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>

      <Modal isOpen={helpOpen} size="2xl" scrollBehavior="inside" onOpenChange={setHelpOpen}>
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader>互传帮助</ModalHeader>
              <ModalBody className="pb-5">
                <TransferFaq iceConfig={iceConfig} networkMode={networkMode} ossFallbackEnabled={ossFallbackEnabled} />
              </ModalBody>
              <ModalFooter><Button color="primary" radius="sm" onPress={onClose}>知道了</Button></ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>
      <PreviewModal target={previewTarget} onClose={() => setPreviewTarget(null)} />
      {sharedModals}
    </main>
  );
}

function ClientNameSettings({
  compact = false,
  hideAction = false,
  inputId,
  value,
  onValueChange,
  status,
  localError,
  isSaving,
  onApply,
}: {
  compact?: boolean;
  hideAction?: boolean;
  inputId: string;
  value: string;
  onValueChange: (value: string) => void;
  status: ClientNameStatus;
  localError: string;
  isSaving: boolean;
  onApply: () => void;
}) {
  const errorMessage = localError
    || (status === "unavailable" ? "该名称已被其他在线设备使用" : "")
    || (status === "error" ? "暂时无法校验名称，请稍后重试" : "");
  const description = status === "checking"
    ? "正在检查名称是否可用…"
    : status === "available" && !localError
      ? "名称可用，保存后立即更新"
      : "在线名称全局唯一，每个标签页可以设置不同名称";

  return (
    <div className={`grid gap-1.5 ${hideAction ? "" : compact ? "grid-cols-[minmax(0,1fr)_auto] items-start" : "sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start"}`}>
      <Input
        id={inputId}
        size={compact ? "sm" : "md"}
        label={compact ? "客户端名称" : "我的客户端名称"}
        radius="sm"
        variant="bordered"
        value={value}
        onValueChange={onValueChange}
        maxLength={MAX_TRANSFER_CLIENT_NAME_LENGTH}
        isRequired
        isInvalid={Boolean(errorMessage)}
        errorMessage={errorMessage}
        description={compact ? undefined : description}
        endContent={compact && !errorMessage ? (
          <span className={`whitespace-nowrap text-[10px] ${status === "available" ? "text-emerald-600 dark:text-emerald-400" : "text-zinc-400"}`}>
            {status === "checking" ? "校验中" : status === "available" ? "可用" : ""}
          </span>
        ) : undefined}
        onKeyDown={(event) => {
          if (event.key === "Enter" && !localError && status !== "checking" && status !== "unavailable") {
            onApply();
          }
        }}
      />
      {!hideAction ? <Button
        className={compact ? "mt-1" : "sm:mt-2"}
        size={compact ? "sm" : "md"}
        color="primary"
        radius="sm"
        variant="flat"
        isDisabled={Boolean(localError) || status === "checking" || status === "unavailable"}
        isLoading={isSaving}
        onPress={onApply}
      >
        {compact ? "保存" : "保存名称"}
      </Button> : null}
    </div>
  );
}

function RoomPermissionSetting({
  compact = false,
  context = "transfer",
  networkMode,
  currentRole,
  inviteRole,
  canManage,
  isLoading,
  onInviteRoleChange,
  onCreateInvite,
}: {
  compact?: boolean;
  context?: "transfer" | "diagram";
  networkMode: TransferNetworkMode;
  currentRole: PublicTransferRoomRole;
  inviteRole: TransferInviteRole;
  canManage: boolean;
  isLoading: boolean;
  onInviteRoleChange: (role: TransferInviteRole) => void;
  onCreateInvite: () => void;
}) {
  const isInternetMode = networkMode === "internet";
  const currentRoleLabel = currentRole === "OWNER" ? "房主" : currentRole === "EDITOR" ? "可编辑" : "只读";
  const displayedRole = canManage ? inviteRole : currentRole === "VIEWER" ? "VIEWER" : "EDITOR";
  const editorRoleDetail = context === "diagram" ? "编辑画布、评论和版本" : "发送文件、剪贴板和白板";
  const viewerRoleDetail = context === "diagram" ? "查看画布和协作更新" : "仅查看和接收房间内容";
  const description = !isInternetMode
    ? "附近房间默认允许编辑；切换到远程模式后，可以为邀请链接设置可编辑或只读权限。"
    : canManage
      ? "此设置作用于新生成的邀请链接，不会改变房主自身权限。"
      : "当前权限由加入房间时使用的邀请链接决定，只有房主可以生成不同权限的链接。";

  if (compact) {
    return (
      <div
        className="grid gap-2 sm:grid-cols-[auto_minmax(220px,1fr)_auto] sm:items-center"
        title={description}
      >
        <div className="flex items-center gap-2">
          <span className="whitespace-nowrap text-tiny font-medium text-zinc-800 dark:text-zinc-200">邀请权限</span>
          <Chip size="sm" radius="sm" variant="flat" color={currentRole === "VIEWER" ? "default" : "success"}>
            {currentRoleLabel}
          </Chip>
        </div>
        <div
          className="grid min-w-0 grid-cols-2 rounded-md border border-black/[0.07] bg-black/[0.018] p-0.5 dark:border-white/[0.08] dark:bg-white/[0.025]"
          role="radiogroup"
          aria-label="新成员房间权限"
        >
          {([['EDITOR', '可编辑'], ['VIEWER', '只读']] as const).map(([role, label]) => (
            <button
              key={role}
              type="button"
              role="radio"
              aria-checked={displayedRole === role}
              disabled={!canManage}
              className={`h-7 rounded px-2 text-tiny font-medium transition-colors ${displayedRole === role ? "bg-white text-zinc-950 shadow-sm dark:bg-white/10 dark:text-white" : "text-zinc-500 dark:text-zinc-400"} disabled:cursor-not-allowed`}
              onClick={() => onInviteRoleChange(role)}
            >
              {label}
            </button>
          ))}
        </div>
        {canManage ? (
          <Button
            className="shrink-0"
            size="sm"
            radius="sm"
            color="primary"
            variant="flat"
            isLoading={isLoading}
            onPress={onCreateInvite}
          >
            生成邀请
          </Button>
        ) : null}
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-black/10 bg-black/[0.018] p-3 dark:border-white/10 dark:bg-white/[0.025]">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-small font-medium text-zinc-900 dark:text-white">房间权限</div>
          <div className="mt-0.5 text-tiny text-zinc-500 dark:text-zinc-400">设置新成员加入后可以执行的操作</div>
        </div>
        <Chip size="sm" radius="sm" variant="flat" color={currentRole === "VIEWER" ? "default" : "success"}>
          当前：{currentRoleLabel}
        </Chip>
      </div>

      <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div
          className="grid min-w-0 flex-1 grid-cols-2 rounded-md border border-black/10 bg-white/60 p-1 dark:border-white/10 dark:bg-black/15"
          role="radiogroup"
          aria-label="新成员房间权限"
        >
          <button
            type="button"
            role="radio"
            aria-checked={displayedRole === "EDITOR"}
            disabled={!canManage}
            className={`rounded px-3 py-2 text-left transition-colors ${displayedRole === "EDITOR" ? "bg-white text-zinc-950 shadow-sm dark:bg-white/10 dark:text-white" : "text-zinc-500 dark:text-zinc-400"} disabled:cursor-not-allowed`}
            onClick={() => onInviteRoleChange("EDITOR")}
          >
            <span className="block text-small font-semibold">可编辑</span>
            <span className="mt-0.5 block text-[10px] leading-4 opacity-75">{editorRoleDetail}</span>
          </button>
          <button
            type="button"
            role="radio"
            aria-checked={displayedRole === "VIEWER"}
            disabled={!canManage}
            className={`rounded px-3 py-2 text-left transition-colors ${displayedRole === "VIEWER" ? "bg-white text-zinc-950 shadow-sm dark:bg-white/10 dark:text-white" : "text-zinc-500 dark:text-zinc-400"} disabled:cursor-not-allowed`}
            onClick={() => onInviteRoleChange("VIEWER")}
          >
            <span className="block text-small font-semibold">只读</span>
            <span className="mt-0.5 block text-[10px] leading-4 opacity-75">{viewerRoleDetail}</span>
          </button>
        </div>
        {canManage ? (
          <Button
            className="shrink-0"
            size="sm"
            radius="sm"
            color="primary"
            variant="flat"
            isLoading={isLoading}
            onPress={onCreateInvite}
          >
            生成邀请链接
          </Button>
        ) : null}
      </div>
      <p className="mt-2 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">{description}</p>
    </div>
  );
}

function NetworkModeToggle({
  activeMode,
  onSelect,
}: {
  activeMode: TransferNetworkMode;
  onSelect: (mode: TransferNetworkMode) => void;
}) {
  const isInternetMode = activeMode === "internet";
  return (
    <div className="transfer-network-toggle">
      <span className={!isInternetMode ? "is-active" : ""}>附近</span>
      <Switch
        size="sm"
        color="primary"
        aria-label="切换附近或远程模式"
        isSelected={isInternetMode}
        onValueChange={(selected) => onSelect(selected ? "internet" : "lan")}
      />
      <span className={isInternetMode ? "is-active" : ""}>远程</span>
    </div>
  );
}

function DiagramWorkspaceLoading({ fullscreen = false }: { fullscreen?: boolean }) {
  return (
    <section className={fullscreen
      ? "fixed inset-0 grid h-[100dvh] place-items-center bg-zinc-100 dark:bg-zinc-950"
      : "mt-5 grid min-h-[520px] place-items-center rounded-2xl border border-black/[0.07] bg-zinc-50/70 dark:border-white/[0.08] dark:bg-zinc-950/55"}
    >
      <div className="flex flex-col items-center gap-3 text-center">
        <span className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--app-apple-blue-soft)] border-t-[var(--app-apple-blue)]" aria-hidden="true" />
        <span className="text-small font-semibold text-zinc-900 dark:text-white">正在加载专业流程图工具</span>
      </div>
    </section>
  );
}

function TransferActivityList({
  outgoing,
  pending,
  receiving,
  peerDisplayNames,
  onCancel,
  onRetry,
  onAccept,
  onReject,
  onCancelReceiving,
}: {
  outgoing: OutgoingTransferActivity[];
  pending: DirectPendingTransfer[];
  receiving: DirectReceivingTransfer[];
  peerDisplayNames: Record<string, string>;
  onCancel: (activityId: string) => void;
  onRetry: (activity: OutgoingTransferActivity) => void;
  onAccept: (item: DirectPendingTransfer) => void;
  onReject: (item: DirectPendingTransfer) => void;
  onCancelReceiving: (item: DirectReceivingTransfer) => void;
}) {
  if (outgoing.length === 0 && pending.length === 0 && receiving.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-black/10 px-4 py-8 text-center text-small text-zinc-500 dark:border-white/10 dark:text-zinc-400">
        暂无传输任务
      </div>
    );
  }
  const completedCount = outgoing.filter((activity) => activity.status === "completed").length;
  const failedCount = outgoing.filter((activity) => activity.status === "failed").length;
  const retryableCount = outgoing.filter((activity) => activity.status === "failed" || activity.status === "cancelled").length;
  const activeCount = outgoing.filter((activity) => (
    activity.status === "queued" || activity.status === "connecting" || activity.status === "sending"
  )).length;
  return (
    <>
      {outgoing.length > 0 ? (
        <div
          className="grid grid-cols-3 gap-2 rounded-md border border-black/[0.07] bg-black/[0.018] p-2.5 text-center dark:border-white/[0.08] dark:bg-white/[0.025]"
          role="status"
          aria-label={`${activeCount} 个进行中，${completedCount} 个成功，${retryableCount} 个可重试`}
        >
          <span><strong className="block text-base text-zinc-900 dark:text-white">{activeCount}</strong><span className="text-[11px] text-zinc-500 dark:text-zinc-400">进行中</span></span>
          <span><strong className="block text-base text-emerald-700 dark:text-emerald-300">{completedCount}</strong><span className="text-[11px] text-zinc-500 dark:text-zinc-400">成功</span></span>
          <span><strong className={`block text-base ${failedCount > 0 ? "text-rose-700 dark:text-rose-300" : "text-zinc-700 dark:text-zinc-200"}`}>{retryableCount}</strong><span className="text-[11px] text-zinc-500 dark:text-zinc-400">可重试</span></span>
        </div>
      ) : null}
      {outgoing.length > 0 ? (
        <section className="mt-4">
          <h3 className="mb-2 text-small font-semibold text-zinc-900 dark:text-white">正在发送与历史</h3>
          <div className="space-y-2">
            {outgoing.map((activity) => {
              const active = activity.status === "queued" || activity.status === "connecting" || activity.status === "sending";
              return (
                <div key={activity.id} className="rounded-md border border-black/[0.07] px-3 py-2.5 dark:border-white/[0.08]">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-small font-medium text-zinc-900 dark:text-white">{activity.fileName}</div>
                      <div className="mt-0.5 truncate text-tiny text-zinc-500 dark:text-zinc-400">
                        发给 {activity.targetPeerLabel} · {formatBytes(activity.sizeBytes)}
                        {activity.transport ? ` · ${transferTransportLabel(activity.transport)}` : ""}
                      </div>
                    </div>
                    <Chip size="sm" radius="sm" variant="flat" color={transferActivityStatusColor(activity.status)}>
                      {transferActivityStatusLabel(activity.status)}
                    </Chip>
                  </div>
                  {(active || activity.progress > 0) ? (
                    <div className="mt-2">
                      <Progress
                        size="sm"
                        aria-label={`${activity.fileName} 传输进度`}
                        value={activity.progress}
                        color={activity.status === "failed" || activity.status === "cancelled" ? "danger" : "primary"}
                      />
                      <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-zinc-400">
                        <span>{formatBytes(activity.transferredBytes)} / {formatBytes(activity.sizeBytes)}</span>
                        <span>
                          {activity.speedBytesPerSecond > 0 ? `${formatBytes(activity.speedBytesPerSecond)}/s` : ""}
                          {activity.etaSeconds !== null && activity.etaSeconds > 0 ? ` · 约 ${formatDuration(activity.etaSeconds)}` : ""}
                        </span>
                      </div>
                    </div>
                  ) : null}
                  {activity.error ? <div className="mt-1.5 text-tiny text-rose-600 dark:text-rose-300">{activity.error}</div> : null}
                  {active || activity.status === "failed" || activity.status === "cancelled" ? (
                    <div className="mt-2 flex justify-end gap-1.5">
                      {active ? <Button size="sm" radius="sm" variant="light" color="danger" onPress={() => onCancel(activity.id)}>取消</Button> : null}
                      {activity.status === "failed" || activity.status === "cancelled" ? (
                        <Button size="sm" radius="sm" color="primary" variant="flat" onPress={() => onRetry(activity)}>重试</Button>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </section>
      ) : null}

      {pending.length > 0 || receiving.length > 0 ? (
        <section>
          <h3 className="mb-2 text-small font-semibold text-zinc-900 dark:text-white">正在接收</h3>
          <div className="space-y-2">
            {pending.map((item) => (
              <div key={`pending-${item.sourcePeerId}-${item.transferId}`} className="flex items-center justify-between gap-3 rounded-md border border-amber-300 bg-amber-50 px-3 py-2.5 dark:border-amber-400/25 dark:bg-amber-500/10">
                <div className="min-w-0">
                  <div className="truncate text-small font-medium">{item.fileName}</div>
                  <div className="mt-0.5 truncate text-tiny opacity-75">来自 {peerDisplayNames[item.sourcePeerId] || "未命名设备"} · {formatBytes(item.sizeBytes)}</div>
                </div>
                <div className="flex shrink-0 gap-1.5">
                  <Button size="sm" radius="sm" variant="light" color="danger" onPress={() => onReject(item)}>拒绝</Button>
                  <Button size="sm" radius="sm" color="primary" onPress={() => onAccept(item)}>接收</Button>
                </div>
              </div>
            ))}
            {receiving.map((item) => {
              const progress = item.sizeBytes > 0 ? Math.min(100, item.receivedBytes * 100 / item.sizeBytes) : 0;
              return (
                <div key={`receiving-${item.sourcePeerId}-${item.transferId}`} className="rounded-md border border-black/[0.07] px-3 py-2.5 dark:border-white/[0.08]">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-small font-medium">{item.fileName}</div>
                      <div className="mt-0.5 truncate text-tiny text-zinc-500 dark:text-zinc-400">来自 {peerDisplayNames[item.sourcePeerId] || "未命名设备"}</div>
                    </div>
                    <Button size="sm" radius="sm" variant="light" color="danger" onPress={() => onCancelReceiving(item)}>取消</Button>
                  </div>
                  <Progress className="mt-2" size="sm" aria-label={`${item.fileName} 接收进度`} value={progress} />
                  <div className="mt-1 text-[11px] text-zinc-400">{formatBytes(item.receivedBytes)} / {formatBytes(item.sizeBytes)}</div>
                </div>
              );
            })}
          </div>
        </section>
      ) : null}
    </>
  );
}

function ToolModeButton({
  mode,
  activeMode,
  label,
  detail,
  unreadCount = 0,
  onSelect,
}: {
  mode: TransferToolMode;
  activeMode: TransferToolMode;
  label: string;
  detail: string;
  unreadCount?: number;
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
      className={`app-apple-tool-tab min-w-0 px-3 py-2 text-left transition-colors ${active ? "is-active" : ""}`}
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
      <span className="flex items-center gap-1.5">
        <span className="min-w-0 truncate text-small font-semibold">{label}</span>
        {unreadCount > 0 ? (
          <span className="grid min-h-4 min-w-4 shrink-0 place-items-center rounded-full bg-primary-600 px-1 text-[10px] font-semibold text-white">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        ) : null}
      </span>
      <span className="app-apple-tool-tab-detail mt-0.5 block truncate text-[11px]">
        {detail}
      </span>
    </button>
  );
}

function IncomingFilesPanel({
  pendingTransfers,
  receivingTransfers,
  peerTransportPaths,
  peerDisplayNames,
  incoming,
  cloudTransferEnabled,
  onAcceptDirect,
  onRejectDirect,
  onCancelReceiving,
  onShare,
  onDownload,
  onLogin,
  onPreview,
}: {
  pendingTransfers: DirectPendingTransfer[];
  receivingTransfers: DirectReceivingTransfer[];
  peerTransportPaths: Record<string, PeerTransportPath>;
  peerDisplayNames: Record<string, string>;
  incoming: IncomingAttachment[];
  cloudTransferEnabled: boolean;
  onAcceptDirect: (item: DirectPendingTransfer) => void;
  onRejectDirect: (item: DirectPendingTransfer) => void;
  onCancelReceiving: (item: DirectReceivingTransfer) => void;
  onShare: (item: IncomingAttachment) => Promise<void>;
  onDownload: (item: IncomingAttachment) => Promise<void>;
  onLogin: () => void;
  onPreview: (target: PreviewTarget) => void;
}) {
  const hasPending = pendingTransfers.length > 0;
  const hasReceiving = receivingTransfers.length > 0;
  const hasIncoming = incoming.length > 0;
  const sourceLabel = (sourcePeerId: string) => peerDisplayNames[sourcePeerId]
    ?? (sourcePeerId === "shared-link" ? "共享链接" : sourcePeerId);

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
                    来自 <span title={item.sourcePeerId}>{sourceLabel(item.sourcePeerId)}</span> · {formatBytes(item.sizeBytes)}
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
            const pathLabel = transportPathLabel(peerTransportPaths[item.sourcePeerId]);
            return (
              <div key={receivingTransferKey(item)} className="rounded-lg border border-cyan-400/30 bg-cyan-50/70 p-3 dark:border-cyan-300/20 dark:bg-cyan-400/10">
                <div className="truncate text-small font-medium text-cyan-950 dark:text-cyan-100">{item.fileName}</div>
                <div className="mt-1 text-tiny text-cyan-800/75 dark:text-cyan-100/70">
                  来自 <span title={item.sourcePeerId}>{sourceLabel(item.sourcePeerId)}</span> · {formatBytes(item.receivedBytes)} / {formatBytes(item.sizeBytes)}{pathLabel ? ` · ${pathLabel}` : ""}
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <Progress className="flex-1" aria-label={`${item.fileName} 接收进度`} color="primary" size="sm" value={percent} />
                  <Button size="sm" radius="sm" variant="light" onPress={() => onCancelReceiving(item)}>
                    取消
                  </Button>
                </div>
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
          const previewUrl = item.previewUrl;
          const cloudLoginRequired = !item.direct && !cloudTransferEnabled;
          return (
            <div key={incomingItemKey(item)} className="rounded-lg glass glass-border border p-3">
              <div className="truncate text-small font-medium">{item.attachment.fileName}</div>
              <div className="mt-1 text-tiny text-zinc-500">
                来自 <span title={item.sourcePeerId}>{sourceLabel(item.sourcePeerId)}</span> · {formatBytes(item.attachment.sizeBytes)}{item.direct ? " · 设备直连" : ""}
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
                <Button size="sm" radius="sm" variant="flat" isDisabled={cloudLoginRequired} onPress={() => void onShare(item)}>
                  分享
                </Button>
                <Button
                  size="sm"
                  radius="sm"
                  color="success"
                  variant={item.downloadUrl || item.direct ? "solid" : "flat"}
                  isLoading={item.downloading}
                  onPress={() => cloudLoginRequired ? onLogin() : void onDownload(item)}
                >
                  {item.direct ? "保存" : cloudLoginRequired ? "登录下载" : "下载"}
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

function TransferProgress({
  state,
  store,
  transportPath,
  busy,
  onCancel,
}: {
  state: UploadState;
  store: TransferProgressStore;
  transportPath?: PeerTransportPath;
  busy: boolean;
  onCancel: () => void;
}) {
  const progress = useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
  const [waitingSeconds, setWaitingSeconds] = useState(0);
  useEffect(() => {
    if (state !== "waiting") {
      setWaitingSeconds(0);
      return undefined;
    }
    const startedAt = Date.now();
    const timer = window.setInterval(() => {
      setWaitingSeconds(Math.floor((Date.now() - startedAt) / 1000));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [state]);
  const pathLabel = state === "direct" || state === "waiting" ? transportPathLabel(transportPath) : null;
  const indeterminate = state === "connecting"
    || state === "waiting"
    || state === "presigning"
    || state === "completing";
  return (
    <>
      <Progress
        aria-label="上传进度"
        isIndeterminate={indeterminate}
        value={indeterminate ? undefined : state === "done" ? 100 : progress}
        color={state === "failed" ? "danger" : "primary"}
        size="sm"
      />
      <div className="mt-2 flex items-center gap-1.5 text-tiny text-zinc-500 dark:text-zinc-400">
        <span>{state === "waiting" ? `等待对方确认接收（已等待 ${waitingSeconds} 秒）` : stateLabel(state, progress)}</span>
        {pathLabel && (
          <span
            className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
              transportPath === "turn"
                ? "bg-amber-500/15 text-amber-700 dark:text-amber-200"
                : "bg-emerald-500/15 text-emerald-700 dark:text-emerald-200"
            }`}
          >
            {pathLabel}
          </span>
        )}
        {busy ? (
          <Button className="ml-auto" size="sm" radius="sm" color="danger" variant="light" onPress={onCancel}>
            取消
          </Button>
        ) : null}
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

function TransferInviteModal({
  isOpen,
  onClose,
  networkMode,
  roomId,
  currentRole,
  inviteRole,
  onInviteRoleChange,
  inviteUrl,
  qrUrl,
  accessExpiresAt,
  pairingCode,
  isPreparing,
  isPairingCodeLoading,
  error,
  canUseSystemShare: systemShareAvailable,
  onShare,
  onCopy,
  onRegenerate,
  onRegeneratePairing,
  pairingCodeDraft,
  onPairingCodeDraftChange,
  isRedeeming,
  onRedeem,
}: {
  isOpen: boolean;
  onClose: () => void;
  networkMode: TransferNetworkMode;
  roomId: string;
  currentRole: PublicTransferRoomRole | null;
  inviteRole: TransferInviteRole;
  onInviteRoleChange: (role: TransferInviteRole) => void;
  inviteUrl: string | null;
  qrUrl: string | null;
  accessExpiresAt: string | null;
  pairingCode: PublicTransferPairingCode | null;
  isPreparing: boolean;
  isPairingCodeLoading: boolean;
  error: string | null;
  canUseSystemShare: boolean;
  onShare: () => void;
  onCopy: () => void;
  onRegenerate: () => void;
  onRegeneratePairing: () => void;
  pairingCodeDraft: string;
  onPairingCodeDraftChange: (value: string) => void;
  isRedeeming: boolean;
  onRedeem: () => void;
}) {
  const isInternetMode = networkMode === "internet";
  const canInvite = !isInternetMode || currentRole === "OWNER";
  const rolePending = isInternetMode && currentRole === null;
  const formattedPairingCode = pairingCode ? formatPairingCode(pairingCode.code) : "";
  const inviteExpiry = accessExpiresAt ? formatInviteExpiry(accessExpiresAt) : null;
  const pairingExpiry = pairingCode ? formatInviteExpiry(pairingCode.expiresAt) : null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      size="3xl"
      scrollBehavior="inside"
      backdrop="blur"
      classNames={{
        base: "border border-black/10 bg-white/95 shadow-2xl dark:border-white/10 dark:bg-zinc-950/95",
        closeButton: "top-4 right-4",
      }}
    >
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1 border-b border-black/[0.07] px-5 py-4 pr-14 dark:border-white/[0.08] sm:px-7">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-lg font-semibold tracking-tight sm:text-xl">邀请对方加入</span>
            <Chip size="sm" radius="sm" color={isInternetMode ? "primary" : "success"} variant="flat">
              {isInternetMode ? "跨网络" : "同一网络"}
            </Chip>
          </div>
          <p className="text-tiny font-normal leading-5 text-zinc-500 dark:text-zinc-400">
            房间 {transferRoomDisplayName(roomId)} · {isInternetMode ? "邀请只包含限时权限，不包含房主凭证" : "扫码设备需连接同一网络"}
          </p>
        </ModalHeader>
        <ModalBody className="gap-0 overflow-y-auto px-5 pb-6 pt-5 sm:px-7">
          {canInvite ? (
            <div className="grid items-stretch gap-5 md:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)] md:gap-7">
              <div className="order-2 flex min-h-[292px] flex-col items-center justify-center overflow-hidden rounded-[28px] border border-cyan-500/15 bg-[radial-gradient(circle_at_50%_18%,rgba(34,211,238,0.18),transparent_46%),linear-gradient(145deg,rgba(8,145,178,0.08),rgba(37,99,235,0.04))] px-5 py-6 dark:border-cyan-300/15 dark:bg-[radial-gradient(circle_at_50%_18%,rgba(34,211,238,0.18),transparent_48%),linear-gradient(145deg,rgba(8,145,178,0.10),rgba(37,99,235,0.06))] md:order-1">
                {qrUrl ? (
                  <>
                    <div className="relative">
                      <span className="absolute -inset-4 -z-0 rounded-[30px] bg-cyan-400/10 blur-xl" aria-hidden="true" />
                      <RoomQrCode value={qrUrl} large />
                    </div>
                    <div className="mt-4 text-center text-small font-semibold text-zinc-900 dark:text-white">
                      {isInternetMode ? "扫码立即配对" : "扫码加入房间"}
                    </div>
                    <div className="mt-1 max-w-56 text-center text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
                      {isInternetMode ? "二维码 5 分钟内单次有效，扫码后自动加入。" : "链接不携带 Token，只用于同网设备发现。"}
                    </div>
                  </>
                ) : (
                  <div className="flex flex-col items-center text-center">
                    <div className="relative h-24 w-24" aria-hidden="true">
                      <span className="absolute inset-0 animate-ping rounded-full border border-cyan-400/40 motion-reduce:animate-none" />
                      <span className="absolute inset-4 rounded-full border border-cyan-500/30" />
                      <span className="absolute inset-[38px] rounded-full bg-cyan-500 shadow-[0_0_24px_rgba(6,182,212,0.65)]" />
                    </div>
                    <div className="mt-4 text-small font-semibold">{isPreparing ? "正在建立安全邀请" : "等待生成二维码"}</div>
                    <div className="mt-1 text-tiny text-zinc-500 dark:text-zinc-400">不会使用房主 Token 作为兜底</div>
                  </div>
                )}
              </div>

              <div className="order-1 flex min-w-0 flex-col md:order-2">
                {isInternetMode ? (
                  <div>
                    <div className="text-tiny font-medium text-zinc-500 dark:text-zinc-400">对方加入后可以</div>
                    <div className="mt-2 grid grid-cols-2 gap-2" role="radiogroup" aria-label="邀请权限">
                      {(["EDITOR", "VIEWER"] as const).map((role) => (
                        <button
                          key={role}
                          type="button"
                          role="radio"
                          aria-checked={inviteRole === role}
                          className={`rounded-xl border px-3 py-2.5 text-left transition-colors ${inviteRole === role
                            ? "border-cyan-500/45 bg-cyan-500/10 text-cyan-800 dark:text-cyan-100"
                            : "border-black/10 bg-black/[0.02] text-zinc-600 hover:border-black/20 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-300 dark:hover:border-white/20"}`}
                          onClick={() => onInviteRoleChange(role)}
                        >
                          <span className="block text-small font-semibold">{role === "EDITOR" ? "互传与协作" : "只读查看"}</span>
                          <span className="mt-0.5 block text-[10px] opacity-70">{role === "EDITOR" ? "可发文件、剪贴板与白板" : "只能接收和查看内容"}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                ) : null}

                <Button
                  className="mt-4 h-11 w-full bg-cyan-600 font-semibold text-white shadow-[0_10px_30px_rgba(8,145,178,0.22)] md:mt-5"
                  color="primary"
                  radius="lg"
                  isLoading={isPreparing && !inviteUrl}
                  isDisabled={!inviteUrl}
                  onPress={onShare}
                >
                  {systemShareAvailable ? "发送邀请" : "复制邀请链接"}
                </Button>
                <div className="mt-2 grid grid-cols-2 gap-2">
                  <Button radius="lg" variant="flat" isDisabled={!inviteUrl} onPress={onCopy}>复制链接</Button>
                  <Button radius="lg" variant="light" isLoading={isPreparing} onPress={onRegenerate}>
                    重新生成
                  </Button>
                </div>

                {isInternetMode ? (
                  <div className="mt-4 rounded-2xl border border-black/[0.07] bg-black/[0.025] px-4 py-3 dark:border-white/[0.08] dark:bg-white/[0.035]">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-tiny font-medium text-zinc-500 dark:text-zinc-400">口头告诉对方</div>
                        <div className="mt-1 font-mono text-2xl font-semibold tracking-[0.18em] text-zinc-950 dark:text-white">
                          {formattedPairingCode || "•••• ••••"}
                        </div>
                      </div>
                      <Button size="sm" radius="lg" variant="light" isLoading={isPairingCodeLoading} onPress={onRegeneratePairing}>
                        换一个
                      </Button>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-zinc-500 dark:text-zinc-400">
                      <span>{pairingExpiry ? `${pairingExpiry} · 单次有效` : "正在生成 5 分钟配对码"}</span>
                      {inviteExpiry ? <span>链接 {inviteExpiry}</span> : null}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          ) : (
            <div className="rounded-2xl border border-amber-500/20 bg-amber-50/80 px-4 py-3 text-small text-amber-950 dark:border-amber-300/15 dark:bg-amber-300/10 dark:text-amber-100">
              {rolePending ? "正在确认当前房间权限，确认后即可生成邀请。" : "当前设备不是房主。为避免转发已有权限，只有房主可以生成新的邀请。"}
            </div>
          )}

          <div className="mt-5 border-t border-black/[0.07] pt-5 dark:border-white/[0.08]">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <Input
                className="min-w-0 flex-1"
                label="已有配对码？"
                description="输入对方告诉你的 8 位数字，不需要复制长链接。"
                placeholder="1234 5678"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={12}
                radius="lg"
                variant="bordered"
                value={pairingCodeDraft}
                onValueChange={(value) => onPairingCodeDraftChange(value.replace(/[^0-9 -]/g, "").slice(0, 12))}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && normalizeTransferPairingCode(pairingCodeDraft)) onRedeem();
                }}
              />
              <Button
                className="h-11 shrink-0 px-6"
                color="primary"
                radius="lg"
                variant="flat"
                isLoading={isRedeeming}
                isDisabled={!normalizeTransferPairingCode(pairingCodeDraft)}
                onPress={onRedeem}
              >
                加入房间
              </Button>
            </div>
          </div>

          {error ? (
            <div className="mt-4 rounded-xl border border-rose-500/20 bg-rose-50 px-3 py-2 text-tiny text-rose-700 dark:border-rose-300/15 dark:bg-rose-300/10 dark:text-rose-100">
              {error}
            </div>
          ) : null}
        </ModalBody>
      </ModalContent>
    </Modal>
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
            <ModalHeader className="flex min-w-0 flex-row items-center gap-2 px-4 py-3 pr-12">
              <span className="min-w-0 flex-1 truncate text-base font-semibold">{target.fileName}</span>
              <Chip color="primary" size="sm" variant="flat" className="shrink-0">
                {previewKindLabel(kind)}
              </Chip>
              <span className="hidden shrink-0 font-mono text-tiny font-normal text-default-400 sm:inline">
                {mimeType}
              </span>
            </ModalHeader>
            <ModalBody className="overflow-y-auto px-3 pb-3 pt-0">
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

// 放大图片预览：自带缩放/旋转工具栏。缩放按宽度撑开；90°/270° 旋转时按图片固有
// 宽高比换算可视尺寸，让外层滚动容器拿到真实布局盒，避免裁剪或滚动失效。
function ExpandedImagePreview({ url, fileName, onError }: { url: string; fileName: string; onError: () => void }) {
  const [scale, setScale] = useState(1);
  const [rotation, setRotation] = useState(0);
  const [natural, setNatural] = useState<{ w: number; h: number } | null>(null);
  const [containerWidth, setContainerWidth] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    setContainerWidth(el.clientWidth);
    const observer = new ResizeObserver(() => setContainerWidth(el.clientWidth));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const zoomBy = (factor: number) =>
    setScale((current) => Math.min(5, Math.max(0.2, Math.round(current * factor * 100) / 100)));
  const rotateCW = () => setRotation((current) => (current + 90) % 360);

  const quarterTurned = rotation % 180 !== 0;
  const imageWidth = Math.max(1, scale * (containerWidth || 1));
  const imageHeight = natural ? (imageWidth * natural.h) / natural.w : 0;
  const visualWidth = quarterTurned ? imageHeight : imageWidth;
  const visualHeight = quarterTurned ? imageWidth : imageHeight;

  const toolButton =
    "grid h-7 min-w-7 place-items-center rounded-md px-1 text-zinc-500 transition hover:bg-black/[0.06] hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/[0.08] dark:hover:text-white";
  return (
    <div className="relative overflow-hidden rounded-lg border border-black/10 bg-zinc-950/[0.04] dark:border-white/10 dark:bg-white/[0.03]">
      <div
        className="absolute right-2 top-2 z-10 flex items-center gap-0.5 rounded-lg border border-black/[0.08] bg-white/90 p-0.5 shadow-sm backdrop-blur dark:border-white/[0.1] dark:bg-zinc-900/90"
        role="toolbar"
        aria-label="图片预览工具栏"
      >
        <button type="button" className={toolButton} aria-label="缩小" title="缩小" onClick={() => zoomBy(1 / 1.25)}>
          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M5 12h14" /></svg>
        </button>
        <span className="w-11 text-center font-mono text-[11px] tabular-nums text-zinc-600 dark:text-zinc-300">
          {Math.round(scale * 100)}%
        </span>
        <button type="button" className={toolButton} aria-label="放大" title="放大" onClick={() => zoomBy(1.25)}>
          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M12 5v14M5 12h14" /></svg>
        </button>
        <button type="button" className={`${toolButton} font-mono text-[10px]`} aria-label="原始大小" title="原始大小" onClick={() => { setScale(1); setRotation(0); }}>
          1:1
        </button>
        <button type="button" className={toolButton} aria-label="顺时针旋转 90°" title="顺时针旋转 90°" onClick={rotateCW}>
          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M20 12a8 8 0 1 1-2.34-5.66" />
            <path d="M20 3.5v4h-4" />
          </svg>
        </button>
        <a className={toolButton} href={url} download={fileName} aria-label={`下载 ${fileName}`} title="下载">
          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 4v11m0 0 4-4m-4 4-4-4M4.5 19.5h15" /></svg>
        </a>
      </div>
      <div ref={scrollRef} className="max-h-[78dvh] overflow-auto">
        <div
          className="mx-auto flex items-center justify-center"
          style={natural ? { width: visualWidth, height: visualHeight } : undefined}
        >
          <img
            src={url}
            alt={fileName}
            onError={onError}
            onLoad={(event) => setNatural({ w: event.currentTarget.naturalWidth, h: event.currentTarget.naturalHeight })}
            style={{ width: containerWidth ? imageWidth : "100%", transform: `rotate(${rotation}deg)` }}
            className="block max-w-none shrink-0 object-contain transition-transform duration-200 motion-reduce:transition-none"
          />
        </div>
      </div>
    </div>
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
    <button
      type="button"
      className="absolute right-2 top-2 z-10 flex h-7 items-center gap-1 rounded-md border border-black/[0.08] bg-white/90 px-2 text-tiny font-medium text-zinc-600 shadow-sm backdrop-blur transition hover:text-zinc-900 dark:border-white/[0.1] dark:bg-zinc-900/90 dark:text-zinc-300 dark:hover:text-white"
      aria-label={`预览 ${fileName}`}
      title="预览"
      onClick={() => onPreview?.({ fileName, mimeType, url, blob, sizeBytes: previewSizeBytes })}
    >
      <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
        <circle cx="12" cy="12" r="3" />
      </svg>
      预览
    </button>
  ) : null;
  const wrapClass = compact && !expanded ? "relative mt-2" : "relative";
  const frameClass = compact
    ? "overflow-hidden rounded border border-black/10 bg-zinc-950/5 dark:border-white/10 dark:bg-white/[0.03]"
    : "overflow-hidden rounded-lg border border-black/10 bg-zinc-950/5 dark:border-white/10 dark:bg-white/[0.03]";
  const mediaClass = expanded
    ? "max-h-[78dvh] w-full object-contain"
    : compact
      ? "max-h-44 w-full object-contain"
      : "h-64 w-full object-contain";
  const documentClass = expanded
    ? "h-[78dvh] w-full"
    : compact
      ? "h-44 w-full"
      : "h-80 w-full";
  const fallbackClass = expanded
    ? "flex min-h-[45dvh] flex-col items-center justify-center rounded-lg glass glass-border border p-4 text-center"
    : compact
      ? "flex min-h-28 flex-col items-center justify-center rounded glass glass-border border p-3 text-center"
      : "flex h-64 flex-col items-center justify-center rounded-lg glass glass-border border p-4 text-center";

  const deferHeavyPreview = !expanded
    && Boolean(onPreview)
    && previewSizeBytes > AUTO_PREVIEW_LIMIT_BYTES
    && (kind === "image" || kind === "pdf");
  if (deferHeavyPreview) {
    return (
      <div className={wrapClass}>
        <div className={fallbackClass}>
          <div className={`${compact ? "text-2xl" : "text-4xl"} font-semibold text-zinc-300 dark:text-white/20`}>{previewKindLabel(kind)}</div>
          <div className="mt-3 max-w-full truncate text-small font-medium">{fileName}</div>
          <div className="mt-1 text-tiny text-zinc-500">文件较大，已暂停自动预览以保持页面流畅</div>
        </div>
        {previewAction}
      </div>
    );
  }

  if (url && kind === "image" && !previewFailed) {
    if (expanded) {
      return <ExpandedImagePreview url={url} fileName={fileName} onError={() => setPreviewFailed(true)} />;
    }
    return (
      <div className={wrapClass}>
        <div className={frameClass}>
          <img src={url} alt={fileName} className={mediaClass} onError={() => setPreviewFailed(true)} />
        </div>
        {previewAction}
      </div>
    );
  }
  if (url && kind === "video" && !previewFailed) {
    return (
      <div className={wrapClass}>
        <div className={`${frameClass} bg-zinc-950`}>
          <video src={url} controls preload="metadata" className={mediaClass} onError={() => setPreviewFailed(true)} />
        </div>
        {previewAction}
      </div>
    );
  }
  if (url && kind === "audio" && !previewFailed) {
    return (
      <div className={wrapClass}>
        <div className={fallbackClass}>
          <div className="text-2xl font-semibold text-zinc-300 dark:text-white/20">AUDIO</div>
          <div className="mt-2 max-w-full truncate text-small font-medium">{fileName}</div>
          <audio src={url} controls preload="metadata" className="mt-3 w-full" onError={() => setPreviewFailed(true)} />
        </div>
        {previewAction}
      </div>
    );
  }
  if (url && kind === "pdf" && !previewFailed) {
    return (
      <div className={wrapClass}>
        <div className={`${frameClass} bg-white`}>
          <object data={url} type="application/pdf" className={documentClass} onError={() => setPreviewFailed(true)}>
            <div className="flex h-full items-center justify-center p-3 text-small text-zinc-500">PDF 预览不可用</div>
          </object>
        </div>
        {previewAction}
      </div>
    );
  }
  if (kind === "text" && blob) {
    return (
      <div className={wrapClass}>
        <TextFilePreview fileName={fileName} mimeType={mimeType} blob={blob} compact={compact} expanded={expanded} />
        {previewAction}
      </div>
    );
  }
  return (
    <div className={wrapClass}>
      <div className={fallbackClass}>
        <div className={`${compact ? "text-2xl" : "text-4xl"} font-semibold text-zinc-300 dark:text-white/20`}>{previewKindLabel(kind)}</div>
        <div className="mt-3 max-w-full truncate text-small font-medium">{fileName}</div>
        <div className="mt-1 text-tiny text-zinc-500">{effectiveMimeType(fileName, mimeType)}</div>
      </div>
      {previewAction}
    </div>
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
    <div className="overflow-hidden rounded border border-black/10 bg-zinc-950 text-zinc-100 dark:border-white/10">
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
  ossFallbackEnabled,
}: {
  iceConfig: PublicTransferIceConfig | null;
  networkMode: TransferNetworkMode;
  ossFallbackEnabled: boolean;
}) {
  const isInternetMode = networkMode === "internet";
  const routeLabel = iceConfig?.turnAuthRequired ? "备用连接已启用" : "备用连接检测中";

  return (
    <section className="rounded-lg border border-black/[0.07] p-3 dark:border-white/[0.08]">
      <h2 className="text-base font-semibold text-zinc-950 dark:text-white">常见问题</h2>
      <div className="mt-2 divide-y divide-black/10 dark:divide-white/10">
        <FaqItem title="怎么把手机加进来？">
          点上方“邀请 / 加入”，用手机相机扫二维码。{isInternetMode ? "远程模式允许手机使用其它网络。" : "附近模式要求手机连接同一网络。"}
        </FaqItem>
        <FaqItem title="找不到对方怎么办？">
          {isInternetMode
            ? "先发送邀请链接；确认双方使用相同房间名称和口令。"
            : "确认双方处于同一网络或公网出口，并使用相同房间名。"}
        </FaqItem>
        <FaqItem title="没有选对方也能发送吗？">
          {isInternetMode
            ? ossFallbackEnabled
              ? "可以。登录用户可生成短期分享链接。"
              : "不可以。匿名模式不会上传云端，需要先选择一台在线设备。"
            : "不可以。附近模式不会上传云端，必须先选择一台在线设备。"}
        </FaqItem>
        <FaqItem title="文件会怎么传？">
          {isInternetMode
            ? ossFallbackEnabled
              ? "优先直接连接对方设备；仍未完成时使用登录账号的短期云端链接。"
              : "匿名用户只连接对方设备；连接失败后不会上传云端。"
            : "只在设备之间直接传输，失败后不会上传云端。"}
        </FaqItem>
        <FaqItem title="为什么有时需要手动写入系统剪贴板？">
          浏览器可能阻止网页在后台改写系统剪贴板。内容仍会保留在页面里，点击“写入系统剪贴板”即可重试。
        </FaqItem>
        <FaqItem title="谁能看到我发的文件？">
          {isInternetMode
            ? "直接发送的文件只到点选设备。云端文件要求登录，并由持有房间口令和文件链接的登录用户下载。"
            : "文件只发送给你点选的附近设备，不创建云端副本或公开下载链接。"}
        </FaqItem>
        <FaqItem title="云端额度是多少？">
          登录账号最多占用 1 GiB 有效附件存储，每个 UTC 自然月可使用 1 GiB 下载流量。生成链接不扣额度；首次打开并成功跳转时按文件完整大小计入，链接只能打开一次。
        </FaqItem>
        <FaqItem title="更多说明">
          {isInternetMode
            ? `远程房间通过口令隔离，文件地址短期有效。当前状态：${routeLabel}。`
            : "附近模式使用服务端发现设备，但文件、剪贴板和白板内容只在设备之间传输。"}
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

function RoomQrCode({ value, large = false }: { value: string; large?: boolean }) {
  const qr = useMemo(() => {
    try {
      return { matrix: createQrMatrix(value), error: null as string | null };
    } catch (err) {
      return { matrix: null, error: err instanceof Error ? err.message : "二维码生成失败" };
    }
  }, [value]);

  if (!qr.matrix) {
    return (
      <div className={`mx-auto flex shrink-0 items-center justify-center border border-dashed border-zinc-300 bg-white p-3 text-center text-tiny text-zinc-500 sm:mx-0 ${large ? "h-52 w-52 rounded-2xl" : "h-36 w-36 rounded-md"}`}>
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
      className={`relative z-10 mx-auto shrink-0 bg-white shadow-sm ring-1 ring-black/10 sm:mx-0 ${large ? "h-52 w-52 rounded-2xl p-3" : "h-36 w-36 rounded-md p-2"}`}
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

function transportPathLabel(path: PeerTransportPath | undefined) {
  return path === "turn" ? "备用通道" : path === "direct" ? "设备直连" : null;
}

function discoveryStatusLabel(status: DiscoveryStatus) {
  if (status === "online") return "已连接";
  if (status === "reconnecting") return "正在重连";
  if (status === "offline") return "已离线";
  if (status === "name-conflict") return "名称冲突";
  if (status === "permission-denied") return "无权加入";
  return "正在连接";
}

function discoveryStatusDescription(status: DiscoveryStatus) {
  if (status === "reconnecting") return "房间连接暂时中断，正在自动恢复。";
  if (status === "offline") return "房间连接已中断，请检查网络后重试。";
  if (status === "name-conflict") return "当前设备名称已被占用，请在设置中更换名称。";
  if (status === "permission-denied") return "无法加入这个房间，请检查邀请链接和房间口令。";
  return "正在建立房间连接。";
}

function transferActivityStatusLabel(status: OutgoingTransferStatus) {
  if (status === "queued") return "等待发送";
  if (status === "connecting") return "正在连接";
  if (status === "sending") return "正在发送";
  if (status === "completed") return "已完成";
  if (status === "failed") return "失败";
  return "已取消";
}

function transferActivityStatusColor(status: OutgoingTransferStatus): "default" | "primary" | "success" | "danger" {
  if (status === "completed") return "success";
  if (status === "failed" || status === "cancelled") return "danger";
  if (status === "connecting" || status === "sending") return "primary";
  return "default";
}

function transferTransportLabel(transport: NonNullable<OutgoingTransferActivity["transport"]>) {
  if (transport === "peer") return "设备直连";
  if (transport === "relay") return "备用通道";
  return "云端接力";
}

function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "不到 1 秒";
  if (seconds < 60) return `${Math.ceil(seconds)} 秒`;
  const minutes = Math.ceil(seconds / 60);
  return minutes < 60 ? `${minutes} 分钟` : `${Math.ceil(minutes / 60)} 小时`;
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
  if (payload.type === "STDG2") {
    if (payload.kind === "diagram-update") {
      return `${sourcePeerId}:diagram-update:${payload.createdAt}:${payload.update.length}:${hashEventPayload(payload.update)}`;
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

function hashEventPayload(value: string | Uint8Array) {
  let hash = 2_166_136_261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= typeof value === "string" ? value.charCodeAt(index) : value[index];
    hash = Math.imul(hash, 16_777_619);
  }
  return (hash >>> 0).toString(36);
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

function readInitialPairingCode() {
  const params = readTransferParams();
  return normalizeTransferPairingCode(params.get("pair") || params.get("pairCode") || "");
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
  } else {
    const fragment = window.location.hash.replace(/^#/, "");
    if (/^(?:token|roomToken|pair|pairCode)=/.test(fragment)) {
      const hashParams = new URLSearchParams(fragment);
      hashParams.forEach((value, key) => {
        if (!params.has(key)) params.set(key, value);
      });
    }
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

function transferRoomDisplayName(roomId: string) {
  return !roomId || roomId === "nearby" ? "附近设备" : roomId;
}

function fileShareUrl(attachment: TransferAttachment, roomId: string, roomToken: string) {
  const inviteUrl = buildTransferInviteUrl({
    origin: window.location.origin,
    workspacePath: "/transfer",
    networkMode: "internet",
    roomId,
    token: roomToken,
  });
  if (!inviteUrl) throw new Error("无法生成安全文件链接");
  const url = new URL(inviteUrl);
  url.searchParams.set("attachmentId", String(attachment.attachmentId));
  return url.toString();
}

function isRoomAccessUsable(created: PublicTransferCreatedAccessToken) {
  if (created.access.revokedAt || !created.access.expiresAt) return false;
  return Date.parse(created.access.expiresAt) > Date.now() + 60_000;
}

function isAccessTokenExpired(access: PublicTransferRoomAccessToken) {
  return Boolean(access.expiresAt) && Date.parse(access.expiresAt as string) <= Date.now();
}

function isPairingCodeUsable(pairingCode: PublicTransferPairingCode) {
  return pairingCode.usedCount < pairingCode.maxUses
    && Date.parse(pairingCode.expiresAt) > Date.now() + 5_000;
}

function formatPairingCode(code: string) {
  const normalized = normalizeTransferPairingCode(code);
  return normalized ? `${normalized.slice(0, 4)} ${normalized.slice(4)}` : code;
}

function formatInviteExpiry(expiresAt: string) {
  const remainingMs = Date.parse(expiresAt) - Date.now();
  if (!Number.isFinite(remainingMs) || remainingMs <= 0) return "已过期";
  const minutes = Math.max(1, Math.ceil(remainingMs / 60_000));
  if (minutes < 60) return `约 ${minutes} 分钟后到期`;
  const hours = Math.ceil(minutes / 60);
  if (hours < 48) return `约 ${hours} 小时后到期`;
  return `约 ${Math.ceil(hours / 24)} 天后到期`;
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
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Clipboard API may be blocked by browser policy; continue with a DOM selection fallback.
    }
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.readOnly = true;
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  textarea.setSelectionRange(0, value.length);
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("当前浏览器不允许自动复制，请手动复制");
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

function claimTransferPeerIdentity(): TransferPeerIdentity {
  const leaseOwner = createRoomToken();
  const now = Date.now();
  let peerId = "";
  try {
    const storedPeerId = sessionStorage.getItem(TRANSFER_PEER_ID_STORAGE_KEY)?.trim() ?? "";
    if (isValidTransferPeerId(storedPeerId) && !isTransferPeerLeaseActive(storedPeerId, now)) {
      peerId = storedPeerId;
    }
  } catch {
    // Restrictive storage modes fall back to a fresh page identity.
  }

  if (!peerId) {
    peerId = `web-${createRoomToken().slice(0, 10)}`;
  }
  try {
    sessionStorage.setItem(TRANSFER_PEER_ID_STORAGE_KEY, peerId);
  } catch {
    // The in-memory identity still keeps this page distinct.
  }

  const identity = { peerId, leaseOwner };
  writeTransferPeerLease(identity, now);
  return identity;
}

function maintainTransferPeerIdentityLease(identity: TransferPeerIdentity) {
  const refresh = () => writeTransferPeerLease(identity, Date.now());
  const release = () => {
    try {
      const current = readTransferPeerLease(identity.peerId);
      if (current?.owner === identity.leaseOwner) {
        localStorage.removeItem(`${TRANSFER_PEER_LEASE_PREFIX}${identity.peerId}`);
      }
    } catch {
      // The short lease expires automatically when storage cannot be updated.
    }
  };

  refresh();
  const interval = window.setInterval(refresh, TRANSFER_PEER_LEASE_REFRESH_MS);
  window.addEventListener("pagehide", release);
  return () => {
    window.clearInterval(interval);
    window.removeEventListener("pagehide", release);
    release();
  };
}

function isTransferPeerLeaseActive(peerId: string, now: number) {
  const lease = readTransferPeerLease(peerId);
  return Boolean(lease && now - lease.updatedAt < TRANSFER_PEER_LEASE_TTL_MS);
}

function readTransferPeerLease(peerId: string): { owner: string; updatedAt: number } | null {
  try {
    const raw = localStorage.getItem(`${TRANSFER_PEER_LEASE_PREFIX}${peerId}`);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as { owner?: unknown; updatedAt?: unknown };
    return typeof parsed.owner === "string" && typeof parsed.updatedAt === "number"
      ? { owner: parsed.owner, updatedAt: parsed.updatedAt }
      : null;
  } catch {
    return null;
  }
}

function writeTransferPeerLease(identity: TransferPeerIdentity, updatedAt: number) {
  try {
    localStorage.setItem(
      `${TRANSFER_PEER_LEASE_PREFIX}${identity.peerId}`,
      JSON.stringify({ owner: identity.leaseOwner, updatedAt }),
    );
  } catch {
    // A random peer id still avoids collisions for the current page load.
  }
}

function isValidTransferPeerId(peerId: string) {
  return /^web-[a-f0-9]{10}$/.test(peerId);
}

function loadTransferClientName(peerId: string) {
  try {
    const scopedName = sessionStorage.getItem(transferClientNameStorageKey(peerId))?.trim() ?? "";
    if (isValidTransferClientName(scopedName)) {
      return scopedName;
    }

    const preferredName = localStorage.getItem(TRANSFER_CLIENT_NAME_STORAGE_KEY)?.trim() ?? "";
    if (isValidTransferClientName(preferredName)) {
      return uniqueDefaultTransferClientName(preferredName, peerId);
    }
  } catch {
    // Storage can be unavailable in restrictive browser modes.
  }
  return uniqueDefaultTransferClientName("网页设备", peerId);
}

function storeTransferClientName(peerId: string, clientName: string) {
  try {
    sessionStorage.setItem(transferClientNameStorageKey(peerId), clientName);
    localStorage.setItem(TRANSFER_CLIENT_NAME_STORAGE_KEY, clientName);
  } catch {
    // Keep the name for the current page even when persistence is unavailable.
  }
}

function transferClientNameStorageKey(peerId: string) {
  return `${TRANSFER_CLIENT_NAME_STORAGE_KEY}:${peerId}`;
}

function isValidTransferClientName(clientName: string) {
  return Boolean(clientName
    && clientName.length <= MAX_TRANSFER_CLIENT_NAME_LENGTH
    && !/[\u0000-\u001f\u007f-\u009f]/.test(clientName));
}

function uniqueDefaultTransferClientName(preferredName: string, peerId: string) {
  const suffix = ` · ${peerId.slice(-4)}`;
  const base = preferredName.slice(0, Math.max(1, MAX_TRANSFER_CLIENT_NAME_LENGTH - suffix.length)).trim();
  return `${base || "网页设备"}${suffix}`;
}

function discoveryPeerDisplayName(peer: Pick<DiscoveryPeer, "peerId" | "displayName">) {
  const displayName = decodeLegacyPeerDisplayName(
    typeof peer.displayName === "string" ? peer.displayName : "",
  );
  if (!displayName || displayName === peer.peerId || /^web-[a-f0-9-]+$/i.test(displayName)) {
    return "未命名设备";
  }
  return displayName;
}

function discoveryWebSocketUrl(ticket: string) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const params = new URLSearchParams({ ticket });
  return `${protocol}//${window.location.host}/ws/public-transfer/discovery?${params.toString()}`;
}
