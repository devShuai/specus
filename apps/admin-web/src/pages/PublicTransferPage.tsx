import { lazy, Suspense, useCallback, useEffect, useId, useMemo, useRef, useState, useSyncExternalStore } from "react";
import type {
  ChangeEvent,
  KeyboardEvent as ReactKeyboardEvent,
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
  Switch,
} from "@heroui/react";
import { AppLogo } from "../components/AppLogo";
import { useAuth } from "../auth/AuthContext";
import { UserMenuButton } from "../components/UserMenuButton";
import { PublicToolsMenu } from "../components/PublicToolsMenu";
import { DeviceAvatar, NearbyDeviceGrid, connectionTag, type NearbyDevice } from "../components/NearbyDeviceGrid";
import { HeroRuntime } from "../components/HeroRuntime";
import { ConfirmModal } from "../components/ConfirmModal";
import { TransferFilePreflight } from "../components/TransferFilePreflight";
import { ResumableTransfersPanel, hasResumableTransfers } from "../components/ResumableTransfersPanel";
import { ProductMetricsMemberNotice } from "../components/ProductMetricsDisclosure";
import { Alert, Icon, Progress, RelativeTime, Tag, type IconName, type Tone } from "../components/ui";
import { fileKindIcon, fileKindLabel } from "../components/transferFileKind";
import { useTransferOutcomeMetrics } from "../hooks/useTransferOutcomeMetrics";
import { useFileLeaveWarning } from "../hooks/useFileLeaveWarning";
import { useTransferCapabilities } from "../hooks/useTransferCapabilities";
import { SyncedClipboard, type ClipboardComposerState, type SyncedClipboardHandle } from "../components/SyncedClipboard";
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
import { formatDateTime, formatElapsed } from "../lib/format";
import { createQrMatrix } from "../lib/qr";
import {
  buildTransferInviteUrl,
  buildTransferNavigationUrl,
  buildTransferPairingUrl,
  normalizeTransferPairingCode,
  selectSafeTransferInviteToken,
} from "../lib/transferInvite";
import { sha256Blob } from "../lib/sha256";
import { effectiveMimeType, mediaKind, shortMimeLabel } from "../lib/transferPreview";
import {
  MAX_TRANSFER_ROOM_NAME_LENGTH,
  MAX_TRANSFER_ROOM_TOKEN_LENGTH,
  localizeTransferDiscoveryError,
  resolveTransferPeerSelection,
  validateTransferRoomSettings,
  type TransferRoomSettingsErrors,
} from "../lib/transferRoom";
import { sendWhiteboardWithFallback } from "../lib/whiteboardTransport";
import { decodeLegacyPeerDisplayName } from "../lib/peerDisplayName";
import { collaborationPeers, keepUncompletedTransfers, transferCompletionLabel } from "../lib/transferExperience";
import { checkFilePreflight, cloudFallbackPermitted, hasVolatileFileWork, retainVisibleFileActivities, type FilePreflightInput, type FileDeliveryMode } from "../lib/transferPreflight";
import {
  clipboardSyncEventKey,
  isClipboardSyncPayload,
  type ClipboardInboundEvent,
  type ClipboardSyncPayload,
} from "../lib/clipboardSync";
import { decodeRelayAppFrame, encodeRelayAppFrame } from "../lib/appMessageProtocol";
import {
  FILE_TRANSFER_TRANSPORT_MODES,
  turnCredentialRefreshDelayMs,
} from "../lib/directPeerTransport";
import {
  DEFAULT_DIRECT_MEMORY_LIMIT_BYTES,
  DIRECT_SEND_USER_CANCEL,
  directResumeSupported,
  directSendFailureKind,
  directSendLimitBytes,
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
/** In the order the content switch shows them; arrow keys follow the same order. */
const TRANSFER_TOOL_MODES: TransferToolMode[] = ["clipboard", "files", "whiteboard"];

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
  sameRoom?: boolean;
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
  /** Resumable direct receives kept in this browser's storage until saved or expired. */
  resumeTransferId?: string;
  restored?: boolean;
  /** When this page added the item, for the inbox's relative time. Display only. */
  receivedAt?: number;
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
  targetSameLan: boolean;
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
  targetSameLan: boolean;
  roomId: string;
  roomToken: string;
  targetPeerId: string;
  targetPeerLabel: string;
  ossFallbackAllowed: boolean;
}

interface DraftFileTransfer extends Pick<QueuedFileTransfer, "roomEpoch" | "roomGeneration" | "roomId" | "roomToken" | "targetPeerId" | "targetPeerLabel" | "targetSameLan"> {
  files: File[];
  mode: FileDeliveryMode;
  allowCloudFallback: boolean;
}

interface OutgoingTransferActivity {
  id: string;
  file: File;
  fileName: string;
  sizeBytes: number;
  targetPeerId: string;
  targetPeerLabel: string;
  ossFallbackAllowed: boolean;
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
// 2 GiB with chunked resume (secure context); the legacy 128 MiB memory limit otherwise.
const DIRECT_SEND_LIMIT_BYTES = directSendLimitBytes();
const STREAM_DOWNLOAD_THRESHOLD_BYTES = 64 * 1024 * 1024;
const AUTO_PREVIEW_LIMIT_BYTES = 8 * 1024 * 1024;
const CLIPBOARD_EVENT_LIMIT = 20;
const CLIPBOARD_SEEN_EVENT_LIMIT = 200;
const CLIPBOARD_SEQUENCE_STATE_LIMIT = 200;
const CLIPBOARD_SEEN_EVENT_TTL_MS = 10 * 60 * 1000;
const CLIPBOARD_DIRECT_TIMEOUT_MS = 1600;
const CLIPBOARD_TURN_TIMEOUT_MS = 5000;
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
const MOBILE_SYSTEM_FILE_ACCEPT = [
  "application/*",
  "text/*",
  "audio/*",
  ".csv",
  ".log",
  ".md",
  ".yaml",
  ".yml",
  ".db",
  ".sqlite",
  ".zip",
  ".rar",
  ".7z",
  ".tar",
  ".gz",
  ".bz2",
  ".xz",
  ".iso",
  ".apk",
  ".ipa",
  ".exe",
  ".msi",
  ".dmg",
  ".pkg",
  ".bin",
].join(",");

function readInitialTransferTool(): TransferToolMode {
  const stored = sessionStorage.getItem(TRANSFER_TOOL_STORAGE_KEY);
  return stored === "files" || stored === "clipboard" || stored === "whiteboard" ? stored : "files";
}

function isDiscoveryPermissionError(message: string): boolean {
  return /无权|权限|只读|forbidden|unauthorized|token|口令/i.test(message);
}

function memoryReasonText(reason: string): string {
  switch (reason) {
    case "PERSISTENCE_UNAVAILABLE": return "本机浏览器存储不可用，例如无痕窗口";
    case "TOO_MANY_PARTIALS": return "本机未完成的接收已达 4 个";
    case "PARTIAL_BYTES_LIMIT": return "本机未完成接收的总大小已达 4 GiB";
    case "INSUFFICIENT_STORAGE": return "本机浏览器存储空间不足";
    default: return reason;
  }
}

function userFacingTransferError(message: string): string {
  const normalized = message.trim();
  if (!normalized) return "发送未完成：检查双方网络后重试";
  if (/拒绝接收|取消了接收/.test(normalized)) return "对方拒绝接收";
  if (/未确认接收|未确认完成|timeout|timed out|超时/i.test(normalized)) {
    return "等待对方响应超时：确认对方页面仍然打开后重试";
  }
  if (/TURN|relay|Direct|WebRTC|ICE/i.test(normalized)) {
    return "设备连接未建立：检查双方网络后重试";
  }
  if (/OSS|presign|object storage/i.test(normalized)) {
    return "文件临时存储暂时不可用，稍后重试";
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
  const systemFileInputRef = useRef<HTMLInputElement | null>(null);
  const mediaFileInputRef = useRef<HTMLInputElement | null>(null);
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
  const currentCollaborationPeerIdsRef = useRef<Set<string>>(new Set());
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
  const [coarsePointer] = useState(
    () => window.matchMedia("(pointer: coarse), (max-width: 767px)").matches,
  );
  const peerId = peerIdentity.peerId;
  const [displayName, setDisplayName] = useState(() => loadTransferClientName(peerId));
  const [displayNameDraft, setDisplayNameDraft] = useState(displayName);
  const [clientNameStatus, setClientNameStatus] = useState<ClientNameStatus>("available");
  const [clientNameSaving, setClientNameSaving] = useState(false);
  const [clientNameConnectionGeneration, setClientNameConnectionGeneration] = useState(0);
  const [roomSettingsOpen, setRoomSettingsOpen] = useState(false);
  const [roomGeneration, setRoomGeneration] = useState(0);
  const [sharedRoomActive, setSharedRoomActive] = useState(() => Boolean(readInitialRoomToken()));
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
  const [discoverable, setDiscoverable] = useState(() => loadDiscoverable());
  const [discoverableDraft, setDiscoverableDraft] = useState(discoverable);
  const [receiveConfirmationDraft, setReceiveConfirmationDraft] = useState(receiveConfirmationRequired);
  const [qrVisible, setQrVisible] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteInitialMode, setInviteInitialMode] = useState<"invite" | "join">("invite");
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [pairingCode, setPairingCode] = useState<PublicTransferPairingCode | null>(null);
  const [pairingCodeLoading, setPairingCodeLoading] = useState(false);
  const [pairingCodeDraft, setPairingCodeDraft] = useState("");
  const [pairingCodeRedeeming, setPairingCodeRedeeming] = useState(false);
  const [sharedAttachmentId] = useState(() => readInitialSharedAttachmentId());
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  // Files the user picked, dropped or pasted, shown in the composer until they press send. Not tied
  // to a recipient yet: the send button turns them into a draft for the chosen device (preflight).
  const [stagedFiles, setStagedFiles] = useState<File[]>([]);
  const [fileDraft, setFileDraft] = useState<DraftFileTransfer | null>(null);
  const fileDraftRef = useRef<DraftFileTransfer | null>(null);
  fileDraftRef.current = fileDraft;
  const [selectedPeerId, setSelectedPeerId] = useState("");
  const [selectedPeerName, setSelectedPeerName] = useState("");
  const [fileDeliveryMode, setFileDeliveryMode] = useState<"device" | "link">("device");
  const [peers, setPeers] = useState<DiscoveryPeer[]>([]);
  const [selfPublicAddress, setSelfPublicAddress] = useState("");
  const [incoming, setIncoming] = useState<IncomingAttachment[]>([]);
  const [state, setState] = useState<UploadState>("idle");
  const [outgoingActivities, setOutgoingActivities] = useState<OutgoingTransferActivity[]>([]);
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
  const clipboardRef = useRef<SyncedClipboardHandle | null>(null);
  const [clipboardComposer, setClipboardComposer] = useState<ClipboardComposerState>({ hasDraft: false, withinLimits: true, sending: false });
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

  usePageSeo({
    title: isDiagramWorkspace ? "专业流程图 · specus" : "互传 · specus",
    description: isDiagramWorkspace
      ? "支持实时协作、draw.io 图形库、多页文档和多格式导入导出的专业流程图工具。"
      : "在电脑和手机之间互传文件、文字与链接，邀请对方加入协作空间后共同绘制白板。",
    canonical: `https://specus.devshuai.com/#/${workspace}`,
  });
  const ossFallbackEnabled = authReady && authed;
  const cloudCapabilities = useTransferCapabilities(Boolean(ossFallbackEnabled && fileDraft
    && (fileDraft.mode === "link" || cloudFallbackPermitted(fileDraft.allowCloudFallback, ossFallbackEnabled, fileDraft.targetSameLan))));
  const effectiveRoomRole: PublicTransferRoomRole = sharedRoomActive ? roomRole ?? "VIEWER" : "EDITOR";
  const isRoomReadOnly = sharedRoomActive && effectiveRoomRole === "VIEWER";
  const collaborationMembers = useMemo(() => collaborationPeers(peers, sharedRoomActive), [peers, sharedRoomActive]);
  const inviteRequestContext = `${normalizeRoomId(roomId)}\u0000${roomToken.trim()}`;
  const inviteRequestContextRef = useRef(inviteRequestContext);
  const roomInviteRoleRef = useRef(roomInviteRole);
  inviteRequestContextRef.current = inviteRequestContext;
  roomInviteRoleRef.current = roomInviteRole;
  const transferRoomScopeKey = `${normalizeRoomId(roomId)}:${sharedRoomActive ? roomToken.trim() : "nearby"}:${roomGeneration}`;
  const diagramPeerDisplayNames = useMemo(() => Object.fromEntries(
    peers.map((peer) => [peer.peerId, discoveryPeerDisplayName(peer)]),
  ), [peers]);
  // 同网判定：本机与对端公网出口 IP 一致；本机地址未知时一律视为非同网
  const peerLanMap = useMemo<Record<string, boolean>>(() => Object.fromEntries(
    peers.map((peer) => [peer.peerId, Boolean(selfPublicAddress) && peer.publicAddress === selfPublicAddress]),
  ), [peers, selfPublicAddress]);
  const normalizedDisplayNameDraft = displayNameDraft.trim();
  const clientNameLocalError = !normalizedDisplayNameDraft
    ? "设备名称不能为空"
    : normalizedDisplayNameDraft.length > MAX_TRANSFER_CLIENT_NAME_LENGTH
      ? `设备名称不能超过 ${MAX_TRANSFER_CLIENT_NAME_LENGTH} 个字符`
      : /[\u0000-\u001f\u007f-\u009f]/.test(normalizedDisplayNameDraft)
        ? "设备名称不能包含控制字符"
        : "";

  useEffect(() => {
    window.history.replaceState({}, "", buildTransferNavigationUrl({
      origin: window.location.origin,
      workspacePath: `/${workspace}`,
      roomId,
    }));
  }, [roomId, workspace]);

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
      setNotice("设备名称已更新");
      return true;
    } catch (err) {
      setClientNameStatus("error");
      setError(err instanceof Error ? err.message : "设备名称校验失败");
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
      || !currentCollaborationPeerIdsRef.current.has(sourcePeerId)
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
    storedReceives,
    outgoingResumes,
    resumeOutgoing,
    abandonOutgoing,
    abandonStoredReceive,
    markDirectSaved,
    clearResumeData,
  } = useDirectTransfer({
    selfPeerId: peerId,
    connectionScopeKey: transferRoomScopeKey,
    iceConfig,
    peers,
    directMemoryLimitBytes: DEFAULT_DIRECT_MEMORY_LIMIT_BYTES,
    receiveConfirmationRequired,
    preconnectPeerChannels: true,
    sendSignal: sendDiscoverySignal,
    canReceiveFromPeer: (sourcePeerId, messageType) => currentRoomPeerRolesRef.current.get(sourcePeerId) !== "VIEWER"
      && (messageType !== "whiteboard" || currentCollaborationPeerIdsRef.current.has(sourcePeerId)),
    onPeerMessage: (sourcePeerId, message) => {
      if (message.messageType === "whiteboard" && isWhiteboardPayload(message.payload)) {
        pushWhiteboardEvent(sourcePeerId, message.payload);
      } else if (message.messageType === "clipboard" && isClipboardSyncPayload(message.payload)) {
        pushClipboardEvent(sourcePeerId, message.payload);
      }
    },
    onIncoming: (item) => {
      setIncoming((items) => limitIncomingItems([{ ...item, receivedAt: Date.now() }, ...items]));
    },
    onPreviewUrl: rememberPreviewUrl,
    onStateChange: (nextState) => {
      setState(nextState);
      const activityId = activeOutgoingActivityIdRef.current;
      if (activityId) {
        if (nextState === "direct") {
          // The peer connection carries this send now: a failure from here on had a path.
          transferMetricsRef.current?.markEstablished(activityId);
        }
        updateOutgoingActivity(activityId, {
          status: nextState === "connecting" || nextState === "waiting" ? "connecting" : "sending",
        });
      }
    },
    onProgress: setProgress,
    onError: (message) => setError(userFacingTransferError(message)),
    onNotice: setNotice,
  });

  // Opt-in product metrics: finished send attempts of a signed-in member, five closed fields only.
  const transferMetrics = useTransferOutcomeMetrics({
    signedIn: authReady && authed,
    sends: outgoingActivities,
    peerPath: (targetPeerId) => peerTransportPaths[targetPeerId],
  });
  const transferMetricsRef = useRef(transferMetrics);
  transferMetricsRef.current = transferMetrics;

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
      // Writing to this browser's storage always needs the user's click (chunked resume §6).
      if (item.storage !== "persistent") {
        acceptIncomingTransfer(item.sourcePeerId, item.transferId);
      }
    });
  }, [acceptIncomingTransfer, pendingTransfers, receiveConfirmationRequired]);

  useEffect(() => {
    sessionStorage.setItem("public-transfer-room-id", roomId || "nearby");
  }, [roomId]);

  useEffect(() => {
    if (!sharedRoomActive || !sharedAttachmentId || !roomToken.trim() || !authReady) {
      return;
    }
    if (!authed) {
      setError("该文件使用云端存储，登录后才能下载");
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
            receivedAt: Date.now(),
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
  }, [authReady, authed, roomToken, sharedRoomActive, sharedAttachmentId]);

  useEffect(() => {
    let active = true;
    let reconnectTimer: number | null = null;
    let heartbeatTimer: number | null = null;
    let reconnectAttempt = 0;
    let reconnectBlocked = false;
    let lastPongAt = Date.now();
    rosterRevisionRef.current = 0;
    setRoomRole(sharedRoomActive ? null : "EDITOR");
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
          publicAddress?: string;
          payload?: unknown;
        };
        if (message.type === "pong") {
          lastPongAt = Date.now();
        } else if (message.type === "hello") {
          setClientNameStatus("available");
          setDiscoveryError(null);
          setSelfPublicAddress(normalizeSelfPublicAddress(message.publicAddress));
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
            setDiscoveryError("设备名称已被其他在线设备使用：在设置里换一个名称后重试");
          } else if (message.error === "client name is required"
            || message.error === "client name is too long"
            || message.error === "client name contains invalid characters") {
            reconnectBlocked = true;
            setClientNameStatus("error");
            setDiscoveryStatus("name-conflict");
            setDiscoveryError("设备名称无效：在设置里修改后重试");
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
          currentCollaborationPeerIdsRef.current = new Set(collaborationPeers(visiblePeers, sharedRoomActive).map((peer) => peer.peerId));
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
                receivedAt: Date.now(),
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
          roomToken: sharedRoomActive ? roomToken : "",
          displayName,
          discoverable,
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
  }, [clientNameConnectionGeneration, discoverable, displayName, handleRelayPeerFrame, handleSignal, isDiagramWorkspace, peerId, pushClipboardEvent, pushWhiteboardEvent, roomId, roomToken, sharedRoomActive]);

  useEffect(() => {
    if (!sharedRoomActive || roomRole !== "OWNER") {
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
  }, [peerId, roomId, roomRole, roomToken, sharedRoomActive]);

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
    sharedRoom: sharedRoomActive,
    currentRole: roomRole,
    currentRoomToken: roomToken,
    explicitInvite: createdRoomAccess
      && createdRoomAccessContextRef.current === inviteRequestContext
      && createdRoomAccess.access.role === roomInviteRole
      && isRoomAccessUsable(createdRoomAccess)
      ? { role: createdRoomAccess.access.role, token: createdRoomAccess.token }
      : undefined,
  }), [createdRoomAccess, inviteRequestContext, roomInviteRole, roomRole, roomToken, sharedRoomActive]);
  const roomJoinUrl = useMemo(() => {
    if (sharedRoomActive && !safeRoomInviteToken) {
      return null;
    }
    return buildTransferInviteUrl({
      origin: window.location.origin,
      workspacePath: `/${workspace}`,
      roomId,
      token: safeRoomInviteToken,
    });
  }, [sharedRoomActive, roomId, safeRoomInviteToken, workspace]);
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
  const isTransferBusy = state === "connecting"
    || state === "waiting"
    || state === "direct"
    || state === "presigning"
    || state === "uploading"
    || state === "completing";
  const selectTransferPeer = (peer: DiscoveryPeer) => {
    setFileDeliveryMode("device");
    setSelectedPeerName(discoveryPeerDisplayName(peer));
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
  const stagedFilesSize = stagedFiles.reduce((total, file) => total + file.size, 0);
  const activeOutgoingCount = outgoingActivities.filter((activity) => (
    activity.status === "queued" || activity.status === "connecting" || activity.status === "sending"
  )).length;
  const volatileFileWork = hasVolatileFileWork({
    // Staged files are a draft as well: leaving the page loses the selection.
    draftCount: (fileDraft?.files.length ?? 0) + stagedFiles.length,
    outgoingCount: activeOutgoingCount + outgoingActivities.filter((activity) => activity.status === "failed").length,
    receivingCount: receivingTransfers.length + incoming.filter((item) => item.downloading).length,
    pendingCount: pendingTransfers.length,
    unsavedIncomingCount: incoming.filter((item) => item.direct && item.downloadProgress !== 100).length,
  });
  useFileLeaveWarning(!isDiagramWorkspace && volatileFileWork);

  const preflightInput = (draft: DraftFileTransfer): FilePreflightInput => ({
    files: draft.files,
    mode: draft.mode,
    memoryLimitBytes: DIRECT_SEND_LIMIT_BYTES,
    queuedCount: queuedFileTransfersRef.current.length + (uploadInFlightRef.current ? 1 : 0),
    signedIn: ossFallbackEnabled,
    rtcSupported: typeof RTCPeerConnection !== "undefined",
    recipientOnline: peers.some((peer) => peer.peerId === draft.targetPeerId),
    discoveryOnline: discoveryStatus === "online",
    writable: !isRoomReadOnly,
    scopeCurrent: draft.roomEpoch === roomEpochRef.current && draft.roomGeneration === roomGenerationRef.current,
    cloudRequested: cloudFallbackPermitted(draft.allowCloudFallback, ossFallbackEnabled, draft.targetSameLan),
    cloudLoading: fileDraftRef.current === draft && cloudCapabilities.loading,
    cloudSnapshot: fileDraftRef.current === draft ? cloudCapabilities.snapshot : null,
  });
  const hasRecoverableRoomContent = isTransferBusy
    || fileDraft != null
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
    currentCollaborationPeerIdsRef.current.clear();
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
    setSelectedPeerName("");
    setFileDeliveryMode("device");
    setSelectedFiles([]);
    fileDraftRef.current = null;
    setFileDraft(null);
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

  const enterSharedRoom = () => {
    requestRoomContextChange(
      "创建共享房间？",
      isTransferBusy ? "正在发送的文件会被取消。" : "当前房间连接和未保存的接收文件会暂时离开。",
      applySharedRoom,
    );
  };

  const applySharedRoom = () => {
    let nextToken = roomToken.trim();
    if (validateTransferRoomSettings(roomId, nextToken).errors.roomToken) {
      nextToken = createRoomToken();
    }

    resetTransferRoomState();
    clearIncomingItems();
    setSharedRoomActive(true);
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
      roomId,
    }));
    setNotice("已进入共享房间，可邀请远程设备加入");
    setDiscoveryError(null);
    setError(null);
  };

  const exitSharedRoom = () => {
    requestRoomContextChange(
      "退出共享房间？",
      isTransferBusy ? "正在发送的文件会被取消。" : "当前房间连接和未保存的接收文件会暂时离开。",
      applyExitSharedRoom,
    );
  };

  const applyExitSharedRoom = () => {
    resetTransferRoomState();
    clearIncomingItems();
    setSharedRoomActive(false);
    setRoomSettingsErrors({});
    setQrVisible(false);
    window.history.replaceState({}, "", buildTransferNavigationUrl({
      origin: window.location.origin,
      workspacePath: `/${workspace}`,
      roomId,
    }));
    setNotice("已退出共享房间，仅与同一网络的设备互传");
    setDiscoveryError(null);
    setError(null);
  };

  const commitRoomSettings = (validation: ReturnType<typeof validateTransferRoomSettings>) => {
    updateDiscoverable(discoverableDraft);
    updateReceiveConfirmationRequired(receiveConfirmationDraft);
    const nextToken = sharedRoomActive ? validation.roomToken : roomToken;
    const changed = validation.roomId !== roomId
      || (sharedRoomActive && nextToken !== roomToken);
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
      roomId: validation.roomId,
    }));
    setRoomSettingsOpen(false);
    setNotice(isDiagramWorkspace ? changed ? "协作空间设置已保存" : "协作空间设置没有变化" : "设备设置已保存");
    setDiscoveryError(null);
    setError(null);
  };

  const applyRoomSettings = () => {
    const validation = validateTransferRoomSettings(roomIdDraft, roomTokenDraft, {
      roomTokenRequired: sharedRoomActive,
    });
    if (validation.errors.roomId || validation.errors.roomToken) {
      setRoomSettingsErrors(validation.errors);
      setNotice(null);
      return;
    }

    const changed = validation.roomId !== roomId
      || (sharedRoomActive && validation.roomToken !== roomToken);
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
    setDisplayNameDraft(displayName);
    setDiscoverableDraft(discoverable);
    setReceiveConfirmationDraft(receiveConfirmationRequired);
    setRoomIdDraft(roomId);
    setRoomTokenDraft(roomToken);
    setRoomSettingsErrors({});
  };

  const updateDiscoverable = (value: boolean) => {
    setDiscoverable(value);
    saveDiscoverable(value);
    setNotice(value
      ? "已允许同一网络的设备发现你"
      : "已停止被发现，你仍可看到其它设备并主动发送");
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
    if (!sharedRoomActive || roomRole !== "OWNER") {
      throw new Error(roomRole === null ? "正在确认房间权限，稍候再试" : "只有房主可以生成安全邀请");
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
        throw new Error("房间已切换，重新生成邀请");
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
    if (!sharedRoomActive || roomRole !== "OWNER") {
      throw new Error(roomRole === null ? "正在确认房间权限，稍候再试" : "只有房主可以生成配对码");
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
        throw new Error("房间已切换，重新生成配对码");
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

  const resolveSafeRoomInviteUrl = async (role: TransferInviteRole) => {
    if (!sharedRoomActive) {
      return buildTransferInviteUrl({
        origin: window.location.origin,
        workspacePath: `/${workspace}`,
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
      roomId,
      token: created.token,
    });
  };

  const prepareSecureInvite = async (role: TransferInviteRole) => {
    if (!sharedRoomActive) return;
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

  const openInvitePanel = (mode: "invite" | "join" = "invite") => {
    setInviteError(null);
    setInviteInitialMode(mode);
    setInviteOpen(true);
  };

  const copyRoomLink = async (role: TransferInviteRole) => {
    try {
      const url = await resolveSafeRoomInviteUrl(role);
      await copyText(url);
      setNotice(sharedRoomActive ? "24 小时限权邀请已复制" : "房间链接已复制");
      setError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : "复制房间链接失败";
      setInviteError(message);
      setError(message);
    }
  };

  const shareRoom = async (role: TransferInviteRole) => {
    try {
      const url = await resolveSafeRoomInviteUrl(role);
      await shareOrCopy(
        {
          title: isDiagramWorkspace ? "加入 specus 流程图房间" : "加入 specus 互传房间",
          text: `${sharedRoomActive ? "共享" : "附近"}房间：${transferRoomDisplayName(roomId)}`,
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
    setNotice(sharedRoomActive
      ? "正在生成一次性扫码邀请"
      : "二维码已生成，用同一网络中的设备扫码");
    setError(null);
    if (sharedRoomActive) void prepareSecureInvite(roomInviteRole);
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
      setNotice(`已创建 24 小时${role === "EDITOR" ? "编辑者" : "只读访客"}邀请，链接只在这次显示，现在复制。`);
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
        roomId,
        token: createdRoomAccess.token,
      });
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
      await issuePairingCode("EDITOR", true);
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : "生成配对码失败");
    }
  };

  const regenerateSecureInvite = async () => {
    if (!sharedRoomActive) return;
    setInviteError(null);
    try {
      await Promise.all([
        issueRoomAccess("EDITOR", "24 小时编辑邀请", true),
        issuePairingCode("EDITOR", true),
      ]);
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : "重新生成邀请失败");
    }
  };

  const redeemPairingCode = async (rawCode = pairingCodeDraft) => {
    const normalizedCode = normalizeTransferPairingCode(rawCode);
    if (!normalizedCode) {
      setInviteError("配对码是 8 位数字，输入完整后再连接");
      return;
    }
    setPairingCodeRedeeming(true);
    setInviteError(null);
    try {
      const redeemed = await publicRedeemTransferPairingCode(normalizedCode, peerId);
      const applyRedeemedRoom = () => {
        resetTransferRoomState();
        clearIncomingItems();
        setSharedRoomActive(true);
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
          roomId: redeemed.roomId,
        }));
        setInviteOpen(false);
        setNotice(`配对成功，已以${redeemed.role === "EDITOR" ? "可编辑" : "只读"}身份加入 ${redeemed.roomId}`);
        setDiscoveryError(null);
        setError(null);
      };
      if (hasRecoverableRoomContent) {
        setTransferInterruptAction({
          title: "加入新的共享房间？",
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
    if (!inviteOpen || !sharedRoomActive || roomRole !== "OWNER") return;
    void prepareSecureInvite("EDITOR");
  }, [inviteOpen, roomId, roomRole, roomToken, sharedRoomActive]);

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
          text: "specus 直连文件",
          files: [record.file],
        };
        if (canShareFiles(fileShareData)) {
          await navigator.share(fileShareData);
          setNotice("已打开系统文件分享");
        } else {
          setError("此浏览器不支持系统文件分享：先保存文件，再选择另一台设备发送；不会生成邀请链接。");
          return;
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
        const file = item.blob ? new File([item.blob], item.attachment.fileName, { type: item.blob.type }) : null;
        const data = file ? { title: file.name, files: [file] } : null;
        if (!data || !canShareFiles(data)) {
          setError("此浏览器不支持系统文件分享：先保存文件，再选择另一台设备发送；不会生成邀请链接。");
          return;
        }
        await navigator.share(data);
        setNotice("已打开系统文件分享");
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
      setError("还没有选择要发送的文件");
      return;
    }
    if (!task.ossFallbackAllowed && !task.targetPeerId) {
      setState("failed");
      const message = "先选择一台在线设备";
      setError(message);
      failOutgoingActivity(task.activityId, message);
      return;
    }
    if (!task.targetSameLan && !task.roomToken.trim()) {
      const message = "远程设备需要先通过“添加设备”里的邀请加入";
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
      transferMetrics.startAttempt(task.activityId);
      updateOutgoingActivity(task.activityId, { status: "connecting", error: undefined });
      if (task.targetPeerId && typeof RTCPeerConnection !== "undefined") {
        let peerResult: DirectTransferResult | null = null;
        let peerTransferRejected = false;
        let peerTransferFatal = false;
        for (const transportMode of FILE_TRANSFER_TRANSPORT_MODES) {
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
              ? `中继传输失败：${message}`
              : `点对点连接失败：${message}`;
            if (message.includes("未确认接收") || message.includes("未确认完成")) {
              // 等待确认超时不进入 transport 降级循环，避免等待翻倍。
              peerTransferError = "对方 2 分钟内未确认：提醒对方查看页面后重试";
              peerTransferFatal = true;
              break;
            }
            if (message.includes("拒绝接收") || message.includes("取消了接收")) {
              peerTransferRejected = true;
              break;
            }
            const failureKind = directSendFailureKind(err);
            if (failureKind === "final") {
              // Decided by a person or paused for a later resume: no other transport, no cloud.
              peerTransferError = message;
              peerTransferFatal = true;
              break;
            }
            if (failureKind === "cloud") {
              // The receiver cannot hold this file; relay would be refused the same way, so
              // only an allowed cloud fallback is left.
              peerTransferError = message;
              peerTransferFatal = task.targetSameLan || !task.ossFallbackAllowed;
              break;
            }
            if (transportMode === "direct") {
              setNotice("点对点连接未建立，正在尝试 TURN 中继");
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
        if (!task.targetSameLan) {
          if (!task.ossFallbackAllowed) {
            setState("failed");
            const message = "设备连接未建立；本次未允许云端存储。检查网络后重试，或重新选择文件生成链接。";
            setError(message);
            failOutgoingActivity(task.activityId, message);
            continue;
          }
          setNotice("设备连接未建立，正在改用文件临时存储");
        }
      }
      if (task.targetSameLan) {
        setNotice(null);
        setState("failed");
        const message = "直连和 TURN 中继均未完成：检查双方网络后重试";
        setError(message);
        failOutgoingActivity(task.activityId, message);
        continue;
      }
      if (!task.ossFallbackAllowed) {
        setState("failed");
        const message = "设备连接未建立：检查双方网络后重试";
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
    task.abortController.abort(DIRECT_SEND_USER_CANCEL);
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

  const acceptFiles = (files: File[], deliveryMode: FileDeliveryMode = fileDeliveryMode) => {
    if (isRoomReadOnly) {
      setError("当前为只读访客，不能向房间发送文件");
      return false;
    }
    if (files.length === 0) {
      return false;
    }
    if (fileDraftRef.current) {
      setError("先确认或取消当前待发送文件，再添加新文件");
      return false;
    }
    const targetRequired = deliveryMode === "device";
    if (!targetRequired && !ossFallbackEnabled) {
      setError("登录后才能生成文件链接");
      return false;
    }
    if (targetRequired && !selectedPeer) {
      setActiveTool("files");
      setError(peers.length === 0 ? "还没有可接收的设备：先让对方打开本页，或用“添加设备”邀请" : "先选择接收设备");
      return false;
    }
    if (discoveryStatus !== "online" && (targetRequired || selectedPeer)) {
      setDiscoveryError("房间连接尚未恢复，恢复后即可发送");
      return false;
    }

    const targetPeerLabel = targetRequired && selectedPeer ? discoveryPeerDisplayName(selectedPeer) : "文件链接";
    const draft: DraftFileTransfer = {
      files, mode: deliveryMode, allowCloudFallback: false,
      roomEpoch: roomEpochRef.current, roomGeneration: roomGenerationRef.current,
      roomId, roomToken, targetPeerId: targetRequired ? selectedPeerId : "", targetPeerLabel,
      targetSameLan: targetRequired && Boolean(selectedPeerId && peerLanMap[selectedPeerId]),
    };
    fileDraftRef.current = draft;
    setFileDraft(draft);
    setError(null);
    return true;
  };

  const cancelFileDraft = () => {
    fileDraftRef.current = null;
    setFileDraft(null);
  };

  const updateFileDraft = (patch: Partial<DraftFileTransfer>) => {
    const current = fileDraftRef.current;
    if (!current) return;
    const next = { ...current, ...patch };
    fileDraftRef.current = next;
    setFileDraft(next);
  };

  const confirmFileDraft = () => {
    const draft = fileDraftRef.current;
    if (!draft) return;
    const preflight = checkFilePreflight(preflightInput(draft));
    if (!preflight.canSend) {
      setError(preflight.errors[0]);
      return;
    }
    const files = draft.files;
    const now = Date.now();
    const ossFallbackAllowed = draft.mode === "link" || cloudFallbackPermitted(draft.allowCloudFallback, ossFallbackEnabled, draft.targetSameLan);
    // Consume the draft synchronously so rapid confirmation cannot enqueue it twice.
    cancelFileDraft();
    const queueItems = files.map((file) => {
      const activityId = `outgoing-${peerId}-${now}-${transferActivitySequenceRef.current += 1}`;
      return {
        activity: {
          id: activityId,
          file,
          fileName: file.name || "attachment",
          sizeBytes: file.size,
          targetPeerId: draft.targetPeerId,
          targetPeerLabel: draft.targetPeerLabel,
          ossFallbackAllowed,
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
          roomEpoch: draft.roomEpoch,
          roomGeneration: draft.roomGeneration,
          targetSameLan: draft.targetSameLan,
          roomId: draft.roomId,
          roomToken: draft.roomToken,
          targetPeerId: draft.targetPeerId,
          targetPeerLabel: draft.targetPeerLabel,
          ossFallbackAllowed,
        } satisfies QueuedFileTransfer,
      };
    });
    queuedFileTransfersRef.current.push(...queueItems.map((item) => item.queued));
    setOutgoingActivities((activities) => retainVisibleFileActivities(
      [...queueItems.map((item) => item.activity), ...activities], TRANSFER_ACTIVITY_LIMIT,
    ));
    setSelectedFiles(files);
    setError(null);
    setNotice(files.length > 1 ? `已加入 ${files.length} 个发送任务` : null);
    runQueuedTransfersRef.current();
  };

  const canOpenFilePicker = () => {
    if (isRoomReadOnly) {
      setError("当前为只读访客，不能向房间发送文件");
      return false;
    }
    return true;
  };

  const openFilePicker = () => {
    if (!canOpenFilePicker()) {
      return;
    }
    if (coarsePointer) {
      systemFileInputRef.current?.click();
      return;
    }
    fileInputRef.current?.click();
  };

  const openSystemFilePicker = () => {
    if (canOpenFilePicker()) {
      systemFileInputRef.current?.click();
    }
  };

  const openMediaFilePicker = () => {
    if (canOpenFilePicker()) {
      mediaFileInputRef.current?.click();
    }
  };

  /**
   * Picked, dropped and pasted files land in the composer's list. Nothing is read or sent here: the
   * send button turns the list into a draft for the chosen recipient and opens the preflight.
   */
  const stageFiles = (files: File[], source: "pick" | "drop" | "paste") => {
    if (files.length === 0) {
      if (source === "drop") setError("没有检测到可发送的文件：拖入的是文件夹或网页内容，换成文件再试");
      return;
    }
    if (isRoomReadOnly) {
      setError("当前为只读访客，不能向房间发送文件");
      return;
    }
    setStagedFiles((current) => {
      const seen = new Set(current.map(stagedFileKey));
      const next = [...current];
      for (const file of files) {
        const key = stagedFileKey(file);
        if (!seen.has(key)) {
          seen.add(key);
          next.push(file);
        }
      }
      return next;
    });
    if (activeTool !== "files") selectTransferTool("files");
    setError(null);
    if (source !== "pick") setNotice(`已添加 ${files.length} 个文件到待发送，尚未发送`);
  };

  const removeStagedFile = (index: number) => {
    setStagedFiles((current) => current.filter((_, fileIndex) => fileIndex !== index));
  };

  const sendStagedFiles = () => {
    if (stagedFiles.length === 0) return;
    if (acceptFiles(stagedFiles)) setStagedFiles([]);
  };

  const handleFileInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.currentTarget.files ?? []);
    event.currentTarget.value = "";
    stageFiles(files, "pick");
  };

  const uploadViaOss = async (file: File, task: FileTransferTask) => {
    assertFileTransferTaskCurrent(task);
    if (!task.ossFallbackAllowed) {
      throw new Error("登录后才可使用文件临时存储");
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
      transferMetrics.markCloudStarted(task.activityId);
      setNotice(`服务端已允许本次上传；文件有效期：${presign.attachment.expiresAt ? formatDateTime(presign.attachment.expiresAt) : "未提供"}。正在上传文件内容。`);
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
      targetSameLan: queued.targetSameLan,
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
    if (uploadInFlightRef.current?.activityId === activity.id || queuedFileTransfersRef.current.some((item) => item.activityId === activity.id)) return;
    const peerStillAvailable = !activity.targetPeerId || peers.some((peer) => peer.peerId === activity.targetPeerId);
    if (activity.targetPeerId && !peerStillAvailable) {
      setError("原接收设备已离线。任务目标不会自动更换：等对方上线后重试，或重新选择文件发送");
      return;
    }
    const preflight = checkFilePreflight(preflightInput({
      files: [activity.file], mode: activity.targetPeerId ? "device" : "link", allowCloudFallback: activity.ossFallbackAllowed,
      roomEpoch: roomEpochRef.current, roomGeneration: roomGenerationRef.current, roomId, roomToken,
      targetPeerId: activity.targetPeerId, targetPeerLabel: activity.targetPeerLabel,
      targetSameLan: Boolean(activity.targetPeerId && peerLanMap[activity.targetPeerId]),
    }));
    if (!preflight.canSend) {
      setError(preflight.errors[0]);
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
      targetSameLan: Boolean(activity.targetPeerId && peerLanMap[activity.targetPeerId]),
      roomId,
      roomToken,
      targetPeerId: activity.targetPeerId,
      targetPeerLabel: activity.targetPeerLabel,
      ossFallbackAllowed: cloudFallbackPermitted(activity.ossFallbackAllowed, ossFallbackEnabled, Boolean(activity.targetPeerId && peerLanMap[activity.targetPeerId])),
    });
    setError(null);
    runQueuedTransfersRef.current();
  };

  const cancelOutgoingActivity = (activityId: string) => {
    cancelledActivityIdsRef.current.add(activityId);
    queuedFileTransfersRef.current = queuedFileTransfersRef.current.filter((item) => item.activityId !== activityId);
    const activeTask = uploadInFlightRef.current;
    if (activeTask?.activityId === activityId) {
      uploadInFlightRef.current = null;
      activeOutgoingActivityIdRef.current = "";
      activeTask.abortController.abort(DIRECT_SEND_USER_CANCEL);
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
        setNotice(`已开始下载：${record.attachment.fileName}`);
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
      setNotice(`已开始下载：${record.attachment.fileName}`);
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
        if (item.resumeTransferId) {
          // Deleted from this browser's storage on the next page load, not now: the
          // browser may still be reading the object URL.
          markDirectSaved(item.resumeTransferId);
        }
        setIncomingDownloadState(key, { downloading: false, downloadProgress: 100, downloadError: null });
        setNotice(`已开始下载：${item.attachment.fileName}`);
        setError(null);
        return;
      }
      if (item.blob) {
        // 之前已下载过，直接复用本地 blob，不再走网络。
        downloadBlob(item.blob, item.attachment.fileName);
        setIncomingDownloadState(key, { downloading: false, downloadProgress: 100, downloadError: null });
        setNotice(`已开始下载：${item.attachment.fileName}`);
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
      setNotice(`已开始下载：${item.attachment.fileName}`);
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
    for (const peer of collaborationMembers) {
      const targetPeerId = peer.peerId;
      // Keep payloads ordered while avoiding a new ICE negotiation for every stroke after a path fails.
      const queueKey = JSON.stringify([sendRoomEpoch, targetPeerId]);
      const previous = whiteboardSendQueuesRef.current.get(queueKey) ?? Promise.resolve();
      const task = previous.catch(() => undefined).then(async () => {
        const isTargetCurrent = () => roomEpochRef.current === sendRoomEpoch
          && currentCollaborationPeerIdsRef.current.has(targetPeerId);
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
  }, [collaborationMembers, isPeerMessageTransportReady, isRoomReadOnly, peers, sendPeerMessage, sendRelayFrame, sendRelayPeerMessage]);

  const sendClipboardPayload = useCallback(async (payload: ClipboardSyncPayload) => {
    if (isRoomReadOnly) {
      throw new Error("当前为只读访客，不能文字与链接");
    }
    if (discoveryStatusRef.current !== "online") {
      throw new Error("房间连接正在重连，恢复后再发送");
    }
    const target = peers.find((peer) => peer.peerId === selectedPeerId);
    if (!target) {
      throw new Error("先选择一台在线设备，再发送文字与链接");
    }
    const sendRoomEpoch = roomEpochRef.current;
    const message = { messageType: "clipboard" as const, payload };
    const sentDirect = await sendPeerMessage(
      target.peerId,
      message,
      CLIPBOARD_DIRECT_TIMEOUT_MS,
      "direct",
    );
    if (roomEpochRef.current !== sendRoomEpoch || !currentRoomPeerIdsRef.current.has(target.peerId)) {
      throw new Error("房间或目标设备已变化，本次剪贴板同步已取消");
    }
    if (sentDirect) {
      return;
    }
    const sentTurn = await sendPeerMessage(
      target.peerId,
      message,
      CLIPBOARD_TURN_TIMEOUT_MS,
      "relay",
    );
    if (roomEpochRef.current !== sendRoomEpoch || !currentRoomPeerIdsRef.current.has(target.peerId)) {
      throw new Error("房间或目标设备已变化，本次剪贴板同步已取消");
    }
    if (sentTurn) {
      return;
    }
    const sentRelay = await sendRelayPeerMessage(target.peerId, message,
      (frame) => sendRelayFrame(target.peerId, frame, sendRoomEpoch));
    if (!sentRelay) {
      throw new Error("互传通道暂时不可用：确认对方仍在线后重试");
    }
  }, [isRoomReadOnly, peers, selectedPeerId, sendPeerMessage, sendRelayFrame, sendRelayPeerMessage]);

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

  // Page-wide drop and paste. Files dropped or pasted anywhere outside a text field join the
  // composer's list; pasted text goes into the text draft. Neither sends anything by itself.
  const activeToolRef = useRef(activeTool);
  activeToolRef.current = activeTool;
  const pageDropRef = useRef<(files: File[]) => void>(() => undefined);
  pageDropRef.current = (files) => stageFiles(files, "drop");
  const pagePasteRef = useRef<(event: ClipboardEvent) => void>(() => undefined);
  pagePasteRef.current = (event) => {
    if (event.defaultPrevented || !event.clipboardData || activeToolRef.current === "whiteboard") return;
    if (isEditablePasteTarget(event.target)) return;
    // A paste inside an open dialog (pairing code, settings) belongs to that dialog.
    if (event.target instanceof Element && event.target.closest("[role='dialog']")) return;
    const files = filesFromClipboard(event.clipboardData);
    if (files.length > 0) {
      event.preventDefault();
      stageFiles(files, "paste");
      return;
    }
    const text = event.clipboardData.getData("text/plain");
    if (!text) return;
    event.preventDefault();
    selectTransferTool("clipboard");
    clipboardRef.current?.insertDraft(text, event.clipboardData.getData("text/html"));
  };
  useEffect(() => {
    if (isDiagramWorkspace) return undefined;
    const carriesFiles = (event: DragEvent) => Boolean(event.dataTransfer && hasDraggedFiles(event.dataTransfer));
    // The whiteboard takes dropped images on its own canvas; elsewhere a dropped file must not
    // make the browser leave the page.
    const stagesFiles = () => activeToolRef.current !== "whiteboard";
    const reset = () => {
      fileDragDepthRef.current = 0;
      setFileDragActive(false);
    };
    const onDragEnter = (event: DragEvent) => {
      if (!carriesFiles(event) || !stagesFiles()) return;
      event.preventDefault();
      fileDragDepthRef.current += 1;
      setFileDragActive(true);
    };
    const onDragOver = (event: DragEvent) => {
      if (!carriesFiles(event) || event.defaultPrevented) return;
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = stagesFiles() ? "copy" : "none";
    };
    const onDragLeave = () => {
      if (fileDragDepthRef.current === 0) return;
      fileDragDepthRef.current -= 1;
      if (fileDragDepthRef.current === 0) setFileDragActive(false);
    };
    const onDrop = (event: DragEvent) => {
      if (!carriesFiles(event) || event.defaultPrevented) return;
      event.preventDefault();
      reset();
      if (stagesFiles()) pageDropRef.current(Array.from(event.dataTransfer?.files ?? []));
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && fileDragDepthRef.current > 0) reset();
    };
    const onPaste = (event: ClipboardEvent) => pagePasteRef.current(event);
    window.addEventListener("dragenter", onDragEnter);
    window.addEventListener("dragover", onDragOver);
    window.addEventListener("dragleave", onDragLeave);
    window.addEventListener("drop", onDrop);
    window.addEventListener("dragend", reset);
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("paste", onPaste);
    return () => {
      window.removeEventListener("dragenter", onDragEnter);
      window.removeEventListener("dragover", onDragOver);
      window.removeEventListener("dragleave", onDragLeave);
      window.removeEventListener("drop", onDrop);
      window.removeEventListener("dragend", reset);
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("paste", onPaste);
    };
  }, [isDiagramWorkspace]);

  // When a device first appeared, so its tile can say "连接中" for a moment before "在线".
  const peerFirstSeenRef = useRef<Map<string, number>>(new Map());
  const nearbyDevices = useMemo<NearbyDevice[]>(() => peers.map((peer) => {
    const firstSeen = peerFirstSeenRef.current;
    if (!firstSeen.has(peer.peerId)) firstSeen.set(peer.peerId, Date.now());
    return {
      peerId: peer.peerId,
      displayName: discoveryPeerDisplayName(peer),
      sameLan: Boolean(peerLanMap[peer.peerId]),
      firstSeenAt: firstSeen.get(peer.peerId),
    };
  }), [peerLanMap, peers]);
  const peerLabel = (sourcePeerId: string) => diagramPeerDisplayNames[sourcePeerId]
    ?? (sourcePeerId === "shared-link" ? "共享链接" : "未命名设备");

  // Short toasts when something arrives or a send finishes; the lists below hold the details.
  const announcedIncomingRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    const seen = announcedIncomingRef.current;
    const fresh = incoming.filter((item) => !seen.has(incomingItemKey(item)));
    incoming.forEach((item) => seen.add(incomingItemKey(item)));
    const announce = fresh.filter((item) => !item.restored && item.sourcePeerId !== "shared-link");
    if (announce.length === 1) {
      setNotice(`收到 ${announce[0].attachment.fileName}（来自 ${peerLabel(announce[0].sourcePeerId)}）`);
    } else if (announce.length > 1) {
      setNotice(`收到 ${announce.length} 个文件`);
    }
  }, [incoming]);
  const announcedPendingRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    const seen = announcedPendingRef.current;
    const fresh = pendingTransfers.filter((item) => !seen.has(receivingTransferKey(item)));
    pendingTransfers.forEach((item) => seen.add(receivingTransferKey(item)));
    if (fresh.length > 0) {
      setNotice(`${peerLabel(fresh[0].sourcePeerId)} 想发送 ${fresh[0].fileName}，在“收到的内容”里接收或拒绝`);
    }
  }, [pendingTransfers]);
  const announcedClipboardRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    const seen = announcedClipboardRef.current;
    const fresh = clipboardEvents.filter((event) => !seen.has(event.eventId));
    clipboardEvents.forEach((event) => seen.add(event.eventId));
    const latest = fresh.at(-1);
    if (latest) setNotice(`收到 ${latest.sourceDisplayName || "未命名设备"} 发来的文字`);
  }, [clipboardEvents]);
  const activityStatusRef = useRef<Map<string, OutgoingTransferStatus>>(new Map());
  useEffect(() => {
    const previous = activityStatusRef.current;
    const finished = outgoingActivities.filter((activity) => activity.status === "completed"
      && previous.has(activity.id) && previous.get(activity.id) !== "completed");
    activityStatusRef.current = new Map(outgoingActivities.map((activity) => [activity.id, activity.status]));
    if (finished.length === 1) {
      const [activity] = finished;
      setNotice(activity.transport === "cloud"
        ? `文件链接已生成：${activity.fileName}`
        : `${activity.targetPeerLabel} 已接收 ${activity.fileName}`);
    } else if (finished.length > 1) {
      setNotice(`${finished.length} 个文件已发送完成`);
    }
  }, [outgoingActivities]);

  // An owner alone in a shared room sees the QR code and pairing code right in the device list.
  const inlineInviteVisible = !isDiagramWorkspace && sharedRoomActive && roomRole === "OWNER"
    && discoveryStatus === "online" && peers.length === 0;
  useEffect(() => {
    if (inlineInviteVisible) void prepareSecureInvite("EDITOR");
  }, [inlineInviteVisible, roomId, roomToken]);

  const clearLocalTransferData = () => {
    void clearResumeData().then(() => {
      setNotice("已清除本机保存的互传数据：未完成的接收、未保存的已收文件和可续传的发送记录");
    });
  };

  const inboxEntries = useMemo<InboxEntry[]>(() => [
    ...incoming.map((item): InboxEntry => ({ kind: "file", key: `file:${incomingItemKey(item)}`, at: item.receivedAt ?? 0, item })),
    ...clipboardEvents.map((event): InboxEntry => ({ kind: "text", key: `text:${event.eventId}`, at: event.receivedAt, event })),
  ].sort((left, right) => right.at - left.at), [clipboardEvents, incoming]);
  const hasTasks = outgoingActivities.length > 0
    || receivingTransfers.length > 0
    || hasResumableTransfers(storedReceives, outgoingResumes);

  const sharedModals = (
    <>
      {fileDraft ? <TransferFilePreflight
        capabilities={cloudCapabilities}
        input={preflightInput(fileDraft)}
        recipientLabel={fileDraft.targetPeerLabel}
        allowCloud={fileDraft.allowCloudFallback}
        canOfferCloudFallback={ossFallbackEnabled && !fileDraft.targetSameLan}
        onAllowCloud={(allowCloudFallback) => updateFileDraft({ allowCloudFallback })}
        onModeChange={() => {
          updateFileDraft({ mode: "link", targetPeerId: "", targetPeerLabel: "文件链接", targetSameLan: false, allowCloudFallback: false });
          setFileDeliveryMode("link");
        }}
        onRemove={(index) => updateFileDraft({ files: fileDraft.files.filter((_, fileIndex) => fileIndex !== index) })}
        onCancel={cancelFileDraft}
        onConfirm={() => {
          confirmFileDraft();
          // On one-column layouts the task list sits below the composer: bring the send into view.
          if (!isDiagramWorkspace && window.matchMedia("(max-width: 1023px)").matches) {
            window.setTimeout(() => document.getElementById("transfer-tasks")?.scrollIntoView({
              behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
              block: "start",
            }), 150);
          }
        }}
        onLogin={openLogin}
      /> : null}
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
    const collaboratorCount = collaborationMembers.length + 1;
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
                {sharedRoomActive ? "共享协作空间" : "本地草稿，尚未共享"} · {discoveryStatus === "reconnecting" ? "连接重连中" : discoveryStatus === "connecting" ? "正在连接" : collaborationMembers.length > 0 ? "协作者在线" : "等待邀请协作者"}
              </div>
            </div>
          </div>
          <span className="diagram-collaboration-count">{collaboratorCount} 人</span>
        </section>

        <section className="diagram-collaboration-section">
          <div className="diagram-collaboration-section-heading">
            <h3>连接与房间</h3>
            <span>{sharedRoomActive ? "共享房间" : "附近设备"}</span>
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
            {sharedRoomActive ? (
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
            {sharedRoomActive ? (
              <div className="diagram-collaboration-permissions">
                <RoomPermissionSetting
                  compact
                  context="diagram"
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
            <span>{sharedRoomActive ? "可跨网络加入" : "尚未与其他设备共享"}</span>
          </div>
          <div className="mt-2 grid grid-cols-4 gap-1.5">
            <Button className="diagram-collaboration-action is-primary" size="sm" color="primary" radius="sm" variant="flat" onPress={() => void shareRoom(roomInviteRole)}>分享</Button>
            <Button className="diagram-collaboration-action" size="sm" radius="sm" variant="flat" onPress={() => void copyRoomLink(roomInviteRole)}>复制链接</Button>
            <Button className={`diagram-collaboration-action ${qrVisible ? "is-active" : ""}`} size="sm" radius="sm" variant="flat" onPress={() => qrVisible ? setQrVisible(false) : showRoomQr()}>
              {qrVisible ? "收起二维码" : "二维码"}
            </Button>
            <Button className="diagram-collaboration-action" size="sm" radius="sm" variant="flat" onPress={createNewRoom}>新房间</Button>
          </div>
          {!sharedRoomActive ? (
            <Button className="diagram-collaboration-action mt-1.5" size="sm" radius="sm" color="primary" variant="flat" onPress={enterSharedRoom}>
              创建共享房间，邀请远程协作者
            </Button>
          ) : null}
          {qrVisible ? (
            <div className="diagram-collaboration-qr mt-2.5">
              {(sharedRoomActive ? pairingJoinUrl : roomJoinUrl) ? (
                <>
                  <RoomQrCode value={(sharedRoomActive ? pairingJoinUrl : roomJoinUrl) as string} />
                  <div className="mt-2 break-all text-center font-mono text-[9px] leading-4 text-zinc-500 dark:text-zinc-400">
                    {sharedRoomActive ? "5 分钟一次性扫码邀请" : roomJoinUrl}
                  </div>
                </>
              ) : (
                <div className="py-6 text-center text-tiny text-zinc-400">正在生成安全二维码…</div>
              )}
            </div>
          ) : null}
        </section>

        {sharedRoomActive && roomRole === "OWNER" ? (
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
            {collaborationMembers.map((peer) => (
              <div key={peer.peerId} className="diagram-collaboration-member">
                <span className="diagram-collaboration-avatar">{discoveryPeerDisplayName(peer).slice(0, 1).toUpperCase()}</span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-tiny font-medium">{discoveryPeerDisplayName(peer)}</div>
                  <div className="text-[10px] text-zinc-500 dark:text-zinc-400">协作者</div>
                </div>
                <span className="diagram-collaboration-online-dot" aria-label="在线" />
              </div>
            ))}
            {collaborationMembers.length === 0 ? <div className="py-2 text-center text-[10px] text-zinc-400">暂无已加入空间的协作者</div> : null}
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
            roomToken={sharedRoomActive ? roomToken : ""}
            roomRole={effectiveRoomRole}
            peerId={peerId}
            peerCount={collaborationMembers.length}
            peerDisplayNames={Object.fromEntries(collaborationMembers.map((peer) => [peer.peerId, discoveryPeerDisplayName(peer)]))}
            isConnected={collaborationMembers.length > 0}
            events={diagramEvents}
            onSend={sendWhiteboardPayload}
          />
        </Suspense>
        {sharedModals}
      </main>
    );
  }

  const selectedPeerLabel = selectedPeer ? discoveryPeerDisplayName(selectedPeer) : "";
  const recipientOffline = Boolean(selectedPeerId && !selectedPeer);
  const linkMode = activeTool === "files" && fileDeliveryMode === "link";
  const connectionTone: Tone = discoveryStatus === "online"
    ? "success"
    : discoveryStatus === "connecting" || discoveryStatus === "reconnecting" ? "warning" : "danger";
  const roomLabel = sharedRoomActive ? `共享房间 ${transferRoomDisplayName(roomId)}` : "附近设备";
  const currentTaskActivityId = uploadInFlightRef.current?.activityId ?? "";
  const completedTaskCount = outgoingActivities.filter((activity) => activity.status === "completed").length;
  const retryableTaskCount = outgoingActivities.filter((activity) => activity.status === "failed" || activity.status === "cancelled").length;
  const runningTaskCount = activeOutgoingCount + receivingTransfers.length;
  const inboxCount = pendingTransfers.length + inboxEntries.length;
  const recordActivityId = record
    ? outgoingActivities.find((activity) => activity.file === record.file && activity.status === "completed")?.id ?? ""
    : "";
  const failedRetryAvailable = state === "failed" && selectedFiles.length > 0
    && outgoingActivities.some((activity) => activity.status === "failed");

  // Why the send button is off, in the order a newcomer has to fix things.
  const recipientBlocker = isRoomReadOnly
    ? "当前为只读访客：可以接收和查看，不能发送"
    : !selectedPeer
      ? recipientOffline ? `${selectedPeerName || "原接收设备"} 已离线，重新选择接收方` : "先选择接收设备"
      : discoveryStatus !== "online" ? "房间连接尚未恢复，恢复后即可发送" : "";
  let send: SendBarModel | null = null;
  if (activeTool === "files" && linkMode) {
    const count = stagedFiles.length;
    send = {
      label: count ? `上传 ${count} 个文件并生成链接` : "上传并生成链接",
      icon: "upload",
      disabled: !count || isRoomReadOnly || !ossFallbackEnabled,
      reason: isRoomReadOnly ? "当前为只读访客：可以接收和查看，不能发送" : !count ? "先添加要上传的文件" : "",
      onSend: sendStagedFiles,
    };
  } else if (activeTool === "files") {
    const count = stagedFiles.length;
    send = {
      label: count
        ? selectedPeer ? `发送 ${count} 个文件给 ${selectedPeerLabel}` : `发送 ${count} 个文件`
        : selectedPeer ? `发送给 ${selectedPeerLabel}` : "发送",
      icon: "send",
      disabled: !count || Boolean(recipientBlocker),
      // The summary already asks for a recipient; the reason line covers what comes after.
      reason: isRoomReadOnly ? recipientBlocker : !selectedPeer ? "" : recipientBlocker || (!count ? "先添加要发送的文件" : ""),
      onSend: sendStagedFiles,
    };
  } else if (activeTool === "clipboard") {
    const { hasDraft, withinLimits, sending } = clipboardComposer;
    send = {
      label: selectedPeer ? `发送文字给 ${selectedPeerLabel}` : "发送文字",
      icon: "send",
      disabled: !hasDraft || !withinLimits || sending || Boolean(recipientBlocker),
      reason: isRoomReadOnly ? recipientBlocker : !selectedPeer
        ? ""
        : recipientBlocker || (!hasDraft ? "输入或粘贴要发送的文字、链接" : !withinLimits ? "内容超过上限，删减后再发送" : sending ? "正在发送…" : ""),
      onSend: () => clipboardRef.current?.submitComposer(),
      hint: <span className="tr-kbd-hint"><kbd>Ctrl/⌘</kbd><kbd>Enter</kbd></span>,
    };
  }

  const recipientSummary = linkMode ? (
    <>
      <span className="tr-sendbar-icon" aria-hidden="true"><Icon name="link" size={18} /></span>
      <span className="tr-sendbar-text">
        <span className="tr-sendbar-caption">生成文件链接 · 文件将临时存储</span>
        <span className="tr-sendbar-name">不需要选择接收方</span>
      </span>
    </>
  ) : selectedPeer ? (
    <>
      <DeviceAvatar peerId={selectedPeer.peerId} name={selectedPeerLabel} size="sm" />
      <span className="tr-sendbar-text">
        <span className="tr-sendbar-caption">发送给</span>
        <span className="tr-sendbar-name">
          <span className="jd-ellipsis">{selectedPeerLabel}</span>
          {(() => {
            const tag = connectionTag(peerTransportPaths[selectedPeer.peerId], {
              firstSeenAt: nearbyDevices.find((device) => device.peerId === selectedPeer.peerId)?.firstSeenAt,
              now: Date.now(),
            });
            return <Tag tone={tag.tone} plain={tag.plain}>{tag.label}</Tag>;
          })()}
        </span>
      </span>
    </>
  ) : recipientOffline ? (
    <>
      <DeviceAvatar peerId={selectedPeerId} name={selectedPeerName || "?"} size="sm" offline />
      <span className="tr-sendbar-text">
        <span className="tr-sendbar-caption tr-text-warning">{selectedPeerName || "原接收设备"} 已离线</span>
        <span className="tr-sendbar-name">重新选择接收方；不会自动换成别的设备</span>
      </span>
    </>
  ) : (
    <>
      <span className="tr-sendbar-icon is-empty" aria-hidden="true"><Icon name="user" size={18} /></span>
      <span className="tr-sendbar-text">
        <span className="tr-sendbar-caption">发送给</span>
        <span className="tr-sendbar-name">先选择接收设备</span>
      </span>
    </>
  );

  const discoveryAlert = discoveryStatus !== "online" || discoveryError ? (
    <Alert
      className="tr-stacked-alert"
      tone={discoveryStatus === "permission-denied" || discoveryStatus === "name-conflict" ? "danger" : "warning"}
      role={discoveryStatus === "permission-denied" || discoveryStatus === "name-conflict" ? "alert" : "status"}
      title={discoveryStatusLabel(discoveryStatus)}
      actions={
        <>
          {/* With no devices, the empty list below already offers the retry as its main action. */}
          {peers.length > 0 || discoveryStatus === "connecting" || discoveryStatus === "reconnecting" || discoveryStatus === "online" ? (
            <button type="button" className="bd-btn bd-btn--secondary bd-btn--sm" onClick={retryDiscoveryConnection}>重试连接</button>
          ) : null}
          <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={() => { resetRoomSettingsDraft(); setRoomSettingsOpen(true); }}>检查设置</button>
          {discoveryErrorDetail ? (
            <Popover placement="bottom-end">
              <PopoverTrigger>
                <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm">查看详情</button>
              </PopoverTrigger>
              <PopoverContent className="tr-popover max-w-[min(88vw,420px)]">
                <div className="tr-popover-title">连接诊断信息</div>
                <code className="tr-popover-code">{discoveryErrorDetail}</code>
              </PopoverContent>
            </Popover>
          ) : null}
        </>
      }
    >
      {discoveryError || discoveryStatusDescription(discoveryStatus)}
    </Alert>
  ) : null;

  const inlineInvite = inlineInviteVisible ? (
    <div className="tr-inline-invite">
      {pairingJoinUrl ? <RoomQrCode value={pairingJoinUrl} /> : <div className="tr-qr-placeholder" role="status">正在生成二维码</div>}
      <div className="tr-inline-invite-text">
        <span className="tr-inline-invite-label">扫码，或在对方的“添加设备 → 输入配对码”里输入</span>
        <span className="tr-pairing-code bd-num">{pairingCode?.role === "EDITOR" ? formatPairingCode(pairingCode.code) : "•••• ••••"}</span>
        <span className="tr-note">{pairingCode?.role === "EDITOR" ? `${formatInviteExpiry(pairingCode.expiresAt)} · 单次有效` : "正在生成 5 分钟配对码"}</span>
        <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={() => void regeneratePairingCode()}>
          <Icon name="refresh" /><span>换一个配对码</span>
        </button>
      </div>
    </div>
  ) : !sharedRoomActive && roomJoinUrl ? (
    <div className="tr-inline-invite">
      <RoomQrCode value={roomJoinUrl} />
      <div className="tr-inline-invite-text">
        <span className="tr-inline-invite-label">同一网络的手机扫码，直接打开本页</span>
        <span className="tr-note">不在同一网络时，生成配对码：对方输入 8 位数字即可加入。</span>
        <button type="button" className="bd-btn bd-btn--secondary bd-btn--sm" onClick={enterSharedRoom}>
          <Icon name="key" /><span>生成配对码</span>
        </button>
      </div>
    </div>
  ) : null;

  const recipientsCard = activeTool === "whiteboard" ? (
    <section className="bd-card tr-card" data-testid="collaboration-audience" aria-labelledby="tr-audience-title">
      <div className="tr-card-head">
        <span className="tr-card-icon" aria-hidden="true"><Icon name="users" /></span>
        <h2 id="tr-audience-title" className="tr-card-title">协作成员</h2>
        <Tag plain>{sharedRoomActive ? `${collaborationMembers.length + 1} 位` : "本地草稿"}</Tag>
      </div>
      <div className="tr-card-body tr-audience">
        <p className="tr-audience-title">{sharedRoomActive ? "本协作空间的参与者" : "本地白板 · 尚未与任何设备共享"}</p>
        {sharedRoomActive ? (
          <ul className="tr-members">
            <li><DeviceAvatar peerId={peerId} name={displayName} size="sm" /><span className="jd-ellipsis">{displayName}（我）</span></li>
            {collaborationMembers.map((peer) => (
              <li key={peer.peerId}>
                <DeviceAvatar peerId={peer.peerId} name={discoveryPeerDisplayName(peer)} size="sm" />
                <span className="jd-ellipsis">{discoveryPeerDisplayName(peer)}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="tr-muted">附近设备不会自动收到白板。创建协作空间并邀请对方后，才会同步内容。</p>
        )}
        <button
          type="button"
          className="bd-btn bd-btn--secondary"
          onClick={sharedRoomActive ? () => openInvitePanel() : enterSharedRoom}
        >
          <Icon name={sharedRoomActive ? "plus" : "users"} />
          <span>{sharedRoomActive ? "邀请参与者 / 输入配对码" : "创建协作空间"}</span>
        </button>
      </div>
    </section>
  ) : linkMode ? (
    <section className="bd-card tr-card" aria-labelledby="tr-link-title">
      <div className="tr-card-head">
        <span className="tr-card-icon" aria-hidden="true"><Icon name="link" /></span>
        <h2 id="tr-link-title" className="tr-card-title">生成文件链接</h2>
      </div>
      <div className="tr-card-body tr-link-explain">
        <p>文件上传到服务端配置的临时存储，生成链接后分享；接收方需要登录，并持有链接和访问口令。</p>
        <p className="tr-note">上传前会显示存储与额度；不需要选择接收方。要直接发给一台设备，在“文件”里改为发送到设备。</p>
      </div>
    </section>
  ) : (
    <section className="bd-card tr-card" aria-labelledby="tr-step-recipient">
      <div className="tr-card-head">
        <StepBadge step={1} done={Boolean(selectedPeer)} />
        <h2 id="tr-step-recipient" className="tr-card-title">选择接收方</h2>
        {peers.length > 0 ? <span className="tr-card-meta bd-num">{peers.length} 台在线</span> : null}
        <button type="button" className="bd-btn bd-btn--secondary bd-btn--sm tr-card-action" onClick={() => openInvitePanel()}>
          <Icon name="plus" /><span>添加设备</span>
        </button>
      </div>
      <div className="tr-card-body tr-recipients">
        {discoveryAlert}
        <NearbyDeviceGrid
          devices={nearbyDevices}
          selectedPeerId={selectedPeerId}
          offlineSelection={recipientOffline ? { peerId: selectedPeerId, displayName: selectedPeerName || "原接收设备" } : null}
          transportPaths={peerTransportPaths}
          discoverable={discoverable}
          discoveryStatus={discoveryStatus}
          emptyAddon={inlineInvite}
          onAddDevice={() => openInvitePanel("join")}
          onRetry={retryDiscoveryConnection}
          onSelect={(device) => {
            const peer = peers.find((item) => item.peerId === device.peerId);
            if (peer) selectTransferPeer(peer);
          }}
          onOpenSettings={() => { resetRoomSettingsDraft(); setRoomSettingsOpen(true); }}
        />
      </div>
    </section>
  );

  return (
    <main className="bd-root tr-page" data-sendbar={send ? "true" : undefined}>
      <header className="tr-topbar">
        <div className="tr-topbar-inner">
          <AppLogo className="tr-brand" label="specus" subtitle="互传" />
          <div className={`tr-conn is-${connectionTone}`} role="status">
            <span className="tr-conn-dot" aria-hidden="true" />
            <span className="tr-conn-state">{discoveryStatus === "online" ? "已连接" : discoveryStatusLabel(discoveryStatus)}</span>
            <span className="tr-conn-room">{roomLabel}</span>
            {discoveryStatus === "online" ? <span className="tr-conn-count bd-num">{peers.length} 台在线</span> : null}
          </div>
          <div className="tr-topbar-tools">
            {hasTasks ? (
              <button
                type="button"
                className={`tr-activity-btn${runningTaskCount > 0 ? " is-running" : ""}`}
                aria-label="传输任务"
                title={runningTaskCount > 0 ? `${runningTaskCount} 个进行中，查看传输任务` : "查看传输任务"}
                onClick={() => {
                  const section = document.getElementById("transfer-tasks");
                  section?.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
                  section?.focus({ preventScroll: true });
                }}
              >
                <Icon name={runningTaskCount > 0 ? "activity" : "list"} />
                {runningTaskCount > 0 ? <span className="bd-num" aria-hidden="true">{runningTaskCount}</span> : null}
              </button>
            ) : null}
            <button
              type="button"
              className="bd-icon-btn tr-tool-btn"
              aria-label="设置"
              title="设备设置：名称、被发现、接收前确认"
              onClick={() => {
                resetRoomSettingsDraft();
                setRoomSettingsOpen(true);
              }}
            >
              <Icon name="settings" />
            </button>
            <div className="public-header-actions tr-header-menus">
              <PublicToolsMenu active={workspace} />
              <UserMenuButton className="public-header-theme-button" />
            </div>
          </div>
        </div>
      </header>

      <div className="tr-shell">
        <div className="tr-head">
          <div className="min-w-0">
            <h1 className="bd-page-title">互传</h1>
            <p className="bd-page-desc">选择接收方 → 选择内容 → 发送。同一网络里打开本页的设备会自动出现。</p>
          </div>
          <div className="tr-head-side">
            <div className="tr-self">
              <DeviceAvatar peerId={peerId} name={displayName} size="sm" />
              <span className="tr-self-text">
                <span className="tr-self-label">这台设备</span>
                <button
                  type="button"
                  className="tr-self-name"
                  title="复制设备名称，在另一台设备上核对"
                  onClick={() => void copyText(displayName).then(() => setNotice("设备名称已复制")).catch((err) => setError(err instanceof Error ? err.message : "复制设备名称失败"))}
                >
                  {displayName}
                </button>
              </span>
              <Popover placement="bottom-end">
                <PopoverTrigger>
                  <button type="button" className={`bd-tag tr-account-tag${ossFallbackEnabled ? " bd-tag--success" : " bd-tag--plain"}`} aria-label="传输方式说明">
                    {!authReady ? "账号检测中" : ossFallbackEnabled ? "已登录 · 可生成文件链接" : "未登录 · 设备互传"}
                  </button>
                </PopoverTrigger>
                <PopoverContent className="tr-popover max-w-72">
                  <div className="tr-popover-title">{ossFallbackEnabled ? "临时文件链接" : "设备互传"}</div>
                  <p className="tr-popover-body">
                    {ossFallbackEnabled
                      ? "生成链接会临时存储文件，需要服务端配置存储且账号额度充足。设备传输只有在发送前单独允许时，才会在失败后改用临时存储。"
                      : "文件可直接传输或经中继转发，不会创建云端文件副本。"}
                  </p>
                </PopoverContent>
              </Popover>
            </div>
            <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={() => setHelpOpen(true)}>
              <Icon name="info-circle" /><span>使用帮助</span>
            </button>
          </div>
        </div>

        <div className="tr-grid">
          <div className="tr-col tr-col--side">
            {recipientsCard}

            {inboxCount > 0 ? (
              <TransferInbox
                pending={pendingTransfers}
                entries={inboxEntries}
                peerLabel={peerLabel}
                cloudTransferEnabled={ossFallbackEnabled}
                onAccept={(item) => acceptIncomingTransfer(item.sourcePeerId, item.transferId)}
                onReject={(item) => rejectIncomingTransfer(item.sourcePeerId, item.transferId)}
                onShare={shareIncomingFile}
                onDownload={downloadIncoming}
                onLogin={openLogin}
                onPreview={setPreviewTarget}
                onCopyText={(text) => void copyText(text).then(() => setNotice("已复制到剪贴板")).catch((err) => setError(err instanceof Error ? err.message : "复制失败：浏览器不允许写入剪贴板，打开预览后手动复制"))}
              />
            ) : null}

            {transferMetrics.collecting ? (
              <ProductMetricsMemberNotice className="tr-metrics-note">
                <button
                  type="button"
                  className="jd-link tr-inline-link"
                  onClick={() => transferMetrics.setOptedOut(!transferMetrics.optedOut)}
                >
                  {transferMetrics.optedOut ? "本设备已不参与 · 恢复参与" : "本设备不参与"}
                </button>
              </ProductMetricsMemberNotice>
            ) : null}
          </div>

          <div className="tr-col tr-col--main">
            <section className={`bd-card tr-card tr-composer${activeTool === "whiteboard" ? " is-board" : ""}`} aria-labelledby="tr-step-content">
              <div className="tr-card-head tr-composer-head">
                {activeTool === "whiteboard"
                  ? <span className="tr-card-icon" aria-hidden="true"><Icon name="edit" /></span>
                  : <StepBadge step={2} done={activeTool === "files" ? stagedFiles.length > 0 : clipboardComposer.hasDraft} />}
                <h2 id="tr-step-content" className="tr-card-title">{activeTool === "whiteboard" ? "一起画" : "选择内容"}</h2>
                <ModeTabs active={activeTool} fileCount={stagedFiles.length} onSelect={selectTransferTool} />
              </div>

              <div className="tr-card-body tr-composer-body">
                <div
                  id="transfer-panel-files"
                  role="tabpanel"
                  aria-labelledby="transfer-tab-files"
                  hidden={activeTool !== "files"}
                  className="tr-panel"
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
                  <input
                    ref={systemFileInputRef}
                    id="public-transfer-system-file-input"
                    type="file"
                    accept={MOBILE_SYSTEM_FILE_ACCEPT}
                    multiple
                    hidden
                    disabled={isRoomReadOnly}
                    tabIndex={-1}
                    onChange={handleFileInputChange}
                  />
                  <input
                    ref={mediaFileInputRef}
                    id="public-transfer-media-file-input"
                    type="file"
                    accept="image/*,video/*"
                    multiple
                    hidden
                    disabled={isRoomReadOnly}
                    tabIndex={-1}
                    onChange={handleFileInputChange}
                  />
                  {ossFallbackEnabled ? (
                    <div className="tr-panel-toolbar">
                      <span className="tr-delivery">
                        <Icon name={linkMode ? "link" : "send"} />
                        {linkMode ? "生成文件链接：上传到临时存储" : "发送到设备：直连或中继，不经过云端"}
                      </span>
                      <button
                        type="button"
                        className="bd-btn bd-btn--ghost bd-btn--sm"
                        onClick={() => setFileDeliveryMode((mode) => mode === "device" ? "link" : "device")}
                      >
                        {fileDeliveryMode === "device" ? "改为生成文件链接" : "改为发送到设备"}
                      </button>
                    </div>
                  ) : null}
                  {stagedFiles.length === 0 ? (
                    <button
                      type="button"
                      data-testid="public-transfer-file-dropzone"
                      aria-label={isFileDragActive ? "松开以添加文件" : coarsePointer ? "选择要发送的文件" : "拖入文件，或选择文件"}
                      aria-describedby="public-transfer-file-dropzone-detail"
                      disabled={isRoomReadOnly}
                      onClick={openFilePicker}
                      className={`tr-dropzone${isFileDragActive ? " is-active" : ""}`}
                    >
                      <span className="tr-dropzone-icon" aria-hidden="true"><Icon name="upload" size={24} /></span>
                      <span className="tr-dropzone-title">
                        {isFileDragActive ? "松开以添加文件" : coarsePointer ? "选择要发送的文件" : "拖入文件，或选择文件"}
                      </span>
                      <span id="public-transfer-file-dropzone-detail" className="tr-dropzone-desc">
                        {linkMode
                          ? "添加后先查看存储与额度，确认后才上传并生成链接。"
                          : <>也可以拖到页面任意位置，或粘贴<span className="tr-nowrap">（Ctrl/⌘ V）</span>。添加后先检查列表，按发送才会发出。</>}
                      </span>
                    </button>
                  ) : (
                    <div className="tr-staged">
                      <div className="tr-staged-head">
                        <span className="tr-staged-total">
                          <strong className="bd-num">{stagedFiles.length} 个文件</strong>
                          <span className="bd-num">合计 {formatBytes(stagedFilesSize)}</span>
                        </span>
                        <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={() => setStagedFiles([])}>
                          <Icon name="trash" /><span>清空</span>
                        </button>
                      </div>
                      <ul aria-label="待发送文件" className="tr-file-list">
                        {stagedFiles.map((file, index) => (
                          <li key={`${stagedFileKey(file)}:${index}`} className="tr-file-row">
                            <span className="tr-file-icon" aria-hidden="true"><Icon name={fileKindIcon(file.name, file.type)} size={16} /></span>
                            <span className="tr-file-text">
                              <span className="tr-file-name" title={file.name}>{file.name}</span>
                              <span className="tr-file-meta bd-num">{formatBytes(file.size)} · {fileKindLabel(file.name, file.type)}</span>
                            </span>
                            <button
                              type="button"
                              className="bd-icon-btn tr-file-remove"
                              aria-label={`移除 ${file.name}`}
                              title="从待发送列表移除"
                              onClick={() => removeStagedFile(index)}
                            >
                              <Icon name="x" />
                            </button>
                          </li>
                        ))}
                      </ul>
                      <button
                        type="button"
                        data-testid="public-transfer-file-dropzone"
                        className={`tr-dropzone tr-dropzone--compact${isFileDragActive ? " is-active" : ""}`}
                        disabled={isRoomReadOnly}
                        onClick={openFilePicker}
                      >
                        <Icon name="plus" />
                        <span className="tr-dropzone-title">添加更多文件</span>
                        <span className="tr-dropzone-desc">也可以拖入或粘贴</span>
                      </button>
                    </div>
                  )}
                  {coarsePointer ? (
                    <div className="tr-pick-row">
                      <button type="button" className="bd-btn bd-btn--secondary" disabled={isRoomReadOnly} onClick={openSystemFilePicker}>
                        <Icon name="folder" /><span>系统文件</span>
                      </button>
                      <button type="button" className="bd-btn bd-btn--secondary" disabled={isRoomReadOnly} onClick={openMediaFilePicker}>
                        <Icon name="image" /><span>照片 / 视频</span>
                      </button>
                    </div>
                  ) : null}
                </div>

                <SyncedClipboard
                  ref={clipboardRef}
                  onComposerStateChange={setClipboardComposer}
                  syncKey={transferRoomScopeKey}
                  isActive={activeTool === "clipboard"}
                  focusRequest={clipboardFocusRequest}
                  canSend={!isRoomReadOnly}
                  fileTargetRequired={true}
                  targetPeerId={selectedPeer?.peerId ?? ""}
                  targetPeerLabel={selectedPeerLabel}
                  events={clipboardEvents}
                  onSend={sendClipboardPayload}
                  onFiles={(files) => acceptFiles(files, "device")}
                  onDraftStateChange={setClipboardHasDraft}
                />

                <div
                  id="transfer-panel-whiteboard"
                  role="tabpanel"
                  aria-labelledby="transfer-tab-whiteboard"
                  hidden={activeTool !== "whiteboard"}
                  className="tr-panel"
                >
                  <SyncedWhiteboard
                    boardKey={transferRoomScopeKey}
                    roomRole={effectiveRoomRole}
                    peerId={peerId}
                    peerCount={collaborationMembers.length}
                    isConnected={collaborationMembers.length > 0}
                    isActive={activeTool === "whiteboard"}
                    events={whiteboardEvents}
                    onSend={sendWhiteboardPayload}
                    onDraftStateChange={setWhiteboardHasDraft}
                  />
                </div>
              </div>

              {send ? (
                <SendBar model={send} summary={recipientSummary} />
              ) : null}
            </section>

            {volatileFileWork ? (
              <p role="status" data-testid="transfer-leave-warning" className="tr-leave-note">
                <Icon name="alert" />
                <span>当前有待处理文件。离开或刷新会中断传输：文件草稿和只在内存中接收的文件不会恢复；写入本机存储的接收在 24 小时内可以续传，但发送方需要重新选择同一文件。浏览器可能无法弹出提醒，离开前先完成传输并保存收到的文件。</span>
              </p>
            ) : null}

            {hasTasks ? (
              <section className="tr-section" id="transfer-tasks" tabIndex={-1} aria-labelledby="tr-tasks-title">
                <div className="jd-section-head">
                  <div className="min-w-0">
                    <h2 id="tr-tasks-title">传输任务</h2>
                    <p className="bd-num">
                      {[
                        runningTaskCount > 0 ? `${runningTaskCount} 个进行中` : "",
                        completedTaskCount > 0 ? `${completedTaskCount} 个完成` : "",
                        retryableTaskCount > 0 ? `${retryableTaskCount} 个可重试` : "",
                      ].filter(Boolean).join(" · ") || "没有进行中的传输"}
                    </p>
                  </div>
                  {completedTaskCount > 0 ? (
                    <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={() => setOutgoingActivities(keepUncompletedTransfers)}>
                      <Icon name="check-check" /><span>清理已完成</span>
                    </button>
                  ) : null}
                </div>
                <div className="tr-task-list">
                  {receivingTransfers.map((item) => (
                    <ReceivingTaskRow
                      key={`receiving:${receivingTransferKey(item)}`}
                      item={item}
                      sourceLabel={peerLabel(item.sourcePeerId)}
                      pathLabel={transportPathLabel(peerTransportPaths[item.sourcePeerId])}
                      onCancel={() => { cancelIncomingTransfer(item.sourcePeerId, item.transferId); setNotice("已取消接收"); }}
                    />
                  ))}
                  {outgoingActivities.map((activity) => (
                    <OutgoingTaskRow
                      key={activity.id}
                      activity={activity}
                      detail={activity.id === currentTaskActivityId ? (
                        <ActiveSendDetail
                          state={state}
                          store={progressStore}
                          transportPath={activity.targetPeerId ? peerTransportPaths[activity.targetPeerId] : undefined}
                        />
                      ) : null}
                      result={activity.id === recordActivityId && record ? (
                        <RecordResult
                          record={record}
                          onShare={() => void shareRecordFile()}
                          onDownload={() => void downloadRecordFile()}
                          onPreview={() => setPreviewTarget({
                            fileName: record.attachment.fileName,
                            mimeType: record.attachment.mimeType,
                            url: record.previewUrl,
                            blob: record.file,
                            sizeBytes: record.attachment.sizeBytes,
                          })}
                        />
                      ) : null}
                      onCancel={() => (activity.id === currentTaskActivityId ? cancelTransfer() : cancelOutgoingActivity(activity.id))}
                      onRetry={() => retryOutgoingActivity(activity)}
                    />
                  ))}
                </div>
                <ResumableTransfersPanel
                  storedReceives={storedReceives}
                  outgoingResumes={outgoingResumes}
                  peerDisplayNames={diagramPeerDisplayNames}
                  onResumeOutgoing={resumeOutgoing}
                  onAbandonOutgoing={(transferId) => { abandonOutgoing(transferId); setNotice("已放弃该发送"); }}
                  onAbandonReceive={(transferId) => { abandonStoredReceive(transferId); setNotice("已放弃并删除本机保存的部分数据"); }}
                  onClearAll={clearLocalTransferData}
                  onError={(message) => setError(message)}
                />
              </section>
            ) : null}
          </div>
        </div>
      </div>

      <div className="bd-toast-region tr-toasts">
        {error ? (
          <div className="bd-toast bd-toast--error" role="alert">
            <Icon name="circle-alert" />
            <span className="tr-toast-text">{error}</span>
            {failedRetryAvailable ? (
              <button type="button" className="bd-toast-action" onClick={retryFailedTransfer}>重试</button>
            ) : null}
            <button type="button" className="bd-toast-close" aria-label="关闭错误提示" onClick={() => setError(null)}>
              <Icon name="x" />
            </button>
          </div>
        ) : null}
        {notice ? (
          <div className="bd-toast bd-toast--success" role="status" aria-live="polite">
            <Icon name="circle-check" />
            <span className="tr-toast-text">{notice}</span>
          </div>
        ) : null}
      </div>

      {isFileDragActive ? (
        <div className="tr-drop-overlay" aria-hidden="true">
          <div className="tr-drop-card">
            <span className="tr-drop-icon"><Icon name="upload" size={28} /></span>
            <strong>松开以添加文件</strong>
            <span>
              {linkMode
                ? "添加到待上传列表，确认后才生成链接"
                : selectedPeer
                  ? `准备发送给 ${selectedPeerLabel}，按发送前不会发出`
                  : "先放进待发送列表，再选择接收方"}
            </span>
          </div>
        </div>
      ) : null}

      <TransferInviteModal
        isOpen={inviteOpen}
        initialMode={inviteInitialMode}
        onClose={() => setInviteOpen(false)}
        sharedRoomActive={sharedRoomActive}
        roomId={roomId}
        currentRole={roomRole}
        inviteUrl={roomJoinUrl}
        qrUrl={sharedRoomActive ? pairingJoinUrl : roomJoinUrl}
        accessExpiresAt={createdRoomAccess?.access.role === "EDITOR"
          ? createdRoomAccess.access.expiresAt
          : null}
        pairingCode={pairingCode?.role === "EDITOR" ? pairingCode : null}
        isPreparing={roomAccessLoading || pairingCodeLoading}
        isPairingCodeLoading={pairingCodeLoading}
        error={inviteError}
        canUseSystemShare={canUseSystemShare()}
        onShare={() => void shareRoom("EDITOR")}
        onCopy={() => void copyRoomLink("EDITOR")}
        onRegenerate={() => void regenerateSecureInvite()}
        onRegeneratePairing={() => void regeneratePairingCode()}
        pairingCodeDraft={pairingCodeDraft}
        onPairingCodeDraftChange={setPairingCodeDraft}
        isRedeeming={pairingCodeRedeeming}
        onRedeem={() => void redeemPairingCode()}
        onCreateSharedRoom={enterSharedRoom}
      />
      <Modal
        isOpen={roomSettingsOpen}
        size="2xl"
        scrollBehavior="inside"
        classNames={{ base: "tr-dialog" }}
        onOpenChange={(open) => {
          setRoomSettingsOpen(open);
          if (!open) resetRoomSettingsDraft();
        }}
      >
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader className="tr-dialog-head">
                <span className="bd-dialog-title">设备设置</span>
                <Tag plain>{sharedRoomActive ? "共享房间" : "附近设备"}</Tag>
              </ModalHeader>
              <ModalBody className="tr-settings">
                <section className="tr-settings-group">
                  <h3 className="tr-settings-title">设备与房间</h3>
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
                </section>

                <section className="tr-settings-row">
                  <div className="min-w-0">
                    <h3 className="tr-settings-title">允许被发现</h3>
                    <p className="tr-note">
                      {discoverableDraft
                        ? "同一公网出口的设备可自动发现你，已加入同一空间的成员也可看到你。"
                        : "其它设备看不到你；你仍可以看到它们并主动发送。"}
                    </p>
                  </div>
                  <Switch
                    size="sm"
                    aria-label="切换允许被发现"
                    isSelected={discoverableDraft}
                    onValueChange={setDiscoverableDraft}
                  />
                </section>

                <section className="tr-settings-row">
                  <div className="min-w-0">
                    <h3 className="tr-settings-title">接收前确认</h3>
                    <p className="tr-note">
                      {receiveConfirmationDraft ? "收到文件后由你确认是否接收。" : "收到文件后立即开始接收。"}
                    </p>
                  </div>
                  <Switch
                    size="sm"
                    aria-label="切换接收前确认"
                    isSelected={receiveConfirmationDraft}
                    onValueChange={setReceiveConfirmationDraft}
                  />
                </section>

                <section className="tr-settings-row">
                  <div className="min-w-0">
                    <h3 className="tr-settings-title">房间</h3>
                    <p className="tr-note">
                      {sharedRoomActive
                        ? `共享房间 ${transferRoomDisplayName(roomId)}：只和加入的成员互传；退出后回到附近设备。`
                        : "附近设备：同一网络里打开本页的设备会自动出现。创建新房间会断开当前设备。"}
                    </p>
                  </div>
                  <div className="bd-row tr-settings-room-actions">
                    {sharedRoomActive ? (
                      <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm tr-danger-text" onClick={exitSharedRoom}>退出共享房间</button>
                    ) : null}
                    <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm tr-danger-text" onClick={createNewRoom}>创建新房间</button>
                  </div>
                </section>
              </ModalBody>
              <ModalFooter className="tr-dialog-foot">
                <span className="tr-dialog-foot-spacer" />
                <button type="button" className="bd-btn bd-btn--ghost" onClick={onClose}>取消</button>
                <button
                  type="button"
                  className={`bd-btn bd-btn--primary${clientNameSaving ? " is-busy" : ""}`}
                  disabled={Boolean(clientNameLocalError) || clientNameStatus === "checking" || clientNameStatus === "unavailable" || clientNameSaving}
                  onClick={() => void saveRoomSettings()}
                >
                  保存设置
                </button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>

      <Modal isOpen={helpOpen} size="2xl" scrollBehavior="inside" classNames={{ base: "tr-dialog" }} onOpenChange={setHelpOpen}>
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader className="tr-dialog-head"><span className="bd-dialog-title">互传帮助</span></ModalHeader>
              <ModalBody>
                <TransferFaq iceConfig={iceConfig} sharedRoom={sharedRoomActive} ossFallbackEnabled={ossFallbackEnabled} onClearResumeData={clearLocalTransferData} />
              </ModalBody>
              <ModalFooter className="tr-dialog-foot">
                <span className="tr-dialog-foot-spacer" />
                <button type="button" className="bd-btn bd-btn--primary" onClick={onClose}>知道了</button>
              </ModalFooter>
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
    || (status === "error" ? "暂时无法校验名称，稍后重试" : "");
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
        label={compact ? "设备名称" : "这台设备的名称"}
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
  currentRole,
  inviteRole,
  canManage,
  isLoading,
  onInviteRoleChange,
  onCreateInvite,
}: {
  compact?: boolean;
  context?: "transfer" | "diagram";
  currentRole: PublicTransferRoomRole;
  inviteRole: TransferInviteRole;
  canManage: boolean;
  isLoading: boolean;
  onInviteRoleChange: (role: TransferInviteRole) => void;
  onCreateInvite: () => void;
}) {
  const currentRoleLabel = currentRole === "OWNER" ? "房主" : currentRole === "EDITOR" ? "可编辑" : "只读";
  const displayedRole = canManage ? inviteRole : currentRole === "VIEWER" ? "VIEWER" : "EDITOR";
  const editorRoleDetail = context === "diagram" ? "编辑画布、评论和版本" : "发送文件、剪贴板和白板";
  const viewerRoleDetail = context === "diagram" ? "查看画布和协作更新" : "仅查看和接收房间内容";
  const description = canManage
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
              className={`h-7 rounded-sm px-2 text-tiny font-medium transition-colors ${displayedRole === role ? "bg-white text-zinc-950 shadow-xs dark:bg-white/10 dark:text-white" : "text-zinc-500 dark:text-zinc-400"} disabled:cursor-not-allowed`}
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
            className={`rounded-sm px-3 py-2 text-left transition-colors ${displayedRole === "EDITOR" ? "bg-white text-zinc-950 shadow-xs dark:bg-white/10 dark:text-white" : "text-zinc-500 dark:text-zinc-400"} disabled:cursor-not-allowed`}
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
            className={`rounded-sm px-3 py-2 text-left transition-colors ${displayedRole === "VIEWER" ? "bg-white text-zinc-950 shadow-xs dark:bg-white/10 dark:text-white" : "text-zinc-500 dark:text-zinc-400"} disabled:cursor-not-allowed`}
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
      <p className="mt-2 text-tiny text-zinc-500 dark:text-zinc-400">{description}</p>
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

type InboxEntry =
  | { kind: "file"; key: string; at: number; item: IncomingAttachment }
  | { kind: "text"; key: string; at: number; event: ClipboardInboundEvent };

interface SendBarModel {
  label: string;
  icon: IconName;
  disabled: boolean;
  /** Why the button is off, or what happens next; empty when the summary already says it. */
  reason: string;
  onSend: () => void;
  hint?: ReactNode;
}

const TRANSFER_TOOL_META: Record<TransferToolMode, { label: string; icon: IconName }> = {
  clipboard: { label: "文字与链接", icon: "message" },
  files: { label: "文件", icon: "folder" },
  whiteboard: { label: "多人白板", icon: "edit" },
};

const OUTGOING_STATUS_TONE: Record<OutgoingTransferStatus, { tone: Tone; plain?: boolean }> = {
  queued: { tone: "neutral", plain: true },
  connecting: { tone: "info" },
  sending: { tone: "info" },
  completed: { tone: "success" },
  failed: { tone: "danger" },
  cancelled: { tone: "warning" },
};

const INBOX_PAGE_SIZE = 6;

/** The current time, refreshed every `intervalMs` while `enabled`; for elapsed-time labels. */
function useNow(intervalMs: number, enabled = true) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return undefined;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [enabled, intervalMs]);
  return now;
}

function StepBadge({ step, done }: { step: number; done: boolean }) {
  return (
    <span className={`tr-step${done ? " is-done" : ""}`} aria-hidden="true">
      {done ? <Icon name="check" size={13} /> : step}
    </span>
  );
}

/** The content switch: the design's segmented control, with tab semantics because it swaps panels. */
function ModeTabs({
  active,
  fileCount,
  onSelect,
}: {
  active: TransferToolMode;
  fileCount: number;
  onSelect: (mode: TransferToolMode, focusContent?: boolean) => void;
}) {
  const focusTab = (mode: TransferToolMode) => {
    window.requestAnimationFrame(() => document.getElementById(`transfer-tab-${mode}`)?.focus());
  };
  return (
    <div className="bd-seg bd-seg--md tr-modes" role="tablist" aria-label="选择发送内容">
      {TRANSFER_TOOL_MODES.map((mode, index) => {
        const selected = mode === active;
        const meta = TRANSFER_TOOL_META[mode];
        return (
          <button
            key={mode}
            id={`transfer-tab-${mode}`}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={`transfer-panel-${mode}`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onSelect(mode, true)}
            onKeyDown={(event: ReactKeyboardEvent<HTMLButtonElement>) => {
              const count = TRANSFER_TOOL_MODES.length;
              const next = event.key === "ArrowRight" ? TRANSFER_TOOL_MODES[(index + 1) % count]
                : event.key === "ArrowLeft" ? TRANSFER_TOOL_MODES[(index - 1 + count) % count]
                  : event.key === "Home" ? TRANSFER_TOOL_MODES[0]
                    : event.key === "End" ? TRANSFER_TOOL_MODES[count - 1]
                      : null;
              if (next) {
                event.preventDefault();
                onSelect(next, false);
                focusTab(next);
              }
            }}
          >
            <Icon name={meta.icon} />
            <span className="tr-mode-label">{meta.label}</span>
            {mode === "files" && fileCount > 0 ? <span className="tr-mode-count bd-num">{fileCount}</span> : null}
          </button>
        );
      })}
    </div>
  );
}

/** Step 3: who receives it, and the one primary button that says what will happen. */
function SendBar({ model, summary }: { model: SendBarModel; summary: ReactNode }) {
  const reasonId = useId();
  return (
    <div className="tr-sendbar" data-testid="transfer-recipient-bar">
      <div className="tr-sendbar-target">{summary}</div>
      {model.reason ? <p id={reasonId} className="tr-sendbar-reason">{model.reason}</p> : null}
      <div className="tr-sendbar-action">
        {model.hint}
        <StepBadge step={3} done={false} />
        <button
          type="button"
          className="bd-btn bd-btn--primary tr-send-btn"
          disabled={model.disabled}
          aria-describedby={model.reason ? reasonId : undefined}
          onClick={model.onSend}
        >
          <Icon name={model.icon} />
          <span>{model.label}</span>
        </button>
      </div>
    </div>
  );
}

/** What the send in flight is waiting for: the receiver's consent, the connection, the upload. */
function ActiveSendDetail({
  state,
  store,
  transportPath,
}: {
  state: UploadState;
  store: TransferProgressStore;
  transportPath?: PeerTransportPath;
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
  const text = state === "waiting"
    ? `等待对方确认接收（已等待 ${formatElapsed(waitingSeconds)}）`
    : state === "direct" || state === "uploading" ? "" : stateLabel(state, progress);
  if (!text && !pathLabel) return null;
  return (
    <p className="tr-task-msg tr-task-detail">
      {text ? <span>{text}</span> : null}
      {pathLabel ? <Tag tone={transportPath === "turn" ? "neutral" : "success"}>{pathLabel}</Tag> : null}
    </p>
  );
}

/** The finished send's result: the file link and its expiry, or the local copy to share or save. */
function RecordResult({
  record,
  onShare,
  onDownload,
  onPreview,
}: {
  record: UploadRecord;
  onShare: () => void;
  onDownload: () => void;
  onPreview: () => void;
}) {
  return (
    <div className="tr-task-result">
      <p className="tr-task-msg">
        {record.direct
          ? "当前会话可直接保存这个文件。"
          : <>文件有效期：{record.attachment.expiresAt ? formatDateTime(record.attachment.expiresAt) : "服务端未提供"}；与房间邀请有效期分别计算。持有链接与访问口令的登录用户可下载。</>}
      </p>
      <div className="bd-row">
        <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" aria-label={`预览 ${record.attachment.fileName}`} onClick={onPreview}>
          <Icon name="eye" /><span>预览</span>
        </button>
        <button type="button" className="bd-btn bd-btn--secondary bd-btn--sm" onClick={onShare}>
          <Icon name="share" /><span>{record.direct ? "系统分享文件" : "分享文件链接"}</span>
        </button>
        <button type="button" className="bd-btn bd-btn--secondary bd-btn--sm" onClick={onDownload}>
          <Icon name="download" /><span>下载到设备</span>
        </button>
      </div>
    </div>
  );
}

function OutgoingTaskRow({
  activity,
  detail,
  result,
  onCancel,
  onRetry,
}: {
  activity: OutgoingTransferActivity;
  detail: ReactNode;
  result: ReactNode;
  onCancel: () => void;
  onRetry: () => void;
}) {
  const active = activity.status === "queued" || activity.status === "connecting" || activity.status === "sending";
  const running = activity.status === "connecting" || activity.status === "sending";
  const retryable = activity.status === "failed" || activity.status === "cancelled";
  const now = useNow(1000, active);
  const elapsedSeconds = Math.max(0, ((activity.completedAt ?? now) - activity.createdAt) / 1000);
  const status = OUTGOING_STATUS_TONE[activity.status];
  const linkTask = !activity.targetPeerId;
  const showError = activity.error && (activity.status === "failed" || activity.error !== "已取消");
  return (
    <article className={`tr-task is-${activity.status}${running ? " is-running" : ""}`}>
      <span className="tr-task-thumb" aria-hidden="true">
        <Icon name={fileKindIcon(activity.fileName, activity.file.type)} size={18} />
      </span>
      <div className="tr-task-main">
        <div className="tr-task-head">
          <span className={`tr-task-kind ${linkTask ? "is-link" : "is-send"}`}>{linkTask ? "链接" : "发送"}</span>
          <span className="tr-task-title" title={activity.fileName}>{activity.fileName}</span>
        </div>
        {running || (activity.progress > 0 && activity.status !== "completed") ? (
          <Progress value={activity.progress} label={`${activity.fileName} 传输进度`} />
        ) : null}
        {showError ? <p className="tr-task-msg tr-text-danger">{activity.error}</p> : null}
        {detail}
        {result}
        <div className="tr-task-meta">
          <Tag tone={status.tone} plain={status.plain}>{transferActivityStatusLabel(activity.status, activity.transport)}</Tag>
          <span>{linkTask ? "生成文件链接" : `发给 ${activity.targetPeerLabel}`}</span>
          <span className="bd-num">
            {active && activity.transferredBytes > 0 ? `${formatBytes(activity.transferredBytes)} / ` : ""}{formatBytes(activity.sizeBytes)}
          </span>
          {running && activity.speedBytesPerSecond > 0 ? <span className="bd-num">{formatBytes(activity.speedBytesPerSecond)}/s</span> : null}
          {running && activity.etaSeconds !== null && activity.etaSeconds > 0 ? <span className="bd-num">剩余约 {formatElapsed(activity.etaSeconds)}</span> : null}
          {activity.transport ? <span>{transferTransportLabel(activity.transport)}</span> : null}
          <span className="bd-num">{activity.status === "queued" ? "已等" : active ? "已用" : "用时"} {formatElapsed(elapsedSeconds)}</span>
          {!active && activity.completedAt ? <span>结束 <RelativeTime value={activity.completedAt} /></span> : null}
        </div>
      </div>
      {active || retryable ? (
        <div className="tr-task-actions">
          {active ? <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={onCancel}>取消</button> : null}
          {retryable ? (
            <button type="button" className="bd-btn bd-btn--secondary bd-btn--sm" onClick={onRetry}>
              <Icon name="refresh" /><span>重试</span>
            </button>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}

function ReceivingTaskRow({
  item,
  sourceLabel,
  pathLabel,
  onCancel,
}: {
  item: DirectReceivingTransfer;
  sourceLabel: string;
  pathLabel: string | null;
  onCancel: () => void;
}) {
  const [startedAt] = useState(() => Date.now());
  const sampleRef = useRef({ at: startedAt, bytes: item.receivedBytes });
  const [speed, setSpeed] = useState(0);
  const now = useNow(1000);
  useEffect(() => {
    const at = Date.now();
    const previous = sampleRef.current;
    if (at - previous.at < 500 || item.receivedBytes < previous.bytes) return;
    const sample = (item.receivedBytes - previous.bytes) * 1000 / (at - previous.at);
    setSpeed((current) => current > 0 ? current * 0.65 + sample * 0.35 : sample);
    sampleRef.current = { at, bytes: item.receivedBytes };
  }, [item.receivedBytes]);
  const percent = transferProgress(item.receivedBytes, item.sizeBytes);
  const remaining = speed > 0 ? Math.ceil(Math.max(0, item.sizeBytes - item.receivedBytes) / speed) : null;
  return (
    <article className="tr-task is-running">
      <span className="tr-task-thumb" aria-hidden="true"><Icon name={fileKindIcon(item.fileName, item.mimeType)} size={18} /></span>
      <div className="tr-task-main">
        <div className="tr-task-head">
          <span className="tr-task-kind is-receive">接收</span>
          <span className="tr-task-title" title={item.fileName}>{item.fileName}</span>
        </div>
        <Progress value={percent} label={`${item.fileName} 接收进度`} />
        <div className="tr-task-meta">
          <Tag tone="info">正在接收</Tag>
          <span>来自 {sourceLabel}</span>
          <span className="bd-num">{formatBytes(item.receivedBytes)} / {formatBytes(item.sizeBytes)}</span>
          {speed > 0 ? <span className="bd-num">{formatBytes(speed)}/s</span> : null}
          {remaining ? <span className="bd-num">剩余约 {formatElapsed(remaining)}</span> : null}
          {pathLabel ? <span>{pathLabel}</span> : null}
          {item.storage === "persistent" ? <span>写入本机，可续传</span> : item.storage === "memory" ? <span>仅内存</span> : null}
          <span className="bd-num">已用 {formatElapsed((now - startedAt) / 1000)}</span>
        </div>
      </div>
      <div className="tr-task-actions">
        <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={onCancel}>取消</button>
      </div>
    </article>
  );
}

/** Everything that arrived: requests to accept first, then files and texts, newest first. */
function TransferInbox({
  pending,
  entries,
  peerLabel,
  cloudTransferEnabled,
  onAccept,
  onReject,
  onShare,
  onDownload,
  onLogin,
  onPreview,
  onCopyText,
}: {
  pending: DirectPendingTransfer[];
  entries: InboxEntry[];
  peerLabel: (sourcePeerId: string) => string;
  cloudTransferEnabled: boolean;
  onAccept: (item: DirectPendingTransfer) => void;
  onReject: (item: DirectPendingTransfer) => void;
  onShare: (item: IncomingAttachment) => Promise<void>;
  onDownload: (item: IncomingAttachment) => Promise<void>;
  onLogin: () => void;
  onPreview: (target: PreviewTarget) => void;
  onCopyText: (text: string) => void;
}) {
  const [limit, setLimit] = useState(INBOX_PAGE_SIZE);
  const visible = entries.slice(0, limit);
  const hiddenCount = entries.length - visible.length;
  const total = pending.length + entries.length;
  return (
    <section className="bd-card tr-card tr-inbox" aria-labelledby="tr-inbox-title">
      <div className="tr-card-head">
        <span className="tr-card-icon" aria-hidden="true"><Icon name="download" /></span>
        <h2 id="tr-inbox-title" className="tr-card-title">收到的内容</h2>
        <span className="tr-count-badge bd-num"><span className="jd-sr-only">共 </span>{total}<span className="jd-sr-only"> 项</span></span>
      </div>
      <div className="tr-card-body tr-inbox-body">
        {pending.map((item) => (
          <article key={`pending:${receivingTransferKey(item)}`} className="tr-inbox-item is-pending">
            <span className="tr-inbox-thumb" aria-hidden="true"><Icon name={fileKindIcon(item.fileName, item.mimeType)} size={18} /></span>
            <div className="tr-inbox-main">
              <div className="tr-inbox-name" title={item.fileName}>{item.fileName}</div>
              <div className="tr-inbox-meta">
                <Tag tone="warning">等待你确认</Tag>
                <span>来自 <span title={item.sourcePeerId}>{peerLabel(item.sourcePeerId)}</span></span>
                <span className="bd-num">{formatBytes(item.sizeBytes)}</span>
              </div>
              {item.storage === "persistent" ? (
                <p className="tr-note">
                  接收后已校验的分块会写入本机浏览器存储，中断或刷新后 24 小时内可续传，可随时放弃并删除；浏览器可能自行清除这些数据。同一站点的页面可以读取它们，共用电脑建议拒绝。
                </p>
              ) : item.storage === "memory" ? (
                <p className="tr-note">
                  只在内存中接收{item.memoryReason ? `（${memoryReasonText(item.memoryReason)}）` : ""}：网络短暂中断可以续传，刷新或关闭页面后无法恢复。
                </p>
              ) : null}
            </div>
            <div className="tr-inbox-actions">
              <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={() => onReject(item)}>拒绝</button>
              <button type="button" className="bd-btn bd-btn--primary bd-btn--sm" onClick={() => onAccept(item)}>
                <Icon name="download" /><span>接收</span>
              </button>
            </div>
          </article>
        ))}
        {visible.length > 0 ? (
          <ul className="tr-inbox-list" aria-label="收到的文件和文字">
            {visible.map((entry) => entry.kind === "file" ? (
              <InboxFileRow
                key={entry.key}
                item={entry.item}
                sourceLabel={peerLabel(entry.item.sourcePeerId)}
                cloudTransferEnabled={cloudTransferEnabled}
                onShare={onShare}
                onDownload={onDownload}
                onLogin={onLogin}
                onPreview={onPreview}
              />
            ) : (
              <InboxTextRow key={entry.key} event={entry.event} onCopyText={onCopyText} onPreview={onPreview} />
            ))}
          </ul>
        ) : null}
        {hiddenCount > 0 ? (
          <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm tr-inbox-more" onClick={() => setLimit((value) => value + INBOX_PAGE_SIZE)}>
            再显示 {Math.min(hiddenCount, INBOX_PAGE_SIZE)} 条
          </button>
        ) : null}
      </div>
    </section>
  );
}

function InboxFileRow({
  item,
  sourceLabel,
  cloudTransferEnabled,
  onShare,
  onDownload,
  onLogin,
  onPreview,
}: {
  item: IncomingAttachment;
  sourceLabel: string;
  cloudTransferEnabled: boolean;
  onShare: (item: IncomingAttachment) => Promise<void>;
  onDownload: (item: IncomingAttachment) => Promise<void>;
  onLogin: () => void;
  onPreview: (target: PreviewTarget) => void;
}) {
  const { fileName, mimeType, sizeBytes } = item.attachment;
  const kind = mediaKind(fileName, mimeType);
  const [thumbFailed, setThumbFailed] = useState(false);
  const thumbUrl = kind === "image" && item.previewUrl && sizeBytes <= AUTO_PREVIEW_LIMIT_BYTES && !thumbFailed ? item.previewUrl : null;
  const previewable = Boolean(item.previewUrl || item.blob);
  const cloudLoginRequired = !item.direct && !cloudTransferEnabled;
  const saved = item.downloadProgress === 100 && !item.downloading;
  const shareLabel = item.direct ? "系统分享文件" : "分享文件链接";
  return (
    <li className="tr-inbox-item">
      <span className={`tr-inbox-thumb${thumbUrl ? " has-image" : ""}`} aria-hidden="true">
        {thumbUrl
          ? <img src={thumbUrl} alt="" onError={() => setThumbFailed(true)} />
          : <Icon name={fileKindIcon(fileName, mimeType)} size={18} />}
      </span>
      <div className="tr-inbox-main">
        <div className="tr-inbox-name" title={fileName}>{fileName}</div>
        <div className="tr-inbox-meta">
          <span className="bd-num">{formatBytes(sizeBytes)}</span>
          <span>来自 <span title={item.sourcePeerId}>{sourceLabel}</span></span>
          {item.receivedAt ? <RelativeTime value={item.receivedAt} /> : null}
          <span>{item.direct ? "设备互传" : "文件链接"}</span>
          {saved ? <Tag tone="success">已保存</Tag> : null}
        </div>
        {item.downloading ? <Progress value={item.downloadProgress ?? 0} label={`${fileName} 下载进度`} /> : null}
        {item.downloadError ? <p className="tr-task-msg tr-text-danger">{item.downloadError}</p> : null}
      </div>
      <div className="tr-inbox-actions">
        {previewable ? (
          <button
            type="button"
            className="bd-icon-btn"
            aria-label={`预览 ${fileName}`}
            title="预览"
            onClick={() => onPreview({ fileName, mimeType, url: item.previewUrl, blob: item.blob, sizeBytes })}
          >
            <Icon name="eye" />
          </button>
        ) : null}
        <button
          type="button"
          className="bd-icon-btn"
          aria-label={shareLabel}
          title={cloudLoginRequired ? "登录后才可分享云端文件" : shareLabel}
          disabled={cloudLoginRequired}
          onClick={() => void onShare(item)}
        >
          <Icon name="share" />
        </button>
        <button
          type="button"
          className={`bd-btn bd-btn--sm ${saved ? "bd-btn--secondary" : "bd-btn--primary"}${item.downloading ? " is-busy" : ""}`}
          aria-busy={item.downloading || undefined}
          onClick={() => (cloudLoginRequired ? onLogin() : void onDownload(item))}
        >
          <Icon name="download" />
          <span>{item.direct ? "保存到设备" : cloudLoginRequired ? "登录下载" : "下载到设备"}</span>
        </button>
      </div>
    </li>
  );
}

function InboxTextRow({
  event,
  onCopyText,
  onPreview,
}: {
  event: ClipboardInboundEvent;
  onCopyText: (text: string) => void;
  onPreview: (target: PreviewTarget) => void;
}) {
  const text = event.payload.text;
  const source = event.sourceDisplayName || "未命名设备";
  const firstLine = text.trim().split(/\r?\n/, 1)[0] || "空白文字";
  const isLink = event.payload.kind === "link";
  return (
    <li className="tr-inbox-item">
      <span className="tr-inbox-thumb is-text" aria-hidden="true"><Icon name={isLink ? "link" : "message"} size={18} /></span>
      <div className="tr-inbox-main">
        <div className="tr-inbox-name" title={text.slice(0, 400)}>{firstLine}</div>
        <div className="tr-inbox-meta">
          <span>{isLink ? "链接" : event.payload.kind === "html" ? "富文本" : "文字"}</span>
          <span className="bd-num">{Array.from(text).length} 字</span>
          <span>来自 {source}</span>
          <RelativeTime value={event.receivedAt} />
        </div>
      </div>
      <div className="tr-inbox-actions">
        <button
          type="button"
          className="bd-icon-btn"
          aria-label={`预览来自 ${source} 的文字`}
          title="预览"
          onClick={() => onPreview({
            fileName: `来自 ${source} 的文字.txt`,
            mimeType: "text/plain",
            blob: new Blob([text], { type: "text/plain" }),
            sizeBytes: new Blob([text]).size,
          })}
        >
          <Icon name="eye" />
        </button>
        <button type="button" className="bd-btn bd-btn--primary bd-btn--sm" onClick={() => onCopyText(text)}>
          <Icon name="copy" /><span>复制</span>
        </button>
      </div>
    </li>
  );
}

function TransferInviteModal({
  isOpen,
  initialMode,
  onClose,
  sharedRoomActive,
  roomId,
  currentRole,
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
  onCreateSharedRoom,
}: {
  isOpen: boolean;
  initialMode: "invite" | "join";
  onClose: () => void;
  sharedRoomActive: boolean;
  roomId: string;
  currentRole: PublicTransferRoomRole | null;
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
  onCreateSharedRoom: () => void;
}) {
  const canInvite = !sharedRoomActive || currentRole === "OWNER";
  const rolePending = sharedRoomActive && currentRole === null;
  const formattedPairingCode = pairingCode ? formatPairingCode(pairingCode.code) : "";
  const [mode, setMode] = useState<"invite" | "join">(initialMode);
  const inviteExpiry = accessExpiresAt ? formatInviteExpiry(accessExpiresAt) : null;
  const pairingExpiry = pairingCode ? formatInviteExpiry(pairingCode.expiresAt) : null;
  const codeReady = Boolean(normalizeTransferPairingCode(pairingCodeDraft));
  useEffect(() => {
    if (isOpen) setMode(initialMode);
  }, [initialMode, isOpen]);

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      size="2xl"
      scrollBehavior="inside"
      placement="center"
      classNames={{ base: "tr-dialog", closeButton: "tr-dialog-close" }}
    >
      <ModalContent>
        <ModalHeader className="tr-dialog-head tr-dialog-head--stack">
          <span className="tr-dialog-title-row">
            <span className="bd-dialog-title">添加设备</span>
            <Tag tone={sharedRoomActive ? "info" : "success"}>{sharedRoomActive ? "已建立协作空间" : "设备互传"}</Tag>
          </span>
          <span className="tr-dialog-desc">
            {sharedRoomActive
              ? `协作空间 ${transferRoomDisplayName(roomId)} · 仅主动加入的成员共享白板`
              : "让对方也打开互传页面；同一网络会自动出现。不在同一网络时，用邀请或配对码连接。"}
          </span>
        </ModalHeader>
        <ModalBody className="tr-invite">
          <div className="bd-seg bd-seg--md tr-invite-modes" role="tablist" aria-label="添加设备方式">
            <button type="button" role="tab" aria-selected={mode === "invite"} onClick={() => setMode("invite")}>
              <Icon name="share" />邀请对方
            </button>
            <button type="button" role="tab" aria-selected={mode === "join"} onClick={() => setMode("join")}>
              <Icon name="key" />输入配对码
            </button>
          </div>

          <div hidden={mode !== "invite"}>
            {!sharedRoomActive ? (
              <div className="tr-invite-start">
                <span className="tr-invite-start-icon" aria-hidden="true"><Icon name="globe" size={22} /></span>
                <div className="min-w-0">
                  <p className="tr-invite-start-title">邀请不在同一网络的设备</p>
                  <p className="tr-note">生成一个限时邀请（二维码、链接和 8 位配对码），不同网络的设备也能加入。现有传输或草稿受影响时会先询问你。</p>
                </div>
                <button type="button" className="bd-btn bd-btn--primary" onClick={onCreateSharedRoom}>
                  <Icon name="key" /><span>生成邀请</span>
                </button>
              </div>
            ) : canInvite ? (
              <div className="tr-invite-grid">
                <div className="tr-invite-qr">
                  {qrUrl ? (
                    <>
                      <RoomQrCode value={qrUrl} large />
                      <span className="tr-invite-qr-title">扫码立即配对</span>
                      <span className="tr-note">二维码 5 分钟内单次有效，扫码后自动加入。</span>
                    </>
                  ) : (
                    <div className="tr-invite-qr-wait" role="status">
                      <span className="nearby-radar" aria-hidden="true"><Icon name="key" size={18} /></span>
                      <span className="tr-invite-qr-title">{isPreparing ? "正在建立安全邀请" : "等待生成二维码"}</span>
                      <span className="tr-note">生成失败时，用“更新邀请链接”重试。</span>
                    </div>
                  )}
                </div>

                <div className="tr-invite-side">
                  <div className="tr-invite-code">
                    <span className="tr-invite-code-label">口头告诉对方</span>
                    <span className="tr-pairing-code bd-num">{formattedPairingCode || "•••• ••••"}</span>
                    <span className="tr-note bd-num">
                      {pairingExpiry ? `${pairingExpiry} · 单次有效` : "正在生成 5 分钟配对码"}
                      {inviteExpiry ? ` · 链接${inviteExpiry}` : ""}
                    </span>
                    <button
                      type="button"
                      className={`bd-btn bd-btn--ghost bd-btn--sm${isPairingCodeLoading ? " is-busy" : ""}`}
                      onClick={onRegeneratePairing}
                    >
                      <Icon name="refresh" /><span>换一个</span>
                    </button>
                  </div>
                  <button
                    type="button"
                    className={`bd-btn bd-btn--primary tr-invite-primary${isPreparing && !inviteUrl ? " is-busy" : ""}`}
                    disabled={!inviteUrl}
                    onClick={onShare}
                  >
                    <Icon name={systemShareAvailable ? "share" : "copy"} />
                    <span>{systemShareAvailable ? "发送邀请" : "复制邀请链接"}</span>
                  </button>
                  <div className="bd-row">
                    {systemShareAvailable ? (
                      <button type="button" className="bd-btn bd-btn--secondary bd-btn--sm" disabled={!inviteUrl} onClick={onCopy}>复制邀请链接</button>
                    ) : null}
                    <button type="button" className={`bd-btn bd-btn--ghost bd-btn--sm${isPreparing ? " is-busy" : ""}`} onClick={onRegenerate}>
                      <Icon name="refresh" /><span>更新邀请链接</span>
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <Alert tone="warning">
                {rolePending ? "正在确认协作权限，确认后即可生成邀请。" : "只有协作空间管理员可以生成邀请：让管理员添加设备。"}
              </Alert>
            )}
          </div>

          <div hidden={mode !== "join"} className="tr-invite-join">
            <Input
              className="min-w-0 flex-1"
              label="对方的配对码"
              description="输入对方告诉你的 8 位数字，不需要复制长链接。"
              placeholder="1234 5678"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={12}
              radius="md"
              variant="bordered"
              value={pairingCodeDraft}
              onValueChange={(value) => onPairingCodeDraftChange(value.replace(/[^0-9 -]/g, "").slice(0, 12))}
              onKeyDown={(event) => {
                if (event.key === "Enter" && codeReady) onRedeem();
              }}
            />
            <button
              type="button"
              className={`bd-btn bd-btn--primary tr-invite-join-btn${isRedeeming ? " is-busy" : ""}`}
              disabled={!codeReady}
              onClick={onRedeem}
            >
              <Icon name="arrow-right" /><span>连接对方</span>
            </button>
          </div>

          {error ? <Alert tone="danger" role="alert">{error}</Alert> : null}
        </ModalBody>
      </ModalContent>
    </Modal>
  );
}

function PreviewModal({ target, onClose }: { target: PreviewTarget | null; onClose: () => void }) {
  const mimeType = target ? effectiveMimeType(target.fileName, target.mimeType) : "";

  return (
    <Modal isOpen={Boolean(target)} onClose={onClose} size="5xl" scrollBehavior="inside" classNames={{ base: "tr-dialog" }}>
      <ModalContent className="max-w-[min(96vw,1480px)]">
        {target && (
          <>
            <ModalHeader className="tr-dialog-head tr-preview-head">
              <span className="bd-dialog-title jd-ellipsis">{target.fileName}</span>
              <Tag plain>{fileKindLabel(target.fileName, target.mimeType)}</Tag>
              <span className="tr-preview-mime">{mimeType}</span>
            </ModalHeader>
            <ModalBody className="tr-preview-body">
              <FilePreview
                fileName={target.fileName}
                mimeType={target.mimeType}
                url={target.url}
                blob={target.blob}
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

  return (
    <div className="tr-preview-frame">
      <div className="tr-preview-toolbar" role="toolbar" aria-label="图片预览工具栏">
        <button type="button" className="bd-icon-btn" aria-label="缩小" title="缩小" onClick={() => zoomBy(1 / 1.25)}>
          <Icon name="zoom-out" />
        </button>
        <span className="tr-preview-zoom bd-num">{Math.round(scale * 100)}%</span>
        <button type="button" className="bd-icon-btn" aria-label="放大" title="放大" onClick={() => zoomBy(1.25)}>
          <Icon name="zoom-in" />
        </button>
        <button type="button" className="bd-icon-btn tr-preview-reset bd-num" aria-label="原始大小" title="原始大小" onClick={() => { setScale(1); setRotation(0); }}>
          1:1
        </button>
        <button type="button" className="bd-icon-btn" aria-label="顺时针旋转 90°" title="顺时针旋转 90°" onClick={rotateCW}>
          <Icon name="rotate-cw" />
        </button>
        <a className="bd-icon-btn" href={url} download={fileName} aria-label={`下载 ${fileName}`} title="下载">
          <Icon name="download" />
        </a>
      </div>
      <div ref={scrollRef} className="tr-preview-scroll">
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
            className="tr-preview-image"
          />
        </div>
      </div>
    </div>
  );
}

/** The preview dialog's body: image, video, audio, PDF or text, with a plain card for the rest. */
function FilePreview({
  fileName,
  mimeType,
  url,
  blob,
}: {
  fileName: string;
  mimeType?: string | null;
  url?: string | null;
  blob?: Blob | null;
}) {
  const kind = mediaKind(fileName, mimeType);
  const [previewFailed, setPreviewFailed] = useState(false);
  useEffect(() => {
    setPreviewFailed(false);
  }, [fileName, mimeType, url, blob]);
  const fallback = (note: string) => (
    <div className="tr-preview-fallback">
      <span className="bd-empty-icon" aria-hidden="true"><Icon name={fileKindIcon(fileName, mimeType)} size={24} /></span>
      <span className="tr-preview-fallback-name">{fileName}</span>
      <span className="tr-note">{note}</span>
    </div>
  );

  if (url && kind === "image" && !previewFailed) {
    return <ExpandedImagePreview url={url} fileName={fileName} onError={() => setPreviewFailed(true)} />;
  }
  if (url && kind === "video" && !previewFailed) {
    return (
      <div className="tr-preview-frame tr-preview-frame--dark">
        <video src={url} controls preload="metadata" className="tr-preview-media" onError={() => setPreviewFailed(true)} />
      </div>
    );
  }
  if (url && kind === "audio" && !previewFailed) {
    return (
      <div className="tr-preview-fallback">
        <span className="bd-empty-icon" aria-hidden="true"><Icon name="headphones" size={24} /></span>
        <span className="tr-preview-fallback-name">{fileName}</span>
        <audio src={url} controls preload="metadata" className="w-full" onError={() => setPreviewFailed(true)} />
      </div>
    );
  }
  if (url && kind === "pdf" && !previewFailed) {
    return (
      <div className="tr-preview-frame tr-preview-frame--paper">
        <object data={url} type="application/pdf" className="tr-preview-document" onError={() => setPreviewFailed(true)}>
          {fallback("这个浏览器不能内嵌 PDF，保存后用系统应用打开")}
        </object>
      </div>
    );
  }
  if (kind === "text" && blob) {
    return <TextFilePreview fileName={fileName} mimeType={mimeType} blob={blob} />;
  }
  return fallback(previewFailed ? "这个文件不能在浏览器里预览，保存后用系统应用打开" : effectiveMimeType(fileName, mimeType));
}

function TextFilePreview({
  fileName,
  mimeType,
  blob,
}: {
  fileName: string;
  mimeType?: string | null;
  blob: Blob;
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
    <div className="tr-text-preview">
      <div className="tr-text-preview-head">
        <span className="jd-ellipsis">{fileName}</span>
        <span className="tr-text-preview-type">{shortMimeLabel(effectiveMimeType(fileName, mimeType))}</span>
      </div>
      <pre>{error || text || "正在读取预览…"}</pre>
    </div>
  );
}

function TransferFaq({
  iceConfig,
  sharedRoom,
  ossFallbackEnabled,
  onClearResumeData,
}: {
  iceConfig: PublicTransferIceConfig | null;
  sharedRoom: boolean;
  ossFallbackEnabled: boolean;
  onClearResumeData?: () => void;
}) {
  const resumable = directResumeSupported();
  const routeLabel = iceConfig?.turnAuthRequired ? "中继授权会在连接时自动申请" : "传输方式以实际连接结果为准";

  return (
    <section className="tr-faq" aria-label="常见问题">
      <ol className="tr-faq-steps">
        <li><StepBadge step={1} done={false} /><span><b>选择接收方</b>：同一网络里打开本页的设备会自动出现，点它的头像。</span></li>
        <li><StepBadge step={2} done={false} /><span><b>选择内容</b>：文字与链接、文件，或多人白板。文件可以拖到页面任意位置，也可以粘贴。</span></li>
        <li><StepBadge step={3} done={false} /><span><b>发送</b>：按下面的发送按钮。粘贴和拖入都只放进草稿，不会自己发出。</span></li>
      </ol>
      <div className="tr-faq-list">
        <FaqItem title="怎么把手机加进来？">
          点“添加设备”，选择“邀请对方”生成二维码和链接，或选择“输入配对码”连接对方。手机和电脑可以使用不同网络。
        </FaqItem>
        <FaqItem title="找不到对方怎么办？">
          {sharedRoom
            ? "先发送邀请链接，或让对方输入邀请弹窗里的 8 位配对码。"
            : "让对方也打开互传页面。自动发现依据公网出口地址，并不保证在同一局域网；没有出现时用邀请或配对码。"}
        </FaqItem>
        <FaqItem title="没有选对方也能发送吗？">
          {ossFallbackEnabled
            ? "在“文件”里选“改为生成文件链接”，上传后可分享临时链接；发送到设备时必须先选择接收方。"
            : "不可以。未登录时不会上传云端，需要先选择一台在线设备。"}
        </FaqItem>
        <FaqItem title="文件会怎么传？">
          {`添加文件后按发送，先查看发送前确认。设备文件优先直连，连接不通时尝试 TURN 中继，中继不会生成云端副本。${resumable ? "单文件最多 2 GiB：128 MiB 以内可以直接收进内存；更大的文件需要接收方同意，写入其浏览器本地存储。对方页面是旧版本时上限仍为 128 MiB。" : "当前页面不是安全连接（HTTPS），无法分块续传，单文件内存上限为 128 MiB。"}${ossFallbackEnabled ? "只有在发送前明确允许云端回退时，远程设备连接失败才会改用临时存储；接收方需要登录下载。" : "未登录时不会上传云端。"}`}
        </FaqItem>
        <FaqItem title="为什么有时需要手动写入系统剪贴板？">
          浏览器可能阻止网页改写系统剪贴板。收到的文字仍在页面里，用“复制”或“复制到剪贴板”重试。本页不会持续读取你在其他应用中复制的内容。
        </FaqItem>
        <FaqItem title="谁能看到我发的文件？">
          通过直连或中继转发的文件只到选中的设备，不创建云端副本。生成文件链接需要登录并启用临时存储，下载方也需要登录并持有访问口令与文件链接。
        </FaqItem>
        <FaqItem title="云端额度是多少？">
          存储额度、下载额度、单文件上限和文件保存时长由服务端配置。选择云端方式后，发送前确认会读取当前账号的额度快照；旧服务端不支持或查询失败时会明确提示未核验。查询不预占额度，实际上传仍可能失败；申请上传可能预占存储额度。下载授权首次打开并成功跳转时，按文件完整大小计入下载额度。临时下载地址只能使用一次，重新下载需重新申请；这不代表文件分享链接只能用一次。文件有效期以生成结果为准。
        </FaqItem>
        <FaqItem title="中断或关闭页面后能继续传吗？">
          <p>
            部分可以。设备传输按 1 MiB 分块逐块校验：网络中断或在直连与中继之间切换时，只要两端页面都开着，发送方会自动重连并从缺失的块继续，最多重试 5 次。
          </p>
          <p>
            接收方同意写入本机存储的文件，刷新或重新打开页面后可以续传，有效期 24 小时，从同意时起算，续传不会延长。发送方刷新后浏览器不允许网页自动重新读取文件，需要在“未完成的发送”里重新选择同一文件；文件内容变了只能作为新传输重新发送，并需要对方重新同意。
          </p>
          <p>
            自动接收或只在内存中接收的文件不写入本机存储，任一端刷新后都要从头开始；文件草稿也不会保留。已收数据只保存在本机浏览器，浏览器可能自行清除；页面关闭期间不会运行任何清理，过期数据要到下次打开本站页面时才删除。接收完成也不等于已保存到设备：用“保存到设备”，再检查浏览器下载记录。网页会尝试提醒离开，但浏览器或手机系统可能不显示提醒。
          </p>
          {onClearResumeData ? (
            <button type="button" className="bd-btn bd-btn--secondary bd-btn--sm" onClick={onClearResumeData}>
              <Icon name="trash" /><span>清除互传本地数据</span>
            </button>
          ) : null}
        </FaqItem>
        <FaqItem title="更多说明">
          {sharedRoom
            ? `共享房间通过口令隔离，文件地址短期有效。当前状态：${routeLabel}。`
            : "自动发现只用于选择设备，不代表加入白板协作。文字和白板可能经直连、TURN 或 WebSocket 中继；白板仅发送给明确加入协作空间的成员。"}
        </FaqItem>
      </div>
    </section>
  );
}

function FaqItem({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details className="tr-faq-item">
      <summary>
        <span>{title}</span>
        <Icon name="chevron-down" />
      </summary>
      <div className="tr-faq-body">
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
      <div className={`tr-qr tr-qr--error${large ? " tr-qr--large" : ""}`}>
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

  // Scanners need dark modules on a light ground in both themes, so the code keeps fixed colors.
  return (
    <svg
      className={`tr-qr${large ? " tr-qr--large" : ""}`}
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
    xhr.onerror = () => finish(() => reject(new Error("文件发送失败：检查网络后重试")));
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
  return path === "turn" ? "中继传输" : path === "direct" ? "设备直连" : null;
}

function discoveryStatusLabel(status: DiscoveryStatus) {
  if (status === "online") return "已上线";
  if (status === "reconnecting") return "正在重连";
  if (status === "offline") return "已离线";
  if (status === "name-conflict") return "名称冲突";
  if (status === "permission-denied") return "无权加入";
  return "正在连接";
}

function discoveryStatusDescription(status: DiscoveryStatus) {
  if (status === "reconnecting") return "房间连接暂时中断，正在自动恢复。";
  if (status === "offline") return "房间连接已中断：检查网络后重试连接。";
  if (status === "name-conflict") return "当前设备名称已被占用：在设置中更换名称。";
  if (status === "permission-denied") return "无法加入这个房间：检查邀请链接和房间口令。";
  return "正在建立房间连接。";
}

function transferActivityStatusLabel(status: OutgoingTransferStatus, transport?: OutgoingTransferActivity["transport"]) {
  if (status === "queued") return "等待发送";
  if (status === "connecting") return "正在连接";
  if (status === "sending") return "正在发送";
  if (status === "completed") return transferCompletionLabel(transport === "cloud");
  if (status === "failed") return "失败";
  return "已取消";
}

function transferTransportLabel(transport: NonNullable<OutgoingTransferActivity["transport"]>) {
  if (transport === "peer") return "设备直连";
  if (transport === "relay") return "中继传输";
  return "文件临时存储";
}

/** Same name, size and timestamp: picking a file twice adds it once. */
function stagedFileKey(file: File) {
  return `${file.name}\u0000${file.size}\u0000${file.type}\u0000${file.lastModified}`;
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
      return "正在确认上传结果";
    case "done":
      return "本次传输处理完成";
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

/**
 * 是否允许被同一网络的其它设备发现。默认允许——内网互传的价值就在于打开即可见；
 * 关闭后本机不出现在他人列表中，但仍能看到他人并主动发送（对齐 AirDrop 的“停止接收”）。
 * 存 localStorage 而非 sessionStorage：这是隐私选择，应跨标签页与重启保持。
 */
function loadDiscoverable() {
  try {
    return localStorage.getItem("public-transfer-discoverable") !== "false";
  } catch {
    return true;
  }
}

function saveDiscoverable(value: boolean) {
  try {
    localStorage.setItem("public-transfer-discoverable", String(value));
  } catch {
    // 隐私偏好非关键项，存储不可用时保持本次会话内有效即可。
  }
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

function normalizeSelfPublicAddress(value: string | undefined) {
  const trimmed = value?.trim() ?? "";
  // 服务端无法识别出口地址时上报 "unknown"/空，一律视为未知（不按同网处理）
  return trimmed && trimmed.toLowerCase() !== "unknown" ? trimmed : "";
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
    roomId,
    token: roomToken,
  });
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
  if (!copied) throw new Error("当前浏览器不允许自动复制：选中文字后手动复制");
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
