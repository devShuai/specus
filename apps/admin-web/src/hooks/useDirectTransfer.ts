import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { PublicTransferIceConfig, TransferAttachment } from "../api/types";
import {
  buildPeerRtcConfiguration,
  hasTurnIceServer,
  normalizePeerTransportMode,
  type PeerTransportMode,
} from "../lib/directPeerTransport";
import { sha256Blob } from "../lib/sha256";
import { effectiveMimeType } from "../lib/transferPreview";
import {
  AppMessageReassembler,
  appMaximumFrameBytes,
  encodeAppAcknowledgement,
  encodeAppMessage,
  type AppPeerMessage,
} from "../lib/appMessageProtocol";
import { ChunkBitmap } from "../lib/chunkedResume/bitmap";
import { fromHex, randomHex128, sha256 as sha256Digest, toHex } from "../lib/chunkedResume/bytes";
import { isRecord, RECEIVER_BOUND_KINDS, SENDER_BOUND_KINDS, sendJson } from "../lib/chunkedResume/channel";
import { hashChunks } from "../lib/chunkedResume/chunkHashes";
import {
  CHUNK_SIZE_DEFAULT,
  MAX_RESUMABLE_BYTES,
  MEMORY_LIMIT_BYTES,
} from "../lib/chunkedResume/constants";
import { maxFrameBytes } from "../lib/chunkedResume/frames";
import { estimateStorage, openIndexedDbResumeStore } from "../lib/chunkedResume/indexedDbStore";
import {
  chunkLengthOf,
  manifestFromHashes,
  normalizeOfferedMimeType,
  normalizeOfferedName,
} from "../lib/chunkedResume/manifest";
import {
  isResumableFileMeta,
  ReceiverController,
  type ReceiverSnapshot,
} from "../lib/chunkedResume/receiverController";
import { sendResumable, type OpenedChannel } from "../lib/chunkedResume/resumableSend";
import {
  SenderError,
  SenderRouter,
  type OutgoingTransfer,
} from "../lib/chunkedResume/senderController";
import { SourceSizeMismatchError } from "../lib/chunkedResume/senderPlan";
import {
  copyBuffer,
  MemoryResumeStore,
  type ResumeStore,
  type SendRecord,
  type StorageMode,
} from "../lib/chunkedResume/store";

export interface DirectTransferSignalPayload {
  signalType?: "offer" | "answer" | "ice";
  transportMode?: PeerTransportMode;
  description?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
}

export type DirectPeerMessage = AppPeerMessage;

export interface DirectTransferPeer {
  peerId: string;
  displayName: string;
}

export type PeerTransportPath = "direct" | "turn";

export interface DirectReceivingTransfer {
  transferId: string;
  sourcePeerId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  receivedBytes: number;
  /** Resumable transfers only: where verified chunks are kept. */
  storage?: StorageMode;
}

export interface DirectPendingTransfer {
  transferId: string;
  sourcePeerId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  /** Resumable offers: "persistent" writes to this browser's storage after the click. */
  storage?: StorageMode;
  /** Why a resumable offer can only be received in memory. */
  memoryReason?: string;
}

/** An interrupted resumable receive kept in IndexedDB (or memory) and not active right now. */
export interface DirectStoredReceive {
  transferId: string;
  sourcePeerId: string;
  sourceName: string;
  fileName: string;
  sizeBytes: number;
  receivedBytes: number;
  expiresAt: number;
  storage: StorageMode;
}

/** A resumable send this page knows about: running, paused, or restored after a reload. */
export interface DirectOutgoingResume {
  transferId: string;
  fileName: string;
  sizeBytes: number;
  lastModified: number;
  targetPeerId: string;
  targetName: string;
  ackedBytes: number;
  expiresAt: number | null;
  /** False after a reload: the user has to select the same file again. */
  hasSource: boolean;
  running: boolean;
  /** Running outside the page's send queue (a resume the receiver asked for, or from the list). */
  background: boolean;
  persistent: boolean;
}

export interface DirectIncomingAttachment {
  sourcePeerId: string;
  attachment: TransferAttachment;
  objectId: string;
  downloadUrl: string | null;
  downloadExpiresAt: string | null;
  direct: true;
  previewUrl: string;
  blob: Blob;
  /** Resumable receives: the transfer id to mark saved once a download starts. */
  resumeTransferId?: string;
  /** Restored from this browser's storage after a reload. */
  restored?: boolean;
}

export interface DirectTransferResult {
  attachment: TransferAttachment;
  previewUrl: string;
}

type DirectTransferPhase = "connecting" | "waiting" | "direct";

interface DirectIncomingState {
  scopeKey: string;
  transferId: string;
  sourcePeerId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  expectedSha256?: string | null;
  chunks: ArrayBuffer[];
  receivedBytes: number;
}

interface DirectAckWaiter {
  targetPeerId: string;
  channel: RTCDataChannel;
  scopeKey: string;
  resolve: () => void;
  reject: (error: Error) => void;
  timer: number;
}

interface DirectPendingRequest extends DirectPendingTransfer {
  scopeKey: string;
  expectedSha256?: string | null;
  channel: RTCDataChannel;
  timer?: number;
}

interface PeerTransportMetadata {
  key: string;
  peerId: string;
  scopeKey: string;
  mode: PeerTransportMode;
  configurationKey: string;
}

type PeerChannelPurpose = "interactive" | "bulk";

interface DataChannelMetadata extends PeerTransportMetadata {
  purpose: PeerChannelPurpose;
}

interface AppAckWaiter {
  targetPeerId: string;
  scopeKey: string;
  channel?: RTCDataChannel;
  resolve: () => void;
  reject: (error: Error) => void;
  timer: number;
}

interface UseDirectTransferOptions {
  selfPeerId?: string;
  connectionScopeKey?: string;
  iceConfig: PublicTransferIceConfig | null;
  peers: DirectTransferPeer[];
  directMemoryLimitBytes: number;
  receiveConfirmationRequired: boolean;
  preconnectPeerChannels?: boolean;
  receivingTransferLimit?: number;
  sendSignal: (targetPeerId: string, payload: DirectTransferSignalPayload) => void;
  canReceiveFromPeer?: (sourcePeerId: string, messageType: "file" | "clipboard" | "whiteboard" | string) => boolean;
  onPeerMessage?: (sourcePeerId: string, message: DirectPeerMessage) => void;
  onIncoming: (item: DirectIncomingAttachment) => void;
  onPreviewUrl: (url: string) => void;
  onStateChange: (state: DirectTransferPhase) => void;
  onProgress: (value: number) => void;
  onError: (message: string) => void;
  /** Informational messages, e.g. a background resume that finished. */
  onNotice?: (message: string) => void;
}

export const DEFAULT_DIRECT_MEMORY_LIMIT_BYTES = MEMORY_LIMIT_BYTES;
/** Device transfers up to this size are resumable; larger receives need persistent storage. */
export const DIRECT_RESUMABLE_LIMIT_BYTES = MAX_RESUMABLE_BYTES;
/**
 * Pass as the abort reason when the user cancels a send: the transfer is abandoned, not paused.
 * An AbortError, so fetch-based fallbacks sharing the signal still see a regular abort.
 */
export const DIRECT_SEND_USER_CANCEL: Error = new DOMException("文件发送已取消", "AbortError");

/** Chunked resume needs WebCrypto and a secure context (§3); otherwise the legacy flow is used. */
export function directResumeSupported(): boolean {
  return typeof isSecureContext !== "undefined" && isSecureContext
    && typeof crypto !== "undefined" && typeof crypto.subtle?.digest === "function";
}

/** Largest file this browser can offer for device transfer. */
export function directSendLimitBytes(): number {
  return directResumeSupported() ? DIRECT_RESUMABLE_LIMIT_BYTES : DEFAULT_DIRECT_MEMORY_LIMIT_BYTES;
}

const CAPACITY_REJECT_CODES = new Set([
  "TOO_LARGE",
  "PERSISTENCE_UNAVAILABLE",
  "TOO_MANY_PARTIALS",
  "PARTIAL_BYTES_LIMIT",
  "INSUFFICIENT_STORAGE",
  "LEGACY_TOO_LARGE",
]);

/**
 * How the page should continue after sendDirect failed:
 * next-transport (try relay), cloud (the receiver cannot hold the file; a link may work) or
 * final (the user or the receiver decided, or the transfer is paused for a later resume).
 */
export function directSendFailureKind(error: unknown): "next-transport" | "cloud" | "final" {
  if (error instanceof SenderError) {
    if (error.failure === "retry" || error.failure === "restart") return "next-transport";
    return error.code && CAPACITY_REJECT_CODES.has(error.code) ? "cloud" : "final";
  }
  if (error instanceof SourceSizeMismatchError) return "final";
  return "next-transport";
}
const DEFAULT_RECEIVING_TRANSFER_LIMIT = 10;
const MAX_PENDING_ICE_CANDIDATES = 256;
const DIRECT_FILE_CHANNEL_OPEN_TIMEOUT_MS = 10_000;
const TURN_FILE_CHANNEL_OPEN_TIMEOUT_MS = 20_000;
const AUTO_FILE_CHANNEL_OPEN_TIMEOUT_MS = 20_000;
const DATA_CHANNEL_BACKPRESSURE_TIMEOUT_MS = 30_000;

export function useDirectTransfer(options: UseDirectTransferOptions) {
  const optionsRef = useRef(options);
  const iceConfigRef = useRef<PublicTransferIceConfig | null>(options.iceConfig);
  const activePeerIdsRef = useRef<Set<string>>(new Set(options.peers.map((peer) => peer.peerId)));
  const connectionScopeRef = useRef(options.connectionScopeKey ?? "default");
  const resetScopeRef = useRef(options.connectionScopeKey ?? "default");
  const manualResetCounterRef = useRef(0);
  const peerConnectionsRef = useRef<Map<string, RTCPeerConnection>>(new Map());
  const peerConnectionMetadataRef = useRef<WeakMap<RTCPeerConnection, PeerTransportMetadata>>(new WeakMap());
  const pendingIceCandidatesRef = useRef<WeakMap<RTCPeerConnection, RTCIceCandidateInit[]>>(new WeakMap());
  const makingOfferConnectionsRef = useRef<WeakSet<RTCPeerConnection>>(new WeakSet());
  const signalQueuesRef = useRef<Map<string, Promise<void>>>(new Map());
  const dataChannelsRef = useRef<Map<string, RTCDataChannel>>(new Map());
  const dataChannelMetadataRef = useRef<WeakMap<RTCDataChannel, DataChannelMetadata>>(new WeakMap());
  const openingChannelsRef = useRef<Map<string, Promise<RTCDataChannel>>>(new Map());
  const openingChannelMetadataRef = useRef<Map<string, DataChannelMetadata>>(new Map());
  const directIncomingRef = useRef<Map<string, DirectIncomingState>>(new Map());
  const directChannelTransfersRef = useRef<Map<RTCDataChannel, string>>(new Map());
  const pendingDirectRequestsRef = useRef<Map<string, DirectPendingRequest>>(new Map());
  const pendingChannelTransfersRef = useRef<Map<RTCDataChannel, string>>(new Map());
  const receivingProgressRef = useRef<Map<string, { lastAt: number; lastBytes: number }>>(new Map());
  const directAckWaitersRef = useRef<Map<string, DirectAckWaiter>>(new Map());
  const appAckWaitersRef = useRef<Map<string, AppAckWaiter>>(new Map());
  const directAppReassemblersRef = useRef<WeakMap<RTCDataChannel, AppMessageReassembler>>(new WeakMap());
  const relayAppReassemblersRef = useRef<Map<string, AppMessageReassembler>>(new Map());
  const [pendingTransfers, setPendingTransfers] = useState<DirectPendingTransfer[]>([]);
  const [receivingTransfers, setReceivingTransfers] = useState<DirectReceivingTransfer[]>([]);
  const [peerTransportPaths, setPeerTransportPaths] = useState<Record<string, PeerTransportPath>>({});
  // Chunked resume (protocol/spec/chunked-resume.md): receiver controller, sender sessions and
  // the outgoing transfers this page can resume.
  const [resumeSnapshot, setResumeSnapshot] = useState<ReceiverSnapshot>({ pending: [], entries: [] });
  const [outgoingResumes, setOutgoingResumes] = useState<DirectOutgoingResume[]>([]);
  const resumeStoreRef = useRef<Promise<ResumeStore | null> | null>(null);
  const memoryResumeStoreRef = useRef<ResumeStore>(new MemoryResumeStore());
  const receiverRef = useRef<ReceiverController | null>(null);
  const senderRouterRef = useRef(new SenderRouter());
  const outgoingRef = useRef<Map<string, OutgoingTransfer>>(new Map());
  const outgoingByFileRef = useRef<WeakMap<Blob, string>>(new WeakMap());
  const runningOutgoingRef = useRef<Map<string, { wake: () => void; background: boolean }>>(new Map());
  const resumeRequestNoticesRef = useRef<Set<string>>(new Set());
  const snapshotTimerRef = useRef<number | null>(null);
  const outgoingViewTimerRef = useRef<number | null>(null);
  const resumeRequestHandlerRef = useRef<(peerId: string, transferId: string) => void>(() => undefined);
  const outgoingCancelHandlerRef = useRef<(transfer: OutgoingTransfer) => void>(() => undefined);

  optionsRef.current = options;
  iceConfigRef.current = options.iceConfig;
  activePeerIdsRef.current = new Set(options.peers.map((peer) => peer.peerId));
  connectionScopeRef.current = options.connectionScopeKey ?? "default";

  const openResumeStore = useCallback((): Promise<ResumeStore | null> => {
    if (!resumeStoreRef.current) {
      resumeStoreRef.current = directResumeSupported() ? openIndexedDbResumeStore() : Promise.resolve(null);
    }
    return resumeStoreRef.current;
  }, []);

  const scheduleResumeSnapshot = useCallback(() => {
    if (snapshotTimerRef.current !== null) return;
    snapshotTimerRef.current = window.setTimeout(() => {
      snapshotTimerRef.current = null;
      if (receiverRef.current) setResumeSnapshot(receiverRef.current.snapshot());
    }, 150);
  }, []);

  const refreshOutgoingView = useCallback((immediate = false) => {
    const update = () => {
      outgoingViewTimerRef.current = null;
      setOutgoingResumes([...outgoingRef.current.values()]
        .filter((transfer) => transfer.resumeToken !== null)
        .map((transfer) => {
          const running = runningOutgoingRef.current.get(transfer.transferId);
          return {
            transferId: transfer.transferId,
            fileName: transfer.manifest.fileName,
            sizeBytes: transfer.manifest.sizeBytes,
            lastModified: transfer.lastModified,
            targetPeerId: transfer.targetPeerId,
            targetName: transfer.targetName,
            ackedBytes: ackedBytesOf(transfer),
            expiresAt: transfer.expiresAt,
            hasSource: transfer.source !== null,
            running: running !== undefined,
            background: running?.background ?? false,
            persistent: transfer.storage === "persistent",
          };
        }));
    };
    if (immediate) {
      if (outgoingViewTimerRef.current !== null) window.clearTimeout(outgoingViewTimerRef.current);
      update();
    } else if (outgoingViewTimerRef.current === null) {
      outgoingViewTimerRef.current = window.setTimeout(update, 250);
    }
  }, []);

  const getReceiver = useCallback((): ReceiverController => {
    if (!receiverRef.current) {
      receiverRef.current = new ReceiverController({
        openPersistentStore: openResumeStore,
        memoryStore: memoryResumeStoreRef.current,
        estimate: estimateStorage,
        now: () => Date.now(),
        digest: sha256Digest,
        randomToken: randomHex128,
        // Auto-accept is memory mode only; anything persistent waits for a click (§6).
        autoAccept: () => !optionsRef.current.receiveConfirmationRequired,
        senderAllowed: (peerId) => activePeerIdsRef.current.has(peerId)
          && optionsRef.current.canReceiveFromPeer?.(peerId, "file") !== false,
        peerName: (peerId) => optionsRef.current.peers.find((peer) => peer.peerId === peerId)?.displayName ?? "",
        setTimer: (callback, ms) => window.setTimeout(callback, ms),
        clearTimer: (handle) => {
          if (typeof handle === "number") window.clearTimeout(handle);
        },
        onChange: scheduleResumeSnapshot,
        onComplete: (file) => {
          const mimeType = effectiveMimeType(file.fileName, file.mimeType);
          const blob = file.blob.type === mimeType ? file.blob : new Blob([file.blob], { type: mimeType });
          const previewUrl = URL.createObjectURL(blob);
          optionsRef.current.onPreviewUrl(previewUrl);
          const attachment = directAttachment(file.transferId, file.fileName, mimeType, file.sizeBytes, null);
          optionsRef.current.onIncoming({
            sourcePeerId: file.sourcePeerId,
            attachment,
            objectId: attachment.objectId,
            downloadUrl: previewUrl,
            downloadExpiresAt: null,
            direct: true,
            previewUrl,
            blob,
            resumeTransferId: file.storage === "persistent" ? file.transferId : undefined,
            restored: file.restored,
          });
          if (file.restored) {
            optionsRef.current.onNotice?.(`已从本机存储恢复未保存的文件：${file.fileName}`);
          }
        },
        onError: (message) => optionsRef.current.onError(message),
      });
    }
    return receiverRef.current;
  }, [openResumeStore, scheduleResumeSnapshot]);

  const isCurrentDataChannel = useCallback((peerId: string, channel: RTCDataChannel, scopeKey: string) => {
    const metadata = dataChannelMetadataRef.current.get(channel);
    return connectionScopeRef.current === scopeKey
      && activePeerIdsRef.current.has(peerId)
      && metadata?.peerId === peerId
      && metadata.scopeKey === scopeKey
      && dataChannelsRef.current.get(metadata.key) === channel;
  }, []);

  const clearPeerTransportPath = useCallback((peerId: string) => {
    setPeerTransportPaths((current) => {
      if (!(peerId in current)) {
        return current;
      }
      const next = { ...current };
      delete next[peerId];
      return next;
    });
  }, []);

  const isCurrentPeerConnection = useCallback((peerId: string, connection: RTCPeerConnection, scopeKey: string) => {
    const metadata = peerConnectionMetadataRef.current.get(connection);
    return connectionScopeRef.current === scopeKey
      && activePeerIdsRef.current.has(peerId)
      && metadata?.peerId === peerId
      && metadata.scopeKey === scopeKey
      && peerConnectionsRef.current.get(metadata.key) === connection;
  }, []);

  const rejectDirectAckWaiters = useCallback((
    predicate: (waiter: DirectAckWaiter) => boolean,
    reason: string,
  ) => {
    for (const [transferId, waiter] of directAckWaitersRef.current) {
      if (!predicate(waiter)) {
        continue;
      }
      directAckWaitersRef.current.delete(transferId);
      window.clearTimeout(waiter.timer);
      waiter.reject(new Error(reason));
    }
  }, []);

  const rejectAppAckWaiters = useCallback((
    predicate: (waiter: AppAckWaiter) => boolean,
    reason: string,
  ) => {
    for (const [messageId, waiter] of appAckWaitersRef.current) {
      if (!predicate(waiter)) continue;
      appAckWaitersRef.current.delete(messageId);
      window.clearTimeout(waiter.timer);
      waiter.reject(new Error(reason));
    }
  }, []);

  const waitForAppAck = useCallback((messageId: string, targetPeerId: string,
    scopeKey: string, timeoutMs: number, channel?: RTCDataChannel) => new Promise<void>((resolve, reject) => {
    let waiter: AppAckWaiter;
    const timer = window.setTimeout(() => {
      if (appAckWaitersRef.current.get(messageId) === waiter) {
        appAckWaitersRef.current.delete(messageId);
      }
      reject(new Error("应用消息确认超时"));
    }, timeoutMs);
    waiter = { targetPeerId, scopeKey, channel, resolve, reject, timer };
    const previous = appAckWaitersRef.current.get(messageId);
    if (previous) {
      window.clearTimeout(previous.timer);
      previous.reject(new Error("应用消息确认被替换"));
    }
    appAckWaitersRef.current.set(messageId, waiter);
  }), []);

  const cancelAppAck = useCallback((messageId: string, reason: string) => {
    const waiter = appAckWaitersRef.current.get(messageId);
    if (!waiter) return;
    appAckWaitersRef.current.delete(messageId);
    window.clearTimeout(waiter.timer);
    waiter.reject(new Error(reason));
  }, []);

  const resetDirectState = useCallback((reason: string, updateView: boolean) => {
    const connections = [...peerConnectionsRef.current.values()];
    const channels = new Set([
      ...dataChannelsRef.current.values(),
      ...directChannelTransfersRef.current.keys(),
      ...pendingChannelTransfersRef.current.keys(),
      ...[...directAckWaitersRef.current.values()].map((waiter) => waiter.channel),
    ]);
    const waiters = [...directAckWaitersRef.current.values()];
    const appWaiters = [...appAckWaitersRef.current.values()];
    const pendingRequests = [...pendingDirectRequestsRef.current.values()];
    peerConnectionsRef.current.clear();
    dataChannelsRef.current.clear();
    openingChannelsRef.current.clear();
    openingChannelMetadataRef.current.clear();
    signalQueuesRef.current.clear();
    directIncomingRef.current.clear();
    directChannelTransfersRef.current.clear();
    pendingDirectRequestsRef.current.clear();
    pendingChannelTransfersRef.current.clear();
    receivingProgressRef.current.clear();
    directAckWaitersRef.current.clear();
    appAckWaitersRef.current.clear();
    relayAppReassemblersRef.current.clear();
    peerConnectionMetadataRef.current = new WeakMap();
    pendingIceCandidatesRef.current = new WeakMap();
    makingOfferConnectionsRef.current = new WeakSet();
    dataChannelMetadataRef.current = new WeakMap();
    directAppReassemblersRef.current = new WeakMap();
    for (const channel of channels) {
      // Resumable state survives: sessions end, records stay for a later resume.
      receiverRef.current?.channelClosed(channel);
      senderRouterRef.current.channelClosed(channel);
      channel.onmessage = null;
      channel.onclose = null;
      channel.close();
    }
    for (const connection of connections) {
      connection.onicecandidate = null;
      connection.ondatachannel = null;
      connection.onconnectionstatechange = null;
      connection.close();
    }
    for (const waiter of waiters) {
      window.clearTimeout(waiter.timer);
      waiter.reject(new Error(reason));
    }
    for (const waiter of appWaiters) {
      window.clearTimeout(waiter.timer);
      waiter.reject(new Error(reason));
    }
    for (const request of pendingRequests) {
      if (request.timer !== undefined) {
        window.clearTimeout(request.timer);
      }
    }
    if (updateView) {
      setPendingTransfers([]);
      setReceivingTransfers([]);
      setPeerTransportPaths({});
    }
  }, []);

  useEffect(() => () => resetDirectState("page closed", false), [resetDirectState]);

  useEffect(() => {
    const scopeKey = options.connectionScopeKey ?? "default";
    if (resetScopeRef.current === scopeKey) {
      return;
    }
    resetScopeRef.current = scopeKey;
    resetDirectState("room changed", true);
  }, [options.connectionScopeKey, resetDirectState]);

  const invalidateConnections = useCallback(() => {
    manualResetCounterRef.current += 1;
    connectionScopeRef.current = `invalidated:${manualResetCounterRef.current}`;
    activePeerIdsRef.current.clear();
    resetDirectState("room changed", true);
  }, [resetDirectState]);

  const sendSignal = useCallback((targetPeerId: string, payload: DirectTransferSignalPayload) => {
    optionsRef.current.sendSignal(targetPeerId, payload);
  }, []);

  const waitForDirectAck = useCallback((
    targetPeerId: string,
    channel: RTCDataChannel,
    scopeKey: string,
    transferId: string,
    timeoutMs: number,
    timeoutMessage = "直连确认超时",
  ) => new Promise<void>((resolve, reject) => {
    let waiter: DirectAckWaiter;
    const timer = window.setTimeout(() => {
      if (directAckWaitersRef.current.get(transferId) === waiter) {
        directAckWaitersRef.current.delete(transferId);
      }
      reject(new Error(timeoutMessage));
    }, timeoutMs);
    waiter = { targetPeerId, channel, scopeKey, resolve, reject, timer };
    const previous = directAckWaitersRef.current.get(transferId);
    if (previous) {
      directAckWaitersRef.current.delete(transferId);
      window.clearTimeout(previous.timer);
      previous.reject(new Error("transfer acknowledgement superseded"));
    }
    directAckWaitersRef.current.set(transferId, waiter);
  }), []);

  const sendDirectReject = useCallback((channel: RTCDataChannel, transferId: string, reason: string) => {
    if (channel.readyState === "open") {
      channel.send(JSON.stringify({ kind: "file-reject", transferId, reason }));
    }
  }, []);

  const removePendingTransfer = useCallback((key: string) => {
    const request = pendingDirectRequestsRef.current.get(key);
    if (request) {
      if (request.timer !== undefined) {
        window.clearTimeout(request.timer);
      }
      pendingDirectRequestsRef.current.delete(key);
      pendingChannelTransfersRef.current.delete(request.channel);
    }
    setPendingTransfers((items) => items.filter((item) => receivingTransferKey(item) !== key));
  }, []);

  const closeDataChannel = useCallback((
    _peerId: string,
    channel: RTCDataChannel,
    reason: string,
    closeChannel: boolean,
  ) => {
    const metadata = dataChannelMetadataRef.current.get(channel);
    if (metadata && dataChannelsRef.current.get(metadata.key) === channel) {
      dataChannelsRef.current.delete(metadata.key);
    }
    dataChannelMetadataRef.current.delete(channel);
    rejectDirectAckWaiters((waiter) => waiter.channel === channel, reason);
    rejectAppAckWaiters((waiter) => waiter.channel === channel, reason);
    receiverRef.current?.channelClosed(channel);
    senderRouterRef.current.channelClosed(channel);

    const activeTransferKey = directChannelTransfersRef.current.get(channel);
    directChannelTransfersRef.current.delete(channel);
    if (activeTransferKey) {
      directIncomingRef.current.delete(activeTransferKey);
      receivingProgressRef.current.delete(activeTransferKey);
      setReceivingTransfers((items) => items.filter((item) => receivingTransferKey(item) !== activeTransferKey));
    }
    const pendingTransferKey = pendingChannelTransfersRef.current.get(channel);
    if (pendingTransferKey) {
      removePendingTransfer(pendingTransferKey);
    }

    if (closeChannel && channel.readyState !== "closed") {
      channel.onmessage = null;
      channel.onclose = null;
      channel.close();
    }
  }, [rejectAppAckWaiters, rejectDirectAckWaiters, removePendingTransfer]);

  useEffect(() => {
    const activePeerIds = new Set(options.peers.map((peer) => peer.peerId));
    for (const channel of dataChannelsRef.current.values()) {
      const metadata = dataChannelMetadataRef.current.get(channel);
      if (!metadata || !activePeerIds.has(metadata.peerId)) {
        closeDataChannel(metadata?.peerId ?? "", channel, "对方设备已离线", true);
      }
    }
    for (const [transportKey, connection] of peerConnectionsRef.current) {
      const metadata = peerConnectionMetadataRef.current.get(connection);
      if (!metadata || !activePeerIds.has(metadata.peerId)) {
        peerConnectionsRef.current.delete(transportKey);
        peerConnectionMetadataRef.current.delete(connection);
        connection.onicecandidate = null;
        connection.ondatachannel = null;
        connection.onconnectionstatechange = null;
        connection.close();
      }
    }
    for (const [transportKey, metadata] of openingChannelMetadataRef.current) {
      if (!activePeerIds.has(metadata.peerId)) {
        openingChannelsRef.current.delete(transportKey);
        openingChannelMetadataRef.current.delete(transportKey);
      }
    }
    rejectDirectAckWaiters(
      (waiter) => !activePeerIds.has(waiter.targetPeerId),
      "对方设备已离线",
    );
    rejectAppAckWaiters(
      (waiter) => !activePeerIds.has(waiter.targetPeerId),
      "对方设备已离线",
    );
  }, [closeDataChannel, options.peers, rejectAppAckWaiters, rejectDirectAckWaiters]);

  const updateReceivingTransfer = useCallback((incomingState: DirectIncomingState) => {
    const key = receivingTransferKey(incomingState);
    const now = Date.now();
    const previous = receivingProgressRef.current.get(key);
    const isComplete = incomingState.sizeBytes > 0 && incomingState.receivedBytes >= incomingState.sizeBytes;
    if (previous && !isComplete && now - previous.lastAt < 200) {
      return;
    }
    receivingProgressRef.current.set(key, { lastAt: now, lastBytes: incomingState.receivedBytes });
    setReceivingTransfers((items) => {
      const view: DirectReceivingTransfer = {
        transferId: incomingState.transferId,
        sourcePeerId: incomingState.sourcePeerId,
        fileName: incomingState.fileName,
        mimeType: incomingState.mimeType,
        sizeBytes: incomingState.sizeBytes,
        receivedBytes: incomingState.receivedBytes,
      };
      return [view, ...items.filter((item) => receivingTransferKey(item) !== key)]
        .slice(0, optionsRef.current.receivingTransferLimit ?? DEFAULT_RECEIVING_TRANSFER_LIMIT);
    });
  }, []);

  const startIncomingTransfer = useCallback((request: DirectPendingRequest, transferKey: string) => {
    if (request.channel.readyState !== "open"
      || !isCurrentDataChannel(request.sourcePeerId, request.channel, request.scopeKey)) {
      removePendingTransfer(transferKey);
      optionsRef.current.onError("直连通道已断开，请让对方重新发送");
      return;
    }
    removePendingTransfer(transferKey);
    const incomingState: DirectIncomingState = {
      scopeKey: request.scopeKey,
      transferId: request.transferId,
      sourcePeerId: request.sourcePeerId,
      fileName: request.fileName,
      mimeType: request.mimeType,
      sizeBytes: request.sizeBytes,
      expectedSha256: request.expectedSha256 || null,
      chunks: [],
      receivedBytes: 0,
    };
    directIncomingRef.current.set(transferKey, incomingState);
    directChannelTransfersRef.current.set(request.channel, transferKey);
    updateReceivingTransfer(incomingState);
    request.channel.send(JSON.stringify({ kind: "file-ready", transferId: request.transferId }));
  }, [isCurrentDataChannel, removePendingTransfer, updateReceivingTransfer]);

  const acceptIncomingTransfer = useCallback((sourcePeerId: string, transferId: string) => {
    const transferKey = receivingTransferKey({ sourcePeerId, transferId });
    const request = pendingDirectRequestsRef.current.get(transferKey);
    if (!request) {
      if (receiverRef.current?.snapshot().pending.some((item) => item.transferId === transferId)) {
        void receiverRef.current.accept(transferId);
      }
      return;
    }
    startIncomingTransfer(request, transferKey);
  }, [startIncomingTransfer]);

  const rejectIncomingTransfer = useCallback((sourcePeerId: string, transferId: string) => {
    const transferKey = receivingTransferKey({ sourcePeerId, transferId });
    const request = pendingDirectRequestsRef.current.get(transferKey);
    if (!request) {
      receiverRef.current?.reject(transferId);
      return;
    }
    sendDirectReject(request.channel, transferId, "对方已拒绝接收");
    removePendingTransfer(transferKey);
  }, [removePendingTransfer, sendDirectReject]);

  const cancelIncomingTransfer = useCallback((sourcePeerId: string, transferId: string) => {
    if (receiverRef.current?.snapshot().entries.some((item) => item.transferId === transferId)) {
      // Abandoning a resumable receive deletes its local data and tells the sender.
      void receiverRef.current.abandon(transferId);
      return;
    }
    const transferKey = receivingTransferKey({ sourcePeerId, transferId });
    let channel: RTCDataChannel | null = null;
    for (const [candidate, key] of directChannelTransfersRef.current) {
      if (key === transferKey) {
        channel = candidate;
        break;
      }
    }
    if (!channel) {
      return;
    }
    if (channel.readyState === "open") {
      channel.send(JSON.stringify({ kind: "file-cancel", transferId }));
    }
    closeDataChannel(sourcePeerId, channel, "对方取消了接收", true);
  }, [closeDataChannel]);

  const completeDirectIncoming = useCallback(async (sourcePeerId: string, channel: RTCDataChannel, transferId: string) => {
    const transferKey = receivingTransferKey({ sourcePeerId, transferId });
    const incomingState = directIncomingRef.current.get(transferKey);
    if (!incomingState
      || directChannelTransfersRef.current.get(channel) !== transferKey
      || !isCurrentDataChannel(sourcePeerId, channel, incomingState.scopeKey)) {
      return;
    }
    directIncomingRef.current.delete(transferKey);
    directChannelTransfersRef.current.delete(channel);
    receivingProgressRef.current.delete(transferKey);
    setReceivingTransfers((items) => items.filter((item) => receivingTransferKey(item) !== transferKey));

    const mimeType = effectiveMimeType(incomingState.fileName, incomingState.mimeType);
    const blob = new Blob(incomingState.chunks, { type: mimeType });
    if (incomingState.expectedSha256) {
      const actualSha256 = await sha256Blob(blob);
      if (!isCurrentDataChannel(sourcePeerId, channel, incomingState.scopeKey)) {
        return;
      }
      if (!actualSha256 || actualSha256 !== incomingState.expectedSha256) {
        sendDirectReject(channel, transferId, "文件完整性校验失败");
        optionsRef.current.onError("直连文件完整性校验失败，已拒绝接收");
        return;
      }
    }

    if (!isCurrentDataChannel(sourcePeerId, channel, incomingState.scopeKey)) {
      return;
    }

    const previewUrl = URL.createObjectURL(blob);
    optionsRef.current.onPreviewUrl(previewUrl);
    const attachment = directAttachment(
      transferId,
      incomingState.fileName,
      mimeType,
      incomingState.receivedBytes || incomingState.sizeBytes,
      incomingState.expectedSha256 || null,
    );
    optionsRef.current.onIncoming({
      sourcePeerId,
      attachment,
      objectId: attachment.objectId,
      downloadUrl: previewUrl,
      downloadExpiresAt: null,
      direct: true,
      previewUrl,
      blob,
    });
    if (channel.readyState === "open") {
      channel.send(JSON.stringify({ kind: "file-ack", transferId }));
    }
  }, [isCurrentDataChannel, sendDirectReject]);

  const handleAppBinaryMessage = useCallback(async (
    sourcePeerId: string,
    frame: ArrayBuffer,
    scopeKey: string,
    reply: (frame: ArrayBuffer) => void,
    channel?: RTCDataChannel,
  ) => {
    if (connectionScopeRef.current !== scopeKey || !activePeerIdsRef.current.has(sourcePeerId)) {
      return;
    }
    let reassembler: AppMessageReassembler;
    if (channel) {
      reassembler = directAppReassemblersRef.current.get(channel) ?? new AppMessageReassembler();
      directAppReassemblersRef.current.set(channel, reassembler);
    } else {
      const key = JSON.stringify([scopeKey, sourcePeerId]);
      reassembler = relayAppReassemblersRef.current.get(key) ?? new AppMessageReassembler();
      relayAppReassemblersRef.current.set(key, reassembler);
    }
    const decoded = await reassembler.push(frame);
    if (!decoded) return;
    if (decoded.kind === "ack") {
      const waiter = appAckWaitersRef.current.get(decoded.messageId);
      if (waiter && waiter.targetPeerId === sourcePeerId && waiter.scopeKey === scopeKey
        && (!waiter.channel || waiter.channel === channel)) {
        appAckWaitersRef.current.delete(decoded.messageId);
        window.clearTimeout(waiter.timer);
        waiter.resolve();
      }
      return;
    }
    if (optionsRef.current.canReceiveFromPeer?.(sourcePeerId, decoded.message.messageType) === false) {
      return;
    }
    optionsRef.current.onPeerMessage?.(sourcePeerId, decoded.message);
    if (decoded.acknowledgementRequired) {
      reply(encodeAppAcknowledgement(decoded.messageId));
    }
  }, []);

  const handleDirectControlMessage = useCallback((
    sourcePeerId: string,
    channel: RTCDataChannel,
    data: string,
    scopeKey: string,
  ) => {
    if (!isCurrentDataChannel(sourcePeerId, channel, scopeKey)) {
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      return;
    }
    if (!isRecord(parsed)) {
      return;
    }
    const message = parsed as {
      kind?: string;
      transferId?: string;
      fileName?: string;
      mimeType?: string;
      sizeBytes?: number;
      sha256?: string | null;
      reason?: string;
    };
    const legacyChannelBusy = () => {
      const activeTransferKey = directChannelTransfersRef.current.get(channel);
      const pendingTransferKey = pendingChannelTransfersRef.current.get(channel);
      return Boolean((activeTransferKey && directIncomingRef.current.has(activeTransferKey))
        || (pendingTransferKey && pendingDirectRequestsRef.current.has(pendingTransferKey)));
    };
    // Chunked resume: a file-meta with `resume`, the handshake and the per-chunk messages.
    if (message.kind === "file-meta" && typeof message.transferId === "string"
      && isResumableFileMeta(parsed) && directResumeSupported()) {
      if (legacyChannelBusy()) {
        sendJson(channel, { kind: "file-reject", transferId: message.transferId, code: "BUSY", reason: "当前还有文件正在接收" });
        return;
      }
      void getReceiver().handleFileMeta(sourcePeerId, channel, parsed);
      return;
    }
    if (message.kind === "resume-offer") {
      if (directResumeSupported()) {
        void getReceiver().handleResumeOffer(sourcePeerId, channel, parsed);
      }
      return;
    }
    if (typeof message.kind === "string" && SENDER_BOUND_KINDS.has(message.kind)
      && senderRouterRef.current.dispatch(channel, parsed)) {
      return;
    }
    if (message.kind === "resume-request" && typeof message.transferId === "string") {
      resumeRequestHandlerRef.current(sourcePeerId, message.transferId);
      return;
    }
    if (message.kind === "file-cancel" && typeof message.transferId === "string") {
      // Outside a session only the resume token proves the receiver abandoned our transfer.
      const outgoing = outgoingRef.current.get(message.transferId);
      if (outgoing?.resumeToken && parsed.resumeToken === outgoing.resumeToken
        && !runningOutgoingRef.current.has(outgoing.transferId)) {
        outgoingCancelHandlerRef.current(outgoing);
        return;
      }
    }
    if (typeof message.kind === "string" && RECEIVER_BOUND_KINDS.has(message.kind) && receiverRef.current) {
      void receiverRef.current.handleSenderMessage(sourcePeerId, channel, parsed);
      if (message.kind === "transfer-error") {
        return;
      }
    }
    if (message.kind === "file-meta" && message.transferId && receiverRef.current?.isChannelBusy(channel)) {
      sendDirectReject(channel, message.transferId, "当前还有文件正在接收");
      return;
    }
    if (message.kind === "file-meta" && message.transferId) {
      if (optionsRef.current.canReceiveFromPeer?.(sourcePeerId, "file") === false) {
        sendDirectReject(channel, message.transferId, "对方在当前房间没有发送权限");
        return;
      }
      const sizeBytes = Number(message.sizeBytes || 0);
      if (!Number.isFinite(sizeBytes) || sizeBytes < 0) {
        sendDirectReject(channel, message.transferId, "文件大小无效");
        return;
      }
      if (sizeBytes > optionsRef.current.directMemoryLimitBytes) {
        const reason = `文件超过 ${formatTransferBytes(optionsRef.current.directMemoryLimitBytes)}，请改用分享链接`;
        sendDirectReject(channel, message.transferId, reason);
        optionsRef.current.onError(reason);
        return;
      }
      const activeTransferKey = directChannelTransfersRef.current.get(channel);
      if (activeTransferKey && directIncomingRef.current.has(activeTransferKey)) {
        sendDirectReject(channel, message.transferId, "当前还有文件正在接收");
        return;
      }
      const pendingTransferKey = pendingChannelTransfersRef.current.get(channel);
      if (pendingTransferKey && pendingDirectRequestsRef.current.has(pendingTransferKey)) {
        sendDirectReject(channel, message.transferId, "当前还有文件等待确认");
        return;
      }
      const fileName = message.fileName || "attachment";
      const transferKey = receivingTransferKey({ sourcePeerId, transferId: message.transferId });
      if (pendingDirectRequestsRef.current.has(transferKey) || directIncomingRef.current.has(transferKey)) {
        return;
      }
      const request: DirectPendingRequest = {
        scopeKey,
        transferId: message.transferId,
        sourcePeerId,
        fileName,
        mimeType: message.mimeType || "application/octet-stream",
        sizeBytes,
        expectedSha256: message.sha256 || null,
        channel,
      };
      if (!optionsRef.current.receiveConfirmationRequired) {
        startIncomingTransfer(request, transferKey);
        return;
      }
      request.timer = window.setTimeout(() => {
        sendDirectReject(channel, message.transferId!, "接收确认超时");
        removePendingTransfer(transferKey);
      }, 118000);
      pendingDirectRequestsRef.current.set(transferKey, request);
      pendingChannelTransfersRef.current.set(channel, transferKey);
      setPendingTransfers((items) => [
        {
          transferId: request.transferId,
          sourcePeerId: request.sourcePeerId,
          fileName: request.fileName,
          mimeType: request.mimeType,
          sizeBytes: request.sizeBytes,
        },
        ...items.filter((item) => receivingTransferKey(item) !== transferKey),
      ].slice(0, optionsRef.current.receivingTransferLimit ?? DEFAULT_RECEIVING_TRANSFER_LIMIT));
      return;
    }
    if (message.kind === "file-cancel" && message.transferId) {
      const transferKey = receivingTransferKey({ sourcePeerId, transferId: message.transferId });
      const pending = pendingDirectRequestsRef.current.get(transferKey);
      if (pending?.channel === channel) {
        removePendingTransfer(transferKey);
      }
      const incoming = directIncomingRef.current.get(transferKey);
      if (incoming && directChannelTransfersRef.current.get(channel) === transferKey) {
        directIncomingRef.current.delete(transferKey);
        directChannelTransfersRef.current.delete(channel);
        receivingProgressRef.current.delete(transferKey);
        setReceivingTransfers((items) => items
          .filter((item) => receivingTransferKey(item) !== transferKey));
      }
      return;
    }
    if (message.kind === "file-complete" && message.transferId) {
      void completeDirectIncoming(sourcePeerId, channel, message.transferId).catch(() => {
        if (isCurrentDataChannel(sourcePeerId, channel, scopeKey)) {
          sendDirectReject(channel, message.transferId!, "文件完整性校验失败");
          optionsRef.current.onError("直连文件完整性校验失败，已拒绝接收");
        }
      });
      return;
    }
    if ((message.kind === "file-ready" || message.kind === "file-ack") && message.transferId) {
      const waiter = directAckWaitersRef.current.get(message.transferId);
      if (waiter
        && waiter.targetPeerId === sourcePeerId
        && waiter.channel === channel
        && waiter.scopeKey === scopeKey) {
        window.clearTimeout(waiter.timer);
        directAckWaitersRef.current.delete(message.transferId);
        waiter.resolve();
      }
      return;
    }
    if (message.kind === "file-reject" && message.transferId) {
      const waiter = directAckWaitersRef.current.get(message.transferId);
      if (waiter
        && waiter.targetPeerId === sourcePeerId
        && waiter.channel === channel
        && waiter.scopeKey === scopeKey) {
        window.clearTimeout(waiter.timer);
        directAckWaitersRef.current.delete(message.transferId);
        waiter.reject(new Error(message.reason || "对方拒绝接收"));
      }
    }
  }, [completeDirectIncoming, getReceiver, isCurrentDataChannel, removePendingTransfer, sendDirectReject, startIncomingTransfer]);

  const handleDataChannelMessage = useCallback((sourcePeerId: string, channel: RTCDataChannel, data: unknown, scopeKey: string) => {
    if (!isCurrentDataChannel(sourcePeerId, channel, scopeKey)) {
      return;
    }
    const purpose = dataChannelMetadataRef.current.get(channel)?.purpose;
    if (purpose === "interactive") {
      if (typeof data === "string") {
        closeDataChannel(sourcePeerId, channel, "legacy app message rejected", true);
        return;
      }
      if (data instanceof ArrayBuffer) {
        void handleAppBinaryMessage(sourcePeerId, data, scopeKey, (reply) => {
          if (isCurrentDataChannel(sourcePeerId, channel, scopeKey) && channel.readyState === "open") {
            channel.send(reply);
          }
        }, channel).catch(() => {
          closeDataChannel(sourcePeerId, channel, "invalid app frame", true);
          optionsRef.current.onError("收到无效的应用同步数据，互动通道已关闭");
        });
        return;
      }
      if (data instanceof Blob) {
        void data.arrayBuffer().then((buffer) => handleDataChannelMessage(sourcePeerId, channel, buffer, scopeKey));
      }
      return;
    }
    if (purpose !== "bulk") {
      closeDataChannel(sourcePeerId, channel, "unknown data channel purpose", true);
      return;
    }
    if (typeof data === "string") {
      handleDirectControlMessage(sourcePeerId, channel, data, scopeKey);
      return;
    }
    if (data instanceof ArrayBuffer) {
      if (receiverRef.current?.hasSession(channel)) {
        receiverRef.current.handleFrame(channel, data);
        return;
      }
      const activeTransferKey = directChannelTransfersRef.current.get(channel);
      const current = activeTransferKey ? directIncomingRef.current.get(activeTransferKey) : null;
      if (current && current.scopeKey === scopeKey && current.sourcePeerId === sourcePeerId) {
        if (current.receivedBytes + data.byteLength > current.sizeBytes) {
          sendDirectReject(channel, current.transferId, "文件大小与声明不一致");
          directIncomingRef.current.delete(activeTransferKey!);
          directChannelTransfersRef.current.delete(channel);
          receivingProgressRef.current.delete(activeTransferKey!);
          setReceivingTransfers((items) => items.filter((item) => receivingTransferKey(item) !== activeTransferKey));
          optionsRef.current.onError("直连文件大小与声明不一致，已拒绝接收");
          return;
        }
        current.chunks.push(data);
        current.receivedBytes += data.byteLength;
        updateReceivingTransfer(current);
      }
      return;
    }
    if (data instanceof Blob) {
      void data.arrayBuffer()
        .then((buffer) => handleDataChannelMessage(sourcePeerId, channel, buffer, scopeKey))
        .catch(() => {
          // A channel can close while a Blob-backed message is being converted.
        });
    }
  }, [closeDataChannel, handleAppBinaryMessage, handleDirectControlMessage, isCurrentDataChannel, sendDirectReject, updateReceivingTransfer]);

  const recordTransportPath = useCallback((peerId: string, connection: RTCPeerConnection, scopeKey: string) => {
    void detectPeerTransportPath(connection).then((path) => {
      if (!path
        || connectionScopeRef.current !== scopeKey
        || !isCurrentPeerConnection(peerId, connection, scopeKey)) {
        return;
      }
      setPeerTransportPaths((current) => current[peerId] === path ? current : { ...current, [peerId]: path });
    });
  }, [isCurrentPeerConnection]);

  const setupDataChannel = useCallback((
    sourcePeerId: string,
    channel: RTCDataChannel,
    mode: PeerTransportMode,
    purpose: PeerChannelPurpose,
  ) => {
    const scopeKey = connectionScopeRef.current;
    const key = peerChannelKey(sourcePeerId, mode, purpose);
    const previous = dataChannelsRef.current.get(key);
    if (previous && previous !== channel) {
      closeDataChannel(sourcePeerId, previous, `${mode} channel replaced`, true);
    }
    const metadata = {
      key,
      peerId: sourcePeerId,
      scopeKey,
      mode,
      purpose,
      configurationKey: peerTransportConfigurationKey(iceConfigRef.current, mode),
    };
    channel.binaryType = "arraybuffer";
    dataChannelMetadataRef.current.set(channel, metadata);
    dataChannelsRef.current.set(key, channel);
    channel.onmessage = (event) => handleDataChannelMessage(sourcePeerId, channel, event.data, scopeKey);
    channel.onclose = () => {
      closeDataChannel(sourcePeerId, channel, `${mode} ${purpose} channel closed`, false);
    };
  }, [closeDataChannel, handleDataChannelMessage]);

  const createPeerConnection = useCallback((targetPeerId: string, mode: PeerTransportMode) => {
    const key = peerTransportKey(targetPeerId, mode);
    const existing = peerConnectionsRef.current.get(key);
    const scopeKey = connectionScopeRef.current;
    const existingMetadata = existing ? peerConnectionMetadataRef.current.get(existing) : undefined;
    const configuration = buildPeerRtcConfiguration(iceConfigRef.current, mode);
    const configurationKey = JSON.stringify(configuration);
    if (existing
      && existingMetadata?.scopeKey === scopeKey
      && existing.connectionState !== "failed"
      && existing.connectionState !== "closed"
      && existingMetadata.configurationKey === configurationKey) {
      return existing;
    }
    if (existing) {
      if (peerConnectionsRef.current.get(key) === existing) {
        peerConnectionsRef.current.delete(key);
      }
      peerConnectionMetadataRef.current.delete(existing);
      existing.onicecandidate = null;
      existing.ondatachannel = null;
      existing.onconnectionstatechange = null;
      existing.close();
      for (const channel of dataChannelsRef.current.values()) {
        const channelMetadata = dataChannelMetadataRef.current.get(channel);
        if (channelMetadata?.peerId === targetPeerId && channelMetadata.mode === mode) {
          closeDataChannel(targetPeerId, channel, `${mode} connection replaced`, true);
        }
      }
    }
    const connection = new RTCPeerConnection(configuration);
    const metadata = { key, peerId: targetPeerId, scopeKey, mode, configurationKey };
    peerConnectionMetadataRef.current.set(connection, metadata);
    peerConnectionsRef.current.set(key, connection);
    connection.onicecandidate = (event) => {
      if (isCurrentPeerConnection(targetPeerId, connection, scopeKey) && event.candidate) {
        sendSignal(targetPeerId, {
          signalType: "ice",
          transportMode: mode,
          candidate: event.candidate.toJSON(),
        });
      }
    };
    connection.ondatachannel = (event) => {
      if (!isCurrentPeerConnection(targetPeerId, connection, scopeKey)) {
        event.channel.close();
        return;
      }
      const purpose = channelPurposeFromLabel(event.channel.label);
      if (!purpose) {
        event.channel.close();
        return;
      }
      setupDataChannel(targetPeerId, event.channel, mode, purpose);
    };
    connection.onconnectionstatechange = () => {
      if (connection.connectionState === "connected"
        && isCurrentPeerConnection(targetPeerId, connection, scopeKey)) {
        recordTransportPath(targetPeerId, connection, scopeKey);
      }
      if ((connection.connectionState === "failed" || connection.connectionState === "closed")
        && peerConnectionsRef.current.get(key) === connection) {
        peerConnectionsRef.current.delete(key);
        peerConnectionMetadataRef.current.delete(connection);
        for (const channel of dataChannelsRef.current.values()) {
          const channelMetadata = dataChannelMetadataRef.current.get(channel);
          if (channelMetadata?.peerId === targetPeerId && channelMetadata.mode === mode) {
            closeDataChannel(targetPeerId, channel, `${mode} connection closed`, true);
          }
        }
        const hasLiveConnection = [...peerConnectionsRef.current.values()]
          .some((candidate) => peerConnectionMetadataRef.current.get(candidate)?.peerId === targetPeerId);
        if (!hasLiveConnection) {
          clearPeerTransportPath(targetPeerId);
        }
      }
    };
    return connection;
  }, [clearPeerTransportPath, closeDataChannel, isCurrentPeerConnection, recordTransportPath, sendSignal, setupDataChannel]);

  const enqueueSignalingOperation = useCallback((
    scopeKey: string,
    peerId: string,
    mode: PeerTransportMode,
    operation: () => Promise<void>,
  ) => {
    const queueKey = JSON.stringify([scopeKey, peerId, mode]);
    const previous = signalQueuesRef.current.get(queueKey) ?? Promise.resolve();
    const task = previous.catch(() => undefined).then(operation);
    signalQueuesRef.current.set(queueKey, task);
    const cleanup = () => {
      if (signalQueuesRef.current.get(queueKey) === task) {
        signalQueuesRef.current.delete(queueKey);
      }
    };
    void task.then(cleanup, cleanup);
    return task;
  }, []);

  const openDirectChannel = useCallback(async (
    targetPeerId: string,
    timeoutMs = 8000,
    mode: PeerTransportMode = "auto",
    purpose: PeerChannelPurpose = "interactive",
  ): Promise<RTCDataChannel> => {
    const scopeKey = connectionScopeRef.current;
    const key = peerChannelKey(targetPeerId, mode, purpose);
    const configurationKey = peerTransportConfigurationKey(iceConfigRef.current, mode);
    if (!activePeerIdsRef.current.has(targetPeerId)) {
      throw new Error("对方设备已离线");
    }
    if (mode === "relay" && !hasTurnIceServer(iceConfigRef.current)) {
      throw new Error("TURN 中继不可用");
    }
    const existing = dataChannelsRef.current.get(key);
    const existingMetadata = existing ? dataChannelMetadataRef.current.get(existing) : undefined;
    const existingMatchesConfiguration = existing
      && existingMetadata?.scopeKey === scopeKey
      && existingMetadata.configurationKey === configurationKey;
    if (existing && !existingMatchesConfiguration) {
      closeDataChannel(targetPeerId, existing,
        existingMetadata?.scopeKey === scopeKey ? "ICE configuration refreshed" : "room changed", true);
    }
    if (existingMatchesConfiguration && existing.readyState === "open") {
      return existing;
    }
    if (existingMatchesConfiguration && existing.readyState === "connecting") {
      const opened = await waitForDataChannelOpen(existing, timeoutMs);
      if (!isCurrentDataChannel(targetPeerId, opened, scopeKey)) {
        throw new Error("room changed");
      }
      return opened;
    }
    const opening = openingChannelsRef.current.get(key);
    const openingMetadata = openingChannelMetadataRef.current.get(key);
    if (opening
      && openingMetadata?.scopeKey === scopeKey
      && openingMetadata.configurationKey === configurationKey) {
      return opening;
    }
    openingChannelsRef.current.delete(key);
    openingChannelMetadataRef.current.delete(key);
    const connection = createPeerConnection(targetPeerId, mode);
    const hasChannels = [...dataChannelsRef.current.values()].some((candidate) => {
      const metadata = dataChannelMetadataRef.current.get(candidate);
      return metadata?.peerId === targetPeerId && metadata.mode === mode && metadata.scopeKey === scopeKey;
    });
    const channel = connection.createDataChannel(peerChannelLabel(purpose), { ordered: true });
    setupDataChannel(targetPeerId, channel, mode, purpose);
    if (!hasChannels) {
      const companionPurpose: PeerChannelPurpose = purpose === "interactive" ? "bulk" : "interactive";
      const companion = connection.createDataChannel(peerChannelLabel(companionPurpose), { ordered: true });
      setupDataChannel(targetPeerId, companion, mode, companionPurpose);
    }
    const openingTask = (async () => {
      await enqueueSignalingOperation(scopeKey, targetPeerId, mode, async () => {
        makingOfferConnectionsRef.current.add(connection);
        try {
          const offer = await connection.createOffer();
          if (!isCurrentPeerConnection(targetPeerId, connection, scopeKey)
            || !isCurrentDataChannel(targetPeerId, channel, scopeKey)) {
            throw new Error("room changed");
          }
          await connection.setLocalDescription(offer);
          if (!isCurrentPeerConnection(targetPeerId, connection, scopeKey)
            || !isCurrentDataChannel(targetPeerId, channel, scopeKey)) {
            throw new Error("room changed");
          }
          sendSignal(targetPeerId, {
            signalType: "offer",
            transportMode: mode,
            description: connection.localDescription ?? offer,
          });
        } finally {
          makingOfferConnectionsRef.current.delete(connection);
        }
      });
      const openedChannel = await waitForDataChannelOpen(channel, timeoutMs);
      if (!isCurrentPeerConnection(targetPeerId, connection, scopeKey)
        || !isCurrentDataChannel(targetPeerId, openedChannel, scopeKey)) {
        throw new Error("room changed");
      }
      return openedChannel;
    })();
    const metadata = {
      key,
      peerId: targetPeerId,
      scopeKey,
      mode,
      purpose,
      configurationKey,
    };
    openingChannelsRef.current.set(key, openingTask);
    openingChannelMetadataRef.current.set(key, metadata);
    try {
      return await openingTask;
    } catch (error) {
      const transportKey = peerTransportKey(targetPeerId, mode);
      if (peerConnectionsRef.current.get(transportKey) === connection) {
        peerConnectionsRef.current.delete(transportKey);
        peerConnectionMetadataRef.current.delete(connection);
        connection.onicecandidate = null;
        connection.ondatachannel = null;
        connection.onconnectionstatechange = null;
        connection.close();
      }
      for (const candidate of [...dataChannelsRef.current.values()]) {
        const candidateMetadata = dataChannelMetadataRef.current.get(candidate);
        if (candidateMetadata?.peerId === targetPeerId && candidateMetadata.mode === mode) {
          closeDataChannel(targetPeerId, candidate, `${mode} channel open failed`, true);
        }
      }
      throw error;
    } finally {
      if (openingChannelsRef.current.get(key) === openingTask) {
        openingChannelsRef.current.delete(key);
        openingChannelMetadataRef.current.delete(key);
      }
    }
  }, [closeDataChannel, createPeerConnection, enqueueSignalingOperation,
    isCurrentDataChannel, isCurrentPeerConnection, sendSignal, setupDataChannel]);

  const flushPendingIceCandidates = useCallback(async (
    sourcePeerId: string,
    connection: RTCPeerConnection,
    scopeKey: string,
  ) => {
    const pending = pendingIceCandidatesRef.current.get(connection);
    pendingIceCandidatesRef.current.delete(connection);
    for (const candidate of pending ?? []) {
      if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
        return;
      }
      try {
        await connection.addIceCandidate(candidate);
      } catch {
        // Candidates from an ignored glare offer can be stale. Continue so a later relay
        // candidate belonging to the accepted description is still installed.
      }
    }
  }, [isCurrentPeerConnection]);

  const processSignal = useCallback(async (
    sourcePeerId: string,
    payload: DirectTransferSignalPayload,
    scopeKey: string,
    mode: PeerTransportMode,
  ) => {
    if (connectionScopeRef.current !== scopeKey || !activePeerIdsRef.current.has(sourcePeerId)) {
      return;
    }
    let connection = createPeerConnection(sourcePeerId, mode);
    try {
      if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
        return;
      }
      if (payload.signalType === "offer" && payload.description) {
        const selfPeerId = optionsRef.current.selfPeerId ?? "";
        const polite = !selfPeerId || selfPeerId.localeCompare(sourcePeerId) > 0;
        const offerCollision = makingOfferConnectionsRef.current.has(connection)
          || connection.signalingState !== "stable";
        if (offerCollision && !polite) {
          return;
        }
        if (offerCollision && connection.signalingState !== "stable") {
          try {
            await connection.setLocalDescription({ type: "rollback" });
          } catch {
            // Older WebKit builds do not implement rollback reliably. Replacing the
            // colliding connection still lets the remote offer establish a clean path.
            const pendingCandidates = pendingIceCandidatesRef.current.get(connection);
            pendingIceCandidatesRef.current.delete(connection);
            connection.close();
            connection = createPeerConnection(sourcePeerId, mode);
            if (pendingCandidates?.length) {
              pendingIceCandidatesRef.current.set(connection, pendingCandidates);
            }
          }
        }
        await connection.setRemoteDescription(payload.description);
        if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
          return;
        }
        await flushPendingIceCandidates(sourcePeerId, connection, scopeKey);
        const answer = await connection.createAnswer();
        if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
          return;
        }
        await connection.setLocalDescription(answer);
        if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
          return;
        }
        sendSignal(sourcePeerId, {
          signalType: "answer",
          transportMode: mode,
          description: connection.localDescription ?? answer,
        });
        return;
      }
      if (payload.signalType === "answer" && payload.description) {
        if (connection.signalingState === "have-local-offer") {
          await connection.setRemoteDescription(payload.description);
          if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
            return;
          }
          await flushPendingIceCandidates(sourcePeerId, connection, scopeKey);
        }
        return;
      }
      if (payload.signalType === "ice" && payload.candidate) {
        if (!connection.remoteDescription) {
          const pending = pendingIceCandidatesRef.current.get(connection) ?? [];
          if (pending.length >= MAX_PENDING_ICE_CANDIDATES) {
            pending.shift();
          }
          pending.push(payload.candidate);
          pendingIceCandidatesRef.current.set(connection, pending);
          return;
        }
        try {
          await connection.addIceCandidate(payload.candidate);
        } catch {
          // A stale candidate can remain after glare rollback; valid later candidates continue.
        }
      }
    } catch (error) {
      if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
        return;
      }
      throw error;
    }
  }, [createPeerConnection, flushPendingIceCandidates, isCurrentPeerConnection, sendSignal]);

  const handleSignal = useCallback((
    sourcePeerId: string,
    payload: DirectTransferSignalPayload,
  ): Promise<void> => {
    if (!payload.signalType || !activePeerIdsRef.current.has(sourcePeerId)) {
      return Promise.resolve();
    }
    const scopeKey = connectionScopeRef.current;
    const mode = normalizePeerTransportMode(payload.transportMode);
    return enqueueSignalingOperation(scopeKey, sourcePeerId, mode,
      () => processSignal(sourcePeerId, payload, scopeKey, mode));
  }, [enqueueSignalingOperation, processSignal]);

  useEffect(() => {
    if (!options.preconnectPeerChannels || !options.selfPeerId || typeof RTCPeerConnection === "undefined") {
      return;
    }
    const selfPeerId = options.selfPeerId;
    for (const peer of options.peers) {
      if (selfPeerId.localeCompare(peer.peerId) < 0) {
        void openDirectChannel(peer.peerId, 10000, "direct").catch(() => {
          // Whiteboard traffic will retry Direct before falling back to TURN and WebSocket.
        });
      }
    }
  }, [openDirectChannel, options.peers, options.preconnectPeerChannels, options.selfPeerId]);

  const isPeerMessageTransportReady = useCallback((targetPeerId: string, mode: PeerTransportMode) => {
    const channel = dataChannelsRef.current.get(peerChannelKey(targetPeerId, mode, "interactive"));
    return Boolean(channel
      && channel.readyState === "open"
      && isCurrentDataChannel(targetPeerId, channel, connectionScopeRef.current));
  }, [isCurrentDataChannel]);

  const sendPeerMessage = useCallback(async (
    targetPeerId: string,
    message: DirectPeerMessage,
    timeoutMs = 1600,
    mode: PeerTransportMode = "auto",
  ): Promise<boolean> => {
    if (!targetPeerId || typeof RTCPeerConnection === "undefined") {
      return false;
    }
    const scopeKey = connectionScopeRef.current;
    let acknowledgement: Promise<void> | null = null;
    let messageId = "";
    try {
      const channel = await openDirectChannel(targetPeerId, timeoutMs, mode, "interactive");
      if (!isCurrentDataChannel(targetPeerId, channel, scopeKey) || channel.readyState !== "open") {
        return false;
      }
      const connection = peerConnectionsRef.current.get(peerTransportKey(targetPeerId, mode));
      const encoded = await encodeAppMessage(message, appMaximumFrameBytes(connection));
      messageId = encoded.messageId;
      channel.bufferedAmountLowThreshold = 256 * 1024;
      for (let index = 0; index < encoded.frames.length; index += 1) {
        const frame = encoded.frames[index];
        while (channel.bufferedAmount > 1024 * 1024) {
          await waitForBufferedAmountLow(channel, Math.max(1000, timeoutMs));
        }
        if (!isCurrentDataChannel(targetPeerId, channel, scopeKey) || channel.readyState !== "open") {
          throw new Error("interactive channel changed");
        }
        if (encoded.acknowledgementRequired && index === encoded.frames.length - 1) {
          acknowledgement = waitForAppAck(
            encoded.messageId, targetPeerId, scopeKey, Math.max(4000, timeoutMs), channel);
        }
        channel.send(frame);
      }
      if (acknowledgement) await acknowledgement;
      return true;
    } catch {
      if (messageId) cancelAppAck(messageId, "应用消息发送失败");
      if (acknowledgement) await acknowledgement.catch(() => undefined);
      return false;
    }
  }, [cancelAppAck, isCurrentDataChannel, openDirectChannel, waitForAppAck]);

  const sendRelayPeerMessage = useCallback(async (
    targetPeerId: string,
    message: DirectPeerMessage,
    sendFrame: (frame: ArrayBuffer) => void,
    timeoutMs = 5000,
  ): Promise<boolean> => {
    if (!targetPeerId || !activePeerIdsRef.current.has(targetPeerId)) return false;
    const scopeKey = connectionScopeRef.current;
    let acknowledgement: Promise<void> | null = null;
    let messageId = "";
    try {
      const encoded = await encodeAppMessage(message);
      messageId = encoded.messageId;
      for (let index = 0; index < encoded.frames.length; index += 1) {
        const frame = encoded.frames[index];
        if (connectionScopeRef.current !== scopeKey || !activePeerIdsRef.current.has(targetPeerId)) {
          throw new Error("room changed");
        }
        if (encoded.acknowledgementRequired && index === encoded.frames.length - 1) {
          acknowledgement = waitForAppAck(encoded.messageId, targetPeerId, scopeKey, timeoutMs);
        }
        sendFrame(frame);
      }
      if (acknowledgement) await acknowledgement;
      return true;
    } catch {
      if (messageId) cancelAppAck(messageId, "应用消息发送失败");
      if (acknowledgement) await acknowledgement.catch(() => undefined);
      return false;
    }
  }, [cancelAppAck, waitForAppAck]);

  const handleRelayPeerFrame = useCallback((
    sourcePeerId: string,
    frame: ArrayBuffer,
    sendReply: (targetPeerId: string, frame: ArrayBuffer) => void,
  ) => handleAppBinaryMessage(sourcePeerId, frame, connectionScopeRef.current,
    (reply) => sendReply(sourcePeerId, reply)), [handleAppBinaryMessage]);

  /** The pre-resume flow: whole-file SHA-256, raw 64 KiB buffers, receiver memory only. */
  const sendDirectLegacy = useCallback(async (
    targetPeerId: string,
    file: File,
    mode: PeerTransportMode = "auto",
    signal?: AbortSignal,
  ): Promise<DirectTransferResult> => {
    const limitBytes = optionsRef.current.directMemoryLimitBytes;
    if (typeof RTCPeerConnection === "undefined") {
      throw new Error("当前浏览器不支持直连");
    }
    if (file.size > limitBytes) {
      throw new Error(`文件超过直连上限 ${formatTransferBytes(limitBytes)}`);
    }
    optionsRef.current.onStateChange("connecting");
    optionsRef.current.onProgress(0);
    const scopeKey = connectionScopeRef.current;
    let channel: RTCDataChannel | null = null;
    let transferId = "";
    try {
      channel = await openDirectChannel(targetPeerId, fileChannelOpenTimeoutMs(mode), mode, "bulk");
      const usedConnection = peerConnectionsRef.current.get(peerTransportKey(targetPeerId, mode));
      if (usedConnection) {
        recordTransportPath(targetPeerId, usedConnection, scopeKey);
      }
      const ensureCurrentChannel = () => {
        if (signal?.aborted) {
          throw new Error("文件发送已取消");
        }
        if (!channel
          || !isCurrentDataChannel(targetPeerId, channel, scopeKey)
          || channel.readyState !== "open") {
          throw new Error("发送过程中房间或对方设备已变化");
        }
      };
      ensureCurrentChannel();
      transferId = createTransferId();
      const fileName = file.name || "attachment";
      const mimeType = effectiveMimeType(fileName, file.type);
      const sha256 = await sha256Blob(file, signal);
      ensureCurrentChannel();
      optionsRef.current.onStateChange("waiting");
      channel.send(JSON.stringify({
        kind: "file-meta",
        transferId,
        fileName,
        mimeType,
        sizeBytes: file.size,
        sha256,
      }));
      await waitForDirectAck(targetPeerId, channel, scopeKey, transferId, 120000, "对方未确认接收");
      ensureCurrentChannel();
      optionsRef.current.onStateChange("direct");
      await sendFileChunks(channel, file, optionsRef.current.onProgress, ensureCurrentChannel, signal);
      ensureCurrentChannel();
      channel.send(JSON.stringify({ kind: "file-complete", transferId }));
      // Slow TURN paths can retain several MiB after send() returns. Start the final
      // acknowledgement timer only after SCTP has accepted the complete payload.
      await waitForDataChannelDrain(channel, 60_000, signal);
      ensureCurrentChannel();
      await waitForDirectAck(targetPeerId, channel, scopeKey, transferId, 60000, "对方未确认完成");

      return {
        attachment: directAttachment(transferId, fileName, mimeType, file.size, sha256),
        previewUrl: URL.createObjectURL(file),
      };
    } catch (error) {
      if (channel) {
        if (transferId && channel.readyState === "open") {
          channel.send(JSON.stringify({ kind: "file-cancel", transferId }));
        }
        closeDataChannel(targetPeerId, channel, `${mode} file transfer failed`, true);
      }
      throw error;
    }
  }, [closeDataChannel, isCurrentDataChannel, openDirectChannel,
    recordTransportPath, waitForDirectAck]);

  const dropOutgoing = useCallback((transfer: OutgoingTransfer) => {
    if (outgoingRef.current.get(transfer.transferId) === transfer) {
      outgoingRef.current.delete(transfer.transferId);
    }
    void openResumeStore().then((store) => store?.deleteSend(transfer.transferId)).catch(() => undefined);
    refreshOutgoingView(true);
  }, [openResumeStore, refreshOutgoingView]);

  outgoingCancelHandlerRef.current = (transfer) => {
    dropOutgoing(transfer);
    optionsRef.current.onNotice?.(`对方已放弃接收 ${transfer.manifest.fileName}，未完成的发送已删除`);
  };

  /** Runs sendResumable for one transfer over `mode`, with in-session reconnects (§9). */
  const runResumable = useCallback(async (params: {
    targetPeerId: string;
    source: Blob;
    lastModified: number;
    fileName: string;
    fileType: string;
    existing: OutgoingTransfer | null;
    mode: PeerTransportMode;
    signal?: AbortSignal;
    background: boolean;
    onTransfer?: (transfer: OutgoingTransfer) => void;
    onPhase: (phase: "waiting" | "sending") => void;
    onProgress: (transfer: OutgoingTransfer) => void;
  }) => {
    const scopeKey = connectionScopeRef.current;
    const { targetPeerId, signal } = params;
    const targetName = optionsRef.current.peers.find((peer) => peer.peerId === targetPeerId)?.displayName ?? "";
    let wake: (() => void) | null = null;
    let registeredId = "";
    const register = (transfer: OutgoingTransfer) => {
      if (registeredId) runningOutgoingRef.current.delete(registeredId);
      registeredId = transfer.transferId;
      runningOutgoingRef.current.set(transfer.transferId, { wake: () => wake?.(), background: params.background });
      outgoingRef.current.set(transfer.transferId, transfer);
      outgoingByFileRef.current.set(params.source, transfer.transferId);
      params.onTransfer?.(transfer);
      refreshOutgoingView(true);
    };
    if (params.existing) register(params.existing);
    try {
      return await sendResumable({
        source: params.source,
        lastModified: params.lastModified,
        targetPeerId,
        targetName,
        existing: params.existing,
        router: senderRouterRef.current,
        digest: sha256Digest,
        signal,
        now: () => Date.now(),
        openChannel: async (): Promise<OpenedChannel> => {
          if (connectionScopeRef.current !== scopeKey) {
            throw new Error("发送过程中房间或对方设备已变化");
          }
          const channel = await openDirectChannel(targetPeerId, fileChannelOpenTimeoutMs(params.mode), params.mode, "bulk");
          const connection = peerConnectionsRef.current.get(peerTransportKey(targetPeerId, params.mode));
          if (connection) {
            recordTransportPath(targetPeerId, connection, scopeKey);
          }
          return {
            channel,
            peerId: targetPeerId,
            frameBytes: maxFrameBytes(connection?.sctp?.maxMessageSize),
            ensureCurrent: () => {
              if (signal?.aborted) {
                throw signal.reason instanceof Error ? signal.reason : new Error("文件发送已取消");
              }
              if (connectionScopeRef.current !== scopeKey || !activePeerIdsRef.current.has(targetPeerId)) {
                throw new Error("发送过程中房间或对方设备已变化");
              }
              if (!isCurrentDataChannel(targetPeerId, channel, scopeKey) || channel.readyState !== "open") {
                throw new SenderError("DataChannel 已关闭", "retry");
              }
            },
          };
        },
        buildManifest: async () => {
          const fileName = normalizeOfferedName(params.fileName || "attachment");
          const mimeType = normalizeOfferedMimeType(effectiveMimeType(fileName, params.fileType));
          const hashes = await hashChunks(params.source, CHUNK_SIZE_DEFAULT, signal);
          return manifestFromHashes({ sizeBytes: params.source.size, chunkSize: CHUNK_SIZE_DEFAULT, fileName, mimeType, hashes });
        },
        // Direct mode hands over to relay quickly; relay and auto keep reconnecting.
        retryOpenFailures: params.mode !== "direct",
        sleep: (ms) => new Promise<void>((resolve) => {
          const done = () => {
            window.clearTimeout(timer);
            signal?.removeEventListener("abort", done);
            wake = null;
            resolve();
          };
          const timer = window.setTimeout(done, ms);
          wake = done;
          signal?.addEventListener("abort", done, { once: true });
        }),
        onTransfer: register,
        onPhase: params.onPhase,
        onProgress: (transfer) => {
          params.onProgress(transfer);
          refreshOutgoingView();
        },
        onAccepted: async (transfer) => {
          if (transfer.storage !== "persistent" || transfer.expiresAt === null || !transfer.resumeToken) {
            return;
          }
          // Only the manifest, hashes and token survive a reload; the file itself never does.
          const store = await openResumeStore();
          await store?.putSend(sendRecordOf(transfer)).catch(() => undefined);
        },
        onFinished: (transfer) => dropOutgoing(transfer),
      });
    } finally {
      if (registeredId) runningOutgoingRef.current.delete(registeredId);
      const current = registeredId ? outgoingRef.current.get(registeredId) : undefined;
      if (current?.storage === "persistent") {
        void openResumeStore()
          .then((store) => store?.patchSend(current.transferId, { acked: copyBuffer(current.acked.bytes) }))
          .catch(() => undefined);
      }
      refreshOutgoingView(true);
    }
  }, [dropOutgoing, isCurrentDataChannel, openDirectChannel, openResumeStore, recordTransportPath, refreshOutgoingView]);

  /** Abandons an outgoing transfer: file-cancel (with the token when off-session) and local deletion. */
  const abandonOutgoingTransfer = useCallback((transfer: OutgoingTransfer) => {
    for (const channel of dataChannelsRef.current.values()) {
      const metadata = dataChannelMetadataRef.current.get(channel);
      if (metadata?.peerId === transfer.targetPeerId && metadata.purpose === "bulk") {
        sendJson(channel, { kind: "file-cancel", transferId: transfer.transferId, resumeToken: transfer.resumeToken });
      }
    }
    dropOutgoing(transfer);
  }, [dropOutgoing]);

  /** Matches a file the user selected to a transfer this page started or restored. */
  const findOutgoing = useCallback((file: File, targetPeerId: string): OutgoingTransfer | null => {
    const now = Date.now();
    const known = outgoingByFileRef.current.get(file);
    const byFile = known ? outgoingRef.current.get(known) : undefined;
    if (byFile && (byFile.expiresAt === null || now < byFile.expiresAt) && !runningOutgoingRef.current.has(byFile.transferId)) {
      return byFile;
    }
    const targetName = optionsRef.current.peers.find((peer) => peer.peerId === targetPeerId)?.displayName ?? "";
    const fileName = normalizeOfferedName(file.name || "attachment");
    for (const transfer of outgoingRef.current.values()) {
      // A reselected file after a reload: same name and size, sent to the same device.
      if (transfer.source === null && transfer.resumeToken !== null
        && transfer.manifest.fileName === fileName && transfer.manifest.sizeBytes === file.size
        && (transfer.targetPeerId === targetPeerId || (targetName !== "" && transfer.targetName === targetName))
        && (transfer.expiresAt === null || now < transfer.expiresAt)
        && !runningOutgoingRef.current.has(transfer.transferId)) {
        return transfer;
      }
    }
    return null;
  }, []);

  const sendDirect = useCallback(async (
    targetPeerId: string,
    file: File,
    mode: PeerTransportMode = "auto",
    signal?: AbortSignal,
  ): Promise<DirectTransferResult> => {
    if (!directResumeSupported()) {
      return sendDirectLegacy(targetPeerId, file, mode, signal);
    }
    if (typeof RTCPeerConnection === "undefined") {
      throw new Error("当前浏览器不支持直连");
    }
    if (file.size > DIRECT_RESUMABLE_LIMIT_BYTES) {
      throw new Error(`文件超过直连上限 ${formatTransferBytes(DIRECT_RESUMABLE_LIMIT_BYTES)}`);
    }
    optionsRef.current.onStateChange("connecting");
    optionsRef.current.onProgress(0);
    const scopeKey = connectionScopeRef.current;
    const reportProgress = createProgressReporter(optionsRef.current.onProgress);
    let active: OutgoingTransfer | null = findOutgoing(file, targetPeerId);
    try {
      const result = await runResumable({
        targetPeerId,
        source: file,
        lastModified: file.lastModified,
        fileName: file.name,
        fileType: file.type,
        existing: active,
        mode,
        signal,
        background: false,
        onTransfer: (transfer) => {
          active = transfer;
        },
        onPhase: (phase) => optionsRef.current.onStateChange(phase === "waiting" ? "waiting" : "direct"),
        onProgress: (transfer) => {
          active = transfer;
          const total = transfer.manifest.sizeBytes;
          reportProgress(total > 0 ? (ackedBytesOf(transfer) / total) * 100 : 100, ackedBytesOf(transfer) >= total);
        },
      });
      active = result.transfer;
      const { manifest } = result.transfer;
      if (result.kind === "legacy") {
        // An old page answered file-ready: it ignores `resume` and receives the raw stream into
        // memory, so only files within its memory limit can go this way (§12).
        const { channel, ensureCurrent } = result.channel;
        if (file.size > MEMORY_LIMIT_BYTES) {
          sendJson(channel, { kind: "file-cancel", transferId: result.transfer.transferId });
          throw new SenderError("对方页面版本较旧，不支持 128 MiB 以上的设备传输，请让对方刷新页面后重试", "drop", "LEGACY_TOO_LARGE");
        }
        const rtcChannel = channel as RTCDataChannel;
        const legacyTransferId = result.transfer.transferId;
        try {
          optionsRef.current.onStateChange("direct");
          await sendFileChunks(rtcChannel, file, optionsRef.current.onProgress, ensureCurrent, signal);
          ensureCurrent();
          // Without a whole-file digest the old page acknowledges right away: listen before
          // file-complete leaves so the acknowledgement cannot arrive before the waiter.
          const acknowledged = waitForDirectAck(targetPeerId, rtcChannel, scopeKey, legacyTransferId, 120_000, "对方未确认完成");
          acknowledged.catch(() => undefined);
          rtcChannel.send(JSON.stringify({ kind: "file-complete", transferId: legacyTransferId }));
          await waitForDataChannelDrain(rtcChannel, 60_000, signal);
          ensureCurrent();
          await acknowledged;
        } catch (error) {
          sendJson(rtcChannel, { kind: "file-cancel", transferId: legacyTransferId });
          closeDataChannel(targetPeerId, rtcChannel, `${mode} file transfer failed`, true);
          throw error;
        }
      }
      reportProgress(100, true);
      return {
        attachment: directAttachment(result.transfer.transferId, manifest.fileName, manifest.mimeType, manifest.sizeBytes, null),
        previewUrl: URL.createObjectURL(file),
      };
    } catch (error) {
      if (signal?.aborted) {
        // The user's cancel abandons the transfer; a room change or page teardown only pauses it.
        if (signal.reason === DIRECT_SEND_USER_CANCEL && active) {
          abandonOutgoingTransfer(active);
        }
        throw new Error("文件发送已取消");
      }
      if (error instanceof SenderError && error.code === "LEGACY_REJECT" && file.size > MEMORY_LIMIT_BYTES) {
        throw new SenderError("对方页面不支持 128 MiB 以上的设备传输，请让对方刷新页面后重试", "drop", "LEGACY_TOO_LARGE");
      }
      throw error;
    }
  }, [abandonOutgoingTransfer, closeDataChannel, findOutgoing, runResumable, sendDirectLegacy, waitForDirectAck]);

  /** Resumes a paused transfer outside the page's send queue (from the list or a resume-request). */
  const runBackgroundResume = useCallback(async (transfer: OutgoingTransfer, targetPeerId: string) => {
    if (!transfer.source || runningOutgoingRef.current.has(transfer.transferId)) return;
    const fileName = transfer.manifest.fileName;
    try {
      await runResumable({
        targetPeerId,
        source: transfer.source,
        lastModified: transfer.lastModified,
        fileName,
        fileType: transfer.manifest.mimeType,
        existing: transfer,
        mode: "auto",
        background: true,
        onPhase: () => undefined,
        onProgress: () => undefined,
      });
      optionsRef.current.onNotice?.(`${fileName} 已续传完成，对方已收到`);
    } catch (error) {
      optionsRef.current.onError(`${fileName} 续传未完成：${error instanceof Error ? error.message : "未知错误"}`);
    }
  }, [runResumable]);

  resumeRequestHandlerRef.current = (peerId: string, transferId: string) => {
    const transfer = outgoingRef.current.get(transferId);
    if (!transfer?.resumeToken) return;
    const running = runningOutgoingRef.current.get(transferId);
    if (running) {
      running.wake(); // skip the remaining backoff: the receiver is back
      return;
    }
    if (!transfer.source) {
      if (!resumeRequestNoticesRef.current.has(transferId)) {
        resumeRequestNoticesRef.current.add(transferId);
        optionsRef.current.onNotice?.(`对方请求继续接收 ${transfer.manifest.fileName}，请在“未完成的发送”中重新选择该文件`);
      }
      return;
    }
    void runBackgroundResume(transfer, peerId);
  };

  const resumeOutgoing = useCallback(async (transferId: string, file?: File) => {
    const transfer = outgoingRef.current.get(transferId);
    if (!transfer) return;
    if (file) {
      // §7: a reselected file of another size is refused before any handshake.
      if (file.size !== transfer.manifest.sizeBytes) {
        throw new SourceSizeMismatchError();
      }
      transfer.source = file;
      outgoingByFileRef.current.set(file, transferId);
    }
    if (!transfer.source) {
      throw new Error("请重新选择原文件后继续发送");
    }
    const peers = optionsRef.current.peers;
    const target = peers.find((peer) => peer.peerId === transfer.targetPeerId)
      ?? peers.find((peer) => transfer.targetName !== "" && peer.displayName === transfer.targetName);
    if (!target) {
      throw new Error(`接收设备 ${transfer.targetName || ""} 不在线，请等对方打开页面后再继续`);
    }
    await runBackgroundResume(transfer, target.peerId);
  }, [runBackgroundResume]);

  const abandonOutgoing = useCallback((transferId: string) => {
    const transfer = outgoingRef.current.get(transferId);
    if (transfer && !runningOutgoingRef.current.has(transferId)) {
      abandonOutgoingTransfer(transfer);
    }
  }, [abandonOutgoingTransfer]);

  const bulkChannelsTo = useCallback((peerId: string): RTCDataChannel[] => [...dataChannelsRef.current.values()]
    .filter((channel) => {
      const metadata = dataChannelMetadataRef.current.get(channel);
      return metadata?.peerId === peerId && metadata.purpose === "bulk" && channel.readyState === "open";
    }), []);

  const abandonStoredReceive = useCallback((transferId: string) => {
    const receiver = receiverRef.current;
    const entry = receiver?.snapshot().entries.find((item) => item.transferId === transferId);
    void receiver?.abandon(transferId, entry ? bulkChannelsTo(entry.sourcePeerId) : []);
  }, [bulkChannelsTo]);

  const markDirectSaved = useCallback((transferId: string) => {
    void receiverRef.current?.markSaved(transferId);
  }, []);

  /** "清除互传本地数据": every receive record and chunk plus every paused send record. */
  const clearResumeData = useCallback(async () => {
    await getReceiver().clearAll();
    for (const transfer of [...outgoingRef.current.values()]) {
      if (!runningOutgoingRef.current.has(transfer.transferId)) {
        outgoingRef.current.delete(transfer.transferId);
      }
    }
    const store = await openResumeStore();
    await store?.clear().catch(() => undefined);
    refreshOutgoingView(true);
  }, [getReceiver, openResumeStore, refreshOutgoingView]);

  const cleanupOutgoing = useCallback(async () => {
    const now = Date.now();
    const store = await openResumeStore();
    for (const transfer of [...outgoingRef.current.values()]) {
      if (transfer.expiresAt !== null && now >= transfer.expiresAt && !runningOutgoingRef.current.has(transfer.transferId)) {
        outgoingRef.current.delete(transfer.transferId);
        await store?.deleteSend(transfer.transferId).catch(() => undefined);
      }
    }
    for (const record of await store?.listSends().catch(() => [] as SendRecord[]) ?? []) {
      if (now >= record.expiresAt) {
        await store?.deleteSend(record.transferId).catch(() => undefined);
      }
    }
    refreshOutgoingView(true);
  }, [openResumeStore, refreshOutgoingView]);

  // Page load: clean up, restore interrupted receives, completed-unsaved files and paused sends.
  // Cleanup also runs whenever the page returns to the foreground; nothing can run while closed.
  useEffect(() => {
    if (!directResumeSupported()) {
      return undefined;
    }
    let cancelled = false;
    void (async () => {
      await getReceiver().restore();
      const store = await openResumeStore();
      if (!store || cancelled) return;
      const now = Date.now();
      for (const record of await store.listSends().catch(() => [] as SendRecord[])) {
        if (now >= record.expiresAt) {
          await store.deleteSend(record.transferId).catch(() => undefined);
        } else if (!outgoingRef.current.has(record.transferId)) {
          outgoingRef.current.set(record.transferId, outgoingFromRecord(record));
        }
      }
      if (!cancelled) refreshOutgoingView(true);
    })();
    const onVisible = () => {
      if (document.visibilityState === "visible") {
        void getReceiver().cleanup();
        void cleanupOutgoing();
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      cancelled = true;
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [cleanupOutgoing, getReceiver, openResumeStore, refreshOutgoingView]);

  // After a reload the receiver asks the original sender (if online) to resume (§9).
  useEffect(() => {
    const receiver = receiverRef.current;
    if (!receiver || connectionScopeRef.current.startsWith("invalidated:")) return;
    for (const target of receiver.resumeRequestTargets()) {
      if (!options.peers.some((peer) => peer.peerId === target.sourcePeerId)) continue;
      void openDirectChannel(target.sourcePeerId, AUTO_FILE_CHANNEL_OPEN_TIMEOUT_MS, "auto", "bulk")
        .then((channel) => receiver.sendResumeRequest(channel, target.transferId))
        .catch(() => undefined);
    }
  }, [openDirectChannel, options.peers, resumeSnapshot]);

  const resumePending = resumeSnapshot.pending;
  const resumeEntries = resumeSnapshot.entries;
  const allPendingTransfers = useMemo<DirectPendingTransfer[]>(() => (resumePending.length === 0
    ? pendingTransfers
    : [...pendingTransfers, ...resumePending.map((item) => ({
      transferId: item.transferId,
      sourcePeerId: item.sourcePeerId,
      fileName: item.fileName,
      mimeType: item.mimeType,
      sizeBytes: item.sizeBytes,
      storage: item.storage,
      memoryReason: item.memoryReason,
    }))]), [pendingTransfers, resumePending]);
  const allReceivingTransfers = useMemo<DirectReceivingTransfer[]>(() => {
    const active = resumeEntries.filter((item) => item.active && item.state !== "COMPLETE");
    return active.length === 0 ? receivingTransfers : [...active.map((item) => ({
      transferId: item.transferId,
      sourcePeerId: item.sourcePeerId,
      fileName: item.fileName,
      mimeType: item.mimeType,
      sizeBytes: item.sizeBytes,
      receivedBytes: item.receivedBytes,
      storage: item.storage,
    })), ...receivingTransfers];
  }, [receivingTransfers, resumeEntries]);
  const storedReceives = useMemo<DirectStoredReceive[]>(() => resumeEntries
    .filter((item) => !item.active && item.state === "INTERRUPTED")
    .map((item) => ({
      transferId: item.transferId,
      sourcePeerId: item.sourcePeerId,
      sourceName: item.sourceName,
      fileName: item.fileName,
      sizeBytes: item.sizeBytes,
      receivedBytes: item.receivedBytes,
      expiresAt: item.expiresAt,
      storage: item.storage,
    })), [resumeEntries]);

  return {
    pendingTransfers: allPendingTransfers,
    receivingTransfers: allReceivingTransfers,
    storedReceives,
    outgoingResumes,
    resumeOutgoing,
    abandonOutgoing,
    abandonStoredReceive,
    markDirectSaved,
    clearResumeData,
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
  };
}

export function receivingTransferKey(item: Pick<DirectReceivingTransfer, "sourcePeerId" | "transferId">) {
  return `${item.sourcePeerId}:${item.transferId}`;
}

function ackedBytesOf(transfer: OutgoingTransfer): number {
  const { sizeBytes, chunkSize } = transfer.manifest;
  let total = 0;
  for (const index of transfer.acked.indexes()) {
    total += chunkLengthOf(sizeBytes, chunkSize, index);
  }
  return total;
}

function sendRecordOf(transfer: OutgoingTransfer): SendRecord {
  const { manifest } = transfer;
  return {
    transferId: transfer.transferId,
    manifestDigest: toHex(manifest.manifestDigest),
    resumeToken: transfer.resumeToken ?? "",
    expiresAt: transfer.expiresAt ?? 0,
    targetPeerId: transfer.targetPeerId,
    targetName: transfer.targetName,
    fileName: manifest.fileName,
    mimeType: manifest.mimeType,
    sizeBytes: manifest.sizeBytes,
    lastModified: transfer.lastModified,
    chunkSize: manifest.chunkSize,
    chunkCount: manifest.chunkCount,
    rootSha256: toHex(manifest.rootSha256),
    hashes: copyBuffer(manifest.hashes),
    acked: copyBuffer(transfer.acked.bytes),
  };
}

/** A send restored after a reload: everything but the file, which the user must select again. */
function outgoingFromRecord(record: SendRecord): OutgoingTransfer {
  return {
    transferId: record.transferId,
    manifest: {
      sizeBytes: record.sizeBytes,
      chunkSize: record.chunkSize,
      chunkCount: record.chunkCount,
      fileName: record.fileName,
      mimeType: record.mimeType,
      hashes: new Uint8Array(record.hashes),
      rootSha256: fromHex(record.rootSha256),
      manifestDigest: fromHex(record.manifestDigest),
    },
    source: null,
    lastModified: record.lastModified,
    targetPeerId: record.targetPeerId,
    targetName: record.targetName,
    resumeToken: record.resumeToken,
    storage: "persistent",
    expiresAt: record.expiresAt,
    acked: new ChunkBitmap(record.chunkCount, record.acked ? new Uint8Array(record.acked) : undefined),
    confirmedPeers: new Set(),
    offered: true,
  };
}

function peerTransportKey(peerId: string, mode: PeerTransportMode) {
  return JSON.stringify([peerId, mode]);
}

function peerChannelKey(peerId: string, mode: PeerTransportMode, purpose: PeerChannelPurpose) {
  return JSON.stringify([peerId, mode, purpose]);
}

function peerChannelLabel(purpose: PeerChannelPurpose) {
  return `specus-v2-${purpose}`;
}

function channelPurposeFromLabel(label: string): PeerChannelPurpose | null {
  if (label === peerChannelLabel("interactive")) return "interactive";
  if (label === peerChannelLabel("bulk")) return "bulk";
  return null;
}

async function detectPeerTransportPath(connection: RTCPeerConnection): Promise<PeerTransportPath | null> {
  try {
    const stats = await connection.getStats();
    const reports = new Map<string, Record<string, unknown>>();
    stats.forEach((report) => reports.set(report.id, report as unknown as Record<string, unknown>));
    let selectedPair: Record<string, unknown> | undefined;
    for (const report of reports.values()) {
      if (report.type === "transport" && typeof report.selectedCandidatePairId === "string") {
        selectedPair = reports.get(report.selectedCandidatePairId);
        if (selectedPair) {
          break;
        }
      }
    }
    if (!selectedPair) {
      // Firefox 不上报 transport.selectedCandidatePairId，退回 nominated 成功的候选对。
      for (const report of reports.values()) {
        if (report.type === "candidate-pair" && report.state === "succeeded" && report.nominated === true) {
          selectedPair = report;
          break;
        }
      }
    }
    if (!selectedPair) {
      return null;
    }
    const local = typeof selectedPair.localCandidateId === "string" ? reports.get(selectedPair.localCandidateId) : undefined;
    const remote = typeof selectedPair.remoteCandidateId === "string" ? reports.get(selectedPair.remoteCandidateId) : undefined;
    if (!local && !remote) {
      return null;
    }
    return local?.candidateType === "relay" || remote?.candidateType === "relay" ? "turn" : "direct";
  } catch {
    return null;
  }
}

function peerTransportConfigurationKey(config: PublicTransferIceConfig | null, mode: PeerTransportMode) {
  return JSON.stringify(buildPeerRtcConfiguration(config, mode));
}

function directAttachment(transferId: string, fileName: string, mimeType: string, sizeBytes: number, sha256?: string | null): TransferAttachment {
  return {
    attachmentId: 0,
    objectId: `direct:${transferId}`,
    fileName,
    mimeType,
    sizeBytes,
    sha256: sha256 || null,
    status: "DIRECT",
    expiresAt: "",
  };
}

function fileChannelOpenTimeoutMs(mode: PeerTransportMode) {
  if (mode === "direct") return DIRECT_FILE_CHANNEL_OPEN_TIMEOUT_MS;
  if (mode === "relay") return TURN_FILE_CHANNEL_OPEN_TIMEOUT_MS;
  return AUTO_FILE_CHANNEL_OPEN_TIMEOUT_MS;
}

function waitForDataChannelOpen(channel: RTCDataChannel, timeoutMs: number): Promise<RTCDataChannel> {
  if (channel.readyState === "open") {
    return Promise.resolve(channel);
  }
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => {
      cleanup();
      reject(new Error("DataChannel 打开超时"));
    }, timeoutMs);
    const cleanup = () => {
      window.clearTimeout(timer);
      channel.removeEventListener("open", onOpen);
      channel.removeEventListener("error", onError);
      channel.removeEventListener("close", onClose);
    };
    const onOpen = () => {
      cleanup();
      resolve(channel);
    };
    const onError = () => {
      cleanup();
      reject(new Error("DataChannel 连接失败"));
    };
    const onClose = () => {
      cleanup();
      reject(new Error("DataChannel 已关闭"));
    };
    channel.addEventListener("open", onOpen);
    channel.addEventListener("error", onError);
    channel.addEventListener("close", onClose);
  });
}

async function sendFileChunks(
  channel: RTCDataChannel,
  file: File,
  onProgress: (value: number) => void,
  ensureCurrentChannel: () => void,
  signal?: AbortSignal,
) {
  const reportProgress = createProgressReporter(onProgress);
  ensureCurrentChannel();
  if (file.size === 0) {
    reportProgress(100, true);
    return;
  }
  const chunkSize = 64 * 1024;
  channel.bufferedAmountLowThreshold = 1024 * 1024;
  for (let offset = 0; offset < file.size; offset += chunkSize) {
    ensureCurrentChannel();
    if (channel.readyState !== "open") {
      throw new Error("DataChannel 已关闭");
    }
    while (channel.bufferedAmount > 4 * 1024 * 1024) {
      await waitForBufferedAmountLow(channel, DATA_CHANNEL_BACKPRESSURE_TIMEOUT_MS, signal);
      ensureCurrentChannel();
    }
    const end = Math.min(file.size, offset + chunkSize);
    const buffer = await file.slice(offset, end).arrayBuffer();
    ensureCurrentChannel();
    channel.send(buffer);
    reportProgress(Math.round((end / file.size) * 100), end >= file.size);
  }
}

function waitForBufferedAmountLow(
  channel: RTCDataChannel,
  timeoutMs = DATA_CHANNEL_BACKPRESSURE_TIMEOUT_MS,
  signal?: AbortSignal,
) {
  if (channel.bufferedAmount <= channel.bufferedAmountLowThreshold) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      cleanup();
      reject(new Error("DataChannel 发送缓冲区等待超时"));
    }, timeoutMs);
    const cleanup = () => {
      window.clearTimeout(timer);
      channel.removeEventListener("bufferedamountlow", onLow);
      channel.removeEventListener("close", onClose);
      signal?.removeEventListener("abort", onAbort);
    };
    const onLow = () => {
      cleanup();
      resolve();
    };
    const onClose = () => {
      cleanup();
      reject(new Error("DataChannel 已关闭"));
    };
    const onAbort = () => {
      cleanup();
      reject(new Error("文件发送已取消"));
    };
    channel.addEventListener("bufferedamountlow", onLow);
    channel.addEventListener("close", onClose);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
    }
  });
}

// waitForDataChannelDrain 等发送缓冲区完全排空。慢链路（如 TURN 中继）上 bufferedAmount
// 归零远晚于 send() 返回，ack 计时必须在排空之后开始，否则接收端还没收完数据发送端就先超时。
export function waitForDataChannelDrain(
  channel: RTCDataChannel,
  timeoutMs = 60000,
  signal?: AbortSignal,
): Promise<void> {
  channel.bufferedAmountLowThreshold = 0;
  if (channel.bufferedAmount === 0) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      cleanup();
      reject(new Error("DataChannel 发送缓冲排空超时"));
    }, timeoutMs);
    const cleanup = () => {
      window.clearTimeout(timer);
      channel.removeEventListener("bufferedamountlow", onLow);
      channel.removeEventListener("close", onClose);
      signal?.removeEventListener("abort", onAbort);
    };
    const onLow = () => {
      if (channel.bufferedAmount !== 0) {
        return;
      }
      cleanup();
      resolve();
    };
    const onClose = () => {
      cleanup();
      reject(new Error("DataChannel 已关闭"));
    };
    const onAbort = () => {
      cleanup();
      reject(new Error("文件发送已取消"));
    };
    channel.addEventListener("bufferedamountlow", onLow);
    channel.addEventListener("close", onClose);
    signal?.addEventListener("abort", onAbort, { once: true });
    // 注册监听与设置阈值之间缓冲区可能已排空。
    if (channel.bufferedAmount === 0) {
      cleanup();
      resolve();
    } else if (signal?.aborted) {
      onAbort();
    }
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

function createTransferId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function formatTransferBytes(bytes: number) {
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
