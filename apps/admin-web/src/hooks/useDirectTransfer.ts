import { useCallback, useEffect, useRef, useState } from "react";
import type { PublicTransferIceConfig, TransferAttachment } from "../api/types";
import {
  buildPeerRtcConfiguration,
  hasTurnIceServer,
  normalizePeerTransportMode,
  type PeerTransportMode,
} from "../lib/directPeerTransport";
import { sha256Blob } from "../lib/sha256";
import { effectiveMimeType } from "../lib/transferPreview";

export interface DirectTransferSignalPayload {
  signalType?: "offer" | "answer" | "ice";
  transportMode?: PeerTransportMode;
  description?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
}

export interface DirectPeerMessage {
  messageType: string;
  payload?: unknown;
}

export interface DirectTransferPeer {
  peerId: string;
  displayName: string;
}

export interface DirectReceivingTransfer {
  transferId: string;
  sourcePeerId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  receivedBytes: number;
}

export interface DirectPendingTransfer {
  transferId: string;
  sourcePeerId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
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
  onPeerMessage?: (sourcePeerId: string, message: DirectPeerMessage) => void;
  onIncoming: (item: DirectIncomingAttachment) => void;
  onPreviewUrl: (url: string) => void;
  onStateChange: (state: DirectTransferPhase) => void;
  onProgress: (value: number) => void;
  onError: (message: string) => void;
}

export const DEFAULT_DIRECT_MEMORY_LIMIT_BYTES = 128 * 1024 * 1024;
const DEFAULT_RECEIVING_TRANSFER_LIMIT = 10;

export function useDirectTransfer(options: UseDirectTransferOptions) {
  const optionsRef = useRef(options);
  const iceConfigRef = useRef<PublicTransferIceConfig | null>(options.iceConfig);
  const activePeerIdsRef = useRef<Set<string>>(new Set(options.peers.map((peer) => peer.peerId)));
  const connectionScopeRef = useRef(options.connectionScopeKey ?? "default");
  const resetScopeRef = useRef(options.connectionScopeKey ?? "default");
  const manualResetCounterRef = useRef(0);
  const peerConnectionsRef = useRef<Map<string, RTCPeerConnection>>(new Map());
  const peerConnectionMetadataRef = useRef<WeakMap<RTCPeerConnection, PeerTransportMetadata>>(new WeakMap());
  const dataChannelsRef = useRef<Map<string, RTCDataChannel>>(new Map());
  const dataChannelMetadataRef = useRef<WeakMap<RTCDataChannel, PeerTransportMetadata>>(new WeakMap());
  const openingChannelsRef = useRef<Map<string, Promise<RTCDataChannel>>>(new Map());
  const openingChannelMetadataRef = useRef<Map<string, PeerTransportMetadata>>(new Map());
  const directIncomingRef = useRef<Map<string, DirectIncomingState>>(new Map());
  const directChannelTransfersRef = useRef<Map<RTCDataChannel, string>>(new Map());
  const pendingDirectRequestsRef = useRef<Map<string, DirectPendingRequest>>(new Map());
  const pendingChannelTransfersRef = useRef<Map<RTCDataChannel, string>>(new Map());
  const receivingProgressRef = useRef<Map<string, { lastAt: number; lastBytes: number }>>(new Map());
  const directAckWaitersRef = useRef<Map<string, DirectAckWaiter>>(new Map());
  const [pendingTransfers, setPendingTransfers] = useState<DirectPendingTransfer[]>([]);
  const [receivingTransfers, setReceivingTransfers] = useState<DirectReceivingTransfer[]>([]);

  optionsRef.current = options;
  iceConfigRef.current = options.iceConfig;
  activePeerIdsRef.current = new Set(options.peers.map((peer) => peer.peerId));
  connectionScopeRef.current = options.connectionScopeKey ?? "default";

  const isCurrentDataChannel = useCallback((peerId: string, channel: RTCDataChannel, scopeKey: string) => {
    const metadata = dataChannelMetadataRef.current.get(channel);
    return connectionScopeRef.current === scopeKey
      && activePeerIdsRef.current.has(peerId)
      && metadata?.peerId === peerId
      && metadata.scopeKey === scopeKey
      && dataChannelsRef.current.get(metadata.key) === channel;
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

  const resetDirectState = useCallback((reason: string, updateView: boolean) => {
    const connections = [...peerConnectionsRef.current.values()];
    const channels = new Set([
      ...dataChannelsRef.current.values(),
      ...directChannelTransfersRef.current.keys(),
      ...pendingChannelTransfersRef.current.keys(),
      ...[...directAckWaitersRef.current.values()].map((waiter) => waiter.channel),
    ]);
    const waiters = [...directAckWaitersRef.current.values()];
    const pendingRequests = [...pendingDirectRequestsRef.current.values()];
    peerConnectionsRef.current.clear();
    dataChannelsRef.current.clear();
    openingChannelsRef.current.clear();
    openingChannelMetadataRef.current.clear();
    directIncomingRef.current.clear();
    directChannelTransfersRef.current.clear();
    pendingDirectRequestsRef.current.clear();
    pendingChannelTransfersRef.current.clear();
    receivingProgressRef.current.clear();
    directAckWaitersRef.current.clear();
    peerConnectionMetadataRef.current = new WeakMap();
    dataChannelMetadataRef.current = new WeakMap();
    for (const channel of channels) {
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
    for (const request of pendingRequests) {
      if (request.timer !== undefined) {
        window.clearTimeout(request.timer);
      }
    }
    if (updateView) {
      setPendingTransfers([]);
      setReceivingTransfers([]);
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
  }, [rejectDirectAckWaiters, removePendingTransfer]);

  useEffect(() => {
    const activePeerIds = new Set(options.peers.map((peer) => peer.peerId));
    for (const channel of dataChannelsRef.current.values()) {
      const metadata = dataChannelMetadataRef.current.get(channel);
      if (!metadata || !activePeerIds.has(metadata.peerId)) {
        closeDataChannel(metadata?.peerId ?? "", channel, "peer is no longer online", true);
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
      "peer is no longer online",
    );
  }, [closeDataChannel, options.peers, rejectDirectAckWaiters]);

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
      return;
    }
    startIncomingTransfer(request, transferKey);
  }, [startIncomingTransfer]);

  const rejectIncomingTransfer = useCallback((sourcePeerId: string, transferId: string) => {
    const transferKey = receivingTransferKey({ sourcePeerId, transferId });
    const request = pendingDirectRequestsRef.current.get(transferKey);
    if (!request) {
      return;
    }
    sendDirectReject(request.channel, transferId, "对方已拒绝接收");
    removePendingTransfer(transferKey);
  }, [removePendingTransfer, sendDirectReject]);

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

  const handleDirectControlMessage = useCallback((
    sourcePeerId: string,
    channel: RTCDataChannel,
    data: string,
    scopeKey: string,
  ) => {
    if (!isCurrentDataChannel(sourcePeerId, channel, scopeKey)) {
      return;
    }
    let message: {
      kind?: string;
      transferId?: string;
      fileName?: string;
      mimeType?: string;
      sizeBytes?: number;
      sha256?: string | null;
      reason?: string;
      messageType?: string;
      payload?: unknown;
    };
    try {
      message = JSON.parse(data);
    } catch {
      return;
    }
    if (message.kind === "app-message" && typeof message.messageType === "string") {
      optionsRef.current.onPeerMessage?.(sourcePeerId, {
        messageType: message.messageType,
        payload: message.payload,
      });
      return;
    }
    if (message.kind === "file-meta" && message.transferId) {
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
  }, [completeDirectIncoming, isCurrentDataChannel, removePendingTransfer, sendDirectReject, startIncomingTransfer]);

  const handleDataChannelMessage = useCallback((sourcePeerId: string, channel: RTCDataChannel, data: unknown, scopeKey: string) => {
    if (!isCurrentDataChannel(sourcePeerId, channel, scopeKey)) {
      return;
    }
    if (typeof data === "string") {
      handleDirectControlMessage(sourcePeerId, channel, data, scopeKey);
      return;
    }
    if (data instanceof ArrayBuffer) {
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
  }, [handleDirectControlMessage, isCurrentDataChannel, sendDirectReject, updateReceivingTransfer]);

  const setupDataChannel = useCallback((
    sourcePeerId: string,
    channel: RTCDataChannel,
    mode: PeerTransportMode,
  ) => {
    const scopeKey = connectionScopeRef.current;
    const key = peerTransportKey(sourcePeerId, mode);
    const previous = dataChannelsRef.current.get(key);
    if (previous && previous !== channel) {
      closeDataChannel(sourcePeerId, previous, `${mode} channel replaced`, true);
    }
    const metadata = {
      key,
      peerId: sourcePeerId,
      scopeKey,
      mode,
      configurationKey: peerTransportConfigurationKey(iceConfigRef.current, mode),
    };
    channel.binaryType = "arraybuffer";
    dataChannelMetadataRef.current.set(channel, metadata);
    dataChannelsRef.current.set(key, channel);
    channel.onmessage = (event) => handleDataChannelMessage(sourcePeerId, channel, event.data, scopeKey);
    channel.onclose = () => {
      closeDataChannel(sourcePeerId, channel, `${mode} channel closed`, false);
    };
  }, [closeDataChannel, handleDataChannelMessage]);

  const createPeerConnection = useCallback((targetPeerId: string, mode: PeerTransportMode) => {
    const key = peerTransportKey(targetPeerId, mode);
    const existing = peerConnectionsRef.current.get(key);
    const scopeKey = connectionScopeRef.current;
    const existingMetadata = existing ? peerConnectionMetadataRef.current.get(existing) : undefined;
    const configuration = buildPeerRtcConfiguration(iceConfigRef.current, mode);
    const configurationKey = JSON.stringify(configuration);
    const existingChannel = dataChannelsRef.current.get(key);
    if (existing
      && existingMetadata?.scopeKey === scopeKey
      && existing.connectionState !== "failed"
      && existing.connectionState !== "closed"
      && (existingChannel?.readyState === "open" || existingMetadata.configurationKey === configurationKey)) {
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
      if (existingChannel) {
        closeDataChannel(targetPeerId, existingChannel, `${mode} connection replaced`, true);
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
      setupDataChannel(targetPeerId, event.channel, mode);
    };
    connection.onconnectionstatechange = () => {
      if ((connection.connectionState === "failed" || connection.connectionState === "closed")
        && peerConnectionsRef.current.get(key) === connection) {
        peerConnectionsRef.current.delete(key);
        peerConnectionMetadataRef.current.delete(connection);
        const channel = dataChannelsRef.current.get(key);
        if (channel) {
          closeDataChannel(targetPeerId, channel, `${mode} connection closed`, true);
        }
      }
    };
    return connection;
  }, [closeDataChannel, isCurrentPeerConnection, sendSignal, setupDataChannel]);

  const openDirectChannel = useCallback(async (
    targetPeerId: string,
    timeoutMs = 8000,
    mode: PeerTransportMode = "auto",
  ): Promise<RTCDataChannel> => {
    const scopeKey = connectionScopeRef.current;
    const key = peerTransportKey(targetPeerId, mode);
    if (!activePeerIdsRef.current.has(targetPeerId)) {
      throw new Error("peer is no longer online");
    }
    if (mode === "relay" && !hasTurnIceServer(iceConfigRef.current)) {
      throw new Error("TURN is unavailable");
    }
    const existing = dataChannelsRef.current.get(key);
    const existingMetadata = existing ? dataChannelMetadataRef.current.get(existing) : undefined;
    const existingMatchesScope = existing && existingMetadata?.scopeKey === scopeKey;
    if (existing && !existingMatchesScope) {
      closeDataChannel(targetPeerId, existing, "room changed", true);
    }
    if (existingMatchesScope && existing.readyState === "open") {
      return existing;
    }
    if (existingMatchesScope && existing.readyState === "connecting") {
      const opened = await waitForDataChannelOpen(existing, timeoutMs);
      if (!isCurrentDataChannel(targetPeerId, opened, scopeKey)) {
        throw new Error("room changed");
      }
      return opened;
    }
    const opening = openingChannelsRef.current.get(key);
    if (opening && openingChannelMetadataRef.current.get(key)?.scopeKey === scopeKey) {
      return opening;
    }
    openingChannelsRef.current.delete(key);
    openingChannelMetadataRef.current.delete(key);
    const connection = createPeerConnection(targetPeerId, mode);
    const channel = connection.createDataChannel(`${mode}-${Date.now()}`, { ordered: true });
    setupDataChannel(targetPeerId, channel, mode);
    const openingTask = (async () => {
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
      configurationKey: peerTransportConfigurationKey(iceConfigRef.current, mode),
    };
    openingChannelsRef.current.set(key, openingTask);
    openingChannelMetadataRef.current.set(key, metadata);
    try {
      return await openingTask;
    } finally {
      if (openingChannelsRef.current.get(key) === openingTask) {
        openingChannelsRef.current.delete(key);
        openingChannelMetadataRef.current.delete(key);
      }
    }
  }, [closeDataChannel, createPeerConnection, isCurrentDataChannel, isCurrentPeerConnection, sendSignal, setupDataChannel]);

  const handleSignal = useCallback(async (sourcePeerId: string, payload: DirectTransferSignalPayload) => {
    if (!payload.signalType || !activePeerIdsRef.current.has(sourcePeerId)) {
      return;
    }
    const scopeKey = connectionScopeRef.current;
    const mode = normalizePeerTransportMode(payload.transportMode);
    const connection = createPeerConnection(sourcePeerId, mode);
    try {
      if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
        return;
      }
      if (payload.signalType === "offer" && payload.description) {
        await connection.setRemoteDescription(payload.description);
        if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
          return;
        }
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
        if (connection.signalingState !== "stable") {
          await connection.setRemoteDescription(payload.description);
          if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
            return;
          }
        }
        return;
      }
      if (payload.signalType === "ice" && payload.candidate) {
        try {
          if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
            return;
          }
          await connection.addIceCandidate(payload.candidate);
        } catch {
          // ICE candidates can race SDP on refresh; the next candidate usually repairs the path.
        }
      }
    } catch (error) {
      if (!isCurrentPeerConnection(sourcePeerId, connection, scopeKey)) {
        return;
      }
      throw error;
    }
  }, [createPeerConnection, isCurrentPeerConnection, sendSignal]);

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
    const channel = dataChannelsRef.current.get(peerTransportKey(targetPeerId, mode));
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
    try {
      const channel = await openDirectChannel(targetPeerId, timeoutMs, mode);
      if (!isCurrentDataChannel(targetPeerId, channel, scopeKey) || channel.readyState !== "open") {
        return false;
      }
      if (channel.bufferedAmount > 1024 * 1024) {
        await waitForBufferedAmountLow(channel);
      }
      if (!isCurrentDataChannel(targetPeerId, channel, scopeKey) || channel.readyState !== "open") {
        return false;
      }
      channel.send(JSON.stringify({
        kind: "app-message",
        messageType: message.messageType,
        payload: message.payload,
      }));
      return true;
    } catch {
      return false;
    }
  }, [isCurrentDataChannel, openDirectChannel]);

  const sendDirect = useCallback(async (
    targetPeerId: string,
    file: File,
    mode: PeerTransportMode = "auto",
  ): Promise<DirectTransferResult> => {
    const limitBytes = optionsRef.current.directMemoryLimitBytes;
    if (typeof RTCPeerConnection === "undefined") {
      throw new Error("当前浏览器不支持直连");
    }
    if (file.size > limitBytes) {
      throw new Error(`文件超过 ${formatTransferBytes(limitBytes)}，改用分享链接`);
    }
    optionsRef.current.onStateChange("connecting");
    optionsRef.current.onProgress(0);
    const scopeKey = connectionScopeRef.current;
    const channel = await openDirectChannel(targetPeerId, 8000, mode);
    const ensureCurrentChannel = () => {
      if (!isCurrentDataChannel(targetPeerId, channel, scopeKey) || channel.readyState !== "open") {
        throw new Error("room or peer changed during direct transfer");
      }
    };
    ensureCurrentChannel();
    const transferId = createTransferId();
    const fileName = file.name || "attachment";
    const mimeType = effectiveMimeType(fileName, file.type);
    const sha256 = await sha256Blob(file);
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
    await sendFileChunks(channel, file, optionsRef.current.onProgress, ensureCurrentChannel);
    ensureCurrentChannel();
    channel.send(JSON.stringify({ kind: "file-complete", transferId }));
    await waitForDirectAck(targetPeerId, channel, scopeKey, transferId, 15000, "对方未确认完成");

    return {
      attachment: directAttachment(transferId, fileName, mimeType, file.size, sha256),
      previewUrl: URL.createObjectURL(file),
    };
  }, [isCurrentDataChannel, openDirectChannel, waitForDirectAck]);

  return {
    pendingTransfers,
    receivingTransfers,
    sendDirect,
    sendPeerMessage,
    isPeerMessageTransportReady,
    handleSignal,
    acceptIncomingTransfer,
    rejectIncomingTransfer,
    invalidateConnections,
  };
}

export function receivingTransferKey(item: Pick<DirectReceivingTransfer, "sourcePeerId" | "transferId">) {
  return `${item.sourcePeerId}:${item.transferId}`;
}

function peerTransportKey(peerId: string, mode: PeerTransportMode) {
  return JSON.stringify([peerId, mode]);
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
      await waitForBufferedAmountLow(channel);
      ensureCurrentChannel();
    }
    const end = Math.min(file.size, offset + chunkSize);
    const buffer = await file.slice(offset, end).arrayBuffer();
    ensureCurrentChannel();
    channel.send(buffer);
    reportProgress(Math.round((end / file.size) * 100), end >= file.size);
  }
}

function waitForBufferedAmountLow(channel: RTCDataChannel) {
  if (channel.bufferedAmount <= channel.bufferedAmountLowThreshold) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      cleanup();
      reject(new Error("DataChannel 发送缓冲区等待超时"));
    }, 5000);
    const cleanup = () => {
      window.clearTimeout(timer);
      channel.removeEventListener("bufferedamountlow", onLow);
      channel.removeEventListener("close", onClose);
    };
    const onLow = () => {
      cleanup();
      resolve();
    };
    const onClose = () => {
      cleanup();
      reject(new Error("DataChannel 已关闭"));
    };
    channel.addEventListener("bufferedamountlow", onLow);
    channel.addEventListener("close", onClose);
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
