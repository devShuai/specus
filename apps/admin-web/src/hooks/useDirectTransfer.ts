import { useCallback, useEffect, useRef, useState } from "react";
import type { PublicTransferIceConfig, TransferAttachment } from "../api/types";
import { sha256Blob } from "../lib/sha256";
import { effectiveMimeType } from "../lib/transferPreview";

export interface DirectTransferSignalPayload {
  signalType?: "offer" | "answer" | "ice";
  description?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
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
  resolve: () => void;
  reject: (error: Error) => void;
  timer: number;
}

interface DirectPendingRequest extends DirectPendingTransfer {
  expectedSha256?: string | null;
  channel: RTCDataChannel;
  timer?: number;
}

interface UseDirectTransferOptions {
  iceConfig: PublicTransferIceConfig | null;
  peers: DirectTransferPeer[];
  directMemoryLimitBytes: number;
  receiveConfirmationRequired: boolean;
  receivingTransferLimit?: number;
  sendSignal: (targetPeerId: string, payload: DirectTransferSignalPayload) => void;
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
  const peerConnectionsRef = useRef<Map<string, RTCPeerConnection>>(new Map());
  const dataChannelsRef = useRef<Map<string, RTCDataChannel>>(new Map());
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

  useEffect(() => () => {
    for (const connection of peerConnectionsRef.current.values()) {
      connection.close();
    }
    for (const waiter of directAckWaitersRef.current.values()) {
      window.clearTimeout(waiter.timer);
      waiter.reject(new Error("page closed"));
    }
    for (const request of pendingDirectRequestsRef.current.values()) {
      if (request.timer !== undefined) {
        window.clearTimeout(request.timer);
      }
    }
    peerConnectionsRef.current.clear();
    dataChannelsRef.current.clear();
    directIncomingRef.current.clear();
    directChannelTransfersRef.current.clear();
    pendingDirectRequestsRef.current.clear();
    pendingChannelTransfersRef.current.clear();
    receivingProgressRef.current.clear();
    directAckWaitersRef.current.clear();
  }, []);

  const sendSignal = useCallback((targetPeerId: string, payload: DirectTransferSignalPayload) => {
    optionsRef.current.sendSignal(targetPeerId, payload);
  }, []);

  const waitForDirectAck = useCallback((transferId: string, timeoutMs: number, timeoutMessage = "直连确认超时") => new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      directAckWaitersRef.current.delete(transferId);
      reject(new Error(timeoutMessage));
    }, timeoutMs);
    directAckWaitersRef.current.set(transferId, { resolve, reject, timer });
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
    if (request.channel.readyState !== "open") {
      removePendingTransfer(transferKey);
      optionsRef.current.onError("直连通道已断开，请让对方重新发送");
      return;
    }
    removePendingTransfer(transferKey);
    const incomingState: DirectIncomingState = {
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
  }, [removePendingTransfer, updateReceivingTransfer]);

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
    if (!incomingState) {
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
      if (!actualSha256 || actualSha256 !== incomingState.expectedSha256) {
        sendDirectReject(channel, transferId, "文件完整性校验失败");
        optionsRef.current.onError("直连文件完整性校验失败，已拒绝接收");
        return;
      }
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
  }, [sendDirectReject]);

  const handleDirectControlMessage = useCallback((sourcePeerId: string, channel: RTCDataChannel, data: string) => {
    let message: { kind?: string; transferId?: string; fileName?: string; mimeType?: string; sizeBytes?: number; sha256?: string | null; reason?: string };
    try {
      message = JSON.parse(data);
    } catch {
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
      void completeDirectIncoming(sourcePeerId, channel, message.transferId);
      return;
    }
    if ((message.kind === "file-ready" || message.kind === "file-ack") && message.transferId) {
      const waiter = directAckWaitersRef.current.get(message.transferId);
      if (waiter) {
        window.clearTimeout(waiter.timer);
        directAckWaitersRef.current.delete(message.transferId);
        waiter.resolve();
      }
      return;
    }
    if (message.kind === "file-reject" && message.transferId) {
      const waiter = directAckWaitersRef.current.get(message.transferId);
      if (waiter) {
        window.clearTimeout(waiter.timer);
        directAckWaitersRef.current.delete(message.transferId);
        waiter.reject(new Error(message.reason || "对方拒绝接收"));
      }
    }
  }, [completeDirectIncoming, removePendingTransfer, sendDirectReject, startIncomingTransfer]);

  const handleDataChannelMessage = useCallback((sourcePeerId: string, channel: RTCDataChannel, data: unknown) => {
    if (typeof data === "string") {
      handleDirectControlMessage(sourcePeerId, channel, data);
      return;
    }
    if (data instanceof ArrayBuffer) {
      const activeTransferKey = directChannelTransfersRef.current.get(channel);
      const current = activeTransferKey ? directIncomingRef.current.get(activeTransferKey) : null;
      if (current) {
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
      void data.arrayBuffer().then((buffer) => handleDataChannelMessage(sourcePeerId, channel, buffer));
    }
  }, [handleDirectControlMessage, sendDirectReject, updateReceivingTransfer]);

  const setupDataChannel = useCallback((sourcePeerId: string, channel: RTCDataChannel) => {
    channel.binaryType = "arraybuffer";
    dataChannelsRef.current.set(sourcePeerId, channel);
    channel.onmessage = (event) => handleDataChannelMessage(sourcePeerId, channel, event.data);
    channel.onclose = () => {
      if (dataChannelsRef.current.get(sourcePeerId) === channel) {
        dataChannelsRef.current.delete(sourcePeerId);
      }
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
    };
  }, [handleDataChannelMessage, removePendingTransfer]);

  const createPeerConnection = useCallback((targetPeerId: string) => {
    const existing = peerConnectionsRef.current.get(targetPeerId);
    if (existing && existing.connectionState !== "failed" && existing.connectionState !== "closed") {
      return existing;
    }
    existing?.close();
    const connection = new RTCPeerConnection({
      iceServers: iceConfigRef.current?.iceServers.map((server) => ({
        urls: server.urls,
        username: server.username || undefined,
        credential: server.credential || undefined,
      })) ?? [],
    });
    peerConnectionsRef.current.set(targetPeerId, connection);
    connection.onicecandidate = (event) => {
      if (event.candidate) {
        sendSignal(targetPeerId, { signalType: "ice", candidate: event.candidate.toJSON() });
      }
    };
    connection.ondatachannel = (event) => setupDataChannel(targetPeerId, event.channel);
    connection.onconnectionstatechange = () => {
      if (connection.connectionState === "failed" || connection.connectionState === "closed") {
        dataChannelsRef.current.delete(targetPeerId);
      }
    };
    return connection;
  }, [sendSignal, setupDataChannel]);

  const openDirectChannel = useCallback(async (targetPeerId: string): Promise<RTCDataChannel> => {
    const existing = dataChannelsRef.current.get(targetPeerId);
    if (existing?.readyState === "open") {
      return existing;
    }
    const connection = createPeerConnection(targetPeerId);
    const channel = connection.createDataChannel(`file-${Date.now()}`, { ordered: true });
    setupDataChannel(targetPeerId, channel);
    const opened = waitForDataChannelOpen(channel, 8000);
    const offer = await connection.createOffer();
    await connection.setLocalDescription(offer);
    sendSignal(targetPeerId, { signalType: "offer", description: connection.localDescription ?? offer });
    return opened;
  }, [createPeerConnection, sendSignal, setupDataChannel]);

  const handleSignal = useCallback(async (sourcePeerId: string, payload: DirectTransferSignalPayload) => {
    if (!payload.signalType) {
      return;
    }
    const connection = createPeerConnection(sourcePeerId);
    if (payload.signalType === "offer" && payload.description) {
      await connection.setRemoteDescription(payload.description);
      const answer = await connection.createAnswer();
      await connection.setLocalDescription(answer);
      sendSignal(sourcePeerId, { signalType: "answer", description: connection.localDescription ?? answer });
      return;
    }
    if (payload.signalType === "answer" && payload.description) {
      if (connection.signalingState !== "stable") {
        await connection.setRemoteDescription(payload.description);
      }
      return;
    }
    if (payload.signalType === "ice" && payload.candidate) {
      try {
        await connection.addIceCandidate(payload.candidate);
      } catch {
        // ICE candidates can race SDP on refresh; the next candidate usually repairs the path.
      }
    }
  }, [createPeerConnection, sendSignal]);

  const sendDirect = useCallback(async (targetPeerId: string, file: File): Promise<DirectTransferResult> => {
    const limitBytes = optionsRef.current.directMemoryLimitBytes;
    if (typeof RTCPeerConnection === "undefined") {
      throw new Error("当前浏览器不支持直连");
    }
    if (file.size > limitBytes) {
      throw new Error(`文件超过 ${formatTransferBytes(limitBytes)}，改用分享链接`);
    }
    optionsRef.current.onStateChange("connecting");
    optionsRef.current.onProgress(0);
    const channel = await openDirectChannel(targetPeerId);
    const transferId = createTransferId();
    const fileName = file.name || "attachment";
    const mimeType = effectiveMimeType(fileName, file.type);
    const sha256 = await sha256Blob(file);
    optionsRef.current.onStateChange("waiting");
    channel.send(JSON.stringify({
      kind: "file-meta",
      transferId,
      fileName,
      mimeType,
      sizeBytes: file.size,
      sha256,
    }));
    await waitForDirectAck(transferId, 120000, "对方未确认接收");
    optionsRef.current.onStateChange("direct");
    await sendFileChunks(channel, file, optionsRef.current.onProgress);
    const ack = waitForDirectAck(transferId, 15000, "对方未确认完成");
    channel.send(JSON.stringify({ kind: "file-complete", transferId }));
    await ack;

    return {
      attachment: directAttachment(transferId, fileName, mimeType, file.size, sha256),
      previewUrl: URL.createObjectURL(file),
    };
  }, [openDirectChannel, waitForDirectAck]);

  return {
    pendingTransfers,
    receivingTransfers,
    sendDirect,
    handleSignal,
    acceptIncomingTransfer,
    rejectIncomingTransfer,
  };
}

export function receivingTransferKey(item: Pick<DirectReceivingTransfer, "sourcePeerId" | "transferId">) {
  return `${item.sourcePeerId}:${item.transferId}`;
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
) {
  const reportProgress = createProgressReporter(onProgress);
  if (file.size === 0) {
    reportProgress(100, true);
    return;
  }
  const chunkSize = 64 * 1024;
  channel.bufferedAmountLowThreshold = 1024 * 1024;
  for (let offset = 0; offset < file.size; offset += chunkSize) {
    if (channel.readyState !== "open") {
      throw new Error("DataChannel 已关闭");
    }
    while (channel.bufferedAmount > 4 * 1024 * 1024) {
      await waitForBufferedAmountLow(channel);
    }
    const end = Math.min(file.size, offset + chunkSize);
    channel.send(await file.slice(offset, end).arrayBuffer());
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
