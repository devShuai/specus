import { useEffect, useMemo, useRef, useState } from "react";
import { Button, Chip, Input, Progress, Textarea } from "@heroui/react";
import { AppLogo } from "../components/AppLogo";
import { ThemeToggleButton } from "../components/ThemeToggleButton";
import { HeroRuntime } from "../components/HeroRuntime";
import {
  fetchPublicTransferIceConfig,
  publicCompleteAttachment,
  publicPresignAttachmentDownload,
  publicPresignAttachmentUpload,
} from "../api/client";
import type { AttachmentPresignUploadResponse, PublicTransferIceConfig, TransferAttachment } from "../api/types";
import { usePageSeo } from "../lib/seo";

type UploadState = "idle" | "connecting" | "direct" | "presigning" | "uploading" | "completing" | "done" | "failed";

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
}

interface IncomingAttachment {
  sourcePeerId: string;
  attachment: TransferAttachment;
  objectId: string;
  downloadUrl: string | null;
  downloadExpiresAt: string | null;
  direct?: boolean;
  previewUrl?: string;
}

interface DiscoverySignalPayload {
  signalType?: "offer" | "answer" | "ice";
  description?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
}

interface DirectIncomingState {
  transferId: string;
  sourcePeerId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  chunks: ArrayBuffer[];
  receivedBytes: number;
}

interface DirectAckWaiter {
  resolve: () => void;
  reject: (error: Error) => void;
  timer: number;
}

export function PublicTransferPage() {
  return (
    <HeroRuntime>
      <PublicTransferPageContent />
    </HeroRuntime>
  );
}

function PublicTransferPageContent() {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const discoverySocketRef = useRef<WebSocket | null>(null);
  const peerConnectionsRef = useRef<Map<string, RTCPeerConnection>>(new Map());
  const dataChannelsRef = useRef<Map<string, RTCDataChannel>>(new Map());
  const directIncomingRef = useRef<Map<string, DirectIncomingState>>(new Map());
  const directAckWaitersRef = useRef<Map<string, DirectAckWaiter>>(new Map());
  const directPreviewUrlsRef = useRef<string[]>([]);
  const [peerId] = useState(() => loadOrCreatePeerId());
  const [roomId, setRoomId] = useState(() => "nearby");
  const [roomToken, setRoomToken] = useState(() => loadOrCreateRoomToken());
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedPeerId, setSelectedPeerId] = useState("");
  const [peers, setPeers] = useState<DiscoveryPeer[]>([]);
  const [incoming, setIncoming] = useState<IncomingAttachment[]>([]);
  const [state, setState] = useState<UploadState>("idle");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [record, setRecord] = useState<UploadRecord | null>(null);
  const [iceConfig, setIceConfig] = useState<PublicTransferIceConfig | null>(null);

  usePageSeo({
    title: "免登录文件互传 · shuai-tunnel",
    description: "通过 WebRTC 优先直连，对象存储预签名 URL 兜底的免登录文件互传页面。",
    canonical: "https://tunnel.devshuai.com/#/transfer",
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
    const url = discoveryWebSocketUrl(roomId, peerId);
    const socket = new WebSocket(url);
    discoverySocketRef.current = socket;
    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(String(event.data)) as {
          type?: string;
          sourcePeerId?: string;
          peers?: DiscoveryPeer[];
          payload?: ({ objectId?: string; attachment?: TransferAttachment } & DiscoverySignalPayload);
        };
        if (message.type === "roster" && Array.isArray(message.peers)) {
          const visiblePeers = message.peers.filter((peer) => peer.peerId !== peerId);
          setPeers(visiblePeers);
          setSelectedPeerId((current) => current && visiblePeers.some((peer) => peer.peerId === current) ? current : visiblePeers[0]?.peerId ?? "");
        } else if (message.type === "attachment" && message.payload?.attachment) {
          setIncoming((items) => [
            {
              sourcePeerId: message.sourcePeerId ?? "peer",
              attachment: message.payload!.attachment!,
              objectId: message.payload!.objectId ?? message.payload!.attachment!.objectId,
              downloadUrl: null,
              downloadExpiresAt: null,
            },
            ...items,
          ].slice(0, 20));
        } else if (message.type === "signal" && message.sourcePeerId && message.payload) {
          void handleSignal(message.sourcePeerId, message.payload);
        }
      } catch {
        // Ignore malformed discovery messages; the page can keep working through manual copy.
      }
    };
    socket.onclose = () => {
      if (discoverySocketRef.current === socket) {
        discoverySocketRef.current = null;
      }
    };
    return () => {
      if (discoverySocketRef.current === socket) {
        discoverySocketRef.current = null;
      }
      socket.close();
    };
  }, [peerId, roomId]);

  useEffect(() => {
    return () => {
      if (record?.previewUrl) {
        URL.revokeObjectURL(record.previewUrl);
      }
    };
  }, [record?.previewUrl]);

  useEffect(() => () => {
    for (const connection of peerConnectionsRef.current.values()) {
      connection.close();
    }
    for (const waiter of directAckWaitersRef.current.values()) {
      window.clearTimeout(waiter.timer);
      waiter.reject(new Error("page closed"));
    }
    for (const url of directPreviewUrlsRef.current) {
      URL.revokeObjectURL(url);
    }
    peerConnectionsRef.current.clear();
    dataChannelsRef.current.clear();
    directIncomingRef.current.clear();
    directAckWaitersRef.current.clear();
    directPreviewUrlsRef.current = [];
  }, []);

  const envelopeText = useMemo(() => {
    if (!record?.presign) {
      return "";
    }
    return JSON.stringify(
      {
        type: "STMSG2",
        messageType: "attachment",
        objectId: record.presign.objectId,
        attachment: record.attachment,
      },
      null,
      2,
    );
  }, [record]);

  const upload = async () => {
    if (!selectedFile) {
      setError("请选择要发送的文件");
      return;
    }
    if (!roomToken.trim()) {
      setError("请输入房间口令");
      return;
    }

    setProgress(0);
    setError(null);
    if (record?.previewUrl) {
      URL.revokeObjectURL(record.previewUrl);
    }
    setRecord(null);

    if (selectedPeerId && typeof RTCPeerConnection !== "undefined") {
      try {
        await sendDirect(selectedPeerId, selectedFile);
        return;
      } catch (err) {
        setError(`直连未完成，已切换 OSS 兜底：${err instanceof Error ? err.message : "unknown"}`);
      }
    }
    await uploadViaOss(selectedFile);
  };

  const uploadViaOss = async (file: File) => {
    setState("presigning");
    setProgress(0);
    try {
      const presign = await publicPresignAttachmentUpload({
        fileName: file.name || "attachment",
        mimeType: file.type || "application/octet-stream",
        sizeBytes: file.size,
        roomId,
        roomToken,
      });

      setState("uploading");
      await putObject(presign.uploadUrl, file, presign.uploadHeaders, setProgress);

      setState("completing");
      const attachment = await publicCompleteAttachment(presign.attachmentId, { roomToken });
      publishAttachmentEnvelope(selectedPeerId, presign.objectId, attachment);
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
      setState("failed");
      setError(err instanceof Error ? err.message : "上传失败");
    }
  };

  const sendDirect = async (targetPeerId: string, file: File) => {
    setState("connecting");
    setProgress(0);
    const channel = await openDirectChannel(targetPeerId);
    const transferId = createTransferId();
    const ack = waitForDirectAck(transferId, 8000);
    setState("direct");
    channel.send(JSON.stringify({
      kind: "file-meta",
      transferId,
      fileName: file.name || "attachment",
      mimeType: file.type || "application/octet-stream",
      sizeBytes: file.size,
    }));
    await sendFileChunks(channel, file, setProgress);
    channel.send(JSON.stringify({ kind: "file-complete", transferId }));
    await ack;

    const attachment = directAttachment(transferId, file.name || "attachment", file.type || "application/octet-stream", file.size);
    setRecord({
      file,
      previewUrl: URL.createObjectURL(file),
      presign: null,
      attachment,
      downloadUrl: null,
      downloadExpiresAt: null,
      direct: true,
    });
    setState("done");
  };

  const openDirectChannel = async (targetPeerId: string): Promise<RTCDataChannel> => {
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
  };

  const handleSignal = async (sourcePeerId: string, payload: DiscoverySignalPayload) => {
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
  };

  const createPeerConnection = (targetPeerId: string) => {
    const existing = peerConnectionsRef.current.get(targetPeerId);
    if (existing && existing.connectionState !== "failed" && existing.connectionState !== "closed") {
      return existing;
    }
    existing?.close();
    const connection = new RTCPeerConnection({
      iceServers: iceConfig?.iceServers.map((server) => ({
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
  };

  const setupDataChannel = (sourcePeerId: string, channel: RTCDataChannel) => {
    channel.binaryType = "arraybuffer";
    dataChannelsRef.current.set(sourcePeerId, channel);
    channel.onmessage = (event) => handleDataChannelMessage(sourcePeerId, event.data);
    channel.onclose = () => {
      if (dataChannelsRef.current.get(sourcePeerId) === channel) {
        dataChannelsRef.current.delete(sourcePeerId);
      }
    };
  };

  const handleDataChannelMessage = (sourcePeerId: string, data: unknown) => {
    if (typeof data === "string") {
      handleDirectControlMessage(sourcePeerId, data);
      return;
    }
    if (data instanceof ArrayBuffer) {
      const current = directIncomingRef.current.get(sourcePeerId);
      if (current) {
        current.chunks.push(data);
        current.receivedBytes += data.byteLength;
      }
      return;
    }
    if (data instanceof Blob) {
      void data.arrayBuffer().then((buffer) => handleDataChannelMessage(sourcePeerId, buffer));
    }
  };

  const handleDirectControlMessage = (sourcePeerId: string, data: string) => {
    let message: { kind?: string; transferId?: string; fileName?: string; mimeType?: string; sizeBytes?: number };
    try {
      message = JSON.parse(data);
    } catch {
      return;
    }
    if (message.kind === "file-meta" && message.transferId) {
      directIncomingRef.current.set(sourcePeerId, {
        transferId: message.transferId,
        sourcePeerId,
        fileName: message.fileName || "attachment",
        mimeType: message.mimeType || "application/octet-stream",
        sizeBytes: Number(message.sizeBytes || 0),
        chunks: [],
        receivedBytes: 0,
      });
      return;
    }
    if (message.kind === "file-complete" && message.transferId) {
      completeDirectIncoming(sourcePeerId, message.transferId);
      return;
    }
    if (message.kind === "file-ack" && message.transferId) {
      const waiter = directAckWaitersRef.current.get(message.transferId);
      if (waiter) {
        window.clearTimeout(waiter.timer);
        directAckWaitersRef.current.delete(message.transferId);
        waiter.resolve();
      }
    }
  };

  const completeDirectIncoming = (sourcePeerId: string, transferId: string) => {
    const incomingState = directIncomingRef.current.get(sourcePeerId);
    if (!incomingState || incomingState.transferId !== transferId) {
      return;
    }
    directIncomingRef.current.delete(sourcePeerId);
    const blob = new Blob(incomingState.chunks, { type: incomingState.mimeType });
    const previewUrl = URL.createObjectURL(blob);
    directPreviewUrlsRef.current.push(previewUrl);
    const attachment = directAttachment(
      transferId,
      incomingState.fileName,
      incomingState.mimeType,
      incomingState.receivedBytes || incomingState.sizeBytes,
    );
    setIncoming((items) => [
      {
        sourcePeerId,
        attachment,
        objectId: attachment.objectId,
        downloadUrl: previewUrl,
        downloadExpiresAt: null,
        direct: true,
        previewUrl,
      },
      ...items,
    ].slice(0, 20));
    const channel = dataChannelsRef.current.get(sourcePeerId);
    if (channel?.readyState === "open") {
      channel.send(JSON.stringify({ kind: "file-ack", transferId }));
    }
  };

  const sendSignal = (targetPeerId: string, payload: DiscoverySignalPayload) => {
    const socket = discoverySocketRef.current;
    if (!targetPeerId || !socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error("发现通道不可用");
    }
    socket.send(JSON.stringify({
      type: "signal",
      targetPeerId,
      payload,
    }));
  };

  const waitForDirectAck = (transferId: string, timeoutMs: number) => new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      directAckWaitersRef.current.delete(transferId);
      reject(new Error("直连确认超时"));
    }, timeoutMs);
    directAckWaitersRef.current.set(transferId, { resolve, reject, timer });
  });

  const createDownloadUrl = async () => {
    if (!record) {
      return;
    }
    try {
      const response = await publicPresignAttachmentDownload(record.attachment.attachmentId, { roomToken });
      setRecord({
        ...record,
        downloadUrl: response.downloadUrl,
        downloadExpiresAt: response.expiresAt,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "换取下载地址失败");
    }
  };

  const downloadIncoming = async (item: IncomingAttachment) => {
    try {
      const response = await publicPresignAttachmentDownload(item.attachment.attachmentId, { roomToken });
      setIncoming((items) => items.map((current) => current === item
        ? { ...current, downloadUrl: response.downloadUrl, downloadExpiresAt: response.expiresAt }
        : current));
    } catch (err) {
      setError(err instanceof Error ? err.message : "换取下载地址失败");
    }
  };

  const publishAttachmentEnvelope = (targetPeerId: string, objectId: string, attachment: TransferAttachment) => {
    const socket = discoverySocketRef.current;
    if (!targetPeerId || !socket || socket.readyState !== WebSocket.OPEN) {
      return;
    }
    socket.send(JSON.stringify({
      type: "attachment",
      targetPeerId,
      payload: {
        type: "STMSG2",
        messageType: "attachment",
        objectId,
        attachment,
      },
    }));
  };

  return (
    <main className="landing-shell relative min-h-screen overflow-hidden text-zinc-950 dark:text-white">
      <div className="landing-grid" aria-hidden="true" />
      <div className="landing-scanline" aria-hidden="true" />

      <header className="relative z-10 mx-auto flex w-full max-w-[1120px] items-center justify-between gap-3 px-5 py-5 sm:px-8">
        <AppLogo label="shuai-tunnel" subtitle="免登录文件互传" markClassName="h-9 w-9" />
        <div className="flex items-center gap-2">
          <ThemeToggleButton className="bg-white/70 text-zinc-950 dark:bg-white/10 dark:text-white" />
          <Button as="a" href="/" radius="sm" variant="flat" className="bg-white/70 text-zinc-950 dark:bg-white/10 dark:text-white">
            控制台
          </Button>
        </div>
      </header>

      <section className="relative z-10 mx-auto grid w-full max-w-[1120px] gap-5 px-5 pb-14 sm:px-8 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="rounded-xl border border-black/10 bg-white/70 p-5 shadow-sm backdrop-blur dark:border-white/10 dark:bg-white/[0.05] sm:p-6">
          <div className="flex flex-wrap items-center gap-2">
            <Chip radius="sm" variant="flat" color="primary">
              WebRTC 优先
            </Chip>
            <Chip radius="sm" variant="flat" color="success">
              OSS 直传兜底
            </Chip>
            {iceConfig?.turnAuthRequired && (
              <Chip radius="sm" variant="flat" color="warning">
                TURN 需认证
              </Chip>
            )}
          </div>

          <div className="mt-5 flex flex-col gap-3">
            <h1 className="text-3xl font-semibold sm:text-4xl">免登录互传文件</h1>
            <p className="max-w-2xl text-small leading-6 text-zinc-700 dark:text-zinc-300">
              上传时只向服务端申请短期签名，文件字节由浏览器直接 PUT 到对象存储。消息 envelope 只包含 objectId 与附件元数据。
            </p>
          </div>

          <div className="mt-6 grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <Input
              label="房间"
              radius="sm"
              variant="bordered"
              value={roomId}
              onValueChange={setRoomId}
              maxLength={120}
            />
            <Input
              label="房间口令"
              radius="sm"
              variant="bordered"
              value={roomToken}
              onValueChange={(value) => {
                setRoomToken(value);
                sessionStorage.setItem("public-transfer-room-token", value);
              }}
              endContent={
                <Button size="sm" variant="light" onPress={() => {
                  const next = createRoomToken();
                  setRoomToken(next);
                  sessionStorage.setItem("public-transfer-room-token", next);
                }}>
                  生成
                </Button>
              }
            />
          </div>

          <div className="mt-5 rounded-lg border border-dashed border-zinc-300 bg-white/60 p-4 dark:border-white/15 dark:bg-white/[0.03]">
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
            />
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <div className="truncate text-small font-medium text-zinc-900 dark:text-white">
                  {selectedFile ? selectedFile.name : "尚未选择文件"}
                </div>
                <div className="mt-1 text-tiny text-zinc-500 dark:text-zinc-400">
                  {selectedFile ? `${formatBytes(selectedFile.size)} · ${selectedFile.type || "application/octet-stream"}` : "支持图片、视频和任意二进制附件"}
                </div>
              </div>
              <div className="flex shrink-0 gap-2">
                <Button radius="sm" variant="flat" onPress={() => fileInputRef.current?.click()}>
                  选择文件
                </Button>
                <Button color="primary" radius="sm" isLoading={state === "presigning" || state === "uploading" || state === "completing"} onPress={() => void upload()}>
                  发送
                </Button>
              </div>
            </div>
          </div>

          {state !== "idle" && (
            <div className="mt-4">
              <Progress
                aria-label="上传进度"
                value={state === "done" ? 100 : progress}
                color={state === "failed" ? "danger" : "primary"}
                size="sm"
              />
              <div className="mt-2 text-tiny text-zinc-500 dark:text-zinc-400">
                {stateLabel(state, progress)}
              </div>
            </div>
          )}

          {error && (
            <div className="mt-4 rounded-lg border border-rose-300 bg-rose-50 px-3 py-2 text-small text-rose-700 dark:border-rose-400/30 dark:bg-rose-500/10 dark:text-rose-100">
              {error}
            </div>
          )}

          {record && (
            <div className="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1fr)_260px]">
              <div className="rounded-lg border border-black/10 bg-white/60 p-4 dark:border-white/10 dark:bg-white/[0.03]">
                <div className="flex flex-wrap items-center gap-2">
                  <Chip size="sm" color="success" variant="flat">
                    {record.attachment.status}
                  </Chip>
                  <span className="text-small font-medium">{record.attachment.fileName}</span>
                  <span className="text-tiny text-zinc-500">{formatBytes(record.attachment.sizeBytes)}</span>
                </div>
                {record.presign && (
                  <Textarea
                    className="mt-3"
                    label="STMSG2 envelope"
                    radius="sm"
                    variant="bordered"
                    minRows={8}
                    value={envelopeText}
                    readOnly
                  />
                )}
                <div className="mt-3 flex flex-wrap gap-2">
                  {record.presign && (
                    <>
                      <Button radius="sm" variant="flat" onPress={() => void navigator.clipboard?.writeText(envelopeText)}>
                        复制 envelope
                      </Button>
                      <Button radius="sm" color="primary" variant="flat" onPress={() => void createDownloadUrl()}>
                        换取下载地址
                      </Button>
                    </>
                  )}
                  {record.direct && (
                    <Button as="a" radius="sm" color="success" href={record.previewUrl} download={record.attachment.fileName}>
                      保存
                    </Button>
                  )}
                  {record.downloadUrl && (
                    <Button as="a" radius="sm" color="success" href={record.downloadUrl} target="_blank" rel="noreferrer">
                      下载
                    </Button>
                  )}
                </div>
                {record.downloadExpiresAt && (
                  <div className="mt-2 text-tiny text-zinc-500 dark:text-zinc-400">
                    下载地址过期时间：{record.downloadExpiresAt}
                  </div>
                )}
              </div>
              <Preview record={record} />
            </div>
          )}
        </div>

        <aside className="rounded-xl border border-black/10 bg-white/70 p-5 shadow-sm backdrop-blur dark:border-white/10 dark:bg-white/[0.05]">
          <h2 className="text-lg font-semibold">附近浏览器</h2>
          <div className="mt-3 flex flex-col gap-2">
            {peers.length === 0 ? (
              <div className="rounded-lg border border-black/10 bg-white/60 p-3 text-small text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
                当前同公网出口、同房间内没有其它网页端。
              </div>
            ) : peers.map((peer) => (
              <button
                key={peer.peerId}
                type="button"
                onClick={() => setSelectedPeerId(peer.peerId)}
                className={`rounded-lg border px-3 py-2 text-left text-small transition-colors ${
                  selectedPeerId === peer.peerId
                    ? "border-cyan-400 bg-cyan-50 text-cyan-900 dark:border-cyan-300/40 dark:bg-cyan-400/10 dark:text-cyan-100"
                    : "border-black/10 bg-white/60 text-zinc-700 hover:border-black/20 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-200"
                }`}
              >
                <div className="font-medium">{peer.displayName || peer.peerId}</div>
                <div className="mt-0.5 font-mono text-tiny opacity-70">{peer.peerId}</div>
              </button>
            ))}
          </div>

          <h2 className="mt-6 text-lg font-semibold">收到的附件</h2>
          <div className="mt-3 flex flex-col gap-2">
            {incoming.length === 0 ? (
              <div className="rounded-lg border border-black/10 bg-white/60 p-3 text-small text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
                暂无附件消息。
              </div>
            ) : incoming.map((item) => (
              <div key={`${item.sourcePeerId}-${item.attachment.attachmentId}`} className="rounded-lg border border-black/10 bg-white/60 p-3 dark:border-white/10 dark:bg-white/[0.03]">
                <div className="truncate text-small font-medium">{item.attachment.fileName}</div>
                <div className="mt-1 text-tiny text-zinc-500">
                  来自 {item.sourcePeerId} · {formatBytes(item.attachment.sizeBytes)}{item.direct ? " · direct" : ""}
                </div>
                {item.previewUrl && item.attachment.mimeType.startsWith("image/") && (
                  <img src={item.previewUrl} alt={item.attachment.fileName} className="mt-2 max-h-44 w-full rounded object-contain" />
                )}
                {item.previewUrl && item.attachment.mimeType.startsWith("video/") && (
                  <video src={item.previewUrl} controls className="mt-2 max-h-44 w-full rounded bg-black object-contain" />
                )}
                <div className="mt-2 flex gap-2">
                  {!item.direct && (
                    <Button size="sm" radius="sm" variant="flat" onPress={() => void downloadIncoming(item)}>
                      换取下载
                    </Button>
                  )}
                  {item.downloadUrl && (
                    <Button as="a" size="sm" radius="sm" color="success" href={item.downloadUrl} target="_blank" rel="noreferrer">
                      {item.direct ? "保存" : "下载"}
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>

          <h2 className="mt-6 text-lg font-semibold">当前传输配置</h2>
          <dl className="mt-4 flex flex-col gap-3 text-small">
            <InfoRow label="ICE servers" value={String(iceConfig?.iceServers.length ?? 0)} />
            <InfoRow label="STUN/TURN 端口" value={String(iceConfig?.stunTurnPort ?? "-")} />
            <InfoRow label="TURN 认证" value={iceConfig?.turnAuthRequired ? "开启" : "未知"} />
          </dl>
          <div className="mt-5 rounded-lg border border-black/10 bg-white/60 p-3 text-tiny leading-5 text-zinc-600 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-300">
            同一个房间口令用于公开传输附件的 complete 和 download 换签。真正进入聊天流时，只发送 objectId，不携带 uploadUrl 或 downloadUrl。
          </div>
        </aside>
      </section>
    </main>
  );
}

function Preview({ record }: { record: UploadRecord }) {
  if (record.attachment.mimeType.startsWith("image/")) {
    return (
      <div className="overflow-hidden rounded-lg border border-black/10 bg-zinc-950/5 dark:border-white/10 dark:bg-white/[0.03]">
        <img src={record.previewUrl} alt={record.attachment.fileName} className="h-64 w-full object-contain" />
      </div>
    );
  }
  if (record.attachment.mimeType.startsWith("video/")) {
    return (
      <div className="overflow-hidden rounded-lg border border-black/10 bg-zinc-950 dark:border-white/10">
        <video src={record.previewUrl} controls className="h-64 w-full object-contain" />
      </div>
    );
  }
  return (
    <div className="flex h-64 flex-col items-center justify-center rounded-lg border border-black/10 bg-white/60 p-4 text-center dark:border-white/10 dark:bg-white/[0.03]">
      <div className="text-4xl font-semibold text-zinc-300 dark:text-white/20">FILE</div>
      <div className="mt-3 max-w-full truncate text-small font-medium">{record.attachment.fileName}</div>
      <div className="mt-1 text-tiny text-zinc-500">{record.attachment.mimeType}</div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-black/10 pb-2 dark:border-white/10">
      <dt className="text-zinc-500 dark:text-zinc-400">{label}</dt>
      <dd className="font-mono text-zinc-900 dark:text-white">{value}</dd>
    </div>
  );
}

function putObject(
  url: string,
  file: File,
  headers: Record<string, string>,
  onProgress: (value: number) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", url, true);
    for (const [key, value] of Object.entries(headers)) {
      xhr.setRequestHeader(key, value);
    }
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        onProgress(100);
        resolve();
      } else {
        reject(new Error(`对象存储上传失败：HTTP ${xhr.status}`));
      }
    };
    xhr.onerror = () => reject(new Error("对象存储上传失败，请检查 bucket CORS 与网络"));
    xhr.send(file);
  });
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
    onProgress(Math.round((end / file.size) * 100));
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

function directAttachment(transferId: string, fileName: string, mimeType: string, sizeBytes: number): TransferAttachment {
  return {
    attachmentId: 0,
    objectId: `direct:${transferId}`,
    fileName,
    mimeType,
    sizeBytes,
    sha256: null,
    status: "DIRECT",
    expiresAt: "",
  };
}

function stateLabel(state: UploadState, progress: number) {
  switch (state) {
    case "connecting":
      return "正在建立 WebRTC 直连通道";
    case "direct":
      return `浏览器正在通过 WebRTC 直传：${progress}%`;
    case "presigning":
      return "正在向服务端申请短期上传签名";
    case "uploading":
      return `浏览器正在直传对象存储：${progress}%`;
    case "completing":
      return "正在通知服务端附件已上传完成";
    case "done":
      return "上传完成";
    case "failed":
      return "上传失败";
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

function loadOrCreateRoomToken() {
  const existing = sessionStorage.getItem("public-transfer-room-token");
  if (existing) {
    return existing;
  }
  const next = createRoomToken();
  sessionStorage.setItem("public-transfer-room-token", next);
  return next;
}

function createRoomToken() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function createTransferId() {
  const bytes = new Uint8Array(16);
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

function discoveryWebSocketUrl(roomId: string, peerId: string) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const params = new URLSearchParams({
    roomId: roomId || "nearby",
    peerId,
    displayName: navigator.userAgent.includes("Mobile") ? "mobile-web" : "web",
  });
  return `${protocol}//${window.location.host}/ws/public-transfer/discovery?${params.toString()}`;
}
