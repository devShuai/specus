import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Button, Chip, Input, Modal, ModalBody, ModalContent, ModalHeader, Progress } from "@heroui/react";
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
import { createQrMatrix } from "../lib/qr";
import { sha256Blob } from "../lib/sha256";
import { effectiveMimeType, mediaKind, previewKindLabel, shortMimeLabel } from "../lib/transferPreview";
import {
  DEFAULT_DIRECT_MEMORY_LIMIT_BYTES,
  receivingTransferKey,
  useDirectTransfer,
  type DirectPendingTransfer,
  type DirectReceivingTransfer,
  type DirectTransferSignalPayload,
} from "../hooks/useDirectTransfer";

type UploadState = "idle" | "connecting" | "waiting" | "direct" | "presigning" | "uploading" | "completing" | "done" | "failed";

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
}

const INCOMING_ITEM_LIMIT = 20;
const DIRECT_MEMORY_LIMIT_BYTES = DEFAULT_DIRECT_MEMORY_LIMIT_BYTES;
const STREAM_DOWNLOAD_THRESHOLD_BYTES = 64 * 1024 * 1024;

export function PublicTransferPage() {
  return (
    <HeroRuntime>
      <PublicTransferPageContent />
    </HeroRuntime>
  );
}

function PublicTransferPageContent() {
  const discoverySocketRef = useRef<WebSocket | null>(null);
  const loadedSharedAttachmentRef = useRef("");
  const directPreviewUrlsRef = useRef<Set<string>>(new Set());
  const [peerId] = useState(() => loadOrCreatePeerId());
  const [roomId, setRoomId] = useState(() => readInitialRoomId());
  const [roomToken, setRoomToken] = useState(() => loadOrCreateRoomToken(readInitialRoomToken()));
  const [sharedDiscoveryEnabled, setSharedDiscoveryEnabled] = useState(() => Boolean(readInitialRoomToken()));
  const [qrVisible, setQrVisible] = useState(false);
  const [sharedAttachmentId] = useState(() => readInitialSharedAttachmentId());
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [selectedPeerId, setSelectedPeerId] = useState("");
  const [peers, setPeers] = useState<DiscoveryPeer[]>([]);
  const [incoming, setIncoming] = useState<IncomingAttachment[]>([]);
  const [state, setState] = useState<UploadState>("idle");
  const [progress, setProgress] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [record, setRecord] = useState<UploadRecord | null>(null);
  const [previewTarget, setPreviewTarget] = useState<PreviewTarget | null>(null);
  const [iceConfig, setIceConfig] = useState<PublicTransferIceConfig | null>(null);

  usePageSeo({
    title: "免登录文件互传 · shuai-tunnel",
    description: "打开同一个房间链接，在电脑和手机之间快速互传文件。",
    canonical: "https://tunnel.devshuai.com/#/transfer",
  });

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

  const {
    pendingTransfers,
    receivingTransfers,
    sendDirect,
    handleSignal,
    acceptIncomingTransfer,
    rejectIncomingTransfer,
  } = useDirectTransfer({
    iceConfig,
    peers,
    directMemoryLimitBytes: DIRECT_MEMORY_LIMIT_BYTES,
    sendSignal: sendDiscoverySignal,
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
    sessionStorage.setItem("public-transfer-room-id", roomId || "nearby");
  }, [roomId]);

  useEffect(() => {
    if (!sharedAttachmentId || !roomToken.trim()) {
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
  }, [roomToken, sharedAttachmentId]);

  useEffect(() => {
    let active = true;
    let reconnectTimer: number | null = null;
    let heartbeatTimer: number | null = null;
    let reconnectAttempt = 0;
    let lastPongAt = Date.now();

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
          peers?: DiscoveryPeer[];
          payload?: ({ objectId?: string; attachment?: TransferAttachment } & DirectTransferSignalPayload);
        };
        if (message.type === "pong") {
          lastPongAt = Date.now();
        } else if (message.type === "error" && message.error) {
          setError(message.error);
        } else if (message.type === "roster" && Array.isArray(message.peers)) {
          const visiblePeers = message.peers.filter((peer) => peer.peerId !== peerId);
          setPeers(visiblePeers);
          setSelectedPeerId((current) => current && visiblePeers.some((peer) => peer.peerId === current) ? current : visiblePeers[0]?.peerId ?? "");
        } else if (message.type === "attachment" && message.payload?.attachment) {
          setIncoming((items) => limitIncomingItems([
            {
              sourcePeerId: message.sourcePeerId ?? "peer",
              attachment: message.payload!.attachment!,
              objectId: message.payload!.objectId ?? message.payload!.attachment!.objectId,
              downloadUrl: null,
              downloadExpiresAt: null,
            },
            ...items,
          ]));
        } else if (message.type === "signal" && message.sourcePeerId && message.payload) {
          void handleSignal(message.sourcePeerId, message.payload);
        }
      } catch {
        // Ignore malformed discovery messages; the page can keep working through manual copy.
      }
    };

    const connect = () => {
      if (!active) {
        return;
      }
      const url = discoveryWebSocketUrl(roomId, peerId, sharedDiscoveryEnabled ? roomToken : "", peerId);
      const socket = new WebSocket(url);
      discoverySocketRef.current = socket;
      socket.onopen = () => {
        reconnectAttempt = 0;
        lastPongAt = Date.now();
        startHeartbeat(socket);
      };
      socket.onmessage = handleMessage;
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
  }, [handleSignal, peerId, roomId, roomToken, sharedDiscoveryEnabled]);

  useEffect(() => {
    return () => {
      if (record?.previewUrl) {
        URL.revokeObjectURL(record.previewUrl);
      }
    };
  }, [record?.previewUrl]);

  useEffect(() => () => {
    for (const url of directPreviewUrlsRef.current) {
      URL.revokeObjectURL(url);
    }
    directPreviewUrlsRef.current.clear();
  }, []);

  const roomJoinUrl = useMemo(() => roomShareUrl(roomId, roomToken), [roomId, roomToken]);
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
    ? selectedPeer ? `将发送给 ${selectedPeer.displayName || selectedPeer.peerId}` : "未选择对方时会先生成分享链接"
    : selectedFiles.length === 1
      ? `${formatBytes(selectedFiles[0].size)} · ${selectedFiles[0].type || "未知类型"}`
      : `${formatBytes(selectedFilesSize)} · 批量顺序发送`;
  const uploadButtonLabel = selectedFiles.length > 1
    ? selectedPeer ? "发送多个文件" : "生成多个链接"
    : selectedPeer ? "发送给对方" : "生成分享链接";

  const updateRoomToken = (value: string) => {
    setRoomToken(value);
    sessionStorage.setItem("public-transfer-room-token", value);
  };

  const enableSharedDiscovery = () => {
    setSharedDiscoveryEnabled(true);
    window.history.replaceState({}, "", roomShareUrl(roomId, roomToken));
  };

  const createNewRoom = () => {
    const nextRoom = `room-${createRoomToken().slice(0, 8)}`;
    const nextToken = createRoomToken();
    setRoomId(nextRoom);
    updateRoomToken(nextToken);
    setSharedDiscoveryEnabled(true);
    setSelectedPeerId("");
    clearIncomingItems();
    window.history.replaceState({}, "", roomShareUrl(nextRoom, nextToken));
    setNotice("已创建新房间");
    setError(null);
  };

  const copyRoomLink = async () => {
    try {
      enableSharedDiscovery();
      await copyText(roomShareUrl(roomId, roomToken));
      setNotice("房间链接已复制");
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "复制房间链接失败");
    }
  };

  const shareRoom = async () => {
    const url = roomShareUrl(roomId, roomToken);
    try {
      enableSharedDiscovery();
      await shareOrCopy(
        {
          title: "加入 shuai-tunnel 文件互传房间",
          text: `房间：${roomId || "nearby"}`,
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
    enableSharedDiscovery();
    setQrVisible(true);
    setNotice("二维码已生成，手机扫码加入同一房间");
    setError(null);
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
          enableSharedDiscovery();
          await copyText(roomShareUrl(roomId, roomToken));
          setNotice("直连文件只在当前会话内可用；已复制房间链接");
        }
      } else {
        enableSharedDiscovery();
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
      enableSharedDiscovery();
      await copyText(record.direct ? roomShareUrl(roomId, roomToken) : fileShareUrl(record.attachment, roomId, roomToken));
      setNotice(record.direct ? "已复制房间链接" : "文件链接已复制");
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "复制文件链接失败");
    }
  };

  const shareIncomingFile = async (item: IncomingAttachment) => {
    try {
      if (item.direct) {
        enableSharedDiscovery();
        await copyText(roomShareUrl(roomId, roomToken));
        setNotice("直连文件只在当前会话内可用；已复制房间链接");
      } else {
        enableSharedDiscovery();
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

  const upload = async () => {
    if (selectedFiles.length === 0) {
      setError("请选择要发送的文件");
      return;
    }
    if (!roomToken.trim()) {
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

    const files = [...selectedFiles];
    const targetPeerId = selectedPeerId;
    for (let index = 0; index < files.length; index += 1) {
      const file = files[index];
      if (files.length > 1) {
        setNotice(`正在发送 ${index + 1}/${files.length}：${file.name || "attachment"}`);
      }
      if (targetPeerId && typeof RTCPeerConnection !== "undefined") {
        try {
          const direct = await sendDirect(targetPeerId, file);
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
          const directError = err instanceof Error ? err.message : "unknown";
          if (directError.includes("拒绝接收")) {
            setError(directError);
            setState("failed");
            continue;
          }
          setError(`直接发送未完成，正在改用分享链接：${directError}`);
        }
      }
      await uploadViaOss(file, targetPeerId);
    }
    if (files.length > 1) {
      setNotice(`已处理 ${files.length} 个文件`);
    }
  };

  const uploadViaOss = async (file: File, targetPeerId = selectedPeerId) => {
    setState("presigning");
    setProgress(0);
    try {
      const mimeType = effectiveMimeType(file.name || "attachment", file.type);
      const sha256 = await sha256Blob(file);
      const presign = await publicPresignAttachmentUpload({
        fileName: file.name || "attachment",
        mimeType,
        sizeBytes: file.size,
        sha256,
        roomId,
        roomToken,
      });

      setState("uploading");
      await putObject(presign.uploadUrl, file, presign.uploadHeaders, setProgress);

      setState("completing");
      const attachment = await publicCompleteAttachment(presign.attachmentId, { roomToken });
      publishAttachmentEnvelope(targetPeerId, presign.objectId, attachment);
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
    <main className="landing-shell relative min-h-screen overflow-x-hidden text-zinc-950 dark:text-white">
      <div className="landing-grid" aria-hidden="true" />
      <div className="landing-scanline" aria-hidden="true" />

      <header className="relative z-10 mx-auto flex w-full max-w-[1120px] items-center justify-between gap-3 px-4 py-4 sm:px-8 sm:py-5">
        <AppLogo label="shuai-tunnel" subtitle="传文件" markClassName="h-8 w-8 sm:h-9 sm:w-9" />
        <div className="flex shrink-0 items-center gap-2">
          <ThemeToggleButton className="bg-white/70 text-zinc-950 dark:bg-white/10 dark:text-white" />
          <Button as="a" href="/" radius="sm" variant="flat" className="bg-white/70 text-zinc-950 dark:bg-white/10 dark:text-white">
            控制台
          </Button>
        </div>
      </header>

      <section className="relative z-10 mx-auto grid w-full max-w-[1120px] gap-5 px-4 pb-10 sm:px-8 sm:pb-14 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="min-w-0 rounded-xl border border-black/10 bg-white/70 p-4 shadow-sm backdrop-blur dark:border-white/10 dark:bg-white/[0.05] sm:p-6">
          <div className="flex flex-col gap-2">
            <div className="text-tiny font-semibold uppercase tracking-[0.18em] text-cyan-700 dark:text-cyan-200">文件互传</div>
            <h1 className="text-2xl font-semibold sm:text-4xl">把文件发给另一台设备</h1>
            <p className="max-w-2xl text-small leading-6 text-zinc-700 dark:text-zinc-300">
              选文件，邀请对方加入，点发送。手机和电脑都可以直接打开这个页面。
            </p>
          </div>

          <div className="mt-4 flex flex-col gap-3 rounded-lg border border-cyan-500/20 bg-cyan-50/70 p-3 dark:border-cyan-300/20 dark:bg-cyan-400/10 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <div className="text-small font-semibold text-cyan-950 dark:text-cyan-100">邀请对方加入</div>
              <div className="mt-1 text-tiny leading-5 text-cyan-800/80 dark:text-cyan-100/70">
                复制邀请链接，或让手机扫码。对方打开后会出现在右侧列表。
              </div>
              <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5 text-tiny text-cyan-800/80 dark:text-cyan-100/70">
                <span>我的名称</span>
                <button
                  type="button"
                  className="max-w-full truncate rounded bg-white/70 px-1.5 py-0.5 font-mono underline-offset-2 hover:underline dark:bg-white/10"
                  onClick={() => void copyText(peerId).then(() => setNotice("客户端名称已复制")).catch((err) => setError(err instanceof Error ? err.message : "复制客户端名称失败"))}
                >
                  {peerId}
                </button>
              </div>
            </div>
            <div className="grid w-full grid-cols-2 gap-2 sm:flex sm:w-auto sm:shrink-0 sm:flex-wrap">
              <Button color="primary" radius="sm" variant="flat" className="w-full sm:w-auto" onPress={() => void shareRoom()}>
                邀请对方
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

          <details className="mt-3 rounded-lg border border-black/10 bg-white/55 p-3 text-small dark:border-white/10 dark:bg-white/[0.03]">
            <summary className="cursor-pointer font-medium text-zinc-900 dark:text-white">房间设置</summary>
            <div className="mt-3 grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <Input
                label="房间名"
                radius="sm"
                variant="bordered"
                value={roomId}
                onValueChange={setRoomId}
                maxLength={120}
              />
              <Input
                label="加入口令"
                radius="sm"
                variant="bordered"
                value={roomToken}
                onValueChange={updateRoomToken}
                endContent={
                  <Button size="sm" variant="light" onPress={() => {
                    const next = createRoomToken();
                    updateRoomToken(next);
                  }}>
                    生成
                  </Button>
                }
              />
            </div>
          </details>

          {qrVisible && (
            <div className="mt-3 flex flex-col gap-3 rounded-lg border border-cyan-500/20 bg-white/65 p-3 dark:border-cyan-300/20 dark:bg-white/[0.04] sm:flex-row sm:items-center">
              <RoomQrCode value={roomJoinUrl} />
              <div className="min-w-0 flex-1">
                <div className="text-small font-semibold text-zinc-900 dark:text-white">扫码加入当前房间</div>
                <div className="mt-1 text-tiny leading-5 text-zinc-600 dark:text-zinc-300">
                  手机打开后会自动带上房间和口令，适合临时把手机照片、视频发到电脑。
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

          <div className="mt-5 rounded-lg border border-dashed border-zinc-300 bg-white/60 p-4 dark:border-white/15 dark:bg-white/[0.03]">
            <input
              id="public-transfer-file-input"
              type="file"
              multiple
              className="sr-only"
              onClick={(event) => {
                event.currentTarget.value = "";
              }}
              onChange={(event) => setSelectedFiles(Array.from(event.target.files ?? []))}
            />
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <div className="text-tiny font-medium uppercase tracking-[0.12em] text-zinc-500 dark:text-zinc-400">选择文件</div>
                <div className="mt-1 truncate text-small font-medium text-zinc-900 dark:text-white">
                  {selectedFileTitle}
                </div>
                <div className="mt-1 text-tiny text-zinc-500 dark:text-zinc-400">
                  {selectedFileDetail}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 sm:flex sm:shrink-0">
                <label
                  htmlFor="public-transfer-file-input"
                  className="inline-flex h-10 min-w-20 w-full cursor-pointer items-center justify-center rounded-small bg-default-100 px-4 text-small font-normal text-foreground transition-colors hover:bg-default-200 sm:w-auto"
                >
                  选择文件
                </label>
                <Button color="primary" radius="sm" className="w-full sm:w-auto" isLoading={state === "connecting" || state === "waiting" || state === "direct" || state === "presigning" || state === "uploading" || state === "completing"} onPress={() => void upload()}>
                  {uploadButtonLabel}
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
              <div className="rounded-lg border border-black/10 bg-white/60 p-4 dark:border-white/10 dark:bg-white/[0.03]">
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

        <aside className="min-w-0 rounded-xl border border-black/10 bg-white/70 p-4 shadow-sm backdrop-blur dark:border-white/10 dark:bg-white/[0.05] sm:p-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold">发送给谁</h2>
              <div className="mt-1 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
                对方打开邀请链接后，点一下名字再发送。
              </div>
            </div>
            <Chip size="sm" radius="sm" variant="flat" color={peers.length > 0 ? "primary" : "default"}>
              {peers.length} 台
            </Chip>
          </div>
          <div className="mt-3 flex flex-col gap-2">
            {peers.length === 0 ? (
              <div className="rounded-lg border border-black/10 bg-white/60 p-3 text-small text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
                还没有其它设备。点击“邀请对方”或“手机扫码”，打开后会出现在这里。
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

          <TransferFaq iceConfig={iceConfig} />
        </aside>
      </section>
      <PreviewModal target={previewTarget} onClose={() => setPreviewTarget(null)} />
    </main>
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
    <section className="mt-5 rounded-lg border border-black/10 bg-white/60 p-4 dark:border-white/10 dark:bg-white/[0.03]">
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
          <div className="rounded-lg border border-dashed border-black/10 bg-white/60 p-4 text-small text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400 md:col-span-2">
            暂无附件消息。对方发送文件后会出现在这里。
          </div>
        ) : incoming.map((item) => {
          const previewUrl = item.previewUrl || item.downloadUrl;
          return (
            <div key={incomingItemKey(item)} className="rounded-lg border border-black/10 bg-white/70 p-3 dark:border-white/10 dark:bg-white/[0.04]">
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

function Preview({ record, onPreview }: { record: UploadRecord; onPreview: (target: PreviewTarget) => void }) {
  return (
    <FilePreview
      fileName={record.attachment.fileName}
      mimeType={record.attachment.mimeType}
      url={record.previewUrl}
      blob={record.file}
      onPreview={onPreview}
    />
  );
}

function PreviewModal({ target, onClose }: { target: PreviewTarget | null; onClose: () => void }) {
  const kind = mediaKind(target?.fileName ?? "", target?.mimeType ?? null);
  const mimeType = target ? effectiveMimeType(target.fileName, target.mimeType) : "";

  return (
    <Modal isOpen={Boolean(target)} onClose={onClose} size="5xl" scrollBehavior="inside">
      <ModalContent className="max-w-[min(96vw,1180px)]">
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
  compact = false,
  expanded = false,
  onPreview,
}: {
  fileName: string;
  mimeType?: string | null;
  url?: string | null;
  blob?: Blob | null;
  compact?: boolean;
  expanded?: boolean;
  onPreview?: (target: PreviewTarget) => void;
}) {
  const kind = mediaKind(fileName, mimeType);
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
        onPress={() => onPreview?.({ fileName, mimeType, url, blob })}
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
    ? "flex min-h-[45dvh] flex-col items-center justify-center rounded-lg border border-black/10 bg-white/60 p-4 text-center dark:border-white/10 dark:bg-white/[0.03]"
    : compact
      ? "mt-2 flex min-h-28 flex-col items-center justify-center rounded border border-black/10 bg-white/60 p-3 text-center dark:border-white/10 dark:bg-white/[0.03]"
      : "flex h-64 flex-col items-center justify-center rounded-lg border border-black/10 bg-white/60 p-4 text-center dark:border-white/10 dark:bg-white/[0.03]";

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

function TransferFaq({ iceConfig }: { iceConfig: PublicTransferIceConfig | null }) {
  const routeLabel = iceConfig?.turnAuthRequired ? "备用通道已启用" : "备用通道检测中";

  return (
    <section className="mt-6 rounded-lg border border-black/10 bg-white/60 p-3 dark:border-white/10 dark:bg-white/[0.03]">
      <h2 className="text-base font-semibold text-zinc-950 dark:text-white">常见问题</h2>
      <div className="mt-2 divide-y divide-black/10 dark:divide-white/10">
        <FaqItem title="怎么把手机加进来？">
          点“手机扫码”，用手机相机扫二维码。手机打开后会自动进入同一个房间。
        </FaqItem>
        <FaqItem title="找不到对方怎么办？">
          先点“邀请对方”或“复制链接”发给对方。对方打开页面后，会出现在“发送给谁”列表里。
        </FaqItem>
        <FaqItem title="没有选对方也能发送吗？">
          可以。页面会先生成一个分享链接，你可以复制或系统分享给任何加入这个房间的人。
        </FaqItem>
        <FaqItem title="文件会怎么传？">
          页面会优先让两端直接传；如果网络不适合直连，会自动换成临时安全链接完成传输。
        </FaqItem>
        <FaqItem title="谁能看到我发的文件？">
          分享到房间的文件，同一个房间里的成员都能看到并下载。只想发给某一台设备时，先在右侧点选对方再发送，会走两端直连、不进房间共享。
        </FaqItem>
        <FaqItem title="更多说明">
          房间口令用于确认房间成员身份；同房间成员可下载分享到该房间的文件，文件地址是短期有效的。当前状态：{routeLabel}。
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
): Promise<void> {
  const reportProgress = createProgressReporter(onProgress);
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
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
        resolve();
      } else {
        reject(new Error(`文件发送失败：HTTP ${xhr.status}`));
      }
    };
    xhr.onerror = () => reject(new Error("文件发送失败，请检查网络后重试"));
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

function roomShareUrl(roomId: string, roomToken: string) {
  const url = new URL("/transfer", window.location.origin);
  url.searchParams.set("room", normalizeRoomId(roomId));
  if (roomToken.trim()) {
    url.searchParams.set("token", roomToken.trim());
  }
  return url.toString();
}

function fileShareUrl(attachment: TransferAttachment, roomId: string, roomToken: string) {
  const url = new URL(roomShareUrl(roomId, roomToken));
  url.searchParams.set("attachmentId", String(attachment.attachmentId));
  return url.toString();
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
