import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type KeyboardEvent } from "react";
import { Button, Card, Chip, ProgressBar, Spinner, TextArea, TextField, Tooltip, TooltipContent, TooltipTrigger } from "@heroui/react";
import { adminApi, tokenStore } from "../../api/client";
import type { AttachmentPresignUploadResponse, Client, TransferAttachment } from "../../api/types";
import { notify, notifyError } from "../../components/toast";
import { formatBytes, formatDateTime } from "../../lib/format";

type ChatDirection = "in" | "out";
type ChatStatus = "sending" | "written" | "delivered" | "failed" | "received";

interface ChatAttachment {
  attachmentId?: number;
  objectId?: string;
  fileName?: string;
  mimeType?: string;
  sizeBytes?: number;
  sha256?: string | null;
  status?: string;
  expiresAt?: string;
}

interface ChatMessage {
  id: string;
  direction: ChatDirection;
  peerName: string;
  body: string;
  rawMessage: string;
  status: ChatStatus;
  transport: string;
  createdAt: string;
  attachment?: ChatAttachment;
  previewUrl?: string;
  downloadUrl?: string;
  downloadExpiresAt?: string;
}

interface ClientMessageSocketEvent {
  type?: string;
  messageId?: string;
  direction?: string;
  fromClientName?: string;
  toClientName?: string;
  message?: string;
  createdAt?: string;
  error?: string;
}

const MAX_MESSAGES = 200;
/** 复用已换取的下载链接时预留的过期安全边距 */
const DOWNLOAD_URL_EXPIRY_MARGIN_MS = 30_000;

export function AdminMessagesPanel() {
  const wsRef = useRef<WebSocket | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const previewUrlsRef = useRef<string[]>([]);
  const messageListRef = useRef<HTMLDivElement | null>(null);
  const stickToBottomRef = useRef(true);
  const selectedPeerNameRef = useRef<string | null>(null);
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedClientId, setSelectedClientId] = useState<number | null>(null);
  const [messagesByPeer, setMessagesByPeer] = useState<Record<string, ChatMessage[]>>({});
  const [unreadByPeer, setUnreadByPeer] = useState<Record<string, number>>({});
  const [hasNewBelow, setHasNewBelow] = useState(false);
  const [body, setBody] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [connected, setConnected] = useState(false);
  const [sending, setSending] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const messageClients = useMemo(
    () => clients.filter((client) => client.online && client.enabled && client.messageReceiveCapable),
    [clients],
  );
  // 选中客户端离线/失去能力时保留选中，不静默改选其他客户端。
  const selectedClient = messageClients.find((client) => client.id === selectedClientId) ?? null;
  const selectedClientInfo = clients.find((client) => client.id === selectedClientId) ?? null;
  const selectedPeerName = selectedClientInfo?.clientName ?? null;
  const selectedOffline = selectedClientId != null && !selectedClient;
  const activeMessages = selectedPeerName ? messagesByPeer[selectedPeerName] ?? [] : [];

  useEffect(() => {
    selectedPeerNameRef.current = selectedPeerName;
  }, [selectedPeerName]);

  const loadClients = useCallback(async () => {
    try {
      const next = await adminApi.listClients();
      setClients(next);
      // 只在尚未选中时补选第一台，之后即使目标离线也保留用户选择。
      setSelectedClientId((current) => {
        if (current != null) {
          return current;
        }
        const capable = next.filter((client) => client.online && client.enabled && client.messageReceiveCapable);
        return capable[0]?.id ?? null;
      });
    } catch (error) {
      notifyError(error, "加载客户端失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadClients();
    const timer = window.setInterval(() => void loadClients(), 15000);
    return () => window.clearInterval(timer);
  }, [loadClients]);

  useEffect(() => {
    let closed = false;
    let retryTimer: number | null = null;
    const connect = async () => {
      const token = tokenStore.get();
      if (!token || closed) {
        return;
      }
      let ticket: string;
      try {
        ticket = (await adminApi.createWebSocketTicket("client-messages")).ticket;
      } catch {
        if (!closed) {
          retryTimer = window.setTimeout(() => void connect(), 3000);
        }
        return;
      }
      if (closed) {
        return;
      }
      const socket = new WebSocket(clientMessagesWsUrl(ticket));
      wsRef.current = socket;
      socket.onopen = () => setConnected(true);
      socket.onmessage = (event) => handleSocketMessage(String(event.data));
      socket.onclose = () => {
        if (wsRef.current === socket) {
          wsRef.current = null;
        }
        setConnected(false);
        if (!closed) {
          retryTimer = window.setTimeout(() => void connect(), 3000);
        }
      };
      socket.onerror = () => setConnected(false);
    };
    void connect();
    return () => {
      closed = true;
      if (retryTimer != null) {
        window.clearTimeout(retryTimer);
      }
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, []);

  useEffect(() => () => {
    for (const url of previewUrlsRef.current) {
      URL.revokeObjectURL(url);
    }
    previewUrlsRef.current = [];
  }, []);

  const scrollToBottom = useCallback(() => {
    const list = messageListRef.current;
    if (list) {
      list.scrollTop = list.scrollHeight;
    }
    stickToBottomRef.current = true;
    setHasNewBelow(false);
  }, []);

  const handleMessageListScroll = useCallback(() => {
    const list = messageListRef.current;
    if (!list) {
      return;
    }
    const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 80;
    stickToBottomRef.current = nearBottom;
    if (nearBottom) {
      setHasNewBelow(false);
    }
  }, []);

  // 新消息到达：贴底或自己发出的消息直接滚到底，否则显示"有新消息"浮标。
  useEffect(() => {
    if (activeMessages.length === 0) {
      return;
    }
    const last = activeMessages[activeMessages.length - 1];
    if (stickToBottomRef.current || last.direction === "out") {
      const list = messageListRef.current;
      if (list) {
        list.scrollTop = list.scrollHeight;
      }
      stickToBottomRef.current = true;
    } else {
      setHasNewBelow(true);
    }
  }, [activeMessages]);

  // 切换会话：清未读、滚到底。
  const selectClient = useCallback((client: Client) => {
    setSelectedClientId(client.id);
    setUnreadByPeer((current) => (current[client.clientName] ? { ...current, [client.clientName]: 0 } : current));
    stickToBottomRef.current = true;
    setHasNewBelow(false);
    requestAnimationFrame(() => {
      const list = messageListRef.current;
      if (list) {
        list.scrollTop = list.scrollHeight;
      }
    });
  }, []);

  const handleSocketMessage = (data: string) => {
    let event: ClientMessageSocketEvent;
    try {
      event = JSON.parse(data) as ClientMessageSocketEvent;
    } catch {
      return;
    }
    if (event.type === "hello") {
      setConnected(true);
      return;
    }
    if (event.type === "written" || event.type === "delivered") {
      markMessage(event.messageId ?? "", event.type);
      return;
    }
    if (event.type === "error" || event.type === "failed") {
      if (event.messageId) {
        markMessage(event.messageId, "failed");
      }
      notifyError(new Error(event.error || "发送失败"), "发送失败");
      return;
    }
    if (event.type === "message") {
      const parsed = parseStmsg2(event.message ?? "");
      appendMessage({
        id: event.messageId || createId(),
        direction: "in",
        peerName: event.fromClientName || "client",
        body: parsed.body,
        rawMessage: event.message ?? "",
        status: "received",
        transport: "server",
        createdAt: event.createdAt || new Date().toISOString(),
        attachment: parsed.attachment,
      });
    }
  };

  const appendMessage = (message: ChatMessage) => {
    const peer = message.peerName;
    setMessagesByPeer((current) => {
      const list = current[peer] ?? [];
      const next = [...list, message];
      const dropped = next.length > MAX_MESSAGES ? next.slice(0, next.length - MAX_MESSAGES) : [];
      // 截断丢弃的消息要及时释放 blob URL，避免泄漏。
      for (const item of dropped) {
        if (item.previewUrl) {
          URL.revokeObjectURL(item.previewUrl);
        }
      }
      return { ...current, [peer]: next.slice(-MAX_MESSAGES) };
    });
    if (message.direction === "in" && peer !== selectedPeerNameRef.current) {
      setUnreadByPeer((current) => ({ ...current, [peer]: (current[peer] ?? 0) + 1 }));
    }
  };

  const markMessage = (id: string, status: ChatStatus) => {
    if (!id) {
      return;
    }
    setMessagesByPeer((current) => {
      let changed = false;
      const next: Record<string, ChatMessage[]> = {};
      for (const [peer, list] of Object.entries(current)) {
        next[peer] = list.map((item) => {
          if (item.id === id) {
            changed = true;
            return { ...item, status };
          }
          return item;
        });
      }
      return changed ? next : current;
    });
  };

  const patchMessage = (id: string, patch: Partial<ChatMessage>) => {
    setMessagesByPeer((current) => {
      let changed = false;
      const next: Record<string, ChatMessage[]> = {};
      for (const [peer, list] of Object.entries(current)) {
        next[peer] = list.map((item) => {
          if (item.id === id) {
            changed = true;
            return { ...item, ...patch };
          }
          return item;
        });
      }
      return changed ? next : current;
    });
  };

  const send = async () => {
    const target = selectedClient;
    const text = body.trim();
    if (!target || (!text && !file)) {
      return;
    }
    const socket = wsRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      notify("消息通道未连接", "error");
      return;
    }
    if (file && !target.messageAttachmentsCapable) {
      notify("目标客户端未上报附件能力", "error");
      return;
    }
    if (file && target.messageMaxAttachmentBytes > 0 && file.size > target.messageMaxAttachmentBytes) {
      notify(`附件超过目标客户端上限：${formatBytes(target.messageMaxAttachmentBytes)}`, "error");
      return;
    }

    const messageId = createId();
    let payload = text;
    let attachment: TransferAttachment | undefined;
    let previewUrl: string | undefined;
    setSending(true);
    try {
      if (file) {
        setUploadProgress(0);
        const presign = await adminApi.presignClientMessageAttachmentUpload({
          targetClientId: target.id,
          fileName: file.name || "attachment",
          mimeType: file.type || "application/octet-stream",
          sizeBytes: file.size,
        });
        await putObject(presign.uploadUrl, file, presign.uploadHeaders, setUploadProgress);
        attachment = await adminApi.completeClientMessageAttachment(presign.attachmentId);
        payload = encodeStmsg2(messageId, target, text, attachment);
        previewUrl = URL.createObjectURL(file);
        previewUrlsRef.current.push(previewUrl);
      }

      appendMessage({
        id: messageId,
        direction: "out",
        peerName: target.clientName,
        body: text,
        rawMessage: payload,
        status: "sending",
        transport: "server",
        createdAt: new Date().toISOString(),
        attachment,
        previewUrl,
      });
      socket.send(JSON.stringify({
        type: "message",
        messageId,
        toClientName: target.clientName,
        message: payload,
      }));
      setBody("");
      setFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    } catch (error) {
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
      }
      notifyError(error, "发送失败");
    } finally {
      setSending(false);
      setUploadProgress(null);
    }
  };

  const resend = (message: ChatMessage) => {
    const socket = wsRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      notify("消息通道未连接", "error");
      return;
    }
    markMessage(message.id, "sending");
    socket.send(JSON.stringify({
      type: "message",
      messageId: message.id,
      toClientName: message.peerName,
      message: message.rawMessage,
    }));
  };

  const chooseFile = (event: ChangeEvent<HTMLInputElement>) => {
    setFile(event.target.files?.[0] ?? null);
  };

  const downloadAttachment = async (message: ChatMessage) => {
    if (!message.attachment?.attachmentId || downloadingId) {
      return;
    }
    const fileName = message.attachment.fileName || "attachment";
    // 已换取的链接在过期前可以直接复用，无需重新换签。
    const expiresAt = message.downloadExpiresAt ? Date.parse(message.downloadExpiresAt) : 0;
    if (message.downloadUrl && Number.isFinite(expiresAt) && expiresAt - Date.now() > DOWNLOAD_URL_EXPIRY_MARGIN_MS) {
      triggerDownload(message.downloadUrl, fileName);
      return;
    }
    setDownloadingId(message.id);
    try {
      const response = await adminApi.presignClientMessageAttachmentDownload(message.attachment.attachmentId);
      patchMessage(message.id, { downloadUrl: response.downloadUrl, downloadExpiresAt: response.expiresAt });
      // 换签成功立即触发下载，不再需要第二步"打开"。
      triggerDownload(response.downloadUrl, fileName);
    } catch (error) {
      notifyError(error, "换取下载地址失败");
    } finally {
      setDownloadingId(null);
    }
  };

  const onComposerKeyDown = (event: KeyboardEvent) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      void send();
    }
  };

  return (
    <div className="mt-4 grid min-h-[calc(100vh-120px)] min-w-0 gap-4 lg:grid-cols-[320px_minmax(0,1fr)]">
      <Card className="rounded-md border border-default-200">
        <Card.Content className="gap-3 p-3">
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-base font-semibold text-foreground">消息客户端</h2>
            <div className="flex items-center gap-2">
              <Chip size="sm" color={connected ? "success" : "default"} variant="soft">
                {connected ? "已连接" : "未连接"}
              </Chip>
              <Button size="sm" variant="secondary" onPress={() => void loadClients()}>
                刷新
              </Button>
            </div>
          </div>

          <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto">
            {messageClients.length === 0 ? (
              <div className="rounded-md border border-default-200 bg-content2 px-3 py-4 text-small text-default-500">
                {loading ? "加载中…" : "暂无可发送客户端"}
              </div>
            ) : messageClients.map((client) => {
              const unread = unreadByPeer[client.clientName] ?? 0;
              return (
                <button
                  key={client.id}
                  type="button"
                  aria-pressed={selectedClient?.id === client.id}
                  onClick={() => selectClient(client)}
                  className={[
                    "rounded-md border px-3 py-2 text-left transition-colors",
                    selectedClient?.id === client.id
                      ? "border-primary bg-primary-50 text-primary-700 dark:bg-primary-400/10 dark:text-primary-300"
                      : "border-default-200 bg-content1 text-foreground hover:bg-default-100",
                  ].join(" ")}
                >
                  <div className="flex min-w-0 items-center justify-between gap-2">
                    <span className="truncate text-small font-medium">{client.clientName}</span>
                    <span className="flex shrink-0 items-center gap-1">
                      {unread > 0 && (
                        <Chip size="sm" color="danger" variant="primary" aria-label={`${unread} 条未读消息`}>
                          {unread > 99 ? "99+" : unread}
                        </Chip>
                      )}
                      <Chip size="sm" color="success" variant="soft">
                        在线
                      </Chip>
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1 text-tiny text-default-500">
                    {client.messageAttachmentsCapable && <span>附件 {formatBytes(client.messageMaxAttachmentBytes)}</span>}
                    {client.messageMediaPreviewCapable && <span>预览</span>}
                  </div>
                </button>
              );
            })}
          </div>
        </Card.Content>
      </Card>

      <Card className="rounded-md border border-default-200">
        <Card.Content className="grid min-h-0 grid-rows-[auto_minmax(0,1fr)_auto] gap-3 p-3">
          <div className="flex min-w-0 items-center justify-between gap-3 border-b border-default-200 pb-3">
            <div className="min-w-0">
              <h2 className="truncate text-base font-semibold text-foreground">{selectedClientInfo?.clientName ?? "未选择客户端"}</h2>
              <div className="mt-1 text-tiny text-default-500">
                {selectedClientInfo ? `#${selectedClientInfo.id} · ${selectedClientInfo.ownerUsername || "-"}` : "-"}
              </div>
            </div>
            {selectedClient && (
              <Tooltip>
                <TooltipTrigger tabIndex={0}><Chip size="sm" color="accent" variant="soft">
                  可聊天
                </Chip></TooltipTrigger>
                <TooltipContent>{`附件 ${selectedClient.messageAttachmentsCapable ? "支持" : "不支持"} · 预览 ${selectedClient.messageMediaPreviewCapable ? "支持" : "不支持"}`}</TooltipContent>
              </Tooltip>
            )}
            {selectedOffline && (
              <Chip size="sm" color="default" variant="soft">
                已离线
              </Chip>
            )}
          </div>

          <div className="relative min-h-0">
            <div
              ref={messageListRef}
              className="h-full overflow-y-auto rounded-md bg-default-50 p-3 dark:bg-content2/40"
              onScroll={handleMessageListScroll}
            >
              {activeMessages.length === 0 ? (
                <div className="flex h-full min-h-[220px] items-center justify-center text-small text-default-500">
                  暂无消息
                </div>
              ) : (
                <div className="flex flex-col gap-3">
                  {activeMessages.map((message) => (
                    <MessageBubble
                      key={message.id}
                      message={message}
                      downloading={downloadingId === message.id}
                      onDownload={() => void downloadAttachment(message)}
                      onResend={() => resend(message)}
                    />
                  ))}
                </div>
              )}
            </div>
            {hasNewBelow && (
              <Button
                className="absolute bottom-3 left-1/2 -translate-x-1/2 shadow-md"
                size="sm" variant="primary"
                onPress={scrollToBottom}
              >
                ↓ 有新消息
              </Button>
            )}
          </div>

          <div className="space-y-2 border-t border-default-200 pt-3">
            {selectedOffline && (
              <div className="rounded-md border border-default-200 bg-default-50 px-3 py-2 text-small text-default-500">
                目标已离线，恢复在线后可继续发送；历史消息保留。
              </div>
            )}
            {uploadProgress != null && (
              <ProgressBar aria-label="上传进度" size="sm" value={uploadProgress} />
            )}
            {file && (
              <div className="flex items-center justify-between gap-2 rounded-md border border-default-200 bg-content2 px-3 py-2 text-small">
                <span className="min-w-0 truncate">{file.name}</span>
                <span className="shrink-0 text-tiny text-default-500">{formatBytes(file.size)}</span>
              </div>
            )}
            <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
              <TextField
                aria-label="消息内容"
                value={body}
                isDisabled={selectedOffline}
                onChange={setBody}
              >
                <TextArea
                  placeholder={selectedOffline ? "目标已离线" : "输入消息"}
                  onKeyDown={onComposerKeyDown}
                />
              </TextField>
              <div className="flex gap-2 sm:flex-col">
                <input ref={fileInputRef} className="hidden" type="file" aria-label="选择附件" onChange={chooseFile} />
                <Button className="flex-1 sm:flex-none" variant="secondary" isDisabled={selectedOffline} onPress={() => fileInputRef.current?.click()}>
                  附件
                </Button>
                <Button variant="primary"
                  className="flex-1 sm:flex-none" isDisabled={!selectedClient || !connected || (!body.trim() && !file) || sending}
                  onPress={() => void send()}
                >{sending ? <Spinner size="sm" /> : null}
                  发送
                </Button>
              </div>
            </div>
          </div>
        </Card.Content>
      </Card>
    </div>
  );
}

function MessageBubble({ message, downloading, onDownload, onResend }: {
  message: ChatMessage;
  downloading: boolean;
  onDownload: () => void;
  onResend: () => void;
}) {
  const mine = message.direction === "out";
  const attachment = message.attachment;
  const failed = message.status === "failed";
  return (
    <div className={`flex ${mine ? "justify-end" : "justify-start"}`}>
      <div className={[
        "max-w-[min(680px,92%)] rounded-md border px-3 py-2 shadow-sm",
        mine
          ? "border-primary-200 bg-primary-50 text-primary-950 dark:border-primary-400/30 dark:bg-primary-400/10 dark:text-primary-50"
          : "border-default-200 bg-content1 text-foreground",
      ].join(" ")}>
        <div className="mb-1 flex flex-wrap items-center gap-2 text-tiny text-default-500">
          <span>{mine ? "我" : message.peerName}</span>
          <span>{formatDateTime(message.createdAt)}</span>
          <span className={failed ? "font-medium text-danger" : undefined}>{statusText(message.status)}</span>
          {failed && mine && (
            <Button className="h-5 min-w-0 px-1.5 text-tiny" size="sm" variant="danger" onPress={onResend}>
              重发
            </Button>
          )}
        </div>
        {message.body && <div className="whitespace-pre-wrap break-words text-small leading-6">{message.body}</div>}
        {attachment && (
          <div className="mt-2 rounded-md border border-default-200 bg-background/70 p-2">
            <div className="flex min-w-0 items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="truncate text-small font-medium">{attachment.fileName || attachment.objectId || "attachment"}</div>
                <div className="mt-0.5 text-tiny text-default-500">
                  {attachment.mimeType || "application/octet-stream"} · {formatBytes(attachment.sizeBytes)}
                </div>
              </div>
              {attachment.attachmentId && (
                <Button size="sm" variant="secondary" onPress={onDownload} isDisabled={downloading}>{downloading ? <Spinner size="sm" /> : null}
                  {downloading ? "下载中…" : "下载"}
                </Button>
              )}
            </div>
            {message.previewUrl && attachment.mimeType?.startsWith("image/") && (
              <img className="mt-2 max-h-64 w-full rounded object-contain" src={message.previewUrl} alt={attachment.fileName || "attachment"} />
            )}
            {message.previewUrl && attachment.mimeType?.startsWith("video/") && (
              <video className="mt-2 max-h-64 w-full rounded bg-black object-contain" src={message.previewUrl} controls />
            )}
            {message.downloadUrl && message.downloadExpiresAt && (
              <div className="mt-2 text-tiny text-default-500">
                链接有效期至 {formatDateTime(message.downloadExpiresAt)}，过期后点下载自动重新换签
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function triggerDownload(url: string, fileName: string) {
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = "noreferrer";
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
}

function encodeStmsg2(messageId: string, target: Client, body: string, attachment: TransferAttachment) {
  return `STMSG2\n${JSON.stringify({
    type: "message",
    id: messageId,
    fromClientName: "admin",
    toClientId: target.id,
    toClientName: target.clientName,
    message: body,
    attachment: {
      objectId: attachment.objectId,
      attachmentId: attachment.attachmentId,
      fileName: attachment.fileName,
      mimeType: attachment.mimeType,
      sizeBytes: attachment.sizeBytes,
      sha256: attachment.sha256,
    },
    createdAtMillis: Date.now(),
  })}`;
}

function parseStmsg2(raw: string): { body: string; attachment?: ChatAttachment } {
  if (!raw.startsWith("STMSG2\n")) {
    return { body: raw };
  }
  try {
    const json = JSON.parse(raw.slice(raw.indexOf("\n") + 1)) as { message?: string; attachment?: ChatAttachment };
    return {
      body: json.message || "",
      attachment: json.attachment,
    };
  } catch {
    return { body: raw };
  }
}

function putObject(
  url: string,
  file: File,
  headers: AttachmentPresignUploadResponse["uploadHeaders"],
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
    xhr.onerror = () => reject(new Error("对象存储上传失败"));
    xhr.send(file);
  });
}

function clientMessagesWsUrl(ticket: string) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const params = new URLSearchParams({ ticket });
  return `${protocol}//${window.location.host}/ws/client-messages?${params.toString()}`;
}

function createId() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID().replace(/-/g, "");
  }
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
}

function statusText(status: ChatStatus) {
  switch (status) {
    case "sending":
      return "发送中";
    case "written":
      return "已写入设备通道";
    case "delivered":
      return "已送达";
    case "failed":
      return "发送失败";
    case "received":
      return "收到";
    default:
      return status;
  }
}
