import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type KeyboardEvent } from "react";
import { PageHeader } from "../../components/PageHeader";
import { Button, Textarea } from "@heroui/react";
import { adminApi, tokenStore } from "../../api/client";
import type { AttachmentPresignUploadResponse, Client, TransferAttachment } from "../../api/types";
import { notify, notifyError } from "../../components/toast";
import { formatAbsoluteTime, formatBytes } from "../../lib/format";
import { Empty, Icon, Progress, RelativeTime, Tag } from "../../components/ui";

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

  const attachmentHint = selectedClient
    ? `附件 ${selectedClient.messageAttachmentsCapable ? "支持" : "不支持"} · 预览 ${selectedClient.messageMediaPreviewCapable ? "支持" : "不支持"}`
    : undefined;

  return (
    <div className="acc-page">
    <PageHeader
      title="消息"
      description="和在线的消息客户端互发文字与文件。"
      meta={<Tag tone={connected ? "success" : "neutral"} plain={!connected}>{connected ? "通道已连接" : "通道未连接"}</Tag>}
    />
    <div className="acc-chat">
      <section className="bd-card acc-chat-peers" aria-label="消息客户端">
        <div className="acc-chat-pane-head">
          <h2 className="bd-card-title">消息客户端</h2>
          <span className="acc-head-count bd-num">{loading ? "" : `${messageClients.length} 台`}</span>
          <Button className="acc-chat-refresh" size="sm" variant="light" startContent={<Icon name="refresh" size={14} />} onPress={() => void loadClients()}>
            刷新
          </Button>
        </div>

        <div className="acc-chat-peer-list">
          {messageClients.length === 0 ? (
            loading ? (
              <div className="acc-chat-peer-state" role="status"><span className="bd-skeleton" /><span className="bd-skeleton" /><span className="bd-skeleton-note">正在读取客户端…</span></div>
            ) : (
              <Empty icon="message" title="没有可发消息的客户端" description="客户端在线并上报消息能力后会出现在这里。" />
            )
          ) : messageClients.map((client) => {
            const unread = unreadByPeer[client.clientName] ?? 0;
            const selected = selectedClient?.id === client.id;
            return (
              <button
                key={client.id}
                type="button"
                aria-pressed={selected}
                onClick={() => selectClient(client)}
                className={`acc-chat-peer${selected ? " is-selected" : ""}`}
              >
                <span className="bd-avatar" aria-hidden="true">{client.clientName.slice(0, 1).toUpperCase()}</span>
                <span className="acc-chat-peer-main">
                  <span className="acc-chat-peer-name">{client.clientName}</span>
                  <span className="acc-chat-peer-sub bd-num">
                    {client.messageAttachmentsCapable ? `附件 ${formatBytes(client.messageMaxAttachmentBytes)}` : "只收文字"}
                    {client.messageMediaPreviewCapable ? " · 预览" : ""}
                  </span>
                </span>
                <span className="acc-chat-peer-tags">
                  {unread > 0 && (
                    <span className="acc-chat-unread bd-num" aria-label={`${unread} 条未读消息`}>
                      {unread > 99 ? "99+" : unread}
                    </span>
                  )}
                  <Tag tone="success">在线</Tag>
                </span>
              </button>
            );
          })}
        </div>
      </section>

      <section className="bd-card acc-chat-thread" aria-label="会话">
        <div className="acc-chat-pane-head">
          {selectedClientInfo ? <span className="bd-avatar" aria-hidden="true">{selectedClientInfo.clientName.slice(0, 1).toUpperCase()}</span> : null}
          <div className="min-w-0 flex-1">
            <h2 className="bd-card-title jd-ellipsis">{selectedClientInfo?.clientName ?? "未选择客户端"}</h2>
            {selectedClientInfo ? (
              <div className="acc-chat-sub bd-num">#{selectedClientInfo.id}{selectedClientInfo.ownerUsername ? ` · ${selectedClientInfo.ownerUsername}` : ""}</div>
            ) : null}
          </div>
          {selectedClient && <Tag tone="info" title={attachmentHint}>可聊天</Tag>}
          {selectedOffline && <Tag plain>已离线</Tag>}
        </div>

        <div className="acc-chat-scroll-wrap">
          <div
            ref={messageListRef}
            className="acc-chat-messages"
            onScroll={handleMessageListScroll}
          >
            {activeMessages.length === 0 ? (
              <Empty
                icon="message"
                title="还没有消息"
                description={selectedClientInfo ? "在下面输入文字或选择附件，按 Ctrl+Enter 发送。" : "先在左边选一台在线的客户端。"}
              />
            ) : (
              <div className="acc-chat-list">
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
              className="acc-chat-new"
              color="primary"
              size="sm"
              variant="solid"
              startContent={<Icon name="arrow-down" size={14} />}
              onPress={scrollToBottom}
            >
              有新消息
            </Button>
          )}
        </div>

        <div className="acc-chat-composer">
          {selectedOffline && (
            <p className="acc-chat-note">
              目标已离线，恢复在线后可继续发送；历史消息保留。
            </p>
          )}
          {file && (
            <div className="acc-file-row is-pending">
              <span className="acc-file-icon" aria-hidden="true"><Icon name="file" size={16} /></span>
              <div className="acc-file-main">
                <div className="acc-file-name">{file.name}</div>
                <div className="acc-file-meta bd-num">
                  {formatBytes(file.size)}
                  {uploadProgress != null ? ` · 已上传 ${uploadProgress}%` : " · 发送时上传"}
                </div>
                {uploadProgress != null && <Progress label="上传进度" value={uploadProgress} />}
              </div>
            </div>
          )}
          <div className="acc-chat-compose-bar">
            <input ref={fileInputRef} className="hidden" type="file" aria-label="选择附件" onChange={chooseFile} />
            <Button className="acc-chat-attach" variant="flat" isDisabled={selectedOffline} startContent={<Icon name="file" />} onPress={() => fileInputRef.current?.click()}>
              附件
            </Button>
            <Textarea
              aria-label="消息内容"
              className="acc-chat-input"
              minRows={1}
              maxRows={5}
              placeholder={selectedOffline ? "目标已离线" : "输入消息，Ctrl+Enter 发送"}
              value={body}
              isDisabled={selectedOffline}
              onValueChange={setBody}
              onKeyDown={onComposerKeyDown}
            />
            <Button
              className="acc-chat-send"
              color="primary"
              isLoading={sending}
              isDisabled={!selectedClient || !connected || (!body.trim() && !file)}
              startContent={sending ? null : <Icon name="send" />}
              onPress={() => void send()}
            >
              发送
            </Button>
          </div>
        </div>
      </section>
    </div>
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
    <div className={`acc-msg${mine ? " is-mine" : ""}`}>
      <div className="acc-msg-meta">
        <span className="acc-msg-who">{mine ? "我" : message.peerName}</span>
        <RelativeTime value={message.createdAt} />
        <span className={failed ? "acc-msg-status is-failed" : "acc-msg-status"}>{statusText(message.status)}</span>
        {failed && mine && (
          <Button className="acc-msg-resend" size="sm" color="danger" variant="light" startContent={<Icon name="refresh" size={12} />} onPress={onResend}>
            重发
          </Button>
        )}
      </div>
      <div className="acc-msg-bubble">
        {message.body && <div className="acc-msg-text">{message.body}</div>}
        {attachment && (
          <div className="acc-file-row">
            <span className="acc-file-icon" aria-hidden="true"><Icon name="file" size={16} /></span>
            <div className="acc-file-main">
              <div className="acc-file-name">{attachment.fileName || attachment.objectId || "attachment"}</div>
              <div className="acc-file-meta bd-num">
                {attachment.mimeType || "application/octet-stream"} · {formatBytes(attachment.sizeBytes)}
              </div>
            </div>
            {attachment.attachmentId && (
              <Button size="sm" variant="flat" isLoading={downloading} startContent={downloading ? null : <Icon name="download" size={14} />} onPress={onDownload}>
                {downloading ? "下载中…" : "下载"}
              </Button>
            )}
          </div>
        )}
        {attachment && message.previewUrl && attachment.mimeType?.startsWith("image/") && (
          <img className="acc-msg-media" src={message.previewUrl} alt={attachment.fileName || "attachment"} />
        )}
        {attachment && message.previewUrl && attachment.mimeType?.startsWith("video/") && (
          <video className="acc-msg-media is-video" src={message.previewUrl} controls />
        )}
        {attachment && message.downloadUrl && message.downloadExpiresAt && (
          <div className="acc-msg-hint">
            链接有效期至 {formatAbsoluteTime(message.downloadExpiresAt)}，过期后再点“下载”会自动重新换签
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
