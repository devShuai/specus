import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type KeyboardEvent } from "react";
import { Button, Card, CardBody, Chip, Progress, Textarea, Tooltip } from "@heroui/react";
import { adminApi, tokenStore } from "../../api/client";
import type { AttachmentPresignUploadResponse, Client, TransferAttachment } from "../../api/types";
import { notify, notifyError } from "../../components/toast";
import { formatBytes, formatDateTime } from "../../lib/format";

type ChatDirection = "in" | "out";
type ChatStatus = "sending" | "sent" | "failed" | "received";

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

export function AdminMessagesPanel() {
  const wsRef = useRef<WebSocket | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const previewUrlsRef = useRef<string[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedClientId, setSelectedClientId] = useState<number | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [body, setBody] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [connected, setConnected] = useState(false);
  const [sending, setSending] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);

  const messageClients = useMemo(
    () => clients.filter((client) => client.online && client.enabled && client.messageReceiveCapable),
    [clients],
  );
  const selectedClient = messageClients.find((client) => client.id === selectedClientId) ?? messageClients[0] ?? null;

  const loadClients = useCallback(async () => {
    try {
      const next = await adminApi.listClients();
      setClients(next);
      setSelectedClientId((current) => {
        const capable = next.filter((client) => client.online && client.enabled && client.messageReceiveCapable);
        return current && capable.some((client) => client.id === current) ? current : capable[0]?.id ?? null;
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
    const connect = () => {
      const token = tokenStore.get();
      if (!token || closed) {
        return;
      }
      const socket = new WebSocket(clientMessagesWsUrl(token));
      wsRef.current = socket;
      socket.onopen = () => setConnected(true);
      socket.onmessage = (event) => handleSocketMessage(String(event.data));
      socket.onclose = () => {
        if (wsRef.current === socket) {
          wsRef.current = null;
        }
        setConnected(false);
        if (!closed) {
          retryTimer = window.setTimeout(connect, 3000);
        }
      };
      socket.onerror = () => setConnected(false);
    };
    connect();
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
    if (event.type === "sent") {
      markMessage(event.messageId ?? "", "sent");
      return;
    }
    if (event.type === "error") {
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
    setMessages((items) => [...items, message].slice(-MAX_MESSAGES));
  };

  const markMessage = (id: string, status: ChatStatus) => {
    if (!id) {
      return;
    }
    setMessages((items) => items.map((item) => (item.id === id ? { ...item, status } : item)));
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

  const chooseFile = (event: ChangeEvent<HTMLInputElement>) => {
    setFile(event.target.files?.[0] ?? null);
  };

  const downloadAttachment = async (message: ChatMessage) => {
    if (!message.attachment?.attachmentId) {
      return;
    }
    try {
      const response = await adminApi.presignClientMessageAttachmentDownload(message.attachment.attachmentId);
      setMessages((items) => items.map((item) => item.id === message.id
        ? { ...item, downloadUrl: response.downloadUrl, downloadExpiresAt: response.expiresAt }
        : item));
    } catch (error) {
      notifyError(error, "换取下载地址失败");
    }
  };

  const consumeAttachmentDownload = (messageId: string) => {
    setMessages((items) => items.map((item) => item.id === messageId
      ? { ...item, downloadUrl: undefined, downloadExpiresAt: undefined }
      : item));
  };

  const onComposerKeyDown = (event: KeyboardEvent) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      void send();
    }
  };

  return (
    <div className="mt-3 grid min-h-[calc(100vh-120px)] min-w-0 gap-4 lg:grid-cols-[320px_minmax(0,1fr)]">
      <Card shadow="none" className="rounded-md border border-default-200">
        <CardBody className="gap-3 p-3">
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-base font-semibold text-foreground">消息客户端</h2>
            <div className="flex items-center gap-2">
              <Chip size="sm" color={connected ? "success" : "default"} variant="flat">
                {connected ? "已连接" : "未连接"}
              </Chip>
              <Button size="sm" variant="flat" onPress={() => void loadClients()}>
                刷新
              </Button>
            </div>
          </div>

          <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto">
            {messageClients.length === 0 ? (
              <div className="rounded-md border border-default-200 bg-content2 px-3 py-4 text-small text-default-500">
                {loading ? "加载中…" : "暂无可发送客户端"}
              </div>
            ) : messageClients.map((client) => (
              <button
                key={client.id}
                type="button"
                onClick={() => setSelectedClientId(client.id)}
                className={[
                  "rounded-md border px-3 py-2 text-left transition-colors",
                  selectedClient?.id === client.id
                    ? "border-primary bg-primary-50 text-primary-700 dark:bg-primary-400/10 dark:text-primary-300"
                    : "border-default-200 bg-content1 text-foreground hover:bg-default-100",
                ].join(" ")}
              >
                <div className="flex min-w-0 items-center justify-between gap-2">
                  <span className="truncate text-small font-medium">{client.clientName}</span>
                  <Chip className="shrink-0" size="sm" color="success" variant="flat">
                    在线
                  </Chip>
                </div>
                <div className="mt-1 flex flex-wrap gap-1 text-tiny text-default-500">
                  {client.messageAttachmentsCapable && <span>附件 {formatBytes(client.messageMaxAttachmentBytes)}</span>}
                  {client.messageMediaPreviewCapable && <span>预览</span>}
                </div>
              </button>
            ))}
          </div>
        </CardBody>
      </Card>

      <Card shadow="none" className="rounded-md border border-default-200">
        <CardBody className="grid min-h-0 grid-rows-[auto_minmax(0,1fr)_auto] gap-3 p-3">
          <div className="flex min-w-0 items-center justify-between gap-3 border-b border-default-200 pb-3">
            <div className="min-w-0">
              <h2 className="truncate text-base font-semibold text-foreground">{selectedClient?.clientName ?? "未选择客户端"}</h2>
              <div className="mt-1 text-tiny text-default-500">
                {selectedClient ? `#${selectedClient.id} · ${selectedClient.ownerUsername || "-"}` : "-"}
              </div>
            </div>
            {selectedClient && (
              <Tooltip content={`附件 ${selectedClient.messageAttachmentsCapable ? "支持" : "不支持"} · 预览 ${selectedClient.messageMediaPreviewCapable ? "支持" : "不支持"}`}>
                <Chip size="sm" color="primary" variant="flat">
                  可聊天
                </Chip>
              </Tooltip>
            )}
          </div>

          <div className="min-h-0 overflow-y-auto rounded-md bg-default-50 p-3 dark:bg-content2/40">
            {messages.length === 0 ? (
              <div className="flex h-full min-h-[220px] items-center justify-center text-small text-default-500">
                暂无消息
              </div>
            ) : (
              <div className="flex flex-col gap-3">
                {messages.map((message) => (
                  <MessageBubble
                    key={message.id}
                    message={message}
                    onDownload={() => void downloadAttachment(message)}
                    onOpen={() => consumeAttachmentDownload(message.id)}
                  />
                ))}
              </div>
            )}
          </div>

          <div className="space-y-2 border-t border-default-200 pt-3">
            {uploadProgress != null && (
              <Progress aria-label="上传进度" size="sm" color="primary" value={uploadProgress} />
            )}
            {file && (
              <div className="flex items-center justify-between gap-2 rounded-md border border-default-200 bg-content2 px-3 py-2 text-small">
                <span className="min-w-0 truncate">{file.name}</span>
                <span className="shrink-0 text-tiny text-default-500">{formatBytes(file.size)}</span>
              </div>
            )}
            <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
              <Textarea
                minRows={2}
                maxRows={5}
                radius="sm"
                variant="bordered"
                placeholder="输入消息"
                value={body}
                onValueChange={setBody}
                onKeyDown={onComposerKeyDown}
              />
              <div className="flex gap-2 sm:flex-col">
                <input ref={fileInputRef} className="hidden" type="file" onChange={chooseFile} />
                <Button className="flex-1 sm:flex-none" variant="flat" onPress={() => fileInputRef.current?.click()}>
                  附件
                </Button>
                <Button
                  className="flex-1 sm:flex-none"
                  color="primary"
                  isLoading={sending}
                  isDisabled={!selectedClient || !connected || (!body.trim() && !file)}
                  onPress={() => void send()}
                >
                  发送
                </Button>
              </div>
            </div>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

function MessageBubble({ message, onDownload, onOpen }: {
  message: ChatMessage;
  onDownload: () => void;
  onOpen: () => void;
}) {
  const mine = message.direction === "out";
  const attachment = message.attachment;
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
          <span>{statusText(message.status)}</span>
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
                <Button size="sm" variant="flat" onPress={onDownload}>
                  下载
                </Button>
              )}
            </div>
            {message.previewUrl && attachment.mimeType?.startsWith("image/") && (
              <img className="mt-2 max-h-64 w-full rounded object-contain" src={message.previewUrl} alt={attachment.fileName || "attachment"} />
            )}
            {message.previewUrl && attachment.mimeType?.startsWith("video/") && (
              <video className="mt-2 max-h-64 w-full rounded bg-black object-contain" src={message.previewUrl} controls />
            )}
            {message.downloadUrl && (
              <div className="mt-2 flex items-center justify-between gap-2 text-tiny text-default-500">
                <span className="truncate">有效期 {formatDateTime(message.downloadExpiresAt)}</span>
                <Button as="a" size="sm" color="success" variant="flat" href={message.downloadUrl}
                  target="_blank" rel="noreferrer" onClick={onOpen}>
                  打开
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
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
  if (!raw.startsWith("STMSG1\n") && !raw.startsWith("STMSG2\n")) {
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

function clientMessagesWsUrl(token: string) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const params = new URLSearchParams({ token });
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
    case "sent":
      return "已发送";
    case "failed":
      return "失败";
    case "received":
      return "收到";
    default:
      return status;
  }
}
