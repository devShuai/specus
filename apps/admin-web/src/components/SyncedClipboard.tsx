import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ClipboardEvent as ReactClipboardEvent } from "react";
import { Button, Chip, Switch } from "@heroui/react";
import {
  CLIPBOARD_TEXT_MAX_CHARS,
  CLIPBOARD_TEXT_MAX_UTF8_BYTES,
  createClipboardSessionId,
  createClipboardSyncPayload,
  type ClipboardInboundEvent,
  type ClipboardSyncPayload,
} from "../lib/clipboardSync";

type ClipboardViewState = "idle" | "ready" | "sending" | "sent" | "received" | "writing" | "written" | "needs-copy" | "failed";
const CLIPBOARD_WRITE_TIMEOUT_MS = 1500;

class ClipboardWriteTimeoutError extends Error {
  constructor() {
    super("浏览器未及时响应剪贴板写入请求");
    this.name = "ClipboardWriteTimeoutError";
  }
}

interface SyncedClipboardProps {
  syncKey: string;
  isActive: boolean;
  focusRequest: number;
  isEnabled: boolean;
  peerCount: number;
  targetPeerId: string;
  targetPeerLabel: string;
  events: ClipboardInboundEvent[];
  onEnabledChange: (enabled: boolean) => void;
  onSend: (payload: ClipboardSyncPayload) => Promise<void>;
}

interface SuccessfulClipboardWrite {
  intent: number;
  text: string;
  generation: number;
}

export function SyncedClipboard({
  syncKey,
  isActive,
  focusRequest,
  isEnabled,
  peerCount,
  targetPeerId,
  targetPeerLabel,
  events,
  onEnabledChange,
  onSend,
}: SyncedClipboardProps) {
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const handledFocusRequestRef = useRef(0);
  const sessionIdRef = useRef(createClipboardSessionId());
  const sequenceRef = useRef(0);
  const lastSeenEventRef = useRef("");
  const lastSuccessfulWriteRef = useRef("");
  const latestInboundRef = useRef<ClipboardInboundEvent | null>(null);
  const isEnabledRef = useRef(isEnabled);
  const syncGenerationRef = useRef(0);
  const clipboardWritePendingRef = useRef(false);
  const clipboardWriteIntentRef = useRef(0);
  const lastSuccessfulNativeWriteRef = useRef<SuccessfulClipboardWrite | null>(null);
  const autoWriteRunRef = useRef<{ token: symbol; eventId: string; generation: number } | null>(null);
  const sendTokenRef = useRef<symbol | null>(null);
  const [draft, setDraft] = useState("");
  const [latestInbound, setLatestInbound] = useState<ClipboardInboundEvent | null>(null);
  const [viewState, setViewState] = useState<ClipboardViewState>("idle");
  const [statusMessage, setStatusMessage] = useState("开启后，在此粘贴的纯文本会立即发送给选中的设备。");
  const [isSending, setSending] = useState(false);
  const [isClipboardWritePending, setClipboardWritePending] = useState(false);
  const [autoWriteRevision, setAutoWriteRevision] = useState(0);

  latestInboundRef.current = latestInbound;
  isEnabledRef.current = isEnabled;

  const byteLength = useMemo(() => new TextEncoder().encode(draft).byteLength, [draft]);
  const draftWithinLimits = draft.length <= CLIPBOARD_TEXT_MAX_CHARS && byteLength <= CLIPBOARD_TEXT_MAX_UTF8_BYTES;
  const targetLabel = targetPeerLabel || targetPeerId || "等待设备";
  const sourceLabel = latestInbound?.sourcePeerId || "在线设备";

  const writeClipboardWithTimeout = useCallback(async (text: string) => {
    clipboardWriteIntentRef.current += 1;
    const intent = clipboardWriteIntentRef.current;
    const generation = syncGenerationRef.current;
    const nativeWrite = writeClipboardText(text);

    const restoreLatestSuccessfulWrite = (expected: SuccessfulClipboardWrite) => {
      void writeClipboardText(expected.text).then(() => {
        const current = lastSuccessfulNativeWriteRef.current;
        if (current && current.intent > expected.intent) {
          restoreLatestSuccessfulWrite(current);
        }
      }, () => {
        const current = lastSuccessfulNativeWriteRef.current;
        if (!current || current.intent !== expected.intent) {
          return;
        }
        lastSuccessfulWriteRef.current = "";
        if (current.generation !== syncGenerationRef.current) {
          setViewState("failed");
          setStatusMessage("上一会话的迟到剪贴板写入未能自动纠正，请检查本机剪贴板。");
          return;
        }
        setViewState("needs-copy");
        setStatusMessage("浏览器未能自动恢复剪贴板，请点击“复制到本机”写入当前页面内容。");
      });
    };

    // The Clipboard API has no cancellation signal. If a timed-out older write eventually
    // succeeds after a newer app write, immediately restore the newest successfully written
    // app value so the stale operation cannot remain authoritative.
    void nativeWrite.then(() => {
      const latestSuccessful = lastSuccessfulNativeWriteRef.current;
      if (latestSuccessful && latestSuccessful.intent > intent) {
        restoreLatestSuccessfulWrite(latestSuccessful);
        return;
      }
      lastSuccessfulNativeWriteRef.current = { intent, text, generation };
    }, () => undefined);

    let timeoutId: number | null = null;
    try {
      await Promise.race([
        nativeWrite,
        new Promise<never>((_, reject) => {
          timeoutId = window.setTimeout(() => reject(new ClipboardWriteTimeoutError()), CLIPBOARD_WRITE_TIMEOUT_MS);
        }),
      ]);
    } finally {
      if (timeoutId !== null) {
        window.clearTimeout(timeoutId);
      }
    }
  }, []);

  useEffect(() => {
    syncGenerationRef.current += 1;
    sessionIdRef.current = createClipboardSessionId();
    sequenceRef.current = 0;
    lastSeenEventRef.current = "";
    lastSuccessfulWriteRef.current = "";
    sendTokenRef.current = null;
    setDraft("");
    setLatestInbound(null);
    setSending(false);
    setViewState(clipboardWritePendingRef.current ? "writing" : "idle");
    setStatusMessage(clipboardWritePendingRef.current
      ? "正在等待浏览器完成上一条剪贴板写入；完成前不会发起新的本机写入。"
      : "开启后，在此粘贴的纯文本会立即发送给选中的设备。");
  }, [syncKey]);

  useEffect(() => {
    if (!isActive
      || focusRequest === 0
      || handledFocusRequestRef.current === focusRequest) {
      return;
    }
    handledFocusRequestRef.current = focusRequest;
    const frame = window.requestAnimationFrame(() => textareaRef.current?.focus());
    return () => window.cancelAnimationFrame(frame);
  }, [focusRequest, isActive]);

  useEffect(() => {
    const incoming = events.at(-1);
    if (!incoming || incoming.eventId === lastSeenEventRef.current) {
      return;
    }
    lastSeenEventRef.current = incoming.eventId;
    setLatestInbound(incoming);
    setDraft(incoming.payload.text);
    setViewState("received");
    setStatusMessage(isEnabled
      ? `已收到 ${incoming.sourcePeerId} 的内容，正在写入本机剪贴板。`
      : `已收到 ${incoming.sourcePeerId} 的内容；开启同步后可自动写入。`);
  }, [events, isEnabled]);

  useEffect(() => {
    if (!isEnabled
      || !latestInbound
      || lastSuccessfulWriteRef.current === latestInbound.eventId
      || clipboardWritePendingRef.current) {
      return;
    }
    const timer = window.setTimeout(() => {
      const candidate = latestInboundRef.current;
      if (!isEnabledRef.current
        || !candidate
        || candidate.eventId !== latestInbound.eventId
        || clipboardWritePendingRef.current) {
        return;
      }
      const token = Symbol("clipboard-auto-write");
      const generation = syncGenerationRef.current;
      autoWriteRunRef.current = { token, eventId: candidate.eventId, generation };
      clipboardWritePendingRef.current = true;
      setClipboardWritePending(true);
      setViewState("writing");

      void writeClipboardWithTimeout(candidate.payload.text)
        .then(() => {
          if (autoWriteRunRef.current?.token !== token) {
            return;
          }
          if (syncGenerationRef.current === generation
            && latestInboundRef.current?.eventId === candidate.eventId) {
            lastSuccessfulWriteRef.current = candidate.eventId;
            setViewState("written");
            setStatusMessage(isEnabledRef.current
              ? `已将 ${candidate.sourcePeerId} 发来的内容写入本机剪贴板。`
              : `同步已暂停；关闭前开始的 ${candidate.sourcePeerId} 内容已完成写入。`);
          }
        })
        .catch((error) => {
          if (autoWriteRunRef.current?.token !== token) {
            return;
          }
          if (syncGenerationRef.current === generation
            && latestInboundRef.current?.eventId === candidate.eventId) {
            setViewState("needs-copy");
            setStatusMessage(error instanceof ClipboardWriteTimeoutError
              ? "自动写入等待超时，请点击“复制到本机”重试。"
              : "浏览器阻止了自动写入，请点击“复制到本机”。");
          }
        })
        .finally(() => {
          if (autoWriteRunRef.current?.token !== token) {
            return;
          }
          autoWriteRunRef.current = null;
          clipboardWritePendingRef.current = false;
          setClipboardWritePending(false);
          const generationChanged = syncGenerationRef.current !== generation;
          if (generationChanged) {
            setViewState(isEnabledRef.current ? "ready" : "idle");
            setStatusMessage(isEnabledRef.current
              ? "同步已开启，等待粘贴或接收内容。"
              : "同步已暂停，收到的内容不会覆盖本机剪贴板。");
          }
          if (isEnabledRef.current
            && latestInboundRef.current
            && (generationChanged || latestInboundRef.current.eventId !== candidate.eventId)) {
            setAutoWriteRevision((value) => value + 1);
          }
        });
    }, 350);
    return () => {
      window.clearTimeout(timer);
    };
  }, [autoWriteRevision, isEnabled, latestInbound, writeClipboardWithTimeout]);

  const submitText = useCallback(async (text: string) => {
    if (!isEnabled) {
      setViewState("idle");
      setStatusMessage("内容已保留在输入框；请先开启剪贴板同步。");
      return;
    }
    if (!targetPeerId) {
      setViewState("failed");
      setStatusMessage("还没有可发送的目标，请先邀请并选择一台设备。");
      return;
    }
    if (sendTokenRef.current) {
      return;
    }
    let sendToken: symbol | null = null;
    try {
      sequenceRef.current += 1;
      const payload = createClipboardSyncPayload(text, sessionIdRef.current, sequenceRef.current);
      sendToken = Symbol("clipboard-send");
      sendTokenRef.current = sendToken;
      setSending(true);
      setViewState("sending");
      setStatusMessage(`正在发送给 ${targetLabel}…`);
      await onSend(payload);
      if (sendTokenRef.current !== sendToken) {
        return;
      }
      setViewState("sent");
      setStatusMessage(`已发送给 ${targetLabel}。对方浏览器允许时会自动写入剪贴板。`);
    } catch (error) {
      if (!sendToken || sendTokenRef.current === sendToken) {
        setViewState("failed");
        setStatusMessage(error instanceof Error ? error.message : "剪贴板内容发送失败");
      }
    } finally {
      if (sendToken && sendTokenRef.current === sendToken) {
        sendTokenRef.current = null;
        setSending(false);
      }
    }
  }, [isEnabled, onSend, targetLabel, targetPeerId]);

  const handlePaste = (event: ReactClipboardEvent<HTMLElement>) => {
    if (sendTokenRef.current) {
      event.preventDefault();
      setStatusMessage("上一条内容仍在发送，请完成后再粘贴。");
      return;
    }
    const hasFiles = Array.from(event.clipboardData.items ?? []).some((item) => item.kind === "file");
    const text = event.clipboardData.getData("text/plain");
    if (!text) {
      if (hasFiles) {
        setViewState("failed");
        setStatusMessage("检测到的是文件，请切换到“文件传输”。");
      }
      return;
    }
    event.preventDefault();
    if (!isClipboardTextWithinLimits(text)) {
      setViewState("failed");
      setStatusMessage("剪贴板内容超过 16,384 个字符或 32 KiB，未发送。");
      return;
    }
    setDraft(text);
    if (!isEnabled) {
      setViewState("idle");
      setStatusMessage("内容已放入输入框；开启同步后再发送。");
      return;
    }
    void submitText(text);
  };

  const handleManualCopy = () => {
    if (!draft) {
      setViewState("failed");
      setStatusMessage("当前没有可以复制的内容。");
      return;
    }
    if (clipboardWritePendingRef.current) {
      setViewState("writing");
      setStatusMessage("浏览器仍在完成上一条剪贴板写入，请稍候再复制。");
      return;
    }
    clipboardWritePendingRef.current = true;
    setClipboardWritePending(true);
    setViewState("writing");
    setStatusMessage("正在写入本机剪贴板…");
    const generation = syncGenerationRef.current;
    const inboundEventIdAtStart = latestInboundRef.current?.eventId ?? "";
    void writeClipboardWithTimeout(draft)
      .then(() => {
        const currentInbound = latestInboundRef.current;
        if (syncGenerationRef.current !== generation) {
          return;
        }
        if (currentInbound?.payload.text === draft) {
          lastSuccessfulWriteRef.current = currentInbound.eventId;
        }
        setViewState("written");
        setStatusMessage("已复制到本机剪贴板。");
      })
      .catch((error) => {
        if (syncGenerationRef.current !== generation) {
          return;
        }
        setViewState("failed");
        setStatusMessage(error instanceof ClipboardWriteTimeoutError
          ? "复制等待超时，已解除占用；可以再次点击“复制到本机”。"
          : error instanceof Error ? error.message : "复制失败");
      })
      .finally(() => {
        clipboardWritePendingRef.current = false;
        setClipboardWritePending(false);
        const generationChanged = syncGenerationRef.current !== generation;
        if (generationChanged) {
          setViewState(isEnabledRef.current ? "ready" : "idle");
          setStatusMessage(isEnabledRef.current
            ? "同步已开启，等待粘贴或接收内容。"
            : "同步已暂停，收到的内容不会覆盖本机剪贴板。");
        }
        if (isEnabledRef.current
          && latestInboundRef.current
          && lastSuccessfulWriteRef.current !== latestInboundRef.current.eventId
          && (generationChanged || latestInboundRef.current.eventId !== inboundEventIdAtStart)) {
          setAutoWriteRevision((value) => value + 1);
        }
      });
  };

  const handleEnabledChange = (enabled: boolean) => {
    onEnabledChange(enabled);
    setViewState(enabled ? "ready" : "idle");
    setStatusMessage(enabled
      ? "同步已开启，等待粘贴或接收内容。"
      : "同步已暂停，收到的内容不会覆盖本机剪贴板。");
  };

  const clearDraft = () => {
    setDraft("");
    setLatestInbound(null);
    setViewState(isEnabled ? "ready" : "idle");
    setStatusMessage(isEnabled ? "内容已清空，继续等待同步。" : "内容已清空。");
    textareaRef.current?.focus();
  };

  return (
    <section
      id="transfer-panel-clipboard"
      role="tabpanel"
      aria-labelledby="transfer-tab-clipboard"
      hidden={!isActive}
      onPaste={handlePaste}
      className="mt-5 overflow-hidden rounded-xl border border-cyan-500/25 bg-gradient-to-br from-cyan-50/80 via-white/55 to-white/25 shadow-[0_18px_55px_-45px_rgba(8,145,178,0.95)] dark:border-cyan-300/20 dark:from-cyan-300/[0.08] dark:via-white/[0.035] dark:to-transparent"
    >
      <div className="flex flex-col gap-3 border-b border-black/10 p-4 dark:border-white/10 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold text-zinc-950 dark:text-white">同步剪贴板</h2>
            <Chip size="sm" radius="sm" variant="flat" color={isEnabled ? "success" : "default"}>
              {isEnabled ? "实时通道已开启" : "默认关闭"}
            </Chip>
          </div>
          <p className="mt-1 max-w-2xl text-tiny leading-5 text-zinc-600 dark:text-zinc-300">
            开启后，在这里粘贴会立即发给选中的设备；收到内容时会尝试写入本机剪贴板。
          </p>
        </div>
        <Switch size="sm" isSelected={isEnabled} onValueChange={handleEnabledChange}>
          {isEnabled ? "已开启" : "开启同步"}
        </Switch>
      </div>

      <div className="p-4">
        <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-3 rounded-lg border border-cyan-500/20 bg-cyan-500/[0.06] px-3 py-3 dark:border-cyan-300/15 dark:bg-cyan-300/[0.06]">
          <div className="min-w-0">
            <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-500 dark:text-zinc-400">Source</div>
            <div className="mt-1 truncate text-small font-semibold text-zinc-900 dark:text-white">本机剪贴板</div>
          </div>
          <div className="flex items-center gap-1.5 text-cyan-600 dark:text-cyan-200" aria-hidden="true">
            <span className={`h-2 w-2 rounded-full ${isEnabled ? "animate-pulse bg-emerald-500 motion-reduce:animate-none" : "bg-zinc-400"}`} />
            <span className="h-px w-5 bg-current sm:w-9" />
            <span className="font-mono text-sm">→</span>
          </div>
          <div className="min-w-0 text-right">
            <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-500 dark:text-zinc-400">Target</div>
            <div className="mt-1 truncate text-small font-semibold text-zinc-900 dark:text-white">{targetLabel}</div>
          </div>
        </div>

        <label htmlFor="public-transfer-clipboard-text" className="mt-4 block text-tiny font-medium uppercase tracking-[0.12em] text-zinc-500 dark:text-zinc-400">
          粘贴或输入纯文本
        </label>
        <textarea
          ref={textareaRef}
          id="public-transfer-clipboard-text"
          data-testid="public-transfer-clipboard-text"
          value={draft}
          maxLength={CLIPBOARD_TEXT_MAX_CHARS}
          spellCheck={false}
          readOnly={isSending}
          onChange={(event) => {
            const value = event.currentTarget.value;
            setDraft(value);
            if (!isClipboardTextWithinLimits(value)) {
              setViewState("failed");
              setStatusMessage("文本的 UTF-8 大小超过 32 KiB，请删减后再同步。");
            }
          }}
          placeholder="点击这里后按 Ctrl+V / ⌘V，粘贴后立即同步"
          className="mt-2 min-h-40 w-full resize-y rounded-lg border border-zinc-300 bg-white/70 px-3 py-3 font-mono text-small leading-6 text-zinc-950 outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-500/10 dark:border-white/15 dark:bg-black/20 dark:text-zinc-100 dark:focus:border-cyan-300"
        />

        <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-tiny text-zinc-500 dark:text-zinc-400">
          <span className={draftWithinLimits ? "" : "font-medium text-rose-600 dark:text-rose-300"}>{draft.length.toLocaleString()} / {CLIPBOARD_TEXT_MAX_CHARS.toLocaleString()} 字符 · {formatByteCount(byteLength)} / {formatByteCount(CLIPBOARD_TEXT_MAX_UTF8_BYTES)}</span>
          <span>{peerCount > 0 ? `${peerCount} 台在线 · 当前定向发送` : "等待另一台设备加入"}</span>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <Button
            color="primary"
            radius="sm"
            isLoading={isSending}
            isDisabled={!draft || !draftWithinLimits || !isEnabled || !targetPeerId}
            onPress={() => void submitText(draft)}
          >
            同步到设备
          </Button>
          <Button
            radius="sm"
            variant={viewState === "needs-copy" ? "solid" : "flat"}
            color={viewState === "needs-copy" ? "warning" : "default"}
            isLoading={isClipboardWritePending}
            isDisabled={isClipboardWritePending}
            onPress={handleManualCopy}
          >
            复制到本机
          </Button>
          <Button radius="sm" variant="light" isDisabled={isSending || isClipboardWritePending} onPress={clearDraft}>
            清空
          </Button>
        </div>

        <div
          aria-live="polite"
          className={`mt-3 rounded-lg border px-3 py-2 text-small ${statusClassName(viewState)}`}
        >
          {statusMessage}
          {latestInbound && (
            <span className="ml-1 text-tiny opacity-75">来源：{sourceLabel}</span>
          )}
        </div>

        <p className="mt-3 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
          内容仅保留在当前页面内存中，不会作为附件保存。直连不可用时会经互传服务实时转发；不要同步密码、令牌等敏感信息。
        </p>
      </div>
    </section>
  );
}

async function writeClipboardText(text: string) {
  if (!window.isSecureContext || !navigator.clipboard?.writeText) {
    throw new Error("当前浏览器不允许写入系统剪贴板，请使用 HTTPS 或 localhost");
  }
  await navigator.clipboard.writeText(text);
}

function statusClassName(state: ClipboardViewState) {
  if (state === "written" || state === "sent") {
    return "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-400/25 dark:bg-emerald-500/10 dark:text-emerald-100";
  }
  if (state === "needs-copy") {
    return "border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-400/25 dark:bg-amber-500/10 dark:text-amber-100";
  }
  if (state === "failed") {
    return "border-rose-300 bg-rose-50 text-rose-700 dark:border-rose-400/25 dark:bg-rose-500/10 dark:text-rose-100";
  }
  return "border-cyan-300/70 bg-cyan-50/70 text-cyan-900 dark:border-cyan-300/20 dark:bg-cyan-300/[0.07] dark:text-cyan-100";
}

function formatByteCount(bytes: number) {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`;
}

function isClipboardTextWithinLimits(text: string) {
  return text.length <= CLIPBOARD_TEXT_MAX_CHARS
    && new TextEncoder().encode(text).byteLength <= CLIPBOARD_TEXT_MAX_UTF8_BYTES;
}
