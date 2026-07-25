import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ClipboardEvent as ReactClipboardEvent } from "react";
import { Button, Chip } from "@heroui/react";
import {
  CLIPBOARD_TEXT_MAX_CHARS,
  CLIPBOARD_TEXT_MAX_UTF8_BYTES,
  clipboardPayloadHtml,
  createClipboardSessionId,
  createClipboardSyncPayload,
  type ClipboardContentKind,
  type ClipboardInboundEvent,
  type ClipboardSyncPayload,
} from "../lib/clipboardSync";
import {
  createInboundClipboardTextBlocks,
  createLocalClipboardTextBlock,
  prependClipboardTextBlocks,
  updateClipboardTextBlock,
  type ClipboardTextBlock,
} from "../lib/clipboardBlocks";

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
  canSend: boolean;
  fileTargetRequired: boolean;
  targetPeerId: string;
  targetPeerLabel: string;
  events: ClipboardInboundEvent[];
  onSend: (payload: ClipboardSyncPayload) => Promise<void>;
  onFiles: (files: File[]) => void;
  onDraftStateChange?: (hasDraft: boolean) => void;
}

interface SuccessfulClipboardWrite {
  intent: number;
  text: string;
  html?: string;
  generation: number;
}

export function SyncedClipboard({
  syncKey,
  isActive,
  focusRequest,
  canSend,
  fileTargetRequired,
  targetPeerId,
  targetPeerLabel,
  events,
  onSend,
  onFiles,
  onDraftStateChange,
}: SyncedClipboardProps) {
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const handledFocusRequestRef = useRef(0);
  const sessionIdRef = useRef(createClipboardSessionId());
  const sequenceRef = useRef(0);
  const materializedInboundEventsRef = useRef<Set<string>>(new Set());
  const lastSuccessfulWriteRef = useRef("");
  const latestInboundRef = useRef<ClipboardInboundEvent | null>(null);
  const canSendRef = useRef(canSend);
  const syncGenerationRef = useRef(0);
  const clipboardWritePendingRef = useRef(false);
  const clipboardWriteIntentRef = useRef(0);
  const lastSuccessfulNativeWriteRef = useRef<SuccessfulClipboardWrite | null>(null);
  const autoWriteRunRef = useRef<{ token: symbol; eventId: string; generation: number } | null>(null);
  const sendTokenRef = useRef<symbol | null>(null);
  const draftStorageKeyRef = useRef("");
  const skipDraftPersistRef = useRef(false);
  const [composerDraft, setComposerDraft] = useState("");
  const [blocks, setBlocks] = useState<ClipboardTextBlock[]>([]);
  const [latestInbound, setLatestInbound] = useState<ClipboardInboundEvent | null>(null);
  const [viewState, setViewState] = useState<ClipboardViewState>("idle");
  const [statusMessage, setStatusMessage] = useState("粘贴文本、富文本、链接或文件，将直接发送给选中的设备。");
  const [isSending, setSending] = useState(false);
  const [sendingBlockId, setSendingBlockId] = useState("");
  const [isClipboardWritePending, setClipboardWritePending] = useState(false);
  const [clipboardWriteBlockId, setClipboardWriteBlockId] = useState("");
  const [isSystemClipboardReading, setSystemClipboardReading] = useState(false);
  const [autoWriteRevision, setAutoWriteRevision] = useState(0);
  const [editingBlockId, setEditingBlockId] = useState("");

  latestInboundRef.current = latestInbound;
  canSendRef.current = canSend;

  const composerByteLength = useMemo(() => new TextEncoder().encode(composerDraft).byteLength, [composerDraft]);
  const composerWithinLimits = composerDraft.length <= CLIPBOARD_TEXT_MAX_CHARS
    && composerByteLength <= CLIPBOARD_TEXT_MAX_UTF8_BYTES;
  const targetLabel = targetPeerLabel || targetPeerId || "等待设备";
  const sourceLabel = latestInbound?.sourceDisplayName || "未命名设备";

  const sendClipboardFiles = (files: File[]) => {
    if (fileTargetRequired && !targetPeerId) {
      setViewState("failed");
      setStatusMessage("剪贴板中包含文件，请先从“发送给谁”选择一台设备。");
      return false;
    }
    onFiles(files);
    return true;
  };

  const writeClipboardWithTimeout = useCallback(async (text: string, html = "") => {
    clipboardWriteIntentRef.current += 1;
    const intent = clipboardWriteIntentRef.current;
    const generation = syncGenerationRef.current;
    const nativeWrite = writeClipboardContent(text, html);

    const restoreLatestSuccessfulWrite = (expected: SuccessfulClipboardWrite) => {
      void writeClipboardContent(expected.text, expected.html ?? "").then(() => {
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
        setStatusMessage("浏览器未能自动恢复剪贴板，请点击“复制到剪贴板”重试。");
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
      lastSuccessfulNativeWriteRef.current = { intent, text, html, generation };
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
    materializedInboundEventsRef.current.clear();
    lastSuccessfulWriteRef.current = "";
    sendTokenRef.current = null;
    const persisted = readClipboardDraft(syncKey);
    skipDraftPersistRef.current = true;
    draftStorageKeyRef.current = syncKey;
    setComposerDraft(persisted.composerDraft);
    setBlocks(persisted.blocks);
    onDraftStateChange?.(Boolean(persisted.composerDraft || persisted.blocks.length > 0));
    setLatestInbound(null);
    setSending(false);
    setSendingBlockId("");
    setClipboardWriteBlockId("");
    setViewState(clipboardWritePendingRef.current ? "writing" : "idle");
    setStatusMessage(clipboardWritePendingRef.current
      ? "正在等待浏览器完成上一条剪贴板写入；完成前不会发起新的本机写入。"
      : "粘贴文本、富文本、链接或文件，将直接发送给选中的设备。");
  }, [onDraftStateChange, syncKey]);

  useEffect(() => {
    if (draftStorageKeyRef.current !== syncKey) return;
    if (skipDraftPersistRef.current) {
      skipDraftPersistRef.current = false;
      return;
    }
    writeClipboardDraft(syncKey, composerDraft, blocks);
    onDraftStateChange?.(Boolean(composerDraft || blocks.length > 0));
  }, [blocks, composerDraft, onDraftStateChange, syncKey]);

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
    const freshEvents = events.filter((event) => !materializedInboundEventsRef.current.has(event.eventId));
    if (freshEvents.length === 0) {
      return;
    }
    for (const event of freshEvents) {
      materializedInboundEventsRef.current.add(event.eventId);
    }
    const incomingBlocks = createInboundClipboardTextBlocks(freshEvents);
    setBlocks((current) => prependClipboardTextBlocks(current, incomingBlocks));
    const incoming = freshEvents.at(-1)!;
    setLatestInbound(incoming);
    setViewState("received");
    const incomingLabel = incoming.sourceDisplayName || "未命名设备";
    setStatusMessage(canSend
      ? `已收到 ${incomingLabel} 的内容，正在写入系统剪贴板。`
      : `已收到 ${incomingLabel} 的内容；当前房间只读，可手动写入系统剪贴板。`);
  }, [canSend, events]);

  useEffect(() => {
    if (!canSend
      || !latestInbound
      || lastSuccessfulWriteRef.current === latestInbound.eventId
      || clipboardWritePendingRef.current) {
      return;
    }
    const timer = window.setTimeout(() => {
      const candidate = latestInboundRef.current;
      if (!canSendRef.current
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
      setClipboardWriteBlockId(`remote:${candidate.eventId}`);
      setViewState("writing");

      void writeClipboardWithTimeout(candidate.payload.text, clipboardPayloadHtml(candidate.payload))
        .then(() => {
          if (autoWriteRunRef.current?.token !== token) {
            return;
          }
          if (syncGenerationRef.current === generation
            && latestInboundRef.current?.eventId === candidate.eventId) {
            lastSuccessfulWriteRef.current = candidate.eventId;
            setViewState("written");
            setStatusMessage(canSendRef.current
              ? `已将 ${candidate.sourceDisplayName || "未命名设备"} 发来的内容写入系统剪贴板。`
              : `房间已切换为只读；此前开始的内容已完成写入。`);
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
              ? "自动写入等待超时，请点击“复制到剪贴板”重试。"
              : "浏览器阻止了自动写入，请点击“复制到剪贴板”。");
          }
        })
        .finally(() => {
          if (autoWriteRunRef.current?.token !== token) {
            return;
          }
          autoWriteRunRef.current = null;
          clipboardWritePendingRef.current = false;
          setClipboardWritePending(false);
          setClipboardWriteBlockId("");
          const generationChanged = syncGenerationRef.current !== generation;
          if (generationChanged) {
            setViewState(canSendRef.current ? "ready" : "idle");
            setStatusMessage(canSendRef.current
              ? "等待粘贴或接收内容。"
              : "当前房间为只读，不能发送剪贴板内容。");
          }
          if (canSendRef.current
            && latestInboundRef.current
            && (generationChanged || latestInboundRef.current.eventId !== candidate.eventId)) {
            setAutoWriteRevision((value) => value + 1);
          }
        });
    }, 350);
    return () => {
      window.clearTimeout(timer);
    };
  }, [autoWriteRevision, canSend, latestInbound, writeClipboardWithTimeout]);

  const submitText = useCallback(async (
    text: string,
    blockId: string,
    kind: ClipboardContentKind = "text",
    html = "",
  ) => {
    if (!canSend) {
      setViewState("idle");
      setStatusMessage("内容已保留在输入框；当前房间为只读，不能发送。");
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
      const payload = createClipboardSyncPayload(text, sessionIdRef.current, sequenceRef.current, { kind, html });
      sendToken = Symbol("clipboard-send");
      sendTokenRef.current = sendToken;
      setSending(true);
      setSendingBlockId(blockId);
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
        setSendingBlockId("");
      }
    }
  }, [canSend, onSend, targetLabel, targetPeerId]);

  const addLocalBlock = useCallback((
    text: string,
    content: { kind?: ClipboardContentKind; html?: string } = {},
  ) => {
    if (!text) {
      setViewState("failed");
      setStatusMessage("请输入或粘贴内容后再创建剪贴板项。");
      return;
    }
    if (!isClipboardContentWithinLimits(text, content.html ?? "")) {
      setViewState("failed");
      setStatusMessage(`剪贴板内容超过 ${CLIPBOARD_TEXT_MAX_CHARS.toLocaleString()} 个字符或 ${formatByteCount(CLIPBOARD_TEXT_MAX_UTF8_BYTES)}，未创建内容项。`);
      return;
    }
    const block = createLocalClipboardTextBlock(text, Date.now(), undefined, content);
    setBlocks((current) => prependClipboardTextBlocks(current, [block]));
    setComposerDraft("");
    window.requestAnimationFrame(() => textareaRef.current?.focus());

    if (!canSend) {
      setViewState("idle");
      setStatusMessage("已保存剪贴板内容；当前房间为只读，不能发送。");
      return;
    }
    if (!targetPeerId) {
      setViewState("ready");
      setStatusMessage("已保存剪贴板内容；选择一台在线设备后可发送。");
      return;
    }
    if (sendTokenRef.current) {
      setViewState("ready");
      setStatusMessage("上一块仍在发送，新内容已保留，可稍后单独同步。");
      return;
    }
    void submitText(text, block.id, block.kind, block.html);
  }, [canSend, submitText, targetPeerId]);

  const readSystemClipboard = () => {
    if (isSystemClipboardReading) {
      return;
    }
    setSystemClipboardReading(true);
    setViewState("ready");
    setStatusMessage("正在读取系统剪贴板…");
    const generation = syncGenerationRef.current;
    void readSystemClipboardContent()
      .then(({ text, html, files }) => {
        if (generation !== syncGenerationRef.current) {
          return;
        }
        const filesAccepted = files.length > 0 ? sendClipboardFiles(files) : false;
        if (!text && files.length === 0) {
          setViewState("idle");
          setStatusMessage("系统剪贴板中没有浏览器可读取的内容。");
          return;
        }
        if (text) {
          addLocalBlock(text, classifyClipboardContent(text, html));
        } else if (filesAccepted) {
          setViewState("ready");
          setStatusMessage(`已读取 ${files.length} 个文件，正在通过文件通道发送。`);
        }
      })
      .catch((error) => {
        if (generation !== syncGenerationRef.current) {
          return;
        }
        setViewState("failed");
        setStatusMessage(systemClipboardErrorMessage(error, "读取"));
      })
      .finally(() => setSystemClipboardReading(false));
  };

  const handlePaste = (event: ReactClipboardEvent<HTMLElement>) => {
    const target = event.target;
    if (target instanceof HTMLElement && target.closest("[data-clipboard-block-editor='true']")) {
      return;
    }
    const files = Array.from(event.clipboardData.files ?? []);
    for (const item of Array.from(event.clipboardData.items ?? [])) {
      const file = item.kind === "file" ? item.getAsFile() : null;
      if (file && !files.some((candidate) => candidate.name === file.name
        && candidate.size === file.size
        && candidate.type === file.type
        && candidate.lastModified === file.lastModified)) {
        files.push(file);
      }
    }
    const text = event.clipboardData.getData("text/plain");
    const html = event.clipboardData.getData("text/html");
    if (!text && files.length === 0) {
      return;
    }
    event.preventDefault();
    let filesBlockedByMissingTarget = false;
    if (files.length > 0) {
      if (sendClipboardFiles(files)) {
        if (!text) {
          setViewState("ready");
          setStatusMessage(`已粘贴 ${files.length} 个文件，正在通过文件通道发送。`);
          return;
        }
      } else if (!text) {
        return;
      } else {
        filesBlockedByMissingTarget = true;
      }
    } else if (!text) {
      return;
    }
    const content = classifyClipboardContent(text, html);
    if (!isClipboardContentWithinLimits(text, content.html ?? "")) {
      setViewState("failed");
      setStatusMessage(`剪贴板内容超过 ${CLIPBOARD_TEXT_MAX_CHARS.toLocaleString()} 个字符或 ${formatByteCount(CLIPBOARD_TEXT_MAX_UTF8_BYTES)}，未发送。`);
      return;
    }
    addLocalBlock(text, content);
    if (filesBlockedByMissingTarget) {
      // 混合粘贴：文件因未选目标被跳过，与文本结果合并成一条提示，避免文件静默丢弃。
      setViewState("failed");
      setStatusMessage("剪贴板中的文件未发送：请先从“发送给谁”选择一台设备；文本已保存，选择设备后可同步。");
    }
  };

  const handleManualCopy = (block: ClipboardTextBlock) => {
    if (!block.text) {
      setViewState("failed");
      setStatusMessage("这一项没有可以写入系统剪贴板的内容。");
      return;
    }
    if (clipboardWritePendingRef.current) {
      setViewState("writing");
      setStatusMessage("浏览器仍在完成上一条剪贴板写入，请稍候再复制。");
      return;
    }
    clipboardWritePendingRef.current = true;
    setClipboardWritePending(true);
    setClipboardWriteBlockId(block.id);
    setViewState("writing");
    setStatusMessage("正在写入本机剪贴板…");
    const generation = syncGenerationRef.current;
    const inboundEventIdAtStart = latestInboundRef.current?.eventId ?? "";
    const text = block.text;
    void writeClipboardWithTimeout(text, block.html ?? "")
      .then(() => {
        const currentInbound = latestInboundRef.current;
        if (syncGenerationRef.current !== generation) {
          return;
        }
        if (block.sourceEventId
          && currentInbound?.eventId === block.sourceEventId
          && currentInbound.payload.text === text) {
          lastSuccessfulWriteRef.current = currentInbound.eventId;
        }
        setViewState("written");
        setStatusMessage("已写入系统剪贴板。");
      })
      .catch((error) => {
        if (syncGenerationRef.current !== generation) {
          return;
        }
        setViewState("failed");
        setStatusMessage(error instanceof ClipboardWriteTimeoutError
          ? "写入等待超时，已解除占用；可以再次点击“复制到剪贴板”。"
          : systemClipboardErrorMessage(error, "写入"));
      })
      .finally(() => {
        clipboardWritePendingRef.current = false;
        setClipboardWritePending(false);
        setClipboardWriteBlockId("");
        const generationChanged = syncGenerationRef.current !== generation;
        if (generationChanged) {
          setViewState(canSendRef.current ? "ready" : "idle");
          setStatusMessage(canSendRef.current
            ? "等待粘贴或接收内容。"
            : "当前房间为只读，不能发送剪贴板内容。");
        }
        if (canSendRef.current
          && latestInboundRef.current
          && lastSuccessfulWriteRef.current !== latestInboundRef.current.eventId
          && (generationChanged || latestInboundRef.current.eventId !== inboundEventIdAtStart)) {
          setAutoWriteRevision((value) => value + 1);
        }
      });
  };

  const updateBlockText = (blockId: string, text: string) => {
    const content = classifyClipboardContent(text, "");
    setBlocks((current) => updateClipboardTextBlock(current, blockId, text, content));
    // 编辑超限只在该内容块内联提示（withinLimits 渲染），不改动全局状态条。
  };

  const removeBlock = (block: ClipboardTextBlock) => {
    setBlocks((current) => current.filter((item) => item.id !== block.id));
    if (editingBlockId === block.id) {
      setEditingBlockId("");
    }
    if (block.sourceEventId && latestInboundRef.current?.eventId === block.sourceEventId) {
      setLatestInbound(null);
    }
    setViewState(canSend ? "ready" : "idle");
    setStatusMessage("剪贴板内容已删除，其它内容未受影响。");
  };

  const clearAllBlocks = () => {
    setBlocks([]);
    setLatestInbound(null);
    setViewState(canSend ? "ready" : "idle");
    setStatusMessage(canSend ? "剪贴板内容已清空，等待粘贴或接收内容。" : "剪贴板内容已清空。");
    textareaRef.current?.focus();
  };

  return (
    <section
      id="transfer-panel-clipboard"
      role="tabpanel"
      aria-labelledby="transfer-tab-clipboard"
      hidden={!isActive}
      onPaste={handlePaste}
      className="mt-3 overflow-hidden rounded-xl border border-black/[0.07] bg-white/40 dark:border-white/[0.08] dark:bg-white/[0.02]"
    >
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1.5 border-b border-black/[0.06] px-4 py-3 dark:border-white/[0.07]">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h2 className="text-base font-semibold text-zinc-950 dark:text-white">同步剪贴板</h2>
          <Chip size="sm" radius="sm" variant="flat" color={canSend && targetPeerId ? "success" : "default"}>
            {canSend ? (targetPeerId ? "粘贴即发送" : "等待设备") : "只读"}
          </Chip>
          {blocks.length > 0 && (
            <Chip size="sm" radius="sm" variant="flat">
              {blocks.length} 项
            </Chip>
          )}
        </div>
        <p className="text-tiny text-zinc-500 dark:text-zinc-400">
          {!canSend
            ? "只读房间：可查看和复制收到的内容"
            : targetPeerId
              ? <>同步到 <span title={targetLabel} className="font-medium text-zinc-700 [overflow-wrap:anywhere] dark:text-zinc-200">{targetLabel}</span></>
              : "选择一台在线设备即可同步"}
        </p>
      </div>

      <div className="flex flex-col gap-3 px-4 py-3">
        <div className="rounded-xl border border-black/[0.06] bg-gradient-to-b from-white/90 to-white/50 p-3 shadow-sm dark:border-white/[0.08] dark:from-white/[0.05] dark:to-white/[0.02]">
          <textarea
            ref={textareaRef}
            id="public-transfer-clipboard-text"
            data-testid="public-transfer-clipboard-text"
            aria-label="添加剪贴板内容"
            value={composerDraft}
            maxLength={CLIPBOARD_TEXT_MAX_CHARS}
            spellCheck={false}
            onChange={(event) => {
              const value = event.currentTarget.value;
              setComposerDraft(value);
              if (!isClipboardContentWithinLimits(value, "")) {
                setViewState("failed");
                setStatusMessage(`文本的 UTF-8 大小超过 ${formatByteCount(CLIPBOARD_TEXT_MAX_UTF8_BYTES)}，请删减后再创建文本块。`);
              }
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
                event.preventDefault();
                addLocalBlock(composerDraft, classifyClipboardContent(composerDraft, ""));
              }
            }}
            placeholder="粘贴或输入内容，Ctrl/⌘ + Enter 添加"
            className="min-h-24 w-full resize-y rounded-lg border border-transparent bg-black/[0.035] px-3.5 py-2.5 font-mono text-small leading-6 text-zinc-950 outline-none transition placeholder:text-zinc-400 hover:bg-black/[0.05] focus:border-primary-500/50 focus:bg-white focus:shadow-[0_0_0_4px_rgba(0,102,204,0.08)] dark:bg-white/[0.05] dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:hover:bg-white/[0.07] dark:focus:border-primary-400/50 dark:focus:bg-black/30"
          />
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
            <span className={`text-tiny ${composerDraft && !composerWithinLimits ? "font-medium text-rose-600 dark:text-rose-300" : "text-zinc-400 dark:text-zinc-500"}`}>
              {composerDraft
                ? `${composerDraft.length.toLocaleString()} / ${CLIPBOARD_TEXT_MAX_CHARS.toLocaleString()} 字符 · ${formatByteCount(composerByteLength)}`
                : "文本、富文本、链接；文件走文件通道"}
            </span>
            <div className="flex items-center gap-1.5">
              <Button
                radius="sm"
                size="sm"
                variant="flat"
                isLoading={isSystemClipboardReading}
                onPress={readSystemClipboard}
              >
                读取剪贴板
              </Button>
              <Button
                color="primary"
                radius="sm"
                size="sm"
                isDisabled={!composerDraft || !composerWithinLimits}
                onPress={() => addLocalBlock(composerDraft, classifyClipboardContent(composerDraft, ""))}
              >
                {canSend && targetPeerId && !isSending ? "添加并同步" : "添加内容"}
              </Button>
            </div>
          </div>
        </div>

        {blocks.length === 0 ? (
          <div className="rounded-lg border border-dashed border-black/15 px-4 py-6 text-center text-small text-zinc-500 dark:border-white/15 dark:text-zinc-400">
            暂无内容。读取系统剪贴板或直接粘贴即可开始。
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-2">
              <p className="text-tiny text-zinc-400 dark:text-zinc-500">最新在前 · 最多保留 80 条</p>
              <Button
                radius="sm"
                size="sm"
                variant="light"
                isDisabled={isSending || isClipboardWritePending}
                onPress={clearAllBlocks}
              >
                清空全部
              </Button>
            </div>
            {blocks.map((block) => {
              const withinLimits = isClipboardContentWithinLimits(block.text, block.html ?? "");
              const isLatestInbound = Boolean(block.sourceEventId && latestInbound?.eventId === block.sourceEventId);
              const needsCopy = viewState === "needs-copy" && isLatestInbound;
              const isEditing = editingBlockId === block.id;
              return (
                <article key={block.id} className="min-w-0 rounded-lg border border-black/[0.07] bg-white/55 p-3 dark:border-white/[0.08] dark:bg-white/[0.03]">
                  <div className="flex min-w-0 items-center gap-2">
                    <Chip size="sm" radius="sm" variant="flat" color={block.origin === "remote" ? "success" : "primary"}>
                      {block.origin === "remote" ? "收到" : "本机"}
                    </Chip>
                    <Chip size="sm" radius="sm" variant="flat">
                      {clipboardKindLabel(block.kind)}
                    </Chip>
                    <span className="min-w-0 flex-1 truncate text-tiny font-medium text-zinc-600 dark:text-zinc-300">
                      {block.origin === "remote" ? `来自 ${block.sourceDisplayName || "未命名设备"}` : "本机剪贴板"}
                    </span>
                    <time className="shrink-0 font-mono text-[10px] text-zinc-400 dark:text-zinc-500" dateTime={new Date(block.createdAt).toISOString()} title={new Date(block.createdAt).toLocaleString()}>
                      {formatClipboardTime(block.createdAt)}
                    </time>
                  </div>
                  {block.kind === "html" && block.html ? (
                    <div
                      className="clipboard-rich-preview mt-2 max-h-40 overflow-auto rounded-md border border-black/[0.07] bg-white px-3 py-2 text-small text-zinc-900 dark:border-white/[0.08] dark:bg-white/[0.04] dark:text-zinc-100"
                      dangerouslySetInnerHTML={{ __html: sanitizeClipboardHtml(block.html) }}
                    />
                  ) : null}
                  {block.kind === "link" ? (
                    <a
                      href={block.text}
                      target="_blank"
                      rel="noreferrer"
                      className="mt-2 block truncate text-small font-medium text-primary-600 underline decoration-primary-500/30 underline-offset-2 dark:text-primary-300"
                    >
                      {block.text}
                    </a>
                  ) : null}
                  <div className="relative mt-2">
                    {isEditing ? (
                      <textarea
                        data-clipboard-block-editor="true"
                        aria-label={block.origin === "remote" ? `编辑来自 ${block.sourceDisplayName || "未命名设备"} 的剪贴板内容` : "编辑本机剪贴板内容"}
                        value={block.text}
                        maxLength={CLIPBOARD_TEXT_MAX_CHARS}
                        spellCheck={false}
                        autoFocus
                        onChange={(event) => updateBlockText(block.id, event.currentTarget.value)}
                        className="block min-h-20 w-full resize-y rounded-md bg-black/[0.045] px-3 py-2 pr-10 font-mono text-small leading-5 text-zinc-800 outline-none ring-1 ring-primary-500/50 transition dark:bg-white/[0.06] dark:text-zinc-200"
                      />
                    ) : (
                      <div className="rounded-md bg-black/[0.03] px-3 py-2 pr-10 transition hover:bg-black/[0.045] dark:bg-white/[0.04] dark:hover:bg-white/[0.055]">
                        <span className="line-clamp-3 whitespace-pre-wrap break-words font-mono text-small leading-5 text-zinc-800 dark:text-zinc-200">
                          {block.text}
                        </span>
                      </div>
                    )}
                    <button
                      type="button"
                      aria-label={isEditing ? "完成编辑" : "编辑内容"}
                      title={isEditing ? "完成编辑" : "编辑内容"}
                      onClick={() => setEditingBlockId(isEditing ? "" : block.id)}
                      className={`absolute right-1.5 top-1.5 grid h-7 w-7 place-items-center rounded-md transition ${
                        isEditing
                          ? "bg-primary-500/10 text-primary-600 hover:bg-primary-500/20 dark:text-primary-300"
                          : "text-zinc-400 hover:bg-black/[0.06] hover:text-zinc-700 dark:hover:bg-white/[0.08] dark:hover:text-zinc-200"
                      }`}
                    >
                      {isEditing ? <CheckGlyph /> : <PencilGlyph />}
                    </button>
                  </div>
                  {!withinLimits && (
                    <p className="mt-1.5 text-tiny font-medium text-rose-600 dark:text-rose-300">
                      内容超过上限，请删减后再同步。
                    </p>
                  )}
                  <div className="mt-2 flex flex-wrap items-center justify-end gap-1.5">
                    <Button
                      color="primary"
                      radius="sm"
                      size="sm"
                      variant="flat"
                      isLoading={sendingBlockId === block.id}
                      isDisabled={!block.text || !withinLimits || !canSend || !targetPeerId || isSending}
                      onPress={() => void submitText(block.text, block.id, block.kind, block.html)}
                    >
                      同步到设备
                    </Button>
                    <Button
                      radius="sm"
                      size="sm"
                      variant={needsCopy ? "solid" : "flat"}
                      color={needsCopy ? "warning" : "default"}
                      isLoading={clipboardWriteBlockId === block.id}
                      isDisabled={isClipboardWritePending && clipboardWriteBlockId !== block.id}
                      onPress={() => handleManualCopy(block)}
                    >
                      复制到剪贴板
                    </Button>
                    <Button
                      radius="sm"
                      size="sm"
                      variant="light"
                      isDisabled={sendingBlockId === block.id || clipboardWriteBlockId === block.id}
                      onPress={() => removeBlock(block)}
                    >
                      删除
                    </Button>
                  </div>
                </article>
              );
            })}
          </div>
        )}

        <div
          aria-live="polite"
          className={`rounded-lg border px-3 py-2 text-small ${statusClassName(viewState)}`}
        >
          {statusMessage}
          {latestInbound && (
            <span className="ml-1 text-tiny opacity-75">来源：{sourceLabel}</span>
          )}
        </div>

        <p className="text-tiny leading-5 text-zinc-400 dark:text-zinc-500">
          内容仅保留在当前页面。不要同步密码、令牌等敏感信息。
        </p>
      </div>
    </section>
  );
}

function clipboardContentByteLength(text: string, html = "") {
  return new TextEncoder().encode(text).byteLength + new TextEncoder().encode(html).byteLength;
}

function PencilGlyph() {
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M16.8 3.8a2.1 2.1 0 0 1 3 3L8.5 18.1 4 19.5l1.4-4.5L16.8 3.8Z" />
      <path d="m14.8 5.8 3 3" />
    </svg>
  );
}

function CheckGlyph() {
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="m4.5 12.5 5 5 10-11" />
    </svg>
  );
}

function formatClipboardTime(timestamp: number) {
  return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

async function writeClipboardContent(text: string, html = "") {
  if (!window.isSecureContext || !navigator.clipboard?.writeText) {
    throw new Error("当前浏览器不允许写入系统剪贴板，请使用 HTTPS 或 localhost");
  }
  const safeHtml = html ? sanitizeClipboardHtml(html) : "";
  if (safeHtml && navigator.clipboard.write && typeof ClipboardItem !== "undefined") {
    await navigator.clipboard.write([
      new ClipboardItem({
        "text/plain": new Blob([text], { type: "text/plain" }),
        "text/html": new Blob([safeHtml], { type: "text/html" }),
      }),
    ]);
    return;
  }
  await navigator.clipboard.writeText(text);
}

async function readSystemClipboardContent(): Promise<{ text: string; html: string; files: File[] }> {
  if (!window.isSecureContext || !navigator.clipboard?.readText) {
    throw new Error("当前浏览器不允许读取系统剪贴板，请使用 HTTPS 或 localhost");
  }
  if (!navigator.clipboard.read) {
    return { text: await navigator.clipboard.readText(), html: "", files: [] };
  }

  const items = await navigator.clipboard.read();
  let text = "";
  let html = "";
  const files: File[] = [];
  for (const item of items) {
    for (const type of item.types) {
      const blob = await item.getType(type);
      if (type === "text/plain" && !text) {
        text = await blob.text();
      } else if (type === "text/html" && !html) {
        html = await blob.text();
      } else if (!type.startsWith("text/")) {
        files.push(new File([blob], clipboardFileName(type, files.length), { type }));
      }
    }
  }
  if (!text && html) {
    text = clipboardHtmlToText(html);
  }
  return { text, html, files };
}

function classifyClipboardContent(text: string, html: string): { kind: ClipboardContentKind; html?: string } {
  const safeHtml = html ? sanitizeClipboardHtml(html) : "";
  if (safeHtml) {
    return { kind: "html", html: safeHtml };
  }
  return { kind: text === text.trim() && isHttpUrl(text) ? "link" : "text" };
}

function sanitizeClipboardHtml(html: string) {
  if (typeof DOMParser === "undefined") {
    return "";
  }
  const document = new DOMParser().parseFromString(html, "text/html");
  document.querySelectorAll("script,style,iframe,object,embed,link,meta,form,input,button,svg,math,img").forEach((node) => node.remove());
  document.body.querySelectorAll("*").forEach((element) => {
    for (const attribute of Array.from(element.attributes)) {
      const name = attribute.name.toLowerCase();
      if (name.startsWith("on") || name === "style" || name === "class" || name === "id" || name === "src" || name === "srcset") {
        element.removeAttribute(attribute.name);
      }
    }
    if (element instanceof HTMLAnchorElement) {
      const href = element.getAttribute("href") ?? "";
      if (!isSafeRichTextLink(href)) {
        element.removeAttribute("href");
      } else {
        element.setAttribute("target", "_blank");
        element.setAttribute("rel", "noreferrer");
      }
    }
  });
  return document.body.innerHTML.trim();
}

function clipboardHtmlToText(html: string) {
  if (typeof DOMParser === "undefined") {
    return "";
  }
  return new DOMParser().parseFromString(html, "text/html").body.textContent?.trim() ?? "";
}

function clipboardFileName(mimeType: string, index: number) {
  const extension = mimeType.split("/", 2)[1]?.replace(/[^a-z0-9.+-]/gi, "") || "bin";
  return `clipboard-${Date.now()}-${index + 1}.${extension}`;
}

function clipboardKindLabel(kind: ClipboardContentKind) {
  if (kind === "html") {
    return "富文本";
  }
  if (kind === "link") {
    return "链接";
  }
  return "文本";
}

function isHttpUrl(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function isSafeRichTextLink(value: string) {
  if (!value) {
    return false;
  }
  try {
    const url = new URL(value, window.location.href);
    return url.protocol === "http:" || url.protocol === "https:" || url.protocol === "mailto:";
  } catch {
    return false;
  }
}

function systemClipboardErrorMessage(error: unknown, action: "读取" | "写入") {
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "SecurityError")) {
    return `浏览器未授权${action}系统剪贴板，请允许剪贴板权限后重试。`;
  }
  return error instanceof Error ? error.message : `${action}系统剪贴板失败`;
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
  return "border-primary-300/70 bg-primary-50/70 text-primary-900 dark:border-primary-300/20 dark:bg-primary-300/[0.07] dark:text-primary-100";
}

function formatByteCount(bytes: number) {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`;
}

function isClipboardContentWithinLimits(text: string, html: string) {
  return text.length + html.length <= CLIPBOARD_TEXT_MAX_CHARS
    && clipboardContentByteLength(text, html) <= CLIPBOARD_TEXT_MAX_UTF8_BYTES;
}

function clipboardDraftStorageKey(syncKey: string) {
  return `public-transfer-clipboard-draft:${syncKey}`;
}

function readClipboardDraft(syncKey: string): { composerDraft: string; blocks: ClipboardTextBlock[] } {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(clipboardDraftStorageKey(syncKey)) ?? "{}") as {
      composerDraft?: unknown;
      blocks?: unknown;
    };
    const composerDraft = typeof parsed.composerDraft === "string"
      ? parsed.composerDraft.slice(0, CLIPBOARD_TEXT_MAX_CHARS)
      : "";
    const blocks = Array.isArray(parsed.blocks)
      ? parsed.blocks.filter(isPersistedClipboardBlock).slice(0, 80)
      : [];
    return { composerDraft, blocks };
  } catch {
    return { composerDraft: "", blocks: [] };
  }
}

function writeClipboardDraft(syncKey: string, composerDraft: string, blocks: ClipboardTextBlock[]) {
  try {
    if (!composerDraft && blocks.length === 0) {
      sessionStorage.removeItem(clipboardDraftStorageKey(syncKey));
      return;
    }
    sessionStorage.setItem(clipboardDraftStorageKey(syncKey), JSON.stringify({
      composerDraft,
      blocks: blocks.slice(0, 80),
    }));
  } catch {
    // Session storage can be unavailable or full; the in-memory draft remains usable.
  }
}

function isPersistedClipboardBlock(value: unknown): value is ClipboardTextBlock {
  if (!value || typeof value !== "object") return false;
  const block = value as Partial<ClipboardTextBlock>;
  return typeof block.id === "string"
    && typeof block.text === "string"
    && (block.kind === "text" || block.kind === "html" || block.kind === "link")
    && (block.origin === "local" || block.origin === "remote")
    && typeof block.createdAt === "number";
}
