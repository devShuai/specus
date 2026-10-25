import { useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import type { ClipboardEvent as ReactClipboardEvent, Ref } from "react";
import { Switch } from "@heroui/react";
import { Icon, RelativeTime, Tag } from "./ui";
import { clipboardQuickSendAllowed } from "../lib/transferExperience";
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

/** What the page's send bar can do with the composer, which lives in this component. */
export interface SyncedClipboardHandle {
  /** Sends the composer's text to the selected device: the same as Ctrl/⌘ Enter in the text box. */
  submitComposer: () => void;
  /** Puts text pasted elsewhere on the page into the composer as a draft; never sends. */
  insertDraft: (text: string, html?: string) => void;
}

export interface ClipboardComposerState {
  hasDraft: boolean;
  withinLimits: boolean;
  sending: boolean;
}

interface SyncedClipboardProps {
  ref?: Ref<SyncedClipboardHandle>;
  /** Reports whether the composer can be sent, so the page's send bar can say why not. */
  onComposerStateChange?: (state: ClipboardComposerState) => void;
  syncKey: string;
  isActive: boolean;
  focusRequest: number;
  canSend: boolean;
  fileTargetRequired: boolean;
  targetPeerId: string;
  targetPeerLabel: string;
  events: ClipboardInboundEvent[];
  onSend: (payload: ClipboardSyncPayload) => Promise<void>;
  onFiles: (files: File[]) => boolean;
  onDraftStateChange?: (hasDraft: boolean) => void;
}

interface SuccessfulClipboardWrite {
  intent: number;
  text: string;
  html?: string;
  generation: number;
}

export function SyncedClipboard({
  ref,
  onComposerStateChange,
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
  const [composerHtml, setComposerHtml] = useState("");
  const [quickSend, setQuickSend] = useState(false);
  const [draftFiles, setDraftFiles] = useState<File[]>([]);
  const [blocks, setBlocks] = useState<ClipboardTextBlock[]>([]);
  const [latestInbound, setLatestInbound] = useState<ClipboardInboundEvent | null>(null);
  const [viewState, setViewState] = useState<ClipboardViewState>("idle");
  const [statusMessage, setStatusMessage] = useState("先粘贴或读取内容，检查接收方后再发送。");
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
      setStatusMessage("剪贴板中包含文件：先在“选择接收方”里选一台设备。");
      return false;
    }
    return onFiles(files);
  };

  const stageClipboardFiles = (files: File[]) => {
    if (clipboardQuickSendAllowed(quickSend, canSend, targetPeerId) && sendClipboardFiles(files)) return true;
    setDraftFiles((current) => [...current, ...files]);
    setStatusMessage(`已添加 ${files.length} 个文件到草稿，尚未发送。`);
    return false;
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
          setStatusMessage("上一会话的迟到剪贴板写入未能自动纠正：检查本机剪贴板里的内容。");
          return;
        }
        setViewState("needs-copy");
        setStatusMessage("浏览器未能自动恢复剪贴板：用“复制到剪贴板”重试。");
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
    setComposerHtml("");
    setDraftFiles([]);
    setQuickSend(false);
    setBlocks(persisted.blocks);
    onDraftStateChange?.(Boolean(persisted.composerDraft || persisted.blocks.length > 0));
    setLatestInbound(null);
    setSending(false);
    setSendingBlockId("");
    setClipboardWriteBlockId("");
    setViewState(clipboardWritePendingRef.current ? "writing" : "idle");
    setStatusMessage(clipboardWritePendingRef.current
      ? "正在等待浏览器完成上一条剪贴板写入；完成前不会发起新的本机写入。"
      : "先粘贴或读取内容，检查接收方后再发送。");
  }, [onDraftStateChange, syncKey]);

  useEffect(() => {
    if (draftStorageKeyRef.current !== syncKey) return;
    if (skipDraftPersistRef.current) {
      skipDraftPersistRef.current = false;
      return;
    }
    writeClipboardDraft(syncKey, composerDraft, blocks);
    onDraftStateChange?.(Boolean(composerDraft || blocks.length > 0 || draftFiles.length > 0));
  }, [blocks, composerDraft, draftFiles.length, onDraftStateChange, syncKey]);

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
              ? "自动写入等待超时：用“复制到剪贴板”重试。"
              : "浏览器阻止了自动写入：用“复制到剪贴板”手动写入。");
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
      setStatusMessage("还没有可发送的目标：先邀请并选择一台设备。");
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
      setStatusMessage("先输入或粘贴内容，再发送。");
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
    setComposerHtml("");
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
        // Reading is always a draft operation, even when paste quick-send is enabled.
        if (files.length > 0) setDraftFiles((current) => [...current, ...files]);
        if (!text && files.length === 0) {
          setViewState("idle");
          setStatusMessage("系统剪贴板中没有浏览器可读取的内容。");
          return;
        }
        if (text) {
          setComposerDraft(text);
          setComposerHtml(html);
        }
        setViewState("ready");
        setStatusMessage("已读取到草稿，尚未发送。检查内容后再发送。");
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
    let filesStaged = false;
    if (files.length > 0) {
      if (stageClipboardFiles(files)) {
        if (!text) {
          setViewState("ready");
          setStatusMessage(`已粘贴 ${files.length} 个文件，正在通过文件通道发送。`);
          return;
        }
      } else if (!text) {
        return;
      } else {
        filesStaged = true;
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
    if (clipboardQuickSendAllowed(quickSend, canSend, targetPeerId)) {
      addLocalBlock(text, content);
    } else {
      setComposerDraft(text);
      setComposerHtml(content.html ?? "");
      setViewState("ready");
      setStatusMessage("内容已放入草稿，尚未发送。");
    }
    if (filesStaged) {
      setViewState("ready");
      setStatusMessage(clipboardQuickSendAllowed(quickSend, canSend, targetPeerId)
        ? "文件尚未发送，已保留为草稿；检查连接后用“发送这些文件”发送。"
        : "文字和文件已保留为草稿，检查接收方后分别发送。");
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
      setStatusMessage("浏览器仍在完成上一条剪贴板写入，稍候再复制。");
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
          ? "写入等待超时，已解除占用；可以再用“复制到剪贴板”重试。"
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

  const canSubmitComposer = Boolean(composerDraft) && composerWithinLimits && canSend && Boolean(targetPeerId) && !isSending;
  const submitComposer = () => {
    if (canSubmitComposer) addLocalBlock(composerDraft, classifyClipboardContent(composerDraft, composerHtml));
  };
  const insertDraft = (text: string, html = "") => {
    if (!text) return;
    const content = classifyClipboardContent(text, html);
    if (!isClipboardContentWithinLimits(text, content.html ?? "")) {
      setViewState("failed");
      setStatusMessage(`剪贴板内容超过 ${CLIPBOARD_TEXT_MAX_CHARS.toLocaleString()} 个字符或 ${formatByteCount(CLIPBOARD_TEXT_MAX_UTF8_BYTES)}，未放入草稿。`);
      return;
    }
    setComposerDraft(text);
    setComposerHtml(content.html ?? "");
    setViewState("ready");
    setStatusMessage("内容已放入草稿，尚未发送。");
    window.requestAnimationFrame(() => textareaRef.current?.focus());
  };
  const submitComposerRef = useRef(submitComposer);
  const insertDraftRef = useRef(insertDraft);
  submitComposerRef.current = submitComposer;
  insertDraftRef.current = insertDraft;
  useImperativeHandle(ref, () => ({
    submitComposer: () => submitComposerRef.current(),
    insertDraft: (text, html) => insertDraftRef.current(text, html),
  }), []);

  const composerHasDraft = Boolean(composerDraft);
  useEffect(() => {
    onComposerStateChange?.({ hasDraft: composerHasDraft, withinLimits: composerWithinLimits, sending: isSending });
  }, [composerHasDraft, composerWithinLimits, isSending, onComposerStateChange]);

  const statusTone = clipboardStatusTone(viewState);

  return (
    <section
      id="transfer-panel-clipboard"
      role="tabpanel"
      aria-labelledby="transfer-tab-clipboard"
      hidden={!isActive}
      onPaste={handlePaste}
      className="tr-panel tr-clipboard"
    >
      <div className="tr-panel-toolbar">
        <Switch
          size="sm"
          classNames={{ base: "tr-switch", label: "tr-switch-label" }}
          isSelected={quickSend}
          onValueChange={setQuickSend}
          isDisabled={!canSend || !targetPeerId}
        >
          粘贴即发送（仅本次页面，读取剪贴板仍需确认）
        </Switch>
        <button
          type="button"
          className={`bd-btn bd-btn--secondary bd-btn--sm${isSystemClipboardReading ? " is-busy" : ""}`}
          aria-busy={isSystemClipboardReading}
          onClick={readSystemClipboard}
        >
          <Icon name="clipboard" />
          <span>读取剪贴板</span>
        </button>
      </div>

      <div className={`tr-composer-box${composerDraft && !composerWithinLimits ? " is-invalid" : ""}`}>
        <textarea
          ref={textareaRef}
          id="public-transfer-clipboard-text"
          data-testid="public-transfer-clipboard-text"
          aria-label="要发送的文字与链接"
          aria-describedby="public-transfer-clipboard-hint"
          value={composerDraft}
          maxLength={CLIPBOARD_TEXT_MAX_CHARS}
          spellCheck={false}
          onChange={(event) => {
            const value = event.currentTarget.value;
            setComposerDraft(value);
            setComposerHtml("");
            if (!isClipboardContentWithinLimits(value, "")) {
              setViewState("failed");
              setStatusMessage(`文本的 UTF-8 大小超过 ${formatByteCount(CLIPBOARD_TEXT_MAX_UTF8_BYTES)}，删减后再发送。`);
            }
          }}
          onKeyDown={(event) => {
            if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
              event.preventDefault();
              if (canSend && targetPeerId && !isSending) addLocalBlock(composerDraft, classifyClipboardContent(composerDraft, composerHtml));
            }
          }}
          placeholder="输入或粘贴文字、链接。粘贴只放进草稿，按发送才会发出。"
          className="tr-textarea"
        />
        <div className="tr-composer-foot" id="public-transfer-clipboard-hint">
          <span className={`bd-num ${composerDraft && !composerWithinLimits ? "tr-text-danger" : ""}`}>
            {composerDraft
              ? `${composerDraft.length.toLocaleString()} / ${CLIPBOARD_TEXT_MAX_CHARS.toLocaleString()} 字符 · ${formatByteCount(composerByteLength)}`
              : "文本、富文本、链接；文件放到“文件”里发送"}
          </span>
        </div>
      </div>

      {draftFiles.length > 0 ? (
        <div className="tr-inline-draft">
          <Icon name="file" />
          <p className="min-w-0 flex-1 [overflow-wrap:anywhere]">待发送文件：{draftFiles.map((file) => file.name).join("、")}</p>
          <div className="bd-row">
            <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={() => setDraftFiles([])}>移除文件</button>
            <button
              type="button"
              className="bd-btn bd-btn--secondary bd-btn--sm"
              disabled={!canSend || (fileTargetRequired && !targetPeerId)}
              onClick={() => {
                if (sendClipboardFiles(draftFiles)) setDraftFiles([]);
              }}
            >
              <Icon name="send" />
              <span>发送这些文件</span>
            </button>
          </div>
        </div>
      ) : null}

      <div aria-live="polite" className={`tr-clip-status is-${statusTone}`}>
        <Icon name={statusTone === "success" ? "circle-check" : statusTone === "danger" ? "circle-alert" : statusTone === "warning" ? "alert" : "info-circle"} />
        <span className="min-w-0">
          {statusMessage}
          {latestInbound && <span className="tr-clip-status-source">来源：{sourceLabel}</span>}
        </span>
      </div>

      {blocks.length > 0 ? (
        <div className="tr-clip-history">
          <div className="tr-subsection-head">
            <div className="min-w-0">
              <h3>记录 <span className="tr-count bd-num">{blocks.length}</span></h3>
              <p>最新在前 · 最多保留 80 条</p>
            </div>
            <button
              type="button"
              className="bd-btn bd-btn--ghost bd-btn--sm"
              disabled={isSending || isClipboardWritePending}
              onClick={clearAllBlocks}
            >
              清空记录
            </button>
          </div>
          {blocks.map((block) => {
            const withinLimits = isClipboardContentWithinLimits(block.text, block.html ?? "");
            const isLatestInbound = Boolean(block.sourceEventId && latestInbound?.eventId === block.sourceEventId);
            const needsCopy = viewState === "needs-copy" && isLatestInbound;
            const isEditing = editingBlockId === block.id;
            const busyHere = sendingBlockId === block.id || clipboardWriteBlockId === block.id;
            return (
              <article key={block.id} className="tr-clip-block">
                <div className="tr-clip-block-head">
                  <Tag tone={block.origin === "remote" ? "success" : "info"}>{block.origin === "remote" ? "收到" : "本机"}</Tag>
                  <Tag plain>{clipboardKindLabel(block.kind)}</Tag>
                  <span className="tr-clip-block-source">
                    {block.origin === "remote" ? `来自 ${block.sourceDisplayName || "未命名设备"}` : "本机剪贴板"}
                  </span>
                  <RelativeTime className="tr-clip-block-time" value={block.createdAt} />
                </div>
                {block.kind === "html" && block.html ? (
                  <div
                    className="clipboard-rich-preview"
                    dangerouslySetInnerHTML={{ __html: sanitizeClipboardHtml(block.html) }}
                  />
                ) : null}
                {block.kind === "link" ? (
                  <a href={block.text} target="_blank" rel="noreferrer" className="jd-link tr-clip-link">
                    {block.text}
                  </a>
                ) : null}
                <div className="tr-clip-body">
                  {isEditing ? (
                    <textarea
                      data-clipboard-block-editor="true"
                      aria-label={block.origin === "remote" ? `编辑来自 ${block.sourceDisplayName || "未命名设备"} 的剪贴板内容` : "编辑本机剪贴板内容"}
                      value={block.text}
                      maxLength={CLIPBOARD_TEXT_MAX_CHARS}
                      spellCheck={false}
                      autoFocus
                      onChange={(event) => updateBlockText(block.id, event.currentTarget.value)}
                      className="tr-textarea tr-textarea--edit"
                    />
                  ) : (
                    <div className="tr-clip-text">{block.text}</div>
                  )}
                  <button
                    type="button"
                    aria-label={isEditing ? "完成编辑" : "编辑内容"}
                    title={isEditing ? "完成编辑" : "编辑内容"}
                    aria-pressed={isEditing}
                    onClick={() => setEditingBlockId(isEditing ? "" : block.id)}
                    className="bd-icon-btn tr-clip-edit"
                  >
                    <Icon name={isEditing ? "check" : "edit"} />
                  </button>
                </div>
                {!withinLimits && (
                  <p className="tr-text-danger tr-clip-limit">内容超过上限：删减后再发送。</p>
                )}
                <div className="tr-clip-actions">
                  <button
                    type="button"
                    className="bd-btn bd-btn--ghost bd-btn--sm"
                    disabled={busyHere}
                    onClick={() => removeBlock(block)}
                  >
                    删除
                  </button>
                  <button
                    type="button"
                    className={`bd-btn bd-btn--sm ${needsCopy ? "bd-btn--primary" : "bd-btn--ghost"}${clipboardWriteBlockId === block.id ? " is-busy" : ""}`}
                    disabled={isClipboardWritePending && clipboardWriteBlockId !== block.id}
                    onClick={() => handleManualCopy(block)}
                  >
                    <Icon name="copy" />
                    <span>复制到剪贴板</span>
                  </button>
                  <button
                    type="button"
                    className={`bd-btn bd-btn--secondary bd-btn--sm${sendingBlockId === block.id ? " is-busy" : ""}`}
                    disabled={!block.text || !withinLimits || !canSend || !targetPeerId || isSending}
                    onClick={() => void submitText(block.text, block.id, block.kind, block.html)}
                  >
                    <Icon name="send" />
                    <span>发送到设备</span>
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      ) : null}

      <p className="tr-note">
        文字草稿临时保存在当前浏览器标签页，刷新后可恢复；未发送文件刷新后需重新选择。不会持续读取系统剪贴板，不要发送密码或令牌。
      </p>
    </section>
  );
}

function clipboardContentByteLength(text: string, html = "") {
  return new TextEncoder().encode(text).byteLength + new TextEncoder().encode(html).byteLength;
}

async function writeClipboardContent(text: string, html = "") {
  if (!window.isSecureContext || !navigator.clipboard?.writeText) {
    throw new Error("当前浏览器不允许写入系统剪贴板：改用 HTTPS 或 localhost 打开本页");
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
    throw new Error("当前浏览器不允许读取系统剪贴板：改用 HTTPS 或 localhost 打开本页");
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
    return `浏览器未授权${action}系统剪贴板：在浏览器里允许剪贴板权限后重试。`;
  }
  return error instanceof Error ? error.message : `${action}系统剪贴板失败`;
}

function clipboardStatusTone(state: ClipboardViewState): "success" | "warning" | "danger" | "info" {
  if (state === "written" || state === "sent") return "success";
  if (state === "needs-copy") return "warning";
  if (state === "failed") return "danger";
  return "info";
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
