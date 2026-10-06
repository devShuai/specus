import { MIB, RESUME_OFFER_TIMEOUT_MS, UNACKED_WINDOW_CHUNKS } from "./constants";
import { ChunkBitmap } from "./bitmap";
import { isHex32, randomHex128, toHex, type Digest } from "./bytes";
import {
  BUFFER_HIGH_WATER_BYTES,
  BUFFER_LOW_THRESHOLD_BYTES,
  sendJson,
  waitForBufferLow,
  type BulkChannel,
} from "./channel";
import { encodeChunkFrames, encodeHashFrames } from "./frames";
import { fileMetaMessage, type Manifest } from "./manifest";
import { receiveRejectText } from "./receiverController";
import { blobChunkReader, readVerifiedChunk, SourceChangedError } from "./senderPlan";
import type { StorageMode } from "./store";

// Sender side of one session (§7, §8): offer or resume handshake, the hash list, then the chunks
// the receiver lacks with at most UNACKED_WINDOW_CHUNKS unacknowledged plus bufferedAmount
// backpressure. Reconnect policy lives with the caller; this module reports what kind of
// failure ended the session.

export interface OutgoingTransfer {
  transferId: string;
  manifest: Manifest;
  /** The File; null after a reload until the user selects it again. */
  source: Blob | null;
  lastModified: number;
  targetPeerId: string;
  targetName: string;
  resumeToken: string | null;
  storage: StorageMode | null;
  /** Local-clock instant (ms) computed from the receiver's ttlSeconds. */
  expiresAt: number | null;
  /** The receiver's bitmap as last acknowledged. */
  acked: ChunkBitmap;
  /** Peers that answered this transfer in this page: their silence is a network problem. */
  confirmedPeers: Set<string>;
  /** A file-meta went out under this transferId. */
  offered: boolean;
}

export function createOutgoing(manifest: Manifest, source: Blob | null, target: {
  peerId: string;
  name: string;
  lastModified: number;
}): OutgoingTransfer {
  return {
    transferId: randomHex128(),
    manifest,
    source,
    lastModified: target.lastModified,
    targetPeerId: target.peerId,
    targetName: target.name,
    resumeToken: null,
    storage: null,
    expiresAt: null,
    acked: new ChunkBitmap(manifest.chunkCount),
    confirmedPeers: new Set(),
    offered: false,
  };
}

/**
 * retry: the session broke but the receiver keeps its state; reconnect and resume.
 * restart: the receiver does not know the transfer (any more); offer it again as a new transfer.
 * stop: give up now but keep the state, the user can resume later (e.g. receiver storage full).
 * drop: the transfer is over for good (rejected, cancelled, integrity failure, source changed).
 */
export type SenderFailure = "retry" | "restart" | "stop" | "drop";

export class SenderError extends Error {
  readonly failure: SenderFailure;
  readonly code?: string;

  constructor(message: string, failure: SenderFailure, code?: string) {
    super(message);
    this.name = "SenderError";
    this.failure = failure;
    this.code = code;
  }
}

type Message = Record<string, unknown>;

/** Collects sender-bound control messages for the one session a channel carries at a time. */
export class SenderInbox {
  readonly channel: BulkChannel;
  readonly transferId: string;
  private messages: Message[] = [];
  private waiter: (() => void) | null = null;
  private closedReason: string | null = null;

  constructor(channel: BulkChannel, transferId: string) {
    this.channel = channel;
    this.transferId = transferId;
  }

  deliver(message: Message) {
    this.messages.push(message);
    this.wake();
  }

  close(reason: string) {
    this.closedReason ??= reason;
    this.wake();
  }

  get closed() {
    return this.closedReason !== null;
  }

  takeAll(): Message[] {
    const out = this.messages;
    this.messages = [];
    return out;
  }

  /** Waits until a message arrives; rejects on close, abort or timeout (with `onTimeout`). */
  async wait(timeoutMs: number, onTimeout: () => SenderError, signal?: AbortSignal): Promise<void> {
    if (this.messages.length > 0) return;
    if (this.closedReason !== null) throw new SenderError(this.closedReason, "retry");
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(onTimeout());
      }, timeoutMs);
      const onAbort = () => {
        cleanup();
        reject(abortError(signal));
      };
      const cleanup = () => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        if (this.waiter === done) this.waiter = null;
      };
      const done = () => {
        cleanup();
        resolve();
      };
      this.waiter = done;
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) onAbort();
    });
    if (this.messages.length === 0 && this.closedReason !== null) {
      throw new SenderError(this.closedReason, "retry");
    }
  }

  private wake() {
    const waiter = this.waiter;
    this.waiter = null;
    waiter?.();
  }
}

/** Routes sender-bound messages to the active session of each channel. */
export class SenderRouter {
  private readonly inboxes = new Map<BulkChannel, SenderInbox>();

  open(channel: BulkChannel, transferId: string): SenderInbox {
    this.inboxes.get(channel)?.close("发送会话被取代");
    const inbox = new SenderInbox(channel, transferId);
    this.inboxes.set(channel, inbox);
    return inbox;
  }

  release(inbox: SenderInbox) {
    if (this.inboxes.get(inbox.channel) === inbox) {
      this.inboxes.delete(inbox.channel);
    }
    inbox.close("发送会话已结束");
  }

  /** True when a session on this channel took the message. */
  dispatch(channel: BulkChannel, message: Message): boolean {
    const inbox = this.inboxes.get(channel);
    if (!inbox || message.transferId !== inbox.transferId) return false;
    inbox.deliver(message);
    return true;
  }

  channelClosed(channel: BulkChannel) {
    const inbox = this.inboxes.get(channel);
    if (inbox) {
      this.inboxes.delete(channel);
      inbox.close("DataChannel 已关闭");
    }
  }

  hasSession(channel: BulkChannel): boolean {
    return this.inboxes.has(channel);
  }
}

export interface SenderSessionContext {
  router: SenderRouter;
  channel: BulkChannel;
  peerId: string;
  frameBytes: number;
  digest: Digest;
  now(): number;
  signal?: AbortSignal;
  /** Throws when the channel or the room changed under the session. */
  ensureCurrent(): void;
  onPhase(phase: "waiting" | "sending"): void;
  onProgress(transfer: OutgoingTransfer): void;
  /** Consent obtained: persist the sender record when the receiver stores persistently. */
  onAccepted(transfer: OutgoingTransfer): Promise<void>;
  /** Waiting time for the receiver's click on a new offer. */
  consentTimeoutMs?: number;
}

export type SessionOutcome = { kind: "complete" } | { kind: "legacy" };

const STALL_TIMEOUT_MS = 60_000;

function abortError(signal?: AbortSignal) {
  return signal?.reason instanceof Error ? signal.reason : new Error("文件发送已取消");
}

function failureFromTransferError(code: unknown): SenderError {
  switch (code) {
    case "STORAGE_FULL":
      return new SenderError("对方浏览器存储空间不足，释放空间后可以继续发送", "stop", code);
    case "INTEGRITY_FAILED":
      return new SenderError("文件多次校验失败，对方已删除已收数据，请重新发送", "drop", code);
    case "SOURCE_CHANGED":
      return new SenderError("源文件已变化，请作为新传输重新发送", "drop", code);
    case "RETRY_EXHAUSTED":
      return new SenderError("同一块多次校验失败，正在重新连接", "retry", code);
    default:
      return new SenderError("直连传输协议错误，正在重新连接", "retry", typeof code === "string" ? code : "PROTOCOL_ERROR");
  }
}

function validIndex(transfer: OutgoingTransfer, value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value < transfer.manifest.chunkCount;
}

/** Runs one session on an open channel: handshake, hash list, missing chunks, completion. */
export async function runSenderSession(transfer: OutgoingTransfer, ctx: SenderSessionContext): Promise<SessionOutcome> {
  const { channel, signal } = ctx;
  const manifestDigest = toHex(transfer.manifest.manifestDigest);
  const inbox = ctx.router.open(channel, transfer.transferId);
  try {
    ctx.ensureCurrent();
    let needHashes: boolean;
    if (transfer.resumeToken === null) {
      transfer.offered = true;
      sendJson(channel, fileMetaMessage(transfer.transferId, transfer.manifest));
      ctx.onPhase("waiting");
      const accepted = await awaitAcceptance(transfer, ctx, inbox, manifestDigest);
      if (accepted === "legacy") return { kind: "legacy" };
      needHashes = accepted.needHashes;
    } else {
      sendJson(channel, {
        kind: "resume-offer",
        transferId: transfer.transferId,
        manifestDigest,
        resumeToken: transfer.resumeToken,
      });
      const state = await awaitResumeState(transfer, ctx, inbox, manifestDigest);
      if (state === "complete") return { kind: "complete" };
      needHashes = state.needHashes;
    }
    ctx.onPhase("sending");
    ctx.onProgress(transfer);
    return await pump(transfer, ctx, inbox, manifestDigest, needHashes);
  } catch (error) {
    if (signal?.aborted) throw abortError(signal);
    throw error;
  } finally {
    ctx.router.release(inbox);
  }
}

async function awaitAcceptance(
  transfer: OutgoingTransfer,
  ctx: SenderSessionContext,
  inbox: SenderInbox,
  manifestDigest: string,
): Promise<"legacy" | { needHashes: boolean }> {
  const timeout = () => new SenderError("对方未确认接收", "drop", "CONSENT_TIMEOUT");
  for (;;) {
    await inbox.wait(ctx.consentTimeoutMs ?? 120_000, timeout, ctx.signal);
    for (const message of inbox.takeAll()) {
      if (message.kind === "file-ready") {
        return "legacy"; // an old page ignored `resume` and answered the legacy way
      }
      if (message.kind === "file-reject") {
        const code = typeof message.code === "string" ? message.code : undefined;
        const reason = typeof message.reason === "string" ? message.reason : undefined;
        throw new SenderError(receiveRejectText(code, reason), "drop", code ?? "LEGACY_REJECT");
      }
      if (message.kind === "file-cancel") {
        throw new SenderError("对方取消了接收", "drop", "CANCELLED");
      }
      if (message.kind !== "file-accept") continue;
      const storage = message.storage;
      const ttlSeconds = message.ttlSeconds;
      const have = typeof message.have === "string" ? ChunkBitmap.decode(transfer.manifest.chunkCount, message.have) : null;
      if (message.manifestDigest !== manifestDigest || !isHex32(message.resumeToken)
        || (storage !== "persistent" && storage !== "memory")
        || typeof ttlSeconds !== "number" || !Number.isFinite(ttlSeconds) || ttlSeconds <= 0
        || !(have instanceof ChunkBitmap) || typeof message.needHashes !== "boolean") {
        throw new SenderError("对方的接收确认无效", "drop", "PROTOCOL_ERROR");
      }
      transfer.resumeToken = message.resumeToken;
      transfer.storage = storage;
      transfer.expiresAt = ctx.now() + ttlSeconds * 1000;
      transfer.acked = have;
      transfer.targetPeerId = ctx.peerId;
      transfer.confirmedPeers.add(ctx.peerId);
      await ctx.onAccepted(transfer);
      return { needHashes: message.needHashes };
    }
  }
}

async function awaitResumeState(
  transfer: OutgoingTransfer,
  ctx: SenderSessionContext,
  inbox: SenderInbox,
  manifestDigest: string,
): Promise<"complete" | { needHashes: boolean }> {
  // No answer in 10 s means an old page or the wrong device, unless this peer already
  // answered for this transfer in this page: then it is the network and worth a retry.
  const timeout = () => transfer.confirmedPeers.has(ctx.peerId)
    ? new SenderError("对方未响应续传请求", "retry", "TIMEOUT")
    : new SenderError("对方无法续传此文件", "restart", "UNKNOWN_TRANSFER");
  for (;;) {
    await inbox.wait(RESUME_OFFER_TIMEOUT_MS, timeout, ctx.signal);
    for (const message of inbox.takeAll()) {
      if (message.kind === "resume-reject") {
        const code = message.code;
        if (code === "BUSY") throw new SenderError("对方正在接收其他文件，稍后自动重试", "retry", code);
        if (code === "NOT_ALLOWED") throw new SenderError("对方在当前房间没有接收你的文件的权限", "drop", code);
        throw new SenderError("对方已无法续传此文件，将作为新传输重新发送", "restart", typeof code === "string" ? code : "UNKNOWN_TRANSFER");
      }
      if (message.kind === "file-cancel") {
        throw new SenderError("对方取消了接收", "drop", "CANCELLED");
      }
      if (message.kind !== "resume-state") continue;
      const have = typeof message.have === "string" ? ChunkBitmap.decode(transfer.manifest.chunkCount, message.have) : null;
      const ttlSeconds = message.ttlSeconds;
      if (message.manifestDigest !== manifestDigest || !(have instanceof ChunkBitmap)
        || typeof message.needHashes !== "boolean" || typeof message.complete !== "boolean"
        || typeof ttlSeconds !== "number" || !Number.isFinite(ttlSeconds) || ttlSeconds < 0) {
        throw new SenderError("对方的续传应答无效", "retry", "PROTOCOL_ERROR");
      }
      transfer.acked = have;
      transfer.targetPeerId = ctx.peerId;
      transfer.confirmedPeers.add(ctx.peerId);
      // The receiver's clock decides; never extend the local expiry.
      const expiresAt = ctx.now() + ttlSeconds * 1000;
      transfer.expiresAt = transfer.expiresAt === null ? expiresAt : Math.min(transfer.expiresAt, expiresAt);
      if (message.complete) return "complete";
      return { needHashes: message.needHashes };
    }
  }
}

async function sendWithBackpressure(ctx: SenderSessionContext, frame: ArrayBuffer) {
  const { channel, signal } = ctx;
  while (channel.bufferedAmount > BUFFER_HIGH_WATER_BYTES) {
    await waitForBufferLow(channel, STALL_TIMEOUT_MS, signal).catch((error: unknown) => {
      if (signal?.aborted) throw abortError(signal);
      throw new SenderError(error instanceof Error ? error.message : "DataChannel 已关闭", "retry");
    });
  }
  ctx.ensureCurrent();
  if (channel.readyState !== "open") {
    throw new SenderError("DataChannel 已关闭", "retry");
  }
  channel.send(frame);
}

async function pump(
  transfer: OutgoingTransfer,
  ctx: SenderSessionContext,
  inbox: SenderInbox,
  manifestDigest: string,
  needHashes: boolean,
): Promise<SessionOutcome> {
  const { channel, signal } = ctx;
  const { manifest } = transfer;
  if (!transfer.source) {
    throw new SenderError("请重新选择原文件后继续发送", "stop", "SOURCE_MISSING");
  }
  const read = blobChunkReader(transfer.source);
  channel.bufferedAmountLowThreshold = BUFFER_LOW_THRESHOLD_BYTES;
  if (needHashes) {
    for (const frame of encodeHashFrames(transfer.transferId, manifest.hashes, ctx.frameBytes)) {
      await sendWithBackpressure(ctx, frame);
    }
  }
  const queue = transfer.acked.missing();
  const inFlight = new Set<number>();
  // Final verification re-reads every stored chunk; allow for roughly 20 MiB/s.
  const finalTimeoutMs = 60_000 + Math.ceil(manifest.sizeBytes / (20 * MIB)) * 1000;
  let complete = false;
  const handle = (message: Message) => {
    switch (message.kind) {
      case "chunk-ack":
        if (validIndex(transfer, message.index)) {
          inFlight.delete(message.index);
          if (!transfer.acked.has(message.index)) {
            transfer.acked.set(message.index);
            ctx.onProgress(transfer);
          }
        }
        return;
      case "chunk-nack":
        if (validIndex(transfer, message.index)) {
          inFlight.delete(message.index);
          transfer.acked.clear(message.index);
          if (!queue.includes(message.index)) {
            queue.push(message.index);
            queue.sort((left, right) => left - right);
          }
        }
        return;
      case "transfer-complete":
        if (message.manifestDigest === manifestDigest) complete = true;
        return;
      case "transfer-error":
        throw failureFromTransferError(message.code);
      case "file-cancel":
        throw new SenderError("对方取消了接收", "drop", "CANCELLED");
      default:
    }
  };
  while (!complete) {
    for (const message of inbox.takeAll()) handle(message);
    if (complete) break;
    if (signal?.aborted) throw abortError(signal);
    if (inbox.closed) throw new SenderError("DataChannel 已关闭", "retry");
    ctx.ensureCurrent();
    if (queue.length > 0 && inFlight.size < UNACKED_WINDOW_CHUNKS) {
      const index = queue.shift()!;
      let bytes;
      try {
        bytes = await readVerifiedChunk(manifest, index, read, ctx.digest);
      } catch (error) {
        if (error instanceof SourceChangedError) {
          sendJson(channel, { kind: "transfer-error", transferId: transfer.transferId, code: "SOURCE_CHANGED" });
          throw new SenderError(error.message, "drop", "SOURCE_CHANGED");
        }
        throw new SenderError("无法读取源文件，请重新选择文件", "stop", "SOURCE_UNREADABLE");
      }
      for (const frame of encodeChunkFrames(transfer.transferId, index, bytes, ctx.frameBytes)) {
        await sendWithBackpressure(ctx, frame);
      }
      inFlight.add(index);
      continue;
    }
    const idle = queue.length === 0 && inFlight.size === 0;
    await inbox.wait(idle ? finalTimeoutMs : STALL_TIMEOUT_MS,
      () => new SenderError("直连传输停滞，正在重新连接", "retry", "STALLED"), signal);
  }
  return { kind: "complete" };
}
