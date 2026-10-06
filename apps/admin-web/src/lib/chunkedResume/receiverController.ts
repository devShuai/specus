import { MAX_ACTIVE_RECEIVES, RESUME_TTL_SECONDS } from "./constants";
import { ChunkBitmap } from "./bitmap";
import { fromHex, isHex32, type Bytes, type Digest } from "./bytes";
import { sendJson, isRecord, type BulkChannel } from "./channel";
import { planCleanup } from "./cleanup";
import { decideConsent, type MemoryReason } from "./consent";
import { decodeFrame } from "./frames";
import { decideResume } from "./handshake";
import { validateOffer, type OfferErrorCode, type ValidOffer } from "./manifest";
import { ChunkReceiver, type ReceiverStep, type ReceiverStorage } from "./receiver";
import { copyBuffer, type ReceiveRecord, type ResumeStore, type StorageMode } from "./store";

// Receiver side of the resumable direct transfer: offer validation and consent (§3, §6),
// sessions over bulk channels (§7), the resume handshake (§8) and cleanup (§10). It knows
// nothing about React or RTCPeerConnection; the hook feeds it channel messages.

export interface ReceivedFile {
  transferId: string;
  sourcePeerId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  blob: Blob;
  storage: StorageMode;
  /** Restored from IndexedDB after a reload, not received in this page. */
  restored: boolean;
}

export interface ReceiverPendingView {
  transferId: string;
  sourcePeerId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  storage: StorageMode;
  memoryReason?: MemoryReason;
}

export interface ReceiverEntryView {
  transferId: string;
  sourcePeerId: string;
  sourceName: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  receivedBytes: number;
  storage: StorageMode;
  state: string;
  active: boolean;
  expiresAt: number;
}

export interface ReceiverSnapshot {
  pending: ReceiverPendingView[];
  entries: ReceiverEntryView[];
}

export interface ReceiverControllerDeps {
  openPersistentStore(): Promise<ResumeStore | null>;
  memoryStore: ResumeStore;
  estimate(): Promise<{ quota: number; usage: number } | null>;
  now(): number;
  digest: Digest;
  randomToken(): string;
  autoAccept(): boolean;
  senderAllowed(peerId: string): boolean;
  peerName(peerId: string): string;
  setTimer(callback: () => void, ms: number): unknown;
  clearTimer(handle: unknown): void;
  onChange(): void;
  onComplete(file: ReceivedFile): void;
  onError(message: string): void;
}

interface Entry {
  record: ReceiveRecord;
  store: ResumeStore;
  engine: ChunkReceiver;
  channel: BulkChannel | null;
  peerId: string | null;
  delivered: boolean;
}

interface Pending {
  offer: ValidOffer;
  peerId: string;
  channel: BulkChannel;
  storage: StorageMode;
  memoryReason?: MemoryReason;
  timer: unknown;
}

const CONSENT_TIMEOUT_MS = 118_000;
const RESUME_REQUEST_INTERVAL_MS = 15_000;

const OFFER_ERROR_TEXT: Record<OfferErrorCode, string> = {
  UNSUPPORTED_VERSION: "续传协议版本不受支持",
  BAD_TRANSFER_ID: "传输编号无效",
  BAD_SIZE: "文件大小无效",
  TOO_LARGE: "文件超过 2 GiB 的设备传输上限",
  BAD_CHUNK_SIZE: "分块大小无效",
  BAD_CHUNK_COUNT: "分块数量与文件大小不一致",
  TOO_MANY_CHUNKS: "分块数量超过上限",
  BAD_FILE_NAME: "文件名无效",
  BAD_MIME_TYPE: "文件类型无效",
  BAD_DIGEST_FORMAT: "文件摘要格式无效",
  MANIFEST_DIGEST_MISMATCH: "文件清单校验失败",
};

const REJECT_TEXT: Record<string, string> = {
  NOT_ALLOWED: "对方在当前房间没有发送权限",
  TRANSFER_ID_IN_USE: "传输编号已被使用",
  PERSISTENCE_UNAVAILABLE: "对方浏览器无法写入本机存储，超过 128 MiB 的文件无法接收",
  TOO_MANY_PARTIALS: "对方未完成的接收过多，请让对方先完成或放弃",
  PARTIAL_BYTES_LIMIT: "对方未完成接收的总大小已达上限",
  INSUFFICIENT_STORAGE: "对方浏览器存储空间不足",
  BUSY: "当前还有文件正在接收",
  DECLINED: "对方已拒绝接收",
  CONSENT_TIMEOUT: "接收确认超时",
};

/** What the receiving user is told when a large offer cannot be stored here. */
const LOCAL_REJECT_TEXT: Record<string, string> = {
  PERSISTENCE_UNAVAILABLE: "本机浏览器无法写入本地存储（如无痕窗口），超过 128 MiB 的文件无法接收",
  TOO_MANY_PARTIALS: "本机未完成的接收已达 4 个，请先完成或放弃",
  PARTIAL_BYTES_LIMIT: "本机未完成接收的总大小已达 4 GiB 上限",
  INSUFFICIENT_STORAGE: "本机浏览器存储空间不足",
};

export function receiveRejectText(code: string | undefined, fallback?: string): string {
  return (code && REJECT_TEXT[code]) || (code && code in OFFER_ERROR_TEXT ? OFFER_ERROR_TEXT[code as OfferErrorCode] : "")
    || fallback || "对方拒绝接收";
}

export class ReceiverController {
  private readonly deps: ReceiverControllerDeps;
  private readonly entries = new Map<string, Entry>();
  private readonly pending = new Map<string, Pending>();
  private readonly channelTransfers = new Map<BulkChannel, string>();
  private readonly resumeRequestedAt = new Map<string, number>();
  private persistentStore: Promise<ResumeStore | null> | null = null;
  private restored: Promise<void> | null = null;

  constructor(deps: ReceiverControllerDeps) {
    this.deps = deps;
  }

  private persistent(): Promise<ResumeStore | null> {
    if (!this.persistentStore) {
      this.persistentStore = this.deps.openPersistentStore().catch(() => null);
    }
    return this.persistentStore;
  }

  snapshot(): ReceiverSnapshot {
    return {
      pending: [...this.pending.values()].map((item) => ({
        transferId: item.offer.transferId,
        sourcePeerId: item.peerId,
        fileName: item.offer.fileName,
        mimeType: item.offer.mimeType,
        sizeBytes: item.offer.sizeBytes,
        storage: item.storage,
        memoryReason: item.memoryReason,
      })),
      entries: [...this.entries.values()]
        .filter((entry) => entry.engine.state !== "FAILED" && entry.engine.state !== "CANCELLED")
        .map((entry) => ({
          transferId: entry.record.transferId,
          sourcePeerId: entry.peerId ?? entry.record.sourcePeerId,
          sourceName: entry.record.sourceName,
          fileName: entry.record.fileName,
          mimeType: entry.record.mimeType,
          sizeBytes: entry.record.sizeBytes,
          receivedBytes: entry.engine.receivedBytes(),
          storage: entry.store.mode,
          state: entry.engine.state,
          active: entry.channel !== null,
          expiresAt: entry.record.expiresAt,
        })),
    };
  }

  /** Channel currently carrying a resumable receive (binary frames go to handleFrame). */
  hasSession(channel: BulkChannel): boolean {
    return this.channelTransfers.has(channel);
  }

  /** Busy with a pending consent or an active session on this channel. */
  isChannelBusy(channel: BulkChannel): boolean {
    return this.channelTransfers.has(channel) || [...this.pending.values()].some((item) => item.channel === channel);
  }

  /** Page load: cleanup, then surface interrupted transfers and completed files not yet saved. */
  restore(): Promise<void> {
    if (!this.restored) {
      this.restored = (async () => {
        await this.cleanup();
        const store = await this.persistent();
        if (!store) return;
        for (const record of await store.listReceives().catch(() => [] as ReceiveRecord[])) {
          if (this.entries.has(record.transferId)) continue;
          const entry = this.entryFromRecord(record, store);
          this.entries.set(record.transferId, entry);
          if (record.state === "COMPLETE" && !record.saved) {
            await this.deliver(entry, true);
          }
        }
        this.deps.onChange();
      })();
    }
    return this.restored;
  }

  /** Deletes expired, failed, cancelled and saved-complete records plus orphan chunks (§10). */
  async cleanup(): Promise<void> {
    const now = this.deps.now();
    for (const [transferId, entry] of [...this.entries]) {
      const dead = now >= entry.record.expiresAt
        || entry.engine.state === "FAILED"
        || entry.engine.state === "CANCELLED"
        || (entry.engine.state === "COMPLETE" && entry.record.saved);
      if (dead && entry.channel === null) {
        this.entries.delete(transferId);
        await entry.store.deleteReceive(transferId).catch(() => undefined);
      }
    }
    for (const store of [await this.persistent(), this.deps.memoryStore]) {
      if (!store) continue;
      try {
        const records = await store.listReceives();
        const plan = planCleanup({
          now,
          records: records.map((record) => ({
            transferId: record.transferId,
            state: this.entries.get(record.transferId)?.engine.state ?? record.state,
            expiresAt: record.expiresAt,
            saved: record.saved,
          })),
          chunkTransferIds: await store.listChunkTransferIds(),
        });
        for (const transferId of plan.deleteRecords) {
          const entry = this.entries.get(transferId);
          if (entry?.channel) continue; // never pull data from under an active session
          this.entries.delete(transferId);
          await store.deleteReceive(transferId);
        }
        for (const transferId of plan.deleteChunksOf) {
          if (!this.entries.get(transferId)?.channel) {
            await store.deleteChunks(transferId);
          }
        }
      } catch {
        // Storage can disappear (cleared by the browser); the next pass retries.
      }
    }
    this.deps.onChange();
  }

  async handleFileMeta(peerId: string, channel: BulkChannel, message: Record<string, unknown>): Promise<void> {
    const transferId = typeof message.transferId === "string" ? message.transferId : "";
    const validation = await validateOffer(message, this.deps.digest);
    if (!validation.ok) {
      this.sendReject(channel, transferId, validation.code);
      return;
    }
    const offer = validation.offer;
    if (this.pending.has(offer.transferId)) {
      return;
    }
    if (this.isChannelBusy(channel)) {
      this.sendReject(channel, offer.transferId, "BUSY");
      return;
    }
    if (this.activeSessions() >= MAX_ACTIVE_RECEIVES) {
      this.sendReject(channel, offer.transferId, "BUSY");
      return;
    }
    await this.cleanup();
    const store = await this.persistent();
    const estimate = store ? await this.deps.estimate() : null;
    const persistentRecords = store ? await store.listReceives().catch(() => [] as ReceiveRecord[]) : [];
    const inUse = this.entries.has(offer.transferId)
      || persistentRecords.some((record) => record.transferId === offer.transferId)
      || (await this.deps.memoryStore.getReceive(offer.transferId)) !== null;
    const decision = decideConsent({
      policy: {
        autoAccept: this.deps.autoAccept(),
        persistentAvailable: Boolean(store && estimate),
        quotaBytes: estimate?.quota ?? 0,
        usageBytes: estimate?.usage ?? 0,
      },
      sizeBytes: offer.sizeBytes,
      livePartials: persistentRecords.map((record) => ({
        sizeBytes: record.sizeBytes,
        receivedBytes: receivedBytesOf(record),
      })),
      senderAllowed: this.deps.senderAllowed(peerId),
      transferIdInUse: inUse,
    });
    if (channel.readyState !== "open" || this.isChannelBusy(channel)) {
      return;
    }
    if (decision.decision === "REJECT") {
      this.sendReject(channel, offer.transferId, decision.code);
      const local = LOCAL_REJECT_TEXT[decision.code];
      if (local) {
        this.deps.onError(`未接收 ${offer.fileName}：${local}`);
      }
      return;
    }
    const pending: Pending = {
      offer,
      peerId,
      channel,
      storage: decision.decision === "PROMPT_PERSISTENT" ? "persistent" : "memory",
      memoryReason: decision.decision === "PROMPT_MEMORY" ? decision.memoryReason : undefined,
      timer: null,
    };
    this.pending.set(offer.transferId, pending);
    if (decision.decision === "AUTO_ACCEPT_MEMORY") {
      await this.accept(offer.transferId);
      return;
    }
    pending.timer = this.deps.setTimer(() => {
      if (this.pending.get(offer.transferId) === pending) {
        this.pending.delete(offer.transferId);
        this.sendReject(channel, offer.transferId, "CONSENT_TIMEOUT");
        this.deps.onChange();
      }
    }, CONSENT_TIMEOUT_MS);
    this.deps.onChange();
  }

  /** The user's click (or auto-accept in memory mode): create the record and answer file-accept. */
  async accept(transferId: string): Promise<void> {
    const pending = this.pending.get(transferId);
    if (!pending) return;
    this.pending.delete(transferId);
    this.deps.clearTimer(pending.timer);
    const { offer, channel, peerId } = pending;
    if (channel.readyState !== "open") {
      this.deps.onError("直连通道已断开，请让对方重新发送");
      this.deps.onChange();
      return;
    }
    let store = pending.storage === "persistent" ? await this.persistent() : this.deps.memoryStore;
    if (!store) store = this.deps.memoryStore;
    if (store.mode === "memory" && offer.sizeBytes > 128 * 1024 * 1024) {
      this.sendReject(channel, transferId, "PERSISTENCE_UNAVAILABLE");
      this.deps.onChange();
      return;
    }
    const now = this.deps.now();
    const have = new ChunkBitmap(offer.chunkCount);
    const record: ReceiveRecord = {
      transferId,
      manifestDigest: offer.manifestDigest,
      resumeToken: this.deps.randomToken(),
      sizeBytes: offer.sizeBytes,
      chunkSize: offer.chunkSize,
      chunkCount: offer.chunkCount,
      fileName: offer.fileName,
      mimeType: offer.mimeType,
      rootSha256: offer.rootSha256,
      hashes: null,
      have: copyBuffer(have.bytes),
      integrityFailures: 0,
      state: "RECEIVING",
      saved: false,
      createdAt: now,
      expiresAt: now + RESUME_TTL_SECONDS * 1000,
      sourcePeerId: peerId,
      sourceName: this.deps.peerName(peerId),
    };
    try {
      await store.putReceive(record);
    } catch {
      this.sendReject(channel, transferId, "INSUFFICIENT_STORAGE");
      this.deps.onError(`未接收 ${offer.fileName}：本机浏览器存储空间不足`);
      this.deps.onChange();
      return;
    }
    const entry = this.entryFromRecord(record, store);
    this.entries.set(transferId, entry);
    await this.bind(entry, channel, peerId);
    sendJson(channel, {
      kind: "file-accept",
      transferId,
      manifestDigest: record.manifestDigest,
      resumeToken: record.resumeToken,
      storage: store.mode,
      ttlSeconds: RESUME_TTL_SECONDS,
      have: have.encode(),
      needHashes: !entry.engine.hashListComplete,
    });
    this.deps.onChange();
    if (entry.engine.bitmap.isComplete()) {
      await this.runFinalVerify(entry); // empty file
    }
  }

  reject(transferId: string): void {
    const pending = this.pending.get(transferId);
    if (!pending) return;
    this.pending.delete(transferId);
    this.deps.clearTimer(pending.timer);
    this.sendReject(pending.channel, transferId, "DECLINED");
    this.deps.onChange();
  }

  async handleResumeOffer(peerId: string, channel: BulkChannel, message: Record<string, unknown>): Promise<void> {
    const transferId = typeof message.transferId === "string" ? message.transferId : "";
    const entry = isHex32(transferId) ? await this.loadEntry(transferId) : null;
    const otherActive = [...this.entries.values()]
      .filter((candidate) => candidate.channel !== null && candidate.record.transferId !== transferId).length;
    const decision = decideResume({
      record: entry ? {
        transferId: entry.record.transferId,
        resumeToken: entry.record.resumeToken,
        manifestDigest: entry.record.manifestDigest,
        expiresAt: entry.record.expiresAt,
        state: entry.engine.state,
        have: entry.engine.bitmap,
        hashesComplete: entry.engine.hashListComplete,
        sizeBytes: entry.record.sizeBytes,
        chunkSize: entry.record.chunkSize,
        chunkCount: entry.record.chunkCount,
      } : null,
      offer: { transferId, resumeToken: message.resumeToken, manifestDigest: message.manifestDigest },
      now: this.deps.now(),
      senderAllowed: this.deps.senderAllowed(peerId),
      otherActiveSessions: otherActive,
    });
    const busyChannel = this.channelTransfers.get(channel);
    if (decision.result === "RESUME" && !decision.complete && busyChannel && busyChannel !== transferId) {
      sendJson(channel, { kind: "resume-reject", transferId, code: "BUSY" });
      return;
    }
    if (decision.result === "REJECT" || !entry) {
      sendJson(channel, { kind: "resume-reject", transferId, code: decision.result === "REJECT" ? decision.code : "UNKNOWN_TRANSFER" });
      return;
    }
    const state = {
      kind: "resume-state",
      transferId,
      manifestDigest: entry.record.manifestDigest,
      have: decision.have,
      needHashes: decision.needHashes,
      complete: decision.complete,
      ttlSeconds: decision.ttlSeconds,
      firstMissing: decision.firstMissing,
      resumeOffset: decision.resumeOffset,
      receivedBytes: decision.receivedBytes,
    };
    if (decision.complete) {
      sendJson(channel, state); // re-sends a lost completion; takes no session slot
      return;
    }
    // A newer session supersedes the old one: the old channel may be half-open.
    await this.bind(entry, channel, peerId);
    entry.record.sourcePeerId = peerId;
    await entry.store.patchReceive(transferId, { sourcePeerId: peerId }).catch(() => undefined);
    sendJson(channel, state);
    this.deps.onChange();
    if (entry.engine.bitmap.isComplete()) {
      await this.runFinalVerify(entry);
    }
  }

  handleFrame(channel: BulkChannel, data: ArrayBuffer): void {
    const transferId = this.channelTransfers.get(channel);
    const entry = transferId ? this.entries.get(transferId) : undefined;
    if (!entry || entry.channel !== channel) {
      return; // NO_SESSION: dropped, state unchanged
    }
    const decoded = decodeFrame(data);
    const step = decoded.ok ? entry.engine.handleFrame(decoded.frame) : entry.engine.protocolError();
    void step.then((result) => this.afterStep(entry, channel, result)).catch(() => undefined);
  }

  /** transfer-error and file-cancel from a sender. */
  async handleSenderMessage(peerId: string, channel: BulkChannel, message: Record<string, unknown>): Promise<void> {
    const transferId = typeof message.transferId === "string" ? message.transferId : "";
    if (message.kind === "file-cancel") {
      const pending = this.pending.get(transferId);
      if (pending && pending.channel === channel) {
        this.pending.delete(transferId);
        this.deps.clearTimer(pending.timer);
        this.deps.onChange();
        return;
      }
      const entry = this.entries.get(transferId) ?? (isHex32(transferId) ? await this.loadEntry(transferId) : null);
      // Over the session's own channel the cancel is trusted; elsewhere it needs the token.
      if (entry && (entry.channel === channel || message.resumeToken === entry.record.resumeToken)) {
        await this.drop(entry, "CANCELLED");
        this.deps.onError(`${peerName(this.deps, peerId)} 已取消发送 ${entry.record.fileName}`);
      }
      return;
    }
    if (message.kind === "transfer-error") {
      const entry = this.entries.get(transferId);
      if (!entry || entry.channel !== channel) return;
      await this.unbind(entry);
      if (message.code === "SOURCE_CHANGED") {
        this.deps.onError(`发送方的 ${entry.record.fileName} 已变化，无法继续接收；可以放弃后让对方重新发送`);
      }
      this.deps.onChange();
    }
  }

  channelClosed(channel: BulkChannel): void {
    for (const [transferId, pending] of [...this.pending]) {
      if (pending.channel === channel) {
        this.pending.delete(transferId);
        this.deps.clearTimer(pending.timer);
      }
    }
    const transferId = this.channelTransfers.get(channel);
    const entry = transferId ? this.entries.get(transferId) : undefined;
    if (entry && entry.channel === channel) {
      void this.unbind(entry).then(() => this.deps.onChange());
    }
    this.deps.onChange();
  }

  /**
   * User abandonment: deletes local state and tells the sender. Over the session's channel a
   * plain file-cancel suffices; on other channels to the sender it carries the resume token.
   */
  async abandon(transferId: string, otherChannels: readonly BulkChannel[] = []): Promise<void> {
    const entry = this.entries.get(transferId) ?? await this.loadEntry(transferId);
    if (!entry) return;
    if (entry.channel) {
      sendJson(entry.channel, { kind: "file-cancel", transferId });
    } else {
      for (const channel of otherChannels) {
        sendJson(channel, { kind: "file-cancel", transferId, resumeToken: entry.record.resumeToken });
      }
    }
    await this.drop(entry, "CANCELLED");
  }

  async markSaved(transferId: string): Promise<void> {
    const entry = this.entries.get(transferId);
    if (!entry) return;
    entry.record.saved = true;
    // Deleted on the next page load, not now: the browser may still be reading the object URL.
    await entry.store.patchReceive(transferId, { saved: true }).catch(() => undefined);
  }

  /** Interrupted transfers whose original sender can be asked for a resume-offer. */
  resumeRequestTargets(): { transferId: string; sourcePeerId: string }[] {
    const now = this.deps.now();
    return [...this.entries.values()]
      .filter((entry) => entry.channel === null && entry.engine.state === "INTERRUPTED"
        && now < entry.record.expiresAt && entry.record.sourcePeerId
        && now - (this.resumeRequestedAt.get(entry.record.transferId) ?? 0) >= RESUME_REQUEST_INTERVAL_MS)
      .map((entry) => ({ transferId: entry.record.transferId, sourcePeerId: entry.record.sourcePeerId }));
  }

  sendResumeRequest(channel: BulkChannel, transferId: string): void {
    this.resumeRequestedAt.set(transferId, this.deps.now());
    sendJson(channel, { kind: "resume-request", transferId });
  }

  /** "清除互传本地数据": every record and chunk, in both stores. */
  async clearAll(): Promise<void> {
    for (const entry of [...this.entries.values()]) {
      if (entry.channel) sendJson(entry.channel, { kind: "file-cancel", transferId: entry.record.transferId });
      await this.unbind(entry);
    }
    for (const pending of this.pending.values()) {
      this.deps.clearTimer(pending.timer);
      this.sendReject(pending.channel, pending.offer.transferId, "DECLINED");
    }
    this.pending.clear();
    this.entries.clear();
    await this.deps.memoryStore.clear().catch(() => undefined);
    const store = await this.persistent();
    await store?.clear().catch(() => undefined);
    this.deps.onChange();
  }

  private activeSessions(): number {
    return [...this.entries.values()].filter((entry) => entry.channel !== null).length;
  }

  private sendReject(channel: BulkChannel, transferId: string, code: string) {
    sendJson(channel, { kind: "file-reject", transferId, code, reason: receiveRejectText(code) });
  }

  private async loadEntry(transferId: string): Promise<Entry | null> {
    const existing = this.entries.get(transferId);
    if (existing) return existing;
    for (const store of [await this.persistent(), this.deps.memoryStore]) {
      const record = store ? await store.getReceive(transferId).catch(() => null) : null;
      if (store && record) {
        const entry = this.entryFromRecord(record, store);
        this.entries.set(transferId, entry);
        return entry;
      }
    }
    return null;
  }

  private entryFromRecord(record: ReceiveRecord, store: ResumeStore): Entry {
    const have = new ChunkBitmap(record.chunkCount, new Uint8Array(record.have));
    const engine = new ChunkReceiver(
      {
        transferId: record.transferId,
        sizeBytes: record.sizeBytes,
        chunkSize: record.chunkSize,
        chunkCount: record.chunkCount,
        rootSha256: fromHex(record.rootSha256),
      },
      {
        have,
        hashes: record.hashes ? new Uint8Array(record.hashes) : null,
        integrityFailures: record.integrityFailures,
        state: record.state,
      },
      receiverStorage(store, record.transferId),
      this.deps.digest,
    );
    return { record: { ...record }, store, engine, channel: null, peerId: null, delivered: false };
  }

  private async bind(entry: Entry, channel: BulkChannel, peerId: string) {
    if (entry.channel && entry.channel !== channel) {
      this.channelTransfers.delete(entry.channel);
      entry.channel = null;
      await entry.engine.closeSession();
    }
    entry.channel = channel;
    entry.peerId = peerId;
    this.channelTransfers.set(channel, entry.record.transferId);
    await entry.engine.openSession();
  }

  private async unbind(entry: Entry) {
    if (entry.channel) {
      if (this.channelTransfers.get(entry.channel) === entry.record.transferId) {
        this.channelTransfers.delete(entry.channel);
      }
      entry.channel = null;
    }
    await entry.engine.closeSession();
  }

  private async drop(entry: Entry, reason: "CANCELLED" | "FAILED") {
    if (entry.channel && this.channelTransfers.get(entry.channel) === entry.record.transferId) {
      this.channelTransfers.delete(entry.channel);
    }
    entry.channel = null;
    if (reason === "CANCELLED") {
      await entry.engine.cancel();
    }
    this.entries.delete(entry.record.transferId);
    await entry.store.deleteReceive(entry.record.transferId).catch(() => undefined);
    this.deps.onChange();
  }

  private async afterStep(entry: Entry, channel: BulkChannel, step: ReceiverStep) {
    for (const message of step.send) {
      sendJson(channel, message.kind === "transfer-complete"
        ? { ...message, transferId: entry.record.transferId, manifestDigest: entry.record.manifestDigest }
        : { ...message, transferId: entry.record.transferId });
    }
    if (!step.sessionOpen && entry.channel === channel) {
      this.channelTransfers.delete(channel);
      entry.channel = null;
    }
    if (step.state === "FAILED") {
      this.deps.onError(`${entry.record.fileName} 校验多次失败，已删除已收数据；请让对方重新发送`);
      await this.drop(entry, "FAILED");
      return;
    }
    if (step.result === "STORAGE_FULL") {
      this.deps.onError(`本机浏览器存储空间不足，${entry.record.fileName} 已暂停；释放空间后可续传，也可以放弃`);
    } else if (step.result === "RETRY_EXHAUSTED") {
      this.deps.onError(`${entry.record.fileName} 同一块多次校验失败，本次连接已结束，可续传`);
    }
    if (step.result === "STORED" || step.result === "DUPLICATE" || !step.sessionOpen) {
      this.deps.onChange();
    }
    if (step.result === "STORED" && step.sessionOpen && entry.engine.bitmap.isComplete()) {
      await this.runFinalVerify(entry);
    }
  }

  private async runFinalVerify(entry: Entry) {
    const channel = entry.channel;
    if (!channel) return;
    const step = await entry.engine.finalVerify();
    if (step.result === "VERIFIED" && entry.channel === channel) {
      // Free the channel before transfer-complete goes out: the sender may offer the next
      // file right away and one bulk channel carries one receive at a time.
      this.channelTransfers.delete(channel);
      entry.channel = null;
    }
    await this.afterStep(entry, channel, step);
    if (step.result === "VERIFIED") {
      await entry.engine.closeSession();
      await this.deliver(entry, false);
    }
  }

  private async deliver(entry: Entry, restored: boolean) {
    if (entry.delivered) return;
    const parts: Blob[] = [];
    for (let index = 0; index < entry.record.chunkCount; index += 1) {
      const chunk = await entry.store.getChunk(entry.record.transferId, index).catch(() => null);
      if (!chunk) {
        this.deps.onError(`${entry.record.fileName} 的本机数据已被浏览器清除，无法恢复`);
        await this.drop(entry, "FAILED");
        return;
      }
      parts.push(chunk);
    }
    entry.delivered = true;
    this.deps.onComplete({
      transferId: entry.record.transferId,
      sourcePeerId: entry.peerId ?? entry.record.sourcePeerId,
      fileName: entry.record.fileName,
      mimeType: entry.record.mimeType,
      sizeBytes: entry.record.sizeBytes,
      blob: new Blob(parts, { type: entry.record.mimeType }),
      storage: entry.store.mode,
      restored,
    });
    if (entry.store.mode === "memory") {
      // The delivered Blob keeps the bytes alive; the record stays so a late resume-offer still
      // learns that the transfer completed.
      await entry.store.deleteChunks(entry.record.transferId).catch(() => undefined);
    }
    this.deps.onChange();
  }
}

function peerName(deps: ReceiverControllerDeps, peerId: string) {
  return deps.peerName(peerId) || "对方";
}

function receivedBytesOf(record: ReceiveRecord): number {
  if (record.state === "COMPLETE") return record.sizeBytes;
  const have = new ChunkBitmap(record.chunkCount, new Uint8Array(record.have));
  let total = 0;
  for (const index of have.indexes()) {
    total += Math.min(record.chunkSize, record.sizeBytes - index * record.chunkSize);
  }
  return total;
}

function receiverStorage(store: ResumeStore, transferId: string): ReceiverStorage {
  return {
    storeChunk: (index, bytes, have) => store.putChunk(transferId, index, bytes, have.bytes),
    readChunk: async (index) => {
      const blob = await store.getChunk(transferId, index);
      return blob ? new Uint8Array(await blob.arrayBuffer()) as Bytes : null;
    },
    storeHashes: (hashes) => store.patchReceive(transferId, { hashes: copyBuffer(hashes) }),
    storeProgress: (update) => store.patchReceive(transferId, {
      have: copyBuffer(update.have.bytes),
      integrityFailures: update.integrityFailures,
      state: update.state,
    }),
    discardChunks: () => store.deleteChunks(transferId),
  };
}

export function isResumableFileMeta(message: Record<string, unknown>): boolean {
  return isRecord(message.resume);
}
