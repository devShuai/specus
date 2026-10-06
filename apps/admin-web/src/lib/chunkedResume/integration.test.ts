import { describe, expect, it } from "vitest";
import { ChunkBitmap } from "./bitmap";
import { randomHex128, sha256, type Bytes } from "./bytes";
import type { BulkChannel } from "./channel";
import { hashChunksOnCurrentThread } from "./chunkHashes";
import { GIB, KIB, RESUME_TTL_SECONDS, UNACKED_WINDOW_CHUNKS } from "./constants";
import { decodeFrame } from "./frames";
import { manifestFromHashes, type Manifest } from "./manifest";
import { ReceiverController, type ReceivedFile } from "./receiverController";
import { sendResumable, type OpenedChannel } from "./resumableSend";
import { SenderError, SenderRouter, type OutgoingTransfer } from "./senderController";
import { MemoryResumeStore } from "./store";

// Two pages over a fake bulk DataChannel pair: real frames, real SHA-256, in-memory storage.
// Storage is the in-memory implementation of the same interface the IndexedDB backend implements
// (no IndexedDB shim is a dependency of this package).

const CHUNK = 64 * KIB;
const FRAME = 16 * KIB;

type Tap = (data: string | ArrayBuffer) => string | ArrayBuffer | "cut" | "drop";
interface Taps {
  sender?: Tap;
  receiver?: Tap;
}

class FakeChannel implements BulkChannel {
  readyState = "open";
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  peer!: FakeChannel;
  onmessage: ((data: string | ArrayBuffer) => void) | null = null;
  onclose: (() => void) | null = null;
  tap: Tap | null = null;
  private readonly listeners = new Map<string, Set<() => void>>();

  addEventListener(type: string, listener: () => void) {
    const set = this.listeners.get(type) ?? new Set();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: string, listener: () => void) {
    this.listeners.get(type)?.delete(listener);
  }

  send(data: string | ArrayBuffer) {
    if (this.readyState !== "open") throw new Error("channel closed");
    const out = this.tap ? this.tap(data) : data;
    if (out === "cut") {
      this.close();
      return;
    }
    if (out === "drop") return;
    const peer = this.peer;
    const payload = typeof out === "string" ? out : out.slice(0);
    setTimeout(() => {
      if (peer.readyState === "open") peer.onmessage?.(payload);
    }, 0);
  }

  close() {
    for (const side of [this, this.peer]) {
      if (side.readyState === "closed") continue;
      side.readyState = "closed";
      for (const listener of [...(side.listeners.get("close") ?? [])]) listener();
      side.onclose?.();
    }
  }
}

function pattern(start: number, length: number): Bytes {
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 1) {
    const i = start + offset;
    out[offset] = (i % 251) ^ (Math.floor(i / 251) & 0xff);
  }
  return out;
}

async function bytesOf(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

class Clock {
  now = Date.parse("2026-10-06T12:00:00Z");
}

class ReceiverPage {
  readonly controller: ReceiverController;
  readonly completed: ReceivedFile[] = [];
  readonly errors: string[] = [];
  autoAccept = true;
  clickAccept = true;

  constructor(readonly persistent: MemoryResumeStore | null, readonly memory: MemoryResumeStore, clock: Clock) {
    this.controller = new ReceiverController({
      openPersistentStore: async () => persistent,
      memoryStore: memory,
      estimate: async () => ({ quota: 10 * GIB, usage: 0 }),
      now: () => clock.now,
      digest: sha256,
      randomToken: randomHex128,
      autoAccept: () => this.autoAccept,
      senderAllowed: () => true,
      peerName: () => "sender",
      setTimer: (callback, ms) => setTimeout(callback, ms),
      clearTimer: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
      onChange: () => {
        if (!this.clickAccept) return;
        for (const pending of this.controller.snapshot().pending) {
          void this.controller.accept(pending.transferId);
        }
      },
      onComplete: (file) => this.completed.push(file),
      onError: (message) => this.errors.push(message),
    });
  }

  attach(channel: FakeChannel, peerId = "sender-peer") {
    channel.onmessage = (data) => {
      if (typeof data !== "string") {
        this.controller.handleFrame(channel, data);
        return;
      }
      const message = JSON.parse(data) as Record<string, unknown>;
      if (message.kind === "file-meta") void this.controller.handleFileMeta(peerId, channel, message);
      else if (message.kind === "resume-offer") void this.controller.handleResumeOffer(peerId, channel, message);
      else void this.controller.handleSenderMessage(peerId, channel, message);
    };
    channel.onclose = () => this.controller.channelClosed(channel);
  }
}

class SenderPage {
  readonly router = new SenderRouter();
  readonly transfers: OutgoingTransfer[] = [];
  readonly finished: { transferId: string; outcome: string }[] = [];
  readonly sleeps: number[] = [];
  /** DATA frames per chunk index, to measure retransmission. */
  readonly dataFrames = new Map<number, number>();
  channel: FakeChannel | null = null;
  persistedRecords = 0;

  constructor(readonly receiver: ReceiverPage, readonly clock: Clock) {}

  connect(taps?: Taps): FakeChannel {
    const sender = new FakeChannel();
    const receiver = new FakeChannel();
    sender.peer = receiver;
    receiver.peer = sender;
    sender.onmessage = (data) => {
      if (typeof data === "string") this.router.dispatch(sender, JSON.parse(data) as Record<string, unknown>);
    };
    sender.onclose = () => this.router.channelClosed(sender);
    sender.tap = (data) => {
      if (typeof data !== "string") {
        const decoded = decodeFrame(data);
        if (decoded.ok && decoded.frame.type === "DATA" && decoded.frame.offset === 0) {
          this.dataFrames.set(decoded.frame.index, (this.dataFrames.get(decoded.frame.index) ?? 0) + 1);
        }
      }
      return taps?.sender ? taps.sender(data) : data;
    };
    receiver.tap = taps?.receiver ?? null;
    this.receiver.attach(receiver);
    this.channel = sender;
    return sender;
  }

  async send(source: Blob, options: {
    existing?: OutgoingTransfer | null;
    tapForNewChannels?: () => Taps | undefined;
    retryOpenFailures?: boolean;
  } = {}) {
    return sendResumable({
      source,
      lastModified: 1,
      targetPeerId: "receiver-peer",
      targetName: "receiver",
      existing: options.existing ?? null,
      router: this.router,
      digest: sha256,
      now: () => this.clock.now,
      openChannel: async (): Promise<OpenedChannel> => {
        const channel = this.channel?.readyState === "open" ? this.channel : this.connect(options.tapForNewChannels?.());
        return { channel, peerId: "receiver-peer", frameBytes: FRAME, ensureCurrent: () => undefined };
      },
      buildManifest: () => buildManifest(source),
      retryOpenFailures: options.retryOpenFailures ?? true,
      sleep: async (ms) => {
        this.sleeps.push(ms);
      },
      onTransfer: (transfer) => this.transfers.push(transfer),
      onPhase: () => undefined,
      onProgress: () => undefined,
      onAccepted: async () => {
        this.persistedRecords += 1;
      },
      onFinished: (transfer, outcome) => this.finished.push({ transferId: transfer.transferId, outcome }),
    });
  }
}

async function buildManifest(source: Blob, fileName = "video.bin"): Promise<Manifest> {
  const hashes = await hashChunksOnCurrentThread(source, CHUNK);
  return manifestFromHashes({ sizeBytes: source.size, chunkSize: CHUNK, fileName, mimeType: "application/octet-stream", hashes });
}

function setup(persistent = true) {
  const clock = new Clock();
  const persistentStore = persistent ? new MemoryResumeStore("persistent") : null;
  const receiver = new ReceiverPage(persistentStore, new MemoryResumeStore(), clock);
  const sender = new SenderPage(receiver, clock);
  return { clock, persistentStore, receiver, sender };
}

/** Receiver side: cuts the channel instead of sending chunk-ack number `limit + 1`. */
function cutAfterAcks(limit: number): Tap {
  let seen = 0;
  return (data) => {
    if (typeof data === "string" && (JSON.parse(data) as { kind?: string }).kind === "chunk-ack") {
      seen += 1;
      if (seen > limit) return "cut";
    }
    return data;
  };
}

/** The first channel is cut after `limit` stored chunks; every later channel dies at once. */
function interruptAfter(limit: number): () => Taps {
  let channels = 0;
  return () => (channels++ === 0 ? { receiver: cutAfterAcks(limit) } : { sender: () => "cut" });
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

// Real SHA-256 over megabytes and real timers: a loaded CI runner needs more than the default 5 s.
describe("chunked resume between two pages", { timeout: 30_000 }, () => {
  it("auto-accepts a small file in memory mode and delivers identical bytes", async () => {
    const { receiver, sender, persistentStore } = setup();
    const source = new Blob([pattern(0, 300_000)]);
    const result = await sender.send(source);
    await settle();
    expect(result.kind).toBe("complete");
    expect(receiver.completed).toHaveLength(1);
    expect(receiver.completed[0].storage).toBe("memory");
    expect(await bytesOf(receiver.completed[0].blob)).toEqual(pattern(0, 300_000));
    // Auto-accept never writes to the persistent store.
    expect(await persistentStore!.listReceives()).toEqual([]);
    expect(sender.finished.at(-1)?.outcome).toBe("complete");
  });

  it("frees the channel after completion so the next file can follow right away", async () => {
    const { receiver, sender } = setup();
    receiver.autoAccept = false;
    const first = await sender.send(new Blob([pattern(0, 2 * CHUNK + 5)]));
    const channel = sender.channel;
    const second = await sender.send(new Blob([pattern(7, 3 * CHUNK)]));
    await settle();
    expect([first.kind, second.kind]).toEqual(["complete", "complete"]);
    expect(sender.channel).toBe(channel);
    expect(receiver.completed).toHaveLength(2);
    expect(await bytesOf(receiver.completed[1].blob)).toEqual(pattern(7, 3 * CHUNK));
  });

  it("asks before writing to persistent storage and completes after the click", async () => {
    const { receiver, sender, persistentStore } = setup();
    receiver.autoAccept = false;
    const source = new Blob([pattern(0, 200_000)]);
    const result = await sender.send(source);
    await settle();
    expect(result.kind).toBe("complete");
    expect(receiver.completed[0].storage).toBe("persistent");
    expect(sender.persistedRecords).toBe(1);
    const [record] = await persistentStore!.listReceives();
    expect(record.state).toBe("COMPLETE");
    expect(record.expiresAt - record.createdAt).toBe(RESUME_TTL_SECONDS * 1000);
    expect(await bytesOf(receiver.completed[0].blob)).toEqual(pattern(0, 200_000));
  });

  it("resumes in-session after a cut and repeats at most the window plus one chunk", async () => {
    const { receiver, sender } = setup();
    receiver.autoAccept = false;
    const size = 20 * CHUNK + 1234;
    const source = new Blob([pattern(0, size)]);
    let cuts = 0;
    const result = await sender.send(source, {
      tapForNewChannels: () => (cuts++ === 0 ? { receiver: cutAfterAcks(9) } : undefined),
    });
    await settle();
    expect(result.kind).toBe("complete");
    expect(sender.sleeps).toEqual([1000]);
    expect(await bytesOf(receiver.completed[0].blob)).toEqual(pattern(0, size));
    const repeated = [...sender.dataFrames.values()].filter((count) => count > 1).length;
    expect(repeated).toBeGreaterThan(0);
    expect(repeated).toBeLessThanOrEqual(UNACKED_WINDOW_CHUNKS + 1);
    // One consent only: the resume needed no second click.
    expect(sender.transfers).toHaveLength(1);
  });

  it("recovers after the receiver reloads: the record comes back from storage without new consent", async () => {
    const { receiver, sender, persistentStore, clock } = setup();
    receiver.autoAccept = false;
    const size = 12 * CHUNK;
    const source = new Blob([pattern(0, size)]);
    // First receiver page: the transfer is cut and every reconnect fails.
    const failure = await sender.send(source, { tapForNewChannels: interruptAfter(5) }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(SenderError);
    expect(sender.sleeps).toEqual([1000, 2000, 4000, 8000, 16000]);
    await settle();
    const transfer = sender.transfers[0];
    const [stored] = await persistentStore!.listReceives();
    expect(stored.state).toBe("INTERRUPTED");
    expect(new ChunkBitmap(stored.chunkCount, new Uint8Array(stored.have)).count()).toBeGreaterThan(0);
    // The receiver reloads: a new controller over the same storage.
    const reloaded = new ReceiverPage(persistentStore, new MemoryResumeStore(), clock);
    reloaded.clickAccept = false; // a resume must not prompt
    await reloaded.controller.restore();
    const sender2 = new SenderPage(reloaded, clock);
    const result = await sender2.send(source, { existing: transfer });
    await settle();
    expect(result.kind).toBe("complete");
    expect(result.transfer.transferId).toBe(transfer.transferId);
    expect(reloaded.controller.snapshot().pending).toEqual([]);
    expect(await bytesOf(reloaded.completed[0].blob)).toEqual(pattern(0, size));
  });

  it("refuses a reselected file whose missing chunk changed with SOURCE_CHANGED", async () => {
    const { receiver, sender, clock, persistentStore } = setup();
    receiver.autoAccept = false;
    const size = 10 * CHUNK;
    const source = new Blob([pattern(0, size)]);
    await sender.send(source, { tapForNewChannels: interruptAfter(3) }).catch(() => undefined);
    await settle();
    const transfer = sender.transfers[0];
    // Sender reloads and the user picks a file of the same size with a changed tail.
    const changed = pattern(0, size);
    changed[size - 1] ^= 0xff;
    const restored: OutgoingTransfer = { ...transfer, source: null, confirmedPeers: new Set() };
    const reloadedReceiver = new ReceiverPage(persistentStore, new MemoryResumeStore(), clock);
    await reloadedReceiver.controller.restore();
    const sender2 = new SenderPage(reloadedReceiver, clock);
    const failure = await sender2.send(new Blob([changed]), { existing: restored }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(SenderError);
    expect((failure as SenderError).code).toBe("SOURCE_CHANGED");
    expect(sender2.finished.at(-1)?.outcome).toBe("dropped");
    await settle();
    expect(reloadedReceiver.errors.some((message) => message.includes("已变化"))).toBe(true);
  });

  it("re-requests a chunk whose bytes were corrupted on the wire", async () => {
    const { receiver, sender, persistentStore } = setup();
    receiver.autoAccept = false;
    const size = 6 * CHUNK;
    let corrupted = false;
    const result = await sender.send(new Blob([pattern(0, size)]), {
      tapForNewChannels: () => ({ sender: (data) => {
        if (typeof data === "string" || corrupted) return data;
        const decoded = decodeFrame(data);
        if (decoded.ok && decoded.frame.type === "DATA" && decoded.frame.index === 2 && decoded.frame.offset === 0) {
          corrupted = true;
          const copy = new Uint8Array(data.slice(0));
          copy[36] ^= 0xff;
          return copy.buffer;
        }
        return data;
      } }),
    });
    await settle();
    expect(result.kind).toBe("complete");
    expect(sender.dataFrames.get(2)).toBe(2);
    const [record] = await persistentStore!.listReceives();
    expect(record.integrityFailures).toBe(1);
    expect(await bytesOf(receiver.completed[0].blob)).toEqual(pattern(0, size));
  });

  it("finds a corrupted stored chunk in final verification and has it sent again", async () => {
    const { receiver, sender, persistentStore } = setup();
    receiver.autoAccept = false;
    const size = 4 * CHUNK;
    const store = persistentStore!;
    const originalGet = store.getChunk.bind(store);
    let corruptedOnce = false;
    store.getChunk = async (transferId, index) => {
      const blob = await originalGet(transferId, index);
      if (blob && index === 1 && !corruptedOnce) {
        corruptedOnce = true;
        const bytes = new Uint8Array(await blob.arrayBuffer());
        bytes[0] ^= 0xff;
        return new Blob([bytes]);
      }
      return blob;
    };
    const result = await sender.send(new Blob([pattern(0, size)]));
    await settle();
    expect(result.kind).toBe("complete");
    expect(sender.dataFrames.get(1)).toBe(2);
    expect(await bytesOf(receiver.completed[0].blob)).toEqual(pattern(0, size));
  });

  it("restarts as a new transfer after the consent expired", async () => {
    const { receiver, sender, clock } = setup();
    receiver.autoAccept = false;
    const size = 8 * CHUNK;
    const source = new Blob([pattern(0, size)]);
    await sender.send(source, { tapForNewChannels: interruptAfter(2) }).catch(() => undefined);
    await settle();
    const first = sender.transfers[0];
    clock.now += RESUME_TTL_SECONDS * 1000; // exactly at expiry counts as expired
    const result = await sender.send(source, { existing: first });
    await settle();
    expect(result.kind).toBe("complete");
    expect(result.transfer.transferId).not.toBe(first.transferId);
    expect(await bytesOf(receiver.completed[0].blob)).toEqual(pattern(0, size));
  });

  it("stops with STORAGE_FULL, keeps the record and resumes after space is freed", async () => {
    const { receiver, sender, persistentStore } = setup();
    receiver.autoAccept = false;
    const size = 6 * CHUNK;
    const source = new Blob([pattern(0, size)]);
    persistentStore!.failWrites = "quota";
    const failure = await sender.send(source).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(SenderError);
    expect((failure as SenderError).failure).toBe("stop");
    await settle();
    const [record] = await persistentStore!.listReceives();
    expect(record.state).toBe("INTERRUPTED");
    persistentStore!.failWrites = false;
    const result = await sender.send(source, { existing: sender.transfers[0] });
    await settle();
    expect(result.kind).toBe("complete");
    expect(await bytesOf(receiver.completed[0].blob)).toEqual(pattern(0, size));
  });

  it("falls back to the legacy flow when an old page answers file-ready", async () => {
    const clock = new Clock();
    const router = new SenderRouter();
    const source = new Blob([pattern(0, 1000)]);
    const sender = new FakeChannel();
    const legacy = new FakeChannel();
    sender.peer = legacy;
    legacy.peer = sender;
    sender.onmessage = (data) => {
      if (typeof data === "string") router.dispatch(sender, JSON.parse(data) as Record<string, unknown>);
    };
    legacy.onmessage = (data) => {
      if (typeof data !== "string") return;
      const message = JSON.parse(data) as { kind: string; transferId: string; sha256: unknown };
      expect(message.sha256).toBeNull();
      if (message.kind === "file-meta") legacy.send(JSON.stringify({ kind: "file-ready", transferId: message.transferId }));
    };
    const result = await sendResumable({
      source,
      lastModified: 1,
      targetPeerId: "old",
      targetName: "old",
      existing: null,
      router,
      digest: sha256,
      now: () => clock.now,
      openChannel: async () => ({ channel: sender, peerId: "old", frameBytes: FRAME, ensureCurrent: () => undefined }),
      buildManifest: () => buildManifest(source),
      retryOpenFailures: false,
      sleep: async () => undefined,
      onTransfer: () => undefined,
      onPhase: () => undefined,
      onProgress: () => undefined,
      onAccepted: async () => undefined,
      onFinished: () => undefined,
    });
    expect(result.kind).toBe("legacy");
  });

  it("offers a new transfer when the receiver does not know the old one", async () => {
    const { receiver, sender } = setup();
    const size = 3 * CHUNK;
    const source = new Blob([pattern(0, size)]);
    const manifest = await buildManifest(source);
    const stale: OutgoingTransfer = {
      transferId: randomHex128(),
      manifest,
      source,
      lastModified: 1,
      targetPeerId: "receiver-peer",
      targetName: "receiver",
      resumeToken: randomHex128(),
      storage: "persistent",
      expiresAt: Date.now() + 1000,
      acked: new ChunkBitmap(manifest.chunkCount),
      confirmedPeers: new Set(),
      offered: true,
    };
    // The receiver has no record: it answers UNKNOWN_TRANSFER right away.
    const result = await sender.send(source, { existing: stale });
    await settle();
    expect(result.kind).toBe("complete");
    expect(result.transfer.transferId).not.toBe(stale.transferId);
    expect(sender.finished.some((item) => item.transferId === stale.transferId && item.outcome === "dropped")).toBe(true);
    expect(receiver.completed).toHaveLength(1);
  });

  it("deletes the receiver's data on an in-channel cancel but ignores a token-less one elsewhere", async () => {
    const { receiver, sender, persistentStore } = setup();
    receiver.autoAccept = false;
    const size = 6 * CHUNK;
    await sender.send(new Blob([pattern(0, size)]), { tapForNewChannels: interruptAfter(2) }).catch(() => undefined);
    await settle();
    const transfer = sender.transfers[0];
    const [record] = await persistentStore!.listReceives();
    expect(record.transferId).toBe(transfer.transferId);
    // A bystander on another channel without the token cannot delete it.
    const bystander = new FakeChannel();
    bystander.peer = new FakeChannel();
    bystander.peer.peer = bystander;
    await receiver.controller.handleSenderMessage("other", bystander, { kind: "file-cancel", transferId: transfer.transferId });
    expect(await persistentStore!.listReceives()).toHaveLength(1);
    // With the token it can.
    await receiver.controller.handleSenderMessage("other", bystander, {
      kind: "file-cancel",
      transferId: transfer.transferId,
      resumeToken: transfer.resumeToken,
    });
    expect(await persistentStore!.listReceives()).toEqual([]);
    expect(await persistentStore!.listChunkTransferIds()).toEqual([]);
  });

  it("cleans expired records and orphan chunks on load and keeps completed unsaved files", async () => {
    const { receiver, sender, persistentStore, clock } = setup();
    receiver.autoAccept = false;
    await sender.send(new Blob([pattern(0, 2 * CHUNK)]));
    await settle();
    const [completed] = await persistentStore!.listReceives();
    expect(completed.state).toBe("COMPLETE");
    // A failed record with a chunk, an orphan chunk without a record and an expired partial.
    const failed = "9".repeat(32);
    const orphan = "8".repeat(32);
    const expired = "7".repeat(32);
    for (const transferId of [failed, orphan, expired]) {
      await persistentStore!.putReceive({ ...completed, transferId, state: "INTERRUPTED" });
      await persistentStore!.putChunk(transferId, 0, pattern(0, 10), new Uint8Array(1));
    }
    await persistentStore!.patchReceive(failed, { state: "FAILED" });
    await persistentStore!.dropRecordOnlyForTest(orphan);
    await persistentStore!.patchReceive(expired, { expiresAt: clock.now });

    const reloaded = new ReceiverPage(persistentStore, new MemoryResumeStore(), clock);
    await reloaded.controller.restore();
    // Completed but unsaved: offered again for saving after the reload.
    expect(reloaded.completed.map((file) => file.restored)).toEqual([true]);
    expect((await persistentStore!.listReceives()).map((record) => record.transferId)).toEqual([completed.transferId]);
    expect(await persistentStore!.listChunkTransferIds()).toEqual([completed.transferId]);

    // Saved: deleted on the next load, not immediately.
    await reloaded.controller.markSaved(completed.transferId);
    expect(await persistentStore!.listReceives()).toHaveLength(1);
    const third = new ReceiverPage(persistentStore, new MemoryResumeStore(), clock);
    await third.controller.restore();
    expect(await persistentStore!.listReceives()).toEqual([]);
    expect(await persistentStore!.listChunkTransferIds()).toEqual([]);
  });

  it("falls back to memory mode with a prompt when persistent storage is unavailable", async () => {
    const { receiver, sender } = setup(false);
    receiver.autoAccept = false;
    const result = await sender.send(new Blob([pattern(0, 3 * CHUNK)]));
    await settle();
    expect(result.kind).toBe("complete");
    expect(receiver.completed[0].storage).toBe("memory");
  });
});
