import {
  MAX_CHUNK_MISMATCHES_PER_SESSION,
  MAX_INTEGRITY_FAILURES,
} from "./constants";
import { ChunkBitmap } from "./bitmap";
import { bytesEqual, concatBytes, ownedBytes, type Bytes, type Digest } from "./bytes";
import type { DecodedFrame } from "./frames";
import { chunkLengthOf } from "./manifest";

// Receiver state machine (§7, vector section `receiver`). One instance per transfer; it outlives
// sessions. Every call is serialized internally, so frames can be fed straight from onmessage.

export type ReceiverState = "RECEIVING" | "INTERRUPTED" | "COMPLETE" | "FAILED" | "CANCELLED";

export type ReceiverResult =
  | "OPENED"
  | "NO_SESSION"
  | "INTERRUPTED"
  | "HASHES_PARTIAL"
  | "HASHES_VERIFIED"
  | "ROOT_MISMATCH"
  | "WRONG_TRANSFER"
  | "HASHES_INCOMPLETE"
  | "OUT_OF_RANGE"
  | "UNEXPECTED_OFFSET"
  | "PARTIAL"
  | "DUPLICATE"
  | "STORED"
  | "HASH_MISMATCH"
  | "RETRY_EXHAUSTED"
  | "INTEGRITY_FAILED"
  | "NOT_READY"
  | "STORAGE_CORRUPT"
  | "VERIFIED"
  | "STORAGE_FULL"
  | "PROTOCOL_ERROR"
  | "CANCELLED";

export type TransferErrorCode =
  | "PROTOCOL_ERROR"
  | "RETRY_EXHAUSTED"
  | "INTEGRITY_FAILED"
  | "STORAGE_FULL"
  | "SOURCE_CHANGED";

/** Receiver messages as the vectors list them: transferId is added by the caller. */
export type ReceiverMessage =
  | { kind: "chunk-ack"; index: number }
  | { kind: "chunk-nack"; index: number; code: "HASH_MISMATCH" | "STORAGE_CORRUPT" }
  | { kind: "transfer-error"; code: TransferErrorCode }
  | { kind: "transfer-complete" };

export interface ReceiverStep {
  result: ReceiverResult;
  send: ReceiverMessage[];
  sessionOpen: boolean;
  state: ReceiverState;
}

const SESSION_ERRORS: Partial<Record<ReceiverResult, TransferErrorCode>> = {
  WRONG_TRANSFER: "PROTOCOL_ERROR",
  HASHES_INCOMPLETE: "PROTOCOL_ERROR",
  OUT_OF_RANGE: "PROTOCOL_ERROR",
  UNEXPECTED_OFFSET: "PROTOCOL_ERROR",
  PROTOCOL_ERROR: "PROTOCOL_ERROR",
  RETRY_EXHAUSTED: "RETRY_EXHAUSTED",
  INTEGRITY_FAILED: "INTEGRITY_FAILED",
  ROOT_MISMATCH: "INTEGRITY_FAILED",
  STORAGE_FULL: "STORAGE_FULL",
};

/** Where verified chunks live: IndexedDB in persistent mode, a Map in memory mode. */
export interface ReceiverStorage {
  /** Writes the chunk and its bit in one transaction: a set bit always has its chunk. */
  storeChunk(index: number, bytes: Bytes, have: ChunkBitmap): Promise<void>;
  readChunk(index: number): Promise<Bytes | null>;
  /** Only a complete, root-verified list is ever stored. */
  storeHashes(hashes: Bytes): Promise<void>;
  storeProgress(update: { have: ChunkBitmap; integrityFailures: number; state: ReceiverState }): Promise<void>;
  /** Drops every stored chunk (transfer failed or cancelled). */
  discardChunks(): Promise<void>;
}

export interface ReceiverManifest {
  transferId: string;
  sizeBytes: number;
  chunkSize: number;
  chunkCount: number;
  rootSha256: Uint8Array;
}

export interface ReceiverInitialState {
  have: ChunkBitmap;
  /** The persisted complete hash list, or null when it never completed. */
  hashes: Uint8Array | null;
  integrityFailures: number;
  state?: ReceiverState;
}

export function isStorageFullError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const name = (error as { name?: unknown }).name;
  return name === "QuotaExceededError" || name === "NS_ERROR_DOM_QUOTA_REACHED";
}

export class ChunkReceiver {
  readonly manifest: ReceiverManifest;
  private readonly storage: ReceiverStorage;
  private readonly digest: Digest;
  private have: ChunkBitmap;
  private hashes: Uint8Array[] = [];
  private hashesComplete: boolean;
  private failures: number;
  private currentState: ReceiverState;
  private session = false;
  private assembling: { index: number; parts: Uint8Array[]; length: number } | null = null;
  private mismatches = new Map<number, number>();
  private queue: Promise<unknown> = Promise.resolve();

  constructor(manifest: ReceiverManifest, initial: ReceiverInitialState, storage: ReceiverStorage, digest: Digest) {
    this.manifest = manifest;
    this.storage = storage;
    this.digest = digest;
    this.have = initial.have.copy();
    this.hashesComplete = initial.hashes !== null || manifest.chunkCount === 0;
    if (initial.hashes) {
      for (let index = 0; index < manifest.chunkCount; index += 1) {
        this.hashes.push(initial.hashes.subarray(index * 32, index * 32 + 32));
      }
    }
    this.failures = initial.integrityFailures;
    this.currentState = initial.state === "RECEIVING" ? "INTERRUPTED" : initial.state ?? "INTERRUPTED";
  }

  get state(): ReceiverState {
    return this.currentState;
  }

  get sessionOpen(): boolean {
    return this.session;
  }

  get integrityFailures(): number {
    return this.failures;
  }

  get hashListComplete(): boolean {
    return this.hashesComplete;
  }

  get bitmap(): ChunkBitmap {
    return this.have.copy();
  }

  hashList(): Bytes | null {
    return this.hashesComplete ? concatBytes(this.hashes) : null;
  }

  receivedBytes(): number {
    let total = 0;
    for (const index of this.have.indexes()) {
      total += chunkLengthOf(this.manifest.sizeBytes, this.manifest.chunkSize, index);
    }
    return total;
  }

  openSession(): Promise<ReceiverStep> {
    return this.serialize(async () => {
      if (this.currentState === "FAILED" || this.currentState === "CANCELLED") {
        return this.step("NO_SESSION", []);
      }
      this.session = true;
      this.assembling = null;
      this.mismatches = new Map();
      if (!this.hashesComplete) {
        this.hashes = []; // a partial hash list never survives a session
      }
      if (this.currentState !== "COMPLETE") {
        this.currentState = "RECEIVING";
        await this.persistProgress();
      }
      return this.step("OPENED", []);
    });
  }

  closeSession(): Promise<ReceiverStep> {
    return this.serialize(async () => {
      if (!this.session) {
        return this.step("NO_SESSION", []);
      }
      this.session = false;
      this.assembling = null;
      if (this.currentState === "RECEIVING") {
        this.currentState = "INTERRUPTED";
        await this.persistProgress();
      }
      return this.step("INTERRUPTED", []);
    });
  }

  /** Ends the session with PROTOCOL_ERROR, e.g. for a frame that does not decode. */
  protocolError(): Promise<ReceiverStep> {
    return this.serialize(async () => (this.session ? this.finish("PROTOCOL_ERROR", []) : this.step("NO_SESSION", [])));
  }

  /** Explicit abandonment by either side: state and stored chunks are dropped. */
  cancel(): Promise<ReceiverStep> {
    return this.serialize(async () => {
      this.session = false;
      this.assembling = null;
      this.currentState = "CANCELLED";
      this.have.clearAll();
      await this.storage.discardChunks().catch(() => undefined);
      await this.persistProgress();
      return this.step("CANCELLED", []);
    });
  }

  handleFrame(frame: DecodedFrame): Promise<ReceiverStep> {
    return this.serialize(async () => {
      if (!this.session) {
        return this.step("NO_SESSION", []);
      }
      const [result, send] = frame.type === "HASHES" ? await this.onHashes(frame) : await this.onData(frame);
      return this.finish(result, send);
    });
  }

  finalVerify(): Promise<ReceiverStep> {
    return this.serialize(async () => {
      if (!this.session) {
        return this.step("NO_SESSION", []);
      }
      const [result, send] = await this.onFinalVerify();
      return this.finish(result, send);
    });
  }

  private serialize<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private step(result: ReceiverResult, send: ReceiverMessage[]): ReceiverStep {
    return { result, send, sessionOpen: this.session, state: this.currentState };
  }

  private async finish(result: ReceiverResult, send: ReceiverMessage[]): Promise<ReceiverStep> {
    const code = SESSION_ERRORS[result];
    if (!code) {
      return this.step(result, send);
    }
    this.session = false;
    this.assembling = null;
    if (code === "INTEGRITY_FAILED") {
      this.currentState = "FAILED";
      this.have.clearAll();
      await this.storage.discardChunks().catch(() => undefined);
    } else {
      this.currentState = "INTERRUPTED";
    }
    await this.persistProgress();
    return this.step(result, [{ kind: "transfer-error", code }]);
  }

  private async persistProgress() {
    try {
      await this.storage.storeProgress({
        have: this.have.copy(),
        integrityFailures: this.failures,
        state: this.currentState,
      });
    } catch {
      // Progress metadata is best effort; chunk writes carry their own bit atomically.
    }
  }

  private async onHashes(frame: DecodedFrame): Promise<[ReceiverResult, ReceiverMessage[]]> {
    const count = this.manifest.chunkCount;
    if (frame.transferId !== this.manifest.transferId) {
      return ["WRONG_TRANSFER", []];
    }
    if (this.hashesComplete) {
      return ["UNEXPECTED_OFFSET", []];
    }
    const received = frame.payload.byteLength / 32;
    if (frame.index + received > count) {
      return ["OUT_OF_RANGE", []];
    }
    if (frame.index !== this.hashes.length) {
      return ["UNEXPECTED_OFFSET", []];
    }
    for (let index = 0; index < received; index += 1) {
      this.hashes.push(ownedBytes(frame.payload.subarray(index * 32, index * 32 + 32)));
    }
    if (this.hashes.length < count) {
      return ["HASHES_PARTIAL", []];
    }
    const list = concatBytes(this.hashes);
    if (!bytesEqual(await this.digest(list), this.manifest.rootSha256)) {
      return ["ROOT_MISMATCH", []];
    }
    try {
      await this.storage.storeHashes(list);
    } catch {
      this.hashes = [];
      return ["STORAGE_FULL", []];
    }
    this.hashesComplete = true;
    return ["HASHES_VERIFIED", []];
  }

  private async onData(frame: DecodedFrame): Promise<[ReceiverResult, ReceiverMessage[]]> {
    const { sizeBytes, chunkSize, chunkCount } = this.manifest;
    if (frame.transferId !== this.manifest.transferId) {
      return ["WRONG_TRANSFER", []];
    }
    if (!this.hashesComplete) {
      return ["HASHES_INCOMPLETE", []];
    }
    const { index, offset } = frame;
    const length = frame.payload.byteLength;
    if (index >= chunkCount || offset + length > chunkLengthOf(sizeBytes, chunkSize, index)) {
      return ["OUT_OF_RANGE", []];
    }
    const expectedOffset = this.assembling ? this.assembling.length : 0;
    if ((this.assembling && this.assembling.index !== index) || offset !== expectedOffset) {
      return ["UNEXPECTED_OFFSET", []];
    }
    if (!this.assembling) {
      this.assembling = { index, parts: [], length: 0 };
    }
    this.assembling.parts.push(ownedBytes(frame.payload));
    this.assembling.length += length;
    if (this.assembling.length < chunkLengthOf(sizeBytes, chunkSize, index)) {
      return ["PARTIAL", []];
    }
    const data = concatBytes(this.assembling.parts);
    this.assembling = null;
    if (this.have.has(index)) {
      return ["DUPLICATE", [{ kind: "chunk-ack", index }]]; // never re-verified, never rewritten
    }
    if (bytesEqual(await this.digest(data), this.hashes[index])) {
      const next = this.have.copy();
      next.set(index);
      try {
        await this.storage.storeChunk(index, data, next);
      } catch {
        return ["STORAGE_FULL", []];
      }
      this.have = next;
      return ["STORED", [{ kind: "chunk-ack", index }]];
    }
    this.failures += 1;
    const mismatches = (this.mismatches.get(index) ?? 0) + 1;
    this.mismatches.set(index, mismatches);
    if (this.failures >= MAX_INTEGRITY_FAILURES) {
      return ["INTEGRITY_FAILED", []];
    }
    if (mismatches >= MAX_CHUNK_MISMATCHES_PER_SESSION) {
      return ["RETRY_EXHAUSTED", []];
    }
    await this.persistProgress();
    return ["HASH_MISMATCH", [{ kind: "chunk-nack", index, code: "HASH_MISMATCH" }]];
  }

  private async onFinalVerify(): Promise<[ReceiverResult, ReceiverMessage[]]> {
    if (!this.hashesComplete || !this.have.isComplete()) {
      return ["NOT_READY", []];
    }
    const bad: number[] = [];
    for (let index = 0; index < this.manifest.chunkCount; index += 1) {
      const stored = await this.storage.readChunk(index).catch(() => null);
      const expectedLength = chunkLengthOf(this.manifest.sizeBytes, this.manifest.chunkSize, index);
      if (!stored || stored.byteLength !== expectedLength
        || !bytesEqual(await this.digest(stored), this.hashes[index])) {
        bad.push(index);
      }
    }
    for (const index of bad) {
      this.have.clear(index);
    }
    this.failures += bad.length;
    if (this.failures >= MAX_INTEGRITY_FAILURES) {
      return ["INTEGRITY_FAILED", []];
    }
    if (bad.length > 0) {
      await this.persistProgress();
      return ["STORAGE_CORRUPT", bad.map((index) => ({ kind: "chunk-nack" as const, index, code: "STORAGE_CORRUPT" as const }))];
    }
    this.currentState = "COMPLETE";
    await this.persistProgress();
    return ["VERIFIED", [{ kind: "transfer-complete" }]];
  }
}
