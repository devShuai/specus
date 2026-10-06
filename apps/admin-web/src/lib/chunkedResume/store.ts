import type { ReceiverState } from "./receiver";
import type { Bytes } from "./bytes";

// Storage behind both modes (§10). Persistent mode is IndexedDB (indexedDbStore.ts); memory mode
// and the tests use MemoryResumeStore. Chunks are Blobs keyed by [transferId, index].

export type StorageMode = "persistent" | "memory";

export interface ReceiveRecord {
  transferId: string;
  manifestDigest: string;
  resumeToken: string;
  sizeBytes: number;
  chunkSize: number;
  chunkCount: number;
  fileName: string;
  mimeType: string;
  rootSha256: string;
  /** The complete, root-verified hash list; null until it completes. */
  hashes: ArrayBuffer | null;
  /** Bitmap bytes; a set bit always has its chunk in the same store. */
  have: ArrayBuffer;
  integrityFailures: number;
  state: ReceiverState;
  saved: boolean;
  createdAt: number;
  /** Local-clock instant (ms): consent time + resumeTtlSeconds, never extended. */
  expiresAt: number;
  sourcePeerId: string;
  /** Display only. */
  sourceName: string;
}

export interface SendRecord {
  transferId: string;
  manifestDigest: string;
  resumeToken: string;
  expiresAt: number;
  targetPeerId: string;
  targetName: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  lastModified: number;
  chunkSize: number;
  chunkCount: number;
  rootSha256: string;
  hashes: ArrayBuffer;
  /** Receiver's bitmap as last acknowledged (display only; the receiver is authoritative). */
  acked: ArrayBuffer;
}

export interface ResumeStore {
  readonly mode: StorageMode;
  listReceives(): Promise<ReceiveRecord[]>;
  getReceive(transferId: string): Promise<ReceiveRecord | null>;
  putReceive(record: ReceiveRecord): Promise<void>;
  patchReceive(transferId: string, patch: Partial<Omit<ReceiveRecord, "transferId">>): Promise<void>;
  /** Writes the chunk and the record's bitmap in one transaction. */
  putChunk(transferId: string, index: number, bytes: Bytes, have: Uint8Array): Promise<void>;
  getChunk(transferId: string, index: number): Promise<Blob | null>;
  deleteReceive(transferId: string): Promise<void>;
  deleteChunks(transferId: string): Promise<void>;
  listChunkTransferIds(): Promise<string[]>;
  listSends(): Promise<SendRecord[]>;
  putSend(record: SendRecord): Promise<void>;
  patchSend(transferId: string, patch: Partial<Omit<SendRecord, "transferId">>): Promise<void>;
  deleteSend(transferId: string): Promise<void>;
  clear(): Promise<void>;
}

export function copyBuffer(bytes: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
}

export class MemoryResumeStore implements ResumeStore {
  readonly mode: StorageMode;
  private readonly receives = new Map<string, ReceiveRecord>();
  private readonly chunks = new Map<string, Map<number, Blob>>();
  private readonly sends = new Map<string, SendRecord>();
  /** Test hook: throw a QuotaExceededError-like error from putChunk. */
  failWrites: false | "quota" = false;

  constructor(mode: StorageMode = "memory") {
    this.mode = mode;
  }

  async listReceives() {
    return [...this.receives.values()].map((record) => ({ ...record }));
  }

  async getReceive(transferId: string) {
    const record = this.receives.get(transferId);
    return record ? { ...record } : null;
  }

  async putReceive(record: ReceiveRecord) {
    this.receives.set(record.transferId, { ...record });
  }

  async patchReceive(transferId: string, patch: Partial<Omit<ReceiveRecord, "transferId">>) {
    const record = this.receives.get(transferId);
    if (record) {
      this.receives.set(transferId, { ...record, ...patch });
    }
  }

  async putChunk(transferId: string, index: number, bytes: Bytes, have: Uint8Array) {
    const record = this.receives.get(transferId);
    if (!record) {
      throw new Error("transfer record is gone");
    }
    if (this.failWrites === "quota") {
      const error = new Error("quota exceeded");
      error.name = "QuotaExceededError";
      throw error;
    }
    const chunks = this.chunks.get(transferId) ?? new Map<number, Blob>();
    chunks.set(index, new Blob([bytes]));
    this.chunks.set(transferId, chunks);
    this.receives.set(transferId, { ...record, have: copyBuffer(have) });
  }

  async getChunk(transferId: string, index: number) {
    return this.chunks.get(transferId)?.get(index) ?? null;
  }

  async deleteReceive(transferId: string) {
    this.receives.delete(transferId);
    this.chunks.delete(transferId);
  }

  async deleteChunks(transferId: string) {
    this.chunks.delete(transferId);
  }

  async listChunkTransferIds() {
    return [...this.chunks.entries()].filter(([, chunks]) => chunks.size > 0).map(([transferId]) => transferId);
  }

  /** Test hook: forget a record but keep its chunks, leaving orphans behind. */
  async dropRecordOnlyForTest(transferId: string) {
    this.receives.delete(transferId);
  }

  async listSends() {
    return [...this.sends.values()].map((record) => ({ ...record }));
  }

  async putSend(record: SendRecord) {
    this.sends.set(record.transferId, { ...record });
  }

  async patchSend(transferId: string, patch: Partial<Omit<SendRecord, "transferId">>) {
    const record = this.sends.get(transferId);
    if (record) {
      this.sends.set(transferId, { ...record, ...patch });
    }
  }

  async deleteSend(transferId: string) {
    this.sends.delete(transferId);
  }

  async clear() {
    this.receives.clear();
    this.chunks.clear();
    this.sends.clear();
  }
}
