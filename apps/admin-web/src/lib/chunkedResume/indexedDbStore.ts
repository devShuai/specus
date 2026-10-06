import type { Bytes } from "./bytes";
import { copyBuffer, type ReceiveRecord, type ResumeStore, type SendRecord } from "./store";

// IndexedDB backend for persistent mode (§10, §14 item 4). A chunk Blob and its bitmap bit are
// written in one readwrite transaction over both object stores, so a set bit always has its chunk.

const DB_NAME = "specus-transfer-resume";
const DB_VERSION = 1;
const RECEIVES = "receives";
const CHUNKS = "chunks";
const SENDS = "sends";

interface ChunkRow {
  transferId: string;
  index: number;
  blob: Blob;
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new DOMException("IndexedDB transaction aborted", "AbortError"));
  });
}

function chunkRange(transferId: string) {
  return IDBKeyRange.bound([transferId, 0], [transferId, Infinity]);
}

export async function openIndexedDbResumeStore(): Promise<ResumeStore | null> {
  if (typeof indexedDB === "undefined" || typeof isSecureContext === "undefined" || !isSecureContext) {
    return null;
  }
  try {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(RECEIVES)) db.createObjectStore(RECEIVES, { keyPath: "transferId" });
      if (!db.objectStoreNames.contains(CHUNKS)) db.createObjectStore(CHUNKS, { keyPath: ["transferId", "index"] });
      if (!db.objectStoreNames.contains(SENDS)) db.createObjectStore(SENDS, { keyPath: "transferId" });
    };
    const db = await requestResult(request);
    return new IndexedDbResumeStore(db);
  } catch {
    // Private windows of some browsers refuse IndexedDB: persistent mode is then unavailable.
    return null;
  }
}

class IndexedDbResumeStore implements ResumeStore {
  readonly mode = "persistent" as const;
  private readonly db: IDBDatabase;

  constructor(db: IDBDatabase) {
    this.db = db;
    db.onversionchange = () => db.close();
  }

  async listReceives(): Promise<ReceiveRecord[]> {
    const transaction = this.db.transaction(RECEIVES, "readonly");
    return requestResult(transaction.objectStore(RECEIVES).getAll() as IDBRequest<ReceiveRecord[]>);
  }

  async getReceive(transferId: string): Promise<ReceiveRecord | null> {
    const transaction = this.db.transaction(RECEIVES, "readonly");
    const record = await requestResult(transaction.objectStore(RECEIVES).get(transferId) as IDBRequest<ReceiveRecord | undefined>);
    return record ?? null;
  }

  async putReceive(record: ReceiveRecord): Promise<void> {
    const transaction = this.db.transaction(RECEIVES, "readwrite");
    transaction.objectStore(RECEIVES).put(record);
    await transactionDone(transaction);
  }

  async patchReceive(transferId: string, patch: Partial<Omit<ReceiveRecord, "transferId">>): Promise<void> {
    const transaction = this.db.transaction(RECEIVES, "readwrite");
    const store = transaction.objectStore(RECEIVES);
    const done = transactionDone(transaction);
    const request = store.get(transferId) as IDBRequest<ReceiveRecord | undefined>;
    request.onsuccess = () => {
      if (request.result) {
        store.put({ ...request.result, ...patch });
      }
    };
    await done;
  }

  async putChunk(transferId: string, index: number, bytes: Bytes, have: Uint8Array): Promise<void> {
    const transaction = this.db.transaction([RECEIVES, CHUNKS], "readwrite");
    const receives = transaction.objectStore(RECEIVES);
    const done = transactionDone(transaction);
    const request = receives.get(transferId) as IDBRequest<ReceiveRecord | undefined>;
    request.onsuccess = () => {
      const record = request.result;
      if (!record || record.state === "FAILED" || record.state === "CANCELLED") {
        transaction.abort();
        return;
      }
      transaction.objectStore(CHUNKS).put({ transferId, index, blob: new Blob([bytes]) } satisfies ChunkRow);
      receives.put({ ...record, have: copyBuffer(have) });
    };
    await done;
  }

  async getChunk(transferId: string, index: number): Promise<Blob | null> {
    const transaction = this.db.transaction(CHUNKS, "readonly");
    const row = await requestResult(transaction.objectStore(CHUNKS).get([transferId, index]) as IDBRequest<ChunkRow | undefined>);
    return row?.blob ?? null;
  }

  async deleteReceive(transferId: string): Promise<void> {
    const transaction = this.db.transaction([RECEIVES, CHUNKS], "readwrite");
    transaction.objectStore(RECEIVES).delete(transferId);
    transaction.objectStore(CHUNKS).delete(chunkRange(transferId));
    await transactionDone(transaction);
  }

  async deleteChunks(transferId: string): Promise<void> {
    const transaction = this.db.transaction(CHUNKS, "readwrite");
    transaction.objectStore(CHUNKS).delete(chunkRange(transferId));
    await transactionDone(transaction);
  }

  async listChunkTransferIds(): Promise<string[]> {
    const transaction = this.db.transaction(CHUNKS, "readonly");
    const ids: string[] = [];
    await new Promise<void>((resolve, reject) => {
      const request = transaction.objectStore(CHUNKS).openKeyCursor();
      request.onerror = () => reject(request.error ?? new Error("IndexedDB cursor failed"));
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) {
          resolve();
          return;
        }
        const [transferId] = cursor.key as [string, number];
        ids.push(transferId);
        // Skip the remaining chunks of this transfer.
        cursor.continue([transferId, Infinity]);
      };
    });
    return ids;
  }

  async listSends(): Promise<SendRecord[]> {
    const transaction = this.db.transaction(SENDS, "readonly");
    return requestResult(transaction.objectStore(SENDS).getAll() as IDBRequest<SendRecord[]>);
  }

  async putSend(record: SendRecord): Promise<void> {
    const transaction = this.db.transaction(SENDS, "readwrite");
    transaction.objectStore(SENDS).put(record);
    await transactionDone(transaction);
  }

  async patchSend(transferId: string, patch: Partial<Omit<SendRecord, "transferId">>): Promise<void> {
    const transaction = this.db.transaction(SENDS, "readwrite");
    const store = transaction.objectStore(SENDS);
    const done = transactionDone(transaction);
    const request = store.get(transferId) as IDBRequest<SendRecord | undefined>;
    request.onsuccess = () => {
      if (request.result) {
        store.put({ ...request.result, ...patch });
      }
    };
    await done;
  }

  async deleteSend(transferId: string): Promise<void> {
    const transaction = this.db.transaction(SENDS, "readwrite");
    transaction.objectStore(SENDS).delete(transferId);
    await transactionDone(transaction);
  }

  async clear(): Promise<void> {
    const transaction = this.db.transaction([RECEIVES, CHUNKS, SENDS], "readwrite");
    transaction.objectStore(RECEIVES).clear();
    transaction.objectStore(CHUNKS).clear();
    transaction.objectStore(SENDS).clear();
    await transactionDone(transaction);
  }
}

/** Free space as the browser reports it; null when estimate() is unavailable. */
export async function estimateStorage(): Promise<{ quota: number; usage: number } | null> {
  try {
    if (typeof navigator === "undefined" || typeof navigator.storage?.estimate !== "function") {
      return null;
    }
    const estimate = await navigator.storage.estimate();
    if (typeof estimate.quota !== "number" || typeof estimate.usage !== "number") {
      return null;
    }
    return { quota: estimate.quota, usage: estimate.usage };
  } catch {
    return null;
  }
}
