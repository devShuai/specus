import { chunkCountOf, chunkLengthOf } from "./manifest";
import { sha256, type Bytes } from "./bytes";

// Per-chunk SHA-256 of a whole file for the manifest (§3). Runs crypto.subtle in a Worker so a
// 2 GiB file does not stall the page (§14 item 15); falls back to the current thread when a
// Worker cannot start (CSP or an embedded browser).

export interface ChunkHashRequest {
  blob: Blob;
  chunkSize: number;
}

export type ChunkHashWorkerMessage =
  | { type: "progress"; hashedBytes: number }
  | { type: "done"; hashes: ArrayBuffer }
  | { type: "error"; message: string };

export async function hashChunksOnCurrentThread(
  blob: Blob,
  chunkSize: number,
  signal?: AbortSignal,
  onProgress?: (hashedBytes: number) => void,
): Promise<Bytes> {
  const count = chunkCountOf(blob.size, chunkSize);
  const hashes = new Uint8Array(count * 32);
  let hashed = 0;
  for (let index = 0; index < count; index += 1) {
    throwIfAborted(signal);
    const start = index * chunkSize;
    const length = chunkLengthOf(blob.size, chunkSize, index);
    const bytes: Bytes = new Uint8Array(await blob.slice(start, start + length).arrayBuffer());
    hashes.set(await sha256(bytes), index * 32);
    hashed += length;
    onProgress?.(hashed);
  }
  throwIfAborted(signal);
  return hashes;
}

export async function hashChunks(
  blob: Blob,
  chunkSize: number,
  signal?: AbortSignal,
  onProgress?: (hashedBytes: number) => void,
): Promise<Bytes> {
  throwIfAborted(signal);
  if (typeof document !== "undefined" && typeof Worker !== "undefined") {
    try {
      return await hashChunksInWorker(blob, chunkSize, signal, onProgress);
    } catch (error) {
      if (signal?.aborted || (error instanceof Error && error.name === "AbortError")) {
        throw error;
      }
    }
  }
  return hashChunksOnCurrentThread(blob, chunkSize, signal, onProgress);
}

function hashChunksInWorker(
  blob: Blob,
  chunkSize: number,
  signal?: AbortSignal,
  onProgress?: (hashedBytes: number) => void,
): Promise<Bytes> {
  return new Promise((resolve, reject) => {
    let worker: Worker;
    try {
      worker = new Worker(new URL("./chunkHashes.worker.ts", import.meta.url), { type: "module" });
    } catch (error) {
      reject(error);
      return;
    }
    const cleanup = () => {
      signal?.removeEventListener("abort", handleAbort);
      worker.terminate();
    };
    const handleAbort = () => {
      cleanup();
      reject(abortError());
    };
    worker.onmessage = (event: MessageEvent<ChunkHashWorkerMessage>) => {
      const message = event.data;
      if (message.type === "progress") {
        onProgress?.(message.hashedBytes);
        return;
      }
      cleanup();
      if (message.type === "done") {
        resolve(new Uint8Array(message.hashes));
      } else {
        reject(new Error(message.message || "文件分块校验失败"));
      }
    };
    worker.onerror = (event) => {
      cleanup();
      reject(new Error(event.message || "文件校验线程启动失败"));
    };
    signal?.addEventListener("abort", handleAbort, { once: true });
    if (signal?.aborted) {
      handleAbort();
      return;
    }
    worker.postMessage({ blob, chunkSize } satisfies ChunkHashRequest);
  });
}

function throwIfAborted(signal?: AbortSignal) {
  if (signal?.aborted) {
    throw abortError();
  }
}

function abortError() {
  if (typeof DOMException !== "undefined") {
    return new DOMException("文件校验已取消", "AbortError");
  }
  const error = new Error("文件校验已取消");
  error.name = "AbortError";
  return error;
}
