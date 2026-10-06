import { hashChunksOnCurrentThread, type ChunkHashRequest, type ChunkHashWorkerMessage } from "./chunkHashes";

const PROGRESS_INTERVAL_BYTES = 16 * 1024 * 1024;

self.onmessage = (event: MessageEvent<ChunkHashRequest>) => {
  const { blob, chunkSize } = event.data;
  let reported = 0;
  void hashChunksOnCurrentThread(blob, chunkSize, undefined, (hashedBytes) => {
    if (hashedBytes - reported >= PROGRESS_INTERVAL_BYTES || hashedBytes === blob.size) {
      reported = hashedBytes;
      self.postMessage({ type: "progress", hashedBytes } satisfies ChunkHashWorkerMessage);
    }
  })
    .then((hashes) => self.postMessage({ type: "done", hashes: hashes.buffer } satisfies ChunkHashWorkerMessage, {
      transfer: [hashes.buffer],
    }))
    .catch((error) => self.postMessage({
      type: "error",
      message: error instanceof Error ? error.message : "文件分块校验失败",
    } satisfies ChunkHashWorkerMessage));
};
