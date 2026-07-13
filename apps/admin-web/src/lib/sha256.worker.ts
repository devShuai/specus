import { sha256BlobOnCurrentThread } from "./sha256";

self.onmessage = (event: MessageEvent<Blob>) => {
  void sha256BlobOnCurrentThread(event.data)
    .then((digest) => self.postMessage({ digest }))
    .catch((error) => self.postMessage({
      error: error instanceof Error ? error.message : "文件校验失败",
    }));
};
