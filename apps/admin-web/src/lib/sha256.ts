const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const SHA256_INITIAL = new Uint32Array([
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
]);

const MAIN_THREAD_YIELD_BYTES = 2 * 1024 * 1024;

export async function sha256Blob(blob: Blob, signal?: AbortSignal): Promise<string> {
  throwIfAborted(signal);
  if (typeof document !== "undefined" && typeof Worker !== "undefined") {
    try {
      return await sha256BlobInWorker(blob, signal);
    } catch (error) {
      if (signal?.aborted || isAbortError(error)) {
        throw error;
      }
      // CSP or older embedded browsers can reject module workers. Keep a cooperative
      // main-thread fallback so file transfer still works without freezing the page.
    }
  }
  return sha256BlobOnCurrentThread(blob, signal);
}

export async function sha256BlobOnCurrentThread(blob: Blob, signal?: AbortSignal): Promise<string> {
  const hasher = new Sha256();
  let bytesSinceYield = 0;
  const shouldYield = typeof document !== "undefined";
  if (typeof blob.stream === "function") {
    const reader = blob.stream().getReader();
    try {
      while (true) {
        throwIfAborted(signal);
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (value) {
          hasher.update(value);
          bytesSinceYield += value.byteLength;
        }
        if (shouldYield && bytesSinceYield >= MAIN_THREAD_YIELD_BYTES) {
          bytesSinceYield = 0;
          await yieldToMainThread();
        }
      }
    } finally {
      if (signal?.aborted) {
        await reader.cancel().catch(() => undefined);
      }
    }
  } else {
    throwIfAborted(signal);
    hasher.update(new Uint8Array(await blob.arrayBuffer()));
  }
  throwIfAborted(signal);
  return hasher.digestHex();
}

function sha256BlobInWorker(blob: Blob, signal?: AbortSignal): Promise<string> {
  return new Promise((resolve, reject) => {
    let worker: Worker;
    try {
      worker = new Worker(new URL("./sha256.worker.ts", import.meta.url), { type: "module" });
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
      reject(createAbortError());
    };
    worker.onmessage = (event: MessageEvent<{ digest?: string; error?: string }>) => {
      cleanup();
      if (event.data.digest) {
        resolve(event.data.digest);
      } else {
        reject(new Error(event.data.error || "文件校验失败"));
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
    worker.postMessage(blob);
  });
}

function throwIfAborted(signal?: AbortSignal) {
  if (signal?.aborted) {
    throw createAbortError();
  }
}

function createAbortError() {
  if (typeof DOMException !== "undefined") {
    return new DOMException("文件校验已取消", "AbortError");
  }
  const error = new Error("文件校验已取消");
  error.name = "AbortError";
  return error;
}

function isAbortError(error: unknown) {
  return error instanceof Error && error.name === "AbortError";
}

function yieldToMainThread() {
  return new Promise<void>((resolve) => setTimeout(resolve, 0));
}

class Sha256 {
  private readonly state = new Uint32Array(SHA256_INITIAL);
  private readonly buffer = new Uint8Array(64);
  private readonly work = new Uint32Array(64);
  private bufferLength = 0;
  private bytesHashed = 0;
  private finished = false;

  update(data: Uint8Array) {
    if (this.finished) {
      throw new Error("sha256 digest already finalized");
    }
    let position = 0;
    this.bytesHashed += data.length;

    if (this.bufferLength > 0) {
      const needed = 64 - this.bufferLength;
      const copied = Math.min(needed, data.length);
      this.buffer.set(data.subarray(0, copied), this.bufferLength);
      this.bufferLength += copied;
      position += copied;
      if (this.bufferLength === 64) {
        this.processBlock(this.buffer, 0);
        this.bufferLength = 0;
      }
    }

    while (position + 64 <= data.length) {
      this.processBlock(data, position);
      position += 64;
    }

    if (position < data.length) {
      this.buffer.set(data.subarray(position), 0);
      this.bufferLength = data.length - position;
    }
  }

  digestHex() {
    if (this.finished) {
      throw new Error("sha256 digest already finalized");
    }
    this.finished = true;
    const bitLength = this.bytesHashed * 8;
    const paddingLength = this.bufferLength < 56 ? 64 : 128;
    const padding = new Uint8Array(paddingLength);
    padding.set(this.buffer.subarray(0, this.bufferLength));
    padding[this.bufferLength] = 0x80;
    const view = new DataView(padding.buffer);
    view.setUint32(paddingLength - 8, Math.floor(bitLength / 0x100000000));
    view.setUint32(paddingLength - 4, bitLength >>> 0);
    for (let offset = 0; offset < padding.length; offset += 64) {
      this.processBlock(padding, offset);
    }
    return Array.from(this.state, (word) => word.toString(16).padStart(8, "0")).join("");
  }

  private processBlock(chunk: Uint8Array, offset: number) {
    for (let i = 0; i < 16; i += 1) {
      const index = offset + i * 4;
      this.work[i] = (
        (chunk[index] << 24)
        | (chunk[index + 1] << 16)
        | (chunk[index + 2] << 8)
        | chunk[index + 3]
      ) >>> 0;
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotateRight(this.work[i - 15], 7) ^ rotateRight(this.work[i - 15], 18) ^ (this.work[i - 15] >>> 3);
      const s1 = rotateRight(this.work[i - 2], 17) ^ rotateRight(this.work[i - 2], 19) ^ (this.work[i - 2] >>> 10);
      this.work[i] = (this.work[i - 16] + s0 + this.work[i - 7] + s1) >>> 0;
    }

    let a = this.state[0];
    let b = this.state[1];
    let c = this.state[2];
    let d = this.state[3];
    let e = this.state[4];
    let f = this.state[5];
    let g = this.state[6];
    let h = this.state[7];

    for (let i = 0; i < 64; i += 1) {
      const s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + SHA256_K[i] + this.work[i]) >>> 0;
      const s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    this.state[0] = (this.state[0] + a) >>> 0;
    this.state[1] = (this.state[1] + b) >>> 0;
    this.state[2] = (this.state[2] + c) >>> 0;
    this.state[3] = (this.state[3] + d) >>> 0;
    this.state[4] = (this.state[4] + e) >>> 0;
    this.state[5] = (this.state[5] + f) >>> 0;
    this.state[6] = (this.state[6] + g) >>> 0;
    this.state[7] = (this.state[7] + h) >>> 0;
  }
}

function rotateRight(value: number, bits: number) {
  return (value >>> bits) | (value << (32 - bits));
}
