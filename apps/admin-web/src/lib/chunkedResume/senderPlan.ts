import { ChunkBitmap } from "./bitmap";
import { bytesEqual, type Bytes, type Digest } from "./bytes";
import { chunkHash, chunkLengthOf } from "./manifest";

// Sender side of §7: send what the bitmap lacks, in ascending order, and check every chunk
// against the manifest right before it leaves. A mismatch means the source file changed.

export interface SenderManifest {
  sizeBytes: number;
  chunkSize: number;
  chunkCount: number;
  hashes: Uint8Array;
}

export class SourceChangedError extends Error {
  readonly index: number;

  constructor(index: number) {
    super("源文件已变化，请重新选择文件并作为新传输发送");
    this.name = "SourceChangedError";
    this.index = index;
  }
}

export class SourceSizeMismatchError extends Error {
  constructor() {
    super("重新选择的文件大小与原文件不同，不能续传");
    this.name = "SourceSizeMismatchError";
  }
}

export type ChunkReader = (index: number, start: number, end: number) => Promise<Bytes>;

export function blobChunkReader(source: Blob): ChunkReader {
  return async (_index, start, end) => new Uint8Array(await source.slice(start, end).arrayBuffer());
}

/** Reads chunk `index` and verifies it against the manifest; throws SourceChangedError otherwise. */
export async function readVerifiedChunk(
  manifest: SenderManifest,
  index: number,
  read: ChunkReader,
  digest: Digest,
): Promise<Bytes> {
  const start = index * manifest.chunkSize;
  const length = chunkLengthOf(manifest.sizeBytes, manifest.chunkSize, index);
  const bytes = await read(index, start, start + length);
  if (bytes.byteLength !== length || !bytesEqual(await digest(bytes), chunkHash(manifest.hashes, index))) {
    throw new SourceChangedError(index);
  }
  return bytes;
}

export interface SendPlan {
  result: "SEND_ALL" | "SOURCE_CHANGED" | "SOURCE_SIZE_MISMATCH";
  hashesFirst: boolean;
  send: number[];
  changedIndex?: number;
}

/** The full plan for one session; used by tests and mirrors what the sender loop does chunk by chunk. */
export async function planSend(input: {
  manifest: SenderManifest;
  have: ChunkBitmap;
  needHashes: boolean;
  sourceSizeBytes: number;
  read: ChunkReader;
  digest: Digest;
}): Promise<SendPlan> {
  if (input.sourceSizeBytes !== input.manifest.sizeBytes) {
    return { result: "SOURCE_SIZE_MISMATCH", hashesFirst: false, send: [] };
  }
  const send: number[] = [];
  for (const index of input.have.missing()) {
    try {
      await readVerifiedChunk(input.manifest, index, input.read, input.digest);
    } catch (error) {
      if (error instanceof SourceChangedError) {
        return { result: "SOURCE_CHANGED", hashesFirst: input.needHashes, send, changedIndex: index };
      }
      throw error;
    }
    send.push(index);
  }
  return { result: "SEND_ALL", hashesFirst: input.needHashes, send };
}
