import { describe, expect, it } from "vitest";
import vectors from "../../../../../protocol/test-vectors/chunked-resume-v1.json";
import * as constants from "./constants";
import { ChunkBitmap, resumeProgress } from "./bitmap";
import { fromHex, sha256, toHex, type Bytes } from "./bytes";
import { decideConsent, type ConsentInput } from "./consent";
import { planCleanup } from "./cleanup";
import { hashChunksOnCurrentThread } from "./chunkHashes";
import { decodeFrame, encodeFrame, FRAME_TYPE_DATA, FRAME_TYPE_HASHES } from "./frames";
import { decideResume } from "./handshake";
import { chunkLengthOf, manifestFromHashes, manifestPreimage, validateOffer } from "./manifest";
import { ChunkReceiver, type ReceiverState, type ReceiverStorage } from "./receiver";
import { planSend } from "./senderPlan";

// Replays every case of protocol/test-vectors/chunked-resume-v1.json through the pure modules.
// File bytes are generated: byte i = (i % 251) ^ (floor(i / 251) & 0xff).

function pattern(start: number, length: number): Bytes {
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 1) {
    const i = start + offset;
    out[offset] = (i % 251) ^ (Math.floor(i / 251) & 0xff);
  }
  return out;
}

function corrupt(bytes: Bytes): Bytes {
  const out = new Uint8Array(bytes);
  out[0] ^= 0xff;
  return out;
}

const instant = (text: string) => Date.parse(text);

type HashingCase = (typeof vectors.hashing)[number];
const manifests = new Map<string, HashingCase>(vectors.hashing.map((item) => [item.name, item]));
function manifestCase(name: string): HashingCase {
  const found = manifests.get(name);
  if (!found) throw new Error(`unknown manifest ${name}`);
  return found;
}
function hashesOf(item: HashingCase): Bytes {
  return fromHex(item.chunkSha256.join(""));
}

describe("chunked resume vectors: constants", () => {
  it("matches every constant of §2", () => {
    const c = vectors.constants;
    expect({
      chunkSizeMin: constants.CHUNK_SIZE_MIN,
      chunkSizeMax: constants.CHUNK_SIZE_MAX,
      chunkSizeDefault: constants.CHUNK_SIZE_DEFAULT,
      maxChunkCount: constants.MAX_CHUNK_COUNT,
      maxResumableBytes: constants.MAX_RESUMABLE_BYTES,
      memoryLimitBytes: constants.MEMORY_LIMIT_BYTES,
      maxStoredPartials: constants.MAX_STORED_PARTIALS,
      maxPartialBytesTotal: constants.MAX_PARTIAL_BYTES_TOTAL,
      storageMarginBytes: constants.STORAGE_MARGIN_BYTES,
      maxActiveReceives: constants.MAX_ACTIVE_RECEIVES,
      maxChunkMismatchesPerSession: constants.MAX_CHUNK_MISMATCHES_PER_SESSION,
      maxIntegrityFailures: constants.MAX_INTEGRITY_FAILURES,
      resumeTtlSeconds: constants.RESUME_TTL_SECONDS,
      frameHeaderBytes: constants.FRAME_HEADER_BYTES,
      frameMaxBytes: constants.FRAME_MAX_BYTES,
    }).toEqual(c);
    expect([1, 2, 3, 4, 5].map(constants.reconnectBackoffMs)).toEqual([1000, 2000, 4000, 8000, 16000]);
  });
});

describe("chunked resume vectors: hashing", () => {
  it.each(vectors.hashing.map((item) => [item.name, item] as const))("%s", async (_name, item) => {
    const file = new Blob([pattern(0, item.sizeBytes)]);
    const hashes = await hashChunksOnCurrentThread(file, item.chunkSize);
    expect(hashes.byteLength / 32).toBe(item.chunkCount);
    const listed = Array.from({ length: item.chunkCount }, (_, index) => toHex(hashes.subarray(index * 32, index * 32 + 32)));
    expect(listed).toEqual(item.chunkSha256);
    const manifest = await manifestFromHashes({
      sizeBytes: item.sizeBytes,
      chunkSize: item.chunkSize,
      fileName: item.fileName,
      mimeType: item.mimeType,
      hashes,
    });
    expect(manifest.chunkCount).toBe(item.chunkCount);
    expect(toHex(manifest.rootSha256)).toBe(item.rootSha256);
    expect(toHex(manifestPreimage({ ...manifest }))).toBe(item.manifestPreimageHex);
    expect(toHex(manifest.manifestDigest)).toBe(item.manifestDigest);
  });
});

describe("chunked resume vectors: offer validation", () => {
  it.each(vectors.offerValidation.map((item) => [item.name, item] as const))("%s", async (_name, item) => {
    const result = await validateOffer(item.offer);
    expect(result.ok ? "OK" : result.code).toBe(item.expect);
  });
});

describe("chunked resume vectors: frames", () => {
  it.each(vectors.frames.map((item) => [item.name, item] as const))("%s", (_name, item) => {
    const header = fromHex(item.frameHex);
    const extra = "appendZeroBytes" in item ? Number(item.appendZeroBytes) : 0;
    const bytes = new Uint8Array(header.byteLength + extra);
    bytes.set(header);
    const decoded = decodeFrame(bytes.buffer);
    if ("error" in item.expect) {
      expect(decoded).toEqual({ ok: false, error: item.expect.error });
      return;
    }
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    const { type, transferId, index, offset, payload } = decoded.frame;
    expect({ type, transferId, index, offset, payloadHex: toHex(payload) }).toEqual(item.expect);
    const reencoded = encodeFrame(type === "HASHES" ? FRAME_TYPE_HASHES : FRAME_TYPE_DATA, transferId, index, offset, payload);
    expect(toHex(new Uint8Array(reencoded))).toBe(item.frameHex);
  });
});

describe("chunked resume vectors: bitmap", () => {
  it.each(vectors.bitmap.encode.map((item) => [item.bitmap, item] as const))("encode %j", (_text, item) => {
    expect(ChunkBitmap.fromIndexes(item.chunkCount, item.have).encode()).toBe(item.bitmap);
  });

  it.each(vectors.bitmap.decode.map((item) => [`${item.chunkCount}:${item.bitmap}`, item] as const))("decode %s", (_key, item) => {
    const decoded = ChunkBitmap.decode(item.chunkCount, item.bitmap);
    if ("error" in item.expect) {
      expect(decoded).toBe(item.expect.error);
    } else {
      expect(decoded).toBeInstanceOf(ChunkBitmap);
      expect((decoded as ChunkBitmap).indexes()).toEqual(item.expect.have);
    }
  });

  it.each(vectors.bitmap.progress.map((item) => [item.bitmap, item] as const))("progress %j", (_text, item) => {
    const manifest = manifestCase(item.manifest);
    const have = ChunkBitmap.decode(manifest.chunkCount, item.bitmap) as ChunkBitmap;
    expect(resumeProgress(manifest, have)).toEqual(item.expect);
  });

  it.each(vectors.bitmap.merge.map((item) => [`${item.left}|${item.right}`, item] as const))("merge %s", (_key, item) => {
    const left = ChunkBitmap.decode(item.chunkCount, item.left) as ChunkBitmap;
    const right = ChunkBitmap.decode(item.chunkCount, item.right) as ChunkBitmap;
    expect(left.union(right).encode()).toBe(item.expect);
  });

  it("encodes a full 4096-chunk bitmap in 512 bytes", () => {
    const full = ChunkBitmap.fromIndexes(4096, Array.from({ length: 4096 }, (_, index) => index));
    expect(full.bytes.byteLength).toBe(512);
    expect((ChunkBitmap.decode(4096, full.encode()) as ChunkBitmap).isComplete()).toBe(true);
  });
});

class MemoryReceiverStorage implements ReceiverStorage {
  chunks = new Map<number, Bytes>();
  hashes: Bytes | null = null;
  progress: { have: string; integrityFailures: number; state: ReceiverState } | null = null;

  async storeChunk(index: number, bytes: Bytes, have: ChunkBitmap) {
    this.chunks.set(index, bytes);
    this.progress = { ...(this.progress ?? { integrityFailures: 0, state: "RECEIVING" }), have: have.encode() };
  }

  async readChunk(index: number) {
    return this.chunks.get(index) ?? null;
  }

  async storeHashes(hashes: Bytes) {
    this.hashes = hashes;
  }

  async storeProgress(update: { have: ChunkBitmap; integrityFailures: number; state: ReceiverState }) {
    this.progress = { have: update.have.encode(), integrityFailures: update.integrityFailures, state: update.state };
  }

  async discardChunks() {
    this.chunks.clear();
  }
}

describe("chunked resume vectors: receiver state machine", () => {
  it.each(vectors.receiver.map((item) => [item.name, item] as const))("%s", async (_name, item) => {
    const manifest = manifestCase(item.manifest);
    const hashes = hashesOf(manifest);
    const initialHave = ChunkBitmap.decode(manifest.chunkCount, item.initial.have) as ChunkBitmap;
    const storage = new MemoryReceiverStorage();
    for (const index of initialHave.indexes()) {
      const start = index * manifest.chunkSize;
      storage.chunks.set(index, pattern(start, chunkLengthOf(manifest.sizeBytes, manifest.chunkSize, index)));
    }
    const receiver = new ChunkReceiver(
      {
        transferId: item.transferId,
        sizeBytes: manifest.sizeBytes,
        chunkSize: manifest.chunkSize,
        chunkCount: manifest.chunkCount,
        rootSha256: fromHex(manifest.rootSha256),
      },
      {
        have: initialHave,
        hashes: item.initial.hashesComplete ? hashes : null,
        integrityFailures: item.initial.integrityFailures,
      },
      storage,
      sha256,
    );
    for (const step of item.steps) {
      const event = step.event as {
        type: string; index?: number; count?: number; offset?: number; length?: number;
        content?: string; transferId?: string; corruptStored?: number[];
      };
      let produced;
      if (event.type === "session-open") {
        produced = await receiver.openSession();
      } else if (event.type === "session-close") {
        produced = await receiver.closeSession();
      } else if (event.type === "hashes") {
        const index = event.index ?? 0;
        const count = event.count ?? 0;
        // Exactly `count` digests; positions past the list are zero so OUT_OF_RANGE stays observable.
        let payload: Bytes = new Uint8Array(count * 32);
        payload.set(hashes.subarray(index * 32, Math.min(hashes.byteLength, (index + count) * 32)));
        if (event.content === "corrupt") payload = corrupt(payload);
        produced = await receiver.handleFrame({ type: "HASHES", transferId: item.transferId, index, offset: 0, payload });
      } else if (event.type === "data") {
        const index = event.index ?? 0;
        const offset = event.offset ?? 0;
        let payload = pattern(index * manifest.chunkSize + offset, event.length ?? 0);
        if (event.content === "corrupt") payload = corrupt(payload);
        produced = await receiver.handleFrame({
          type: "DATA",
          transferId: event.transferId ?? item.transferId,
          index,
          offset,
          payload,
        });
      } else if (event.type === "final-verify") {
        for (const index of event.corruptStored ?? []) {
          const stored = storage.chunks.get(index);
          if (stored) storage.chunks.set(index, corrupt(stored));
        }
        produced = await receiver.finalVerify();
      } else {
        throw new Error(`unknown event ${event.type}`);
      }
      expect(produced, JSON.stringify(event)).toEqual(step.expect);
    }
    expect({
      have: receiver.bitmap.encode(),
      integrityFailures: receiver.integrityFailures,
      state: receiver.state,
      sessionOpen: receiver.sessionOpen,
    }).toEqual(item.final);
    // Every set bit has its chunk (the atomicity invariant of §10).
    for (const index of receiver.bitmap.indexes()) {
      expect(storage.chunks.has(index)).toBe(true);
    }
  });
});

describe("chunked resume vectors: consent", () => {
  it.each(vectors.consent.map((item) => [item.name, item] as const))("%s", (_name, item) => {
    expect(decideConsent(item as ConsentInput)).toEqual(item.expect);
  });
});

describe("chunked resume vectors: resume handshake", () => {
  it.each(vectors.resume.map((item) => [item.name, item] as const))("%s", (_name, item) => {
    const manifest = manifestCase(item.manifest);
    const record = item.record ? {
      transferId: item.record.transferId,
      resumeToken: item.record.resumeToken,
      manifestDigest: item.record.manifestDigest,
      expiresAt: instant(item.record.expiresAt),
      state: item.record.state,
      have: ChunkBitmap.decode(manifest.chunkCount, item.record.have) as ChunkBitmap,
      hashesComplete: item.record.hashesComplete,
      sizeBytes: manifest.sizeBytes,
      chunkSize: manifest.chunkSize,
      chunkCount: manifest.chunkCount,
    } : null;
    expect(decideResume({
      record,
      offer: item.offer,
      now: instant(item.now),
      senderAllowed: item.senderAllowed,
      otherActiveSessions: item.otherActiveSessions,
    })).toEqual(item.expect);
  });
});

describe("chunked resume vectors: cleanup", () => {
  it.each(vectors.cleanup.map((item) => [item.name, item] as const))("%s", (_name, item) => {
    expect(planCleanup({
      now: instant(item.now),
      records: item.records.map((record) => ({ ...record, expiresAt: instant(record.expiresAt) })),
      chunkTransferIds: item.chunkTransferIds,
    })).toEqual(item.expect);
  });
});

describe("chunked resume vectors: sender plan", () => {
  it.each(vectors.senderPlan.map((item) => [item.name, item] as const))("%s", async (_name, item) => {
    const manifest = manifestCase(item.manifest);
    const plan = await planSend({
      manifest: { ...manifest, hashes: hashesOf(manifest) },
      have: ChunkBitmap.decode(manifest.chunkCount, item.have) as ChunkBitmap,
      needHashes: item.needHashes,
      sourceSizeBytes: item.reselectedSizeBytes,
      read: async (index, start, end) => {
        const bytes = pattern(start, end - start);
        return item.modifiedChunks.includes(index) ? corrupt(bytes) : bytes;
      },
      digest: sha256,
    });
    expect(plan).toEqual(item.expect);
  });
});
