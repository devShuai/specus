import { describe, expect, it } from "vitest";
import {
  buildStandaloneMp4Index,
  findMp4MoovBox,
  locateCachedMoovBox,
  normalizeMp4IndexRanges,
  type Mp4IndexChunk,
} from "./mp4PlaybackIndex";

describe("normalizeMp4IndexRanges", () => {
  it("merges overlapping and adjacent cached ranges", () => {
    expect(normalizeMp4IndexRanges([
      { start: 20, end: 29 },
      { start: 0, end: 9 },
      { start: 8, end: 19 },
      { start: 50, end: 59 },
    ])).toEqual([
      { start: 0, end: 29 },
      { start: 50, end: 59 },
    ]);
  });
});

describe("findMp4MoovBox", () => {
  it("finds a regular moov box at its absolute file offset", () => {
    const data = new ArrayBuffer(40);
    const bytes = new Uint8Array(data);
    const view = new DataView(data);
    view.setUint32(8, 20, false);
    bytes.set([0x6d, 0x6f, 0x6f, 0x76], 12);

    expect(findMp4MoovBox(data, 100)).toEqual({
      headerBytes: 8,
      size: 20,
      start: 108,
    });
  });

  it("supports extended-size moov boxes", () => {
    const data = new ArrayBuffer(48);
    const bytes = new Uint8Array(data);
    const view = new DataView(data);
    view.setUint32(4, 1, false);
    bytes.set([0x6d, 0x6f, 0x6f, 0x76], 8);
    view.setUint32(12, 0, false);
    view.setUint32(16, 32, false);

    expect(findMp4MoovBox(data, 200)).toEqual({
      headerBytes: 16,
      size: 32,
      start: 204,
    });
  });
});

describe("buildStandaloneMp4Index", () => {
  it("prepends a valid ftyp box before the cached moov box", () => {
    const moov = new Uint8Array([
      0x00, 0x00, 0x00, 0x08,
      0x6d, 0x6f, 0x6f, 0x76,
    ]).buffer;
    const index = new Uint8Array(buildStandaloneMp4Index(moov));

    expect(String.fromCharCode(...index.slice(4, 8))).toBe("ftyp");
    expect(String.fromCharCode(...index.slice(28, 32))).toBe("moov");
  });
});

describe("locateCachedMoovBox", () => {
  it("skips an unavailable cached range and loads moov from another block", async () => {
    const storage = new Uint8Array(256);
    const view = new DataView(storage.buffer);
    view.setUint32(104, 24, false);
    storage.set([0x6d, 0x6f, 0x6f, 0x76], 108);
    storage.fill(0x2a, 112, 128);
    const requests: Array<[number, number]> = [];
    const read = async (start: number, end: number): Promise<Mp4IndexChunk | null> => {
      requests.push([start, end]);
      if (start >= 200) {
        return null;
      }
      const data = storage.slice(start, end + 1).buffer;
      return { data, end, start };
    };

    const moov = await locateCachedMoovBox([
      { start: 0, end: 31 },
      { start: 96, end: 143 },
      { start: 200, end: 231 },
    ], read);

    expect(requests[0]).toEqual([200, 231]);
    expect(new Uint8Array(moov ?? new ArrayBuffer(0))).toEqual(
      storage.slice(104, 128),
    );
  });
});
