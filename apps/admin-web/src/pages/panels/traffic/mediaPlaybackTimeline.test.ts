import { describe, expect, it } from "vitest";
import {
  buildIndexedMediaTimeWindows,
  estimateMediaTimeWindow,
  estimateMediaTimeWindows,
  snapMediaTimeToWindow,
  windowStart,
} from "./mediaPlaybackTimeline";

describe("estimateMediaTimeWindow", () => {
  it("maps the selected byte block onto the media timeline", () => {
    expect(estimateMediaTimeWindow({
      capturedBytes: 25,
      durationSeconds: 400,
      rangeEnd: 49,
      rangeStart: 25,
      totalBytes: 100,
    })).toEqual({
      startSeconds: 100,
      endSeconds: 200,
      startPercent: 25,
      endPercent: 50,
    });
  });

  it("infers the block end from the captured byte count", () => {
    expect(estimateMediaTimeWindow({
      capturedBytes: 20,
      durationSeconds: 200,
      rangeEnd: null,
      rangeStart: 40,
      totalBytes: 100,
    })).toEqual({
      startSeconds: 80,
      endSeconds: 120,
      startPercent: 40,
      endPercent: 60,
    });
  });

  it("clamps an overlong block to the media boundary", () => {
    expect(estimateMediaTimeWindow({
      capturedBytes: 50,
      durationSeconds: 100,
      rangeEnd: 120,
      rangeStart: 90,
      totalBytes: 100,
    })).toEqual({
      startSeconds: 90,
      endSeconds: 100,
      startPercent: 90,
      endPercent: 100,
    });
  });

  it("returns null when duration or total length is unavailable", () => {
    expect(estimateMediaTimeWindow({
      capturedBytes: 20,
      durationSeconds: 0,
      rangeEnd: 19,
      rangeStart: 0,
      totalBytes: 100,
    })).toBeNull();
    expect(estimateMediaTimeWindow({
      capturedBytes: 20,
      durationSeconds: 60,
      rangeEnd: 19,
      rangeStart: 0,
      totalBytes: null,
    })).toBeNull();
  });

  it("maps and orders every cached byte block", () => {
    expect(estimateMediaTimeWindows([
      { start: 80, end: 99 },
      { start: 0, end: 19 },
      { start: 40, end: 59 },
    ], 100, 200)).toEqual([
      {
        startSeconds: 0,
        endSeconds: 40,
        startPercent: 0,
        endPercent: 20,
      },
      {
        startSeconds: 80,
        endSeconds: 120,
        startPercent: 40,
        endPercent: 60,
      },
      {
        startSeconds: 160,
        endSeconds: 200,
        startPercent: 80,
        endPercent: 100,
      },
    ]);
  });

  it("snaps seeks in uncached gaps to the next or previous block", () => {
    const windows = estimateMediaTimeWindows([
      { start: 0, end: 19 },
      { start: 40, end: 59 },
    ], 100, 200);

    expect(snapMediaTimeToWindow(60, windows, 1)).toBeCloseTo(80.08);
    expect(snapMediaTimeToWindow(60, windows, -1)).toBeCloseTo(39.92);
    expect(snapMediaTimeToWindow(90, windows, 0)).toBe(90);
  });
});

describe("buildIndexedMediaTimeWindows", () => {
  it("uses MP4 keyframes and real seek offsets instead of byte ratios", () => {
    const windows = buildIndexedMediaTimeWindows([
      sample(0, 100, 0, true),
      sample(1, 400, 1, false),
      sample(2, 1_100, 2, true),
      sample(3, 1_400, 3, false),
      sample(4, 2_100, 10, true),
      sample(5, 2_400, 11, false),
    ], [
      { start: 0, end: 999 },
      { start: 2_000, end: 2_999 },
    ], 20, (time) => ({
      offset: time >= 10 ? 2_020 : 80,
      time,
    }), true);

    expect(windows).toEqual([
      {
        byteEnd: 999,
        byteStart: 0,
        endPercent: 10,
        endSeconds: 2,
        exact: true,
        seekOffset: 80,
        startPercent: 0,
        startSeconds: 0,
      },
      {
        byteEnd: 2_999,
        byteStart: 2_000,
        endPercent: 60,
        endSeconds: 12,
        exact: true,
        seekOffset: 2_020,
        startPercent: 50,
        startSeconds: 10,
      },
    ]);
    expect(windowStart(windows[1])).toBe(10);
  });

  it("omits a cached block when its nearest decodable seek starts in a hole", () => {
    const windows = buildIndexedMediaTimeWindows([
      sample(0, 2_100, 10, true),
      sample(1, 2_400, 11, false),
    ], [
      { start: 2_000, end: 2_999 },
    ], 20, () => ({
      offset: 1_900,
      time: 10,
    }), true);

    expect(windows).toEqual([]);
  });
});

function sample(
  number: number,
  offset: number,
  ctsSeconds: number,
  isSync: boolean,
) {
  return {
    cts: ctsSeconds * 1_000,
    duration: 1_000,
    isSync,
    number,
    offset,
    size: 100,
    timescale: 1_000,
  };
}
