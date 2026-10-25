import { describe, expect, it } from "vitest";
import { formatBytes, formatDuration, formatElapsed, formatRelativeTime, formatSince } from "./format";

describe("formatBytes", () => {
  it("renders zero and units", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1024)).toBe("1.00 KB");
    expect(formatBytes(1024 * 1024)).toBe("1.00 MB");
    expect(formatBytes(1536)).toBe("1.50 KB");
  });

  it("handles nullish input", () => {
    expect(formatBytes(null)).toBe("0 B");
    expect(formatBytes(undefined)).toBe("0 B");
  });
});

describe("formatDuration", () => {
  it("computes a closed interval", () => {
    const from = "2026-01-01T00:00:00Z";
    const to = "2026-01-01T00:01:30Z";
    expect(formatDuration(from, to)).toBe("1m");
  });

  it("prefixes active connections with ~", () => {
    const from = "2026-01-01T00:00:00Z";
    const now = new Date("2026-01-01T00:00:05Z").getTime();
    expect(formatDuration(from, null, now)).toBe("~5s");
  });

  it("returns - for missing start", () => {
    expect(formatDuration(null, null)).toBe("-");
  });
});

describe("formatSince", () => {
  it("uses the supplied browser time", () => {
    const loginAt = new Date("2026-01-01T00:00:00Z").getTime();
    const now = new Date("2026-01-01T00:02:10Z").getTime();
    expect(formatSince(loginAt, now)).toBe("2m");
  });
});

describe("design time formats", () => {
  const now = new Date(2026, 9, 25, 12, 0, 0).getTime();

  it("writes relative times within 24 hours and the full time beyond", () => {
    expect(formatRelativeTime(now - 20_000, now)).toBe("刚刚");
    expect(formatRelativeTime(now + 20_000, now)).toBe("马上");
    expect(formatRelativeTime(now - 3 * 60_000, now)).toBe("3 分钟前");
    expect(formatRelativeTime(now + 40 * 60_000, now)).toBe("40 分钟后");
    expect(formatRelativeTime(now - 5 * 3600_000, now)).toBe("5 小时前");
    expect(formatRelativeTime(new Date(2026, 9, 23, 16, 2), now)).toBe("2026-10-23 16:02");
    expect(formatRelativeTime(null, now)).toBe("");
    expect(formatRelativeTime("not a date", now)).toBe("not a date");
  });

  it("writes durations with units", () => {
    expect(formatElapsed(2)).toBe("2 秒");
    expect(formatElapsed(200)).toBe("3 分 20 秒");
    expect(formatElapsed(180)).toBe("3 分");
    expect(formatElapsed(3900)).toBe("1 小时 5 分");
    expect(formatElapsed(2 * 86400 + 3 * 3600)).toBe("2 天 3 小时");
    expect(formatElapsed(-1)).toBe("");
  });
});
