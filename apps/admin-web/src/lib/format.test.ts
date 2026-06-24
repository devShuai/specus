import { describe, expect, it } from "vitest";
import { formatBytes, formatDuration, formatSince } from "./format";

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
