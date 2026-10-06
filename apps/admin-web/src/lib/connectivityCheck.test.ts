import { describe, expect, it } from "vitest";
import { formatCheckTime, parseRetryAfter, validCheckPath } from "./connectivityCheck";

describe("connectivity check helpers", () => {
  it("accepts the paths the server accepts", () => {
    for (const path of ["/", "/healthz", "/a//b", "/v1/%E4%B8%AD", "/a.b/..c/~x", "/a:b@c!$&'()*+,;="]) {
      expect(validCheckPath(path), path).toBe(true);
    }
    expect(validCheckPath(`/${"a".repeat(255)}`)).toBe(true);
  });

  it("refuses the paths the server refuses", () => {
    for (const path of ["", "healthz", "//evil.example/", "/a?b", "/a#b", "/a\\b", "/a b", "/.", "/a/../b",
      "/%2e%2E/x", "/a/%2e", "/%zz", "/%4", `/${"a".repeat(256)}`, "/ä"]) {
      expect(validCheckPath(path), path).toBe(false);
    }
  });

  it("reads Retry-After as whole seconds", () => {
    expect(parseRetryAfter("10")).toBe(10);
    expect(parseRetryAfter(" 1 ")).toBe(1);
    expect(parseRetryAfter("1.2")).toBe(2);
    for (const value of [null, "", "0", "-3", "Wed, 21 Oct 2015 07:28:00 GMT"]) {
      expect(parseRetryAfter(value)).toBeNull();
    }
  });

  it("labels the check time as hh:mm:ss", () => {
    expect(formatCheckTime("2026-10-06T08:00:00Z")).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    expect(formatCheckTime("not a time")).toBe("not a time");
  });
});
