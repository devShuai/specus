import { describe, expect, it } from "vitest";
import type { PeerMeshSharedService } from "../api/types";
import { ApiError } from "../api/client";
import { collectServices, httpRouteAccessUrl, isWorkbenchUnsupported, peerOpenUrl, safePeerPath } from "./workbenchModel";

function peer(application: string, path: string, publishedAddress: string | null = "100.96.0.2:8080"): PeerMeshSharedService {
  return { id: 1, application, path, publishedAddress } as PeerMeshSharedService;
}

describe("workbench model", () => {
  it("builds the HTTP access link like the routes panel", () => {
    expect(httpRouteAccessUrl({ clientName: "office pc", route: "wiki" }, "https://specus.example"))
      .toBe("https://specus.example/http/office%20pc/wiki/");
  });

  it("opens Peer HTTP(S) services only at the authoritative address and a safe path", () => {
    expect(peerOpenUrl(peer("http", ""))).toBe("http://100.96.0.2:8080/");
    expect(peerOpenUrl(peer("https", "/admin/"))).toBe("https://100.96.0.2:8080/admin/");
    expect(peerOpenUrl(peer("ssh", "/"))).toBeNull();
    expect(peerOpenUrl(peer("http", "/", null))).toBeNull();
    expect(peerOpenUrl(peer("http", "/", "evil.example:80"))).toBeNull();
    for (const path of ["admin", "//evil.example/", "/a/../b", "/a\\b", "/a b", "http://evil.example/"]) {
      expect(safePeerPath(path), path).toBeNull();
      expect(peerOpenUrl(peer("http", path)), path).toBeNull();
    }
  });

  it("treats only 404/405 as an older server", () => {
    expect(isWorkbenchUnsupported(new ApiError("x", 404))).toBe(true);
    expect(isWorkbenchUnsupported(new ApiError("x", 405))).toBe(true);
    expect(isWorkbenchUnsupported(new ApiError("x", 503))).toBe(false);
    expect(isWorkbenchUnsupported(new TypeError("Failed to fetch"))).toBe(false);
  });

  it("merges the three lists in kind order, then id", () => {
    const merged = collectServices({
      peerServices: [{ id: 1, clientId: 1, enabled: true } as PeerMeshSharedService],
      httpRoutes: [{ id: 9, clientId: 1, enabled: true }, { id: 3, clientId: 1, enabled: false }] as never,
      tcpMappings: [{ id: 2, clientId: 1, enabled: true }] as never,
    });
    expect(merged.map((service) => `${service.kind}:${service.id}`))
      .toEqual(["http-route:3", "http-route:9", "tcp-mapping:2", "peer-service:1"]);
  });
});
