import { describe, expect, it } from "vitest";
import type { PeerMeshSharedService, PeerMeshSharedServiceInstance } from "../../api/types";
import {
  groupPeerMeshServices,
  PeerMeshOperationLocks,
  peerServiceAvailability,
  peerServiceSharingControl,
} from "./peerMeshServicesModel";

function instance(
  publisherSessionId: number,
  overrides: Partial<PeerMeshSharedServiceInstance> = {},
): PeerMeshSharedServiceInstance {
  return {
    publisherSessionId,
    instanceId: `instance-${publisherSessionId}`,
    online: true,
    advertised: true,
    revision: 1,
    expiresAt: "2026-08-20T12:10:00Z",
    ...overrides,
  };
}

function service(
  id: number,
  clientId: number,
  clientName: string,
  instances: PeerMeshSharedServiceInstance[],
): PeerMeshSharedService {
  return {
    id,
    serviceId: `svc-${id}`,
    clientId,
    clientName,
    name: `service-${id}`,
    description: "",
    transport: "tcp",
    application: "http",
    targetHost: "127.0.0.1",
    targetPort: 8080,
    publishedPort: 18080,
    path: "/",
    enabled: true,
    visibility: "OWNER",
    publishedAddress: `http://100.96.0.${clientId}:18080/`,
    instances,
    createdAt: "2026-08-20T12:00:00Z",
    updatedAt: "2026-08-20T12:00:00Z",
  };
}

describe("peer service admin presentation", () => {
  it("keeps the global control unknown and disabled after an initial load failure", () => {
    const control = peerServiceSharingControl({
      deploymentEnabled: true,
      isAdmin: true,
      loading: false,
      loadError: "gateway timeout",
      updating: false,
      sharing: null,
    });

    expect(control).toEqual({
      disabled: true,
      selected: false,
      label: "状态未知 · 重新加载后才能操作",
    });
  });

  it("groups by authenticated publisher id and session instead of client name", () => {
    const groups = groupPeerMeshServices([
      service(1, 10, "same-name", [instance(101), instance(102)]),
      service(2, 11, "same-name", [instance(201)]),
    ], true, Date.parse("2026-08-20T12:00:00Z"));

    expect(groups.map((group) => group.key)).toEqual(["10:101", "10:102", "11:201"]);
    expect(groups[0].rows[0].service).toMatchObject({ serviceId: "svc-1", name: "service-1" });
  });

  it.each([
    [false, instance(1), "全局服务共享已关闭"],
    [true, instance(1, { online: false }), "发布实例已离线"],
    [true, instance(1, { expiresAt: "2026-08-20T11:59:59Z" }), "服务目录已过期"],
    [true, instance(1, { advertised: false }), "发布实例尚未上报此服务"],
  ])("disables stale actions with an explicit reason", (sharing, current, reason) => {
    expect(peerServiceAvailability(
      service(1, 10, "client", [current]),
      current,
      sharing,
      Date.parse("2026-08-20T12:00:00Z"),
    )).toMatchObject({ available: false, reason });
  });

  it("allows only one mutation for a rapid repeated row operation while keeping other rows independent", () => {
    const locks = new PeerMeshOperationLocks();
    expect(locks.acquire("service:1")).toBe(true);
    expect(locks.acquire("service:1")).toBe(false);
    expect(locks.acquire("service:2")).toBe(true);
    locks.release("service:1");
    expect(locks.acquire("service:1")).toBe(true);
  });
});
