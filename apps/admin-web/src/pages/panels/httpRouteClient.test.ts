import { describe, expect, it } from "vitest";
import { findHttpRouteClient } from "./httpRouteClient";

const clients = [
  { id: 7, clientName: "alpha", online: true },
  { id: 8, clientName: "beta", online: false },
];

describe("findHttpRouteClient", () => {
  it("matches numeric and string identifiers", () => {
    expect(findHttpRouteClient({ clientId: 7, clientName: "stale" }, clients)?.clientName).toBe("alpha");
    expect(findHttpRouteClient({ clientId: "8", clientName: "stale" }, clients)?.clientName).toBe("beta");
  });

  it("falls back to clientName when the route identifier is absent or unmatched", () => {
    expect(findHttpRouteClient({ clientName: "alpha" }, clients)?.id).toBe(7);
    expect(findHttpRouteClient({ clientId: 999, clientName: "beta" }, clients)?.id).toBe(8);
  });

  it("returns undefined for an orphaned route", () => {
    expect(findHttpRouteClient({ clientId: 999, clientName: "missing" }, clients)).toBeUndefined();
  });
});
