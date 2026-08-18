import { describe, expect, it } from "vitest";
import { readPublicRoute, type PublicRouteLocation } from "./publicRoute";

function location(overrides: Partial<PublicRouteLocation> = {}): PublicRouteLocation {
  return {
    hash: "",
    pathname: "/",
    search: "",
    ...overrides,
  };
}

describe("readPublicRoute", () => {
  it.each([
    ["/download", "", ""],
    ["/download/", "", ""],
    ["/", "#/download", ""],
    ["/index.html", "#/download", ""],
    ["/", "", "?panel=download"],
  ])("recognizes the download page from path=%s hash=%s search=%s", (pathname, hash, search) => {
    expect(readPublicRoute(location({ pathname, hash, search }))).toBe("download");
  });

  it.each(["nat-detect", "transfer", "diagram-embed", "diagram"] as const)(
    "keeps the existing %s public route",
    (route) => {
      expect(readPublicRoute(location({ pathname: `/${route}` }))).toBe(route);
      expect(readPublicRoute(location({ pathname: "/index.html", hash: `#/${route}` }))).toBe(route);
      expect(readPublicRoute(location({ search: `?panel=${route}` }))).toBe(route);
    },
  );

  it.each([
    { pathname: "/downloads" },
    { hash: "#/downloads" },
    { pathname: "/index.html", hash: "#/downloads" },
    { search: "?panel=downloads" },
  ])("does not treat the plural downloads route as download: %o", (overrides) => {
    expect(readPublicRoute(location(overrides))).toBeNull();
  });

  it("keeps the original route-name priority when location sources conflict", () => {
    expect(
      readPublicRoute(
        location({
          pathname: "/download",
          hash: "#/transfer",
          search: "?panel=diagram",
        }),
      ),
    ).toBe("transfer");

    expect(
      readPublicRoute(
        location({
          pathname: "/nat-detect",
          hash: "#/download",
          search: "?panel=downloads",
        }),
      ),
    ).toBe("nat-detect");
  });

  it("ignores unrecognized and empty locations", () => {
    expect(readPublicRoute(location())).toBeNull();
    expect(readPublicRoute(location({ pathname: "/console", hash: "#/downloads" }))).toBeNull();
  });
});
