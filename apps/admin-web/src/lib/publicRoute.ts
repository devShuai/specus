export type PublicRoute = "nat-detect" | "transfer" | "diagram-embed" | "diagram" | "download";

export interface PublicRouteLocation {
  hash: string;
  pathname: string;
  search: string;
}

const PUBLIC_ROUTES: readonly PublicRoute[] = [
  "nat-detect",
  "transfer",
  "diagram-embed",
  "diagram",
  "download",
];

function readFirstSegment(value: string, prefix: RegExp) {
  return value.replace(prefix, "").split(/[/?#]/, 1)[0];
}

/**
 * Resolve the public page encoded in a location without reading browser globals.
 *
 * Route priority intentionally matches the original App implementation: the
 * known route names are checked in order across hash, pathname and `panel`.
 */
export function readPublicRoute(location: PublicRouteLocation): PublicRoute | null {
  const hash = readFirstSegment(location.hash, /^#\/?/);
  const path = readFirstSegment(location.pathname, /^\/+/);
  const queryPanel = new URLSearchParams(location.search).get("panel");

  return (
    PUBLIC_ROUTES.find((route) => hash === route || path === route || queryPanel === route) ?? null
  );
}
