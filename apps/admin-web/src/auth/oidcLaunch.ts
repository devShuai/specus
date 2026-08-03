/**
 * Recognizes the portal's one-click OIDC entry and returns the safe local path
 * that should be restored after authentication. The launch flag is removed so
 * completing the callback cannot start another login loop.
 */
export function oidcLaunchReturnPath(rawUrl: string): string | null {
  const url = new URL(rawUrl);
  if (url.searchParams.get("login") !== "oidc") {
    return null;
  }
  url.searchParams.delete("login");
  return `${url.pathname}${url.search}${url.hash}`;
}
