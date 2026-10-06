import { useEffect, useRef, useState } from "react";
import { AppLogo } from "../components/AppLogo";
import { captureShareToken, exchangeShareToken, forgetShareToken } from "../lib/httpShare";

type LandingState = { phase: "opening" } | { phase: "failed"; message: string; code: string };

const FAILURE_HINTS: Record<string, string> = {
  SHARE_EXPIRED: "这个分享的有效期已经结束。如仍需访问，请联系分享者重新创建。",
  SHARE_REVOKED: "分享者已撤销这个分享，或它所依赖的访问权限已经变化。",
  SHARE_NOT_FOUND: "链接不完整或已失效。请确认复制了完整的分享链接。",
  SHARE_REQUEST_INVALID: "链接不完整或已失效。请确认复制了完整的分享链接。",
};

/**
 * The public landing page of a share link (`#/http-share/<token>`). The token has already been
 * taken out of the address bar by the time this renders; it is exchanged for the share cookie and
 * the page replaces itself with the share, so the history keeps no entry with the token.
 */
export function HttpShareLandingPage() {
  const [state, setState] = useState<LandingState>({ phase: "opening" });
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const token = captureShareToken(window.location, window.history);
    void exchangeShareToken(token).then((result) => {
      if (result.ok) {
        forgetShareToken();
        window.location.replace(result.location);
        return;
      }
      if (result.code !== "SHARE_UNAVAILABLE" && result.code !== "SHARE_RATE_LIMITED") {
        forgetShareToken();
      }
      setState({ phase: "failed", message: result.message, code: result.code });
    });
  }, []);

  return (
    <main className="app-apple flex min-h-screen items-center justify-center bg-background px-4 text-foreground">
      <section className="w-full max-w-md rounded-large border border-default-200 bg-content1 p-6 shadow-small" aria-live="polite">
        <div className="mb-4 flex items-center gap-2">
          <AppLogo />
        </div>
        {state.phase === "opening" ? (
          <div className="flex items-center gap-3 text-small text-default-600" role="status">
            <span className="h-4 w-4 animate-spin rounded-full border-2 border-default-300 border-t-primary" />
            <span>正在打开分享…</span>
          </div>
        ) : (
          <div role="alert">
            <h1 className="text-large font-semibold">{state.message}</h1>
            <p className="mt-2 text-small text-default-500">
              {FAILURE_HINTS[state.code] ?? "暂时无法打开这个分享，请稍后刷新页面重试。"}
            </p>
          </div>
        )}
      </section>
    </main>
  );
}
