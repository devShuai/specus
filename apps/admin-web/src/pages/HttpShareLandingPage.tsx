import { useEffect, useRef, useState } from "react";
import { PublicPage } from "../components/PublicTopBar";
import { Icon, type IconName } from "../components/ui";
import { captureShareToken, exchangeShareToken, forgetShareToken } from "../lib/httpShare";

type LandingState = { phase: "opening" } | { phase: "failed"; message: string; code: string };

/** What went wrong (shown under the title) and what the visitor can do next. */
const FAILURE_HINTS: Record<string, { icon: IconName; tone: "warning" | "danger"; cause: string; next: string }> = {
  SHARE_EXPIRED: {
    icon: "clock",
    tone: "warning",
    cause: "这个分享的有效期已经结束。",
    next: "如仍需访问，联系分享者重新创建一个分享。",
  },
  SHARE_REVOKED: {
    icon: "ban",
    tone: "danger",
    cause: "分享者已撤销这个分享，或它所依赖的访问权限已经变化。",
    next: "如仍需访问，联系分享者确认后重新分享。",
  },
  SHARE_NOT_FOUND: {
    icon: "link",
    tone: "warning",
    cause: "链接不完整或已失效。",
    next: "确认复制了完整的分享链接，再重新打开。",
  },
  SHARE_REQUEST_INVALID: {
    icon: "link",
    tone: "warning",
    cause: "链接不完整或已失效。",
    next: "确认复制了完整的分享链接，再重新打开。",
  },
};

const FALLBACK_HINT = {
  icon: "circle-alert" as IconName,
  tone: "warning" as const,
  cause: "暂时无法打开这个分享。",
  next: "过一会儿重新打开分享链接再试。",
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

  const hint = state.phase === "failed" ? FAILURE_HINTS[state.code] ?? FALLBACK_HINT : null;

  return (
    <PublicPage minimal>
      <div className="pub-container pub-share">
        <section className="bd-card pub-share-card" aria-live="polite">
          {state.phase === "opening" || !hint ? (
            <div className="pub-share-state" role="status">
              <span className="pub-share-icon" data-tone="info" aria-hidden="true">
                <Icon name="loader" size={24} className="animate-spin" />
              </span>
              <h1 className="pub-share-title">正在打开分享…</h1>
              <p className="pub-share-desc">验证分享链接后会直接进入分享的页面。</p>
            </div>
          ) : (
            <div className="pub-share-state" role="alert">
              <span className="pub-share-icon" data-tone={hint.tone} aria-hidden="true">
                <Icon name={hint.icon} size={24} />
              </span>
              <h1 className="pub-share-title">{state.message}</h1>
              <p className="pub-share-desc">{hint.cause}</p>
              <p className="pub-share-next">
                <Icon name="arrow-right" size={14} />
                <span>{hint.next}</span>
              </p>
            </div>
          )}
        </section>
      </div>
    </PublicPage>
  );
}
