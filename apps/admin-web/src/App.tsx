import { lazy, Suspense, useEffect, useLayoutEffect, useState, type ReactNode } from "react";
import { useAuth } from "./auth/AuthContext";
import { tokenStore } from "./api/client";
import { AuthDialog } from "./components/AuthDialog";
import { readPublicRoute, type PublicRoute } from "./lib/publicRoute";
import { captureShareToken } from "./lib/httpShare";

const LazyLoginPage = lazy(() => import("./pages/LoginPage").then((module) => ({ default: module.LoginPage })));
const LazyDashboard = lazy(() => import("./pages/Dashboard").then((module) => ({ default: module.Dashboard })));

const LazyNatDetectionPanel = lazy(() =>
  import("./pages/panels/NatDetectionPanel").then((module) => ({ default: module.NatDetectionPanel })),
);
const LazyPublicTransferPage = lazy(() =>
  import("./pages/PublicTransferPage").then((module) => ({ default: module.PublicTransferPage })),
);
const LazyPublicDiagramPage = lazy(() =>
  import("./pages/PublicDiagramPage").then((module) => ({ default: module.PublicDiagramPage })),
);
const LazyDiagramEmbedPage = lazy(() =>
  import("./pages/DiagramEmbedPage").then((module) => ({ default: module.DiagramEmbedPage })),
);
const LazyPublicDownloadPage = lazy(() =>
  import("./pages/PublicDownloadPage").then((module) => ({ default: module.PublicDownloadPage })),
);
const LazyHttpShareLandingPage = lazy(() =>
  import("./pages/HttpShareLandingPage").then((module) => ({ default: module.HttpShareLandingPage })),
);

/**
 * Resolves the public page and, for a share link, takes the token out of the address bar before
 * anything else loads or runs.
 */
function currentPublicRoute(): PublicRoute | null {
  const route = readPublicRoute(window.location);
  if (route === "http-share") {
    captureShareToken(window.location, window.history);
  }
  return route;
}

function hasOidcCallback() {
  const params = new URLSearchParams(window.location.search);
  return params.has("code") || params.has("error");
}

export function App() {
  const { ready, authed } = useAuth();
  const [publicRoute, setPublicRoute] = useState<PublicRoute | null>(currentPublicRoute);

  useEffect(() => {
    const syncPublicRoute = () => {
      const route = currentPublicRoute();
      // Opening a share link from an open tab fires popstate and then hashchange; the first one
      // already took the token and cleared the fragment, so the second must not unmount the
      // landing page in the middle of its exchange. Any other hash still leaves it.
      setPublicRoute((previous) =>
        previous === "http-share" && route === null && window.location.hash === "" ? previous : route,
      );
    };
    window.addEventListener("hashchange", syncPublicRoute);
    window.addEventListener("popstate", syncPublicRoute);
    return () => {
      window.removeEventListener("hashchange", syncPublicRoute);
      window.removeEventListener("popstate", syncPublicRoute);
    };
  }, []);

  useLayoutEffect(() => {
    if (publicRoute !== "diagram" && publicRoute !== "diagram-embed") return;
    const root = window.document.documentElement;
    const body = window.document.body;
    const previousRootOverflow = root.style.overflow;
    const previousScrollbarGutter = root.style.getPropertyValue("scrollbar-gutter");
    const previousBodyOverflow = body.style.overflow;
    const previousOverscrollBehavior = body.style.overscrollBehavior;
    root.style.overflow = "hidden";
    root.style.setProperty("scrollbar-gutter", "auto");
    body.style.overflow = "hidden";
    body.style.overscrollBehavior = "none";
    return () => {
      root.style.overflow = previousRootOverflow;
      if (previousScrollbarGutter) root.style.setProperty("scrollbar-gutter", previousScrollbarGutter);
      else root.style.removeProperty("scrollbar-gutter");
      body.style.overflow = previousBodyOverflow;
      body.style.overscrollBehavior = previousOverscrollBehavior;
    };
  }, [publicRoute]);

  let content: ReactNode;
  if (publicRoute === "nat-detect") {
    content = <LazyNatDetectionPanel publicPage />;
  } else if (publicRoute === "transfer") {
    content = <LazyPublicTransferPage />;
  } else if (publicRoute === "diagram") {
    content = <LazyPublicDiagramPage />;
  } else if (publicRoute === "diagram-embed") {
    content = <LazyDiagramEmbedPage />;
  } else if (publicRoute === "download") {
    content = <LazyPublicDownloadPage />;
  } else if (publicRoute === "http-share") {
    content = <LazyHttpShareLandingPage />;
  } else {
    const canShowGuestShell = !ready && !tokenStore.valid() && !hasOidcCallback();
    if (!ready && !canShowGuestShell) {
      return <FullScreenLoading />;
    }
    content = authed ? <LazyDashboard /> : <LazyLoginPage />;
  }

  return (
    <>
      <Suspense fallback={<FullScreenLoading />}>{content}</Suspense>
      <AuthDialog />
    </>
  );
}

function FullScreenLoading() {
  return (
    <div className="app-apple flex min-h-screen items-center justify-center bg-background text-foreground" role="status">
      <div className="flex items-center gap-3 rounded-md border border-default-200 bg-content1 px-4 py-3 text-small text-default-600 shadow-xs">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-default-300 border-t-primary" />
        <span>加载中…</span>
      </div>
    </div>
  );
}
