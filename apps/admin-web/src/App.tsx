import { lazy, Suspense, useEffect, useState } from "react";
import { useAuth } from "./auth/AuthContext";
import { tokenStore } from "./api/client";

const LazyLoginPage = lazy(() => import("./pages/LoginPage").then((module) => ({ default: module.LoginPage })));
const LazyDashboard = lazy(() => import("./pages/Dashboard").then((module) => ({ default: module.Dashboard })));

const LazyNatDetectionPanel = lazy(() =>
  import("./pages/panels/NatDetectionPanel").then((module) => ({ default: module.NatDetectionPanel })),
);

function readPublicRoute() {
  const hash = window.location.hash.replace(/^#\/?/, "").split(/[/?#]/, 1)[0];
  const queryPanel = new URLSearchParams(window.location.search).get("panel");
  return hash === "nat-detect" || queryPanel === "nat-detect" ? "nat-detect" : null;
}

function hasOidcCallback() {
  const params = new URLSearchParams(window.location.search);
  return params.has("code") || params.has("error");
}

export function App() {
  const { ready, authed } = useAuth();
  const [publicRoute, setPublicRoute] = useState<string | null>(() => readPublicRoute());

  useEffect(() => {
    const syncPublicRoute = () => setPublicRoute(readPublicRoute());
    window.addEventListener("hashchange", syncPublicRoute);
    window.addEventListener("popstate", syncPublicRoute);
    return () => {
      window.removeEventListener("hashchange", syncPublicRoute);
      window.removeEventListener("popstate", syncPublicRoute);
    };
  }, []);

  if (publicRoute === "nat-detect") {
    return (
      <Suspense fallback={<FullScreenLoading />}>
        <LazyNatDetectionPanel publicPage />
      </Suspense>
    );
  }

  const canShowGuestShell = !ready && !tokenStore.valid() && !hasOidcCallback();
  if (!ready && !canShowGuestShell) {
    return <FullScreenLoading />;
  }
  return (
    <Suspense fallback={<FullScreenLoading />}>
      {authed ? <LazyDashboard /> : <LazyLoginPage />}
    </Suspense>
  );
}

function FullScreenLoading() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background text-foreground">
      <div className="flex items-center gap-3 rounded-md border border-default-200 bg-content1 px-4 py-3 text-small text-default-600 shadow-sm">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-default-300 border-t-primary" />
        <span>加载中…</span>
      </div>
    </div>
  );
}
