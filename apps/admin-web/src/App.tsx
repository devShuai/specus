import { lazy, Suspense, useEffect, useState } from "react";
import { Spinner } from "@heroui/react";
import { useAuth } from "./auth/AuthContext";
import { LoginPage } from "./pages/LoginPage";
import { Dashboard } from "./pages/Dashboard";

const LazyNatDetectionPanel = lazy(() =>
  import("./pages/panels/NatDetectionPanel").then((module) => ({ default: module.NatDetectionPanel })),
);

function readPublicRoute() {
  const hash = window.location.hash.replace(/^#\/?/, "").split(/[/?#]/, 1)[0];
  const queryPanel = new URLSearchParams(window.location.search).get("panel");
  return hash === "nat-detect" || queryPanel === "nat-detect" ? "nat-detect" : null;
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

  if (publicRoute === "nat-detect" && !authed) {
    return (
      <Suspense fallback={<FullScreenLoading />}>
        <LazyNatDetectionPanel publicPage />
      </Suspense>
    );
  }

  if (!ready) {
    return <FullScreenLoading />;
  }
  return authed ? <Dashboard /> : <LoginPage />;
}

function FullScreenLoading() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <Spinner label="加载中…" />
    </div>
  );
}
