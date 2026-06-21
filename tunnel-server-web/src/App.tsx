import { Spinner } from "@heroui/react";
import { useAuth } from "./auth/AuthContext";
import { LoginPage } from "./pages/LoginPage";
import { Dashboard } from "./pages/Dashboard";

export function App() {
  const { ready, authed } = useAuth();

  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner label="加载中…" />
      </div>
    );
  }
  return authed ? <Dashboard /> : <LoginPage />;
}
