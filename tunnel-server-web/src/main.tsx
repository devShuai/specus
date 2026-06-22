import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HeroUIProvider, ToastProvider } from "@heroui/react";
import { AuthProvider } from "./auth/AuthContext";
import { App } from "./App";
import "./index.css";

function Root() {
  return (
    <HeroUIProvider className="light">
      <ToastProvider placement="top-right" toastOffset={12} />
      <AuthProvider>
        <div className="min-h-screen bg-background text-foreground">
          <App />
        </div>
      </AuthProvider>
    </HeroUIProvider>
  );
}

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
