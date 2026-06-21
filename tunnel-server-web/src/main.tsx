import { StrictMode, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { HeroUIProvider, ToastProvider } from "@heroui/react";
import { AuthProvider } from "./auth/AuthContext";
import { App } from "./App";
import "./index.css";

// Follow the OS color scheme by toggling the `dark` class HeroUI keys off.
function useSystemTheme(): void {
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      document.documentElement.classList.toggle("dark", media.matches);
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, []);
}

function Root() {
  useSystemTheme();
  return (
    <HeroUIProvider>
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
