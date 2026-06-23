import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HeroUIProvider, ToastProvider } from "@heroui/react";
import { AuthProvider } from "./auth/AuthContext";
import { App } from "./App";
import { ThemeProvider, useTheme } from "./theme/ThemeContext";
import "./index.css";

function Root() {
  return (
    <ThemeProvider>
      <ThemedRoot />
    </ThemeProvider>
  );
}

function ThemedRoot() {
  const { theme } = useTheme();

  return (
    <HeroUIProvider className={theme}>
      <div className={theme}>
        <ToastProvider placement="top-right" toastOffset={12} />
        <AuthProvider>
          <div className="min-h-screen bg-background text-foreground">
            <App />
          </div>
        </AuthProvider>
      </div>
    </HeroUIProvider>
  );
}

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
