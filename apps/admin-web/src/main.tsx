import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { AuthProvider } from "./auth/AuthContext";
import { App } from "./App";
import { ThemeProvider } from "./theme/ThemeContext";
import "./index.css";

applyPlatformClasses();

function applyPlatformClasses() {
  const userAgent = window.navigator.userAgent;
  const isAndroid = /\bAndroid\b/i.test(userAgent);
  const isChrome = /\bChrome\//i.test(userAgent);
  const isExcludedChromiumShell = /\b(EdgA|OPR|SamsungBrowser|HuaweiBrowser|MiuiBrowser)\//i.test(userAgent);

  if (isAndroid && isChrome && !isExcludedChromiumShell) {
    document.documentElement.classList.add("android-chrome");
  }
}

function Root() {
  return (
    <ThemeProvider>
      <ThemedRoot />
    </ThemeProvider>
  );
}

function ThemedRoot() {
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
}

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
