import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type AppTheme = "light" | "dark";

interface ThemeContextValue {
  theme: AppTheme;
  toggleTheme: () => void;
  setTheme: (theme: AppTheme) => void;
  /** True 表示用户主动切过；之后系统深浅切换不会再覆盖。调 resetToSystem() 可回到跟随系统。 */
  userOverride: boolean;
  resetToSystem: () => void;
}

const THEME_KEY = "specus_theme";
const ThemeContext = createContext<ThemeContextValue | null>(null);

function readPersistedTheme(): AppTheme | null {
  if (typeof window === "undefined") {
    return null;
  }
  const saved = window.localStorage.getItem(THEME_KEY);
  return saved === "light" || saved === "dark" ? saved : null;
}

function getSystemTheme(): AppTheme {
  if (typeof window === "undefined") {
    return "dark";
  }
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function initialTheme(): AppTheme {
  return readPersistedTheme() ?? getSystemTheme();
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<AppTheme>(initialTheme);
  // 初始 override 状态：localStorage 里已经存了具体值，说明用户之前手动切过。
  const [userOverride, setUserOverride] = useState<boolean>(() => readPersistedTheme() !== null);

  const setTheme = useCallback((nextTheme: AppTheme) => {
    setThemeState(nextTheme);
    setUserOverride(true);
  }, []);

  const toggleTheme = useCallback(() => {
    setThemeState((current) => (current === "dark" ? "light" : "dark"));
    setUserOverride(true);
  }, []);

  const resetToSystem = useCallback(() => {
    setUserOverride(false);
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(THEME_KEY);
      setThemeState(getSystemTheme());
    }
  }, []);

  // 把当前主题同步到 <html> 上：暗色加 .dark，浅色加 .light，并设置 color-scheme。
  // 只有当用户已经手动切过的时候才把选择写进 localStorage，避免把"跟随系统"也固化掉。
  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", theme === "dark");
    root.classList.toggle("light", theme === "light");
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
    if (userOverride) {
      window.localStorage.setItem(THEME_KEY, theme);
    }
  }, [theme, userOverride]);

  // 跟随系统深浅切换：仅当用户未做过主动覆盖时生效。订阅 prefers-color-scheme 媒体查询，
  // 系统切换的瞬间同步页面主题。用户一旦点过切换按钮，这里就解绑、不再跟随。
  useEffect(() => {
    if (userOverride || typeof window === "undefined") {
      return;
    }
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const handler = (event: MediaQueryListEvent) => {
      setThemeState(event.matches ? "light" : "dark");
    };
    // addEventListener 是现代 API；老 Safari (<14) 仍需 addListener fallback。
    if (typeof mq.addEventListener === "function") {
      mq.addEventListener("change", handler);
      return () => mq.removeEventListener("change", handler);
    }
    mq.addListener(handler);
    return () => mq.removeListener(handler);
  }, [userOverride]);

  const value = useMemo(
    () => ({ theme, setTheme, toggleTheme, userOverride, resetToSystem }),
    [theme, setTheme, toggleTheme, userOverride, resetToSystem],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used inside ThemeProvider");
  }
  return context;
}
