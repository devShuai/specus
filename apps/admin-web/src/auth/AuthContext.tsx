import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  adminApi,
  fetchOidcConfig,
  oidcExchange,
  passwordLogin as apiPasswordLogin,
  refreshToken,
  registerAccount as apiRegisterAccount,
  setUnauthorizedHandler,
  tokenStore,
} from "../api/client";
import type { ManagementUser, OidcConfig } from "../api/types";
import { codeChallenge, randomToken } from "../lib/pkce";

const PKCE_VERIFIER_KEY = "pkce_verifier";
const OIDC_STATE_KEY = "oidc_state";
const AUTH_RETURN_PATH_KEY = "auth_return_path";
const REFRESH_INTERVAL_MS = 60_000;
const REFRESH_WINDOW_MS = 5 * 60_000;

interface AuthState {
  ready: boolean;
  authed: boolean;
  profile: ManagementUser | null;
  oidcConfig: OidcConfig | null;
  loginHint: string;
  /** 全局登录/注册弹窗是否打开（由 openLogin/closeLogin 控制）。 */
  loginOpen: boolean;
  /** 弹窗打开时的初始页签。 */
  loginInitialTab: "login" | "register";
  expireSession: () => void;
  reloadProfile: () => Promise<ManagementUser>;
  passwordLogin: (username: string, password: string) => Promise<void>;
  register: (username: string, password: string) => Promise<void>;
  startOidcLogin: () => Promise<void>;
  openLogin: (initialTab?: "login" | "register") => void;
  closeLogin: () => void;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [authed, setAuthed] = useState(false);
  const [profile, setProfile] = useState<ManagementUser | null>(null);
  const [oidcConfig, setOidcConfig] = useState<OidcConfig | null>(null);
  const [loginHint, setLoginHint] = useState("请登录");
  const [loginOpen, setLoginOpen] = useState(false);
  const [loginInitialTab, setLoginInitialTab] = useState<"login" | "register">("login");
  const refreshTimer = useRef<number | null>(null);
  const initialized = useRef(false);
  const sessionExpired = useRef(false);

  const stopRefresh = useCallback(() => {
    if (refreshTimer.current !== null) {
      window.clearInterval(refreshTimer.current);
      refreshTimer.current = null;
    }
  }, []);

  const startRefresh = useCallback(() => {
    stopRefresh();
    const tick = async () => {
      if (tokenStore.loginType() !== "password") {
        return;
      }
      const expiry = tokenStore.expiry();
      if (expiry === 0 || Date.now() < expiry - REFRESH_WINDOW_MS) {
        return;
      }
      try {
        const data = await refreshToken();
        tokenStore.save(data.accessToken, data.expiresIn, "password");
      } catch {
        // Silent: the next 401 will force re-login.
      }
    };
    void tick();
    refreshTimer.current = window.setInterval(tick, REFRESH_INTERVAL_MS);
  }, [stopRefresh]);

  const reloadProfile = useCallback(async () => {
    const nextProfile = await adminApi.me();
    setProfile(nextProfile);
    return nextProfile;
  }, []);

  const handleUnauthorized = useCallback(() => {
    if (sessionExpired.current) {
      return;
    }
    sessionExpired.current = true;
    tokenStore.clear();
    stopRefresh();
    setProfile(null);
    setAuthed(false);
    setLoginHint("登录已过期，请重新登录");
  }, [stopRefresh]);

  const logout = useCallback(() => {
    const loginType = tokenStore.loginType();
    tokenStore.clear();
    stopRefresh();
    setProfile(null);
    if (loginType === "oidc" && oidcConfig?.endSessionEndpoint) {
      window.location.href = oidcConfig.endSessionEndpoint;
      return;
    }
    setAuthed(false);
    setLoginHint("已退出登录");
  }, [oidcConfig, stopRefresh]);

  const completePasswordAuth = useCallback(
    async (data: { accessToken: string; expiresIn: number }) => {
      try {
        tokenStore.save(data.accessToken, data.expiresIn, "password");
        await reloadProfile();
        sessionExpired.current = false;
        setAuthed(true);
        setLoginOpen(false);
        startRefresh();
      } catch (error) {
        tokenStore.clear();
        setProfile(null);
        throw error;
      }
    },
    [reloadProfile, startRefresh],
  );

  const passwordLogin = useCallback(
    async (username: string, password: string) => {
      await completePasswordAuth(await apiPasswordLogin(username, password));
    },
    [completePasswordAuth],
  );

  const register = useCallback(
    async (username: string, password: string) => {
      await completePasswordAuth(await apiRegisterAccount(username, password));
    },
    [completePasswordAuth],
  );

  const startOidcLogin = useCallback(async () => {
    if (!oidcConfig?.configured) {
      return;
    }
    const verifier = randomToken();
    const state = randomToken();
    sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier);
    sessionStorage.setItem(OIDC_STATE_KEY, state);
    if (!safeAuthReturnPath(sessionStorage.getItem(AUTH_RETURN_PATH_KEY))) {
      sessionStorage.setItem(
        AUTH_RETURN_PATH_KEY,
        `${window.location.pathname}${window.location.search}${window.location.hash}`,
      );
    }
    const challenge = await codeChallenge(verifier);
    const url = new URL(oidcConfig.authorizationEndpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", oidcConfig.clientId);
    url.searchParams.set("redirect_uri", oidcConfig.redirectUri);
    url.searchParams.set("scope", oidcConfig.scope || "openid");
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("state", state);
    window.location.href = url.toString();
  }, [oidcConfig]);

  // onPress={openLogin} 之类的调用会把事件对象当第一个参数传进来，所以只认字面量 "register"。
  const openLogin = useCallback((initialTab?: unknown) => {
    setLoginInitialTab(initialTab === "register" ? "register" : "login");
    setLoginOpen(true);
  }, []);
  const closeLogin = useCallback(() => setLoginOpen(false), []);

  useEffect(() => {
    if (initialized.current) {
      return;
    }
    initialized.current = true;
    setUnauthorizedHandler(handleUnauthorized);

    const init = async () => {
      const config = await fetchOidcConfig();
      setOidcConfig(config);

      const params = new URLSearchParams(window.location.search);
      if (params.get("error")) {
        setLoginHint(params.get("error_description") || params.get("error") || "登录失败");
        cleanUrl();
      } else if (params.get("code")) {
        await completeOidcRedirect(params, setLoginHint, async () => {
          await reloadProfile();
          sessionExpired.current = false;
          setAuthed(true);
          startRefresh();
        });
      } else if (tokenStore.valid()) {
        try {
          await reloadProfile();
          setAuthed(true);
          startRefresh();
        } catch (error) {
          tokenStore.clear();
          setProfile(null);
          setLoginHint(error instanceof Error ? error.message : "登录已过期，请重新登录");
        }
      } else if (config && !config.passwordLoginEnabled && !config.configured) {
        setLoginHint("未配置任何登录方式：请设置用户名/密码或 OIDC");
      }
      setReady(true);
    };
    void init();

    return () => setUnauthorizedHandler(null);
  }, [handleUnauthorized, reloadProfile, startRefresh]);

  const value: AuthState = {
    ready,
    authed,
    profile,
    oidcConfig,
    loginHint,
    loginOpen,
    loginInitialTab,
    expireSession: handleUnauthorized,
    reloadProfile,
    passwordLogin,
    register,
    startOidcLogin,
    openLogin,
    closeLogin,
    logout,
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

async function completeOidcRedirect(
  params: URLSearchParams,
  setHint: (hint: string) => void,
  onSuccess: () => Promise<void>,
): Promise<void> {
  const expectedState = sessionStorage.getItem(OIDC_STATE_KEY);
  if (!expectedState || params.get("state") !== expectedState) {
    setHint("登录状态校验失败，请重试");
    cleanUrl();
    return;
  }
  let completed = false;
  try {
    const verifier = sessionStorage.getItem(PKCE_VERIFIER_KEY) || "";
    const data = await oidcExchange(params.get("code") as string, verifier);
    tokenStore.save(data.accessToken, data.expiresIn, "oidc");
    await onSuccess();
    completed = true;
  } catch (error) {
    setHint(error instanceof Error ? error.message : "登录失败");
  } finally {
    sessionStorage.removeItem(PKCE_VERIFIER_KEY);
    sessionStorage.removeItem(OIDC_STATE_KEY);
    const returnPath = safeAuthReturnPath(sessionStorage.getItem(AUTH_RETURN_PATH_KEY));
    sessionStorage.removeItem(AUTH_RETURN_PATH_KEY);
    if (completed && returnPath && returnPath !== `${window.location.pathname}${window.location.search}${window.location.hash}`) {
      window.location.replace(returnPath);
      return;
    }
    cleanUrl();
  }
}

function safeAuthReturnPath(value: string | null): string | null {
  return value && value.startsWith("/") && !value.startsWith("//") ? value : null;
}

function cleanUrl(): void {
  window.history.replaceState({}, document.title, window.location.pathname);
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}
