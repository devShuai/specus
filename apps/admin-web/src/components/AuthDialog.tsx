import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";

/**
 * 全局登录 / 注册弹窗。挂在 App 顶层，任何页面调用 useAuth().openLogin() 都会弹出，
 * 替代原先落地页内嵌的登录卡片和 /#login-panel 跳转。
 *
 * 有意不用 HeroUI Modal：HeroUIProvider 是每个页面外壳（HeroRuntime）内部各自包的，
 * 这里位于所有页面之外，用纯 CSS 覆盖层可以在任何路由下工作。
 */
export function AuthDialog() {
  const {
    loginOpen,
    loginInitialTab,
    closeLogin,
    authed,
    oidcConfig,
    loginHint,
    passwordLogin,
    register,
    startOidcLogin,
  } = useAuth();
  const [tab, setTab] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const usernameInputRef = useRef<HTMLInputElement | null>(null);

  const passwordEnabled = oidcConfig?.passwordLoginEnabled ?? true;
  const oidcEnabled = oidcConfig?.configured ?? false;
  const registrationEnabled = (oidcConfig?.registrationEnabled ?? false) && passwordEnabled;
  const isRegister = tab === "register" && registrationEnabled;

  const resetForm = useCallback(() => {
    setUsername("");
    setPassword("");
    setConfirmPassword("");
    setError(null);
    setSubmitting(false);
  }, []);

  useEffect(() => {
    if (!loginOpen) return;
    setTab(loginInitialTab);
    resetForm();
    const timer = window.setTimeout(() => usernameInputRef.current?.focus(), 50);
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeLogin();
    };
    window.addEventListener("keydown", onKeyDown);
    const body = window.document.body;
    const previousOverflow = body.style.overflow;
    body.style.overflow = "hidden";
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("keydown", onKeyDown);
      body.style.overflow = previousOverflow;
    };
  }, [closeLogin, loginInitialTab, loginOpen, resetForm]);

  useEffect(() => {
    if (authed && loginOpen) closeLogin();
  }, [authed, closeLogin, loginOpen]);

  if (!loginOpen || authed) return null;

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (isRegister && password !== confirmPassword) {
      setError("两次输入的密码不一致");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      if (isRegister) {
        await register(username.trim(), password);
      } else {
        await passwordLogin(username.trim(), password);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : isRegister ? "注册失败" : "登录失败");
    } finally {
      setSubmitting(false);
    }
  };

  const loginWithOidc = async () => {
    setError(null);
    try {
      await startOidcLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "OIDC 登录失败");
    }
  };

  const switchTab = (nextTab: "login" | "register") => {
    setTab(nextTab);
    setError(null);
    setConfirmPassword("");
  };

  return (
    <div
      className="fixed inset-0 z-[120] flex items-center justify-center overflow-y-auto bg-black/45 p-4 backdrop-blur-sm"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) closeLogin();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={isRegister ? "注册账号" : "登录管理台"}
        className="landing-card w-full max-w-[380px] rounded-2xl bg-white text-zinc-950 shadow-2xl dark:bg-zinc-900 dark:text-white"
      >
        <div className="flex items-start justify-between gap-2 px-5 pb-1 pt-5">
          <div>
            <h2 className="text-xl font-semibold tracking-tight">{isRegister ? "注册账号" : "进入控制台"}</h2>
            <p className="mt-1 text-small text-zinc-600 dark:text-zinc-400">
              {isRegister ? "注册后自动登录，可使用云端保存与文件分享。" : loginHint}
            </p>
          </div>
          <button
            type="button"
            aria-label="关闭"
            className="grid h-8 w-8 shrink-0 place-items-center rounded-full text-zinc-500 transition hover:bg-black/5 hover:text-zinc-950 dark:hover:bg-white/10 dark:hover:text-white"
            onClick={closeLogin}
          >
            <svg aria-hidden="true" className="h-4 w-4" fill="none" viewBox="0 0 24 24">
              <path d="M6 6l12 12M6 18L18 6" stroke="currentColor" strokeLinecap="round" strokeWidth="2" />
            </svg>
          </button>
        </div>

        {registrationEnabled && (
          <div className="mx-5 mt-3 grid grid-cols-2 rounded-lg bg-black/5 p-1 text-small dark:bg-white/10">
            {([["login", "登录"], ["register", "注册"]] as const).map(([key, label]) => (
              <button
                key={key}
                type="button"
                className={`rounded-md py-1.5 font-medium transition ${
                  tab === key
                    ? "bg-white text-zinc-950 shadow-sm dark:bg-zinc-700 dark:text-white"
                    : "text-zinc-600 hover:text-zinc-950 dark:text-zinc-300 dark:hover:text-white"
                }`}
                onClick={() => switchTab(key)}
              >
                {label}
              </button>
            ))}
          </div>
        )}

        <div className="flex flex-col gap-4 px-5 pb-5 pt-4">
          {passwordEnabled && (
            <form className="flex flex-col gap-3" onSubmit={onSubmit}>
              <label className="grid gap-1.5 text-small text-zinc-700 dark:text-zinc-300">
                <span>用户名 <span className="text-danger">*</span></span>
                <input
                  ref={usernameInputRef}
                  className="landing-form-input"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="username"
                  maxLength={80}
                  required
                />
              </label>
              <label className="grid gap-1.5 text-small text-zinc-700 dark:text-zinc-300">
                <span>密码 <span className="text-danger">*</span></span>
                <input
                  className="landing-form-input"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete={isRegister ? "new-password" : "current-password"}
                  maxLength={120}
                  required
                />
              </label>
              {isRegister && (
                <label className="grid gap-1.5 text-small text-zinc-700 dark:text-zinc-300">
                  <span>确认密码 <span className="text-danger">*</span></span>
                  <input
                    className="landing-form-input"
                    type="password"
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    autoComplete="new-password"
                    maxLength={120}
                    required
                  />
                </label>
              )}
              {error && (
                <p className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-small text-danger-700 dark:text-danger-200">
                  {error}
                </p>
              )}
              <button
                type="submit"
                className="landing-primary-button"
                disabled={submitting || !username.trim() || !password || (isRegister && !confirmPassword)}
              >
                {submitting ? (isRegister ? "注册中..." : "登录中...") : isRegister ? "注册并登录" : "登录管理台"}
              </button>
            </form>
          )}

          {passwordEnabled && oidcEnabled && !isRegister && (
            <div className="flex items-center gap-3 text-tiny text-zinc-500 dark:text-zinc-500">
              <span className="h-px flex-1 bg-black/10 dark:bg-white/10" />
              <span>或</span>
              <span className="h-px flex-1 bg-black/10 dark:bg-white/10" />
            </div>
          )}

          {oidcEnabled && !isRegister && (
            <button type="button" className="landing-secondary-button" onClick={() => void loginWithOidc()}>
              使用 OIDC 登录
            </button>
          )}

          {!passwordEnabled && !oidcEnabled && (
            <p className="rounded-md border border-danger/40 bg-danger/10 p-3 text-small text-danger-700 dark:text-danger-200">
              未配置任何登录方式：请设置用户名/密码或 OIDC
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
