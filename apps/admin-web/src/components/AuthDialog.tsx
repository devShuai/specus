import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import type { RegistrationChallengeResponse } from "../api/types";
import { AppLogo } from "./AppLogo";

/** Global login and two-step email registration dialog. */
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
    verifyRegistration,
    startOidcLogin,
  } = useAuth();
  const [tab, setTab] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [challenge, setChallenge] = useState<RegistrationChallengeResponse | null>(null);
  const [resendAvailableAt, setResendAvailableAt] = useState(0);
  const [clock, setClock] = useState(() => Date.now());
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const usernameInputRef = useRef<HTMLInputElement | null>(null);
  const codeInputRef = useRef<HTMLInputElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);

  const passwordEnabled = oidcConfig?.passwordLoginEnabled ?? true;
  const oidcEnabled = oidcConfig?.configured ?? false;
  const registrationEnabled = (oidcConfig?.registrationEnabled ?? false) && passwordEnabled;
  const isRegister = tab === "register" && registrationEnabled;
  const isVerifyingEmail = isRegister && challenge !== null;
  const resendSeconds = Math.max(0, Math.ceil((resendAvailableAt - clock) / 1000));

  const resetForm = useCallback(() => {
    setUsername("");
    setEmail("");
    setPassword("");
    setConfirmPassword("");
    setVerificationCode("");
    setChallenge(null);
    setResendAvailableAt(0);
    setClock(Date.now());
    setError(null);
    setSubmitting(false);
  }, []);

  useEffect(() => {
    if (!loginOpen) return;
    const previouslyFocused = window.document.activeElement instanceof HTMLElement
      ? window.document.activeElement
      : null;
    const fallbackFocusTarget = window.document.querySelector<HTMLElement>(
      ".header-menu-trigger.theme-toggle-button",
    );
    const focusReturnTarget = previouslyFocused && previouslyFocused !== window.document.body
      ? previouslyFocused
      : fallbackFocusTarget;
    setTab(loginInitialTab);
    resetForm();
    const focusTimer = window.setTimeout(() => {
      const firstControl = panelRef.current?.querySelector<HTMLElement>(
        "input:not([disabled]), button:not([disabled]), [href], [tabindex]:not([tabindex='-1'])",
      );
      (usernameInputRef.current ?? firstControl)?.focus();
    }, 50);
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeLogin();
        return;
      }
      if (event.key !== "Tab") return;
      const controls = Array.from(panelRef.current?.querySelectorAll<HTMLElement>(
        "input:not([disabled]), button:not([disabled]), [href], [tabindex]:not([tabindex='-1'])",
      ) ?? []);
      if (controls.length === 0) {
        event.preventDefault();
        return;
      }
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && window.document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && window.document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    const body = window.document.body;
    const previousOverflow = body.style.overflow;
    body.style.overflow = "hidden";
    return () => {
      window.clearTimeout(focusTimer);
      window.removeEventListener("keydown", onKeyDown);
      body.style.overflow = previousOverflow;
      if (focusReturnTarget?.isConnected) focusReturnTarget.focus();
    };
  }, [closeLogin, loginInitialTab, loginOpen, resetForm]);

  useEffect(() => {
    if (!challenge) return;
    setClock(Date.now());
    const focusTimer = window.setTimeout(() => codeInputRef.current?.focus(), 50);
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => {
      window.clearTimeout(focusTimer);
      window.clearInterval(timer);
    };
  }, [challenge]);

  useEffect(() => {
    if (authed && loginOpen) closeLogin();
  }, [authed, closeLogin, loginOpen]);

  if (!loginOpen || authed) return null;

  const applyChallenge = (next: RegistrationChallengeResponse) => {
    setChallenge(next);
    setVerificationCode("");
    setResendAvailableAt(Date.now() + Math.max(0, next.resendAfterSeconds) * 1000);
    setClock(Date.now());
  };

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (isRegister && !isVerifyingEmail && password !== confirmPassword) {
      setError("两次输入的密码不一致");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      if (isVerifyingEmail && challenge) {
        await verifyRegistration(challenge.registrationId, verificationCode);
      } else if (isRegister) {
        applyChallenge(await register(username.trim(), email.trim(), password));
      } else {
        await passwordLogin(username.trim(), password);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : isRegister ? "注册失败" : "登录失败");
    } finally {
      setSubmitting(false);
    }
  };

  const resendCode = async () => {
    if (!challenge || resendSeconds > 0 || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      applyChallenge(await register(username.trim(), email.trim(), password));
    } catch (err) {
      setError(err instanceof Error ? err.message : "验证码发送失败");
    } finally {
      setSubmitting(false);
    }
  };

  const loginWithOidc = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await startOidcLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "OIDC 登录失败");
    } finally {
      setSubmitting(false);
    }
  };

  const switchTab = (nextTab: "login" | "register") => {
    setTab(nextTab);
    resetForm();
  };

  const editRegistration = () => {
    setChallenge(null);
    setVerificationCode("");
    setResendAvailableAt(0);
    setError(null);
    window.setTimeout(() => usernameInputRef.current?.focus(), 50);
  };

  const title = isVerifyingEmail ? "验证邮箱" : isRegister ? "注册账号" : "登录账号";
  const description = isVerifyingEmail
    ? `验证码已发送至 ${challenge?.emailMasked ?? "邮箱"}`
    : isRegister
      ? "验证邮箱后创建账号，可使用云端保存与文件分享。"
      : loginHint;

  return (
    <div
      className="auth-dialog-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) closeLogin();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-dialog-title"
        aria-describedby="auth-dialog-description"
        className="app-apple auth-dialog-panel"
      >
        <div className="auth-dialog-brand-row">
          <AppLogo
            label="shuai-tunnel"
            subtitle={isVerifyingEmail ? "邮箱安全验证" : isRegister ? "创建账号" : "安全账号访问"}
            markClassName="h-9 w-9"
          />
          <button
            type="button"
            aria-label="关闭"
            className="auth-dialog-close"
            onClick={closeLogin}
          >
            <svg aria-hidden="true" className="h-4 w-4" fill="none" viewBox="0 0 24 24">
              <path d="M6 6l12 12M6 18L18 6" stroke="currentColor" strokeLinecap="round" strokeWidth="2" />
            </svg>
          </button>
        </div>

        <div className="auth-dialog-intro">
          <h2 id="auth-dialog-title">{title}</h2>
          <p id="auth-dialog-description">{description}</p>
        </div>

        {registrationEnabled && !isVerifyingEmail && (
          <div className="auth-dialog-tabs" role="tablist" aria-label="账号操作">
            {([["login", "登录"], ["register", "注册"]] as const).map(([key, label]) => (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={tab === key}
                className={`auth-dialog-tab${tab === key ? " is-active" : ""}`}
                onClick={() => switchTab(key)}
              >
                {label}
              </button>
            ))}
          </div>
        )}

        <div className="auth-dialog-body">
          {passwordEnabled && (
            <form className="auth-dialog-form" onSubmit={onSubmit}>
              {isVerifyingEmail ? (
                <>
                  <div className="auth-dialog-verification-summary">
                    <p>{username}</p>
                    <p>
                      验证码有效期至 {formatExpiry(challenge?.expiresAt ?? "")}
                    </p>
                  </div>
                  <label className="auth-dialog-field">
                    <span>邮箱验证码</span>
                    <input
                      ref={codeInputRef}
                      className="auth-dialog-input text-center font-mono"
                      value={verificationCode}
                      onChange={(event) => setVerificationCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                      autoComplete="one-time-code"
                      inputMode="numeric"
                      maxLength={6}
                      required
                    />
                  </label>
                </>
              ) : (
                <>
                  <label className="auth-dialog-field">
                    <span>用户名</span>
                    <input
                      ref={usernameInputRef}
                      className="auth-dialog-input"
                      value={username}
                      onChange={(event) => setUsername(event.target.value)}
                      autoComplete="username"
                      inputMode="text"
                      spellCheck={false}
                      maxLength={80}
                      required
                    />
                  </label>
                  {isRegister && (
                    <label className="auth-dialog-field">
                      <span>邮箱</span>
                      <input
                        className="auth-dialog-input"
                        type="email"
                        value={email}
                        onChange={(event) => setEmail(event.target.value)}
                        autoComplete="email"
                        maxLength={254}
                        required
                      />
                    </label>
                  )}
                  <label className="auth-dialog-field">
                    <span>密码</span>
                    <input
                      className="auth-dialog-input"
                      type="password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      autoComplete={isRegister ? "new-password" : "current-password"}
                      maxLength={120}
                      required
                    />
                  </label>
                  {isRegister && (
                    <label className="auth-dialog-field">
                      <span>确认密码</span>
                      <input
                        className="auth-dialog-input"
                        type="password"
                        value={confirmPassword}
                        onChange={(event) => setConfirmPassword(event.target.value)}
                        autoComplete="new-password"
                        maxLength={120}
                        required
                      />
                    </label>
                  )}
                </>
              )}

              {!isVerifyingEmail && oidcConfig?.turnstileEnabled && (
                <div id="auth-turnstile" className="auth-dialog-turnstile" aria-live="polite" />
              )}

              {error && (
                <p className="auth-dialog-error" role="alert">
                  {error}
                </p>
              )}
              <button
                type="submit"
                className="auth-dialog-primary"
                disabled={
                  submitting
                  || (isVerifyingEmail
                    ? verificationCode.length !== 6
                    : !username.trim() || !password || (isRegister && (!email.trim() || !confirmPassword)))
                }
                aria-busy={submitting}
              >
                {submitting
                  ? isVerifyingEmail ? "验证中..." : isRegister ? "发送中..." : "登录中..."
                  : isVerifyingEmail ? "验证并登录" : isRegister ? "发送邮箱验证码" : "登录管理台"}
              </button>

              {isVerifyingEmail && (
                <div className="auth-dialog-inline-actions">
                  <button
                    type="button"
                    className="auth-dialog-text-button"
                    disabled={submitting || resendSeconds > 0}
                    onClick={() => void resendCode()}
                  >
                    {resendSeconds > 0 ? `${resendSeconds} 秒后可重发` : "重新发送验证码"}
                  </button>
                  <button
                    type="button"
                    className="auth-dialog-text-button"
                    disabled={submitting}
                    onClick={editRegistration}
                  >
                    修改注册信息
                  </button>
                </div>
              )}
            </form>
          )}

          {!passwordEnabled && error && (
            <p className="auth-dialog-error" role="alert">
              {error}
            </p>
          )}

          {passwordEnabled && oidcEnabled && !isRegister && (
            <div className="auth-dialog-divider">
              <span />
              <span>或</span>
              <span />
            </div>
          )}

          {oidcEnabled && !isRegister && (
            <button
              type="button"
              className="auth-dialog-secondary"
              disabled={submitting}
              aria-busy={submitting}
              onClick={() => void loginWithOidc()}
            >
              {submitting ? "正在跳转..." : "使用 OIDC 登录"}
            </button>
          )}

          {!passwordEnabled && !oidcEnabled && (
            <p className="auth-dialog-error" role="alert">
              未配置任何登录方式：请设置用户名/密码或 OIDC
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function formatExpiry(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return "稍后";
  return new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit" }).format(timestamp);
}
