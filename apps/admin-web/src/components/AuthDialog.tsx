import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import type { RegistrationChallengeResponse } from "../api/types";
import { AppLogo } from "./AppLogo";
import { Glyph } from "./PublicGlyph";

/** E-7: 焦点陷阱的选择器；补上 iframe，Turnstile 的挑战 iframe 不会再逃出陷阱。 */
const FOCUSABLE_SELECTOR =
  "input:not([disabled]), button:not([disabled]), [href], iframe, [tabindex]:not([tabindex='-1'])";

/** E-18: 触屏设备打开对话框时不自动聚焦输入框，避免软键盘弹起遮挡表单。 */
function isCoarsePointer(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(pointer: coarse)").matches;
}

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
    startOidcRegistration,
  } = useAuth();
  const [tab, setTab] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [challenge, setChallenge] = useState<RegistrationChallengeResponse | null>(null);
  const [resendAvailableAt, setResendAvailableAt] = useState(0);
  const [clock, setClock] = useState(() => Date.now());
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const usernameInputRef = useRef<HTMLInputElement | null>(null);
  const codeInputRef = useRef<HTMLInputElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);

  const passwordEnabled = oidcConfig?.passwordLoginEnabled ?? true;
  const oidcEnabled = oidcConfig?.configured ?? false;
  const certusRegistrationEnabled = oidcEnabled && Boolean(oidcConfig?.registrationEndpoint);
  const registrationEnabled = (oidcConfig?.registrationEnabled ?? false) && passwordEnabled;
  const isRegister = tab === "register" && registrationEnabled;
  const isVerifyingEmail = isRegister && challenge !== null;
  const resendSeconds = Math.max(0, Math.ceil((resendAvailableAt - clock) / 1000));

  const resetForm = useCallback(() => {
    setUsername("");
    setTenantId("");
    setEmail("");
    setPassword("");
    setConfirmPassword("");
    setVerificationCode("");
    setChallenge(null);
    setResendAvailableAt(0);
    setClock(Date.now());
    setError(null);
    setConfirmError(null);
    setShowPassword(false);
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
      if (isCoarsePointer()) return;
      const firstControl = panelRef.current?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
      (usernameInputRef.current ?? firstControl)?.focus();
    }, 50);
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeLogin();
        return;
      }
      if (event.key !== "Tab") return;
      const controls = Array.from(panelRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR) ?? []);
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
    // E-7: 对话框打开期间把背景主内容设为 inert/aria-hidden，
    // 防止指针与读屏器穿过遮罩操作背后的页面。
    const backdrop = panelRef.current?.parentElement ?? null;
    const inertSiblings: HTMLElement[] = [];
    if (backdrop?.parentElement) {
      for (const sibling of Array.from(backdrop.parentElement.children)) {
        if (sibling !== backdrop && sibling instanceof HTMLElement) {
          sibling.setAttribute("inert", "");
          sibling.setAttribute("aria-hidden", "true");
          inertSiblings.push(sibling);
        }
      }
    }
    return () => {
      window.clearTimeout(focusTimer);
      window.removeEventListener("keydown", onKeyDown);
      body.style.overflow = previousOverflow;
      for (const sibling of inertSiblings) {
        sibling.removeAttribute("inert");
        sibling.removeAttribute("aria-hidden");
      }
      if (focusReturnTarget?.isConnected) focusReturnTarget.focus();
    };
  }, [closeLogin, loginInitialTab, loginOpen, resetForm]);

  useEffect(() => {
    if (!challenge) return;
    setClock(Date.now());
    const focusTimer = window.setTimeout(() => {
      if (!isCoarsePointer()) codeInputRef.current?.focus();
    }, 50);
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
      setConfirmError("两次输入的密码不一致");
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
        await passwordLogin(username.trim(), password, tenantId.trim() || undefined);
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

  const registerWithCertus = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await startOidcRegistration();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Certus 注册跳转失败");
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
    window.setTimeout(() => {
      if (!isCoarsePointer()) usernameInputRef.current?.focus();
    }, 50);
  };

  /** E-6: 确认密码失焦即校验，不等提交。 */
  const validateConfirmOnBlur = () => {
    if (confirmPassword && password !== confirmPassword) {
      setConfirmError("两次输入的密码不一致");
    } else {
      setConfirmError(null);
    }
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
        className="bd-card jd-login-card auth-dialog-panel"
      >
        <div className="auth-dialog-head">
          <AppLogo
            label="specus"
            subtitle={isVerifyingEmail ? "邮箱安全验证" : isRegister ? "创建账号" : "安全账号访问"}
          />
          <button
            type="button"
            aria-label="关闭"
            className="bd-icon-btn auth-dialog-close"
            onClick={closeLogin}
          >
            <Glyph name="x" size={18} />
          </button>
        </div>

        <div className="auth-dialog-body">
          <div className="auth-dialog-intro">
            <h2 id="auth-dialog-title" className="jd-login-title">{title}</h2>
            <p id="auth-dialog-description" className="auth-dialog-sub">{description}</p>
          </div>

          {registrationEnabled && !isVerifyingEmail && (
            // E-15: 这里不是完整的 APG tab 模式（无 tabpanel/方向键漫游），
            // 降级为 aria-pressed 切换按钮组（设计规范的 Segmented），语义更诚实。
            <div className="bd-seg bd-seg--md auth-dialog-seg" role="group" aria-label="账号操作">
              {([["login", "登录"], ["register", "注册"]] as const).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  aria-pressed={tab === key}
                  onClick={() => switchTab(key)}
                >
                  {label}
                </button>
              ))}
            </div>
          )}

          {passwordEnabled && (
            <form className="jd-login-form" onSubmit={onSubmit}>
              {isVerifyingEmail ? (
                <>
                  <div className="auth-dialog-verification">
                    <Glyph name="send" />
                    <div className="min-w-0">
                      <p className="auth-dialog-verification-name">{username}</p>
                      <p className="auth-dialog-verification-meta">
                        验证码有效期至 <span className="bd-num">{formatExpiry(challenge?.expiresAt ?? "")}</span>
                      </p>
                    </div>
                  </div>
                  <label className="bd-field">
                    <span className="bd-label">邮箱验证码</span>
                    <input
                      ref={codeInputRef}
                      className="bd-input jd-input-lg auth-dialog-code-input"
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
                  {!isRegister && (
                    <label className="bd-field">
                      <span className="bd-label">
                        租户 ID<span className="bd-form-opt">（非默认租户填写）</span>
                      </span>
                      <input
                        className="bd-input jd-input-lg"
                        value={tenantId}
                        onChange={(event) => setTenantId(event.target.value)}
                        autoComplete="organization"
                        inputMode="text"
                        spellCheck={false}
                        maxLength={80}
                      />
                    </label>
                  )}
                  <label className="bd-field">
                    <span className="bd-label">用户名</span>
                    <input
                      ref={usernameInputRef}
                      className="bd-input jd-input-lg"
                      value={username}
                      onChange={(event) => setUsername(event.target.value)}
                      autoComplete="username"
                      inputMode="text"
                      spellCheck={false}
                      maxLength={80}
                      required
                      aria-invalid={error ? true : undefined}
                      aria-describedby={error ? "auth-dialog-error" : undefined}
                    />
                  </label>
                  {isRegister && (
                    <label className="bd-field">
                      <span className="bd-label">邮箱</span>
                      <input
                        className="bd-input jd-input-lg"
                        type="email"
                        value={email}
                        onChange={(event) => setEmail(event.target.value)}
                        autoComplete="email"
                        maxLength={254}
                        required
                        aria-invalid={error ? true : undefined}
                        aria-describedby={error ? "auth-dialog-error" : undefined}
                      />
                    </label>
                  )}
                  <label className="bd-field">
                    <span className="bd-label">密码</span>
                    <div className="auth-dialog-password">
                      <input
                        className="bd-input jd-input-lg"
                        type={showPassword ? "text" : "password"}
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        autoComplete={isRegister ? "new-password" : "current-password"}
                        maxLength={120}
                        required
                        aria-invalid={error ? true : undefined}
                        aria-describedby={error ? "auth-dialog-error" : undefined}
                      />
                      <button
                        type="button"
                        className="bd-icon-btn auth-dialog-password-toggle"
                        aria-label={showPassword ? "隐藏密码" : "显示密码"}
                        aria-pressed={showPassword}
                        onClick={() => setShowPassword((value) => !value)}
                      >
                        <Glyph name={showPassword ? "eye-off" : "eye"} />
                      </button>
                    </div>
                  </label>
                  {isRegister && (
                    <label className="bd-field">
                      <span className="bd-label">确认密码</span>
                      <div className="auth-dialog-password">
                        <input
                          className="bd-input jd-input-lg"
                          type={showPassword ? "text" : "password"}
                          value={confirmPassword}
                          onChange={(event) => {
                            setConfirmPassword(event.target.value);
                            if (confirmError) setConfirmError(null);
                          }}
                          onBlur={validateConfirmOnBlur}
                          autoComplete="new-password"
                          maxLength={120}
                          required
                          aria-invalid={confirmError ? true : undefined}
                          aria-describedby={confirmError ? "auth-dialog-confirm-error" : undefined}
                        />
                        <button
                          type="button"
                          className="bd-icon-btn auth-dialog-password-toggle"
                          aria-label={showPassword ? "隐藏密码" : "显示密码"}
                          aria-pressed={showPassword}
                          onClick={() => setShowPassword((value) => !value)}
                        >
                          <Glyph name={showPassword ? "eye-off" : "eye"} />
                        </button>
                      </div>
                      {confirmError && (
                        <p className="bd-help bd-help--error" id="auth-dialog-confirm-error" role="alert">
                          {confirmError}
                        </p>
                      )}
                    </label>
                  )}
                </>
              )}

              {oidcConfig?.turnstileEnabled && (
                <div id="auth-turnstile" className="auth-dialog-turnstile" aria-live="polite" />
              )}

              {error && (
                <div className="bd-alert bd-alert--danger auth-dialog-error" id="auth-dialog-error" role="alert">
                  <Glyph name="circle-alert" />
                  <div className="bd-alert-title">{error}</div>
                </div>
              )}
              <button
                type="submit"
                className={`bd-btn bd-btn--primary bd-btn--lg jd-login-submit${submitting ? " is-busy" : ""}`}
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
                    className="bd-btn bd-btn--ghost bd-btn--sm"
                    disabled={submitting || resendSeconds > 0}
                    onClick={() => void resendCode()}
                  >
                    <Glyph name="refresh" />
                    <span>{resendSeconds > 0 ? `${resendSeconds} 秒后可重发` : "重新发送验证码"}</span>
                  </button>
                  <button
                    type="button"
                    className="bd-btn bd-btn--ghost bd-btn--sm"
                    disabled={submitting}
                    onClick={editRegistration}
                  >
                    <Glyph name="edit" />
                    <span>修改注册信息</span>
                  </button>
                </div>
              )}
            </form>
          )}

          {!passwordEnabled && error && (
            <div className="bd-alert bd-alert--danger auth-dialog-error" role="alert">
              <Glyph name="circle-alert" />
              <div className="bd-alert-title">{error}</div>
            </div>
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
              className="bd-btn bd-btn--secondary bd-btn--lg jd-login-submit"
              disabled={submitting}
              aria-busy={submitting}
              onClick={() => void loginWithOidc()}
            >
              <Glyph name="key" />
              <span>{submitting ? "正在跳转..." : "使用 OIDC 登录"}</span>
            </button>
          )}

          {certusRegistrationEnabled && !isRegister && (
            <button
              type="button"
              className="bd-btn bd-btn--secondary bd-btn--lg jd-login-submit"
              disabled={submitting}
              aria-busy={submitting}
              onClick={() => void registerWithCertus()}
            >
              <Glyph name="user" />
              <span>{submitting ? "正在跳转..." : "注册 Certus 账号"}</span>
            </button>
          )}

          {!passwordEnabled && !oidcEnabled && (
            <div className="bd-alert bd-alert--danger auth-dialog-error" role="alert">
              <Glyph name="circle-alert" />
              <div>
                <div className="bd-alert-title">未配置任何登录方式</div>
                <div className="bd-alert-body">在服务端设置用户名/密码或 OIDC 后再登录。</div>
              </div>
            </div>
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
