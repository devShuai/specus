import { useAuth } from "../auth/AuthContext";
import { useTheme } from "../theme/ThemeContext";
import { HeaderMenu } from "./HeaderMenu";

/** 公共页头的账号 + 主题合并菜单按钮，替代原先分开的登录按钮和主题切换按钮。 */
export function UserMenuButton({ className }: { className?: string }) {
  const { ready, authed, profile, openLogin, logout } = useAuth();
  const { theme, setTheme, userOverride, resetToSystem } = useTheme();
  const mode = userOverride ? theme : "system";
  const modeLabel = mode === "system" ? "跟随系统" : mode === "dark" ? "深色模式" : "浅色模式";
  const name = profile?.username || "";
  const accountLabel = authed ? `已登录：${name}` : "未登录";

  return (
    <HeaderMenu
      label={`账号与主题：${accountLabel}，主题${modeLabel}`}
      menuClassName="public-header-menu"
      title={`${accountLabel} · 主题：${modeLabel}`}
      triggerClassName={`theme-toggle-button ${className ?? ""}`}
      trigger={
        authed ? (
          <span className="grid h-5 w-5 place-items-center rounded-full bg-primary-500 text-[10px] font-semibold leading-none text-primary-foreground">
            {name.slice(0, 1).toUpperCase() || "U"}
          </span>
        ) : (
          <UserIcon />
        )
      }
    >
      {authed ? (
        <>
          <div className="header-menu-static space-y-0.5" role="presentation" onClick={(event) => event.stopPropagation()}>
            <div className="text-small font-semibold text-foreground">{name}</div>
            <div className="text-tiny text-default-500">{profile?.admin ? "管理员" : "普通用户"} · 已登录</div>
          </div>
          <button type="button" className="header-menu-item header-menu-item-danger" role="menuitem" onClick={() => logout()}>
            退出登录
          </button>
        </>
      ) : (
        <button type="button" className="header-menu-item" disabled={!ready} role="menuitem" onClick={() => openLogin()}>
          <UserIcon />
          <span className="flex-1">{ready ? "登录" : "账号检测中…"}</span>
        </button>
      )}
      <div className="header-menu-divider" role="separator" />
      <button type="button" className="header-menu-item" role="menuitem" onClick={() => resetToSystem()}>
        <SystemIcon />
        <span className="flex-1">跟随系统</span>
        {mode === "system" ? <CheckIcon /> : null}
      </button>
      <button type="button" className="header-menu-item" role="menuitem" onClick={() => setTheme("light")}>
        <SunIcon />
        <span className="flex-1">浅色模式</span>
        {mode === "light" ? <CheckIcon /> : null}
      </button>
      <button type="button" className="header-menu-item" role="menuitem" onClick={() => setTheme("dark")}>
        <MoonIcon />
        <span className="flex-1">深色模式</span>
        {mode === "dark" ? <CheckIcon /> : null}
      </button>
    </HeaderMenu>
  );
}

function UserIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" fill="none" viewBox="0 0 24 24">
      <path
        d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM4.5 20.4c.9-3.3 3.9-5.4 7.5-5.4s6.6 2.1 7.5 5.4"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

function SystemIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" fill="none" viewBox="0 0 24 24">
      <rect x="3" y="4" width="18" height="13" rx="2" stroke="currentColor" strokeWidth="1.8" />
      <path d="M8 21h8M12 17v4" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
    </svg>
  );
}

function SunIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" fill="none" viewBox="0 0 24 24">
      <path
        d="M12 4V2M12 22v-2M4.93 4.93 3.52 3.52M20.48 20.48l-1.41-1.41M4 12H2M22 12h-2M4.93 19.07l-1.41 1.41M20.48 3.52l-1.41 1.41M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" fill="none" viewBox="0 0 24 24">
      <path
        d="M20.25 14.15A7.75 7.75 0 0 1 9.85 3.75 8.5 8.5 0 1 0 20.25 14.15Z"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4 text-primary" fill="none" viewBox="0 0 24 24">
      <path d="m5 12 4 4L19 6" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2" />
    </svg>
  );
}
