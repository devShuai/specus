import { useAuth } from "../auth/AuthContext";
import { useTheme } from "../theme/ThemeContext";
import { HeaderMenu } from "./HeaderMenu";
import { Glyph } from "./PublicGlyph";

/** 公共页头的账号 + 主题合并菜单按钮（设计规范的 Menu 组件），替代原先分开的登录按钮和主题切换按钮。 */
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
          <span className="bd-avatar bd-avatar--sm user-menu-avatar">{name.slice(0, 1).toUpperCase() || "U"}</span>
        ) : (
          <Glyph name="user" size={18} />
        )
      }
    >
      {authed ? (
        <>
          <div className="header-menu-static" role="presentation" onClick={(event) => event.stopPropagation()}>
            <div className="header-menu-static-name">{name}</div>
            <div className="header-menu-static-meta">{profile?.admin ? "管理员" : "普通用户"} · 已登录</div>
          </div>
          <button type="button" className="header-menu-item header-menu-item-danger" role="menuitem" onClick={() => logout()}>
            <Glyph name="logout" />
            <span className="flex-1">退出登录</span>
          </button>
        </>
      ) : (
        <button type="button" className="header-menu-item" disabled={!ready} role="menuitem" onClick={() => openLogin()}>
          <Glyph name="user" />
          <span className="flex-1">{ready ? "登录" : "账号检测中…"}</span>
        </button>
      )}
      <div className="header-menu-divider" role="separator" />
      <div className="header-menu-label" role="presentation">外观</div>
      <button type="button" className="header-menu-item" role="menuitem" onClick={() => resetToSystem()}>
        <Glyph name="monitor" />
        <span className="flex-1">跟随系统</span>
        {mode === "system" ? <Glyph name="check" className="header-menu-check" /> : null}
      </button>
      <button type="button" className="header-menu-item" role="menuitem" onClick={() => setTheme("light")}>
        <Glyph name="sun" />
        <span className="flex-1">浅色模式</span>
        {mode === "light" ? <Glyph name="check" className="header-menu-check" /> : null}
      </button>
      <button type="button" className="header-menu-item" role="menuitem" onClick={() => setTheme("dark")}>
        <Glyph name="moon" />
        <span className="flex-1">深色模式</span>
        {mode === "dark" ? <Glyph name="check" className="header-menu-check" /> : null}
      </button>
    </HeaderMenu>
  );
}
