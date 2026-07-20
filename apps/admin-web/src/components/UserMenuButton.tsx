import { Button, Dropdown, DropdownItem, DropdownMenu, DropdownSection, DropdownTrigger } from "@heroui/react";
import { useAuth } from "../auth/AuthContext";
import { useTheme } from "../theme/ThemeContext";

interface UserMenuButtonProps {
  className?: string;
  size?: "sm" | "md" | "lg";
}

/** 公共页头的账号 + 主题合并菜单按钮，替代原先分开的登录按钮和主题切换按钮。 */
export function UserMenuButton({ className, size = "sm" }: UserMenuButtonProps) {
  const { ready, authed, profile, openLogin, logout } = useAuth();
  const { theme, setTheme, userOverride, resetToSystem } = useTheme();
  const mode = userOverride ? theme : "system";
  const modeLabel = mode === "system" ? "跟随系统" : mode === "dark" ? "深色模式" : "浅色模式";
  const name = profile?.username || "";
  const accountLabel = authed ? `已登录：${name}` : "未登录";

  return (
    <Dropdown placement="bottom-end" shouldBlockScroll={false}>
      <DropdownTrigger>
        <Button
          isIconOnly
          aria-label={`账号与主题：${accountLabel}，主题${modeLabel}`}
          className={`theme-toggle-button ${className ?? ""}`}
          radius="full"
          size={size}
          title={`${accountLabel} · 主题：${modeLabel}`}
          variant="light"
        >
          {authed ? (
            <span className="grid h-5 w-5 place-items-center rounded-full bg-primary-500 text-[10px] font-semibold leading-none text-primary-foreground">
              {name.slice(0, 1).toUpperCase() || "U"}
            </span>
          ) : (
            <UserIcon />
          )}
        </Button>
      </DropdownTrigger>
      <DropdownMenu
        aria-label="账号与主题"
        className="public-header-menu"
        onAction={(key) => {
          if (key === "login") openLogin();
          else if (key === "logout") logout();
          else if (key === "system") resetToSystem();
          else if (key === "light" || key === "dark") setTheme(key);
        }}
      >
        <DropdownSection aria-label="账号" showDivider>
          {authed ? (
            <DropdownItem key="profile" isReadOnly textValue="账号信息">
              <div className="space-y-0.5 py-0.5">
                <div className="text-small font-semibold text-foreground">{name}</div>
                <div className="text-tiny text-default-500">{profile?.admin ? "管理员" : "普通用户"} · 已登录</div>
              </div>
            </DropdownItem>
          ) : (
            <DropdownItem key="login" isDisabled={!ready} startContent={<UserIcon />} textValue="登录">
              {ready ? "登录" : "账号检测中…"}
            </DropdownItem>
          )}
          {authed ? (
            <DropdownItem key="logout" className="text-danger" color="danger" textValue="退出登录">
              退出登录
            </DropdownItem>
          ) : null}
        </DropdownSection>
        <DropdownSection aria-label="主题">
          <DropdownItem key="system" startContent={<SystemIcon />} endContent={mode === "system" ? <CheckIcon /> : null}>
            跟随系统
          </DropdownItem>
          <DropdownItem key="light" startContent={<SunIcon />} endContent={mode === "light" ? <CheckIcon /> : null}>
            浅色模式
          </DropdownItem>
          <DropdownItem key="dark" startContent={<MoonIcon />} endContent={mode === "dark" ? <CheckIcon /> : null}>
            深色模式
          </DropdownItem>
        </DropdownSection>
      </DropdownMenu>
    </Dropdown>
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
