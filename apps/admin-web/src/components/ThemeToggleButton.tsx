import { Button, Dropdown, DropdownItem, DropdownMenu, DropdownTrigger } from "@heroui/react";
import { useTheme } from "../theme/ThemeContext";

interface ThemeToggleButtonProps {
  className?: string;
  size?: "sm" | "md" | "lg";
}

export function ThemeToggleButton({ className, size = "sm" }: ThemeToggleButtonProps) {
  const { theme, setTheme, userOverride, resetToSystem } = useTheme();
  const mode = userOverride ? theme : "system";
  const modeLabel = mode === "system" ? "跟随系统" : mode === "dark" ? "深色模式" : "浅色模式";

  return (
    <Dropdown placement="bottom-end" shouldBlockScroll={false}>
      <DropdownTrigger>
        <Button
          isIconOnly
          aria-label={`主题模式：${modeLabel}`}
          className={`theme-toggle-button ${className ?? ""}`}
          radius="full"
          size={size}
          title={`主题：${modeLabel}`}
          variant="light"
        >
          {mode === "system" ? <SystemIcon /> : theme === "dark" ? <SunIcon /> : <MoonIcon />}
        </Button>
      </DropdownTrigger>
      <DropdownMenu
        aria-label="主题模式"
        className="public-header-menu"
        onAction={(key) => {
          if (key === "system") resetToSystem();
          else if (key === "light" || key === "dark") setTheme(key);
        }}
      >
        <DropdownItem key="system" startContent={<SystemIcon />} endContent={mode === "system" ? <CheckIcon /> : null}>
          跟随系统
        </DropdownItem>
        <DropdownItem key="light" startContent={<SunIcon />} endContent={mode === "light" ? <CheckIcon /> : null}>
          浅色模式
        </DropdownItem>
        <DropdownItem key="dark" startContent={<MoonIcon />} endContent={mode === "dark" ? <CheckIcon /> : null}>
          深色模式
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
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
