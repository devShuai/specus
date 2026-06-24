import { Button, Tooltip } from "@heroui/react";
import { useTheme } from "../theme/ThemeContext";

interface ThemeToggleButtonProps {
  className?: string;
  size?: "sm" | "md" | "lg";
}

export function ThemeToggleButton({ className, size = "sm" }: ThemeToggleButtonProps) {
  const { theme, toggleTheme } = useTheme();
  const nextThemeLabel = theme === "dark" ? "切换到浅色模式" : "切换到深色模式";

  return (
    <Tooltip content={nextThemeLabel} placement="bottom">
      <Button
        isIconOnly
        aria-label={nextThemeLabel}
        className={className}
        radius="sm"
        size={size}
        variant="flat"
        onPress={toggleTheme}
      >
        {theme === "dark" ? <SunIcon /> : <MoonIcon />}
      </Button>
    </Tooltip>
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
