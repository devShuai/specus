import { HeroUIProvider, ToastProvider } from "@heroui/react";
import type { ReactNode } from "react";
import { useTheme } from "../theme/ThemeContext";

export function HeroRuntime({ children }: { children: ReactNode }) {
  const { theme } = useTheme();

  return (
    <HeroUIProvider className={theme}>
      <div className={`${theme} min-h-screen bg-background text-foreground`}>
        <ToastProvider placement="top-right" toastOffset={12} />
        {children}
      </div>
    </HeroUIProvider>
  );
}
