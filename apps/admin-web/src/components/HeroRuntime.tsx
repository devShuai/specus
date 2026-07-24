import { HeroUIProvider, ToastProvider } from "@heroui/react";
import type { ReactNode } from "react";

/**
 * HeroUI 运行时容器。主题 class 只由 ThemeContext 写到 <html> 上（E-14），
 * 这里不再重复叠加 theme class，避免同一信息三处维护。
 */
export function HeroRuntime({ children }: { children: ReactNode }) {
  return (
    <HeroUIProvider>
      <div className="app-apple min-h-screen bg-background text-foreground">
        <ToastProvider placement="top-right" toastOffset={12} />
        {children}
      </div>
    </HeroUIProvider>
  );
}
