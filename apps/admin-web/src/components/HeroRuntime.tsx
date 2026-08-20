import { ToastProvider } from "@heroui/react";
import type { ReactNode } from "react";

/**
 * HeroUI 运行时容器。主题 class 只由 ThemeContext 写到 <html> 上（E-14），
 * 这里不再重复叠加 theme class，避免同一信息三处维护。
 *
 * HeroUI 3 不再需要 HeroUIProvider：主题标定走 CSS 变量，组件各自读取，
 * 只有 toast 需要一个挂载区域。
 */
export function HeroRuntime({ children }: { children: ReactNode }) {
  return (
    <div className="app-apple min-h-screen bg-background text-foreground">
      <ToastProvider placement="top end" />
      {children}
    </div>
  );
}
