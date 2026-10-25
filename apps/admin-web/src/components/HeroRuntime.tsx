import { HeroUIProvider, ToastProvider } from "@heroui/react";
import type { ReactNode } from "react";

// Toasts follow the design's Toast component: dark translucent glass at the top center.
const toastProps = {
  radius: "lg" as const,
  classNames: {
    base: "app-toast",
    title: "app-toast-title",
    description: "app-toast-desc",
    closeButton: "app-toast-close",
  },
};

/**
 * HeroUI 运行时容器。主题 class 只由 ThemeContext 写到 <html> 上（E-14），
 * 这里不再重复叠加 theme class，避免同一信息三处维护。
 * 字段标签统一放在输入框上方（设计规范的 Input 组件）。
 */
export function HeroRuntime({ children }: { children: ReactNode }) {
  return (
    <HeroUIProvider labelPlacement="outside-top">
      <div className="app-apple min-h-screen bg-background text-foreground">
        <ToastProvider placement="top-center" toastOffset={16} toastProps={toastProps} />
        {children}
      </div>
    </HeroUIProvider>
  );
}
