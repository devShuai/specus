import { useEffect, useRef, useState, type ReactNode } from "react";

/**
 * 页头轻量下拉菜单：不依赖 HeroUI，让落地页/公共页首屏不必加载整个 heroui-vendor。
 * 支持点击外部与 Escape 关闭；菜单内任意点击后自动收起。
 */
export function HeaderMenu({
  label,
  menuClassName = "",
  title,
  trigger,
  triggerClassName = "",
  children,
}: {
  label: string;
  menuClassName?: string;
  title?: string;
  trigger: ReactNode;
  triggerClassName?: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <div className="header-menu" ref={rootRef}>
      <button
        type="button"
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label={label}
        className={`header-menu-trigger ${triggerClassName}`}
        title={title}
        onClick={() => setOpen((value) => !value)}
      >
        {trigger}
      </button>
      {open ? (
        <div
          aria-label={label}
          className={`header-menu-panel ${menuClassName}`}
          role="menu"
          onClick={() => setOpen(false)}
        >
          {children}
        </div>
      ) : null}
    </div>
  );
}
