import { useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";

const MENU_ITEM_SELECTOR = '[role="menuitem"]:not([disabled])';

/**
 * 页头轻量下拉菜单：不依赖 HeroUI，让落地页/公共页首屏不必加载整个 heroui-vendor。
 * 支持点击外部与 Escape 关闭（焦点归还触发按钮）、↑/↓/Home/End 方向键导航；
 * 只有点到真正的菜单项（role="menuitem"）才自动收起，静态信息区不会误关菜单。
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
  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  // 键盘（↑/↓）打开菜单时记录初始聚焦位置，渲染完成后移焦。
  const initialFocusRef = useRef<"first" | "last" | null>(null);

  const menuItems = () =>
    Array.from(panelRef.current?.querySelectorAll<HTMLElement>(MENU_ITEM_SELECTOR) ?? []);

  useEffect(() => {
    if (!open) {
      return;
    }
    if (initialFocusRef.current) {
      const items = menuItems();
      const target = initialFocusRef.current === "first" ? items[0] : items[items.length - 1];
      initialFocusRef.current = null;
      target?.focus();
    }
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  const onTriggerKeyDown = (event: ReactKeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      initialFocusRef.current = event.key === "ArrowDown" ? "first" : "last";
      setOpen(true);
    }
  };

  const onMenuKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const items = menuItems();
    if (items.length === 0) {
      return;
    }
    const index = items.indexOf(document.activeElement as HTMLElement);
    if (event.key === "ArrowDown") {
      event.preventDefault();
      items[(index + 1) % items.length].focus();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      items[(index - 1 + items.length) % items.length].focus();
    } else if (event.key === "Home") {
      event.preventDefault();
      items[0].focus();
    } else if (event.key === "End") {
      event.preventDefault();
      items[items.length - 1].focus();
    }
  };

  return (
    <div className="header-menu" ref={rootRef}>
      <button
        type="button"
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label={label}
        className={`header-menu-trigger ${triggerClassName}`}
        ref={triggerRef}
        title={title}
        onClick={() => setOpen((value) => !value)}
        onKeyDown={onTriggerKeyDown}
      >
        {trigger}
      </button>
      {open ? (
        <div
          aria-label={label}
          className={`header-menu-panel ${menuClassName}`}
          ref={panelRef}
          role="menu"
          onClick={(event) => {
            // 只有激活菜单项才收起；静态区/分隔线上的点击不关菜单。
            if ((event.target as HTMLElement).closest(MENU_ITEM_SELECTOR)) {
              setOpen(false);
              triggerRef.current?.focus();
            }
          }}
          onKeyDown={onMenuKeyDown}
        >
          {children}
        </div>
      ) : null}
    </div>
  );
}
