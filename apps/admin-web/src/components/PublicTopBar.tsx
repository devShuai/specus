import type { ReactNode } from "react";
import { AppLogo } from "./AppLogo";
import { PUBLIC_TOOLS, PublicToolsMenu, type PublicToolKey } from "./PublicToolsMenu";
import { UserMenuButton } from "./UserMenuButton";
import { Glyph } from "./PublicGlyph";

/**
 * The logged-out top bar of the design: one slim glass bar with the brand mark, the public tools as
 * links (a tools menu on narrow screens) and the account and appearance menu. Sticky, so content
 * passes behind the glass.
 */
export function PublicTopBar({ active, minimal = false }: { active?: PublicToolKey; minimal?: boolean }) {
  return (
    <header className="pub-topbar">
      <div className="pub-topbar-bar">
        <a className="pub-brand" href="/" aria-label="specus 首页">
          <AppLogo label="specus" />
        </a>
        {minimal ? null : (
          <nav className="pub-nav" aria-label="工具">
            {PUBLIC_TOOLS.filter((tool) => tool.key !== "console").map((tool) => (
              <a key={tool.key} href={`/${tool.key}`} aria-current={active === tool.key ? "page" : undefined}>
                <Glyph name={tool.icon} />
                <span>{tool.short}</span>
              </a>
            ))}
          </nav>
        )}
        <div className="pub-topbar-tools">
          {minimal ? null : <PublicToolsMenu active={active} variant="topbar" />}
          <UserMenuButton className="pub-icon-btn" />
        </div>
      </div>
    </header>
  );
}

/** A logged-out page: the design's canvas with its glows, the top bar and a centered column. */
export function PublicPage({ active, minimal, className, children }: {
  active?: PublicToolKey; minimal?: boolean; className?: string; children: ReactNode;
}) {
  return (
    <div className={`bd-root pub-page${className ? ` ${className}` : ""}`}>
      <PublicTopBar active={active} minimal={minimal} />
      <main className="pub-main">{children}</main>
    </div>
  );
}
