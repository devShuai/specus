import type { ReactNode } from "react";

export interface PageHeaderProps {
  title: string;
  /** One line under the title saying what the page is for. */
  description?: ReactNode;
  /** Shown next to the title, e.g. a count. */
  meta?: ReactNode;
  /** Page-level actions, right-aligned (primary action last). */
  actions?: ReactNode;
}

/** PageHeader of the design (bd-page-header): one 30px title per page, a short description and the page's actions. */
export function PageHeader({ title, description, meta, actions }: PageHeaderProps) {
  return (
    <header className="bd-page-header">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="bd-page-title">{title}</h1>
          {meta}
        </div>
        {description ? <p className="bd-page-desc max-w-3xl">{description}</p> : null}
      </div>
      {actions ? <div className="bd-page-actions">{actions}</div> : null}
    </header>
  );
}
