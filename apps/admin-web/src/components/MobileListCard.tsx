import type { KeyboardEvent, ReactNode } from "react";

/**
 * 移动端列表卡片模板。桌面端继续用表格，窄屏下用卡片堆叠。
 *
 * 设计规范的卡片（bd-card：surface 底、发丝线、radius-xl）：标题 + 可选副标题 + 可选标签行 +
 * 名称/取值字段表 + 底部操作行。样式在 styles/area-access.css 的 app-list-card 一节。
 *
 *  - 字段表左列固定宽度的 text-subtle 名称，右列取值可换行；数字用等宽数字。
 *  - 操作行 flex-wrap，按钮多时自动换行；危险操作放在最后。
 *  - 卡片本身不固定宽度，跟随父容器流式布局。
 */
export interface MobileListCardField {
  label: string;
  value: ReactNode;
}

export interface MobileListCardProps {
  title: ReactNode;
  subtitle?: ReactNode;
  badges?: ReactNode;
  fields?: MobileListCardField[];
  actions?: ReactNode;
  /** 主要内容区下方可插入自定义节点（譬如带预览的 hex/text 块）。 */
  extra?: ReactNode;
  /** 整张卡可点击时传 onPress，光标变 pointer。 */
  onPress?: () => void;
}

export function MobileListCard({
  title,
  subtitle,
  badges,
  fields,
  actions,
  extra,
  onPress,
}: MobileListCardProps) {
  const clickable = typeof onPress === "function";
  const pressProps = clickable
    ? {
      role: "button",
      tabIndex: 0,
      onClick: onPress,
      onKeyDown: (event: KeyboardEvent<HTMLElement>) => {
        if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) {
          event.preventDefault();
          onPress?.();
        }
      },
    }
    : {};
  return (
    <article className={`bd-card app-list-card${clickable ? " is-pressable" : ""}`} {...pressProps}>
      <div className="app-list-card-head">
        <div className="app-list-card-title">{title}</div>
        {subtitle ? <div className="app-list-card-sub">{subtitle}</div> : null}
      </div>
      {badges ? <div className="app-list-card-badges">{badges}</div> : null}
      {fields && fields.length > 0 ? (
        <dl className="app-list-card-fields">
          {fields.map((field) => (
            <FieldRow key={field.label} label={field.label} value={field.value} />
          ))}
        </dl>
      ) : null}
      {extra}
      {actions ? <div className="app-list-card-actions">{actions}</div> : null}
    </article>
  );
}

function FieldRow({ label, value }: MobileListCardField) {
  return (
    <div className="app-list-card-field">
      <dt>{label}</dt>
      <dd className="bd-num">{value ?? <span className="jd-subtle">—</span>}</dd>
    </div>
  );
}

/**
 * 卡片列表容器：负责加载态、空态、内边距统一。
 */
export function MobileListCardList({
  items,
  isLoading,
  emptyContent,
  renderCard,
}: {
  items: unknown[];
  isLoading?: boolean;
  emptyContent?: ReactNode;
  renderCard: (item: unknown, index: number) => ReactNode;
}) {
  if (isLoading && items.length === 0) {
    return (
      <div className="bd-card app-list-card-state" role="status">
        <span className="bd-skeleton" />
        <span className="bd-skeleton app-list-card-skeleton-short" />
        <span className="bd-skeleton-note">正在加载…</span>
      </div>
    );
  }
  if (!isLoading && items.length === 0) {
    return <div className="bd-card app-list-card-state">{emptyContent ?? <p className="jd-muted">还没有数据</p>}</div>;
  }
  return (
    <div className="app-list-card-list">
      {items.map((item, index) => renderCard(item, index))}
    </div>
  );
}
