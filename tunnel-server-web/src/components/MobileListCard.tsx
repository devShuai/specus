import type { ReactNode } from "react";
import { Card, CardBody } from "@heroui/react";

/**
 * 移动端列表卡片模板。桌面端继续用 <Table>，< lg 断点下用卡片堆叠。
 *
 * 字段格式：title + 可选 subtitle + 可选 chip 行 + label-value 字段表 + 底部操作行。
 *
 * 设计要点：
 *  - grid-cols-[80px_1fr] 左侧标签固定宽度，右侧 value 允许换行、截断。
 *  - actions 行用 flex-wrap，按钮多时自动换行。
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
  return (
    <Card
      shadow="none"
      isPressable={clickable}
      onPress={onPress}
      className={`w-full rounded-md border border-default-200 bg-content1 ${
        clickable ? "cursor-pointer hover:border-primary" : ""
      }`}
    >
      <CardBody className="gap-3 p-3">
        <div className="flex flex-col gap-1">
          <div className="min-w-0 break-words text-small font-semibold text-foreground">{title}</div>
          {subtitle ? (
            <div className="min-w-0 break-words text-tiny text-default-500">{subtitle}</div>
          ) : null}
        </div>
        {badges ? <div className="flex flex-wrap gap-1.5">{badges}</div> : null}
        {fields && fields.length > 0 ? (
          <div className="grid grid-cols-[80px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-tiny">
            {fields.map((field, index) => (
              <FieldRow key={index} label={field.label} value={field.value} />
            ))}
          </div>
        ) : null}
        {extra}
        {actions ? <div className="flex flex-wrap items-center gap-2 pt-1">{actions}</div> : null}
      </CardBody>
    </Card>
  );
}

function FieldRow({ label, value }: MobileListCardField) {
  return (
    <>
      <div className="text-default-500">{label}</div>
      <div className="min-w-0 break-words text-foreground">{value ?? <span className="text-default-400">-</span>}</div>
    </>
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
      <div className="rounded-md border border-default-200 bg-content1 p-6 text-center text-small text-default-500">
        加载中…
      </div>
    );
  }
  if (!isLoading && items.length === 0) {
    return (
      <div className="rounded-md border border-default-200 bg-content1 p-6 text-center text-small text-default-500">
        {emptyContent ?? "暂无数据"}
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-2">
      {items.map((item, index) => renderCard(item, index))}
    </div>
  );
}
