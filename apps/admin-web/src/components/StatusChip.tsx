import { Chip } from "@heroui/react";
import type { ReactNode } from "react";

/**
 * 全站状态色彩语义约定：
 * - success：在线 / 启用 / 正常 / 成功
 * - warning：降级 / 部分可用 / 需要注意（非错误）
 * - danger：失败 / 错误 / 离线异常（不用于普通"停用"）
 * - default：停用 / 离线（中性）/ 未配置
 * - primary / secondary：信息性标记，不表达健康度
 */
export type StatusTone = "success" | "warning" | "danger" | "default" | "primary" | "secondary";

export interface StatusChipProps {
  tone?: StatusTone;
  children: ReactNode;
  className?: string;
}

/** 统一的状态徽章：固定 size/variant，颜色只能从语义 tone 进入。 */
export function StatusChip({ tone = "default", children, className = "" }: StatusChipProps) {
  return (
    <Chip size="sm" variant="flat" color={tone} className={className}>
      {children}
    </Chip>
  );
}

/** 启用/停用的标准 tone：停用不闯红灯。 */
export function enabledTone(enabled: boolean): StatusTone {
  return enabled ? "success" : "default";
}

/** 在线状态 tone：停用优先于在线，避免"已停用但在线"显示绿色。 */
export function onlineTone(online: boolean, disabled = false): StatusTone {
  if (disabled) return "default";
  return online ? "success" : "default";
}
