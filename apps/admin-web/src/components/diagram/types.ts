import type { CellStyle } from "@maxgraph/core";
import type { DiagramNodeKind } from "../../lib/diagramDocument";

/**
 * 流程图编辑器的共享类型。
 *
 * 这里只放跨模块使用的契约；仅主组件内部使用的类型仍留在组件文件里，避免无谓的公开面。
 */

/** 对话框返回值：文本输入返回字符串，确认返回 true，取消返回 null。 */
export type DiagramDialogResult = string | true | null;

/** 状态栏语气。错误语气应由调用点显式指定，不要依赖文案推断。 */
export type DiagramStatusTone = "info" | "success" | "error";

export interface DiagramDialogRequest {
  id: number;
  kind: "confirm" | "text";
  title: string;
  message?: string;
  inputLabel?: string;
  initialValue?: string;
  placeholder?: string;
  maxLength?: number;
  multiline?: boolean;
  confirmLabel?: string;
  tone?: "default" | "danger";
}

/** 本项目在 maxGraph CellStyle 上附加的自定义键。 */
export type DiagramCellStyle = CellStyle & {
  diagramKind?: DiagramNodeKind;
  diagramStencilName?: string;
  diagramStencilLibrary?: string;
  connectable?: boolean;
  collapsible?: boolean;
  recursiveResize?: boolean;
  diagramLocked?: boolean;
  diagramCubicControl1T?: number;
  diagramCubicControl1N?: number;
  diagramCubicControl2T?: number;
  diagramCubicControl2N?: number;
};
