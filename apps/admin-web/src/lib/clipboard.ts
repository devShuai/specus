import { notify } from "../components/toast";

/**
 * 复制文本到剪贴板，带完整失败兜底：
 * - 优先 navigator.clipboard（需要安全上下文）
 * - 降级 execCommand("copy")（http 内网部署）
 * - 全部失败返回 false，由调用方提示用户手动复制
 */
export async function copyTextToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // 权限被拒时继续走降级路径
  }
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}

/** 复制并 toast 反馈结果；失败时提示用户手动复制。 */
export async function copyTextWithFeedback(text: string, successMessage = "已复制"): Promise<boolean> {
  const ok = await copyTextToClipboard(text);
  if (ok) {
    notify(successMessage);
  } else {
    notify("复制失败，请手动选择文本复制", "error");
  }
  return ok;
}
