import type { DiagramNodeKind } from "../../lib/diagramDocument";
import { isDiagramNodeKind } from "./paletteCatalog";

/**
 * 编辑器 UI 偏好的本地存储读写。
 *
 * 这些偏好都是非关键项：浏览器禁用存储（无痕模式、被策略限制）时读取应回退到默认值、
 * 写入应静默失败，绝不能因此中断编辑流程。
 */

export function readDiagramNodeKindList(key: string): DiagramNodeKind[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(key) ?? "[]");
    return Array.isArray(parsed) ? parsed.filter(isDiagramNodeKind).slice(0, 24) : [];
  } catch {
    return [];
  }
}

export function writeDiagramNodeKindList(key: string, values: DiagramNodeKind[]) {
  try {
    localStorage.setItem(key, JSON.stringify(values));
  } catch {
    // Preferences remain available in memory when browser storage is unavailable.
  }
}

export function readDiagramPanelWidth(key: string, fallback: number, min: number, max: number) {
  try {
    const value = Number(localStorage.getItem(key));
    return Number.isFinite(value) && value >= min && value <= max ? value : fallback;
  } catch {
    return fallback;
  }
}

export function writeDiagramPanelWidth(key: string, width: number) {
  try {
    localStorage.setItem(key, String(Math.round(width)));
  } catch {
    // Width preference is nonessential.
  }
}

export function readDiagramBooleanPreference(key: string): boolean | null {
  try {
    const value = localStorage.getItem(key);
    if (value === "true") return true;
    if (value === "false") return false;
  } catch {
    // UI preferences are nonessential.
  }
  return null;
}

export function writeDiagramBooleanPreference(key: string, value: boolean) {
  try {
    localStorage.setItem(key, String(value));
  } catch {
    // UI preferences are nonessential.
  }
}
