import { mediaKind, type MediaKind } from "../lib/transferPreview";
import type { IconName } from "./ui/Icon";

const KIND_ICON: Record<MediaKind, IconName> = {
  image: "image",
  video: "video",
  audio: "headphones",
  pdf: "file-text",
  text: "file-text",
  document: "file-text",
  archive: "archive",
  file: "file",
};

const KIND_LABEL: Record<MediaKind, string> = {
  image: "图片",
  video: "视频",
  audio: "音频",
  pdf: "PDF",
  text: "文本",
  document: "文档",
  archive: "压缩包",
  file: "文件",
};

/** The design icon for a file in the transfer lists, picked by its name and MIME type. */
export function fileKindIcon(fileName: string, mimeType?: string | null): IconName {
  return KIND_ICON[mediaKind(fileName, mimeType)];
}

/** A short Chinese label for the file's kind, shown next to its size. */
export function fileKindLabel(fileName: string, mimeType?: string | null): string {
  return KIND_LABEL[mediaKind(fileName, mimeType)];
}
