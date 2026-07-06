import type { HttpResponseBodyType, HttpTrafficSearchField, ResourceTrafficUsage } from "../../../api/types";

export const HTTP_EXCHANGE_PAGE_SIZE = 20;
export const TCP_FRAME_PAGE_SIZE = 20;
export const TCP_STREAM_PAGE_SIZE = 200;

export type TrafficViewKey = "client" | "tcp" | "http";

export const TRAFFIC_VIEW_TABS: Array<{ key: TrafficViewKey; label: string }> = [
  { key: "client", label: "客户端汇总" },
  { key: "tcp", label: "TCP 映射" },
  { key: "http", label: "HTTP 路由" },
];

export const TRAFFIC_MODAL_CLASS_NAMES = {
  wrapper: "overflow-hidden p-2 sm:p-4",
  base: "my-0 max-h-[calc(100dvh-2rem)]",
  header: "px-4 py-3 sm:px-5",
  body: "px-4 py-2 sm:px-5",
  footer: "px-4 py-3 sm:px-5",
} as const;

export const HTTP_SEARCH_FIELDS: Array<{ value: HttpTrafficSearchField; label: string; placeholder: string }> = [
  { value: "summary", label: "常用字段", placeholder: "method / 状态 / 路径 / 客户端 / route" },
  { value: "method", label: "请求方法", placeholder: "GET / POST / PUT" },
  { value: "status", label: "状态码", placeholder: "200 / 404 / 500" },
  { value: "path", label: "路径与查询", placeholder: "/api/user 或 keyword" },
  { value: "route", label: "HTTP 路由", placeholder: "route 名称" },
  { value: "client", label: "客户端", placeholder: "客户端名称或 ID" },
  { value: "resource", label: "资源", placeholder: "资源名称或 ID" },
  { value: "remote", label: "远端地址", placeholder: "IP / 端口" },
  { value: "contentType", label: "Content-Type", placeholder: "application/json" },
  { value: "error", label: "错误信息", placeholder: "异常 / timeout / refused" },
  { value: "requestHeaders", label: "请求 Header", placeholder: "Header 名称或值" },
  { value: "responseHeaders", label: "响应 Header", placeholder: "Header 名称或值" },
  { value: "requestBody", label: "请求 Body", placeholder: "请求体内容" },
  { value: "responseBody", label: "响应 Body", placeholder: "响应体内容" },
  { value: "id", label: "记录 ID", placeholder: "记录 ID" },
  { value: "all", label: "全部字段", placeholder: "跨所有字段搜索" },
];

export const HTTP_RESPONSE_BODY_TYPES: Array<{ value: "" | HttpResponseBodyType; label: string }> = [
  { value: "", label: "全部类型" },
  { value: "empty", label: "空响应" },
  { value: "json", label: "JSON" },
  { value: "html", label: "HTML" },
  { value: "xml", label: "XML" },
  { value: "image", label: "图片" },
  { value: "video", label: "视频" },
  { value: "audio", label: "音频" },
  { value: "form", label: "表单" },
  { value: "script", label: "脚本" },
  { value: "text", label: "文本" },
  { value: "binary", label: "二进制" },
];

export const desktopFilterControlClass =
  "h-9 w-full rounded-medium border border-default-200 bg-default-50 px-2 text-small outline-none transition-colors hover:border-default-300 focus:border-primary";

export interface TrafficSummary {
  resources: number;
  uploadBytes: number;
  downloadBytes: number;
  updatedAt: string | null;
}

export interface ResourceTotal {
  key: string;
  name: string;
  clientName: string;
  uploadBytes: number;
  downloadBytes: number;
  totalBytes: number;
  updatedAt: string | null;
}

export type HttpBodyDecodeStatus = "plain" | "pending" | "decoded" | "stored-decoded" | "unsupported" | "failed";

export interface BodyPreviewTarget {
  title: string;
  contentType: string | null;
  contentEncoding: string | null;
  content: string | null;
  bytes: number;
  truncated: boolean;
  decodeMessage: string | null;
  decodeStatus: HttpBodyDecodeStatus;
}

export function aggregateResources(rows: ResourceTrafficUsage[]): ResourceTotal[] {
  const byResource = new Map<string, ResourceTotal>();
  for (const row of rows) {
    const key = `${row.resourceType}:${row.resourceKey}:${row.clientId}`;
    const item = byResource.get(key) ?? {
      key,
      name: row.resourceName,
      clientName: row.clientName,
      uploadBytes: 0,
      downloadBytes: 0,
      totalBytes: 0,
      updatedAt: null,
    };
    item.name = row.resourceName || item.name;
    item.clientName = row.clientName || item.clientName;
    item.uploadBytes += row.uploadBytes;
    item.downloadBytes += row.downloadBytes;
    item.totalBytes = item.uploadBytes + item.downloadBytes;
    item.updatedAt = later(item.updatedAt, row.updatedAt);
    byResource.set(key, item);
  }
  return Array.from(byResource.values()).sort((a, b) => b.totalBytes - a.totalBytes);
}

export function normalizeHttpResponseType(value: string): "" | HttpResponseBodyType {
  return HTTP_RESPONSE_BODY_TYPES.some((type) => type.value === value) ? (value as "" | HttpResponseBodyType) : "";
}

export function httpResponseTypeOption(value: "" | HttpResponseBodyType) {
  return HTTP_RESPONSE_BODY_TYPES.find((type) => type.value === value) ?? HTTP_RESPONSE_BODY_TYPES[0];
}

export function httpResponseTypeLabel(
  value: string | null | undefined,
  contentType: string | null | undefined,
  bytes: number,
): string {
  const normalized = normalizeHttpResponseType(value ?? "") || inferHttpResponseType(contentType, bytes);
  return httpResponseTypeOption(normalized).label;
}

export function httpResponseTypeColor(
  value: string | null | undefined,
  contentType: string | null | undefined,
  bytes: number,
): "default" | "primary" | "secondary" | "success" | "warning" {
  const normalized = normalizeHttpResponseType(value ?? "") || inferHttpResponseType(contentType, bytes);
  if (normalized === "json" || normalized === "html" || normalized === "xml") {
    return "primary";
  }
  if (normalized === "image" || normalized === "video" || normalized === "audio") {
    return "secondary";
  }
  if (normalized === "empty") {
    return "success";
  }
  if (normalized === "binary") {
    return "warning";
  }
  return "default";
}

export function inferHttpResponseType(contentType: string | null | undefined, bytes: number): "" | HttpResponseBodyType {
  if (bytes <= 0) {
    return "empty";
  }
  const mediaType = (contentType ?? "").split(";", 1)[0]?.trim().toLowerCase() ?? "";
  if (!mediaType) {
    return "binary";
  }
  if (mediaType === "application/json" || mediaType.endsWith("+json")) {
    return "json";
  }
  if (mediaType === "text/html") {
    return "html";
  }
  if (mediaType === "application/xml" || mediaType === "text/xml" || mediaType.endsWith("+xml")) {
    return "xml";
  }
  if (mediaType.startsWith("image/")) {
    return "image";
  }
  if (mediaType.startsWith("video/")) {
    return "video";
  }
  if (mediaType.startsWith("audio/")) {
    return "audio";
  }
  if (mediaType === "application/x-www-form-urlencoded" || mediaType === "multipart/form-data") {
    return "form";
  }
  if (mediaType.includes("javascript") || mediaType.includes("ecmascript")) {
    return "script";
  }
  if (mediaType.startsWith("text/")) {
    return "text";
  }
  return "binary";
}

export function normalizeHttpSearchField(value: string): HttpTrafficSearchField {
  return HTTP_SEARCH_FIELDS.some((field) => field.value === value) ? (value as HttpTrafficSearchField) : "summary";
}

export function httpSearchFieldOption(value: HttpTrafficSearchField) {
  return HTTP_SEARCH_FIELDS.find((field) => field.value === value) ?? HTTP_SEARCH_FIELDS[0];
}

export function latestUpdatedAt(rows: Array<{ updatedAt: string }>): string | null {
  return rows.reduce<string | null>((latest, row) => later(latest, row.updatedAt), null);
}

export function later(left: string | null, right: string | null | undefined): string | null {
  if (!right) {
    return left;
  }
  if (!left) {
    return right;
  }
  return new Date(right).getTime() > new Date(left).getTime() ? right : left;
}
