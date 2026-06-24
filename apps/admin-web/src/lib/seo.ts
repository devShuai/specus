/**
 * 单页应用的 SEO 工具：动态更新 <title>、meta description、canonical、og/twitter
 * 和路由级 JSON-LD。
 *
 * <p>Vite + React SPA 默认只在 index.html 写一份静态 SEO，搜索引擎抓到的标题描述都一样，
 * 子页面（如 NAT 检测）拿不到独立的 ranking 信号。本工具在挂载和卸载时切换 head 标签：
 *
 * <ul>
 *   <li>{@code applyPageSeo(spec)} —— 覆写一组 SEO 字段，返回还原函数</li>
 *   <li>{@code usePageSeo(spec)} —— React hook，组件卸载或 spec 变化时自动还原</li>
 * </ul>
 */
import { useEffect } from "react";

export interface PageSeo {
  title: string;
  description: string;
  canonical?: string;
  keywords?: string;
  ogImage?: string;
  /** 整段 JSON-LD 对象，会序列化为 <script type="application/ld+json"> */
  jsonLd?: Record<string, unknown> | Record<string, unknown>[];
}

const DEFAULT_DESCRIPTION =
  "shuai-tunnel 是一套自托管的内网穿透控制面，支持 TCP 端口映射、HTTP 反向代理（含路径改写）、私有组网对端互联与浏览器 NAT 类型检测，自带 Java / Go / .NET 多语言客户端。";

const SEO_MARK_ATTR = "data-seo-runtime";
const JSONLD_MARK_ATTR = "data-seo-jsonld";

function setMeta(selector: string, attr: "content" | "href", value: string) {
  let el = document.head.querySelector<HTMLMetaElement | HTMLLinkElement>(selector);
  if (!el) {
    if (selector.startsWith("link")) {
      el = document.createElement("link");
      const rel = selector.match(/rel="([^"]+)"/)?.[1];
      if (rel) {
        (el as HTMLLinkElement).rel = rel;
      }
    } else {
      el = document.createElement("meta");
      const name = selector.match(/name="([^"]+)"/)?.[1];
      const property = selector.match(/property="([^"]+)"/)?.[1];
      if (name) {
        (el as HTMLMetaElement).name = name;
      } else if (property) {
        el.setAttribute("property", property);
      }
    }
    el.setAttribute(SEO_MARK_ATTR, "1");
    document.head.appendChild(el);
  }
  el.setAttribute(attr, value);
}

function removeRuntimeJsonLd() {
  document.head.querySelectorAll(`script[${JSONLD_MARK_ATTR}]`).forEach((node) => node.remove());
}

function appendJsonLd(payload: PageSeo["jsonLd"]) {
  if (!payload) {
    return;
  }
  const items = Array.isArray(payload) ? payload : [payload];
  for (const item of items) {
    const script = document.createElement("script");
    script.type = "application/ld+json";
    script.setAttribute(JSONLD_MARK_ATTR, "1");
    script.text = JSON.stringify(item);
    document.head.appendChild(script);
  }
}

export function applyPageSeo(spec: PageSeo): () => void {
  const previousTitle = document.title;
  const previousDescription = document.head
    .querySelector<HTMLMetaElement>('meta[name="description"]')
    ?.content ?? DEFAULT_DESCRIPTION;
  const previousCanonical = document.head
    .querySelector<HTMLLinkElement>('link[rel="canonical"]')
    ?.href ?? `${window.location.origin}/`;
  const previousKeywords = document.head
    .querySelector<HTMLMetaElement>('meta[name="keywords"]')
    ?.content;
  const previousOgTitle = document.head
    .querySelector<HTMLMetaElement>('meta[property="og:title"]')
    ?.content ?? previousTitle;
  const previousOgDescription = document.head
    .querySelector<HTMLMetaElement>('meta[property="og:description"]')
    ?.content ?? previousDescription;
  const previousOgUrl = document.head
    .querySelector<HTMLMetaElement>('meta[property="og:url"]')
    ?.content ?? previousCanonical;

  document.title = spec.title;
  setMeta('meta[name="description"]', "content", spec.description);
  setMeta('meta[property="og:title"]', "content", spec.title);
  setMeta('meta[property="og:description"]', "content", spec.description);
  setMeta('meta[name="twitter:title"]', "content", spec.title);
  setMeta('meta[name="twitter:description"]', "content", spec.description);
  if (spec.canonical) {
    setMeta('link[rel="canonical"]', "href", spec.canonical);
    setMeta('meta[property="og:url"]', "content", spec.canonical);
  }
  if (spec.keywords) {
    setMeta('meta[name="keywords"]', "content", spec.keywords);
  }
  if (spec.ogImage) {
    setMeta('meta[property="og:image"]', "content", spec.ogImage);
    setMeta('meta[name="twitter:image"]', "content", spec.ogImage);
  }
  appendJsonLd(spec.jsonLd);

  return () => {
    document.title = previousTitle;
    setMeta('meta[name="description"]', "content", previousDescription);
    setMeta('link[rel="canonical"]', "href", previousCanonical);
    setMeta('meta[property="og:title"]', "content", previousOgTitle);
    setMeta('meta[property="og:description"]', "content", previousOgDescription);
    setMeta('meta[property="og:url"]', "content", previousOgUrl);
    setMeta('meta[name="twitter:title"]', "content", previousOgTitle);
    setMeta('meta[name="twitter:description"]', "content", previousOgDescription);
    if (previousKeywords) {
      setMeta('meta[name="keywords"]', "content", previousKeywords);
    }
    removeRuntimeJsonLd();
  };
}

export function usePageSeo(spec: PageSeo) {
  useEffect(() => applyPageSeo(spec), [
    spec.title,
    spec.description,
    spec.canonical,
    spec.keywords,
    spec.ogImage,
    JSON.stringify(spec.jsonLd ?? null),
  ]);
}
