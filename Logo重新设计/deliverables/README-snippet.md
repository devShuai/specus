<!-- 放在 README.md 顶部。GitHub 会按读者的明/暗主题自动切换 -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
  <img alt="specus 引水渠" src="docs/assets/logo-light.svg" width="280">
</picture>

# specus

引水渠 —— 内网服务接入、网络打洞与流量观测。

---

## 文件放置

| 文件 | 仓库位置 |
| --- | --- |
| logo-light.svg | docs/assets/logo-light.svg |
| logo-dark.svg | docs/assets/logo-dark.svg |
| logo.svg | apps/admin-web/public/logo.svg |
| logo-mark.svg / logo-mark-dark.svg | docs/assets/ |
| favicon.svg | apps/admin-web/public/favicon.svg |
| favicon-32.svg / favicon-16.svg | apps/admin-web/public/ |
| AppLogo.tsx | apps/admin-web/src/components/AppLogo.tsx |

favicon.ico 由 `apps/admin-web/scripts/generate-favicon.mjs` 用代码逐笔绘制,需按新图形改写后重新生成。

### index.html 引用

```html
<link rel="icon" type="image/svg+xml" sizes="any" href="/favicon.svg" />
<link rel="icon" type="image/svg+xml" sizes="32x32" href="/favicon-32.svg" />
<link rel="icon" type="image/svg+xml" sizes="16x16" href="/favicon-16.svg" />
<link rel="alternate icon" href="/favicon.ico" />
```
