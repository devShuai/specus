# 界面设计系统：Liquid Glass Base

管理后台、CLI 本地管理页、Windows 桌面客户端与 Android 客户端共用一套视觉规范：浅色磨砂玻璃、单一系统蓝强调色、大圆角、胶囊页签与标签、系统字体，浅色与深色两套主题。本文记录各端把规范落在哪里，以及改界面时要守的规则。

## 令牌在哪里

规范的颜色、字号、间距、圆角、阴影与玻璃材质都是令牌（token），各端各有一份，取值一致：

| 端 | 令牌位置 | 主题切换 |
|---|---|---|
| 管理后台（`apps/admin-web`） | `src/design-tokens.css`；HeroUI 主题在 `hero.ts` | `ThemeContext.tsx` 在 `<html>` 上切 `.light` / `.dark` |
| CLI 本地管理页（Go / Java / .NET 共用） | `implementations/go/client/cmd/specus-client/web/app.css` 开头 | 跟随系统 `prefers-color-scheme` |
| Windows 桌面（WPF） | `Specus.Client.Desktop/App.xaml` 资源；深浅两套取值在 `MainWindow.xaml.cs` 的 `LightPalette()` / `DarkPalette()` | 代码替换 `Application.Resources` 里的画刷，所有画刷用 `DynamicResource` |
| Android | `res/values/gui-theme.xml` 与 `res/values-night/gui-theme.xml`；间距、圆角、字号是 `MainActivity` 里的常量 | 系统深色模式（`values-night`） |

管理后台里原有的 `--app-apple-*`、`--diagram-apple-*` 与落地页 `--landing-*` 变量都指向令牌，Tailwind 的 `rounded-*` 与 `font-*` 也读同一套圆角和字体。新样式直接用令牌（`var(--accent)`、`var(--radius-md)` 等），不要再写颜色或圆角的字面值。

管理后台的页面用设计规范自己的组件写：

- `src/styles/liquid-glass.css`：设计规范的 `bd-*` / `jd-*` 组件与外框类（按钮、字段、标签、提示条、卡片、表格、页签、分段、页头、区块标题、筛选条、数字卡、空状态、搜索框、玻璃圆按钮、手机抽屉与叠成条的表格），放在 components 层，同元素上的 Tailwind 工具类仍然优先。
- `src/components/ui`：图标集（`Icon`，132 个线性图标，不用 emoji 或别的图标库）和这些类的 React 封装（Card、Section、Stat、TableWrap、FilterBar、Tag、Alert、Progress、Empty、Tabs、Segmented、RelativeTime）。
- `src/styles/` 下每个页面区域一份样式（`area-ops`、`area-access`、`area-mesh-system`、`public-pages`、`transfer`），只写本区域的类。
- 外框在 `Dashboard.tsx`：可收起的玻璃侧栏、透明顶栏里的搜索框（`/` 或 Ctrl/⌘ K）和圆按钮、同组页面的区域页签；页面自己从页头开始。

## 主要取值

- 页面底色 `bg`：浅色 `#f5f5f7`，深色 `#0c0c0e`，上面铺三团很淡的彩色辉光。
- 实底面 `surface`：浅色 `#ffffff`，深色 `#1c1c1f`；发丝线 `border`：浅色 `rgba(0,0,0,.08)`，深色 `rgba(255,255,255,.08)`。
- 强调色 `accent`：浅色 `#0071e3`，深色 `#0a84ff`。全站只有这一个强调色，用于主按钮、链接、选中与进度。
- 状态色 `success` / `warning` / `danger` / `info` 只表达状态，配各自的 `*-bg` 浅底，且总带文字。
- 文字三级：`text`、`text-muted`、`text-subtle`。
- 圆角：复选框 6，小按钮 8，按钮与输入框 10，提示条与表格外框 14，卡片 20，侧栏与对话框 24，页签、标签、开关为胶囊。
- 控件高度：小 30，默认 36，登录页 44（移动端触控区不低于 44 / 48）。
- 字体：系统字体栈（苹方、微软雅黑、Segoe UI 等），不打包网页字体；数字用等宽数字。

## 页面结构

- 侧栏是浮在页面上的玻璃面板，当前页是凸起的玻璃块，用文字色而不是强调色。
- 每页一个 30px 页面标题，下面一行说明，页级操作在右侧（管理后台用 `PageHeader` 组件）。
- 内容放在卡片里；页内切换用胶囊页签；二选一的模式用分段控件，选中项是凸起的实底块。
- 对话框：实底、24 圆角、大阴影，取消在左、确认在右，标题用问句。

## 文案

- 按钮用动词开头；不写“点击”“请”“确定”。
- 错误写原因和下一步。
- 数字与单位之间留空格；不用 emoji。

## 各端的已知差异

- WPF 没有背景模糊，玻璃只是半透明色；卡片与玻璃不加阴影（WPF 的阴影效果会让文字发虚）；微软雅黑没有 500 / 600 字重，分别画成常规与粗体。
- Android 卡片阴影是 1dp 的底边，不用 elevation（会被滚动区裁掉）。
- CLI 本地管理页受严格 CSP 约束（不内联脚本与样式、不加载外部资源），图标是页面内的 SVG；窄屏用顶部页签栏代替抽屉。
