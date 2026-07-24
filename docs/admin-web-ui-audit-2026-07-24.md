# admin-web UI/交互审查清单（2026-07-24）

> 范围：`apps/admin-web` 全部前端（应用外壳、登录/认证、12 个管理面板、公开传输页、剪贴板/流程图协作组件），约 4.8 万行。
> 方法：四组并行人工审查（外壳/登录、面板组A、面板组B、公开页/协作组件），交叉核对去重后汇总。
> 本文档兼作修复进度清单，修复完成后在对应条目前标记 `✅`。
>
> **修复结果（2026-07-24 当日完成）**：除以下两项外全部条目已修复并通过验证（`tsc --noEmit` 零错误、24 个测试文件 162 个测试全部通过、生产构建成功；新增共享件 `components/ConfirmModal.tsx`、`components/StatusChip.tsx`、`lib/clipboard.ts`）：
> - A-8 表格排序：原标注"可选做"，未实现（四表已加分页）。
> - SystemPanel 用户表/下载链接表分页：行数少，未加（其余四表已加分页）。
> - 配套变更：生产 CSP（Go `securityHeaders` + openresty 两处）加入主题引导内联脚本 hash `sha256-j+6j8kbf/TP/2vaoa07rGqJUenu5ZBaVvdQE1uczdHo=`；若 `index.html` 该脚本有任何字节改动，hash 需重新计算并同步三处。

## 0. 总体评价

基础水准明显高于一般内部管理台：设计 token 三套变量组织清晰、暗色模式覆盖彻底、`prefers-reduced-motion` 处理全部六组动画、传输协议层（ack 超时/背压/TURN 兜底/房间 epoch）扎实、剪贴板状态机细致、NAT 检测页可访问性是亮点。

短板集中在三条链路：

1. **键盘与读屏链路**——焦点泄漏、暗色焦点指示被误删、自绘控件欠键盘契约（"鼠标用户无感、键盘用户断链"）。
2. **状态反馈的闭环**——能开始不能取消、会失败不能重试、成功不清场、断线不可见、静默改选目标。
3. **一致性**——确认弹窗、状态色、loading、空态、间距各面板各自实现；已有正确组件（`EmptyState`、带 catch 的复制、`UserMenuButton` 的 mode 计算）未被复用。

---

## 1. 高危问题（功能缺陷类）

### H-1 客户端详情抽屉完全没有入口（死功能）
`ClientsPanel.tsx:44,411`：`setDetailClient` 只被 `onClose` 调用，`detailClient` 永远为 null，`ClientDetailDrawer`（含"强制刷新端口映射"）不可达。
**修复**：实例表格与移动卡片操作区加"详情"按钮。

### H-2 客户端表格每秒整体重挂载
`ClientsPanel.tsx:333`（`key={clients-${durationTick}}` + `useNowTick(1000)`）：每秒销毁重建整表 DOM，hover/焦点/滚动位置每秒重置。
**修复**：去掉表格级 key，"在线时长"抽成自 tick 的小组件。

### H-3 直连失败走云端兜底成功后红色错误条残留
`PublicTransferPage.tsx:1669,1805-1861`：兜底成功只 `setState("done")` 未清 error；TURN 切换 notice 同样残留。绿"发送完成"与红"发送未完成"同屏。
**修复**：降级信息走 notice；`uploadViaOss` 成功时清 error/notice。

### H-4 消息面板不按客户端隔离会话
`AdminMessagesPanel.tsx:57,68,182-184,366-383`：单一全局数组混排所有客户端消息，与"按人选会话"UI 模型矛盾。
**修复**：按对端分组存储 `Map<peerName, ChatMessage[]>`，切换只渲染对应会话，非当前会话来消息显示未读角标。

### H-5 PeerMesh 指标卡用分页数据冒充全局总量
`PeerMeshPanel.tsx:118-121,256,262,280`：指标与 Tab 计数基于当前页 20 条数据计算。
**修复**：改用 `pathStats` 全局字段 / `sessionTotal`。

### H-6 传输全程无取消按钮
`PublicTransferPage.tsx:3324-3359,997-1002`：底层 AbortController 全链路就绪但 UI 无入口；直连等待 120s + TURN 再等 120s 只能干等。
**修复**：TransferProgress 加"取消"按钮，abort 后回到 idle 并提示。

### H-7 发现通道断线/重连零 UI 反馈
`PublicTransferPage.tsx:822-884,447-457,2134-2137`：WS 静默重连，roster 过期，协作面板状态点"假在线"。
**修复**：维护 `discoveryStatus`，房间 hub 行显示连接 Chip，重连期禁用发送，状态点改用真实 socket 状态。

### H-8 移动端抽屉导航焦点泄漏
`Dashboard.tsx:147-155`：关闭态仅 `-translate-x-full`，十几个导航按钮留在 Tab 序列；无 `role="dialog"`/焦点管理。
**修复**：关闭态 `inert`，打开时焦点移入、Esc/关闭焦点归还汉堡按钮。

### H-9 暗黑模式 HeroUI 输入框焦点指示被误删
`index.css:125-168`：`data-focus-visible` 的 outline/box-shadow 被 `none !important` 清空且无暗色补回（WCAG 2.4.7）。
**修复**：为 `.dark [data-slot="input-wrapper"][data-focus-visible="true"]` 补焦点 ring。

### H-10 主题首屏闪烁（FOUC）
`index.html:10-44` + `ThemeContext.tsx:61-70`：`.dark` class 等 React 挂载后才写入，暗色用户先闪一帧亮屏。
**修复**：index.html `<head>` 内联脚本首帧前读 localStorage/matchMedia 写 class 与 `color-scheme`。

---

## 2. 系统性问题（横切全站，统一收敛）

### S-1 原生 confirm/prompt 与 HeroUI 混用，部分高权操作无确认
`Dashboard.tsx:105`、`ClientsPanel.tsx:130,143`、`TunnelsPanel.tsx:114`、`HttpRoutesPanel.tsx:134`、`SystemPanel.tsx:97,105,167`、`PeerMeshPanel.tsx:176,189,208`、`PublicTransferPage.tsx:1362,1374` 用原生对话框；`SystemPanel.tsx:285,294`（设为管理员/停用用户）**无确认**；移动端 WebView 中 `prompt` 可能静默失效。
**修复**：封装共享 `ConfirmModal`（危险操作红按钮+后果说明）与输入 Modal，全站替换；补齐角色变更/停用确认。

### S-2 可点击 Chip 充当开关，无语义无键盘支持
`TunnelsPanel.tsx:170-187,232-251`、`HttpRoutesPanel.tsx:225-251,349-380`、`SystemPanel.tsx:389-397,488-496`：无 `aria-pressed`、Tab 不可达、无 pending 态、连点竞态。
**修复**：统一改 `Switch size="sm"` + 乐观更新 + 切换期禁用。

### S-3 状态色彩语义不一致
- "停用"：用户管理 `danger`（`SystemPanel.tsx:273`）/ 隧道·路由 `warning` / 凭证 `default`（`ClientsPanel.tsx:162,219`）。
- 已停用但在线的客户端显示绿色（`ClientsPanel.tsx:155-167`）。
- 概览"上传"：趋势图绿（`OverviewPanel.tsx:240-241`）vs 占比环蓝（`:148-149`）。
- 英文 tone 字符串直出（`TrafficPanel.tsx:554-556`）。
- 方向徽章误用 `warning` 琥珀色（`TrafficPanel.tsx:2092,2189,2286,2460`）。
**修复**：制定配色规范（`danger` 只给错误/失败），封装共享 `StatusChip`；指标配色全局常量。

### S-4 加载/刷新/空态/复制反馈不统一
- 刷新按钮一半无 `isLoading`（`ClientsPanel.tsx:191`、`TunnelsPanel.tsx:146`、`HttpRoutesPanel.tsx:194`）。
- PeerMesh 共享 loading 态，局部操作整页闪烁（`PeerMeshPanel.tsx:75-102`）；TrafficPanel 刷新全表变 Spinner（`TrafficPanel.tsx:196-214`），观测面板无自动刷新。
- `EmptyState` 无任何面板使用，列表空态全是灰字一行；traffic 插画残缺（`EmptyState.tsx:26` 三个 `height="0"`）。
- 复制 secret 无失败兜底，非安全上下文误报"已复制"（`ClientsPanel.tsx:394-401`；正确实现见 `HttpRoutesPanel.tsx:497-504`）。
**修复**：统一 `StatusChip`/`ConfirmModal`/复制工具/`EmptyState` 四共享件；刷新"保留旧数据+按钮 loading"。

---

## 3. 传输页专项（核心路径）

| # | 级别 | 问题 | 位置 |
|---|------|------|------|
| T-1 | 中 | 接收侧显示裸 peerId 而非设备名（设备名 map 现成未接入） | `PublicTransferPage.tsx:3232,3261,3282` |
| T-2 | 中 | 等待确认进度条停 0% 像卡死，应 `isIndeterminate` + 已等待秒数 | `:3337-3342` |
| T-3 | 中 | 失败后无"重试"按钮（`selectedFiles` 仍在） | `:2654-2658` |
| T-4 | 高 | 切换网络模式/新房间静默中止进行中传输，无确认 | `:1071-1102,1150-1169,1717-1719` |
| T-5 | 中 | 已选设备离线后目标静默切换到列表第一台（误发风险）；消息面板同病 | `:789`；`AdminMessagesPanel.tsx:74-77` |
| T-6 | 中 | 等待确认超时后自动降级 TURN 再发一次，等待翻倍至 4 分钟 | `useDirectTransfer.ts:1355`；`:1617-1640` |
| T-7 | 中 | 内网大文件超限具体错误被通用文案覆盖 | `:1672-1676`；`useDirectTransfer.ts:1316-1318` |
| T-8 | 中 | 手机端"发送给谁"列表排在整屏之后 | `:2374-2378,2780-2838` |
| T-9 | 中 | 页面 notice/error 无 `aria-live`、永不消失、可堆叠 | `:2648-2658` |
| T-10 | 中 | 传输中点拖放区收到红色"错误"（应为 notice/disabled） | `:2599-2630,1734-1744` |
| T-11 | 中 | 已下载 blob 的条目重复下载仍走网络 | `:1919-1927` |
| T-12 | 低 | 收到文件超 20 条静默丢弃无提示 | `:170,432-438` |
| T-13 | 低 | 接收中无"取消接收" | `:3252-3268` |
| T-14 | 低 | 邀请名称 `window.prompt`、撤销 `window.confirm` | `:1362,1374` |
| T-15 | 低 | "仅 Direct/TURN" Chip 关键信息只在 hover title | `:2410-2418` |
| T-16 | 低 | 英文服务端错误直出（rate limited / TURN is unavailable） | `:770`；`useDirectTransfer.ts:967-968` |
| T-17 | 低 | 拖放区 aria-label 与动态文案脱节 | `:2602` |
| T-18 | 低 | FAQ 引用不存在的"手机扫码"按钮 | `:3919-3921` |
| T-19 | 低 | done 后进度条与完成卡片重复驻留 | `:2633-2645` |
| T-20 | 低 | 剪贴板混合粘贴无目标时文件静默丢弃；编辑超限全局状态误变 failed | `SyncedClipboard.tsx:433-441,514-521` |
| T-21 | 低 | DiagramEmbedPage 就绪前白屏无 loading | `DiagramEmbedPage.tsx:170-187` |

---

## 4. 外壳与登录页问题

| # | 级别 | 问题 | 位置 |
|---|------|------|------|
| E-1 | 中 | 侧栏"互传/流程图"点击卸载整个管理外壳，与面板切换项无视觉区分 | `Dashboard.tsx:68-75`；`App.tsx:29-37` |
| E-2 | 中 | 主题菜单"跟随系统+系统暗色"时双对勾（`UserMenuButton.tsx:9` 已有正确写法） | `Dashboard.tsx:190-192` |
| E-3 | 中 | HeaderMenu 关闭焦点丢失、无方向键导航、静态区误关菜单 | `HeaderMenu.tsx:34-38,60-66` |
| E-4 | 中 | 移动端页头不吸顶，长页面失去导航入口 | `Dashboard.tsx:124-131`；`index.css:1879-1884` |
| E-5 | 中 | 切换面板不重置滚动位置 | `Dashboard.tsx:133` |
| E-6 | 中 | 登录错误无 `aria-invalid`/`aria-describedby` 关联、确认密码无失焦校验、无密码可见切换 | `AuthDialog.tsx:135-137,284-349` |
| E-7 | 中 | Turnstile iframe 可逃出焦点陷阱；背景未 inert | `AuthDialog.tsx:80-95,341-343` |
| E-8 | 中 | 验证码字距 CSS 写了但 class 名不匹配从未生效 | `index.css:3545-3550`；`AuthDialog.tsx:272` |
| E-9 | 低 | 侧栏导航项 32px 低于 44px 触控建议 | `index.css:1900` |
| E-10 | 低 | 菜单项 focus-visible 仅 5.5% 透明度底色 | `index.css:2861-2865` |
| E-11 | 低 | MobileTopologyDiagram aria-label 在无 role 的 div 上 | `LoginPage.tsx:411-414` |
| E-12 | 低 | 全屏/面板加载态无 `role="status"` | `App.tsx:106-115`；`Dashboard.tsx:228` |
| E-13 | 低 | 缺"跳到主内容"链接 | `Dashboard.tsx:112-141` |
| E-14 | 低 | HeroRuntime 主题 class 三重冗余 | `HeroRuntime.tsx:9-10`；`ThemeContext.tsx:63-64` |
| E-15 | 低 | 登录/注册 tablist 不符合 APG tab 模式 | `AuthDialog.tsx:240-255` |
| E-16 | 低 | 工具菜单详情文字 10px 过小 | `PublicToolsMenu.tsx:36` |
| E-17 | 低 | 非管理员停留 `#/system` 时 URL 与实际面板不一致 | `Dashboard.tsx:91-93` |
| E-18 | 低 | 登录框打开即聚焦，移动端软键盘遮挡 | `AuthDialog.tsx:68-73` |
| E-19 | 低 | `.app-apple-main` `!important` 内边距与 Tailwind 类打架 | `index.css:1886-1889`；`Dashboard.tsx:132` |

---

## 5. 管理面板问题（组 A）

| # | 级别 | 问题 | 位置 |
|---|------|------|------|
| A-1 | 中 | HTTP 路由"操作"列仅 6% 宽按钮溢出；状态/明细/改写各 6% 放不下 Chip | `HttpRoutesPanel.tsx:320` |
| A-2 | 中 | HTTP 路由桌面端无刷新按钮（只在 `xl:hidden` 容器） | `HttpRoutesPanel.tsx:184-197` |
| A-3 | 中 | 用户管理表无移动端卡片；重置密码用原生 prompt 明文 | `SystemPanel.tsx:241-323,97` |
| A-4 | 中 | 概览趋势图 360px 手机有效字号约 6px 不可读 | `OverviewPanel.tsx:188-207` |
| A-5 | 低 | 客户端状态 Chip 颜色只看在线忽略停用 | `ClientsPanel.tsx:155-167` |
| A-6 | 低 | 数字输入静默兜底（`Number(maxOnline) \|\| 2`） | `ClientsPanel.tsx:93,448,567` |
| A-7 | 低 | 时间格式不统一（`toLocaleString()` vs `formatDateTime`） | `SystemPanel.tsx:719-724` |
| A-8 | 低 | 除连接记录外表格无分页无排序 | `ClientsPanel.tsx:245,333` 等 |
| A-9 | 低 | 详情抽屉字段 truncate 无 title；访问链接提示条无关闭；开关文案两端不一致；MobileListCard 用下标做 key；单页仍显示分页器 | `ClientDetailDrawer.tsx:47`；`HttpRoutesPanel.tsx:167-182,241,250,367,379`；`MobileListCard.tsx:61`；`ConnectionsPanel.tsx:441-446` |

## 6. 管理面板问题（组 B）

| # | 级别 | 问题 | 位置 |
|---|------|------|------|
| B-1 | 中 | PeerMesh 清理链路后列表与计数不一致 | `PeerMeshPanel.tsx:203-225` |
| B-2 | 中 | 消息区无自动滚动与新消息提示 | `AdminMessagesPanel.tsx:366-383` |
| B-3 | 中 | 附件下载两步晦涩交互（下载→换签→再点打开，点完即失效） | `AdminMessagesPanel.tsx:272-290,460-479` |
| B-4 | 中 | NAT 检测徽章与实际检测路径数据源不一致 | `NatDetectionPanel.tsx:704-706,765-767,412` |
| B-5 | 中 | NAT 检测 15s 无法取消（AbortController 已具备） | `NatDetectionPanel.tsx:403-427,927-938` |
| B-6 | 中 | 客户端下载接口失败被伪装成"未配置"空态（try/finally 无 catch） | `ClientDownloadsPanel.tsx:28-35,69-72` |
| B-7 | 中 | ACL 方向列纯符号无文字无 aria-label | `PeerMeshPanel.tsx:538` |
| B-8 | 中 | 自绘 Tab 组件无键盘契约且 `focus-visible:outline-none` 无替代 | `TrafficPanel.tsx:486-497,321-331` |
| B-9 | 低 | 同页桌面断点不一致（`lg:block` vs `xl:block`） | `TrafficPanel.tsx:448,629,879` |
| B-10 | 低 | 资源排行 Top 8 无说明；拓扑 slice 截断无提示 | `TrafficPanel.tsx:595`；`PeerMeshPanel.tsx:1492,1517` |
| B-11 | 低 | 耗时裸渲染毫秒（125000 ms） | `TrafficPanel.tsx:866,971,1241`；`NatDetectionPanel.tsx:700-702` |
| B-12 | 低 | TCP 帧表翻页整表重挂载丢滚动/焦点 | `TrafficPanel.tsx:2171,2183` |
| B-13 | 低 | 消息输入框无 label；客户端列表选中态无 aria | `AdminMessagesPanel.tsx:396-405,321-343` |
| B-14 | 低 | 消息截断时 blob URL 泄漏（未 revokeObjectURL） | `AdminMessagesPanel.tsx:137-142,182-184` |
| B-15 | 低 | 超时输入非法值静默钳制；改服务器列表后旧结果仍显示"检测完成" | `NatDetectionPanel.tsx:769-777,587-595` |
| B-16 | 低 | 帮助锚点滚动依赖 setTimeout(80) 魔法延时 | `HelpPanel.tsx:70-84` |
| B-17 | 低 | 代码块复制按钮遮挡长行 | `HelpPanel.tsx:553-561` |
| B-18 | 低 | 下载卡缺版本/更新时间；`target="_blank"` 闪空白页 | `ClientDownloadsPanel.tsx:85-111` |
| B-19 | 低 | PeerMesh 每秒 tick 驱动整面板重渲染但数据不刷新 | `PeerMeshPanel.tsx:73` |
| B-20 | 低 | 指标卡未加载时显示"默认关闭"误导 | `PeerMeshPanel.tsx:253` |
| B-21 | 低 | 桌面筛选 Popover 应用后不关闭 | `TrafficPanel.tsx:1067-1074,1131-1139` |
| B-22 | 低 | 面板顶部间距不统一（mt-2/3/4 混用） | 各面板首行 |
| B-23 | 低 | 失败消息无色彩强调无重发入口 | `AdminMessagesPanel.tsx:444-448` |

---

## 7. 修复顺序（执行口径）

1. **共享件先行**：`ConfirmModal`、`StatusChip`、带兜底复制工具、修复 `EmptyState` traffic 插画。
2. **高危 H-1 ~ H-10**（功能缺陷 + 外壳无障碍）。
3. **传输页 T 系列**（核心路径闭环：取消/重试/清场/设备名/连接可见性）。
4. **系统性 S-1 ~ S-4 全站替换**。
5. **中低级别批量收尾**（A/B/E 系列）。

验收：每组修复后 `npm run typecheck` + `npm run test` 通过；涉及协议的改动需与 `useDirectTransfer` 现有状态机对齐。
