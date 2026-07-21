# 专业流程图页面审计与优化清单（2026-07）

本文记录 2026-07-20 对"专业流程图"页面的一次完整审查：从**交互、功能、界面美化**三个维度发现的问题、影响与建议修法。审查动因是回答"专业流程图页面还有哪些需要优化的交互、功能和界面美化问题"。

涉及的主要文件：

* 编辑器核心：`apps/admin-web/src/components/SyncedDiagram.tsx`（约 6,900 行，maxGraph 0.24 + Yjs 协同）
* 页面外壳：`apps/admin-web/src/pages/PublicTransferPage.tsx`（`PublicTransferWorkspacePage workspace="diagram"`）
* 嵌入页：`apps/admin-web/src/pages/DiagramEmbedPage.tsx`（iframe + postMessage 协议）
* 文档模型：`apps/admin-web/src/lib/diagramDocument.ts`、`diagramTextFormats.ts`、`diagramDrawio.ts`、`diagramVisio.ts`
* 公共导航：`apps/admin-web/src/components/PublicToolsMenu.tsx`
* 样式：`apps/admin-web/src/index.css`（`.diagram-apple` 皮肤、`--diagram-apple-*` token）

结论摘要：

* 找到 **2 个严重功能 bug**（结构性替换与远端更新的同步竞态，可产生孤儿节点并导致全房间永久失同步）、**3 个高风险项**（远端校验 O(文档²) 卡顿、发送失败静默发散、drawio/VSDX 解压无上限）、**6 个高严重度交互问题**（锁定形同虚设、快捷键焦点失效、无滚轮缩放且误触浏览器整页缩放、跨页静默撤销、属性草稿被远端清空、只读/全屏切换重建画布）。
* 界面美化最显眼的问题是**蓝色主题残留大量 cyan 强调色**与**三个弹窗三种暗色表面**；功能与文档不符项中 **drawio 导入全部文字变粗体**影响每个导入用户。
* 已确认无问题的部分：embed postMessage 协议（origin 锁定、数据定向回复、readonly 贯穿）实现正确；maxGraph CellEditor 的 Esc 取消、Enter 提交行为正常。

本文同时作为后续修复的进度清单：修复后在对应条目标注完成状态与核对依据。

## 优先级总览

| 级别 | 维度 | 编号 | 问题 |
|---|---|---|---|
| P0 | 功能 | F1 | 结构性替换未清理挂起的 graph→Yjs 同步定时器，可产生孤儿节点并永久瘫痪协作同步 |
| P0 | 功能 | F2 | 远端更新与本地挂起同步竞态，`replaceYMapForPage` 误删协作者刚写入的元素 |
| P1 | 功能 | F3 | `isSafeRemoteDiagramUpdate` 每条远端更新做全文档复制校验，O(文档²) 卡顿 |
| P1 | 功能 | F4 | 协作发送彻底失败时完全静默，文档发散无提示 |
| P1 | 功能 | F5 | draw.io / VSDX 解压无输出上限（zip bomb），解析在确认对话框之前 |
| P1 | 交互 | I1 | "锁定"功能形同虚设：可删除、可键盘移动、可经属性面板改样式 |
| P1 | 交互 | I2 | 键盘快捷键只挂在画布 div 上，焦点离开画布全部失效 |
| P1 | 交互 | I3 | 无滚轮/捏合缩放，且触控板捏合会缩放整个浏览器页面 |
| P1 | 交互 | I4 | 撤销/重做零反馈，且作用域是整个文档而非当前页 |
| P1 | 交互 | I5 | 属性面板文本编辑被远端更新/任何模型变化静默清空 |
| P1 | 交互 | I6 | 切换只读/全屏销毁重建整个 Graph：缩放、滚动位置、选区全丢 |
| P1 | 功能 | F6 | drawio 往返"默认粗体"bug：导入后全部文字变粗体 |
| P1 | 美化 | U1 | 蓝色主题残留大量 cyan 强调色，同屏蓝/青两种强调色 |
| P1 | 美化 | U4 | 三个弹窗三种暗色表面、三种结构，EditorDialog 硬编码主题色 |
| P1 | 美化 | U10 | 错误只在 9px 灰色状态栏以普通文字呈现，错误/成功/提示无区分 |
| P2 | 交互 | I7 | Escape 键几乎未处理（选区/右键菜单/移动侧栏/全屏均不响应） |
| P2 | 交互 | I8 | 右键菜单：底部右击被裁剪、焦点管理失效、旧选区残留 |
| P2 | 交互 | I9 | 远程光标在本地平移/缩放/滚动后停在错误位置 |
| P2 | 交互 | I10 | 复制不进系统剪贴板却阻止了浏览器默认复制 |
| P2 | 交互 | I11 | 移动端所有操作反馈不可见（status 文本 `hidden md:flex`） |
| P2 | 交互 | I12 | 画布平移方式（Ctrl+Shift+拖拽）不可发现 |
| P2 | 交互 | I13 | 协作时状态栏被"已合并来自 …"提示刷屏 |
| P2 | 交互 | I14 | 远程选区只显示数量，标签中英混杂且暴露裸 peerId |
| P2 | 功能 | F7 | "会话版本"实为内存版本，刷新即丢，与文档"会话保存"不符 |
| P2 | 功能 | F8 | embed 模式本地缓存冲突（无 key 时共享 `embed:default`） |
| P2 | 功能 | F9 | 文档上限未在本地路径强制（评论条数、复制页面连线数） |
| P2 | 美化 | U2 | 成功/错误色多源并存（绿两种、红四套、当前高亮蓝色值不符） |
| P2 | 美化 | U5 | 工具栏下拉菜单未做皮肤，与右键菜单两套语言 |
| P2 | 美化 | U6 | 同屏中英文混排、裸 peerId 外露（状态栏/光标标签） |
| P2 | 美化 | U11 | 加载与空状态规格不一（无 spinner、版本 Tab 无空状态） |
| P2 | 美化 | U12 | 独立流程图页无公共头部，与其他工具页导航断裂 |
| P3 | 功能 | F10 | 页面 order 复用导致排序并列，各端页签顺序可能不一致 |
| P3 | 功能 | F11 | 远端选区数据已传但只显示数量（文档声称可视化，属半成品） |
| P3 | 功能 | F12 | diagram 事件去重 key 同毫秒可互丢；whiteboardEvents 300 条共享队列可能被挤出 |
| P3 | 功能 | F13 | 性能热点：`renderFromDocument` 全量重建 + `refreshPages` 每条 update setState |
| P3 | 交互 | I15–I21 | 空粘贴无反馈、Mac 符号快捷键标签、无缩放快捷键、缺 Ctrl+X、评论定位静默失败、背景点阵不随缩放、重命名不回显选中 |
| P3 | 美化 | U3 | 暗色画布底色 `#272729` 是 token 体系之外的"第三种灰" |
| P3 | 美化 | U7 | 全局 `letter-spacing: 0 !important` 使字距类成死代码 |
| P3 | 美化 | U8 | 9px 字号承载过多正文信息，叠加低对比可读性差 |
| P3 | 美化 | U9 | 日期格式不统一（长格式 vs 短格式） |
| P3 | 美化 | U13–U17 | 双 token 体系漂移风险、侧边栏宽度两套值、计数徽标三种样式、面板标题冗余、嵌入模式 min-h 溢出 |

编号规则：F = 功能（Functionality），I = 交互（Interaction），U = 界面美化（UI/Visual）。下文按维度分节详述，节内按严重度排序。

---

## 一、功能问题

### P0-F1 结构性替换未清理挂起的同步定时器，可产生孤儿节点并永久瘫痪协作同步

* 位置：`SyncedDiagram.tsx:1531-1542`（`scheduleGraphSync` 60ms 防抖）、`3066-3075`（`importDiagram`）、`3148-3182`（`replaceDiagramWithUpdate`）、`3230-3256`（`restoreVersion`）、`3309`（embed `loadSnapshot`）；对照正确做法 `3279-3283`（`encodeCurrentCloudSnapshot` 先 `clearTimeout(graphSyncTimerRef)` 再 flush）。
* 问题：上述结构性替换入口清空并重写 Y.Map 时，都没有取消可能仍在倒计时的 `graphSyncTimerRef`。若 60ms 前刚有过画布编辑，定时器随后触发 `syncGraphToDocument`（`1511-1529`），它读取的仍是**旧 graph**（rAF 重渲染尚未执行），`replaceYMapForPage` 会把旧内容写回、把刚导入的内容整页删除。更严重的是：替换后 `activePageId` 可能已指向新 pageId，旧 graph 内容会以**已不存在的 pageId** 写回 nodes/edges，形成孤儿节点。
* 触发场景：拖动画布元素后 60ms 内执行导入 .stdg/.drawio、恢复版本、打开云端文件，或 embed 宿主在编辑过程中下发 `load`。
* 放大效应：`isSafeRemoteDiagramUpdate`（`5137-5158`，尤其 `5149-5152` 的 pageId 归属校验）会拒绝一切含孤儿节点的更新——该 peer 之后**所有**更新（包括全量状态）都被其他成员丢弃，本地缓存（`1294`）还会把"中毒"文档持久化，刷新后依然无法恢复同步，只能换房间。
* 修复建议：把 `encodeCurrentCloudSnapshot` 的清定时器模式抽成公共函数，在所有结构性替换入口调用；`syncGraphToDocument` 写入前校验 `activePageId` 仍存在于 `pagesMap`，不存在则放弃本次写入；导入/恢复完成后强制立即 `renderFromDocument` 而非等 rAF。

### P0-F2 远端更新与本地挂起同步竞态，误删协作者刚写入的元素

* 位置：`SyncedDiagram.tsx:1268-1285`（`handleUpdate` 对 REMOTE_ORIGIN 仅 `scheduleDocumentRender`）、`1170-1176`（rAF 渲染）、`1511-1542`（60ms 同步）、`5122-5135`（`replaceYMapForPage` 按"graph 里没有就删"）。
* 问题：本地编辑后 60ms 同步尚未触发时，远端 update 到达 → 仅排队 rAF 重渲染。若 60ms 定时器先于 rAF 执行（主线程繁忙、掉帧），`syncGraphToDocument` 读到的 graph 不含远端新节点，`replaceYMapForPage` 把"graph 里没有的条目"判定为删除，把远端刚插入的节点从 Y.Doc 删除并广播。同样地，远端删页/删节点到达时若本地正在编辑该页，本地挂起的 flush 会把已删除内容以孤儿 pageId 写回（与 F1 汇合）。
* 触发场景：双人同时编辑同一页，一方连续拖动、另一方增删节点或删除页面。
* 修复建议：应用 REMOTE 更新时同时 `clearTimeout(graphSyncTimerRef)`；或给 `syncGraphToDocument` 加"距上次远端渲染不足 N ms 则跳过/重排"的保护；长期方案是放弃"整页重写 Y.Map"的同步模型，改为增量操作。

### P1-F3 `isSafeRemoteDiagramUpdate` 全文档复制校验，O(文档²)

* 位置：`SyncedDiagram.tsx:5137-5158`，调用点 `1843-1852`。
* 问题：每条远端增量 update 都执行 `Y.encodeStateAsUpdate(document)`（全量）+ 创建 probe Doc + 两次 applyUpdate + 全量结构校验 + `probe.destroy()`。1000 节点文档、拖动期每 60ms 一条 update 时，主线程被全量序列化/反序列化占满，协作大文档必然卡顿；同时每次产生一个完整 Doc 的 GC 压力。校验本身正确性没问题，但代价与收益严重不匹配。
* 修复建议：增量校验（只解码 update 中的新内容做结构检查），或对来自同一可信 peer 的增量更新免校验、仅对全量 state 做完整校验；至少加 LRU/节流。

### P1-F4 协作发送彻底失败时完全静默

* 位置：`whiteboardTransport.ts:15-28`（全部路径失败返回 `null` 且注释明确吞掉错误）、`PublicTransferPage.tsx:1914-1996`（`sendWhiteboardPayload` fire-and-forget）、`SyncedDiagram.tsx:1178-1191`（`sendYUpdate` 不感知投递结果）。
* 问题：Direct 超时、TURN 不可用、WebSocket 断开三者同时失败时，Yjs 增量直接丢失，UI 仍显示"实时同步"。Yjs 丢一条增量后只能靠新成员加入时的全量 state 偶发修复，期间两端文档持续发散。
* 修复建议：`onSend` 改为返回 `Promise<boolean>`，失败时在 SyncedDiagram 提示"同步中断"并周期性重发全量 state（现有 sync-request 机制可复用，增加定时重传）。

### P1-F5 draw.io / VSDX 解压无输出上限（zip bomb）

* 位置：`diagramDrawio.ts:397-408`（`decodeCompressedDiagram` 对 `inflateRaw` 结果无大小检查）；`diagramVisio.ts:27-44`（`unzipSync` filter 只按文件名，page XML 解压后无上限）。
* 问题：8 MB 的 .drawio（或 16 MB 的 .vsdx）压缩 XML 可解压出数百 MB 字符串，解析发生在用户确认对话框**之前**（`importDiagram` 先 parse 后 confirm，`SyncedDiagram.tsx:3024-3046`），选择恶意文件即冻结/OOM 标签页。
* 修复建议：分块 inflate 并累计字节数、超过明确解压上限即抛错；VSDX 同理对单 entry 解压大小设限。

### P1-F6 drawio 往返"默认粗体"bug

* 位置：`SyncedDiagram.tsx:5313`（`fontStyle: (node.style.bold === false ? 0 : 1) + …`，`bold` 为 `undefined` 时按粗体渲染）；`diagramDrawio.ts:299-300` 导出侧同样逻辑；`diagramDrawio.ts:175-178` 导入侧只在 `style.has("fontStyle")` 时设置 `bold`。
* 问题：drawio 文件省略 `fontStyle`（即非粗体，drawio 常规写法）→ 导入后 `bold === undefined` → 渲染与再导出都按粗体处理。普通 drawio 文档导入后全部文字变粗体，往返不保真。与计划文档 4.6 节"常用样式"声明不符。另：节点缺省粗体与连线缺省非粗体（`5383-5410`）默认值不对称，同根因。
* 修复建议：三处统一为 `bold === true ? 1 : 0`（undefined = 非粗体）。

### P2-F7 "会话版本"实为内存版本，刷新即丢

* 位置：`SyncedDiagram.tsx:918`（`versionsRef`）、`3211-3219`（非服务端分支只写 `versionsRef`）、`1242-1243`（room/boardKey 切换即清空）。
* 问题：计划文档 4.5 声称"本次浏览器会话保存最多 20 个版本"，实际只存于组件内存，浏览器刷新、甚至组件重挂载即全部丢失，与"会话保存"语义不符。
* 修复建议：落到 sessionStorage（或 IndexedDB），或把文档降级描述为"本次编辑会话"。

### P2-F8 embed 模式的本地缓存冲突

* 位置：`DiagramEmbedPage.tsx:57`（无 `key` 参数时 `boardKey="embed:default"`）、`SyncedDiagram.tsx:1246-1255`（挂载即恢复缓存）。
* 问题：同一 SPA 会话内先后打开两个不带 `key` 的嵌入页，第二个会恢复第一个的缓存内容；宿主若不下发 `load`（预期空白文档），展示的是上一份文档，且随后 `change`→`save` 可能把旧内容写回宿主的新文档。
* 修复建议：`standalone` 模式下跳过 `diagramStateCache` 恢复/写入，或要求宿主必须提供 `key`。

### P2-F9 文档上限未在本地路径强制

* 位置：`SyncedDiagram.tsx:3087-3114`（`addComment` 无 `MAX_DIAGRAM_COMMENTS` 检查）；`1962-1970`（`duplicatePage` 只查节点数不查连线数）；`5137-5158`（远端校验也不限制评论条数、页面总数）。
* 问题：计划文档 4.2 声明"最多 2,000 评论"，实际只能通过导出截断体现；协作态可无限增长评论；复制页面可使连线总数超过 2,000。

### P3-F10 页面 order 复用导致排序并列

* 位置：`SyncedDiagram.tsx:1925`（`order: pageMap.size`）。
* 问题：删除中间页后新增页面会复用已有的 order 值（如 [0,1,2] 删 1 后新增 → 两个 order=2），排序结果依赖 Y.Map 迭代顺序，各端页签顺序可能不一致或跳动。
* 修复建议：`order = Math.max(...existing) + 1`。

### P3-F11 远端选区未真正可视化

* 位置：`SyncedDiagram.tsx:4184-4194`（presence 只渲染光标 + "N selected" 文本）。
* 问题：计划文档 4.3 声称"协作者 presence 可在流程图中显示（远端光标/选区）"，实际选中元素 id 列表（`1210`、`1836`）只用于计数展示，画布上不高亮对方选中的元素。属半成品，与交互 I14 同源。

### P3-F12 事件队列小问题

* `PublicTransferPage.tsx:3989`：diagram 事件去重 key 为 `createdAt + update.length + 前 20 字符`，同一毫秒内两条不同 update 可能互相丢弃（60ms 防抖下概率低，但 flush 路径可绕过防抖）。建议改用单调递增序号。
* `PublicTransferPage.tsx:459-467`：`whiteboardEvents` 只保留最近 300 条；白板高频事件与流程图 update 共用该队列，极端突发下流程图 update 可能在被消费前被挤出队列（Yjs 丢增量，放大 F4）。建议按 `payload.type` 分队列。

### P3-F13 性能热点

* 位置：`SyncedDiagram.tsx:1544-1649`（`renderFromDocument` 对每条远端更新全量 `removeCells` + 重建全部 cell）、`1269`、`1259-1264`（`handleUpdate`→`refreshPages` 对每条 update 重建 pages/comments 数组并 setState）、`5129-5134`（`replaceYMapForPage` 每次同步对整页做 `JSON.stringify` 比对）。
* 问题：大图协作时三重 O(page) 叠加。计划文档阶段 5 已规划性能专项，但当前实现是最直接的热点。

### 已确认无问题（列出以免重复怀疑）

* `DiagramEmbedPage.tsx` postMessage 协议：origin 锁定（`101-113`）、数据类回复均定向到 `event.origin`、init/change 不含数据、readonly 经 `roomRole="VIEWER"` 贯穿到 graph 配置，未发现绕过。
* maxGraph CellEditor：Esc 取消编辑、Enter 提交（Shift+Enter 换行）行为正常；in-canvas 编辑器为 textarea，`input/textarea` 守卫有效。
* 计划文档过时（以代码为准，不算缺陷）：代码已实现账号云文档线（`adminApi.listDiagrams/createDiagram/updateDiagram` + 乐观 revision，`SyncedDiagram.tsx:3316-3454`）和 `DiagramEmbedPage` 嵌入协议，计划文档第 3/4 章未提及；计划文档仍写"数据库只保存…用户主动创建的版本快照"，与云文档功能并存但文档未更新。建议同步更新 `professional-diagram-complete-plan.md`。

---

## 二、交互问题

### P1-I1 "锁定"功能形同虚设

* 位置：`SyncedDiagram.tsx:1471-1477`（只重写了 `isCellMovable/isCellResizable/isCellRotatable/isCellEditable`）、`2684-2694`（toggleNodeLock）、`2252-2260`（removeSelection）、`3552-3560`（方向键）、`4272`（检查器 fieldset 只按 isReadOnly 禁用）。
* 问题：maxGraph 的 `removeCells → isCellDeletable` 只认内置 `deletable` 样式，组件自定义的 `diagramLocked` 完全不影响删除；`graph.moveCells` 源码中不做 movable 检查，方向键可以直接搬动锁定节点；`commitSelectionLabel`/`updateSelectedStyle`/`updateNodeGeometry` 也都不检查锁定。
* 场景：协作中用户锁定底图/泳道防止误改，自己或队友按一下 Delete（或 Ctrl+A 后 Delete）就把锁定节点删了，锁定给人虚假安全感。
* 修复建议：补充重写 `graph.isCellDeletable`（或在 removeSelection 过滤锁定单元并提示"已跳过 N 个锁定元素"）；方向键分支改用 `graph.getMovableCells(...)` 过滤；检查器在 `selection.locked` 时禁用或提示。

### P1-I2 键盘快捷键只挂在画布 div 上

* 位置：`SyncedDiagram.tsx:4163-4165`（`onKeyDown={handleKeyDown}` 在 `.diagram-apple-canvas-wrap` 上）、`3486-3561`。
* 问题：工具栏、菜单、页面标签、检查器都在该 div 之外。用户点一次工具栏按钮（焦点留在按钮上）后按 Ctrl+Z / Delete / 方向键毫无反应，也没有任何提示。
* 场景：点"排列→左对齐"后想立刻 Ctrl+Z 撤销——无效；用户会以为撤销坏了。
* 修复建议：把 keydown 监听挂到 window（保留现有 `input/textarea/contenteditable` 守卫即可），或至少在工具栏操作后把焦点还回画布。

### P1-I3 无滚轮/捏合缩放，触控板捏合会缩放整个浏览器页面

* 位置：`SyncedDiagram.tsx:1339-1358`（Graph 初始化段没有任何 wheel 处理）；maxGraph 默认插件（`getDefaultPlugins`）不含滚轮缩放；`PanningHandler` 的 pinch 只响应 Safari 的 `gesturestart` 事件。
* 问题：Ctrl+滚轮、Chrome/Edge 触控板捏合产生 ctrl+wheel，组件未 `preventDefault`，浏览器会整页缩放 UI；缩放只能开"视图"菜单点按钮（`3789-3805`），也没有 Ctrl+= / Ctrl+- / Ctrl+0 快捷键。
* 场景：Windows 笔记本用户在画布上捏合想放大流程图，结果整个应用界面被浏览器放大。
* 修复建议：在容器上加 wheel 监听（ctrl/meta 时 zoomIn/zoomOut 并 preventDefault），并补缩放快捷键。

### P1-I4 撤销/重做零反馈，作用域是整个文档而非当前页

* 位置：`SyncedDiagram.tsx:1222-1225`（UndoManager 挂在整篇 Y.Doc）、`3513-3528`（undo/redo 无 setStatus）。
* 问题：撤销栈跨所有页面。用户在页面 2 按 Ctrl+Z，被撤销的可能是页面 1 的最后一次操作——当前页面上"什么都没发生"，也没有状态提示，用户往往会连按多次，不知不觉回滚掉其他页面的内容。
* 场景：A 在"页面 1"画了半小时，B 在"页面 2"连按 Ctrl+Z 想撤销自己刚画的框，实际把页面 1 的内容一步步删了且无人察觉。
* 修复建议：undo/redo 后 setStatus 说明撤销了什么（如"已撤销：移动 2 个节点"）；理想做法是给 Y.Map 条目带 pageId 判断，撤销影响非当前页时提示或自动切页。

### P1-I5 属性面板文本编辑被远端更新静默清空

* 位置：`SyncedDiagram.tsx:4287-4297`（textarea 的 value 直接绑 `selection.label`）、`1647`、`1655-1658`（`renderFromDocument`/modelListener/selectionListener 都会整体重算 selection）。
* 问题：textarea 的草稿只存在 `selection.label` 这一个受控状态里，远端任何改动（哪怕别人移动了一个无关节点）或本地方向键微调都会触发 `updateSelection`，把正在输入的文字重置为已提交值。
* 场景：多人协作时你在右侧改节点文字，队友拖动任意图形，你打了一半的字瞬间消失。
* 修复建议：文本框用独立草稿 state（以 cell id 为 key），仅在切换选中单元或该单元 label 真的被外部改写时才重置；数字/颜色字段同理（`InspectorNumberField` 的 useEffect 重置也有此问题，只是窗口更小）。

### P1-I6 切换只读/全屏销毁重建整个 Graph

* 位置：`SyncedDiagram.tsx:1715`（graph 创建 effect 依赖含 `isFullViewport`、`isReadOnly`）、`3698-3702`（只读切换按钮）、`3652`（全屏按钮）。
* 问题：每次切换都 `graph.destroy()` 重建，新 Graph 视图回到 scale=1、translate=0，选区也不恢复（`renderFromDocument` 只能恢复"重建前已选中"的 id，而重建时选区已空）。
* 场景：用户放大到 200% 精修时点"只读预览"检查效果，回来又要重新缩放、重新找到刚才的位置和选区。
* 修复建议：把只读相关配置（connectable/editable 等）改为在已有 graph 上动态 set（这些都有 setter），不要重建；全屏切换同理（isFullViewport 只影响 CSS，不应重建 graph）。

### P2-I7 Escape 键几乎未处理

* 位置：`SyncedDiagram.tsx:3486-3561`（handleKeyDown 无 Escape 分支；组件也未使用 maxGraph 的 KeyHandler）。
* 问题：Esc 不能取消选区、不能关闭自定义右键菜单（`4209-4234` 只在画布 pointerdown 时关闭）、不能关闭移动端侧栏（compactPanel）、不能退出全屏。目前 Esc 仅能：取消单元格文本编辑（maxGraph CellEditor 自带）和关闭协作面板（`1052-1059`）。
* 修复建议：统一 Esc 优先级：关右键菜单 → 关 compactPanel/对话框 → 清空选区 → 退出全屏。

### P2-I8 右键菜单一组问题

* 位置：`SyncedDiagram.tsx:3467-3484`（openContextMenu）、`4209-4234`（菜单 JSX）、`4164`（容器 overflow-hidden）。
* 问题：
  * a) 菜单位置按高度 280px 估算 clamp（`3480-3481`），但 8 个菜单项实际约 330px，在画布底部右击时菜单被容器 `overflow-hidden` 裁掉，"删除"等靠下的项不可达；
  * b) 打开菜单时 `graphContainerRef.current?.focus()`（`3483`）立即把焦点抢回画布，`role="menu"` 形同虚设，键盘无法操作菜单；
  * c) 菜单打开期间焦点在画布上，按 Delete 仍会删除选中元素，菜单却停在原地显示过期状态；
  * d) 右击空白处不清空旧选区（`3473-3477` 只在命中单元时改选区），菜单显示的是无关旧选区的操作。
* 修复建议：测量实际菜单高度后再 clamp（或改用 Floating UI 类库自动翻转）；菜单打开时聚焦菜单本身并支持方向键/Esc；菜单打开期间屏蔽画布编辑快捷键；右击空白时清空选区或显示"粘贴/全选"等空白菜单。

### P2-I9 远程光标在本地平移/缩放/滚动后停在错误位置

* 位置：`SyncedDiagram.tsx:4184-4197`（光标的 left/top 在 React render 时用当前 scale/translate/scroll 计算）。
* 问题：本地缩放、滚动、平移不触发 React 重渲染，远端光标标记停留在旧屏幕坐标，直到对方下次移动鼠标（80ms 节流的存在消息）才跳回。
* 修复建议：监听 graph view 的 translate/scale/scroll 变化（或把光标画进 overlay 层随视图变换），让光标位置跟随视图。

### P2-I10 复制不进系统剪贴板，且阻止了浏览器默认复制

* 位置：`SyncedDiagram.tsx:2262-2269`（`Clipboard.copy` 是 maxGraph 模块内静态剪贴板）、`3502-3506`（keydown preventDefault）。
* 问题：复制的内容只能在当前标签页的内存里粘贴；跨标签页、跨窗口、跨设备、粘贴到其他应用都不可能。而 Ctrl+C 已 preventDefault，用户以为复制成功，去别处粘贴得到的却是旧的系统剪贴板内容。
* 修复建议：复制时同时把导出的 JSON（或 SVG/文本）写入 `navigator.clipboard`，粘贴时优先读内部剪贴板、回退读系统剪贴板，实现跨页面/跨窗口粘贴。

### P2-I11 移动端所有操作反馈不可见

* 位置：`SyncedDiagram.tsx:4622-4626`（status 文本 `hidden md:flex`，窄屏只剩一个圆点+title）。
* 问题：组件里几十个操作的唯一反馈渠道是 `setStatus`，但在 <md 宽度下文本被隐藏。手机上删除、粘贴、插入、锁定、对齐等操作全部"无反应"式成功。
* 修复建议：窄屏下用浮动 toast（如 HeroUI 的）或在底部加一行可消失的提示，而不是隐藏 status。

### P2-I12 画布平移方式不可发现

* 位置：`SyncedDiagram.tsx:1345`（setPanning(true)）、`4205-4208`（提示条）。
* 问题：maxGraph `PanningHandler` 默认触发是 Ctrl+Shift+拖拽（`useLeftButtonForPanning=false`，这点是对的，左键拖留给框选），但界面任何位置都没写；无空格+拖、无中键拖。鼠标用户只能靠滚轮纵向滚、Shift+滚轮横向滚。
* 修复建议：提示条补上"框选拖空白处 / Ctrl+Shift 拖拽平移"，并考虑空格临时平移。

### P2-I13 协作时状态栏被合并提示刷屏

* 位置：`SyncedDiagram.tsx:1849`（每条远端 update 事件都 `setStatus("已合并来自 <peerId> 的流程图更新")`）。
* 问题：本地每次事务（60ms 防抖后）都会产生一条同步事件，对方每收到一条就刷一次状态栏——协作中状态栏持续闪烁无意义的 peerId 文本，覆盖掉真正有用的操作反馈。
* 修复建议：远端合并不打扰 status（或节流为"正在同步…/已同步"且不显示裸 peerId）。

### P2-I14 远程选区只显示数量，标签中英混杂且暴露裸 peerId

* 位置：`SyncedDiagram.tsx:1201-1214`（selectedIds 已随 presence 发送）、`4192-4195`（仅渲染 `{peerId.slice(0,12)} · N selected`）。
* 问题：队友选中了哪些元素看不出来（draw.io/Figma 都有彩色选框）；label 里英文 "selected" 与中文界面不一致；peerId 是机器串而非协作面板里的成员名。
* 修复建议：用 presence 颜色在对应单元上画远程选框；label 用成员显示名；文案中文化。

### P3-I15 剪贴板为空时"粘贴"可点且无反馈

* 位置：`SyncedDiagram.tsx:2271-2279`（无 else 分支）、`3710`（菜单项只按 isReadOnly 禁用）。空粘贴应提示"剪贴板为空"或禁用。

### P3-I16 快捷键标签全平台显示 Mac 符号

* 位置：`SyncedDiagram.tsx:3707-3714`、`3848`（"⌘Z""⇧⌘Z""⌘S"等）。Windows/Linux 用户看到 ⌘ 无所适从；应按 `navigator.platform` 显示 Ctrl/⌘。

### P3-I17 无缩放键盘快捷键

* 位置：`SyncedDiagram.tsx:3789-3812` 视图菜单项没有 shortcut；补 Ctrl+=、Ctrl+-、Ctrl+0、Shift+1（适应画布）。

### P3-I18 缺少 Ctrl+X 剪切

* 位置：`SyncedDiagram.tsx:3502-3538`、`3706-3715` 键盘与编辑菜单都没有剪切项，`Clipboard.cut` 现成可用。

### P3-I19 评论定位静默失败

* 位置：`SyncedDiagram.tsx:3132-3146`：关联元素被删后点击评论无任何提示，应 setStatus("关联元素已被删除")。

### P3-I20 背景点阵不随缩放变化

* 位置：`SyncedDiagram.tsx:4178-4182`：背景点固定 20px，与 graph 的 10px 吸附网格在非 100% 缩放下视觉错位；可按 view.scale 动态调整 backgroundSize 或直接用 maxGraph 网格。

### P3-I21 重命名/版本命名对话框不回显选中

* 位置：`SyncedDiagram.tsx:4936-4951`：Input autoFocus 但不 select，重命名页面时用户需手动全选删除旧名；应 `onFocus={e => e.target.select()}`。

---

## 三、界面美化问题

### P1-U1 蓝色主题残留大量 cyan 强调色

* 背景：视觉皮肤已从 cyan 迁移到 Apple 蓝（`--diagram-apple-blue: #0066cc / 暗色 #2997ff`，`index.css:3420/3442`），index.css 用 `!important` 覆盖了一批旧 cyan 类，但以下位置**没有被任何覆盖规则命中**，在界面上直接呈现青色，与全站蓝色语言冲突：
  * `SyncedDiagram.tsx:4447 / 4470 / 4484 / 4495` — 评论与版本面板的操作按钮（"+ 评论"、"标记解决"、"+ 快照"、"恢复"）：`text-cyan-700 hover:bg-cyan-50 dark:text-cyan-200`。这两个面板的 Tab 激活态（`6566`）用的是 `var(--diagram-apple-blue)`，同屏出现蓝/青两种强调色。
  * `SyncedDiagram.tsx:4101` — 图形库集合行激活态 `bg-cyan-500/10 text-cyan-800`。
  * `SyncedDiagram.tsx:4141` — "加载更多"按钮 `text-cyan-700 hover:bg-cyan-50`。
  * `SyncedDiagram.tsx:4004 / 4050 / 4128` — 图形卡片 `focus-visible:ring-cyan-400/50`（focus 环不在 `index.css:3611-3624` 的覆盖清单里，键盘聚焦时出现青色光环）。
  * `SyncedDiagram.tsx:6407` — stencil 占位块 `border-cyan-500/60 bg-cyan-50`。
  * `PublicTransferPage.tsx:3017` — 编辑器加载页 spinner `border-cyan-500/25 border-t-cyan-500`，是用户进入页面的第一屏。
* 修复建议：全部改用 `text-[var(--diagram-apple-blue)]`、`hover:bg-[var(--diagram-apple-blue-soft)]`、`focus-visible:ring-[var(--diagram-apple-blue)]`；同时清理已被 CSS 覆盖的死 cyan 类（`3619/3639/3652/3943/6286/6894/6921` 等），避免后来者误以为 cyan 仍是主题色。

### P1-U4 三个弹窗三种暗色表面、三种结构

* 位置：
  * `DiagramAccountDialog`（`SyncedDiagram.tsx:4685`）：`dark:bg-[#151b24]`，页眉无分隔线，页脚有 border-t。
  * `DiagramCloudDocumentsDialog`（`4786`）：`dark:bg-[#11161e]`，`bg-zinc-50` 浅色底（与登录弹窗的 `bg-white` 不同），页脚有 border-t。
  * `DiagramEditorDialog`（`4892`）：`dark:bg-[#171c24]/95` + `backdrop-blur-2xl` + 自定义大阴影 + `rounded-2xl`，页眉有 border-t，页脚还有 `bg-zinc-50/70 dark:bg-black/15` 底色；内部硬编码 `#0066cc/#2997ff` 共 4 处（`4901、4925、4948、4980`）。
* 根因：HeroUI Modal 是 portal 到 body 的，`.diagram-apple` 作用域的 CSS 变量在弹窗内取不到，所以作者只能硬编码 hex——但三个弹窗各编了一个值，且都与编辑器暗色表面 `#2c2c2e` 不同。
* 修复建议：把 `--diagram-apple-*` token 定义提升到 `:root` / `:root.dark`（或在 body 级别注入），三个弹窗统一 `bg-[var(--diagram-apple-surface)]`、`rounded-2xl`、统一的页眉/页脚结构；蓝色 hex 全部换成 token 或 HeroUI `color="primary"` 默认样式。

### P1-U10 错误只在 9px 灰色状态栏以普通文字呈现

* 位置：所有 catch 分支都走 `setStatus(error.message)`（`SyncedDiagram.tsx:1092、1135、1157、1181、1321、1560` 等），状态栏渲染（`4622-4626`）只有连接绿/灰点 + 灰字，错误、成功、提示三者视觉完全一样——"流程图同步数据超过 4 MB"这类关键错误和"已切换到页面 2"长得一模一样。
* 修复建议：给 status 增加级别（info/success/error），error 时状态点变红、文字用 danger token，严重错误叠加一个可关闭的 toast/横幅。

### P2-U2 成功/错误色多源并存

* 连接状态绿点用 `bg-emerald-500`（`SyncedDiagram.tsx:3645、4623、4626`），协作面板在线点用硬编码 `#30a46c`（`index.css:3691`）——同产品两种绿。
* 红色家族：`text-red-600`（`SyncedDiagram.tsx:6370`）、`text-red-500`（`4473、4497`）、CSS 硬编码 `#dc2626/#b91c1c`（`index.css:3987-3990`）、`--app-apple-danger: #c9343a`（`index.css:1803`）四套并存。
* 云端文件"当前"高亮用 tailwind `blue-500/blue-700` 系（`SyncedDiagram.tsx:4815、4821`），与主题 `#0066cc` 色值明显不同。
* 修复建议：在 `.diagram-apple` 作用域补 `--diagram-apple-success / --diagram-apple-danger` 两个 token，JSX 与 CSS 统一引用；"当前"徽标改用 HeroUI primary 系。

### P2-U5 工具栏下拉菜单完全未做皮肤

* 位置：`DiagramToolbarMenu`（`SyncedDiagram.tsx:6312-6347`）直接用 HeroUI `Dropdown/DropdownMenu` 默认 popover 样式，与画布右键菜单（`4211`，自定义 rounded-lg + apple skin hover 蓝）和整体 Apple 皮肤明显两套语言；且右键菜单项被 CSS 强制成 999px 全圆角药丸（`index.css:3525`），下拉项是 HeroUI 默认圆角。
* 修复建议：给 `Dropdown` 传 `classNames={{ content: "diagram-apple-context-menu ..." }}` 复用右键菜单的表面/边框/hover 样式，或至少在 popover 上统一圆角与 hover 蓝。

### P2-U6 同屏中英文混排、裸 peerId 外露

* `SyncedDiagram.tsx:4627`：桌面端状态栏用英文 `{nodeCount} nodes` / `{edgeCount} edges`，而移动端面板（`3898`）用中文 `{nodeCount} 节点 · {edgeCount} 连线`，同页两种语言。
* `SyncedDiagram.tsx:4194`：远端协作者光标标签直接显示 `presence.peerId.slice(0, 12)`（随机字符串）加英文 `"N selected"`，而协作面板成员列表（`PublicTransferPage.tsx:2229` 起）显示的是"我"/客户端名。
* 修复建议：状态栏统一为"{n} 节点 · {n} 连线 · 已选 {n}"；光标标签改用协作面板已有的 displayName，文案改"{name} · 已选 {n}"。

### P2-U11 加载与空状态规格不一

* 云端文件加载（`SyncedDiagram.tsx:4802`）是纯文字"正在读取云端文件…"，无 spinner；而编辑器入口加载（`PublicTransferPage.tsx:3017`）有 spinner。
* 评论 Tab 有空状态提示（`4454-4457`），**版本 Tab 没有任何空状态**（`4487-4502` 直接渲染空列表，面板一片空白）。
* 图形库空结果有两处样式：`4064`（容器内嵌）与 `4158`（独立虚线框），文案相同样式不同。
* 修复建议：加载态统一 spinner + 文案；版本 Tab 补"暂无版本快照"空状态；图形库两处空结果合并为同一虚线框组件。

### P2-U12 独立流程图页没有公共头部，导航断裂

* 位置：`PublicTransferPage.tsx:2256-2274`：`workspace="diagram"` 时直接返回全屏 `LazySyncedDiagram`，**不包含** `2286-2292` 行的公共 header（`AppLogo` + `PublicToolsMenu` + `UserMenuButton`）。
* 问题：互传页和 NAT 检测页都有统一头部可互相跳转，流程图页只能点"返回控制台"（`SyncedDiagram.tsx:3665`，`href="/"`）回控制台再进其他工具；主题切换也藏在"视图"菜单三级项里，而其他页面 header 上有显式入口。`2287` 行 `isDiagramWorkspace ? "专业流程图" : "互传"` 因此成为 dead code。
* 修复建议：在 standalone 模式下把 `PublicToolsMenu`（和主题按钮）注入编辑器 titlebar 右侧（云端菜单旁），保持公共导航在各工具页可达。

### P3-U3 暗色画布底色与 token 体系脱钩

* 位置：`SyncedDiagram.tsx:3576-3577`：暗色画布 `canvasBackground = "#272729"`，而暗色 `--diagram-apple-page = #1d1d1f`、`--diagram-apple-surface = #2c2c2e`（`index.css:3449-3450`）。`#272729` 是两个 token 之间的"第三种灰"，`gridColor` 也用魔法字符串。
* 修复建议：新增 `--diagram-apple-canvas: #272729` token 而不是内联 hex，否则主题调整时这里会漏。

### P3-U7 全局 `letter-spacing: 0 !important` 使字距类成死代码

* 位置：`index.css:3436-3439` 对 `.diagram-apple *` 强制 `letter-spacing: 0`，导致 `SyncedDiagram.tsx:3627`（`tracking-tight`）和 `3936`（"快速模板"的 `tracking-[0.14em]`，uppercase 大写标签本需要字距呼吸感）失效。
* 修复建议：把该规则收窄到具体需要复位的元素，或删掉让 tailwind 字距类生效。

### P3-U8 9px 字号承载过多正文信息

* 位置：状态栏（`SyncedDiagram.tsx:4575`）、画布提示（`4205`）、字段标签（`6585`）、评论时间（`4467`）、版本时间（`4492`）、图形详情（`4013`）、移动端统计（`3898`）均为 `text-[9px]`，且多处叠加 `text-zinc-400` 低对比。9px 只适合做角标，作为状态与说明文字可读性差。
* 修复建议：建立最小 10px 的层级规范：状态栏/说明文字升到 `text-[10px]`，字段标签保持 9px 但加 `font-medium` + 提高对比（zinc-500→zinc-600 / 暗色 zinc-400）。

### P3-U9 日期格式同屏不统一

* 位置：评论（`SyncedDiagram.tsx:4467`）和版本（`4492`）用 `toLocaleString()` 输出完整长日期（9px 塞很长一串），云端文件列表（`4854`）用自定义 `Intl.DateTimeFormat` 短格式。
* 修复建议：统一用 `4851` 行的短格式函数。

### P3-U13 编辑器与落地页双 token 体系漂移风险

* 落地页/互传页用 `--app-apple-*` 体系（`index.css:1789` 起），编辑器用 `--diagram-apple-*`（`3419` 起）——两套 token 色值几乎相同但各自维护（blue 一致，但 line/control/shadow 有微妙差异，如 line 透明度 0.1 vs 0.12）。另外：编辑器主按钮是全圆角药丸（`index.css:3525`），互传页按钮是 `radius="sm"`；编辑器 Tab 是下划线式（`SyncedDiagram.tsx:6566`），页面 Tab 是药丸填充式（`4584`）。
* 修复建议：两套 token 合并同源（`--diagram-apple-*` 直接 `= var(--app-apple-*)`），避免日后漂移；药丸按钮在编辑器内是统一语言可保留。

### P3-U14 侧边栏宽度桌面/移动两套值无对应关系

* 图形库：桌面 grid 列 260px（`SyncedDiagram.tsx:3902`）vs 移动抽屉 310px（`3912`）；属性栏：桌面 300px（`3902`）vs 移动 340px（`4237`）。同一面板两种宽度，从窄屏拖宽到 lg 断点时内容会跳动。
* 修复建议：统一为 280/320 或都让 grid 列宽 = 抽屉宽。

### P3-U15 同类"计数徽标"三种样式

* 图形库计数（`SyncedDiagram.tsx:3919`：`font-mono text-[10px]`）、属性栏计数（`4248`：`text-[9px] font-medium`）、协作面板计数（`index.css:3714` `.diagram-collaboration-count`，蓝色描边药丸）。同一"数量"语义三种视觉。
* 修复建议：抽一个统一的 count-badge 类（建议沿用协作面板的 blue-soft 药丸）。

### P3-U16 评论/版本 Tab 标题与 Tab 标签信息冗余

* `SyncedDiagram.tsx:4268` Tab 已是"评论 N"，面板内 `4441-4443` 又渲染"评论 · N"标题 + 大号"+ 评论"按钮，版本 Tab 同样重复（`4483`）。在 300px 宽面板里占了两行垂直空间。
* 修复建议：面板内只保留操作按钮（右对齐小按钮），删除重复计数标题。

### P3-U17 嵌入式模式最小高度在矮视口溢出

* `SyncedDiagram.tsx:3661`：非全屏时 `h-[min(78dvh,680px)] min-h-[540px]`——在高度 < ~700px 的设备（如横屏手机、小窗）540px 最小高会顶破页面流。独立页不受影响（全屏模式）。
* 修复建议：`min-h-[540px]` 改为 `min-h-[min(540px,100dvh-头部高度)]` 或去掉 min-h 改用 `h-[max(420px,min(78dvh,680px))]`。

---

## 建议的修复顺序

| 批次 | 内容 | 理由 |
|---|---|---|
| 第一批（数据安全） | F1 + F2（同步竞态同根因）、F5（解压上限） | 数据损坏 + 全房间永久失同步、恶意文件冻结标签页 |
| 第二批（小改动高收益） | I1（锁定语义）、I2（快捷键上移 window，顺带 I7 Esc）、I3（滚轮缩放）、F6（粗体判定）、U1（cyan 残留） | 编辑器基本盘与最显眼视觉分裂，改动均较小 |
| 第三批（协作体验） | I4（撤销反馈/跨页）、I5（属性草稿）、F3（校验性能）、F4（发送失败感知）、I13（状态栏刷屏） | 协作高频痛点与性能 |
| 第四批（精致度） | U4（弹窗统一）、U10（错误可视化）、U12（公共导航）、U2/U6/U11（token/文案/空状态）、其余 P3 | 感知"精致度"的部分 |
