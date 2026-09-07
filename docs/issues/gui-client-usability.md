# 图形客户端 #40：实现与发版验收记录

日期：2026-09-07。关联 [GUI #40](https://github.com/devShuai/specus/issues/40) 与 [CLI #39](https://github.com/devShuai/specus/issues/39)。

当前实现及自动化回归已完成一轮，**不代表 #40 已可关闭**。2026-09-07 用户明确决定“先发布”，因此安排 v1.2.5 联合发布，并在发布说明公开尚未完成的真机、长期运行及实际服务可达性验收；不据此勾选未验证项目或宣称可靠性指标已提升。

## 本轮实现

| 项目 | 实现 | 仍需验证的边界 |
| --- | --- | --- |
| GUI-01 | Android 按实际模式选择前台服务类型；VPN 授权后使用 systemExempted，非 VPN 常驻隧道使用带用途说明的 specialUse。不声明无关闹钟权限，不循环重启规避限制。超时/撤销授权保留恢复说明，用户停止后不自动重启。 | Android 15+ 真机 VPN/非 VPN 长期后台、系统限制及厂商电池策略；商店分发的 specialUse 审核。 |
| GUI-02 | Android 默认网络变化、Windows 网络变化/睡眠恢复唤醒现有重连循环；2 秒合并重复提示、带随机抖动的有界退避、立即重试、取消当前登录/连接并刷新会话信息。停止后事件不启动新实例。 | 真机 Wi-Fi/蜂窝切换、Windows 睡眠恢复、断网恢复及完整无重连风暴测量。 |
| GUI-03 | Android DNS/控制连接按地址族交错遍历，最多 8 个候选，每通道总预算 15 秒，TCP 单候选最多 1.5 秒，TLS 使用剩余预算且保留原始主机名验证。DNS 工作线程和队列有界，取消清理连接。 | 真实 IPv4/IPv6 单栈、双栈、DNS 黑洞和 TLS 故障；这是顺序回退，不是 Happy Eyeballs 竞速。 |
| GUI-04 | Android HTTP 错误结构化分类，不展示响应体；408/425/429/5xx 退避，凭据/权限/网关等需干预的拒绝停止自动循环并可手动重试。403 说明同时包含凭据、账户、时钟和网关，不声称永久失效。Windows 复用 CLI 分类并保留具体失败摘要。 | 各真实服务端/代理拒绝与限流路径的端到端表现。 |
| GUI-05 | Android 进程内权威状态及有界消息记录，Activity 恢复/重建重新拉取，草稿恢复。控制认证、转发通道就绪、降级及停止分离；业务目标尚未探测。 | 真实后台长连接、进程被系统终止后的恢复说明与厂商行为。 |
| GUI-06 | Android 在线且有接收能力的设备选择；本地稳定消息 ID 更新发送结果，失败保留文本，不将提交显示成送达。直连尝试后 ACK 丢失视为结果未知，不自动转服务端重复发送。长按可恢复内容重新编辑，重发前提示确认对方未收到。 | 跨设备 ACK 超时、附件能力、离线/不兼容目标及人工重新发送；本地 ID 不等于跨传输协议幂等键，不保证用户重发的 exactly-once。 |
| GUI-07 | Android 首次设置入口、凭据来源及 VPN 权限解释；Windows 已配置后折叠连接设置，技术选项收进高级设置，关闭窗口选择后台/停止退出/取消，提供托盘入口和明确退出，不增加自启动。 | 首次接入用户试用、真实 VPN 授权/拒绝、Windows 交互桌面托盘与退出。 |
| GUI-08 | Windows 默认共享服务，连接诊断二级入口，运行日志折叠；800×520 最小窗口下按钮常驻、分页换行、表格水平滚动；明暗主题。 | 真实显示器 150%/200% DPI、键盘和读屏、连接后有数据状态。 |
| GUI-09 | Android 设备/互传/设置分区、弹性聊天高度、48dp 常用触控目标、系统明暗主题、键盘避让；记录清除入口不再占据整行聊天高度。 | 完整大字体/小屏/横屏/键盘组合，TalkBack 和真实设备输入法。 |

消息保留策略：Android 仅保留本次进程最近 100 条，每条显示文本上限 16,384 字符；不新增聊天明文磁盘存储。Activity 重建恢复草稿，不承诺被系统杀进程后的聊天历史。清除仅作用于本机记录与草稿，不删除已下载文件或对方记录。

服务类型依据：[Android 前台服务类型](https://developer.android.com/develop/background-work/services/fgs/service-types)、[系统超时](https://developer.android.com/develop/background-work/services/fgs/timeout)。VPN 身份是 systemExempted 的前提，specialUse 的声明不等于已通过 Google Play 审核。

## 已执行验证

- Windows `.NET 10`：共享核心 327 项及 WPF 布局 1 项通过。新增网络事件突发测试的活动登录并发峰值为 1，50 次提示合并后共 2 次登录尝试；这是受控用例，不是生产成功率。
- `.NET CLI` 独立进程矩阵：Windows 32 项、WSL Ubuntu Linux 33 项通过。覆盖登录/状态查询、控制认证与通道就绪区分、临时失败恢复、终止、状态目录权限等；Linux 使用本轮重新发布的自包含测试产物。Go/Java 未在本轮重复执行，其 CLI 结果见 #39。
- Android JVM：207 项通过；Android 16 / API 36.1 专用只读模拟器：8 项设备测试通过。包括后台消息/Activity 重建/草稿、发送失败单记录、真实非 VPN 前台服务启动及本机 HTTP 403 拒绝后停止（请求 1 次，响应正文未显示）。这些不替代 Android 15 真机长期在线测试。
- Android `lintDebug` 通过，仍存在警告，不宣称零警告。
- WPF 使用真实 XAML、隔离的测试配置进行明暗主题、800×520/1200×760 布局测试，产生 1×/1.5×/2× 共 12 张离屏 PNG。高分辨率离屏渲染不等于操作系统真实高 DPI 验收，也未覆盖系统托盘/睡眠。
- Android 实际模拟器截图覆盖首次设置、互传、键盘、深色横屏与小屏 150% 字体；截图检查发现并修正文件按钮裁切、横屏记录区过小。截图为工作区 `.tmp/gui40/` 本地产物，不作为已上传 issue 的附件。

复现命令（仓库根目录，平台依赖需先安装）：

```powershell
dotnet test implementations/csharp/client/Specus.Client.slnx
$env:SPECUS_GUI_TEST_SCREENSHOTS = '1'
$env:SPECUS_GUI_TEST_OUTPUT = Join-Path (Get-Location) '.tmp/gui40'
dotnet test implementations/csharp/client/tests/Specus.Client.Desktop.Tests
python scripts/test-cli-matrix.py --name dotnet -- dotnet implementations/csharp/client/src/Specus.Client/bin/Debug/net10.0/specus-client.dll
```

Android 项目目录：`gradlew.bat :app:testDebugUnitTest :app:connectedDebugAndroidTest :app:lintDebug`。设备测试只在专用模拟器/测试设备运行，避免改动日常用户配置。

## 发布后的跟进验收

1. 接入 Android 15+ 测试真机及受控服务端/第二客户端，完成 VPN/非 VPN 长期后台、网络切换、真实消息/附件/ACK 故障测试，记录型号、系统、时长、样本和结果。
2. Windows 交互桌面验证托盘后台/退出、睡眠唤醒、真实高 DPI 与读屏；不能用离屏 PNG 代替。
3. 分开测量首次连接成功率、恢复耗时、长期在线率、显示通道就绪后的服务可访问率。当前这些指标均**未测量**，不能从单元测试通过率推导。
4. 将验收证据逐项补到 #40，确认剩余实现和交互边界后才能关闭。本次按用户决定先联合发布，但仍执行仓库现有构建、测试与产物校验，不绕过 Android 签名或发布环境保护。
