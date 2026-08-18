# 客户端版本编目与升级

本文定义 Java、Go、.NET 服务端以及 Java、Go、.NET、Android 客户端共用的版本发布契约。C 语言实现不在本轮范围内。

## 发布模型

- 管理员通过 `POST /api/admin/client-packages` 上传二进制。服务端在受控临时文件中流式接收，计算 SHA-256 与文件大小，校验元数据后原子发布到 `data/packages/{id}`。
- 唯一发布坐标是 `implementation / platform / arch / version`。同一 `implementation / platform / arch` 只允许一个 `isLatest=true` 版本，且停用的版本不能标记为最新。升级检查只采用管理员显式标记的 latest；删除或停用 latest 后不会自动把历史版本晋级为新 latest。
- `android / android / any` 表示 Android 通用 APK；Java 和 .NET CLI 可使用 `any / any`；Go 与 Windows 桌面版使用精确平台和架构。
- 删除托管记录时同步删除本记录拥有的包文件；外部 HTTPS 链接记录不触碰文件系统。路径始终由服务端记录生成，不接受用户提供的磁盘路径。
- 旧 `client_download_link` 数据保留并回填兼容字段，原 JSON CRUD 仍可维护外链。公开仓库默认把带摘要和大小的 GitHub Release 资产登记为外链；服务端托管包是内网、离线或自建分发的可选方式。公开下载页统一读取版本编目，GitHub API 仅用于补齐尚未登记的目标或短时故障回退。

## 公共接口

`GET /api/public/client-downloads` 保留旧字段并追加：

```json
{
  "version": "1.4.0",
  "sha256": "…64 lowercase hex…",
  "fileSize": 123456,
  "isLatest": true,
  "changelogUrl": "https://…",
  "minSupportedVersion": "1.2.0",
  "hosted": true,
  "packageId": 42
}
```

外链记录的 `hosted=false`、`packageId=null`，`downloadUrl` 是无 userinfo/query/fragment 的绝对 HTTPS Release 资产 URL；托管记录的 `downloadUrl` 指向同源 `/api/public/client-packages/{id}/download`。两类记录只有在具备权威 `sha256` 与正数 `fileSize` 后才能标记为 latest 并参与版本检查。

`GET /api/public/client-version-check?implementation=&platform=&arch=&current=` 返回固定结构：

```json
{
  "updateAvailable": true,
  "mandatory": false,
  "latestVersion": "1.4.0",
  "packageId": 42,
  "downloadUrl": "/api/public/client-packages/42/download",
  "sha256": "…",
  "fileSize": 123456,
  "changelogUrl": "https://…"
}
```

无匹配版本时仍返回 `200`，两个布尔值为 `false`、`fileSize=0`，其余版本/包字段为 `null`。版本比较忽略可选前导 `v`，按数字语义比较稳定版本；无法安全解释的版本不能静默覆盖已有最新版本。`mandatory` 只表示当前版本低于最新记录的 `minSupportedVersion`，不授权客户端绕过用户确认。

版本检查可返回两种下载位置：托管包携带正数 `packageId` 并使用同源精确路径；外部 Release 资产的 `packageId=null`，使用绝对 HTTPS URL。自更新客户端对外链最多跟随 5 次 HTTPS 重定向，禁止降级，最后仍按编目中的大小与 SHA-256 校验内容。

包下载支持 `GET` 与 `HEAD`，匿名只读，应用可信代理后的客户端 IP 限速；响应禁止 MIME sniffing，并使用附件下载及 `no-store`。生产环境由 HTTPS 入口提供传输保护。

## 管理接口

`POST /api/admin/client-packages` 使用 multipart 独立字段：

`file`, `implementation`, `platform`, `arch`, `version`, `displayName`, `description`, `changelogUrl`, `minSupportedVersion`, `displayOrder`, `enabled`, `isLatest`。

托管上传的 `sha256`、`fileSize`、`downloadUrl` 和 `packageId` 不接受客户端覆盖。既有 `/api/admin/client-downloads` JSON CRUD 保留，用于登记外部 Release URL 及其权威摘要/大小；`POST /api/admin/client-downloads/{id}/latest` 在事务内切换同目标最新版本。

## 客户端行为

- 全部客户端把构建版本写入登录环境的 `clientVersion`；管理端客户端列表与概览版本分布使用最近一次会话上报值。
- Go 与 .NET 在启动时检查，并按 `updateCheckIntervalHours` 周期复查（默认 24 小时，可配置 1..168 小时）。交互运行先提示；显式自动升级配置才允许无人值守安装。下载可以来自 GitHub Release 外链或同源托管包，必须核对长度和 SHA-256，再以同卷临时目录、备份和原子替换完成；替换或重启进程创建失败时恢复并重新启动旧版本。
- Java 在启动与周期检查时只提示版本、更新说明和下载地址，不自动覆盖正在运行的 JAR。
- Android 在应用启动或再次进入前台时最多每 24 小时检查；只打开 Android 的受校验 HTTPS/同源下载 URL，由系统下载与安装界面再次确认，不请求静默安装权限。
- 检查失败不得阻止隧道启动。用户拒绝或稍后处理不得被当作运行错误。

## 发布流水线

tag 构建统一注入版本到 Go `-ldflags`、Java Maven revision、.NET `Version` 与 Android `versionName`，并在打包前执行对应测试；手动 workflow 以 commit 试跑时映射为合法的 `0.0.0-commit.<hash>` 构建版本，归档名仍保留原 commit。Android `versionCode` 使用单调递增的 workflow run number。APK 先在不接触密钥的构建任务中测试并产出 unsigned 内部 artifact，再由独立的 `release-signing` 受保护环境签名；签名任务必须同时匹配固定的 `SPECUS_ANDROID_CERT_SHA256`，unsigned artifact 不进入 GitHub Release。缺少签名 secrets 或证书指纹不匹配时流水线直接失败。所有归档与 APK 同时生成名称不冲突的 SHA-256 sidecar/清单，GitHub Release 继续作为默认外链分发和灾备来源。
