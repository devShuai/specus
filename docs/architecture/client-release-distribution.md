# 客户端版本编目与升级

本文定义 Java、Go、.NET 服务端以及 Java、Go、.NET、Android 客户端共用的版本发布契约。C 语言实现不在本轮范围内。

## 发布模型

- 管理员通过 `POST /api/admin/client-packages` 上传二进制。服务端在受控临时文件中流式接收，计算 SHA-256 与文件大小，校验元数据后原子发布到 `data/packages/{id}`。
- 唯一发布坐标是 `implementation / platform / arch / version`。同一 `implementation / platform / arch` 只允许一个启用的 `isLatest=true` 版本。
- `android / android / any` 表示 Android 通用 APK；Java 和 .NET CLI 可使用 `any / any`；Go 与 Windows 桌面版使用精确平台和架构。
- 删除托管记录时同步删除本记录拥有的包文件；外部 HTTPS 链接记录不触碰文件系统。路径始终由服务端记录生成，不接受用户提供的磁盘路径。
- 旧 `client_download_link` 数据保留并回填兼容字段，原 JSON CRUD 仍可维护外链。公开下载页优先采用服务端编目，并用 GitHub Releases 补齐未托管目标或作为短时故障回退。

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

外链记录的 `hosted=false`、`packageId=null`。托管记录的 `downloadUrl` 指向同源 `/api/public/client-packages/{id}/download`。

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

包下载支持 `GET` 与 `HEAD`，匿名只读，应用可信代理后的客户端 IP 限速；响应禁止 MIME sniffing，并使用附件下载及 `no-store`。生产环境由 HTTPS 入口提供传输保护。

## 管理接口

`POST /api/admin/client-packages` 使用 multipart 独立字段：

`file`, `implementation`, `platform`, `arch`, `version`, `displayName`, `description`, `changelogUrl`, `minSupportedVersion`, `displayOrder`, `enabled`, `isLatest`。

`sha256`、`fileSize`、`downloadUrl` 和 `packageId` 不接受客户端覆盖。既有 `/api/admin/client-downloads` JSON CRUD 保留；`POST /api/admin/client-downloads/{id}/latest` 在事务内切换同目标最新版本。

## 客户端行为

- 全部客户端把构建版本写入登录环境的 `clientVersion`；管理端客户端列表与概览版本分布使用最近一次会话上报值。
- Go 与 .NET 在启动时检查，并对长时间进程最多每 24 小时复查。交互运行先提示；显式自动升级配置才允许无人值守安装。下载必须核对长度和 SHA-256，再以同目录临时文件、备份和原子替换完成；启动/替换失败恢复旧文件。
- Java 在启动与周期检查时只提示版本、更新说明和下载地址，不自动覆盖正在运行的 JAR。
- Android 在应用启动或再次进入前台时最多每 24 小时检查；只打开 Android 的受校验 HTTPS/同源下载 URL，由系统下载与安装界面再次确认，不请求静默安装权限。
- 检查失败不得阻止隧道启动。用户拒绝或稍后处理不得被当作运行错误。

## 发布流水线

tag 构建统一注入版本到 Go `-ldflags`、Java Maven revision、.NET `Version` 与 Android `versionName`。Android `versionCode` 使用单调递增的 workflow run number，并必须使用长期稳定的发布签名；缺少签名 secrets 时流水线直接失败，不发布不可升级的 unsigned APK。所有归档与 APK 同时生成 SHA-256 sidecar，GitHub Release 继续作为独立分发和灾备来源。
