# Go Server 远端部署

该目录提供从 Windows PowerShell 构建并通过 SSH 部署 Go server 的入口。默认目标为
SSH 配置中的 `ali2`，也可以通过 `-HostName` 或 `GO_SERVER_DEPLOY_HOST` 指定。

## 首次安装

首次安装建议提供已填写的生产环境文件。脚本会安装 systemd unit、写入环境文件、
启动服务并检查 `/health`：

```powershell
.\deploy\go-server\remote\deploy.ps1 `
  -HostName ali2 `
  -EnvFile .\deploy\go-server\remote\tunnel-server.env `
  -Yes
```

真实环境文件不要提交到 Git。未传 `-EnvFile` 时，首次安装只生成
`/etc/tunnel-server-go/tunnel-server.env` 模板，不会启动带默认密码的服务。

## 滚动更新

服务器已经安装后，脚本保留现有环境文件，更新二进制和 systemd 文件，执行健康检查；
失败时由 `systemd/update.sh` 自动回滚二进制：

```powershell
.\deploy\go-server\remote\deploy.ps1 -HostName ali2 -Yes
```

## 替换 Java server

`-ReplaceJava` 从远端 `/etc/tunnel-server/tunnel-server.env` 生成 Go 配置，在服务器内
转换 Java MySQL JDBC 参数，因此数据库和认证密钥不会下载到构建机。切换前会备份
Java JAR、unit 和 env；Go 未通过健康检查、页面检查或端口检查时自动恢复 Java。

```powershell
.\deploy\go-server\remote\deploy.ps1 `
  -HostName ali2 `
  -ReplaceJava `
  -Yes
```

成功后 Java 服务仅停止并禁用，不会删除。备份保存在
`/var/backups/shuai-tunnel/java-to-go-*`。

常用参数：

| 参数 | 说明 |
| --- | --- |
| `-Architecture amd64|arm64` | Linux CPU 架构，默认 `amd64` |
| `-SkipBuild` | 使用 `deploy/go-server/out` 中已有产物 |
| `-SkipFrontend` | 使用当前已生成的嵌入式管理前端 |
| `-SkipTests` | 构建时跳过 Go 测试 |
| `-ReplaceJava` | 迁移远端 Java 配置并以可回滚方式切换到 Go |
| `-DryRun` | 仅显示构建和远端命令 |
| `-KeepRemoteTemp` | 成功后仍保留远端临时目录 |

构建产物也可以单独生成：

```powershell
.\deploy\go-server\build-linux.ps1 -Architecture amd64
```

输出目录为 `deploy/go-server/out/shuai-tunnel-server-linux-amd64`，同时生成
`tar.gz`、`manifest.json` 和 `SHA256SUMS`。
