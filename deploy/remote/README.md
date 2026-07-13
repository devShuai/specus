# 一键部署到远端服务

`deploy/remote` 把本地当前工作区构建并部署到远端生产式环境。默认目标是 SSH
别名 `ali2`，Java 服务使用现有的 systemd 回滚更新流程，管理前端使用现有的
OpenResty 安装流程。

## 快速使用

macOS / Linux：

```bash
./deploy/remote/deploy.sh auto --yes
```

Windows PowerShell：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\remote\deploy.ps1 -Mode Auto -Yes
```

不加 `--yes` / `-Yes` 时，脚本会显示分支、改动文件和部署范围并等待确认。

## 部署模式

| 模式 | 行为 |
| --- | --- |
| `auto` | 根据当前 Git 已跟踪改动和未跟踪文件判断；前后端都有改动时执行 `all` |
| `frontend` | 运行 `npm run build:openresty`，更新 `/opt/shuai-tunnel/admin-web` 并 reload OpenResty |
| `server` | 运行 Maven Java server 打包，调用远端 `update.sh` 更新并执行健康检查 |
| `all` | 先更新 Java server，再更新 OpenResty 前端 |

`auto` 在没有发现部署相关改动时会执行 `all`，可用于重新部署当前提交。

```bash
./deploy/remote/deploy.sh frontend
./deploy/remote/deploy.sh server
./deploy/remote/deploy.sh all --host user@example-host --yes
```

PowerShell 使用对应的 `-Mode Frontend|Server|All` 和 `-HostName` 参数。

## 参数

### Bash

```text
--host <ssh-host>       默认 ali2；端口、密钥等高级设置放在 ~/.ssh/config
--site-url <origin>     默认 https://tunnel.devshuai.com
--yes                   跳过交互确认
--dry-run               只打印计划和命令，不构建、不连接远端
--no-clean              Maven 不执行 clean，仅作为文件锁等场景的显式回退
--keep-remote-temp      成功后仍保留远端 /tmp 上传目录
```

环境变量 `DEPLOY_HOST`、`DEPLOY_SITE_URL` 可提供默认值。

### PowerShell

参数分别为 `-HostName`、`-SiteUrl`、`-Yes`、`-DryRun`、`-NoClean`、
`-KeepRemoteTemp`，也支持相同的两个环境变量。

## 安全与回滚

- 脚本不会执行 Git stage、commit、reset 或 push，部署的是当前工作区实际内容。
- 默认先显示最多 20 个本地改动文件；非交互环境应显式使用 `--yes` / `-Yes`。
- Java 更新复用 `deploy/java-server/systemd/update.sh`：备份现有 jar、更新、等待
  systemd active 和 Actuator `UP`；失败时自动回滚。
- 远端 `/etc/tunnel-server/tunnel-server.env` 不会被覆盖，只更新 env 示例文件。
- OpenResty 更新复用 `deploy/openresty/install-admin-web.sh`，安装前会执行配置检查。
- 每次上传使用唯一 `/tmp/shuai-tunnel-deploy-*` 目录。成功后自动清理；失败时保留并
  输出路径，便于定位。
- 当前入口面向生产使用的 Java server + OpenResty，不会部署 Go、.NET 或 C server。

## 预演

提交部署前可以完整查看将执行的命令：

```bash
./deploy/remote/deploy.sh auto --dry-run
```

```powershell
.\deploy\remote\deploy.ps1 -Mode Auto -DryRun
```
