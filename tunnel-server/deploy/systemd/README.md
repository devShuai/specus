# tunnel-server Linux systemd 部署

本目录提供把 `tunnel-server` 作为 systemd 服务部署到 Linux 上、并通过环境变量
配置 MySQL 数据库连接的全套文件：

| 文件 | 用途 |
| --- | --- |
| `tunnel-server.service` | systemd unit 定义，启动 / 停止 / 自动重启 / 日志接 journald |
| `tunnel-server.env.example` | 环境变量模板（**MySQL 连接、管理员密码、JWT 密钥都在这里**） |
| `install.sh` | 一键安装：建用户、建目录、拷 jar、注册服务 |

---

## 1. 前置条件

* Linux + systemd（CentOS 7+/8+/9、Ubuntu 20.04+、Debian 11+ 等均可）
* JDK 21+（推荐 Temurin 21 或 OpenJDK 21）
* 已经准备好可访问的 MySQL 8 实例
* 已经在本机或本地 dev 机器上构建好 `tunnel-server` jar：

  ```bash
  mvn -pl tunnel-server -am -DskipTests clean package
  # 产物：tunnel-server/target/tunnel-server-1.0-SNAPSHOT.jar
  ```

把 jar 上传到目标 Linux 机器（任意临时目录皆可）。

## 2. 准备 MySQL

```sql
CREATE DATABASE tunnel
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER 'tunnel'@'%' IDENTIFIED BY 'CHANGE_ME_STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON tunnel.* TO 'tunnel'@'%';
FLUSH PRIVILEGES;
```

`tunnel-server` 启动时 Hibernate 会按 `ddl-auto=update` 自动建表，无需手动迁移。

## 3. 一键安装

```bash
# 把整个 deploy/systemd 目录拷到目标机器，例如 /tmp/systemd
sudo bash /tmp/systemd/install.sh /tmp/tunnel-server-1.0-SNAPSHOT.jar
```

脚本会做以下事情：

1. 创建 `tunnel` 系统账号（`/usr/sbin/nologin`，不能交互登录）
2. 准备目录：
   * `/opt/tunnel-server/tunnel-server.jar` —— 程序
   * `/etc/tunnel-server/tunnel-server.env` —— 环境变量（chmod 640，root 与 tunnel 组可读）
   * `/var/lib/tunnel-server` —— 工作目录（fallback SQLite 文件、临时数据）
   * `/var/log/tunnel-server` —— 预留日志目录（默认日志走 journald）
3. 把 `tunnel-server.service` 安装到 `/etc/systemd/system/`
4. 把 `tunnel-server.env.example` 拷贝为 `/etc/tunnel-server/tunnel-server.env`（已存在则不覆盖）
5. `systemctl daemon-reload && systemctl enable tunnel-server`

## 4. 配置环境变量

编辑 `/etc/tunnel-server/tunnel-server.env`，**至少修改 3 类字段**：

```bash
sudo vim /etc/tunnel-server/tunnel-server.env
```

### 4.1 MySQL 连接

```env
TUNNEL_DB_URL=jdbc:mysql://192.168.1.20:3306/tunnel?useUnicode=true&characterEncoding=UTF-8&connectionCollation=utf8mb4_unicode_ci&useSSL=false&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true
TUNNEL_DB_DRIVER=com.mysql.cj.jdbc.Driver
TUNNEL_DB_USERNAME=tunnel
TUNNEL_DB_PASSWORD=CHANGE_ME_STRONG_PASSWORD
TUNNEL_DB_DIALECT=org.hibernate.dialect.MySQLDialect
TUNNEL_DB_POOL_SIZE=16
```

> JDBC URL 必须显式带上 `serverTimezone` 与 `allowPublicKeyRetrieval=true`，
> 否则 `mysql-connector-j` 8.x + MySQL 8 的默认 `caching_sha2_password` 认证会失败。
>
> ⚠️ `characterEncoding` 用的是 **Java 字符集名 `UTF-8`**，不要写成 MySQL 服务端的 `utf8mb4`，
> 否则启动时会抛 `Unsupported character encoding 'utf8mb4'`。
> emoji / 中文的存储靠服务端建库时的 `CHARACTER SET utf8mb4` 加 URL 上的
> `connectionCollation=utf8mb4_unicode_ci` 一起保证。

### 4.2 管理员账号

```env
TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED=true
TUNNEL_AUTH_USERNAME=admin
TUNNEL_AUTH_PASSWORD=YourStrongAdminPassword
TUNNEL_AUTH_JWT_SECRET=$(openssl rand -base64 48)   # 用命令生成后填入
```

### 4.3 对外地址（可选，部署在反代 / NAT 后必填）

```env
TUNNEL_PUBLIC_ADDRESS=tunnel.example.com
```

环境变量文件中**不需要也不能用 shell 展开**，必须填字面量。

## 5. 启动 / 验证

```bash
sudo systemctl start tunnel-server
sudo systemctl status tunnel-server
sudo journalctl -u tunnel-server -f       # 实时日志
```

正常情况下能看到 `Started TunnelServerApplication ... in X seconds` 与 Netty 监听
`7010`、HTTP 监听 `8088` 的输出。

健康检查：

```bash
curl -s http://127.0.0.1:8088/actuator/health
# {"status":"UP"}
```

## 6. 升级 / 卸载

### 升级 jar（推荐：滚动升级脚本）

```bash
# 把新 jar 上传到任意临时位置
sudo bash deploy/systemd/update.sh /tmp/tunnel-server-NEW.jar
```

`update.sh` 自动完成：
1. 备份当前 jar → `/opt/tunnel-server/tunnel-server.jar.bak.<时间戳>`（保留最近 5 份）
2. `systemctl stop` → 替换 jar → `systemctl start`
3. 等服务进入 `active`（最多 60s）
4. 轮询 `http://127.0.0.1:8088/actuator/health` 直到返回 `UP`（最多 60s）
5. 任一步失败 → 自动回滚到刚刚备份的旧 jar 并重启

退出码：`0` 成功 / `2` 升级失败但已回滚 / `3` 回滚失败需人工介入。

健康检查地址可用环境变量覆盖（例如端口不是 8088）：
```bash
sudo TUNNEL_HEALTH_URL=http://127.0.0.1:9090/actuator/health \
     bash deploy/systemd/update.sh /tmp/tunnel-server-NEW.jar
```

### 手动升级（不要回滚 / 不要健康检查时）

```bash
sudo systemctl stop tunnel-server
sudo install -m 0644 -o root -g root \
     /tmp/tunnel-server-NEW.jar /opt/tunnel-server/tunnel-server.jar
sudo systemctl start tunnel-server
```

或者直接重跑 `install.sh`，脚本对 jar 是覆盖式安装、对 env 文件是保留式安装。

### 修改环境变量后重启

```bash
sudo systemctl restart tunnel-server
```

> systemd 不会热加载 `EnvironmentFile`，必须重启服务才能让新值生效。

### 卸载

```bash
sudo systemctl stop tunnel-server
sudo systemctl disable tunnel-server
sudo rm -f /etc/systemd/system/tunnel-server.service
sudo systemctl daemon-reload

# 数据目录与配置请按需要保留 / 备份后再删
sudo rm -rf /opt/tunnel-server /var/log/tunnel-server
sudo rm -rf /etc/tunnel-server /var/lib/tunnel-server   # ⚠️ 含数据库密码 / 本地 fallback 数据
sudo userdel tunnel
sudo groupdel tunnel
```

## 7. 常见问题

| 现象 | 原因 / 解决 |
| --- | --- |
| `Unable to obtain isolated JDBC connection [Unsupported character encoding 'utf8mb4']` | URL 里把 `characterEncoding` 写成了 MySQL 服务端字符集名。改为 Java 字符集名 `UTF-8`，并用 `connectionCollation=utf8mb4_unicode_ci` 控制连接 collation |
| `Communications link failure` 或 `Public Key Retrieval is not allowed` | URL 缺少 `allowPublicKeyRetrieval=true`；或 MySQL bind-address 未对 tunnel-server 开放 |
| `The server time zone value 'CST' is unrecognized` | URL 缺少 `serverTimezone=Asia/Shanghai` |
| 启动报 `Access denied for user` | env 文件中 `TUNNEL_DB_USERNAME` / `TUNNEL_DB_PASSWORD` 与 MySQL 不一致；密码若含 `#`、空格等特殊字符，请用双引号包裹：`TUNNEL_DB_PASSWORD="my pa#ss"` |
| 启动看到 `Cache provider classpath warning` 之类 | 与本部署无关，可忽略 |
| 客户端连不上 7010 端口 | 检查防火墙：`sudo firewall-cmd --add-port=7010/tcp --permanent && sudo firewall-cmd --reload` |
| 想绑定 80/443 等特权端口 | 在 `tunnel-server.service` 的 `[Service]` 中追加 `AmbientCapabilities=CAP_NET_BIND_SERVICE` 与 `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` |

## 8. 文件清单

```
deploy/systemd/
├── README.md                    # 本文件
├── install.sh                   # 一键安装脚本（root 执行，首次安装）
├── update.sh                    # 滚动升级脚本（root 执行，备份 / 健康检查 / 失败回滚）
├── tunnel-server.service        # systemd unit
└── tunnel-server.env.example    # 环境变量模板（含 MySQL 注释说明）
```
