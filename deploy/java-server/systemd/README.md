# tunnel-server Linux systemd 部署

本目录提供把 `tunnel-server` 作为 systemd 服务部署到 Linux 上、并通过环境变量
配置 MySQL 数据库连接的全套文件：

| 文件 | 用途 |
| --- | --- |
| `tunnel-server.service` | systemd unit 定义，启动 / 停止 / 自动重启 / 文件日志与 journald |
| `tunnel-server.env.example` | 环境变量模板（**MySQL 连接、管理员密码、JWT 密钥都在这里**） |
| `install.sh` | 一键安装：建用户、建目录、拷 jar、注册服务 |
| `update.sh` | 滚动升级：备份 / 替换 jar / 健康检查 / 失败回滚，并同步最新 unit 与 env.example |

---

## 1. 前置条件

* Linux + systemd（CentOS 7+/8+/9、Ubuntu 20.04+、Debian 11+ 等均可）
* JDK 21+（推荐 Temurin 21 或 OpenJDK 21）
* 已经准备好可访问的 MySQL 8 实例
* 已经在本机或本地 dev 机器上构建好 `tunnel-server` jar：

  ```bash
  mvn -pl :tunnel-server -am -DskipTests clean package
  # 产物：implementations/java/server/target/tunnel-server-1.0-SNAPSHOT.jar
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
# 把整个 deploy/java-server/systemd 目录拷到目标机器，例如 /tmp/systemd
sudo bash /tmp/systemd/install.sh /tmp/tunnel-server-1.0-SNAPSHOT.jar
```

脚本会做以下事情：

1. 创建 `tunnel` 系统账号（`/usr/sbin/nologin`，不能交互登录）
2. 准备目录：
   * `/opt/tunnel-server/tunnel-server.jar` —— 程序
   * `/etc/tunnel-server/tunnel-server.env` —— 环境变量（chmod 640，root 与 tunnel 组可读）
   * `/var/lib/tunnel-server` —— 工作目录（fallback SQLite 文件、临时数据）
   * `/var/log/tunnel-server` —— 应用滚动日志目录（同时保留 journald）
3. 把 `tunnel-server.service` 安装到 `/etc/systemd/system/`
4. 把 `tunnel-server.env.example` 拷贝为 `/etc/tunnel-server/tunnel-server.env`（已存在则不覆盖），并始终同步一份最新模板到 `/etc/tunnel-server/tunnel-server.env.example`
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

先在 shell 中生成随机值并复制输出：

```bash
openssl rand -base64 48
```

再把**字面量结果**写入 env 文件：

```env
TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED=true
TUNNEL_AUTH_REGISTRATION_ENABLED=false
TUNNEL_AUTH_USERNAME=admin
TUNNEL_AUTH_PASSWORD=YourStrongAdminPassword
TUNNEL_AUTH_JWT_SECRET=粘贴上一步生成的随机值
TUNNEL_AUTH_TENANT_ID=default
```

注册采用“Cloudflare Turnstile + 邮箱验证码”两阶段流程。先在 Turnstile 控制台创建 widget 的 site key/secret 并限制允许的 hostname，再准备 SMTP 账号；然后配置模板中的 `TUNNEL_AUTH_TURNSTILE_*`、`TUNNEL_AUTH_EMAIL_*`、`TUNNEL_AUTH_SMTP_*`，最后把 `TUNNEL_AUTH_REGISTRATION_ENABLED`、`TUNNEL_AUTH_TURNSTILE_ENABLED`、`TUNNEL_AUTH_EMAIL_VERIFICATION_ENABLED` 同时设为 `true`。缺少任一密钥、hostname 白名单或 SMTP 参数时，服务端不会开放注册入口。

### 4.3 客户端在线限制（可选）

```env
TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES=1
TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES=2
TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS=28800
```

默认策略是同一用户 + 同一机器只允许 1 个客户端进程在线，每个客户端账号最多同时在线 2 个实例。客户端访问令牌过期前会主动刷新，避免隧道因为令牌到期中断。

### 4.4 对外地址（可选，部署在反代 / NAT 后必填）

```env
TUNNEL_PUBLIC_ADDRESS=tunnel.example.com
```

### 4.5 私有组网 / Peer Mesh（可选，默认关闭）

Peer Mesh 用于让同一租户 / 同一用户下多个客户端组成私有组网。开启后，server 仍只负责身份、ACL、虚拟 IP、信令和 relay；客户端优先走 LAN / UDP 直连，失败时自动走 server 内置 relay。

```env
TUNNEL_PEER_MESH_ENABLED=false
TUNNEL_PEER_MESH_CIDR=100.96.0.0/11
TUNNEL_PEER_MESH_PUBLIC_ADDRESS=tunnel.example.com
TUNNEL_PEER_MESH_STUN_TURN_PORT=3478
TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT=3479
# 完整 RFC 5780 可选配置；PUBLIC_ADDRESS 此时填写主公网 IP A1
#TUNNEL_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS=10.0.0.10
#TUNNEL_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS=10.0.0.11
#TUNNEL_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS=203.0.113.11
#TUNNEL_PEER_MESH_STUN_BEHAVIOR_STRICT=true
TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS=stun.example.com:3478,stun2.example.com:3478
TUNNEL_PEER_MESH_SESSION_TTL_SECONDS=3600
TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS=300
TUNNEL_PEER_MESH_RELAY_MIN_PORT=49152
TUNNEL_PEER_MESH_RELAY_MAX_PORT=65535
TUNNEL_PEER_MESH_RELAY_WORKER_THREADS=0
TUNNEL_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY=10000
TUNNEL_PEER_MESH_UDP_RECEIVE_BUFFER_BYTES=4194304
TUNNEL_PEER_MESH_UDP_SEND_BUFFER_BYTES=4194304
TUNNEL_PEER_MESH_UDP_TRAFFIC_CLASS=16
TUNNEL_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS=5000
TUNNEL_PEER_MESH_TURN_AUTH_REQUIRED=true
TUNNEL_PEER_MESH_TURN_REALM=shuai-tunnel
#TUNNEL_PEER_MESH_TURN_SHARED_SECRET=CHANGE_ME_RANDOM_SECRET
TUNNEL_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS=3600
```

启用后需要额外放行 UDP：

```bash
sudo firewall-cmd --add-port=3478/udp --permanent
sudo firewall-cmd --add-port=3479/udp --permanent
sudo firewall-cmd --add-port=49152-65535/udp --permanent
sudo firewall-cmd --reload
```

默认 `3478/udp` 承载服务端标准 STUN/TURN 控制面，`3479/udp` 是 NAT 类型辅助探测端口，`49152-65535/udp`
是标准 TURN relay 分配端口范围。只有一个公网 IP 时，Binding 仍可用，但服务端不会按标准返回
`OTHER-ADDRESS`，带 `CHANGE-REQUEST` 的请求会得到 `420 Unknown Attribute`。

配置 `TUNNEL_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS`、`TUNNEL_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS`、主公网 IP
`TUNNEL_PEER_MESH_PUBLIC_ADDRESS` 和备用公网 IP `TUNNEL_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS` 后，Java server 会在
A1:P1、A1:P2、A2:P1、A2:P2 四个端点启用 RFC 5780。TURN 只保留在 A1:P1，其余端点只接受 Binding。
如果希望 STUN 与业务服务完全解耦，使用
[`deploy/stun-server/systemd`](../../stun-server/systemd/README.md) 的独立 JAR。

`TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS` 是额外公共 STUN 列表，客户端会同时向服务端 STUN 和这些公共 STUN
发起 Binding 探测。公共 STUN 只补充 `srflx` 候选地址，不参与 relay；服务端 TURN 仍是直连失败后的兜底路径。

relay 数据面使用标准 TURN `Send Indication` / `Data Indication` 承载加密后的 peer frame。
`TUNNEL_PEER_MESH_RELAY_WORKER_THREADS` 控制 relay 数据帧工作线程，0 表示自动；relay 流量不会每帧写库，而是按 `TUNNEL_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS` 周期聚合入库。UDP socket 的请求缓冲区和 Traffic Class 可通过 `TUNNEL_PEER_MESH_UDP_RECEIVE_BUFFER_BYTES`、`TUNNEL_PEER_MESH_UDP_SEND_BUFFER_BYTES`、`TUNNEL_PEER_MESH_UDP_TRAFFIC_CLASS` 调整，实际缓冲区上限仍受宿主机内核约束。

客户端侧默认 `peerMeshDevice=noop`，只运行控制面、候选交换、探测和加密 UDP 数据面；要真正接管虚拟 IP 流量，需要启用虚拟网卡：

* Linux：`peerMeshDevice=linux-tun` 或 `auto`，进程需要 root 或 `CAP_NET_ADMIN`，系统需要 `/dev/net/tun` 和 `ip` 命令。
* Windows：`peerMeshDevice=windows-wintun` 或 `auto`，需要管理员权限，并把 `wintun.dll` 放在工作目录 / PATH，或通过 `-Dshuai.peerMesh.wintunDll=完整路径` 指定。
* macOS：`peerMeshDevice=mac-utun`、`utun` 或 `auto`，Java 客户端会创建 utun；可用 `peerMeshTunName=utunN` 尝试请求固定编号，否则由系统分配。

更多验证步骤见仓库内 `docs/peer-mesh/peer-mesh-implementation.md`。

### 4.6 公共互传附件 / 私有 OSS（可选，默认关闭）

公共发现信令无需对象存储；附件上传/下载需要配置私有 Aliyun OSS。浏览器使用短期预签名 URL 直传，
服务端只保存元数据并在存储启用时用 HEAD 校验实际大小。完整变量及限流默认值以同目录
`tunnel-server.env.example` 为准：

```env
TUNNEL_OBJECT_STORAGE_PROVIDER=disabled
#TUNNEL_OBJECT_STORAGE_ENDPOINT=oss-cn-hangzhou.aliyuncs.com
#TUNNEL_OBJECT_STORAGE_REGION=cn-hangzhou
#TUNNEL_OBJECT_STORAGE_BUCKET=your-private-bucket
#TUNNEL_OBJECT_STORAGE_ACCESS_KEY_ID=
#TUNNEL_OBJECT_STORAGE_ACCESS_KEY_SECRET=
TUNNEL_OBJECT_STORAGE_PREFIX=shuai-tunnel/attachments
#TUNNEL_OBJECT_STORAGE_UPLOAD_CALLBACK_URL=https://tunnel.devshuai.com/api/public/transfer/oss-callback
TUNNEL_OBJECT_STORAGE_UPLOAD_URL_TTL_SECONDS=900
TUNNEL_OBJECT_STORAGE_DOWNLOAD_URL_TTL_SECONDS=600
TUNNEL_OBJECT_STORAGE_DOWNLOAD_OBJECT_URL_TTL_SECONDS=30
TUNNEL_OBJECT_STORAGE_RETENTION_HOURS=72
TUNNEL_OBJECT_STORAGE_MAX_ATTACHMENT_BYTES=536870912
TUNNEL_OBJECT_STORAGE_PER_USER_STORAGE_QUOTA_BYTES=1073741824
TUNNEL_OBJECT_STORAGE_PER_USER_MONTHLY_DOWNLOAD_QUOTA_BYTES=1073741824
TUNNEL_OBJECT_STORAGE_EXPIRATION_SCAN_INTERVAL_MS=3600000
TUNNEL_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_PER_IP=30
TUNNEL_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_WINDOW_SECONDS=300
TUNNEL_PUBLIC_TRANSFER_MAX_PENDING_UPLOADS_PER_ROOM=50
TUNNEL_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM=32
TUNNEL_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION=360
TUNNEL_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS=60
TUNNEL_PUBLIC_TRANSFER_CLUSTER_ENABLED=false
TUNNEL_PUBLIC_TRANSFER_REDIS_URI=
TUNNEL_PUBLIC_TRANSFER_REDIS_KEY_PREFIX=shuai-tunnel:v2:public-transfer
TUNNEL_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS=30
TUNNEL_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS=10000
TUNNEL_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS=2000
TUNNEL_PUBLIC_TRANSFER_PAIRING_CODE_TTL_SECONDS=300
TUNNEL_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_PER_IP=10
TUNNEL_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_WINDOW_SECONDS=300
```

配置上传回调后，预签名 PUT 会返回已参与签名的 `x-oss-callback` 请求头，OSS 上传成功时直接回调业务服务；
回调地址必须从公网 HTTPS 可达，且反向代理不能改写路径。bucket CORS 需允许网页来源、`PUT`，以及
`Content-Type`、`x-oss-callback` 请求头。客户端仍调用 complete，作为回调失败时的 HEAD 兜底；两条路径均幂等。

生产环境不要把 OSS 密钥提交到仓库；通过仅 root 可读的 systemd environment file 注入。

### 4.7 HTTP 媒体采集 / RustFS（可选，默认关闭）

媒体采集与公共互传附件相互独立。对需要采集的 HTTP 路由打开管理页中的“媒体采集”开关后，
服务端会把 MP4/WebM Range 响应、HLS/DASH 清单及分段直接以 S3 multipart 写入 RustFS；
业务数据库只保存对象 key、ETag、`Content-Range`、分段序号、初始化段关系和有效期，不保存媒体正文。

```env
TUNNEL_MEDIA_CAPTURE_ENABLED=false
#TUNNEL_MEDIA_CAPTURE_ENDPOINT=http://127.0.0.1:9000
TUNNEL_MEDIA_CAPTURE_REGION=us-east-1
#TUNNEL_MEDIA_CAPTURE_BUCKET=shuai-tunnel-media
#TUNNEL_MEDIA_CAPTURE_ACCESS_KEY_ID=
#TUNNEL_MEDIA_CAPTURE_ACCESS_KEY_SECRET=
TUNNEL_MEDIA_CAPTURE_PREFIX=shuai-tunnel/http-media
TUNNEL_MEDIA_CAPTURE_PATH_STYLE=true
TUNNEL_MEDIA_CAPTURE_CREATE_BUCKET_IF_MISSING=false
TUNNEL_MEDIA_CAPTURE_PART_SIZE_BYTES=8388608
TUNNEL_MEDIA_CAPTURE_MAX_INFLIGHT_PARTS=4
TUNNEL_MEDIA_CAPTURE_UPLOAD_THREADS=4
# 点播/Range 媒体默认保留 7 天；直播分段仍使用下方的滚动窗口。
TUNNEL_MEDIA_CAPTURE_RETENTION_SECONDS=604800
TUNNEL_MEDIA_CAPTURE_LIVE_WINDOW_SECONDS=300
TUNNEL_MEDIA_CAPTURE_MANIFEST_MAX_BYTES=16777216
TUNNEL_MEDIA_CAPTURE_PLAYBACK_TICKET_TTL_SECONDS=900
TUNNEL_MEDIA_CAPTURE_CLEANUP_INTERVAL_MS=60000
```

bucket 应保持私有，`TUNNEL_MEDIA_CAPTURE_ENDPOINT` 填 RustFS S3 API 端口并保持
`TUNNEL_MEDIA_CAPTURE_PATH_STYLE=true`。浏览器通过 tunnel-server 的短期播放票据回放，
不直连 RustFS，因此无需把 RustFS 地址加入前端 CSP。生产环境可再配置 bucket 生命周期作为
过期清理的第二道保障。提高 `TUNNEL_MEDIA_CAPTURE_RETENTION_SECONDS` 后，服务端会在旧记录
原到期时间到达时按新周期自动延长仍应保留的非直播采集；已经删除的对象无法恢复。

### 4.8 HTTP 直转与流量明细（可选）

```env
TUNNEL_HTTP_TIMEOUT_MS=30000
TUNNEL_HTTP_MAX_REQUEST_BODY_SIZE=16777216

TUNNEL_TRAFFIC_CAPTURE_DETAIL_ENABLED=false
TUNNEL_TRAFFIC_CAPTURE_PREVIEW_BYTES=256
TUNNEL_TRAFFIC_CAPTURE_HEADER_CHARS=8192
TUNNEL_TRAFFIC_CAPTURE_DECODE_MAX_BYTES=1048576
TUNNEL_TRAFFIC_CAPTURE_MAX_PENDING=20000
TUNNEL_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE=1000
TUNNEL_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS=2000
```

HTTP / TCP 明细默认写入业务数据库；管理页会分页读取 HTTP 请求/响应和 TCP payload。`TUNNEL_TRAFFIC_CAPTURE_DETAIL_ENABLED` 是总开关，默认关闭；每条 HTTP 路由 / TCP 映射仍需在管理页单独开启明细采集，新建通道默认关闭。启用后 HTTP 请求体和响应体会完整保存，不再按 64 KiB 截断；`TUNNEL_TRAFFIC_CAPTURE_PREVIEW_BYTES` 只限制搜索摘要。原始压缩 Body 保持原样入库，展示摘要会按 `Content-Encoding` 解压 `gzip`、`deflate`、`br`，解压受 `TUNNEL_TRAFFIC_CAPTURE_DECODE_MAX_BYTES` 限制。管理查询默认不强制 flush，手动排查时可在流量明细接口追加 `flush=true`。

完整 Body 会提高内存、数据库和 Elasticsearch 占用，应同时设置明细保留期并按业务流量规划容量。
媒体正文应使用上一节的 RustFS 媒体采集，不应依赖普通明细长期保存。

### 4.9 Elasticsearch 流量明细存储（可选）

配置 `TUNNEL_ELASTICSEARCH_URIS` 后，HTTP / TCP 明细会从业务数据库切换到 Elasticsearch，聚合流量和管理业务数据仍在 MySQL。

```env
TUNNEL_ELASTICSEARCH_URIS=http://127.0.0.1:9200
TUNNEL_ELASTICSEARCH_USERNAME=elastic
TUNNEL_ELASTICSEARCH_PASSWORD=CHANGE_ME_ES_PASSWORD
#TUNNEL_ELASTICSEARCH_API_KEY=
TUNNEL_ELASTICSEARCH_HTTP_INDEX=shuai-tunnel-http-traffic
TUNNEL_ELASTICSEARCH_TCP_INDEX=shuai-tunnel-tcp-traffic
TUNNEL_ELASTICSEARCH_HTTP_MAX_STORE_SIZE=100GB
TUNNEL_ELASTICSEARCH_TCP_MAX_STORE_SIZE=10GB
```

> 多 ES 节点可用逗号分隔。`TUNNEL_ELASTICSEARCH_HTTP_MAX_STORE_SIZE` 默认限制 HTTP 明细索引到 100GB，`TUNNEL_ELASTICSEARCH_TCP_MAX_STORE_SIZE` 默认限制 TCP payload 索引到 10GB；超过后服务端会定期删除最旧记录。若单节点部署出现 `yellow`，通常是副本分片无法分配，不影响单副本读写。

环境变量文件中**不需要也不能用 shell 展开**，必须填字面量。

## 5. 启动 / 验证

```bash
sudo systemctl start tunnel-server
sudo systemctl status tunnel-server
sudo tail -F /var/log/tunnel-server/tunnel-server.log
sudo journalctl -u tunnel-server -f       # 实时日志
```

Linux systemd 部署默认写入 `/var/log/tunnel-server/tunnel-server.log`。日志达到
`50MB` 或跨日期时滚动并 gzip 压缩，最多保留 `30` 个历史周期且总量不超过
`2GB`。可在 `/etc/tunnel-server/tunnel-server.env` 中覆盖：

```env
TUNNEL_LOG_FILE=/var/log/tunnel-server/tunnel-server.log
TUNNEL_LOG_MAX_FILE_SIZE=50MB
TUNNEL_LOG_MAX_HISTORY=30
TUNNEL_LOG_TOTAL_SIZE_CAP=2GB
TUNNEL_LOG_CLEAN_HISTORY_ON_START=true
```

文件由 `tunnel:tunnel` 创建，目录权限为 `0750`；systemd 的 `UMask=0027`
确保日志不会向其他用户开放。控制台输出仍进入 journald，便于继续使用
`journalctl -u tunnel-server` 排障。

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
sudo bash deploy/java-server/systemd/update.sh /tmp/tunnel-server-NEW.jar
```

`update.sh` 自动完成：
1. 同步当前目录里的 `tunnel-server.service` 到 systemd，并同步最新 `tunnel-server.env.example` 到 `/etc/tunnel-server/tunnel-server.env.example`
2. 备份当前 jar → `/opt/tunnel-server/tunnel-server.jar.bak.<时间戳>`（保留最近 5 份）
3. `systemctl stop` → 替换 jar → `systemctl start`
4. 等服务进入 `active`（最多 60s）
5. 轮询 actuator health 直到返回 `UP`（默认最多 120s，可用 `TUNNEL_HEALTH_TIMEOUT_SEC` 覆盖）
6. 任一步失败 → 自动回滚到刚刚备份的旧 jar 并重启

退出码：`0` 成功 / `2` 升级失败但已回滚 / `3` 回滚失败需人工介入。

健康检查地址默认会从 `/etc/tunnel-server/tunnel-server.env` 的 `SERVER_PORT` 推导；也可用环境变量覆盖：
```bash
sudo TUNNEL_HEALTH_PORT=9090 \
     bash deploy/java-server/systemd/update.sh /tmp/tunnel-server-NEW.jar

sudo TUNNEL_HEALTH_URL=http://127.0.0.1:9090/actuator/health \
     bash deploy/java-server/systemd/update.sh /tmp/tunnel-server-NEW.jar
```

真实环境变量文件不会被脚本覆盖。升级后如需合并新增配置：

```bash
sudo diff -u /etc/tunnel-server/tunnel-server.env \
             /etc/tunnel-server/tunnel-server.env.example
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
| 配置了 ES 但管理页无 HTTP/TCP 明细 | 确认 `TUNNEL_ELASTICSEARCH_URIS` 是复数变量名；重启后查看日志是否启用了 Elasticsearch store，并确认索引名与管理 API 使用一致 |
| ES 索引 health 是 `yellow` | 单节点 ES 默认副本无法分配会显示 `yellow`，一般不影响读写；生产可增加节点或把副本数调为 0 |
| 客户端连不上 7010 端口 | 检查防火墙：`sudo firewall-cmd --add-port=7010/tcp --permanent && sudo firewall-cmd --reload` |
| 想绑定 80/443 等特权端口 | 在 `tunnel-server.service` 的 `[Service]` 中追加 `AmbientCapabilities=CAP_NET_BIND_SERVICE` 与 `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` |

## 8. 文件清单

```
deploy/java-server/systemd/
├── README.md                    # 本文件
├── install.sh                   # 一键安装脚本（root 执行，首次安装）
├── update.sh                    # 滚动升级脚本（root 执行，备份 / 健康检查 / 失败回滚）
├── tunnel-server.service        # systemd unit
└── tunnel-server.env.example    # 环境变量模板（含 MySQL 注释说明）
```
