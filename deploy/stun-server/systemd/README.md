# 独立 RFC 5780 STUN Server 部署

该服务是独立 Java 进程，只处理 UDP STUN Binding 与 RFC 5780
`CHANGE-REQUEST`，不启动 tunnel-server、数据库、HTTP、WebSocket 或 TURN。

## 1. 网络拓扑

完整区分 NAT 映射和过滤行为需要四个端点：

| 端点 | 本地绑定 | 对外地址 |
| --- | --- | --- |
| A1:P1 | `10.0.0.10:3478` | `203.0.113.10:3478` |
| A1:P2 | `10.0.0.10:3479` | `203.0.113.10:3479` |
| A2:P1 | `10.0.0.11:3478` | `203.0.113.11:3478` |
| A2:P2 | `10.0.0.11:3479` | `203.0.113.11:3479` |

两张本地地址必须同时存在于运行服务的主机。云环境可以给两张私网 IP
分别绑定一个 EIP，要求出站源地址也保持对应的 1:1 映射。两个公网 IP
都要放行 `3478/udp` 和 `3479/udp`。

## 2. 构建

```bash
mvn -pl :stun-server -am clean package
```

产物：

```text
implementations/java/stun-server/target/stun-server.jar
```

该 JAR 已包含运行需要的共享 STUN 类，可以脱离 tunnel-server 单独运行。

## 3. 安装

```bash
sudo bash deploy/stun-server/systemd/install.sh \
  implementations/java/stun-server/target/stun-server.jar
sudo vim /etc/shuai-stun-server/stun-server.env
```

填写真实地址后先校验配置：

```bash
sudo -u stun bash -c '
  set -a
  source /etc/shuai-stun-server/stun-server.env
  set +a
  java $JAVA_OPTS -jar /opt/shuai-stun-server/stun-server.jar --check-config
'
```

再启动：

```bash
sudo systemctl start stun-server
sudo systemctl status stun-server
sudo journalctl -u stun-server -f
sudo ss -lunp | grep -E ':(3478|3479)\b'
```

`ExecStartPre` 每次启动都会执行一次 `--check-config`。如果四端点缺失、
两个公网 IP 相同、端口重复或地址族不一致，systemd 会在监听前直接失败。

## 4. 同一个 STUN 域名

最简单的配置是让域名只指向入口 A1：

```dns
stun.example.com. 300 IN A 203.0.113.10
_stun-behavior._udp.example.com. 300 IN SRV 0 0 3478 stun.example.com.
```

客户端先访问 `stun.example.com:3478`，服务端通过标准
`OTHER-ADDRESS` 告知 A2:P2，因此不需要为第二个公网 IP 单独配置客户端域名。
也可以让同一域名同时返回 A1/A2；服务对四个端点均可接收请求，并会以请求
实际到达的 IP/端口为基准计算 `OTHER-ADDRESS`。

在 tunnel-server 中把原生客户端和公开 NAT 检测页指向该独立入口：

```env
TUNNEL_PEER_MESH_STANDALONE_STUN_ADDRESS=stun.example.com
TUNNEL_PEER_MESH_STANDALONE_STUN_PORT=3478
```

这只替换登录配置中的 `stunHost/stunPort`。认证 TURN 继续使用
`TUNNEL_PEER_MESH_PUBLIC_ADDRESS:TUNNEL_PEER_MESH_STUN_TURN_PORT`，
因此 STUN 与 TURN 可以独立扩容、独立部署和独立维护。

## 5. 单公网 IP 兼容模式

不配置 `STUN_ALTERNATE_BIND_ADDRESS` 和
`STUN_ALTERNATE_PUBLIC_ADDRESS` 时，服务仍可作为普通 STUN Binding
server 使用。此模式不会返回 `OTHER-ADDRESS`，收到 `CHANGE-REQUEST`
会按 RFC 5780 返回 `420 Unknown Attribute`，因此不能完整区分 NAT
映射与过滤行为。

`STUN_LEGACY_SINGLE_IP_OTHER_ADDRESS=true` 仅用于兼容 shuai-tunnel
旧版单 IP / 双端口探测，不应作为公开 RFC 5780 服务配置。

## 6. 更新

```bash
sudo bash deploy/stun-server/systemd/update.sh /tmp/stun-server.jar
```

脚本会保留最近 5 个 JAR 备份；新进程不能通过配置校验或无法绑定四个
UDP 端点时会自动恢复上一版。
