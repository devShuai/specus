# Peer Mesh IPv6/NAT64 生产验收

本文把代码级 IPv6 支持转换为可重复的发布验收。协议测试通过只证明 candidate、地址族选择和帧处理正确，
不能替代真实运营商、NAT64 和移动网络切换验证。

## 1. 前置条件

1. STUN/TURN 主备域名同时检查 A 与 AAAA；测试 IPv6 direct 时至少一个可达端点必须有公网 IPv6。
2. 服务端 UDP socket 监听 IPv6 或双栈地址，安全组和主机防火墙开放对应 UDP 端口。
3. 管理端 `/api/admin/peer-mesh/stats` 能返回 `addressFamilies`，客户端上报 candidate 的
   `addressFamily` 为 `IPv4`、`IPv6` 或 `UNKNOWN`。
4. 每次测试固定 server/client commit、网络运营商、设备系统版本和时间段。
5. 不把访问令牌、TURN credential、room token 或公网用户地址写入证据文件。

建议先保存以下基线：

```bash
dig A stun1.specus.devshuai.com
dig AAAA stun1.specus.devshuai.com
dig A stun2.specus.devshuai.com
dig AAAA stun2.specus.devshuai.com
curl -fsS -H "Authorization: Bearer ${SPECUS_ADMIN_TOKEN}" \
  https://specus.devshuai.com/api/admin/peer-mesh/stats
```

Windows 使用 `Resolve-DnsName` 和 `Invoke-RestMethod` 执行同一检查。

## 2. 必测矩阵

| 编号 | 网络 | 设备 | 预期 |
| --- | --- | --- | --- |
| V6-01 | IPv4 only | Windows/Linux | IPv4 direct 或认证 relay，作为对照组 |
| V6-02 | 原生双栈 | Windows/Linux | 优先选择可用且 priority 更高的路径；统计显示实际地址族 |
| V6-03 | IPv6 only | Linux | IPv6 candidate 可直连；失败时给出 relay/端点不可达原因，不空转 |
| V6-04 | IPv6 only | Android | VPN TUN、打洞、业务流量和前后台切换正常 |
| V6-05 | NAT64/DNS64 | Android | IPv4-only 管理服务可经 NAT64 到达；Peer 路径不误报为原生 IPv4 direct |
| V6-06 | NAT64/DNS64 | Linux | DNS64 合成、控制连接、STUN/TURN fallback 和业务流量完整 |
| V6-07 | Wi-Fi 双栈切蜂窝 NAT64 | Android | 旧路径进入 stale，60 秒内重建 direct 或 relay，不复用旧 session nonce |
| V6-08 | IPv4 Wi-Fi 切 IPv6-only | Android | 地址族切换后重新收集 candidate，业务自动恢复 |

每个场景至少执行双向虚拟 IP ping、TCP echo、HTTP over mesh、1 GiB 连续传输和 30 分钟空闲保活。
TCP echo 容量证据使用：

```bash
go run ./tools/loadtest/tcp_stream_load.go \
  -addr '<peer-virtual-ip>:19000' \
  -levels 1,10,100,1000 \
  -duration 60s \
  -output peer-capacity.json
```

## 3. 网络扰动

Linux 使用 `tools/loadtest/netem-profile.sh` 分别覆盖：

| Profile | RTT/单向延迟配置 | 丢包 |
| --- | ---: | ---: |
| clean | 0 ms | 0% |
| metro | 20 ms | 1% |
| regional | 100 ms | 1% |
| mobile | 100 ms | 3% |
| long-haul | 300 ms | 3% |

示例：

```bash
sudo ./tools/loadtest/netem-profile.sh apply eth0 100 3
go run ./tools/loadtest/tcp_stream_load.go -addr '<peer-virtual-ip>:19000' -duration 60s
sudo ./tools/loadtest/netem-profile.sh clear eth0
```

移动网络切换必须在真机上执行。记录切换开始、旧路径 stale、candidate 重收集、新路径 active 和业务恢复时间。

## 4. 通过标准

1. candidate 中存在的地址族与系统接口和 DNS 结果一致，不把 IPv4-mapped IPv6 错报为原生 IPv6。
2. 管理端 `addressFamilies` 的 active/direct/relay 数量与会话明细一致。
3. 路径切换后不出现 sequence 回卷、replay storm、旧 session 持续发包或无限重试。
4. direct 不可达时 60 秒内切到认证 relay，或返回稳定且可诊断的失败原因。
5. 1 GiB 传输 checksum 一致；稳定路径丢包不超过注入值之外的 0.1%，计量误差小于 2%。
6. `1/10/100/1000` 流报告必须有非零成功操作；发布阈值由目标机器基线确定并版本化，不能用开发机数字代替。
7. Android Wi-Fi/蜂窝切换最多短暂中断，恢复后 VPN 路由、socket bypass 和 Peer 会话都指向新网络。

## 5. 证据清单

每个场景保存一份脱敏目录，包含：

- `environment.md`：commit、系统/设备、运营商、网络类型、服务端实例；
- `dns.txt`：A/AAAA/DNS64 结果；
- `path-stats-before.json` 与 `path-stats-after.json`；
- server 和双端 client 的时间对齐日志；
- `peer-capacity.json`、checksum、ping/恢复时间；
- 管理页地址族和 active path 截图。

仓库实施审计中的 P3-2 已按代码、测试和工具状态标记为 `DONE`；只有 V6-01 到 V6-08 都有可复核证据时，
对应版本的生产发布验收才可标记为 `DONE`。两种状态必须分开记录，不能用单元测试代替真机证据。
