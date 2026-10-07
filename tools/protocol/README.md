# 协议向量生成与校验

Peer 出口分流（[`protocol/spec/peer-egress.md`](../../protocol/spec/peer-egress.md)）的测试向量由脚本生成，不手写。
IPv4 与传输层校验和手算容易出错，而向量一旦写错，四端实现会一起对着错误的事实来源对齐。

从仓库根目录运行：

```bash
python tools/protocol/generate_peer_egress_frame_vectors.py
python tools/protocol/generate_peer_egress_policy_vectors.py
python tools/protocol/generate_peer_egress_socket_binding_vectors.py
python tools/protocol/verify_peer_egress_vectors.py
```

| 脚本 | 产物 |
| --- | --- |
| `generate_peer_egress_frame_vectors.py` | `protocol/test-vectors/peer-egress-frame-v1.json` |
| `generate_peer_egress_policy_vectors.py` | `protocol/test-vectors/peer-egress-rules-v1.json`、`peer-egress-authz-v1.json` |
| `generate_peer_egress_socket_binding_vectors.py` | `protocol/test-vectors/peer-egress-socket-binding-v1.json`（出口 socket 的接口选择；读取 macOS 路由向量里的真机样本） |
| `verify_peer_egress_vectors.py` | 无产物；校验失败时退出码非零 |
| `generate_temporary_share_vectors.py` | `protocol/test-vectors/temporary-http-share-v1.json`（临时 HTTP 分享草案的创建、兑换、访问判定、级联失效、审计与限流；见 [`temporary-http-share.md`](../../protocol/spec/temporary-http-share.md)） |
| `generate_service_connectivity_vectors.py` | `protocol/test-vectors/service-connectivity-check-v1.json`（服务连通性检查草案的四阶段状态机与限流；见 [`service-connectivity-check.md`](../../protocol/spec/service-connectivity-check.md)） |
| `generate_service_workbench_vectors.py` | `protocol/test-vectors/service-workbench-v1.json`（服务工作台：收藏与最近打开的上限、保留期、排序、隔离与级联；见 [`service-workbench.md`](../../protocol/spec/service-workbench.md)） |
| `generate_product_metrics_vectors.py` | `protocol/test-vectors/product-metrics-v1.json`（产品指标的上报校验、分桶、接入队列、计数、限流、保存期与汇总；见 [`product-metrics.md`](../../protocol/spec/product-metrics.md)） |

两个生成器各自带一份参考实现（规则匹配器、授权判定器），写文件前会用它断言每条期望，
因此向量不会带着自相矛盾的用例发布。

校验器与生成器**不共享代码**，把三份 JSON 当外部输入重新解析，断言：

- 每个 `frameHex` 解出的头部字段与声明一致
- accept 用例的 IPv4 头部与传输层校验和都能验证通过
- 控制消息 body 恰好等于 `controlJson` 的 canonical 编码
- 声明的 `innerSourceIp` / `innerDestinationIp` 与包内实际地址一致
- 向量用到的每个错误码都在规范的错误码表里，且表里每个错误码都至少被一个用例覆盖
- 判定顺序中 `forcedDeny` 排在 `scope` 与 `destination` 之前——宽泛的目标规则永远不能抢在强制拒绝清单前面

修改规范里的语义后，必须重新生成并让校验通过，再让四端实现读新向量。
