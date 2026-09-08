# 协议向量生成与校验

Peer 出口分流（[`protocol/spec/peer-egress.md`](../../protocol/spec/peer-egress.md)）的测试向量由脚本生成，不手写。
IPv4 与传输层校验和手算容易出错，而向量一旦写错，四端实现会一起对着错误的事实来源对齐。

从仓库根目录运行：

```bash
python tools/protocol/generate_peer_egress_frame_vectors.py
python tools/protocol/generate_peer_egress_policy_vectors.py
python tools/protocol/verify_peer_egress_vectors.py
```

| 脚本 | 产物 |
| --- | --- |
| `generate_peer_egress_frame_vectors.py` | `protocol/test-vectors/peer-egress-frame-v1.json` |
| `generate_peer_egress_policy_vectors.py` | `protocol/test-vectors/peer-egress-rules-v1.json`、`peer-egress-authz-v1.json` |
| `verify_peer_egress_vectors.py` | 无产物；校验失败时退出码非零 |

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
