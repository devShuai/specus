# Peer Mesh 移动端实现方案

> 将 specus 的 peer-to-peer mesh 组网能力移植到 Android（Kotlin）和 iOS（Swift），
> 使移动设备能通过 VPN 隧道参与私有组网，与其他 peer 设备直连或经 relay 通信。
>
> 状态复核（2026-07-10）：本文主体仍是跨 Android/iOS 的目标方案，不是当前代码结构说明。仓库已经有
> `implementations/android/client`，采用原生 Java 独立实现而非 KMP/OkHttp WebSocket，已接入 HTTP 启动登录、
> 二进制控制连接、`VpnService`、X25519/HKDF/AES-GCM、标准 STUN/TURN、UDP direct/relay 和基础状态上报；
> 端口预测、本地 ACL 镜像和完整真机 E2E 仍待完成。iOS 与 KMP 共享核心尚未实现。

---

## 整体架构

```
┌─────────────────────────────────────────────┐
│       目标移动端 App (Kotlin/Swift)           │
│                                              │
│  ┌───────────────────────────────────────┐  │
│  │        PeerMeshEngine (共享核心)        │  │
│  │  candidates / probes / keepalive      │  │
│  │  session / crypto / path selection    │  │
│  │  port prediction / hairpin detection  │  │
│  └──────────┬────────────────────────────┘  │
│             │                                │
│  ┌──────────▼──────────┐ ┌───────────────┐  │
│  │  平台适配层          │ │  VPN Provider │  │
│  │  - UDP socket       │ │  - VpnService │  │
│  │  - 控制通道          │ │  - NEPacket   │  │
│  │  - 密钥存储          │ │  SpecusProvider│ │
│  │  - STUN/TURN        │ └───────────────┘  │
│  └─────────────────────┘                     │
└─────────────────────────────────────────────┘
```

---

## Phase 1 — 共享核心

**目标**：一份 `PeerMeshEngine` 核心逻辑，Android/iOS 共用。

### 共享核心模块清单

| 模块 | 内容 | Java 行数 | 实现方案 |
|------|------|-----------|----------|
| **协议层** | `PeerControlMessage`、`PeerCandidate`、`PeerUdpProbe`、`PeerRelayMessage`、`PeerRelayBinaryFrame`、`PeerDataFrameHeader` | ~200 | Kotlin `data class` + kotlinx.serialization / Swift `struct` + `Codable` |
| **加密** | `deriveAes256Key` (X25519 + HKDF-SHA256 → AES-256-GCM) | ~80 | 方案A: C 跨界 (libsodium); 方案B: 各平台原生 (Android KeyStore / iOS CryptoKit) |
| **防重放** | `PeerReplayWindow` (4096 位滑动窗口) | ~60 | 纯逻辑，平台无关 |
| **NAT 检测** | `classifyNat()` (primary/alternate/changed-port 三观测比较) | ~60 | 纯逻辑 |
| **探针** | `sendUdpProbe` + `scheduleProbeBurst` + `replyUdpProbe` + `completeUdpProbe` + RTT 滞回 | ~200 | 纯逻辑（UDP I/O 走平台适配层） |
| **候选收集** | `gatherHostCandidates` + srflx/portmap/relay 候选管理 | ~120 | 网络接口枚举走平台适配层 |
| **会话** | `PeerSession` 状态机 + `PeerInfo` roster + `pendingProbes` + `pendingPackets` | ~300 | 纯逻辑 |
| **保活** | `keepaliveDirectPaths` + `fallbackStaleDirectPaths` | ~80 | 定时器走平台 |
| **端口预测** | 对称 NAT 端口预测 ±8 | ~40 | 纯逻辑 |
| **Hairpin** | 同 NAT 检测 + host-only 探针 | ~30 | 纯逻辑 |
| **合计** | | **~1170** | |

### 实现方式对比

| 方案 | 优点 | 缺点 |
|------|------|------|
| **Kotlin Multiplatform (KMP)** | 最高代码共享率；单一语言 | X25519/AES-GCM 需 BouncyCastle；iOS bridge 学习成本 |
| **C 核心** (libpeer) | 最优性能；libsodium 直接调用；前后端通用 | 开发成本高；FFI 维护成本 |
| **各平台独立实现** | 零共享成本；各平台最佳实践 | 维护两份代码；协议一致性风险 |

**推荐**：KMP 共享核心，加密通过 `libsodium` C binding。

---

## Phase 2 — Android 平台（4-6 周）

### 2.1 控制通道

| Java 组件 | Android 替代 |
|-----------|-------------|
| Netty TCP 控制通道 | OkHttp WebSocket (`okhttp3:okhttp`) |
| `LoginResponseHandler` | WebSocket `onMessage` 回调 |
| `MessageResponseHandler` | JSON 路由按 `messageType` 分发 |
| `ControlSender` 接口 | WebSocket `send(json)` |
| 自动重连 + 退避 | Coroutine `Flow` + `retryWhen` |

### 2.2 UDP 传输

| Java 组件 | Android 替代 |
|-----------|-------------|
| `DatagramSocket` | `java.net.DatagramSocket`（Android 完整支持） |
| `receiveLoop` (daemon thread) | `CoroutineScope(Dispatchers.IO).launch { while(active) { socket.receive(packet) } }` |
| STUN/TURN 消息 | 复用 `StunMessage` DTO（kotlinx.serialization） |

### 2.3 VPN 隧道

| Java 组件 | Android 替代 |
|-----------|-------------|
| `PeerVirtualDevice` | `android.net.VpnService` + `Builder` |
| `sendVirtualPacket` 回调 | VpnService 内部循环读取 `FileDescriptor` |
| `handlePlainPacket` 写入 | `FileDescriptor.write(packet)` 注入 VPN |
| TUN 接口名 `specus0` | `Builder.setSession("specus")` |

**VPN 启动流程**：
```kotlin
class MeshVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val builder = Builder().apply {
            setSession("specus")
            addAddress(meshConfig.virtualIp, 11)
            addRoute("100.96.0.0", 11)
            setMtu(PeerVirtualDeviceOptions.DEFAULT_MTU)
        }
        vpnInterface = builder.establish()
        // 读循环 → peerMeshEngine.sendVirtualPacket(ipv4)
        // peerMeshEngine.handlePlainPacket(ipv4) → vpnInterface.write(ipv4)
    }
}
```

### 2.4 加密与密钥

| Java 组件 | Android 替代 |
|-----------|-------------|
| `PeerKeyStore` 文件存储 | `AndroidKeyStore` + `EncryptedSharedPreferences` |
| X25519 (API 26+) | `KeyPairGenerator.getInstance("XDH")` |
| X25519 (API < 26) | BouncyCastle `bcprov-jdk15on` |
| AES-256-GCM | `Conscrypt`（Android 内置） |

### 2.5 依赖清单

| 用途 | 库 |
|------|-----|
| WebSocket 控制通道 | `com.squareup.okhttp3:okhttp` |
| JSON 序列化 | `org.jetbrains.kotlinx:kotlinx-serialization-json` |
| X25519 (API < 26) | `org.bouncycastle:bcprov-jdk15on` |
| 协程 | `org.jetbrains.kotlinx:kotlinx-coroutines` |
| HTTP 登录 | OkHttp（复用） |
| UPnP | 可选 (`org.bitlet:weupnp`) |

### 2.6 文件预估

| 文件 | 行数 |
|------|------|
| `PeerMeshEngine.kt`（共享核心适配层） | ~600 |
| `ControlChannel.kt`（WebSocket） | ~200 |
| `UdpTransport.kt`（UDP 收发） | ~150 |
| `MeshVpnService.kt`（VpnService） | ~250 |
| `KeyStoreAdapter.kt`（AndroidKeyStore） | ~100 |
| `CryptoAdapter.kt`（加密桥接） | ~80 |
| `LoginClient.kt`（HTTP 登录） | ~100 |
| UI 层（启停开关 / 状态 / peer 列表） | ~300 |
| **合计** | **~1780** |

---

## Phase 3 — iOS 平台（4-6 周）

### 3.1 控制通道

| Java 组件 | iOS 替代 |
|-----------|---------|
| Netty TCP | `URLSessionWebSocketTask` |
| 自动重连 | `AsyncStream` + `Task` + 指数退避 |

### 3.2 UDP 传输

| Java 组件 | iOS 替代 |
|-----------|---------|
| `DatagramSocket` | `NWConnection` (Network.framework) |
| receiveLoop | `NWConnection.receiveMessage` 回调链 |

### 3.3 VPN 隧道

| Java 组件 | iOS 替代 |
|-----------|---------|
| `PeerVirtualDevice` | `NEPacketTunnelProvider` |
| `sendVirtualPacket` 回调 | `NEPacketTunnelFlow.readPackets` |
| `handlePlainPacket` 写入 | `NEPacketTunnelFlow.writePackets` |

**VPN 启动流程**：
```swift
class SpecusPacketProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String : NSObject]?) async throws {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: meshConfig.cidr)
        settings.mtu = NSNumber(value: PeerVirtualDeviceOptions.DEFAULT_MTU)
        let ipv4 = NEIPv4Settings(addresses: [meshConfig.virtualIp], subnetMasks: ["255.224.0.0"])
        settings.ipv4Settings = ipv4
        try await setTunnelNetworkSettings(settings)
        packetFlow.readPackets { packets, protocols in
            for packet in packets { engine.sendVirtualPacket(packet) }
        }
    }
}
```

### 3.4 加密与密钥

| Java 组件 | iOS 替代 |
|-----------|---------|
| `PeerKeyStore` | `SecKeyCreateRandomKey` (Secure Enclave 可选) |
| X25519 | CryptoKit `Curve25519.KeyAgreement` |
| AES-256-GCM | CryptoKit `AES.GCM` |
| HKDF-SHA256 | CryptoKit `HKDF` |

### 3.5 依赖清单

| 用途 | 框架 |
|------|------|
| WebSocket | `URLSessionWebSocketTask`（内置） |
| JSON | `Codable` + `JSONEncoder/Decoder`（内置） |
| X25519 + AES-GCM | `CryptoKit`（iOS 13+） |
| HKDF | CryptoKit `HKDF` |
| 网络 | `NWConnection` (Network.framework) |
| VPN | `NEPacketTunnelProvider`（系统框架） |
| UPnP | 可选（`TCP:1900` 简单实现） |

### 3.6 文件预估

| 文件 | 行数 |
|------|------|
| `PeerMeshEngine.swift`（共享核心适配层） | ~600 |
| `ControlChannel.swift`（WebSocket） | ~200 |
| `UdpTransport.swift`（NWConnection UDP） | ~150 |
| `MeshPacketSpecusProvider.swift` | ~250 |
| `KeyStoreAdapter.swift`（Keychain） | ~80 |
| `CryptoAdapter.swift`（CryptoKit 桥接） | ~80 |
| `LoginClient.swift`（HTTP 登录） | ~100 |
| UI 层（SwiftUI） | ~300 |
| **合计** | **~1760** |

---

## Phase 4 — 联调与测试（2 周）

| 项目 | 内容 |
|------|------|
| **单元测试** | NAT 分类 6 种场景、ReplayWindow 边界、HKDF key derivation、探针突发 timing |
| **集成测试** | Android ↔ 服务端 STUN binding / TURN allocation；iOS ↔ 服务端 信令交互 |
| **端到端测试** | Android ↔ iOS 直连 ping（同 NAT + 跨 NAT） |
| **场景测试** | 对称 NAT × 对称 NAT、同 NAT hairpin、IPv4/v6 混合、蜂窝 + Wi-Fi 切换 |

---

## 时间线

| Phase | 内容 | 工期 |
|-------|------|------|
| 1 | KMP 共享核心（protocol + crypto + engine） | 3 周 |
| 2 | Android 平台（控制通道 + UDP + VPN + UI） | 4-6 周 |
| 3 | iOS 平台（控制通道 + UDP + VPN + UI） | 4-6 周 |
| 4 | 联调 + 测试 + 发布 | 2 周 |
| **总计** | | **13-17 周** |

---

## 协议兼容性

移动端实现必须与现有 Java 客户端互通的关键点：

| 协议层 | 兼容性要求 |
|--------|-----------|
| `PeerControlMessage` JSON | `@SerialName` 与 Java 字段名一致 |
| `PeerUdpProbe` JSON | magic `"specus-peer-mesh"` + 字段名一致 |
| `PeerDataFrameHeader` | `0x53504D31` + 46 字节 AAD |
| `deriveAes256Key` | HKDF salt = `SHA-256("specus-peer-mesh\n<sessionId>\n<token>\n<minId>\n<maxId>")` |
| 标准 STUN binding | 二进制 STUN、`XOR-MAPPED-ADDRESS`、`RESPONSE-ORIGIN`、`OTHER-ADDRESS` |
| 标准 TURN | Allocate / Refresh / CreatePermission / Send Indication / Data Indication；当前不使用 ChannelBind/ChannelData |
| 探针突发 | `PROBE_BURST_COUNT=3`, `INTERVAL=30ms` |
| 端口预测 | `PREDICTED_PORT_RANGE=8` |
| 保活 | `DIRECT_KEEPALIVE_INTERVAL=25s`, `DIRECT_STALE=45s` |
| RTT 滞回 | `RTT_HYSTERESIS_MS=100` |

---

## 风险与缓解

| 风险 | 缓解方案 |
|------|----------|
| Android VPN 电池消耗 | 仅在 mesh 活跃时建立 VPN；30 秒空闲自动关闭；使用 `AlarmManager` 保活替代常驻 |
| iOS Network Extension 审核 | 需 `com.apple.developer.networking.vpn.api` entitlement；企业证书或 App Store 特殊申请 |
| 蜂窝网络端口预测不可靠 | 移动网络下 relay 为主要路径，直接探测为 best-effort；蜂窝时 `shouldAvoidDirectPath` 返回 `true` |
| 加密库不兼容 | libsodium C binding 确保一致性向量测试 |
| 协议版本漂移 | `PeerControlMessage` 增加 `protocolVersion` 字段；服务端拒绝不兼容版本 |
