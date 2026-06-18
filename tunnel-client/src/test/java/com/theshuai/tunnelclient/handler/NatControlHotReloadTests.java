package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.tunnelclient.bean.HttpTunnelConfig;
import com.theshuai.tunnelclient.client.TcpConnection;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * NAT_CONTROL 到 client 的整合契约测试。覆盖：
 * <ul>
 *   <li>{@code httpTunnelConfigList} 出现时调用 {@link DirectHttpRequestHandler#applyRoutes}（即热更新）</li>
 *   <li>{@code httpTunnelConfigList} 缺省时**保留** boot 期 fallback 表，不要误清空</li>
 *   <li>{@code httpTunnelConfigList} 为空数组时整体清空（接管态全部禁用/删除）</li>
 * </ul>
 *
 * <p>这里直接拼装 NAT_CONTROL JSON，避开 server 端依赖；这是与 server
 * {@code NatControlService.sendNatControl} 的隐式契约——格式由 {@code TunnelBean} 这一侧驱动。
 *
 * <p>注意：HTTP_ROUTES_REPORT 在 {@link MessageResponseHandler} 中由
 * {@code addLast(NatClientHandler)} 触发，**先于** {@code applyRoutes} 调用，因此首次
 * NAT_CONTROL 中报告的 routes 反映的是 boot fallback；下次重连后才反映 push 后的最新值。
 * 本测试只断言路由表本身的状态，不再约束首次 report 内容。
 */
class NatControlHotReloadTests {

    @Test
    void natControlHttpListReplacesRoutes() {
        DirectHttpRequestHandler directHttp = new DirectHttpRequestHandler(List.of(
                routeConfig("legacy", "http://127.0.0.1:9999")
        ));
        EmbeddedChannel channel = new EmbeddedChannel(directHttp, new MessageResponseHandler(new TcpConnection()));
        try {
            // server 下发：tcp 一个端口 + http 整体替换为新的 web/api 两条
            String json = """
                    {
                      "clientName":"unit",
                      "remoteAddress":"127.0.0.1",
                      "remotePort":7010,
                      "tunnelConfigList":[{"port":9000,"tunnelAddress":"127.0.0.1","tunnelPort":8080}],
                      "httpTunnelConfigList":[
                        {"route":"web","targetBaseUrl":"http://127.0.0.1:8080"},
                        {"route":"api","targetBaseUrl":"https://api.example.com"}
                      ]
                    }
                    """;
            channel.writeInbound(natControl(json));

            // applyRoutes 已被触发：legacy 不复存在，新两条已生效
            Map<String, String> snapshot = directHttp.getCurrentRoutes();
            assertEquals(2, snapshot.size());
            assertEquals("http://127.0.0.1:8080", snapshot.get("web"));
            assertEquals("https://api.example.com", snapshot.get("api"));

            // NatClientHandler 由 NAT_CONTROL 路径动态加入 pipeline；handlerAdded 后会先发 REGISTER，
            // 再发 HTTP_ROUTES_REPORT。两条都应到达 outbound 队列；至于 report 的 metaData，
            // 由于 addLast 早于 applyRoutes，反映的是 fallback "legacy"，这里仅断言 frame 类型。
            NatMessagePacket register = readNatMessage(channel);
            assertNotNull(register);
            assertEquals(NatMessageType.REGISTER, register.getNatMessageType());
            NatMessagePacket report = readNatMessage(channel);
            assertNotNull(report);
            assertEquals(NatMessageType.HTTP_ROUTES_REPORT, report.getNatMessageType());
            assertNotNull(report.getMetaData().get("routes"));
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void natControlWithoutHttpListPreservesFallbackRoutes() {
        DirectHttpRequestHandler directHttp = new DirectHttpRequestHandler(List.of(
                routeConfig("legacy", "http://127.0.0.1:9999")
        ));
        EmbeddedChannel channel = new EmbeddedChannel(directHttp, new MessageResponseHandler(new TcpConnection()));
        try {
            // 服务端"未接管"——不下发 httpTunnelConfigList 字段；客户端必须保留 fallback
            String json = """
                    {
                      "clientName":"unit",
                      "remoteAddress":"127.0.0.1",
                      "remotePort":7010,
                      "tunnelConfigList":[]
                    }
                    """;
            channel.writeInbound(natControl(json));

            assertEquals(Map.of("legacy", "http://127.0.0.1:9999"), directHttp.getCurrentRoutes());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void natControlEmptyHttpListClearsFallbackRoutes() {
        DirectHttpRequestHandler directHttp = new DirectHttpRequestHandler(List.of(
                routeConfig("legacy", "http://127.0.0.1:9999")
        ));
        EmbeddedChannel channel = new EmbeddedChannel(directHttp, new MessageResponseHandler(new TcpConnection()));
        try {
            // 服务端"接管态但全部禁用/删除"——下发空数组，客户端整体替换为空
            String json = """
                    {
                      "clientName":"unit",
                      "remoteAddress":"127.0.0.1",
                      "remotePort":7010,
                      "tunnelConfigList":[],
                      "httpTunnelConfigList":[]
                    }
                    """;
            channel.writeInbound(natControl(json));

            assertFalse(directHttp.getCurrentRoutes().containsKey("legacy"));
            assertTrue(directHttp.getCurrentRoutes().isEmpty());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static MessageResponsePacket natControl(String json) {
        MessageResponsePacket packet = new MessageResponsePacket();
        packet.setMessageType(MessageType.NAT_CONTROL);
        packet.setMessage(json);
        return packet;
    }

    private static HttpTunnelConfig routeConfig(String route, String targetBaseUrl) {
        HttpTunnelConfig config = new HttpTunnelConfig();
        config.setRoute(route);
        config.setTargetBaseUrl(targetBaseUrl);
        return config;
    }

    /** 跳过非 NatMessagePacket（ByteBuf 等）只取我们关心的协议帧。 */
    private static NatMessagePacket readNatMessage(EmbeddedChannel channel) {
        for (int i = 0; i < 16; i++) {
            Object outbound = channel.readOutbound();
            if (outbound == null) {
                return null;
            }
            if (outbound instanceof NatMessagePacket packet) {
                return packet;
            }
        }
        return null;
    }
}
