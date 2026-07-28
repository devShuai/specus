package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.specusclient.bean.HttpSpecusConfig;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.client.TcpConnection;
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
 *   <li>{@code httpSpecusConfigList} 出现时替换 {@link NatClientHandler} 的 HTTP/WS 路由快照</li>
 *   <li>{@code httpSpecusConfigList} 缺省时**保留** HTTP 登录初始快照，不要误清空</li>
 *   <li>{@code httpSpecusConfigList} 为空数组时整体清空（接管态全部禁用/删除）</li>
 * </ul>
 *
 * <p>这里直接拼装 NAT_CONTROL JSON，避开 server 端依赖；这是与 server
 * {@code NatControlService.sendNatControl} 的隐式契约——格式由 {@code SpecusBean} 这一侧驱动。
 *
 */
class NatControlHotReloadTests {

    @Test
    void natControlHttpListReplacesRoutes() {
        NatClientHandler nat = natHandlerWithInitialRoute();
        EmbeddedChannel channel = new EmbeddedChannel(nat, new MessageResponseHandler(new TcpConnection()));
        try {
            // server 下发：tcp 一个端口 + http 整体替换为新的 web/api 两条
            String json = """
                    {
                      "clientName":"unit",
                      "remoteAddress":"127.0.0.1",
                      "remotePort":7010,
                      "specusConfigList":[{"port":9000,"specusAddress":"127.0.0.1","specusPort":8080}],
                      "httpSpecusConfigList":[
                        {"route":"web","targetBaseUrl":"http://127.0.0.1:8080"},
                        {"route":"api","targetBaseUrl":"https://api.example.com"}
                      ]
                    }
                    """;
            channel.writeInbound(natControl(json));

            // applyRoutes 已被触发：initial 不复存在，新两条已生效
            Map<String, String> snapshot = nat.getCurrentHttpRoutes();
            assertEquals(2, snapshot.size());
            assertEquals("http://127.0.0.1:8080", snapshot.get("web"));
            assertEquals("https://api.example.com", snapshot.get("api"));

            // NatClientHandler 由 NAT_CONTROL 路径动态加入 pipeline，并发送 TCP REGISTER。
            NatMessagePacket register = readNatMessage(channel);
            assertNotNull(register);
            assertEquals(NatMessageType.REGISTER, register.getNatMessageType());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void natControlWithoutHttpListPreservesInitialRoutes() {
        NatClientHandler nat = natHandlerWithInitialRoute();
        EmbeddedChannel channel = new EmbeddedChannel(nat, new MessageResponseHandler(new TcpConnection()));
        try {
            // 本次 NAT_CONTROL 不下发 httpSpecusConfigList 字段；客户端必须保留初始快照
            String json = """
                    {
                      "clientName":"unit",
                      "remoteAddress":"127.0.0.1",
                      "remotePort":7010,
                      "specusConfigList":[]
                    }
                    """;
            channel.writeInbound(natControl(json));

            assertEquals(Map.of("initial", "http://127.0.0.1:9999"), nat.getCurrentHttpRoutes());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void natControlEmptyHttpListClearsInitialRoutes() {
        NatClientHandler nat = natHandlerWithInitialRoute();
        EmbeddedChannel channel = new EmbeddedChannel(nat, new MessageResponseHandler(new TcpConnection()));
        try {
            // 服务端"接管态但全部禁用/删除"——下发空数组，客户端整体替换为空
            String json = """
                    {
                      "clientName":"unit",
                      "remoteAddress":"127.0.0.1",
                      "remotePort":7010,
                      "specusConfigList":[],
                      "httpSpecusConfigList":[]
                    }
                    """;
            channel.writeInbound(natControl(json));

            assertFalse(nat.getCurrentHttpRoutes().containsKey("initial"));
            assertTrue(nat.getCurrentHttpRoutes().isEmpty());
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

    private static HttpSpecusConfig routeConfig(String route, String targetBaseUrl) {
        HttpSpecusConfig config = new HttpSpecusConfig();
        config.setRoute(route);
        config.setTargetBaseUrl(targetBaseUrl);
        return config;
    }

    private static NatClientHandler natHandlerWithInitialRoute() {
        SpecusBean bean = new SpecusBean();
        bean.setClientName("unit");
        bean.setRemoteAddress("127.0.0.1");
        bean.setSpecusConfigList(List.of());
        bean.setHttpSpecusConfigList(List.of(routeConfig("initial", "http://127.0.0.1:9999")));
        return new NatClientHandler(bean, new TcpConnection());
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
