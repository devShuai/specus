package com.theshuai.tunnelclient.handler;

import com.theshuai.common.codec.PacketEncoder;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import com.theshuai.tunnelclient.bean.HttpTunnelConfig;
import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DirectHttpRequestHandlerTests {

    @Test
    void shouldEncodeResponseWhenForwarderCompletesAsynchronously() throws Exception {
        EmbeddedChannel channel = new EmbeddedChannel(new DirectHttpRequestHandler(null), new PacketEncoder());
        try {
            DirectHttpRequestPacket request = new DirectHttpRequestPacket();
            request.setRequestId("request-id");
            request.setRequestMethod("GET");
            request.setRoute("missing");
            request.setRelativePath("/");
            channel.writeInbound(request);

            ByteBuf encoded = waitForOutbound(channel);
            try {
                DirectHttpResponsePacket response = assertInstanceOf(
                        DirectHttpResponsePacket.class,
                        PacketCodec.INSTANCE.decode(encoded)
                );
                assertEquals("request-id", response.getRequestId());
                assertEquals(502, response.getStatusCode());
            } finally {
                encoded.release();
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void applyRoutesReplacesEntireRoutingTable() {
        // 启动时使用本地 fallback 表
        DirectHttpRequestHandler handler = new DirectHttpRequestHandler(List.of(
                routeConfig("legacy", "http://127.0.0.1:9999")
        ));
        assertEquals(Map.of("legacy", "http://127.0.0.1:9999"), handler.getCurrentRoutes());

        // 服务端权威下发：整体替换 —— 老 route 必须消失
        handler.applyRoutes(List.of(
                routeConfig("web", "http://127.0.0.1:8080"),
                routeConfig("api", "https://api.example.com")
        ));

        Map<String, String> snapshot = handler.getCurrentRoutes();
        assertEquals(2, snapshot.size());
        assertEquals("http://127.0.0.1:8080", snapshot.get("web"));
        assertEquals("https://api.example.com", snapshot.get("api"));
        // 不可变：channelRead0 抓到的快照在 worker 线程里被改写时直接抛
        assertThrows(UnsupportedOperationException.class, () -> snapshot.put("evil", "x"));
    }

    @Test
    void applyRoutesEmptyListClearsRoutes() {
        DirectHttpRequestHandler handler = new DirectHttpRequestHandler(List.of(
                routeConfig("web", "http://127.0.0.1:8080")
        ));
        handler.applyRoutes(List.of());
        assertTrue(handler.getCurrentRoutes().isEmpty());
    }

    @Test
    void applyRoutesNullIsTreatedAsClear() {
        DirectHttpRequestHandler handler = new DirectHttpRequestHandler(List.of(
                routeConfig("web", "http://127.0.0.1:8080")
        ));
        handler.applyRoutes(null);
        assertTrue(handler.getCurrentRoutes().isEmpty());
    }

    @Test
    void applyRoutesSkipsBlankRouteEntries() {
        DirectHttpRequestHandler handler = new DirectHttpRequestHandler(null);
        handler.applyRoutes(List.of(
                routeConfig("", "http://127.0.0.1:8080"),
                routeConfig("  ", "http://127.0.0.1:8081"),
                routeConfig("web", "http://127.0.0.1:8082")
        ));
        // 仅 "web" 进入路由表；空 / 全空白 entry 被忽略
        assertEquals(Map.of("web", "http://127.0.0.1:8082"), handler.getCurrentRoutes());
    }

    private static HttpTunnelConfig routeConfig(String route, String targetBaseUrl) {
        HttpTunnelConfig config = new HttpTunnelConfig();
        config.setRoute(route);
        config.setTargetBaseUrl(targetBaseUrl);
        return config;
    }

    private ByteBuf waitForOutbound(EmbeddedChannel channel) throws InterruptedException {
        for (int attempt = 0; attempt < 100; attempt++) {
            ByteBuf encoded = channel.readOutbound();
            if (encoded != null) {
                return encoded;
            }
            Thread.sleep(10);
        }
        ByteBuf encoded = channel.readOutbound();
        assertNotNull(encoded, "HTTP 直转响应未经过 PacketEncoder");
        return encoded;
    }
}
