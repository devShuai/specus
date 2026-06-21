package com.theshuai.common.tools;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.common.protocol.request.HttpRequestPacket;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.request.LogoutRequestPacket;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import com.theshuai.common.protocol.response.HeartBeatResponsePacket;
import com.theshuai.common.protocol.response.HttpResponsePacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.protocol.response.LogoutResponsePacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Emits canonical encoded bytes for every packet type to <c>tests/fixtures/*.bin</c> in the
 * csharp project. Run with:
 * <pre>
 *   mvn -pl tunnel-common test-compile exec:java \
 *       -Dexec.mainClass=com.theshuai.common.tools.WireFixtureGenerator \
 *       -Dexec.classpathScope=test \
 *       -Dexec.args="../tunnel-server-tunnel-server-csharp/tests/fixtures"
 * </pre>
 *
 * <p>The C# tests load these as expected-bytes fixtures — see
 * <c>tunnel-server-csharp/tests/ShuaiTunnel.Protocol.Tests/PacketCodecFixtureTests.cs</c>.
 *
 * <p>Each fixture is named after the packet kind (e.g. <c>login_request.bin</c>) plus optional
 * variant suffixes. Update {@link Fixtures#emit(Path)} when adding new fixtures and re-run.
 */
public final class WireFixtureGenerator {

    public static void main(String[] args) throws IOException {
        Path outputDir = Paths.get(args.length > 0 ? args[0] : "tunnel-server-csharp/tests/fixtures").toAbsolutePath();
        Files.createDirectories(outputDir);
        new Fixtures(outputDir).emit();
        System.out.println("wrote fixtures to " + outputDir);
    }

    private static final class Fixtures {
        private final Path outputDir;

        Fixtures(Path outputDir) {
            this.outputDir = outputDir;
        }

        void emit() throws IOException {
            // Login request: HMAC sign field is a deterministic 32-byte sequence so the wire
            // bytes are stable across runs. Real signatures come from HmacSigner.
            LoginRequestPacket login = new LoginRequestPacket();
            login.setClientName("Demo client");
            login.setTimestamp("1700000000000");
            login.setNonce("nonce-fixture");
            login.setCheckSign(deterministicSign());
            write("login_request.bin", login);

            LoginResponsePacket loginResp = new LoginResponsePacket();
            loginResp.setClientName("Demo client");
            loginResp.setSuccess(true);
            loginResp.setReason(null);
            write("login_response.bin", loginResp);

            LoginResponsePacket loginRespFail = new LoginResponsePacket();
            loginRespFail.setClientName("Demo client");
            loginRespFail.setSuccess(false);
            loginRespFail.setReason("时间戳过期");
            write("login_response_fail.bin", loginRespFail);

            write("logout_request.bin", new LogoutRequestPacket());

            LogoutResponsePacket logoutResp = new LogoutResponsePacket();
            logoutResp.setSuccess(true);
            logoutResp.setReason(null);
            write("logout_response.bin", logoutResp);

            write("heartbeat_request.bin", new HeartBeatRequestPacket());
            write("heartbeat_response.bin", new HeartBeatResponsePacket());

            MessageRequestPacket msgReq = new MessageRequestPacket();
            msgReq.setClientName("Demo client");
            msgReq.setToClientName("admin");
            msgReq.setMessageType(MessageType.CLIENT_TO_SERVER);
            msgReq.setMessage("hello, server");
            write("message_request.bin", msgReq);

            MessageResponsePacket msgResp = new MessageResponsePacket();
            msgResp.setClientName("admin");
            msgResp.setToClientName("Demo client");
            msgResp.setMessageType(MessageType.NAT_CONTROL);
            msgResp.setMessage("{\"clientName\":\"Demo client\",\"remotePort\":7010}");
            write("message_response.bin", msgResp);

            // HttpRequest covers UUID, HTTP_METHOD enum, STRING_MAP, and a small body.
            HttpRequestPacket http = new HttpRequestPacket();
            http.setClientName("Demo client");
            http.setToClientName("upstream");
            http.setRequestId("123e4567-e89b-12d3-a456-426614174000");
            http.setRequestMethod("POST");
            http.setRequestUrl("http://127.0.0.1:8080/api/demo");
            http.setHeaderMap(orderedStringMap(
                    "Content-Type", "application/json",
                    "X-Request-Id", "fixture-1"));
            http.setParamMap(orderedStringMap("limit", "10"));
            http.setBody("{\"hello\":\"world\"}");
            write("http_request.bin", http);

            HttpResponsePacket httpResp = new HttpResponsePacket();
            httpResp.setClientName("upstream");
            httpResp.setToClientName("Demo client");
            httpResp.setRequestId("123e4567-e89b-12d3-a456-426614174000");
            httpResp.setResponse("{\"ok\":true}");
            write("http_response.bin", httpResp);

            // Direct HTTP — exercises STRING_LIST and BYTE_ARRAY together.
            DirectHttpRequestPacket direct = new DirectHttpRequestPacket();
            direct.setRequestId("11111111-2222-3333-4444-555555555555");
            direct.setRequestMethod("GET");
            direct.setRoute("api");
            direct.setRelativePath("/v1/items");
            direct.setRawQuery("limit=10&page=1");
            direct.setHeaders(List.of("accept: application/json", "x-fixture: 1"));
            direct.setBody(new byte[0]);
            write("direct_http_request.bin", direct);

            DirectHttpResponsePacket directResp = new DirectHttpResponsePacket();
            directResp.setRequestId("11111111-2222-3333-4444-555555555555");
            directResp.setStatusCode(200);
            directResp.setHeaders(List.of("content-type: application/json"));
            directResp.setBody("{\"ok\":true}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            directResp.setError(null);
            write("direct_http_response.bin", directResp);

            // NAT_MESSAGE — one fixture per type. Metadata layouts mirror what the server emits.
            write("nat_register.bin", natPacket(NatMessageType.REGISTER, orderedMap(
                    "clientName", "Demo client",
                    "port", 18080,
                    "tunnelAddress", "127.0.0.1",
                    "tunnelPort", 80), null));
            write("nat_register_result.bin", natPacket(NatMessageType.REGISTER_RESULT, orderedMap(
                    "port", 18080,
                    "success", true), null));
            write("nat_connected.bin", natPacket(NatMessageType.CONNECTED, orderedMap(
                    "channelId", "00010203-aaaa-bbbb-cccc-ddddeeeeffff",
                    "port", 18080), null));
            write("nat_disconnected.bin", natPacket(NatMessageType.DISCONNECTED, orderedMap(
                    "channelId", "00010203-aaaa-bbbb-cccc-ddddeeeeffff"), null));
            write("nat_keepalive.bin", natPacket(NatMessageType.KEEPALIVE, new LinkedHashMap<>(), null));
            write("nat_unregister.bin", natPacket(NatMessageType.UNREGISTER, orderedMap("port", 18080), null));

            // Small DATA packet — under the 64-byte threshold, raw payload prefix.
            byte[] tinyPayload = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            write("nat_data_small.bin", natPacket(NatMessageType.DATA, orderedMap(
                    "channelId", "00010203-aaaa-bbbb-cccc-ddddeeeeffff"), tinyPayload));

            // Large DATA packet — repeating bytes to exercise the deflate path. Note: the exact
            // deflated bytes depend on the underlying zlib implementation, so the C# tests treat
            // this fixture as decode-only (they don't compare encode output byte-for-byte).
            byte[] largePayload = new byte[256];
            Arrays.fill(largePayload, (byte) 'A');
            write("nat_data_large_deflated.bin", natPacket(NatMessageType.DATA, orderedMap(
                    "channelId", "00010203-aaaa-bbbb-cccc-ddddeeeeffff"), largePayload));
        }

        private NatMessagePacket natPacket(NatMessageType type, Map<String, Object> meta, byte[] data) {
            NatMessagePacket packet = new NatMessagePacket();
            packet.setNatMessageType(type);
            packet.setMetaData(meta);
            packet.setData(data);
            return packet;
        }

        private void write(String name, Packet packet) throws IOException {
            ByteBuf buf = Unpooled.buffer();
            try {
                PacketCodec.INSTANCE.encode(buf, packet);
                byte[] bytes = new byte[buf.readableBytes()];
                buf.readBytes(bytes);
                Files.write(outputDir.resolve(name), bytes);
            } catch (Exception e) {
                throw new IOException("failed to encode " + name, e);
            } finally {
                buf.release();
            }
        }

        private static Map<String, Object> orderedMap(Object... kvPairs) {
            Map<String, Object> map = new LinkedHashMap<>();
            for (int i = 0; i < kvPairs.length; i += 2) {
                map.put((String) kvPairs[i], kvPairs[i + 1]);
            }
            return map;
        }

        private static Map<String, String> orderedStringMap(String... kvPairs) {
            Map<String, String> map = new LinkedHashMap<>();
            for (int i = 0; i < kvPairs.length; i += 2) {
                map.put(kvPairs[i], kvPairs[i + 1]);
            }
            return map;
        }

        private static byte[] deterministicSign() {
            byte[] sign = new byte[32];
            for (int i = 0; i < 32; i++) {
                sign[i] = (byte) (i + 1);
            }
            return sign;
        }
    }

    private WireFixtureGenerator() {
    }
}
