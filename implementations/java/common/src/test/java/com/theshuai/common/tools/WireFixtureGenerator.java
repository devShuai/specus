package com.theshuai.common.tools;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.request.LogoutRequestPacket;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.HeartBeatResponsePacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.protocol.response.LogoutResponsePacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Emits canonical control-protocol v2 frames into the repository-wide test-vector directory.
 * Run with:
 * <pre>
 *   mvn -pl :specus-common test-compile exec:java \
 *       -Dexec.mainClass=com.theshuai.common.tools.WireFixtureGenerator \
 *       -Dexec.classpathScope=test \
 *       -Dexec.args="protocol/test-vectors/control-v2/frames"
 * </pre>
 *
 * <p>Every language loads these as expected-bytes fixtures. The C# entry point is
 * <c>implementations/csharp/protocol/tests/Specus.Protocol.Tests/PacketCodecFixtureTests.cs</c>.
 *
 * <p>Each fixture is named after the packet kind (e.g. <c>login_request.bin</c>) plus optional
 * variant suffixes. Update {@link Fixtures#emit(Path)} when adding new fixtures and re-run.
 */
public final class WireFixtureGenerator {

    public static void main(String[] args) throws IOException {
        Path outputDir = Paths.get(args.length > 0 ? args[0] : "protocol/test-vectors/control-v2/frames").toAbsolutePath();
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
            LoginRequestPacket login = new LoginRequestPacket();
            login.setClientName("Demo client");
            login.setClientSessionId(1700000000000L);
            login.setAccessToken("cs_fixture_access_token");
            login.setConnectionRole(ConnectionRole.CONTROL);
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

            // NAT_MESSAGE — one fixture per type. Metadata layouts mirror what the server emits.
            write("nat_register.bin", natPacket(NatMessageType.REGISTER, orderedMap(
                    "clientName", "Demo client",
                    "port", 18080,
                    "specusAddress", "127.0.0.1",
                    "specusPort", 80), null));
            write("nat_register_result.bin", natPacket(NatMessageType.REGISTER_RESULT, orderedMap(
                    "port", 18080,
                    "success", true), null));
            write("nat_open.bin", natPacket(NatMessageType.OPEN, 1, 0, orderedMap(
                    "channelId", "00010203-aaaa-bbbb-cccc-ddddeeeeffff",
                    "port", 18080), null));
            write("nat_fin.bin", natPacket(NatMessageType.FIN, 1, 0, null, null));
            write("nat_rst.bin", natPacket(NatMessageType.RST, 1, 7,
                    orderedMap("reason", "upstream reset"), null));
            write("nat_window_update.bin", natPacket(NatMessageType.WINDOW_UPDATE, 1, 65536,
                    null, null));
            write("nat_keepalive.bin", natPacket(NatMessageType.KEEPALIVE, new LinkedHashMap<>(), null));
            write("nat_unregister.bin", natPacket(NatMessageType.UNREGISTER, orderedMap("port", 18080), null));

            // DATA payload is always raw in control protocol v2.
            byte[] tinyPayload = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            write("nat_data_small.bin", natPacket(NatMessageType.DATA, 1, 0, null, tinyPayload));

            // Large DATA packet verifies exact lengths and raw payload interoperability.
            byte[] largePayload = new byte[256];
            java.util.Arrays.fill(largePayload, (byte) 'A');
            write("nat_data_large.bin", natPacket(NatMessageType.DATA, 1, 0, null, largePayload));

            write("http_stream_request_open.bin", natPacket(NatMessageType.OPEN, 101, 0, orderedMap(
                    "source", "http",
                    "phase", "request",
                    "method", "POST",
                    "route", "api",
                    "relativePath", "/v2/items",
                    "rawQuery", "limit=10",
                    "headers", List.of("Content-Type:application/json", "X-Fixture:1"),
                    "contentLength", 14,
                    "trailerNames", List.of()), null));
            write("http_stream_request_data.bin", natPacket(NatMessageType.DATA, 101, 0, null,
                    "{\"hello\":true}".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            write("http_stream_request_fin.bin", natPacket(NatMessageType.FIN, 101, 0,
                    orderedMap("trailers", List.of()), null));
            write("http_stream_response_open.bin", natPacket(NatMessageType.OPEN, 101, 0, orderedMap(
                    "source", "http",
                    "phase", "response",
                    "statusCode", 200,
                    "headers", List.of("Content-Type:application/json"),
                    "trailerNames", List.of("Digest")), null));
            write("http_stream_response_data.bin", natPacket(NatMessageType.DATA, 101, 0, null,
                    "{\"ok\":true}".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            write("http_stream_response_fin.bin", natPacket(NatMessageType.FIN, 101, 0,
                    orderedMap("trailers", List.of("Digest:sha-256=fixture")), null));

            emitMalformedFrames();
        }

        private void emitMalformedFrames() throws IOException {
            byte[] heartbeat = Files.readAllBytes(outputDir.resolve("heartbeat_request.bin"));

            byte[] badMagic = heartbeat.clone();
            badMagic[0] ^= 0x01;
            writeRaw("invalid_bad_magic.bin", badMagic);

            byte[] oldVersion = heartbeat.clone();
            oldVersion[4] = 1;
            writeRaw("invalid_version_v1.bin", oldVersion);

            byte[] badSerializer = heartbeat.clone();
            badSerializer[5] = 1;
            writeRaw("invalid_serializer.bin", badSerializer);

            byte[] unknownCommand = heartbeat.clone();
            unknownCommand[6] = 99;
            writeRaw("invalid_unknown_command.bin", unknownCommand);

            writeRaw("invalid_truncated_header.bin", java.util.Arrays.copyOf(heartbeat, 10));

            byte[] truncatedBody = Files.readAllBytes(outputDir.resolve("login_request.bin"));
            writeRaw("invalid_truncated_body.bin", java.util.Arrays.copyOf(truncatedBody, truncatedBody.length - 1));

            byte[] trailingBody = java.util.Arrays.copyOf(heartbeat, heartbeat.length + 1);
            trailingBody[trailingBody.length - 1] = 0x2a;
            writeRaw("invalid_trailing_body.bin", trailingBody);

            byte[] nonEmptyHeartbeat = java.util.Arrays.copyOf(heartbeat, heartbeat.length + 1);
            nonEmptyHeartbeat[7] = 0;
            nonEmptyHeartbeat[8] = 0;
            nonEmptyHeartbeat[9] = 0;
            nonEmptyHeartbeat[10] = 1;
            nonEmptyHeartbeat[11] = 0;
            writeRaw("invalid_heartbeat_body.bin", nonEmptyHeartbeat);

            byte[] oversized = heartbeat.clone();
            int oversizedBody = 32 * 1024 * 1024;
            oversized[7] = (byte) (oversizedBody >>> 24);
            oversized[8] = (byte) (oversizedBody >>> 16);
            oversized[9] = (byte) (oversizedBody >>> 8);
            oversized[10] = (byte) oversizedBody;
            writeRaw("invalid_oversized_length.bin", oversized);
        }

        private NatMessagePacket natPacket(NatMessageType type, Map<String, Object> meta, byte[] data) {
            return natPacket(type, 0, 0, meta, data);
        }

        private NatMessagePacket natPacket(NatMessageType type, int streamId, long value,
                                           Map<String, Object> meta, byte[] data) {
            NatMessagePacket packet = new NatMessagePacket();
            packet.setNatMessageType(type);
            packet.setStreamId(streamId);
            packet.setValue(value);
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

        private void writeRaw(String name, byte[] bytes) throws IOException {
            Files.write(outputDir.resolve(name), bytes);
        }

        private static Map<String, Object> orderedMap(Object... kvPairs) {
            Map<String, Object> map = new LinkedHashMap<>();
            for (int i = 0; i < kvPairs.length; i += 2) {
                map.put((String) kvPairs[i], kvPairs[i + 1]);
            }
            return map;
        }

    }

    private WireFixtureGenerator() {
    }
}
