package com.theshuai.common.protocol;

import com.theshuai.common.protocol.request.LoginRequestPacket;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class CanonicalControlFixtureTests {
    @Test
    void loginRequestUsesMandatoryControlRole() throws Exception {
        byte[] fixture = Files.readAllBytes(findFixture("login_request.bin"));
        ByteBuf input = Unpooled.wrappedBuffer(fixture);
        try {
            LoginRequestPacket packet = assertInstanceOf(
                    LoginRequestPacket.class,
                    PacketCodec.INSTANCE.decode(input));
            assertFalse(input.isReadable());
            assertEquals("Demo client", packet.getClientName());
            assertEquals(1_700_000_000_000L, packet.getClientSessionId());
            assertEquals("cs_fixture_access_token", packet.getAccessToken());
            assertEquals(ConnectionRole.CONTROL, packet.getConnectionRole());
        } finally {
            input.release();
        }
    }

    private static Path findFixture(String name) {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 6; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/control-v2/frames").resolve(name);
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("cannot locate canonical control fixture: " + name);
    }
}
