package com.theshuai.specus.android;

import org.json.JSONObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

final class ProtocolVectorTestSupport {
    private ProtocolVectorTestSupport() {
    }

    static JSONObject read(String name) throws Exception {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors").resolve(name);
            if (Files.isRegularFile(candidate)) {
                return new JSONObject(new String(Files.readAllBytes(candidate), StandardCharsets.UTF_8));
            }
        }
        throw new IllegalStateException("cannot locate protocol vector: " + name);
    }

    static byte[] hex(String value) {
        return HexFormat.of().parseHex(value);
    }
}
