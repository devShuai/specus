package com.theshuai.common.clientauth;

import com.theshuai.common.security.HmacSigner;

import java.util.HexFormat;
import java.util.Objects;

public final class ClientAuthSigner {
    private ClientAuthSigner() {
    }

    public static String signApiKey(String apiKey,
                                    String timestamp,
                                    String nonce,
                                    ClientEnvironmentInfo environment,
                                    String secret) {
        return HexFormat.of().formatHex(HmacSigner.hmacSha256(
                HmacSigner.sha256(secret),
                canonicalApiKeyMessage(apiKey, timestamp, nonce, environment)
        ));
    }

    public static String canonicalApiKeyMessage(String apiKey,
                                                String timestamp,
                                                String nonce,
                                                ClientEnvironmentInfo environment) {
        Objects.requireNonNull(environment, "environment");
        return value(apiKey) + "\n"
                + value(timestamp) + "\n"
                + value(nonce) + "\n"
                + value(environment.getMachineFingerprint()) + "\n"
                + value(environment.getOsUser());
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }
}
