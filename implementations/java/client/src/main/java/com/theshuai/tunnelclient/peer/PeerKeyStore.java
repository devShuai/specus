package com.theshuai.tunnelclient.peer;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

@Slf4j
public final class PeerKeyStore {
    private static final String DIRECTORY = ".shuai-tunnel";
    private static final String PUBLIC_KEY_FILE = "peer-public.x25519";
    private static final String PRIVATE_KEY_FILE = "peer-private.x25519";

    private PeerKeyStore() {
    }

    public static String publicKeyBase64() {
        return keyMaterial().publicKeyBase64();
    }

    public static String privateKeyBase64() {
        return keyMaterial().privateKeyBase64();
    }

    public static synchronized KeyMaterial keyMaterial() {
        try {
            Path directory = Path.of(System.getProperty("user.home"), DIRECTORY);
            Path publicKey = directory.resolve(PUBLIC_KEY_FILE);
            Path privateKey = directory.resolve(PRIVATE_KEY_FILE);
            if (Files.exists(publicKey) && Files.exists(privateKey)) {
                String existingPublic = Files.readString(publicKey, StandardCharsets.UTF_8).trim();
                String existingPrivate = Files.readString(privateKey, StandardCharsets.UTF_8).trim();
                if (StringUtils.hasText(existingPublic) && StringUtils.hasText(existingPrivate)) {
                    return new KeyMaterial(existingPublic, existingPrivate);
                }
            }
            Files.createDirectories(directory);
            KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");
            KeyPair keyPair = generator.generateKeyPair();
            String encodedPublic = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String encodedPrivate = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            Files.writeString(publicKey, encodedPublic, StandardCharsets.UTF_8);
            Files.writeString(privateKey, encodedPrivate, StandardCharsets.UTF_8);
            return new KeyMaterial(encodedPublic, encodedPrivate);
        } catch (Exception e) {
            log.warn("生成 peer mesh X25519 公钥失败: {}", e.getMessage());
            return new KeyMaterial("", "");
        }
    }

    public record KeyMaterial(String publicKeyBase64, String privateKeyBase64) {
    }
}
