package com.theshuai.tunnelserver.peer;

import com.theshuai.tunnelserver.config.PeerMeshProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Service
@Slf4j
public class TurnCredentialService {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final PeerMeshProperties properties;
    private final byte[] runtimeSecret;
    private final String nonce;

    public TurnCredentialService(PeerMeshProperties properties) {
        this.properties = properties;
        this.runtimeSecret = randomBytes(32);
        this.nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(18));
        if (properties.isTurnAuthRequired() && !StringUtils.hasText(properties.getTurnSharedSecret())) {
            log.warn("[peer-mesh] TURN auth is enabled without TUNNEL_PEER_MESH_TURN_SHARED_SECRET; "
                    + "using an in-memory secret until restart");
        }
    }

    public boolean authRequired() {
        return properties.isTurnAuthRequired();
    }

    public String realm() {
        return StringUtils.hasText(properties.getTurnRealm())
                ? properties.getTurnRealm().trim()
                : "shuai-tunnel";
    }

    public String nonce() {
        return nonce;
    }

    public TurnCredential issue(String subject) {
        long ttl = Math.max(60, properties.getTurnCredentialTtlSeconds());
        long expiresAtEpochSeconds = Instant.now().plusSeconds(ttl).getEpochSecond();
        String safeSubject = sanitizeSubject(subject);
        String username = expiresAtEpochSeconds + ":" + safeSubject + ":" + randomHex(4);
        String credential = credentialForUsername(username);
        return new TurnCredential(username, credential, realm(), nonce, Instant.ofEpochSecond(expiresAtEpochSeconds));
    }

    public String credentialForUsername(String username) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(hmacSha1(secret(), username.getBytes(StandardCharsets.UTF_8)));
    }

    public boolean usernameCredentialValid(String username, String credential) {
        if (!StringUtils.hasText(username) || !StringUtils.hasText(credential)) {
            return false;
        }
        long expiresAt = parseExpiresAt(username);
        long now = Instant.now().getEpochSecond();
        if (expiresAt <= now || expiresAt - now > Math.max(60, properties.getTurnCredentialTtlSeconds()) + 60) {
            return false;
        }
        byte[] expected = credentialForUsername(username).getBytes(StandardCharsets.UTF_8);
        byte[] actual = credential.trim().getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, actual);
    }

    public byte[] longTermKey(String username, String credential) {
        String text = username + ":" + realm() + ":" + credential;
        return md5(text.getBytes(StandardCharsets.UTF_8));
    }

    /** 公开互传（浏览器 WebRTC）凭证的 subject 前缀；这类 allocation 走通用 TURN 语义 */
    public static final String GENERAL_SUBJECT_PREFIX = "public-transfer";

    /**
     * 判断该 TURN 用户名是否属于通用中继用途（当前只有公开互传）。
     *
     * <p>浏览器经 TURN 转发的是 DTLS/SRTP/SCTP 与 STUN 连通性检查，既不是 SPM2 帧也不是
     * 本项目的 probe JSON，无法通过 Peer Mesh 专用校验；这类 allocation 必须按标准 TURN 放行，
     * 并由独立的目的地址策略和配额约束。
     */
    public boolean isGeneralRelaySubject(String username) {
        if (!StringUtils.hasText(username)) {
            return false;
        }
        String[] parts = username.split(":", 3);
        return parts.length == 3 && parts[1].startsWith(GENERAL_SUBJECT_PREFIX);
    }

    public long peerMeshClientId(String username) {
        if (!StringUtils.hasText(username)) {
            return 0;
        }
        String[] parts = username.split(":", 3);
        if (parts.length != 3 || !parts[1].startsWith("pm-")) {
            return 0;
        }
        try {
            long clientId = Long.parseLong(parts[1].substring(3));
            return clientId > 0 ? clientId : 0;
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private long parseExpiresAt(String username) {
        int colon = username.indexOf(':');
        String prefix = colon < 0 ? username : username.substring(0, colon);
        try {
            return Long.parseLong(prefix.trim());
        } catch (Exception ignored) {
            return 0;
        }
    }

    private byte[] secret() {
        if (StringUtils.hasText(properties.getTurnSharedSecret())) {
            return properties.getTurnSharedSecret().trim().getBytes(StandardCharsets.UTF_8);
        }
        return runtimeSecret;
    }

    private static String sanitizeSubject(String subject) {
        String normalized = StringUtils.hasText(subject) ? subject.trim() : "peer";
        return normalized.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    private static byte[] randomBytes(int count) {
        byte[] bytes = new byte[count];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static String randomHex(int bytes) {
        return HexFormat.of().formatHex(randomBytes(bytes));
    }

    private static byte[] hmacSha1(byte[] key, byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            return mac.doFinal(payload);
        } catch (Exception e) {
            throw new IllegalStateException("cannot sign TURN credential", e);
        }
    }

    private static byte[] md5(byte[] payload) {
        try {
            return MessageDigest.getInstance("MD5").digest(payload);
        } catch (Exception e) {
            throw new IllegalStateException("cannot derive TURN long-term key", e);
        }
    }

    public record TurnCredential(String username,
                                 String credential,
                                 String realm,
                                 String nonce,
                                 Instant expiresAt) {
    }
}
