package com.theshuai.specusserver.security;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.management.tenant.TenantResolver;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;

/**
 * Issues and signs the local (password-login) JWTs and verifies the admin credentials. The HS256
 * key is shared with the resource server's local decoder so the same token is accepted on the API.
 */
@Service
public class LocalTokenService {
    public static final String ISSUER = "specus";

    private final AuthProperties properties;
    private final SecretKey secretKey;
    private final JwtEncoder encoder;

    public LocalTokenService(AuthProperties properties) {
        this.properties = properties;
        this.secretKey = buildKey(properties.getJwtSecret());
        this.encoder = new NimbusJwtEncoder(new ImmutableSecret<>(secretKey));
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public long getTtlSeconds() {
        return properties.getTokenTtlSeconds();
    }

    public boolean isPasswordLoginEnabled() {
        return properties.isPasswordLoginEnabled() && StringUtils.hasText(properties.getPassword());
    }

    public boolean authenticate(String username, String password) {
        if (!isPasswordLoginEnabled() || username == null || password == null) {
            return false;
        }
        // Bitwise & (not &&) so both comparisons always run, avoiding an early-out timing signal.
        return constantTimeEquals(properties.getUsername(), username)
                & constantTimeEquals(properties.getPassword(), password);
    }

    public String issueToken(String username) {
        return issueToken(username, properties.getTenantId(), ManagementRole.ADMIN);
    }

    public String issueToken(String username, String tenantId, ManagementRole role) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(ISSUER)
                .subject(username)
                .claim(TenantResolver.LOCAL_TENANT_CLAIM, TenantContext.normalize(tenantId))
                .claim("role", role == null ? ManagementRole.USER.name() : role.name())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(properties.getTokenTtlSeconds()))
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private static SecretKey buildKey(String secret) {
        byte[] keyBytes = new byte[32];
        if (StringUtils.hasText(secret)) {
            keyBytes = sha256(secret);
        } else {
            new SecureRandom().nextBytes(keyBytes);
        }
        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
