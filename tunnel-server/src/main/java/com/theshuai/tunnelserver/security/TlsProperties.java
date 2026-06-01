package com.theshuai.tunnelserver.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Type-safe binding for the {@code tunnel.tls.*} block in application.yml.
 *
 * <p>Defaults to {@code disabled} so existing deployments without TLS continue
 * to work until operators opt in by setting {@code tunnel.tls.mode=file} or
 * {@code tunnel.tls.mode=self-signed}.
 */
@Component
@ConfigurationProperties(prefix = "tunnel.tls")
public class TlsProperties {

    /**
     * {@code disabled}: no TLS, control channel is plain TCP.
     * {@code file}: load a real keystore / truststore from disk.
     * {@code self-signed}: generate a transient self-signed cert at startup (dev/test only).
     */
    private String mode = "disabled";

    /** Path to the server keystore (JKS / PKCS12). Only used when mode=file. */
    private String keystore;

    /** Password for the keystore and (by default) the key inside it. */
    private String keystorePassword;

    /** Password for the key inside the keystore; if null, falls back to keystorePassword. */
    private String keyPassword;

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getKeystore() {
        return keystore;
    }

    public void setKeystore(String keystore) {
        this.keystore = keystore;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public void setKeystorePassword(String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public TlsContextFactory.Mode resolveMode() {
        if (mode == null) {
            return TlsContextFactory.Mode.DISABLED;
        }
        return switch (mode.trim().toLowerCase()) {
            case "file" -> TlsContextFactory.Mode.FILE;
            case "self-signed", "selfsigned", "self_signed" -> TlsContextFactory.Mode.SELF_SIGNED;
            default -> TlsContextFactory.Mode.DISABLED;
        };
    }
}
