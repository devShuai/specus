package com.theshuai.tunnelserver.security;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Objects;

/**
 * Builds the Netty {@link SslContext} used for the control-channel TLS handshake.
 *
 * <p>Three modes are supported:
 * <ol>
 *   <li>{@code file} — production: load a real keystore / truststore from disk.</li>
 *   <li>{@code self-signed} — dev / tests: generate a transient self-signed
 *       certificate on the fly so the control channel is still encrypted, just
 *       not authenticated against a real CA.</li>
 *   <li>{@code disabled} — return {@code null} so callers can leave TLS off the
 *       pipeline entirely.</li>
 * </ol>
 */
@Slf4j
public final class TlsContextFactory {

    public enum Mode {
        DISABLED,
        FILE,
        SELF_SIGNED
    }

    private TlsContextFactory() {
    }

    public static SslContext buildServerContext(Mode mode,
                                                String keystorePath,
                                                String keystorePassword,
                                                String keyPassword) {
        Objects.requireNonNull(mode, "mode");
        if (mode == Mode.DISABLED) {
            return null;
        }
        try {
            SslContextBuilder builder;
            if (mode == Mode.SELF_SIGNED) {
                log.warn("[tls] building self-signed server context (dev/test only)");
                SelfSignedCertificate cert = new SelfSignedCertificate();
                builder = SslContextBuilder.forServer(cert.certificate(), cert.privateKey());
            } else {
                File keystoreFile = new File(keystorePath);
                if (!keystoreFile.isFile()) {
                    throw new SSLException("keystore not found: " + keystoreFile.getAbsolutePath());
                }
                char[] storePass = keystorePassword == null ? new char[0] : keystorePassword.toCharArray();
                char[] keyPass = keyPassword == null ? storePass : keyPassword.toCharArray();
                KeyManagerFactory kmf = loadKeyManagerFactory(keystoreFile, storePass, keyPass);
                builder = SslContextBuilder.forServer(kmf);
            }
            builder.sslProvider(SslProvider.JDK);
            return builder.build();
        } catch (CertificateException | SSLException e) {
            throw new IllegalStateException("Failed to build server SslContext: " + e.getMessage(), e);
        }
    }

    private static KeyManagerFactory loadKeyManagerFactory(File keystoreFile, char[] storePassword, char[] keyPassword) throws CertificateException {
        try (InputStream in = new FileInputStream(keystoreFile)) {
            String type = keystoreFile.getName().toLowerCase().endsWith(".p12")
                    || keystoreFile.getName().toLowerCase().endsWith(".pfx")
                    ? "PKCS12"
                    : KeyStore.getDefaultType();
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(in, storePassword);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keyPassword);
            return kmf;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new IllegalStateException("Failed to load keystore " + keystoreFile.getAbsolutePath() + ": " + e.getMessage(), e);
        }
    }

    private static javax.net.ssl.TrustManagerFactory loadTrustManagerFactory(File truststoreFile, String password) throws CertificateException {
        try (InputStream in = new FileInputStream(truststoreFile)) {
            String type = truststoreFile.getName().toLowerCase().endsWith(".p12")
                    || truststoreFile.getName().toLowerCase().endsWith(".pfx")
                    ? "PKCS12"
                    : KeyStore.getDefaultType();
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(in, password.toCharArray());
            javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory
                    .getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            return tmf;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to load truststore " + truststoreFile.getAbsolutePath() + ": " + e.getMessage(), e);
        }
    }

    public static SslContext buildClientContext(Mode mode,
                                                String truststorePath,
                                                String truststorePassword,
                                                boolean trustAll) {
        Objects.requireNonNull(mode, "mode");
        if (mode == Mode.DISABLED) {
            return null;
        }
        try {
            SslContextBuilder builder;
            if (mode == Mode.SELF_SIGNED || trustAll) {
                log.warn("[tls] trusting all server certificates (dev/test only)");
                builder = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE);
            } else {
                File truststore = new File(truststorePath);
                if (!truststore.isFile()) {
                    throw new SSLException("truststore not found: " + truststore.getAbsolutePath());
                }
                javax.net.ssl.TrustManagerFactory tmf = loadTrustManagerFactory(truststore,
                        truststorePassword == null ? "" : truststorePassword);
                builder = SslContextBuilder.forClient().trustManager(tmf);
            }
            builder.sslProvider(SslProvider.JDK);
            return builder.build();
        } catch (SSLException | CertificateException e) {
            throw new IllegalStateException("Failed to build client SslContext: " + e.getMessage(), e);
        }
    }
}
