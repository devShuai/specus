package com.theshuai.specusclient.client;

import com.theshuai.specusclient.bean.UpstreamTlsConfig;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Builds the {@link SslContext} used for HTTPS and WebSocket connections to the forwarding target.
 *
 * <p>See {@link UpstreamTlsConfig} for why verification is the default and how a self-signed
 * target is described. Misconfiguration throws here rather than falling back to trusting
 * everything, because a silent fallback is exactly the behaviour this replaces.
 */
public final class UpstreamTlsPolicy {
    private final UpstreamTlsConfig config;

    public UpstreamTlsPolicy(UpstreamTlsConfig config) {
        this.config = config == null ? new UpstreamTlsConfig() : config;
    }

    /** Whether connections built by this policy verify the peer at all. */
    public boolean verifies() {
        return !config.isInsecureSkipVerify();
    }

    /** Whether the peer is identified by a pin rather than by a certificate chain. */
    public boolean pins() {
        return !normalizedPins(config.getPinnedCertificateSha256()).isEmpty();
    }

    public SslContext buildContext() {
        try {
            if (config.isInsecureSkipVerify()) {
                return SslContextBuilder.forClient()
                        .trustManager(InsecureTrustManagerFactory.INSTANCE)
                        .build();
            }

            Set<String> pinned = normalizedPins(config.getPinnedCertificateSha256());
            if (!pinned.isEmpty()) {
                // Pinning replaces chain verification: a pinned target usually has no chain to
                // verify. The pin is the check, and it is stricter than a chain.
                return SslContextBuilder.forClient()
                        .trustManager(new PinningTrustManager(pinned))
                        .build();
            }

            SslContextBuilder builder = SslContextBuilder.forClient();
            String caPath = config.getCaCertificatePath();
            if (caPath != null && !caPath.isBlank()) {
                File caFile = new File(caPath.trim());
                if (!caFile.isFile()) {
                    throw new IllegalStateException(
                            "upstreamTls.caCertificatePath does not exist: " + caPath);
                }
                builder.trustManager(caFile);
            }
            // With no explicit trust manager Netty falls back to the platform default roots.
            return builder.build();
        } catch (IllegalStateException rethrow) {
            throw rethrow;
        } catch (Exception error) {
            throw new IllegalStateException("failed to build upstream TLS context", error);
        }
    }

    /**
     * Builds the configured context unless a route explicitly opts out of verification.
     * The route override is deliberately one-way: it can relax the global policy for a single
     * self-signed target, while the existing global insecure setting still applies to all routes.
     */
    public SslContext buildContext(boolean routeInsecureSkipVerify) {
        if (!routeInsecureSkipVerify) {
            return buildContext();
        }
        try {
            return SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();
        } catch (Exception error) {
            throw new IllegalStateException("failed to build insecure upstream TLS context", error);
        }
    }

    /**
     * Turns on hostname verification. A trust manager checks that the certificate is trusted, not
     * that it belongs to the host being dialled, so without this a valid certificate for any host
     * would be accepted for every host. Pinning identifies the peer directly and does not need it.
     */
    public void applyHostnameVerification(SSLEngine engine) {
        if (!verifies() || pins()) {
            disableHostnameVerification(engine);
            return;
        }
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        engine.setSSLParameters(parameters);
    }

    public void applyHostnameVerification(SSLEngine engine, boolean routeInsecureSkipVerify) {
        if (routeInsecureSkipVerify) {
            disableHostnameVerification(engine);
            return;
        }
        applyHostnameVerification(engine);
    }

    private static void disableHostnameVerification(SSLEngine engine) {
        SSLParameters parameters = engine.getSSLParameters();
        // Netty's OpenSSL engine keeps its default when given null; an empty algorithm is the
        // portable way to turn endpoint identification off (also used by NettyClient).
        parameters.setEndpointIdentificationAlgorithm("");
        engine.setSSLParameters(parameters);
    }

    static Set<String> normalizedPins(List<String> configured) {
        Set<String> pinned = new HashSet<>();
        if (configured == null) {
            return pinned;
        }
        for (String value : configured) {
            if (value == null || value.isBlank()) {
                continue;
            }
            // Tools print fingerprints as colon-separated uppercase pairs; accept that form too.
            String normalized = value.trim()
                    .replace(":", "").replace(" ", "").replace("-", "")
                    .toLowerCase(Locale.ROOT);
            if (normalized.length() != 64) {
                throw new IllegalStateException(
                        "upstreamTls.pinnedCertificateSha256 entry is not a SHA-256 digest: " + value);
            }
            try {
                new BigInteger(normalized, 16);
            } catch (NumberFormatException notHex) {
                throw new IllegalStateException(
                        "upstreamTls.pinnedCertificateSha256 entry is not hex: " + value, notHex);
            }
            pinned.add(normalized);
        }
        return pinned;
    }

    /** Accepts only the pinned leaf certificates. Intermediates are free to change. */
    private static final class PinningTrustManager implements X509TrustManager {
        private final Set<String> pinned;

        private PinningTrustManager(Set<String> pinned) {
            this.pinned = pinned;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new CertificateException("this trust manager is for client-side use only");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            if (chain == null || chain.length == 0) {
                throw new CertificateException(
                        "upstream presented no certificate to match against the pin");
            }
            String fingerprint = sha256Hex(chain[0]);
            if (!pinned.contains(fingerprint)) {
                throw new CertificateException("upstream certificate " + fingerprint
                        + " does not match any pinned fingerprint");
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        private static String sha256Hex(X509Certificate certificate) throws CertificateException {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
                StringBuilder builder = new StringBuilder(digest.length * 2);
                for (byte value : digest) {
                    builder.append(Character.forDigit(value >>> 4 & 0x0F, 16));
                    builder.append(Character.forDigit(value & 0x0F, 16));
                }
                return builder.toString();
            } catch (Exception error) {
                throw new CertificateException("cannot fingerprint upstream certificate", error);
            }
        }
    }
}
