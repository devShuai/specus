package com.theshuai.specus.android;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import java.io.File;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509TrustManager;

/**
 * Trust policy for connections to the service this client forwards to.
 *
 * <p>Those connections used to be made with verification disabled outright, on the reasoning that
 * an operator-managed LAN target may present a self-signed certificate. That reasoning trades a
 * real guarantee for a convenience: anything able to answer on the target address, or to sit
 * between the phone and it, was accepted silently, and the tunnel then carried the result to a
 * remote user with no way to notice. On a phone this is worse than on a server, because the device
 * routinely sits on networks nobody controls.
 *
 * <p>Verification is the default. A self-signed target is still supported, but only by saying so:
 * name the CA that issued it, pin its leaf certificate, or state plainly that it is not verified.
 */
public final class UpstreamTlsPolicy {
    private static volatile UpstreamTlsPolicy current = new UpstreamTlsPolicy(false, null, List.of());

    private final boolean insecureSkipVerify;
    private final String caCertificatePath;
    private final Set<String> pinned;

    public UpstreamTlsPolicy(boolean insecureSkipVerify, String caCertificatePath,
                             List<String> pinnedCertificateSha256) {
        this.insecureSkipVerify = insecureSkipVerify;
        this.caCertificatePath = caCertificatePath;
        this.pinned = normalizedPins(pinnedCertificateSha256);
    }

    /**
     * Publishes the operator's policy. The transports build their SSL context statically and have
     * no reference to the settings, so it is read from here.
     *
     * <p>The default is a policy that verifies: if configuration never arrives, the transports
     * fall back to checking certificates rather than to trusting everything.
     */
    public static void configure(UpstreamTlsPolicy policy) {
        current = policy == null ? new UpstreamTlsPolicy(false, null, List.of()) : policy;
    }

    public static UpstreamTlsPolicy current() {
        return current;
    }

    public boolean verifies() {
        return !insecureSkipVerify;
    }

    public boolean pins() {
        return !pinned.isEmpty();
    }

    public SslContext buildContext() {
        try {
            if (insecureSkipVerify) {
                return SslContextBuilder.forClient()
                        .trustManager(InsecureTrustManagerFactory.INSTANCE)
                        .build();
            }
            if (!pinned.isEmpty()) {
                // Pinning replaces chain verification: a pinned target usually has no chain to
                // verify. The pin is the check, and it is stricter than a chain.
                return SslContextBuilder.forClient()
                        .trustManager(new PinningTrustManager(pinned))
                        .build();
            }

            SslContextBuilder builder = SslContextBuilder.forClient();
            if (caCertificatePath != null && !caCertificatePath.trim().isEmpty()) {
                File caFile = new File(caCertificatePath.trim());
                if (!caFile.isFile()) {
                    throw new IllegalStateException(
                            "upstream CA certificate does not exist: " + caCertificatePath);
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
     * Turns on hostname verification. A trust manager checks that a certificate is trusted, not
     * that it belongs to the host being dialled, so without this a valid certificate for any host
     * would be accepted for every host. Pinning identifies the peer directly and does not need it.
     */
    public void applyHostnameVerification(SSLEngine engine) {
        if (!verifies() || pins()) {
            return;
        }
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        engine.setSSLParameters(parameters);
    }

    static Set<String> normalizedPins(List<String> configured) {
        if (configured == null || configured.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> result = new HashSet<>();
        List<String> rejected = new ArrayList<>();
        for (String value : configured) {
            if (value == null || value.trim().isEmpty()) {
                continue;
            }
            // Tools print fingerprints as colon-separated uppercase pairs; accept that form too.
            String normalized = value.trim()
                    .replace(":", "").replace(" ", "").replace("-", "")
                    .toLowerCase(Locale.ROOT);
            if (normalized.length() != 64) {
                rejected.add(value);
                continue;
            }
            try {
                new BigInteger(normalized, 16);
            } catch (NumberFormatException notHex) {
                rejected.add(value);
                continue;
            }
            result.add(normalized);
        }
        if (!rejected.isEmpty()) {
            throw new IllegalStateException(
                    "pinned certificate fingerprints are not SHA-256 hex digests: " + rejected);
        }
        return result;
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
