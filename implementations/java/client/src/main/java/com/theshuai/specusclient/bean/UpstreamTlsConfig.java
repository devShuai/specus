package com.theshuai.specusclient.bean;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Trust settings for connections to the service this client forwards to.
 *
 * <p>These connections used to be made with verification disabled outright, on the reasoning that
 * an operator-managed LAN target may present a self-signed certificate. That reasoning trades a
 * real guarantee for a convenience: anything able to answer on the target address, or to sit
 * between the client and it, was accepted silently, and the tunnel then carried the result to a
 * remote user with no way to notice.
 *
 * <p>Verification is the default. A self-signed target is still supported, but only by saying so:
 * name the CA that issued it, pin its leaf certificate, or state plainly that it is not verified.
 */
@Data
public class UpstreamTlsConfig {
    /**
     * Accepts any certificate. It exists because some deployments genuinely cannot do better; it
     * has to be written down rather than assumed.
     */
    private boolean insecureSkipVerify;

    /**
     * Trusts a private CA in addition to the platform roots, which is the right answer when the
     * operator runs their own issuer.
     */
    private String caCertificatePath;

    /**
     * Accepts exactly these leaf certificates, as SHA-256 fingerprints. Pinning suits a single
     * self-signed target that has no CA at all.
     */
    private List<String> pinnedCertificateSha256 = new ArrayList<>();
}
