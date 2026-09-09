package com.theshuai.common.peeregress;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

/**
 * One consumer-side split-routing rule.
 *
 * <p>Rules match on destination address only. The consumer steers traffic by installing routes and
 * a route selects on destination address alone, so a port-scoped rule could neither be expressed as
 * a route nor cleanly returned to the local stack once the packet had already been captured. Port
 * and protocol limits live on the egress policy and are enforced when the flow is opened.
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PeerEgressRule {
    public static final String ACTION_EGRESS = "egress";
    public static final String ACTION_DIRECT = "direct";
    public static final String ACTION_BLOCK = "block";

    /** IPv4 address or CIDR. Domains and IPv6 are rejected in this version. */
    private String match;

    private String action;

    /** Required when {@link #action} is {@link #ACTION_EGRESS}. */
    private Long egressClientId;

    /**
     * Present only so that a configuration carrying it can be rejected with a specific code
     * instead of silently ignoring the field.
     */
    private Integer port;
}
