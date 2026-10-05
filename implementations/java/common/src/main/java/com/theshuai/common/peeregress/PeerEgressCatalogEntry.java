package com.theshuai.common.peeregress;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.util.List;

/**
 * One entry of {@code egress-catalog}, sent by the server to a consumer device.
 *
 * <p>The catalogue deliberately omits the egress node's destination allowlist. A consumer does not
 * need it to route, and shipping it would hand every peer a map of that node's reachable network.
 * A consumer that configures a destination the egress does not permit learns so when the flow is
 * refused, through a {@code flow-reject} control message carrying the reason.
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PeerEgressCatalogEntry {
    private Long clientId;
    private String clientName;
    private boolean online;
    private String scope;
    private List<String> protocols = List.of();
    private boolean domainTargetCapable;
    private boolean ipv6TargetCapable;
    /**
     * The {@code clientEgressCapabilities.version} the egress's current online session announced;
     * {@code 0} when it is offline or announced none. A primitive so the server always writes it,
     * {@code 0} included: a consumer reads an absent field as an old server and keeps routing, but
     * reads {@code 0} as an egress that cannot take a flow. Decoding through this class cannot tell
     * those two apart, so a consumer must read the raw field instead.
     */
    private int egressVersion;
}
