package com.theshuai.common.peeregress;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.util.List;

/** One flow-open attempt seen by the egress node, evaluated before any socket is created. */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PeerEgressRequest {
    private long consumerClientId;
    private String destinationIp;
    private int destinationPort;
    /** {@code tcp} or {@code udp}. */
    private String protocol;

    /** Set when the SPEG1 frame already carried the hop marker; egress chaining is not supported. */
    private boolean hop;

    private int activeFlowsForConsumer;
    private int activeFlowsTotal;

    /**
     * Networks owned by the egress node's own tunnel or virtual interfaces. Forwarding into one of
     * them would loop back into this node's own capture path.
     */
    private List<String> localInterfaceCidrs = List.of();
}
