package client

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Wiring the egress data plane into Peer Mesh.
//
// Three joins. SPEG1 frames are demultiplexed out of the decrypted payload stream, the pushed
// egress-config becomes the policy the plane enforces, and a closing session revokes that peer's
// flows.
//
// Lock ordering is the constraint that shapes this file. The mesh takes its own mutex and the
// egress plane takes its own, and the plane holds its mutex while emitting frames. So frames are
// queued rather than sent inline: sending inline would mean the plane's mutex is held while the
// mesh's is taken, and the mesh already takes its mutex on paths that reach into the plane, which
// is a cycle. Everything below either queues or is called with no mesh lock held.

const (
	peerControlTypeEgressConfig = "egress-config"

	// peerEgressSendQueueDepth bounds frames waiting to be encrypted and sent. A full queue drops,
	// which is safe here in a way it would not be elsewhere: TCP retransmits what is lost and UDP
	// is lossy by contract, whereas blocking would stall every flow on the node.
	peerEgressSendQueueDepth = 512

	// peerEgressTickInterval drives retransmission and idle expiry. Well under the minimum RTO, so
	// a retransmit is never delayed by more than a fraction of the interval it waited for.
	peerEgressTickInterval = 100 * time.Millisecond
)

type peerEgressOutbound struct {
	consumer int64
	frame    []byte
}

// egressConfigMessage is the server push. Decoded from the raw control payload rather than from
// peerControlMessage, so the mesh's own signalling struct does not grow fields only the egress
// reads.
type egressConfigMessage struct {
	Type                     string                  `json:"type"`
	Enabled                  bool                    `json:"enabled"`
	Revision                 int64                   `json:"revision"`
	Scope                    string                  `json:"scope"`
	AllowedConsumerClientIDs []int64                 `json:"allowedConsumerClientIds"`
	DestinationRules         []egressDestinationRule `json:"destinationRules"`
	Limits                   egressLimits            `json:"limits"`
}

// ensureEgress lazily builds the plane and the goroutines that carry its frames and its clock.
// Called with no mesh lock held.
func (mesh *peerMeshClient) ensureEgress() *egressRuntime {
	mesh.mu.Lock()
	if mesh.egress != nil {
		runtime := mesh.egress
		mesh.mu.Unlock()
		return runtime
	}
	queue := make(chan peerEgressOutbound, peerEgressSendQueueDepth)
	done := make(chan struct{})
	runtime := newEgressRuntime(mesh.logger, func(consumer int64, frame []byte) error {
		select {
		case queue <- peerEgressOutbound{consumer: consumer, frame: frame}:
		default:
		}
		return nil
	}, nil)
	mesh.egress = runtime
	mesh.egressQueue = queue
	mesh.egressDone = done
	mesh.mu.Unlock()

	go mesh.egressSendLoop(queue, done)
	go mesh.egressTickLoop(runtime, done)
	return runtime
}

// egressSendLoop encrypts and sends queued frames. It is the only place the egress plane's output
// meets the mesh lock, and it never holds the plane's lock while doing so.
func (mesh *peerMeshClient) egressSendLoop(queue chan peerEgressOutbound, done chan struct{}) {
	for {
		var outbound peerEgressOutbound
		select {
		case <-done:
			return
		case outbound = <-queue:
		}
		mesh.mu.Lock()
		session := mesh.sessions[outbound.consumer]
		mesh.mu.Unlock()
		if session == nil {
			continue
		}
		if err := mesh.sendEncryptedPayload(session, outbound.frame); err != nil {
			mesh.logger.Printf("Peer Mesh egress send failed: peer=%d err=%v", outbound.consumer, err)
		}
	}
}

func (mesh *peerMeshClient) egressTickLoop(runtime *egressRuntime, done chan struct{}) {
	ticker := time.NewTicker(peerEgressTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			runtime.onTick(time.Now())
		}
	}
}

// handlePeerEgressFrame demultiplexes SPEG1 out of the decrypted payload stream.
//
// It sits after the application-message check and before the bare IPv4 endpoint check, because a
// frame that carries the SPEG1 magic is addressed to the egress path and must be refused with its
// own code rather than dropped as an unrecognised mesh packet. Called with no mesh lock held.
func (mesh *peerMeshClient) handlePeerEgressFrame(frame *peerDataFrame, session *peerMeshSession) bool {
	if !looksLikePeerEgressFrame(frame.Payload) {
		return false
	}
	mesh.mu.Lock()
	runtime := mesh.egress
	mesh.mu.Unlock()
	if runtime == nil {
		// Nothing has enabled the egress on this node, so there is no policy to judge against,
		// and building a plane on first contact would let any peer turn an unconfigured device
		// into an egress by sending it a frame. The frame is dropped rather than answered with a
		// refusal: a reply would need the rate limiting only the plane provides, and a peer that
		// never got an egress in the first place learns from its own timeout.
		return true
	}
	// A returning segment travels inside an SPEG1 frame, so the frame header has to come out of
	// the budget the stack sizes segments against. sendEncryptedPayload cannot do this for us: its
	// clamp only recognises a bare IPv4 packet, and an egress frame is not one.
	if session.PathMTU != nil {
		runtime.setPathMTU(session.PathMTU.effectiveMTU(mesh.config.PeerMeshMTU) - peerEgressFrameHeaderLen)
	}
	return runtime.handleFrame(session.PeerID, frame.Payload, time.Now())
}

// applyEgressControl installs a pushed egress-config.
//
// The revision guard is the spec's: a snapshot at or below the last accepted one is ignored, so a
// reordered or replayed push cannot walk the policy backwards. Called with no mesh lock held.
func (mesh *peerMeshClient) applyEgressControl(payload string) {
	var message egressConfigMessage
	if err := json.Unmarshal([]byte(payload), &message); err != nil {
		mesh.logger.Printf("decode egress-config failed: %v", err)
		return
	}
	runtime := mesh.ensureEgress()
	if !runtime.acceptRevision(message.Revision) {
		return
	}
	context := newEgressContext()
	context.DeploymentDenyCIDRs = mesh.deploymentDenyCIDRs()
	runtime.setLocalInterfaceCIDRs(localInterfaceCIDRs())
	runtime.applyPolicy(egressPolicy{
		Enabled:                  message.Enabled,
		Scope:                    strings.ToUpper(strings.TrimSpace(message.Scope)),
		AllowedConsumerClientIDs: message.AllowedConsumerClientIDs,
		DestinationRules:         message.DestinationRules,
		Limits:                   message.Limits,
	}, context, time.Now())
	mesh.logger.Printf("[peer-egress] policy applied enabled=%v revision=%d rules=%d",
		message.Enabled, message.Revision, len(message.DestinationRules))
}

// revokeEgressConsumer closes a peer's flows when its session ends. The plane cannot poll for this:
// asking the mesh whether a peer is still authorised would mean taking the mesh lock from under the
// plane's own, so revocation is delivered as an event instead. Called with no mesh lock held.
func (mesh *peerMeshClient) revokeEgressConsumer(peerID int64) {
	mesh.mu.Lock()
	runtime := mesh.egress
	mesh.mu.Unlock()
	if runtime != nil && peerID > 0 {
		runtime.revokeConsumer(peerID, time.Now())
	}
}

// shutdownEgress stops forwarding. Called with no mesh lock held, deliberately: the plane closes
// sockets under its own lock and taking the mesh lock around that would invert the order the send
// loop relies on.
func (mesh *peerMeshClient) shutdownEgress() {
	mesh.mu.Lock()
	runtime, done := mesh.egress, mesh.egressDone
	mesh.egress, mesh.egressQueue, mesh.egressDone = nil, nil, nil
	mesh.mu.Unlock()
	if runtime != nil {
		runtime.shutdown(time.Now())
	}
	// The loops are stopped by their own signal, never by closing the frame queue. A socket
	// goroutine can still be between releasing the plane's lock and queuing its last frame, and a
	// closed queue would turn that into a panic instead of a dropped frame.
	if done != nil {
		close(done)
	}
}

// deploymentDenyCIDRs are this deployment's control, STUN and TURN endpoints. Forwarding a
// consumer's traffic to them would let a peer reach the infrastructure through the egress it is
// only supposed to reach the internet through.
func (mesh *peerMeshClient) deploymentDenyCIDRs() []string {
	mesh.mu.Lock()
	runtime := mesh.runtime
	baseURL := mesh.config.ServerBaseURL
	relay := mesh.relay
	mesh.mu.Unlock()

	denied := make([]string, 0, 4)
	appendHost := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
		// Only literal addresses are added. A hostname would have to be resolved here, and a
		// resolution taken at policy time can differ from the one the connect uses, which would
		// make the block look enforced when it is not.
		if _, ok := parseEgressAddress(host); ok {
			denied = append(denied, host+"/32")
		}
	}
	if parsed, err := url.Parse(strings.TrimSpace(baseURL)); err == nil {
		appendHost(parsed.Host)
	}
	appendHost(runtime.PeerMesh.StunHost)
	appendHost(runtime.PeerMesh.TurnHost)
	if relay != nil {
		appendHost(relay.Address)
	}
	return denied
}

// localInterfaceCIDRs enumerates the networks this host itself owns.
//
// Forwarding into one would loop back into this node's own capture path, or reach a service the
// consumer was never authorised to see. Enumerated at policy time rather than cached, because an
// interface can appear after start-up and a stale list is a hole rather than an inconvenience.
func localInterfaceCIDRs() []string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	networks := make([]string, 0, len(addresses))
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok || network.IP.To4() == nil {
			continue
		}
		prefix, bits := network.Mask.Size()
		if bits != 32 {
			continue
		}
		masked := network.IP.To4().Mask(network.Mask)
		networks = append(networks, masked.String()+"/"+strconv.Itoa(prefix))
	}
	return networks
}
