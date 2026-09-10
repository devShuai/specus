package client

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
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

var (
	errNoEgressSession = errors.New("no Peer Mesh session with the egress")
	errNoEgressDevice  = errors.New("no virtual device to write to")
)

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
	runtime, consumer := mesh.egress, mesh.egressConsumer
	mesh.mu.Unlock()
	// The consumer role is offered the frame first. A node can be both, and both roles receive
	// type=1 frames; the consumer claims only what is addressed to its own virtual IP, so trying
	// it first costs nothing and keeps a reply from being judged as an egress request.
	if consumer != nil && consumer.handleInbound(frame.Payload, session.PeerID, time.Now()) {
		return true
	}
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

// ensureEgressConsumer lazily builds the consumer side. Called with no mesh lock held.
func (mesh *peerMeshClient) ensureEgressConsumer() *egressConsumer {
	mesh.mu.Lock()
	if mesh.egressConsumer != nil {
		consumer := mesh.egressConsumer
		mesh.mu.Unlock()
		return consumer
	}
	consumer := newEgressConsumer(mesh.logger,
		func(egress int64, frame []byte) error { return mesh.sendEgressFrameToPeer(egress, frame) },
		func(packet []byte) error { return mesh.writeEgressPacketToDevice(packet) })
	mesh.egressConsumer = consumer
	mesh.mu.Unlock()
	return consumer
}

// sendEgressFrameToPeer carries one frame to the egress peer.
//
// Synchronous, unlike the egress role's own sender. It is called from the TUN read path with no
// plane lock held, and the caller needs to know whether the packet left: a send that failed means
// the rule's destination has to be blocked, not allowed out locally.
func (mesh *peerMeshClient) sendEgressFrameToPeer(egress int64, frame []byte) error {
	mesh.mu.Lock()
	session := mesh.sessions[egress]
	mesh.mu.Unlock()
	if session == nil {
		return errNoEgressSession
	}
	return mesh.sendEncryptedPayload(session, frame)
}

func (mesh *peerMeshClient) writeEgressPacketToDevice(packet []byte) error {
	mesh.mu.Lock()
	device := mesh.device
	mesh.mu.Unlock()
	if device == nil {
		return errNoEgressDevice
	}
	return device.WritePacket(packet)
}

// handleEgressOutbound offers a packet read from the TUN to the consumer rules, and reports whether
// the consumer claimed it.
//
// Sits at the top of the TUN read path, because a destination a rule claims is not a mesh peer and
// the existing path would drop it as such: silently, and as though nothing had been configured.
func (mesh *peerMeshClient) handleEgressOutbound(packet []byte) bool {
	mesh.mu.Lock()
	consumer := mesh.egressConsumer
	mesh.mu.Unlock()
	if consumer == nil {
		return false
	}
	outcome := consumer.handleOutbound(packet, time.Now())
	if outcome == egressOutcomeNotMine {
		return false
	}
	if outcome != egressOutcomeForwarded && mesh.logger != nil {
		// Logged without the destination: a per-destination record of what a user was blocked
		// from reaching is their own browsing history.
		mesh.logger.Printf("[peer-egress-consumer] packet not forwarded: %s", outcome)
	}
	return true
}

// syncEgressAvailability tells the consumer which egresses can take a flow, and delivers the purges
// a peer going offline produces. Called with no mesh lock held.
func (mesh *peerMeshClient) syncEgressAvailability(online map[int64]bool) {
	mesh.mu.Lock()
	consumer := mesh.egressConsumer
	mesh.mu.Unlock()
	if consumer == nil {
		return
	}
	for egress, up := range online {
		mesh.deliverEgressPurges(consumer.setEgressOnline(egress, up, time.Now()))
	}
}

// deliverEgressPurges sends one flow-purge per affected egress.
//
// Best effort by design. The message is what closes the far side promptly, but the egress reclaims
// the flow on its own idle timer regardless, so a purge that cannot be delivered delays cleanup
// rather than losing it.
func (mesh *peerMeshClient) deliverEgressPurges(purge map[int64][]string) {
	for egress, destinations := range purge {
		if len(destinations) == 0 {
			continue
		}
		body, err := encodePeerEgressControl(peerEgressControl{
			Type: peerEgressControlFlowPurge, Destinations: destinations, Code: egressCodeDisabled,
		})
		if err != nil {
			continue
		}
		_ = mesh.sendEgressFrameToPeer(egress, encodePeerEgressFrame(peerEgressTypeControl, false, body))
	}
}

// applyEgressRules installs the consumer's own rules and the routes they need.
//
// Refused rules are reported and skipped; the rest take effect. A rule set is rarely wrong all at
// once, and refusing to apply any of it would leave a user with one typo sending everything out
// locally, which is the failure this feature exists to prevent.
func (mesh *peerMeshClient) applyEgressRules(rules []egressRule, runtime RuntimeConfig) {
	consumer := mesh.ensureEgressConsumer()
	meshCIDR := strings.TrimSpace(runtime.PeerMesh.CIDR)
	if meshCIDR == "" {
		meshCIDR = egressDefaultMeshCIDR
	}
	mesh.deliverEgressPurges(consumer.configure(rules, meshCIDR, runtime.PeerMesh.VirtualIP, time.Now()))

	desired, refused := planEgressRoutes(rules, mesh.egressBypassAddresses(), meshCIDR)
	for _, entry := range refused {
		mesh.logger.Printf("[peer-egress-consumer] rule %d (%s) refused: %s", entry.Index, entry.Match, entry.Code)
	}

	installer := mesh.ensureEgressRouteInstaller()
	if installer == nil {
		return
	}
	result := installer.apply(desired)
	for _, conflict := range result.Conflicts {
		// Not preempted and not compared by metric. The operator is told which of their own
		// routes is in the way, so they can decide rather than discover it later.
		mesh.logger.Printf("[peer-egress-consumer] route %s not installed, already present: %s",
			conflict.Route.CIDR, conflict.Existing)
	}
	if result.Err != nil {
		mesh.logger.Printf("[peer-egress-consumer] route install failed: %v rolledBack=%v",
			result.Err, result.RolledBack)
	}
	if len(result.Added) > 0 || len(result.Removed) > 0 {
		mesh.logger.Printf("[peer-egress-consumer] routes added=%d removed=%d",
			len(result.Added), len(result.Removed))
	}
}

// ensureEgressRouteInstaller builds the installer and adopts any journal a previous run left.
//
// Adoption comes first so a process that was killed has its routes taken back rather than left for
// a user to find and wonder about.
func (mesh *peerMeshClient) ensureEgressRouteInstaller() *egressRouteInstaller {
	mesh.mu.Lock()
	if mesh.egressRoutes != nil {
		installer := mesh.egressRoutes
		mesh.mu.Unlock()
		return installer
	}
	device := mesh.device
	mesh.mu.Unlock()

	tun := ""
	if device != nil {
		tun = device.Name()
	}
	journal := mesh.egressJournalPath
	if journal == "" {
		journal = egressRouteJournalPath()
	}
	installer := newEgressRouteInstaller(newEgressRouteCommanderForPlatform(tun), journal)
	if err := installer.load(); err != nil {
		mesh.logger.Printf("[peer-egress-consumer] route journal unusable, starting empty: %v", err)
	}

	mesh.mu.Lock()
	mesh.egressRoutes = installer
	mesh.mu.Unlock()
	return installer
}

func egressRouteJournalPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".specus", "egress-routes.json")
}

// egressBypassAddresses are the addresses that must keep reaching the physical network: the control
// connection, STUN and TURN, and every peer's own endpoint. Without them a rule broad enough to
// cover one would route the tunnel's transport into the tunnel.
func (mesh *peerMeshClient) egressBypassAddresses() []string {
	bypass := make([]string, 0, 8)
	for _, cidr := range mesh.deploymentDenyCIDRs() {
		bypass = append(bypass, strings.TrimSuffix(cidr, "/32"))
	}
	mesh.mu.Lock()
	for _, session := range mesh.sessions {
		if session.RemoteEndpoint != nil && session.RemoteEndpoint.IP != nil {
			bypass = append(bypass, session.RemoteEndpoint.IP.String())
		}
	}
	mesh.mu.Unlock()
	return bypass
}

// withdrawEgressRoutes takes back every route this feature installed. Called with no mesh lock held.
func (mesh *peerMeshClient) withdrawEgressRoutes() {
	mesh.mu.Lock()
	installer := mesh.egressRoutes
	mesh.egressRoutes = nil
	mesh.mu.Unlock()
	if installer != nil {
		installer.withdrawAll()
	}
}

// applyEgressControl installs a pushed egress-config.
//
// The revision guard is the spec's: a snapshot at or below the last accepted one is ignored, so a
// reordered or replayed push cannot walk the policy backwards. Called with no mesh lock held.
func (mesh *peerMeshClient) applyEgressControl(payload string) {
	policy, revision, ok := decodeEgressConfig([]byte(payload))
	if !ok {
		mesh.logger.Printf("decode egress-config failed")
		return
	}
	runtime := mesh.ensureEgress()
	if !runtime.acceptRevision(revision) {
		return
	}
	context := newEgressContext()
	context.DeploymentDenyCIDRs = mesh.deploymentDenyCIDRs()
	runtime.setLocalInterfaceCIDRs(localInterfaceCIDRs())
	runtime.applyPolicy(policy, context, time.Now())
	mesh.logger.Printf("[peer-egress] policy applied enabled=%v revision=%d rules=%d",
		policy.Enabled, revision, len(policy.DestinationRules))
}

// decodeEgressConfig reads an egress-config push into the policy a client enforces.
//
// Refuses anything that is not this message: a type naming something else, a payload that is not an
// object, or text that is not JSON. Reading a catalogue as a policy would install one.
//
// The revision guard is deliberately not here. It is the runtime's state, and this function has to
// give the same answer for the same message every time it is called.
//
// Shared vector: protocol/test-vectors/peer-egress-control-v1.json.
func decodeEgressConfig(payload []byte) (egressPolicy, int64, bool) {
	var message egressConfigMessage
	if err := json.Unmarshal(payload, &message); err != nil {
		return egressPolicy{}, 0, false
	}
	if message.Type != peerControlTypeEgressConfig {
		return egressPolicy{}, 0, false
	}
	return egressPolicy{
		Enabled: message.Enabled,
		// Trimmed and uppercased before it is stored. The judgment layer compares this for
		// equality against a scope it computes itself, so a push saying "public" would be
		// refused by an implementation that kept the raw string.
		Scope:                    strings.ToUpper(strings.TrimSpace(message.Scope)),
		AllowedConsumerClientIDs: message.AllowedConsumerClientIDs,
		DestinationRules:         message.DestinationRules,
		Limits:                   message.Limits,
	}, message.Revision, true
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

	relayAddress := ""
	if relay != nil {
		relayAddress = relay.Address
	}
	return egressDeploymentDenyCIDRs(baseURL, runtime.PeerMesh.StunHost,
		runtime.PeerMesh.TurnHost, relayAddress)
}

// egressDeploymentDenyCIDRs turns this deployment's endpoints into the /32 prefixes the forced-deny
// list needs. Pure, so the three clients can be held to the same derivation.
//
// Shared vector: protocol/test-vectors/peer-egress-control-v1.json.
func egressDeploymentDenyCIDRs(baseURL, stunHost, turnHost, relayAddress string) []string {
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
	appendHost(stunHost)
	appendHost(turnHost)
	appendHost(relayAddress)
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
