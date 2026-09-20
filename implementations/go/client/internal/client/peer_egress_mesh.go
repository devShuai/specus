package client

import (
	"encoding/json"
	"errors"
	"fmt"
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
	}, newEgressDialer(mesh.egressTunnelName))
	mesh.egress = runtime
	mesh.egressQueue = queue
	mesh.egressDone = done
	mesh.mu.Unlock()

	go mesh.egressSendLoop(queue, done)
	go mesh.egressTickLoop(runtime, done)
	return runtime
}

// egressTunnelName is the interface whose routes an egress socket must not follow: this node's own
// TUN, or "" when the device is a noop that creates no interface. Called by the dialer with no mesh
// lock held.
func (mesh *peerMeshClient) egressTunnelName() string {
	mesh.mu.Lock()
	device := mesh.device
	mesh.mu.Unlock()
	if device == nil {
		return ""
	}
	if _, noop := device.(*noopPeerVirtualDevice); noop {
		return ""
	}
	return device.Name()
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

// Keeping the routes true while the process runs.
//
// The rules are fixed for the life of the process, but what they need installed is not. A bypass
// exists for an address a rule covers, and those addresses move: peers connect and drop, the relay
// is reassigned, the control connection is re-established. So the plan is recomputed on the mesh's
// own tick -- after the virtual device is up, then every few seconds -- and applied only when it
// changed, or to retry an apply that left something undone. Everything below runs under
// egressPlanMu, which serialises the installer, and never under the mesh lock, because resolving a
// hostname and running a route command are both things nothing else should wait on.

// reconcileEgressRoutes recomputes the consumer's routes and applies them if that is due. Called
// with no mesh lock held.
func (mesh *peerMeshClient) reconcileEgressRoutes() {
	mesh.reconcileEgressRoutesAt(time.Now())
}

func (mesh *peerMeshClient) reconcileEgressRoutesAt(now time.Time) {
	mesh.egressPlanMu.Lock()
	defer mesh.egressPlanMu.Unlock()

	rules := mesh.config.PeerEgressRules
	mesh.mu.Lock()
	runtime := mesh.runtime
	device := mesh.device
	mesh.mu.Unlock()
	meshCIDR := strings.TrimSpace(runtime.PeerMesh.CIDR)
	if meshCIDR == "" {
		meshCIDR = egressDefaultMeshCIDR
	}

	// The consumer exists only when there are rules for it to apply. Building it for an empty
	// set would start the threads that carry its work and report a consumer with nothing to do.
	if len(rules) > 0 {
		mesh.configureEgressConsumer(rules, meshCIDR, runtime.PeerMesh.VirtualIP, now)
	}

	// Without a device there is nothing to route into. A rule's route pointed at an interface
	// that is not there is a black hole rather than the local fallback the user would get with
	// no route at all, so the plan is empty until the device is up, and empties again if it goes.
	var desired []egressRoute
	if egressDeviceReady(device) {
		mesh.egressDeviceWaitLogged = false
		bypass := mesh.egressBypassAddresses(now)
		var refused []egressRuleSetError
		desired, refused = planEgressRoutes(rules, bypass, meshCIDR)
		mesh.logEgressRefusals(refused)
	} else if len(rules) > 0 && !mesh.egressDeviceWaitLogged {
		mesh.egressDeviceWaitLogged = true
		mesh.logger.Printf("[peer-egress-consumer] routes not installed: virtual device is %s",
			egressDeviceStatus(device))
	}

	installer := mesh.ensureEgressRouteInstaller()
	if installer == nil {
		return
	}
	if !egressRouteReconcileDue(mesh.egressPlan, desired, now) {
		// The common tick: the plan has nothing to do, so the table is checked against it.
		if egressDeviceReady(device) {
			mesh.repairEgressDrift(installer, now)
		}
		return
	}
	result := installer.apply(desired)
	mesh.egressPlan = &egressRoutePlanAttempt{
		At: now, Desired: desired, Troubled: len(result.Conflicts) > 0 || result.Err != nil,
	}
	mesh.egressRepairAt, mesh.egressRepairTroubled = time.Time{}, false

	// Remembered before it is logged. A conflict is the one part of this outcome nothing can
	// recompute -- the answer came from the platform's routing table at this moment -- and
	// writing it only to the log is what left an operator with no way to see that a rule they
	// wrote is not in force.
	outcome := egressApplyOutcome{
		At:         now,
		Conflicts:  append([]egressRouteConflict(nil), result.Conflicts...),
		RolledBack: result.RolledBack,
		Applied:    true,
	}
	if result.Err != nil {
		outcome.Err = result.Err.Error()
	}
	mesh.mu.Lock()
	mesh.egressApplied = outcome
	mesh.mu.Unlock()

	// Logged when they change, not on every retry. A conflict is retried every minute for as
	// long as the other route is there, and repeating the same line each time would bury the
	// one that says it went away.
	conflicts := make([]string, 0, len(result.Conflicts))
	for _, conflict := range result.Conflicts {
		conflicts = append(conflicts, conflict.Route.CIDR+"="+conflict.Existing)
	}
	if joined := strings.Join(conflicts, ";"); joined != mesh.egressConflictsLogged {
		mesh.egressConflictsLogged = joined
		for _, conflict := range result.Conflicts {
			// Not preempted and not compared by metric. The operator is told which of their
			// own routes is in the way, so they can decide rather than discover it later.
			mesh.logger.Printf("[peer-egress-consumer] route %s not installed, already present: %s",
				conflict.Route.CIDR, conflict.Existing)
		}
	}
	if outcome.Err != mesh.egressErrorLogged {
		mesh.egressErrorLogged = outcome.Err
		if result.Err != nil {
			mesh.logger.Printf("[peer-egress-consumer] route install failed: %v rolledBack=%v",
				result.Err, result.RolledBack)
		}
	}
	if len(result.Added) > 0 || len(result.Removed) > 0 {
		mesh.logger.Printf("[peer-egress-consumer] routes added=%d removed=%d",
			len(result.Added), len(result.Removed))
	}
}

// repairEgressDrift puts back what the routing table lost since the plan was applied: a route
// dropped with its interface, a bypass still naming a gateway the machine left behind. Called
// under egressPlanMu on the ticks the plan itself has nothing to do.
func (mesh *peerMeshClient) repairEgressDrift(installer *egressRouteInstaller, now time.Time) {
	if mesh.egressRepairTroubled && now.Sub(mesh.egressRepairAt) < egressRouteRetryInterval {
		return
	}
	result := installer.repair()
	if result.TableErr != nil {
		// Said once per failure. Without the table nothing can be compared, and a machine whose
		// `ip` is missing would otherwise say so every five seconds.
		if text := result.TableErr.Error(); text != mesh.egressTableErrorLogged {
			mesh.egressTableErrorLogged = text
			mesh.logger.Printf("[peer-egress-consumer] cannot read the routing table to check the routes: %v",
				result.TableErr)
		}
		mesh.egressRepairAt, mesh.egressRepairTroubled = now, true
		return
	}
	mesh.egressTableErrorLogged = ""
	mesh.egressRepairAt, mesh.egressRepairTroubled = now, result.Err != nil

	for _, drift := range result.Repaired {
		// Each one is a real event -- the machine changed networks -- so each one is said.
		mesh.logger.Printf("[peer-egress-consumer] route %s put back, it was %s", drift.Route.CIDR, drift.Reason)
	}
	if len(result.Lost) > 0 {
		// Reported the way an apply reports a conflict, and remembered the same way, so the
		// status lists the prefix as not installed with what holds it. The plan still wants it:
		// marked troubled, it asks again after the interval and reports the conflict if it is
		// still there.
		mesh.mu.Lock()
		outcome := mesh.egressApplied
		outcome.At = now
		outcome.Conflicts = mergeEgressConflicts(outcome.Conflicts, result.Lost)
		mesh.egressApplied = outcome
		mesh.mu.Unlock()
		if mesh.egressPlan != nil {
			mesh.egressPlan.At, mesh.egressPlan.Troubled = now, true
		}
		for _, lost := range result.Lost {
			mesh.logger.Printf("[peer-egress-consumer] route %s lost to another route, not taken back: %s",
				lost.Route.CIDR, lost.Existing)
		}
	}
	if result.Err != nil {
		if text := result.Err.Error(); text != mesh.egressErrorLogged {
			mesh.egressErrorLogged = text
			mesh.logger.Printf("[peer-egress-consumer] route repair failed: %v", result.Err)
		}
	}
}

// mergeEgressConflicts adds conflicts to a list, replacing an entry for the same prefix.
func mergeEgressConflicts(existing, more []egressRouteConflict) []egressRouteConflict {
	merged := append([]egressRouteConflict(nil), existing...)
	for _, conflict := range more {
		replaced := false
		for index := range merged {
			if merged[index].Route.CIDR == conflict.Route.CIDR {
				merged[index] = conflict
				replaced = true
				break
			}
		}
		if !replaced {
			merged = append(merged, conflict)
		}
	}
	return merged
}

// configureEgressConsumer gives the consumer its rules, once per distinct configuration.
//
// Reconfiguring purges the flows the new rules no longer cover, and with the same rules that is
// every flow being re-examined for nothing on every tick; with a change of virtual IP it is what
// has to happen.
func (mesh *peerMeshClient) configureEgressConsumer(rules []egressRule, meshCIDR, virtualIP string, now time.Time) {
	key := fmt.Sprintf("%s|%s|%+v", meshCIDR, strings.TrimSpace(virtualIP), rules)
	if key == mesh.egressConsumerKey {
		return
	}
	mesh.egressConsumerKey = key
	consumer := mesh.ensureEgressConsumer()
	mesh.deliverEgressPurges(consumer.configure(rules, meshCIDR, virtualIP, now))
}

// logEgressRefusals reports the rules that were thrown out, once per distinct set. The rules do not
// change while the process runs, so in practice this is once.
func (mesh *peerMeshClient) logEgressRefusals(refused []egressRuleSetError) {
	keys := make([]string, 0, len(refused))
	for _, entry := range refused {
		keys = append(keys, strconv.Itoa(entry.Index)+":"+entry.Code)
	}
	if joined := strings.Join(keys, ","); joined != mesh.egressRefusalsLogged {
		mesh.egressRefusalsLogged = joined
		for _, entry := range refused {
			mesh.logger.Printf("[peer-egress-consumer] rule %d (%s) refused: %s", entry.Index, entry.Match, entry.Code)
		}
	}
}

// egressDeviceReady says whether there is an interface to route into: a real device that started.
// A noop device creates no interface, and one that failed has none either.
func egressDeviceReady(device peerVirtualDevice) bool {
	if device == nil {
		return false
	}
	if _, noop := device.(*noopPeerVirtualDevice); noop {
		return false
	}
	return strings.EqualFold(device.Status(), "UP")
}

func egressDeviceStatus(device peerVirtualDevice) string {
	if device == nil {
		return "absent"
	}
	return device.Status()
}

// ensureEgressRouteInstaller builds the installer and takes back whatever a previous run left in
// the journal.
//
// Taken back rather than adopted. A journal outlives the process that wrote it, and that process's
// interface is gone with it, so the routes it describes are either gone too or pointing at nothing;
// what is still wanted is put back by the apply that follows. This is also what clears a crash's
// leftovers when the rules have since been removed: there is no rule set so small that the journal
// is not read.
func (mesh *peerMeshClient) ensureEgressRouteInstaller() *egressRouteInstaller {
	mesh.mu.Lock()
	if mesh.egressRoutes != nil {
		installer := mesh.egressRoutes
		mesh.mu.Unlock()
		return installer
	}
	device := mesh.device
	commander := mesh.egressCommander
	mesh.mu.Unlock()

	tun := strings.TrimSpace(mesh.config.PeerMeshTunName)
	if device != nil {
		tun = device.Name()
	}
	journal := mesh.egressJournalPath
	if journal == "" {
		journal = egressRouteJournalPath()
	}
	if commander == nil {
		commander = newEgressRouteCommanderForPlatform(tun)
	}
	installer := newEgressRouteInstaller(commander, journal)
	if err := installer.load(); err != nil {
		mesh.logger.Printf("[peer-egress-consumer] route journal unusable, starting empty: %v", err)
	}
	if leftover := installer.withdrawAll(); len(leftover) > 0 {
		mesh.logger.Printf("[peer-egress-consumer] took back %d routes left by a previous run", len(leftover))
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
// connection, the server the client logs in to, STUN and TURN, the relay, and every peer's own
// endpoint. Without them a rule broad enough to cover one would route the tunnel's transport into
// the tunnel. Called under egressPlanMu with no mesh lock held; hostnames are resolved here.
func (mesh *peerMeshClient) egressBypassAddresses(now time.Time) []string {
	mesh.mu.Lock()
	runtime := mesh.runtime
	conn := mesh.conn
	relay := mesh.relay
	peers := make([]string, 0, len(mesh.sessions))
	for _, session := range mesh.sessions {
		if session.RemoteEndpoint != nil && session.RemoteEndpoint.IP != nil {
			peers = append(peers, session.RemoteEndpoint.IP.String())
		}
	}
	mesh.mu.Unlock()

	hosts := make([]string, 0, 8)
	if conn != nil && conn.RemoteAddr() != nil {
		hosts = append(hosts, conn.RemoteAddr().String())
	}
	hosts = append(hosts, mesh.config.ServerBaseURL, runtime.PeerMesh.StunHost, runtime.PeerMesh.TurnHost)
	hosts = append(hosts, runtime.PeerMesh.PublicStunServers...)
	if relay != nil {
		hosts = append(hosts, relay.Address)
	}
	if mesh.egressBypass == nil {
		mesh.egressBypass = newEgressBypassResolver(nil)
	}
	resolved, failed := mesh.egressBypass.resolve(hosts, now)
	if joined := strings.Join(failed, ","); joined != mesh.egressBypassFailedLogged {
		mesh.egressBypassFailedLogged = joined
		for _, host := range failed {
			// Said once per failure, not per tick: the cache retries after its TTL and the next
			// line is the one that says it resolved.
			mesh.logger.Printf("[peer-egress-consumer] bypass host %s did not resolve; a rule covering it would capture it", host)
		}
	}
	return append(resolved, peers...)
}

// withdrawEgressRoutes takes back every route this feature installed and forgets the plan, so the
// next reconcile starts from nothing. Called with no mesh lock held.
func (mesh *peerMeshClient) withdrawEgressRoutes() {
	mesh.egressPlanMu.Lock()
	defer mesh.egressPlanMu.Unlock()
	mesh.mu.Lock()
	installer := mesh.egressRoutes
	mesh.egressRoutes = nil
	mesh.mu.Unlock()
	mesh.egressPlan = nil
	mesh.egressRepairAt, mesh.egressRepairTroubled = time.Time{}, false
	// What was logged belongs to the routes that are going; the next start says its own.
	mesh.egressConflictsLogged, mesh.egressErrorLogged, mesh.egressDeviceWaitLogged = "", "", false
	mesh.egressTableErrorLogged = ""
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
