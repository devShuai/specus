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
	errEgressQueueFull = errors.New("egress send queue is full")
)

const (
	peerControlTypeEgressConfig = "egress-config"

	// Bounds frames waiting for encryption. TCP keeps rejected payload/FIN in its bounded
	// state until a writable notification; UDP and untracked control frames remain best effort.
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
	// Raw, so that decodeEgressDomainRules decides what an entry it cannot read means rather than
	// the JSON library refusing the whole push over it.
	DomainRules json.RawMessage `json:"domainRules"`
	Limits      egressLimits    `json:"limits"`
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
			return errEgressQueueFull
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
		runtime := mesh.egress
		mesh.mu.Unlock()
		if runtime != nil {
			runtime.sendReady(time.Now())
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
	// A catalogue that arrived before the consumer was built still says which egresses resolve
	// names; nothing else will repeat it until the server has a reason to.
	if mesh.egressCatalog != nil {
		consumer.capable = mesh.egressCatalog.domainCapable()
	}
	consumer.dnsUpstreams = append([]string(nil), mesh.egressDNSUpstreams...)
	mesh.egressConsumer = consumer
	mesh.mu.Unlock()
	return consumer
}

// setEgressDNSUpstreams gives the DNS responder the resolvers it forwards to, in order. Step five
// supplies them from the system's DNS settings as they were before the takeover; until a caller
// does, the list is empty and every query the responder forwards is answered SERVFAIL. Called with
// no mesh lock held.
func (mesh *peerMeshClient) setEgressDNSUpstreams(upstreams []string) {
	mesh.mu.Lock()
	mesh.egressDNSUpstreams = append([]string(nil), upstreams...)
	consumer := mesh.egressConsumer
	mesh.mu.Unlock()
	if consumer != nil {
		consumer.setDNSUpstreams(upstreams)
	}
}

// applyEgressCatalog reads a pushed egress-catalog and gives the consumer the capabilities it lists.
// A change can close flows: a flow to a name stops the moment its egress is no longer said to
// resolve names. Called with no mesh lock held.
func (mesh *peerMeshClient) applyEgressCatalog(payload string) {
	mesh.mu.Lock()
	if mesh.egressCatalog == nil {
		mesh.egressCatalog = newEgressCatalogReader()
	}
	accepted := mesh.egressCatalog.read([]byte(payload))
	capable := mesh.egressCatalog.domainCapable()
	ids := mesh.egressCatalog.capableIDs()
	consumer := mesh.egressConsumer
	mesh.mu.Unlock()
	if !accepted {
		// A stale revision is ordinary after a reorder and says nothing worth a line; a malformed
		// catalogue is the server's to fix, and the known capabilities stand either way.
		return
	}
	mesh.logger.Printf("[peer-egress-consumer] egress catalogue applied; egresses resolving names: %v", ids)
	if consumer != nil {
		mesh.deliverEgressPurges(consumer.setDomainCapable(capable, time.Now()))
	}
}

// newEgressCatalogSessionLocked resets the catalogue's revision floor for a new control session.
// Called with the mesh lock held.
func (mesh *peerMeshClient) newEgressCatalogSessionLocked() {
	if mesh.egressCatalog != nil {
		mesh.egressCatalog.newSession()
	}
}

// egressPhaseTwoFor evaluates phase two against the mesh network the server gave, and, the first
// time phase two would run with a pool, against the networks this device sits on. Called under
// egressPlanMu with no mesh lock held.
//
// The device check is done once and kept. It answers whether the pool can be routed into the tunnel
// at all, and phase two starting and stopping as interfaces come and go would hand the same names
// out of a pool that is sometimes there; a network change is the system DNS takeover's to handle.
func (mesh *peerMeshClient) egressPhaseTwoFor(meshCIDR string) egressPhaseTwo {
	cidr := effectiveEgressFakeIPCIDR(mesh.config.PeerEgressFakeIPCIDR)
	active, code := evaluateEgressPhaseTwo(mesh.config.PeerEgressEnabled, mesh.config.PeerEgressDNSTakeover, cidr, meshCIDR)
	if active {
		if mesh.egressPoolCheckedFor != cidr {
			networks := mesh.egressLocalNetworks
			if networks == nil {
				networks = localInterfaceCIDRs
			}
			mesh.egressPoolCheckedFor = cidr
			mesh.egressPoolOverlapsLocal = egressFakeIPPoolOverlapsLocal(cidr, networks())
		}
		if mesh.egressPoolOverlapsLocal {
			active, code = false, egressCodeFakeIPPoolInvalid
		}
	}
	phase := egressPhaseTwo{CIDR: cidr, Active: active, Code: code}
	if logged := fmt.Sprintf("%v|%s|%s", phase.Active, phase.CIDR, phase.Code); mesh.config.PeerEgressDNSTakeover &&
		logged != mesh.egressPhaseLogged {
		mesh.egressPhaseLogged = logged
		// Without the pool itself: configuration values stay out of the log, as a rule's match does.
		switch {
		case phase.Active:
			mesh.logger.Printf("[peer-egress-consumer] phase two running")
		case phase.Code != "":
			mesh.logger.Printf("[peer-egress-consumer] phase two not started: %s "+
				"(peerEgressFakeIpCidr must be an IPv4 /8 to /24 clear of the Peer Mesh network and of this device's networks)",
				phase.Code)
		}
	}
	mesh.mu.Lock()
	mesh.egressPhase, mesh.egressPhaseEvaluated = phase, true
	mesh.mu.Unlock()
	return phase
}

// currentEgressPhaseTwo is phase two as the last reconcile found it. Before the first one it is
// evaluated from the configuration alone, which cannot yet say it is running.
func (mesh *peerMeshClient) currentEgressPhaseTwo() egressPhaseTwo {
	mesh.mu.Lock()
	phase, evaluated := mesh.egressPhase, mesh.egressPhaseEvaluated
	meshCIDR := strings.TrimSpace(mesh.runtime.PeerMesh.CIDR)
	mesh.mu.Unlock()
	if evaluated {
		return phase
	}
	if meshCIDR == "" {
		meshCIDR = egressDefaultMeshCIDR
	}
	cidr := effectiveEgressFakeIPCIDR(mesh.config.PeerEgressFakeIPCIDR)
	_, code := evaluateEgressPhaseTwo(mesh.config.PeerEgressEnabled, mesh.config.PeerEgressDNSTakeover, cidr, meshCIDR)
	return egressPhaseTwo{CIDR: cidr, Code: code}
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
	// A DNS query is the responder's business, answered or not, and one line per lookup would be
	// a record of every name this device asked for.
	if outcome != egressOutcomeForwarded && outcome != egressOutcomeDNS && mesh.logger != nil {
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
	for egress, frame := range egressFlowPurgeFrames(purge) {
		_ = mesh.sendEgressFrameToPeer(egress, frame)
	}
}

// egressFlowPurgeFrames encodes one flow-purge frame per egress with anything to purge. A flow to a
// fake address is purged by that address as a /32, which is what the egress keyed the flow on.
func egressFlowPurgeFrames(purge map[int64][]string) map[int64][]byte {
	frames := make(map[int64][]byte, len(purge))
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
		frames[egress] = encodePeerEgressFrame(peerEgressTypeControl, false, body)
	}
	return frames
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

	// With the master switch off nothing is taken over. The plan is then empty, which withdraws
	// whatever a previous run left installed, and the consumer is not built.
	var rules []egressRule
	if mesh.config.PeerEgressEnabled {
		rules = mesh.config.PeerEgressRules
	}
	mesh.mu.Lock()
	runtime := mesh.runtime
	device := mesh.device
	mesh.mu.Unlock()
	meshCIDR := strings.TrimSpace(runtime.PeerMesh.CIDR)
	if meshCIDR == "" {
		meshCIDR = egressDefaultMeshCIDR
	}
	// Built on the first reconcile whatever the configuration, like the route installer, so that a
	// takeover a killed process left is given back even when this run no longer asks for one.
	takeover := mesh.ensureEgressDNSTakeover()
	if mesh.config.PeerEgressEnabled && mesh.config.PeerEgressDNSTakeover && takeover.networkChanged(now) {
		// Given back first and taken again below, so the new network's DNS is read afresh rather
		// than queries going on to the last network's resolver; and the pool is checked against
		// the new network's addresses, which may now overlap it.
		mesh.logger.Printf("[peer-egress-consumer] the network changed; giving the system DNS back to take it again")
		takeover.release("the network changed")
		takeover.forgetAttempt()
		mesh.egressPoolCheckedFor = ""
	}
	// Phase two needs the master switch too, so with it off this is never running either.
	phase := mesh.egressPhaseTwoFor(meshCIDR)
	// Last, whichever way the route work below ends: the takeover follows the pool's route, so it
	// is decided once the route has been applied or checked.
	defer mesh.reconcileEgressDNSTakeover(takeover, phase, meshCIDR, device, now)

	// The consumer is built only when it has something to do: rules to apply, or phase two's pool to
	// own. Building it for nothing would start the threads that carry its work and report a
	// consumer with nothing to do. One that exists is always given the current setup, even an
	// empty one: phase two stopping with no rules configured -- the mesh network moved over the
	// pool, say -- has to take its pool and its responder away, or packets to the old fake
	// addresses would still be answered for names no longer handed out.
	mesh.mu.Lock()
	built := mesh.egressConsumer != nil
	mesh.mu.Unlock()
	if len(rules) > 0 || phase.Active || built {
		mesh.configureEgressConsumer(rules, meshCIDR, runtime.PeerMesh.VirtualIP, phase.pool(), now)
	}

	// Without a device there is nothing to route into. A rule's route pointed at an interface
	// that is not there is a black hole rather than the local fallback the user would get with
	// no route at all, so the plan is empty until the device is up, and empties again if it goes.
	var desired []egressRoute
	if egressDeviceReady(device) {
		mesh.egressDeviceWaitLogged = false
		bypass := mesh.egressBypassAddresses(now)
		var refused []egressRuleSetError
		desired, refused = planEgressRoutesIn(rules, bypass, meshCIDR, phase.pool())
		mesh.logEgressRefusals(refused)
	} else if (len(rules) > 0 || phase.Active) && !mesh.egressDeviceWaitLogged {
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
func (mesh *peerMeshClient) configureEgressConsumer(rules []egressRule, meshCIDR, virtualIP, fakeIPPool string, now time.Time) {
	key := fmt.Sprintf("%s|%s|%s|%+v", meshCIDR, strings.TrimSpace(virtualIP), fakeIPPool, rules)
	if key == mesh.egressConsumerKey {
		return
	}
	mesh.egressConsumerKey = key
	consumer := mesh.ensureEgressConsumer()
	mesh.deliverEgressPurges(consumer.configureIn(rules, meshCIDR, virtualIP, fakeIPPool, now))
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
			// The index and the code, not the match: configuration values stay out of the log.
			mesh.logger.Printf("[peer-egress-consumer] rule %d refused: %s", entry.Index, entry.Code)
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
	lastControlRemote := mesh.lastControlRemote
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
	} else if lastControlRemote != "" {
		// Suspended: the connection is gone but the routes are not, so the address it used still
		// has to stay out of the tunnel or the reconnect that restores it cannot get through.
		hosts = append(hosts, lastControlRemote)
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
	takeover := mesh.egressDNS
	mesh.mu.Unlock()
	// The system DNS goes back first, while the pool's route and the responder behind it are still
	// there: a system pointed at an address nothing answers has no DNS at all.
	if takeover != nil {
		takeover.release("the client is stopping or restarting the mesh")
		takeover.forgetAttempt()
	}
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
	context.DeploymentDenyCIDRs = append(mesh.deploymentDenyCIDRs(), mesh.egressOwnFakeIPPool()...)
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
		DomainRules:              decodeEgressDomainRules(message.DomainRules),
		Limits:                   message.Limits,
	}, message.Revision, true
}

// decodeEgressDomainRules reads the domainRules of an egress-config push (protocol/spec/peer-egress.md,
// 按域名授权).
//
// A field that is absent, null or not an array is no domain rules. An entry that is not an object,
// or whose match is not a name or *.name as a consumer's domain rule is written, is skipped and the
// rest are kept: a rule this node cannot read must grant nothing, and refusing the whole push over
// it would also throw away the destination rules that came with it. An entry whose protocols or
// port ranges do not have a destination rule's shape is skipped for the same reason. The match is
// kept trimmed, without its trailing dot and in lower case, the form names are compared in.
//
// Shared vector: protocol/test-vectors/peer-egress-domain-policy-v1.json.
func decodeEgressDomainRules(raw json.RawMessage) []egressDomainRule {
	var entries []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	var rules []egressDomainRule
	for _, entry := range entries {
		if trimmed := strings.TrimSpace(string(entry)); !strings.HasPrefix(trimmed, "{") {
			continue
		}
		var rule struct {
			Match      string   `json:"match"`
			Protocols  []string `json:"protocols"`
			PortRanges [][]int  `json:"portRanges"`
		}
		if json.Unmarshal(entry, &rule) != nil {
			continue
		}
		match := strings.TrimSpace(rule.Match)
		if !looksLikeEgressDomainRule(match) || !validEgressDomainMatch(match) {
			continue
		}
		rules = append(rules, egressDomainRule{
			Match:      normalizeEgressName(match),
			Protocols:  rule.Protocols,
			PortRanges: rule.PortRanges,
		})
	}
	return rules
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

// egressOwnFakeIPPool is this node's own fake-IP pool when its configuration runs phase two, for the
// egress role's forced-deny list (protocol/spec/peer-egress-dns.md, 五). A consumer's flow dialled
// into it would be routed into this node's own tunnel and steered by this node's own names.
//
// Read from the configuration and the mesh network rather than from the last reconcile, which may
// not have run yet when the policy arrives.
func (mesh *peerMeshClient) egressOwnFakeIPPool() []string {
	mesh.mu.Lock()
	meshCIDR := strings.TrimSpace(mesh.runtime.PeerMesh.CIDR)
	mesh.mu.Unlock()
	if meshCIDR == "" {
		meshCIDR = egressDefaultMeshCIDR
	}
	cidr := effectiveEgressFakeIPCIDR(mesh.config.PeerEgressFakeIPCIDR)
	if active, _ := evaluateEgressPhaseTwo(mesh.config.PeerEgressEnabled, mesh.config.PeerEgressDNSTakeover, cidr, meshCIDR); !active {
		return nil
	}
	return []string{cidr}
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
