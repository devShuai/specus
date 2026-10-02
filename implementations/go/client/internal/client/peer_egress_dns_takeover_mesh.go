package client

import (
	"errors"
	"time"
)

// Joining the DNS takeover to the mesh's reconcile. Everything here runs under egressPlanMu, the lock
// that already serialises the route installer: the takeover follows the pool's route, runs commands,
// and must never be held up by, or hold up, the mesh's own lock.

// SetEgressDNSClientCheck tells the DNS takeover how to recognise another client that is running:
// running(pid) reports whether that process publishes fresh CLI state. A journal such a client owns
// is its live takeover and is left alone; any other journal found is given back
// (protocol/spec/peer-egress-dns.md, 六, 事务日志). Called before Run; without it every journal is
// given back.
func (client *Client) SetEgressDNSClientCheck(running func(pid int) bool) {
	client.peerMesh.egressDNSClientRunning = running
}

// ensureEgressDNSTakeover builds the takeover on first use and gives back whatever a previous run
// left in the journal. Called under egressPlanMu with no mesh lock held.
func (mesh *peerMeshClient) ensureEgressDNSTakeover() *egressDNSTakeover {
	mesh.mu.Lock()
	takeover := mesh.egressDNS
	mesh.mu.Unlock()
	if takeover != nil {
		return takeover
	}
	host := mesh.egressDNSHost
	if host == nil {
		host = defaultEgressDNSHost()
	}
	platform := mesh.egressDNSPlatform
	if platform == "" {
		platform = egressDNSPlatform()
	}
	path := mesh.egressDNSJournalPath
	if path == "" {
		path = EgressDNSJournalPath()
	}
	takeover = newEgressDNSTakeover(host, platform, path, mesh.logger)
	takeover.tunnelAddresses = mesh.egressDNSTunnelAddresses
	if takeover.tunnelAddresses == nil {
		takeover.tunnelAddresses = egressTunnelInterfaceAddresses
	}
	takeover.fingerprint = mesh.egressDNSFingerprint
	if takeover.fingerprint == nil {
		takeover.fingerprint = mesh.systemNetworkFingerprint
	}
	takeover.clientRunning = mesh.egressDNSClientRunning
	takeover.recoverLeftover()
	mesh.mu.Lock()
	mesh.egressDNS = takeover
	mesh.mu.Unlock()
	return takeover
}

// systemNetworkFingerprint reads the network the way the route installer sees it: the default
// route's interface from its table, and this device's IPv4 addresses. Called under egressPlanMu.
func (mesh *peerMeshClient) systemNetworkFingerprint() (string, error) {
	mesh.mu.Lock()
	installer := mesh.egressRoutes
	mesh.mu.Unlock()
	if installer == nil {
		return "", errors.New("no routing table read yet")
	}
	routes, tunnel, err := installer.commander.Table()
	if err != nil {
		return "", err
	}
	return egressDNSNetworkFingerprint(routes, tunnel, localInterfaceAddresses()), nil
}

// reconcileEgressDNSTakeover takes the system's DNS over while phase two runs with its route in
// place, and gives it back otherwise. Called under egressPlanMu with no mesh lock held.
func (mesh *peerMeshClient) reconcileEgressDNSTakeover(takeover *egressDNSTakeover, phase egressPhaseTwo,
	meshCIDR string, device peerVirtualDevice, now time.Time) {
	pool, parsed := parseEgressCIDR(phase.CIDR)
	if !mesh.config.PeerEgressDNSTakeover || !phase.Active || !parsed {
		takeover.idle("phase two is not running")
		return
	}
	normalized := formatEgressCIDR(pool)
	installed := false
	mesh.mu.Lock()
	installer := mesh.egressRoutes
	mesh.mu.Unlock()
	if installer != nil {
		for _, route := range installer.installedRoutes() {
			installed = installed || route.Origin == egressRouteOriginFakeIPPool && route.CIDR == normalized
		}
	}
	tunnel := ""
	if egressDeviceReady(device) {
		tunnel = device.Name()
	}
	request := egressDNSTakeoverRequest{
		Listen: formatEgressAddress(pool.network + 1), Tunnel: tunnel, Pool: normalized, Mesh: meshCIDR,
		PoolRouteInstalled: installed && tunnel != "",
	}
	if upstreams, committed := takeover.engage(request, now); committed {
		// The responder forwards to what the system used before the takeover, the journal's
		// upstreams. Kept after a give-back: a system pointed at the listen address by hand still
		// gets answers.
		mesh.setEgressDNSUpstreams(upstreams)
	}
}

// egressDNSTakeoverStatusLocked is the takeover's status for consumer.dns. Called with the mesh
// lock held.
func (mesh *peerMeshClient) egressDNSTakeoverStatusLocked() egressDNSTakeoverStatus {
	if mesh.egressDNS == nil {
		return egressDNSTakeoverStatus{Journal: egressDNSJournalNone}
	}
	return mesh.egressDNS.statusSnapshot()
}
