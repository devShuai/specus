package client

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// Keeping the consumer's routes true while the process runs.
//
// The plan is recomputed on the mesh's tick and applied only when it changed or when a retry is
// due. What these cases pin is the wiring around that: what the plan is fed, when the installer is
// asked to act, and what happens to the routes when the device is not there.

// fakePeerVirtualDevice stands in for a TUN that came up, or one that did not.
type fakePeerVirtualDevice struct {
	name   string
	status string
}

func (d *fakePeerVirtualDevice) Name() string                                  { return d.name }
func (d *fakePeerVirtualDevice) Start(_ <-chan struct{}, _ func([]byte)) error { return nil }
func (d *fakePeerVirtualDevice) SyncPeerRoutes(_ []string)                     {}
func (d *fakePeerVirtualDevice) WritePacket(_ []byte) error                    { return nil }
func (d *fakePeerVirtualDevice) Close() error                                  { return nil }
func (d *fakePeerVirtualDevice) Status() string                                { return d.status }
func (d *fakePeerVirtualDevice) Error() string                                 { return "" }

// applyEgressRulesForTest runs one reconcile with the rules given and a device that is up, against
// a routing table that accepts everything and touches nothing on this machine.
func applyEgressRulesForTest(t *testing.T, mesh *peerMeshClient, rules []egressRule, runtime RuntimeConfig) {
	t.Helper()
	mesh.config.PeerEgressRules = rules
	if mesh.egressJournalPath == "" {
		mesh.egressJournalPath = journalPath(t)
	}
	mesh.mu.Lock()
	mesh.runtime = runtime
	if !egressDeviceReady(mesh.device) {
		mesh.device = &fakePeerVirtualDevice{name: "specus0", status: "UP"}
	}
	if mesh.egressCommander == nil && mesh.egressRoutes == nil {
		mesh.egressCommander = newFakeRouteCommander()
	}
	mesh.mu.Unlock()
	mesh.reconcileEgressRoutesAt(time.Now())
}

type reconcileHarness struct {
	mesh      *peerMeshClient
	commander *fakeRouteCommander
	lookups   map[string][]net.IP
	now       time.Time
}

func newReconcileHarness(t *testing.T, rules ...egressRule) *reconcileHarness {
	t.Helper()
	harness := &reconcileHarness{
		mesh:      newConsumerMeshHarness(t),
		commander: newFakeRouteCommander(),
		lookups:   map[string][]net.IP{},
		now:       time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC),
	}
	harness.mesh.config.PeerEgressRules = rules
	harness.mesh.egressCommander = harness.commander
	harness.mesh.egressBypass = newEgressBypassResolver(func(host string) ([]net.IP, error) {
		if ips, ok := harness.lookups[host]; ok {
			return ips, nil
		}
		return nil, errors.New("no such host in this test")
	})
	harness.mesh.mu.Lock()
	harness.mesh.runtime = consumerRuntimeConfig()
	harness.mesh.sessions = map[int64]*peerMeshSession{}
	harness.mesh.device = &fakePeerVirtualDevice{name: "specus0", status: "UP"}
	harness.mesh.mu.Unlock()
	return harness
}

func (h *reconcileHarness) tick(after time.Duration) {
	h.now = h.now.Add(after)
	h.mesh.reconcileEgressRoutesAt(h.now)
}

func (h *reconcileHarness) appliedAt() time.Time {
	h.mesh.mu.Lock()
	defer h.mesh.mu.Unlock()
	return h.mesh.egressApplied.At
}

func contains(list []string, want string) bool {
	for _, entry := range list {
		if entry == want {
			return true
		}
	}
	return false
}

// With no rules there is nothing for a consumer to do, so none is built and the status says so.
// The installer is still built, because the journal has to be read regardless.
func TestMeshReconcileBuildsNoConsumerWithoutRules(t *testing.T) {
	harness := newReconcileHarness(t)
	harness.tick(0)

	harness.mesh.mu.Lock()
	consumer, installer := harness.mesh.egressConsumer, harness.mesh.egressRoutes
	harness.mesh.mu.Unlock()
	if consumer != nil {
		t.Error("a consumer was built for an empty rule set")
	}
	if installer == nil {
		t.Error("the journal was not read because the rule set was empty")
	}
	section := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")
	if active, _ := section["active"].(bool); active {
		t.Error("the status reports a consumer with no rules as active")
	}
}

// A journal from a process that was killed describes routes whose interface is gone. They are taken
// back on the first reconcile -- with no rules at all, which is the case that used to leave them.
func TestMeshReconcileTakesBackRoutesLeftByAPreviousRun(t *testing.T) {
	harness := newReconcileHarness(t)
	leftover := `{"version":1,"routes":[
		{"cidr":"198.51.100.7/32","kind":"bypass","origin":"bypass"},
		{"cidr":"203.0.113.0/24","kind":"tun","origin":"rule:203.0.113.0/24"}]}`
	if err := os.WriteFile(harness.mesh.egressJournalPath, []byte(leftover), 0o600); err != nil {
		t.Fatal(err)
	}

	harness.tick(0)

	for _, cidr := range []string{"203.0.113.0/24", "198.51.100.7/32"} {
		if !contains(harness.commander.removeLog, cidr) {
			t.Errorf("%s from the previous run was not taken back: removed %v", cidr, harness.commander.removeLog)
		}
	}
	if _, err := os.Stat(harness.mesh.egressJournalPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the journal still exists after its routes were taken back: %v", err)
	}
}

// An unchanged plan is not reapplied, and the table is not asked about it again. When a peer's
// endpoint falls under a rule, its bypass goes in on the next tick; when the peer goes, so does the
// bypass.
func TestMeshReconcileAppliesOnlyWhenThePlanChanges(t *testing.T) {
	harness := newReconcileHarness(t,
		egressRule{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2})

	harness.tick(0)
	first := harness.appliedAt()
	if !contains(harness.commander.installLog, "203.0.113.0/24") {
		t.Fatalf("the rule's route was not installed: %v", harness.commander.installLog)
	}
	queries := len(harness.commander.conflictLog)

	harness.tick(5 * time.Second)
	if harness.appliedAt() != first {
		t.Error("an unchanged plan was applied again")
	}
	if len(harness.commander.conflictLog) != queries {
		t.Error("an unchanged plan queried the table again")
	}

	harness.mesh.mu.Lock()
	harness.mesh.sessions[2] = &peerMeshSession{PeerID: 2,
		RemoteEndpoint: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 40000}}
	harness.mesh.mu.Unlock()
	harness.tick(5 * time.Second)
	if !contains(harness.commander.installLog, "203.0.113.7/32") {
		t.Errorf("the peer's endpoint under the rule got no bypass: %v", harness.commander.installLog)
	}
	if harness.appliedAt() != harness.now {
		t.Error("a changed plan was not applied on the tick it changed")
	}

	harness.mesh.mu.Lock()
	delete(harness.mesh.sessions, 2)
	harness.mesh.mu.Unlock()
	harness.tick(5 * time.Second)
	if !contains(harness.commander.removeLog, "203.0.113.7/32") {
		t.Errorf("the departed peer's bypass was left in place: %v", harness.commander.removeLog)
	}
	if _, still := harness.commander.table["203.0.113.0/24"]; !still {
		t.Error("the rule's own route was lost while the bypass came and went")
	}
}

// A prefix somebody else owns is asked about again after the interval, not on every tick, and is
// installed once the other route is gone.
func TestMeshReconcileRetriesAConflictAfterTheInterval(t *testing.T) {
	harness := newReconcileHarness(t,
		egressRule{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2})
	harness.commander.foreign["203.0.113.0/24"] = "203.0.113.0/24 via 192.0.2.1 dev eth0"

	harness.tick(0)
	if len(harness.commander.conflictLog) != 1 || len(harness.commander.installLog) != 0 {
		t.Fatalf("queries=%v installs=%v", harness.commander.conflictLog, harness.commander.installLog)
	}
	harness.tick(5 * time.Second)
	if len(harness.commander.conflictLog) != 1 {
		t.Error("the conflict was retried inside the interval")
	}
	harness.tick(egressRouteRetryInterval - 5*time.Second)
	if len(harness.commander.conflictLog) != 2 {
		t.Errorf("the conflict was not retried after the interval: %v", harness.commander.conflictLog)
	}

	delete(harness.commander.foreign, "203.0.113.0/24")
	harness.tick(egressRouteRetryInterval)
	if !contains(harness.commander.installLog, "203.0.113.0/24") {
		t.Errorf("the route was not installed once the prefix was free: %v", harness.commander.installLog)
	}
	section := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")
	for _, route := range section["routes"].([]map[string]any) {
		if _, contested := route["conflict"]; contested {
			t.Errorf("the status still reports the conflict: %v", route)
		}
	}
}

// Routes point into the device, so there are none until it is up, and none again once it is gone.
func TestMeshReconcileFollowsTheDevice(t *testing.T) {
	harness := newReconcileHarness(t,
		egressRule{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2})
	device := &fakePeerVirtualDevice{name: "specus0", status: "ERROR"}
	harness.mesh.mu.Lock()
	harness.mesh.device = device
	harness.mesh.mu.Unlock()

	harness.tick(0)
	if len(harness.commander.installLog) != 0 {
		t.Fatalf("routes were installed into a device that failed: %v", harness.commander.installLog)
	}
	harness.mesh.mu.Lock()
	consumer := harness.mesh.egressConsumer
	harness.mesh.mu.Unlock()
	if consumer == nil {
		t.Error("the consumer was not built while the device was down; the rules should still be reported")
	}

	device.status = "UP"
	harness.tick(5 * time.Second)
	if !contains(harness.commander.installLog, "203.0.113.0/24") {
		t.Errorf("routes were not installed once the device came up: %v", harness.commander.installLog)
	}

	device.status = "ERROR"
	harness.tick(5 * time.Second)
	if !contains(harness.commander.removeLog, "203.0.113.0/24") {
		t.Errorf("routes were left pointing at a device that failed: %v", harness.commander.removeLog)
	}
}

// Everything the tunnel's transport talks to is pinned when a rule covers it: the control connection
// by its live address, the login server and STUN by name, the relay by its assignment.
func TestMeshReconcilePinsTheTransportEndpoints(t *testing.T) {
	harness := newReconcileHarness(t,
		egressRule{Match: "127.0.0.0/8", Action: egressActionEgress, EgressClientID: 2},
		egressRule{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2})
	harness.lookups["api.example.test"] = []net.IP{net.IPv4(203, 0, 113, 61)}
	harness.lookups["stun.example.test"] = []net.IP{net.ParseIP("2001:db8::1"), net.IPv4(203, 0, 113, 60)}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener:", err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	harness.mesh.config.ServerBaseURL = "https://api.example.test:8443/"
	harness.mesh.mu.Lock()
	harness.mesh.conn = conn
	harness.mesh.runtime.PeerMesh.StunHost = "stun.example.test"
	harness.mesh.relay = &peerCandidate{Type: "relay", Address: "203.0.113.50", Port: 3478}
	harness.mesh.mu.Unlock()

	harness.tick(0)

	for _, want := range []string{"127.0.0.1/32", "203.0.113.61/32", "203.0.113.60/32", "203.0.113.50/32"} {
		if !contains(harness.commander.installLog, want) {
			t.Errorf("%s was not pinned: %v", want, harness.commander.installLog)
		}
	}
	for _, cidr := range harness.commander.installLog {
		if cidr == "2001:db8::1/32" {
			t.Error("an IPv6 answer was turned into a route")
		}
	}
}

// The resolver reads a URL, a host with a port, and a bare host or literal, and answers from its
// cache for the TTL -- for a failure as well as for a success.
func TestEgressBypassResolverReadsEveryFormAndCaches(t *testing.T) {
	calls := map[string]int{}
	resolver := newEgressBypassResolver(func(host string) ([]net.IP, error) {
		calls[host]++
		switch host {
		case "api.example.test":
			return []net.IP{net.IPv4(203, 0, 113, 61)}, nil
		case "stun.example.test":
			return []net.IP{net.ParseIP("2001:db8::1"), net.IPv4(203, 0, 113, 60)}, nil
		}
		return nil, errors.New("no such host")
	})
	entries := []string{
		"https://api.example.test:8443/login", "stun.example.test:3478", "203.0.113.9:443",
		"198.51.100.1", "", "[2001:db8::2]:3478", "gone.example.test", "stun.example.test",
	}
	start := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

	addresses, failed := resolver.resolve(entries, start)
	want := []string{"203.0.113.61", "203.0.113.60", "203.0.113.9", "198.51.100.1"}
	if len(addresses) != len(want) {
		t.Fatalf("resolved %v, want %v", addresses, want)
	}
	for index := range want {
		if addresses[index] != want[index] {
			t.Errorf("address %d = %s, want %s", index, addresses[index], want[index])
		}
	}
	if len(failed) != 1 || failed[0] != "gone.example.test" {
		t.Errorf("failed = %v", failed)
	}

	// Inside the TTL nothing is asked again, and the failure is still reported from the cache.
	_, failed = resolver.resolve(entries, start.Add(egressBypassResolveTTL-time.Second))
	if calls["api.example.test"] != 1 || calls["stun.example.test"] != 1 || calls["gone.example.test"] != 1 {
		t.Errorf("lookups inside the TTL: %v", calls)
	}
	if len(failed) != 1 {
		t.Errorf("the cached failure was not reported: %v", failed)
	}

	// At the TTL everything is asked again.
	resolver.resolve(entries, start.Add(egressBypassResolveTTL))
	if calls["api.example.test"] != 2 || calls["gone.example.test"] != 2 {
		t.Errorf("lookups after the TTL: %v", calls)
	}
}

// A control connection that drops must not take the routes with it.
//
// Almost every control connection that ends is followed by another within seconds. Withdrawing
// for that gap put every destination a rule had claimed back on the local default route, so the
// traffic went out of the machine directly instead of being blocked -- silently, and for as long
// as the reconnect took. Real runs measured about two seconds of it.
//
// Stopping is the other case: the client is finished, nothing is coming back, and the routes have
// to go or they outlive the process that owns them.
func TestMeshSuspendKeepsTheRoutesAndStopTakesThemBack(t *testing.T) {
	harness := newReconcileHarness(t,
		egressRule{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2})
	harness.tick(0)
	if _, installed := harness.commander.table["203.0.113.0/24"]; !installed {
		t.Fatal("the rule installed no route to begin with, so this proves nothing")
	}

	harness.mesh.suspend()

	if _, installed := harness.commander.table["203.0.113.0/24"]; !installed {
		t.Error("suspending withdrew the rule's route: its traffic would leave through the machine's own default route")
	}
	harness.mesh.mu.Lock()
	device, installer, conn := harness.mesh.device, harness.mesh.egressRoutes, harness.mesh.conn
	harness.mesh.mu.Unlock()
	if device == nil {
		t.Error("suspending closed the virtual device, and the kernel drops the routes that point into it")
	}
	if installer == nil {
		t.Error("suspending forgot the installer, so the next reconcile would reinstall from nothing")
	}
	if conn != nil {
		t.Error("suspending kept the dead control connection, which the next send would write to")
	}

	// The maintenance tick keeps running while the connection is down, and must leave the route
	// alone rather than decide it is no longer wanted.
	harness.tick(5 * time.Second)
	if _, installed := harness.commander.table["203.0.113.0/24"]; !installed {
		t.Error("a reconcile during the suspension withdrew the rule's route")
	}

	harness.mesh.stop()

	if _, installed := harness.commander.table["203.0.113.0/24"]; installed {
		t.Error("stopping left the rule's route behind, pointing into a tunnel nothing serves")
	}
}

// The address the control connection last used has to stay out of the tunnel while the connection
// is gone. The routes are no longer withdrawn across a reconnect, so a rule covering the server's
// own prefix would now capture the reconnect itself and leave the client unable to come back.
func TestMeshSuspendKeepsTheControlAddressOutOfTheTunnel(t *testing.T) {
	harness := newReconcileHarness(t,
		egressRule{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2})
	harness.mesh.mu.Lock()
	harness.mesh.conn = &fakeControlConn{remote: "203.0.113.2:7010"}
	harness.mesh.mu.Unlock()
	harness.tick(0)
	if _, installed := harness.commander.table["203.0.113.2/32"]; !installed {
		t.Fatal("the control address had no bypass to begin with")
	}

	harness.mesh.suspend()
	harness.tick(5 * time.Second)

	if _, installed := harness.commander.table["203.0.113.2/32"]; !installed {
		t.Error("the bypass for the control address went away with the connection, so the reconnect would be routed into the tunnel")
	}
}

// fakeControlConn stands in for the control connection where only its remote address matters.
type fakeControlConn struct {
	net.Conn
	remote string
}

func (c *fakeControlConn) RemoteAddr() net.Addr {
	address, err := net.ResolveTCPAddr("tcp", c.remote)
	if err != nil {
		return nil
	}
	return address
}
