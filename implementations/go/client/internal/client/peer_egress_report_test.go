package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/protocol"
)

// When an egress reports to the server and what it says. The decision is bound to the shared
// vector; the rest of this file holds down the join: that a report leaves over the control
// connection the way the server accepts one, carrying the numbers the status shows.

type egressReportVector struct {
	IntervalSeconds int `json:"intervalSeconds"`
	Events          []struct {
		NewSession bool  `json:"newSession"`
		WallMs     int64 `json:"wallMs"`
		Active     bool  `json:"active"`
		Egress     struct {
			Flows      int64            `json:"flows"`
			TotalFlows int64            `json:"totalFlows"`
			Refused    map[string]int64 `json:"refused"`
			BytesIn    int64            `json:"bytesIn"`
			BytesOut   int64            `json:"bytesOut"`
		} `json:"egress"`
		Report json.RawMessage `json:"report"`
	} `json:"events"`
}

func TestEgressReportMatchesSharedVector(t *testing.T) {
	var vector egressReportVector
	readRepositoryJSON(t, "protocol/test-vectors/peer-egress-report-v1.json", &vector)
	if time.Duration(vector.IntervalSeconds)*time.Second != egressReportInterval {
		t.Errorf("the vector checks every %d s, this client every %s", vector.IntervalSeconds, egressReportInterval)
	}
	if len(vector.Events) == 0 {
		t.Fatal("the vector has no events")
	}

	var reporter egressReporter
	for index, event := range vector.Events {
		if event.NewSession {
			reporter.newSession()
			continue
		}
		report := reporter.check(event.WallMs, event.Active, egressReportCounters{
			Flows: event.Egress.Flows, TotalFlows: event.Egress.TotalFlows, Refused: event.Egress.Refused,
			BytesIn: event.Egress.BytesIn, BytesOut: event.Egress.BytesOut,
		})
		if string(event.Report) == "null" {
			if report != nil {
				t.Errorf("event %d (wallMs %d): sent %+v, want nothing", index, event.WallMs, *report)
			}
			continue
		}
		if report == nil {
			t.Errorf("event %d (wallMs %d): sent nothing, want %s", index, event.WallMs, event.Report)
			continue
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatalf("event %d: marshal: %v", index, err)
		}
		if got, want := parseJSONNumbers(t, encoded), parseJSONNumbers(t, event.Report); !reflect.DeepEqual(got, want) {
			t.Errorf("event %d (wallMs %d):\n got %s\nwant %s", index, event.WallMs, encoded, event.Report)
		}
	}
}

// parseJSONNumbers decodes keeping numbers as written, so a revision in milliseconds is compared
// exactly rather than as a float.
func parseJSONNumbers(t *testing.T, raw []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return value
}

// controlRecorder is the client's end of a control connection, keeping what the client wrote.
// Writes are synchronous, so whatever a check sent is here once the check has returned.
type controlRecorder struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *controlRecorder) Write(payload []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written.Write(payload)
}

// sentMessages decodes every packet written so far.
func (c *controlRecorder) sentMessages(t *testing.T) []protocol.MessageResponse {
	t.Helper()
	c.mu.Lock()
	reader := bytes.NewReader(append([]byte(nil), c.written.Bytes()...))
	c.mu.Unlock()
	var messages []protocol.MessageResponse
	for reader.Len() > 0 {
		packet, err := protocol.ReadPacket(reader)
		if err != nil {
			t.Fatalf("read a packet the client wrote: %v", err)
		}
		if packet.Command != protocol.CommandMessageRequest {
			t.Fatalf("the client wrote command %d, want MESSAGE_REQUEST", packet.Command)
		}
		// A MESSAGE_REQUEST body is laid out as a MESSAGE_RESPONSE is: sender, target, type,
		// message.
		message, err := protocol.DecodeMessageResponse(packet.Body)
		if err != nil {
			t.Fatalf("decode a MESSAGE_REQUEST the client wrote: %v", err)
		}
		messages = append(messages, message)
	}
	return messages
}

// egressReports keeps the PEER_CONTROL egress-reports among what the client wrote.
func (c *controlRecorder) egressReports(t *testing.T) []protocol.MessageResponse {
	t.Helper()
	var reports []protocol.MessageResponse
	for _, message := range c.sentMessages(t) {
		var head struct {
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(message.Message), &head) == nil && head.Type == peerControlTypeEgressReport {
			reports = append(reports, message)
		}
	}
	return reports
}

func (c *controlRecorder) waitForEgressReports(t *testing.T, count int) []protocol.MessageResponse {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		reports := c.egressReports(t)
		if len(reports) >= count {
			return reports
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d egress-reports written, want %d", len(reports), count)
		}
		time.Sleep(time.Millisecond)
	}
}

// egressReportClient is a client logged in on a recorded control connection, with the report
// checks run by hand: each runtime's ticker is handed to the test, which sends the ticks.
type egressReportClient struct {
	t       *testing.T
	client  *Client
	mesh    *peerMeshClient
	tickers chan chan time.Time
}

func newEgressReportClient(t *testing.T) *egressReportClient {
	t.Helper()
	specus := New(Config{PeerMeshDevice: "noop", PeerMeshTunName: "specus0", PeerMeshMTU: 1280,
		ServerBaseURL: "https://198.51.100.7:8443"}, log.New(io.Discard, "", 0))
	specus.applyRuntime(RuntimeConfig{ClientName: "egress-node"})
	harness := &egressReportClient{t: t, client: specus, mesh: specus.peerMesh, tickers: make(chan chan time.Time, 4)}
	// Unbuffered, so a tick handed over means the check before it has finished.
	harness.mesh.egressReportTicks = func() (<-chan time.Time, func()) {
		ticks := make(chan time.Time)
		harness.tickers <- ticks
		return ticks, func() {}
	}
	t.Cleanup(harness.mesh.stop)
	return harness
}

// login does what a successful control login does, on a fresh recorded connection. The mesh
// itself is left off: starting it would read this machine's route journal, and the egress runs
// and reports without it.
func (h *egressReportClient) login() *controlRecorder {
	control := &controlRecorder{}
	h.mesh.start(control, h.client.currentRuntime(), h.client.sendPeerControl)
	return control
}

// push delivers a PEER_CONTROL message from the server.
func (h *egressReportClient) push(control net.Conn, payload string) {
	if err := h.client.handlePeerControl(control, payload); err != nil {
		h.t.Fatalf("handle %s: %v", payload, err)
	}
}

// ticker is the ticker of the runtime the last pushed egress-config built.
func (h *egressReportClient) ticker() chan time.Time {
	select {
	case ticks := <-h.tickers:
		return ticks
	case <-time.After(5 * time.Second):
		h.t.Fatal("no egress runtime was built")
		return nil
	}
}

// waitForReporter waits until the reporter's state satisfies condition.
func (h *egressReportClient) waitForReporter(what string, condition func(egressReporter) bool) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.mesh.mu.Lock()
		reached := condition(h.mesh.egressReport)
		h.mesh.mu.Unlock()
		if reached {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// egressReportPolicyAt is an egress-config as a server pushes it, envelope fields included.
func egressReportPolicyAt(enabled bool, revision int64) string {
	return fmt.Sprintf(`{"type":"egress-config","enabled":%t,"revision":%d,"scope":"PUBLIC",
		"allowedConsumerClientIds":[7],
		"destinationRules":[{"cidr":"203.0.113.0/24","protocols":["udp"],"portRanges":[[53,53]]}],
		"limits":{"maxConcurrentFlows":16,"maxFlowsPerConsumer":8,"idleTimeoutSeconds":600},
		"sourceClientId":3,"sourceClientName":"egress-node","targetClientId":3,"targetClientName":"egress-node"}`,
		enabled, revision)
}

// A report leaves over the control connection the way the server takes one: MESSAGE_REQUEST,
// PEER_CONTROL, no target, and no identity in the body. It carries what the status shows, read from
// real flows, numbered by the clock of the check that sent it.
func TestEgressReportGoesToTheServerOverTheControlConnection(t *testing.T) {
	harness := newEgressReportClient(t)
	control := harness.login()
	harness.push(control, egressReportPolicyAt(true, 3))
	ticks := harness.ticker()

	// Real traffic through the real plane, on a dialer that opens no socket.
	runtime := harness.mesh.ensureEgress()
	upstream := newFakeEgressConn()
	runtime.mu.Lock()
	runtime.dial = func(string, string, time.Duration) (net.Conn, error) { return upstream, nil }
	runtime.mu.Unlock()
	query := buildUDPDatagram(udpDatagram{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.53"),
		SourcePort: 51000, DestinationPort: 53, Payload: []byte("query"),
	})
	runtime.handleFrame(7, egressFrameFor(query), time.Now())
	upstream.reads <- []byte("answer!")
	// Outside every destination rule: refused.
	runtime.handleFrame(7, egressFrameFor(buildUDPDatagram(udpDatagram{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "198.51.100.10"),
		SourcePort: 51001, DestinationPort: 53, Payload: []byte("query"),
	})), time.Now())
	waitForEgressStats(t, runtime, func(snapshot runtimeStatusSnapshot) bool { return snapshot.Stats.BytesIn == 7 })

	first := time.UnixMilli(1_791_000_000_000)
	ticks <- first
	reports := control.waitForEgressReports(t, 1)
	report := checkEgressReportEnvelope(t, reports[0])
	wantEgressReport(t, report, first.UnixMilli(), 1, 1, map[string]int64{egressCodeDestinationDenied: 1}, 7, 5)
	matchesEgressStatus(t, report, harness.mesh)

	// More bytes on the same flow: a change, reported at the next check.
	runtime.handleFrame(7, egressFrameFor(query), time.Now())
	waitForEgressStats(t, runtime, func(snapshot runtimeStatusSnapshot) bool { return snapshot.Stats.BytesOut == 10 })
	second := first.Add(egressReportInterval)
	ticks <- second
	reports = control.waitForEgressReports(t, 2)
	report = checkEgressReportEnvelope(t, reports[1])
	wantEgressReport(t, report, second.UnixMilli(), 1, 1, map[string]int64{egressCodeDestinationDenied: 1}, 7, 10)
	matchesEgressStatus(t, report, harness.mesh)

	// Nothing changed: two checks, nothing sent. The third tick is taken only once the second
	// check has finished.
	ticks <- second.Add(egressReportInterval)
	ticks <- second.Add(2 * egressReportInterval)
	ticks <- second.Add(3 * egressReportInterval)
	if reports := control.egressReports(t); len(reports) != 2 {
		t.Errorf("%d egress-reports after two unchanged checks, want still 2", len(reports))
	}
}

// A new control session hears the report at its first check even when nothing changed, because
// the server behind it may have restarted; and the revision goes on rising past a clock that went
// back, on a connection the old session never saw.
func TestEgressReportRepeatsInANewControlSession(t *testing.T) {
	harness := newEgressReportClient(t)
	control := harness.login()
	harness.push(control, egressReportPolicyAt(true, 3))
	ticks := harness.ticker()

	first := time.UnixMilli(1_791_000_000_000)
	ticks <- first
	report := checkEgressReportEnvelope(t, control.waitForEgressReports(t, 1)[0])
	wantEgressReport(t, report, first.UnixMilli(), 0, 0, map[string]int64{}, 0, 0)
	ticks <- first.Add(egressReportInterval)
	ticks <- first.Add(2 * egressReportInterval)
	if reports := control.egressReports(t); len(reports) != 1 {
		t.Fatalf("%d egress-reports in one session with nothing changed, want 1", len(reports))
	}

	// The control connection drops and the client logs in again; the server pushes the policy
	// again with the login.
	harness.mesh.suspend()
	next := harness.login()
	harness.push(next, egressReportPolicyAt(true, 3))
	ticks = harness.ticker()

	earlier := first.Add(-time.Hour)
	ticks <- earlier
	report = checkEgressReportEnvelope(t, next.waitForEgressReports(t, 1)[0])
	wantEgressReport(t, report, first.UnixMilli()+1, 0, 0, map[string]int64{}, 0, 0)
	if reports := control.egressReports(t); len(reports) != 1 {
		t.Errorf("the old connection got %d egress-reports, want only its own 1", len(reports))
	}
}

// A check that read a runtime its control session has since taken down decides nothing. Deciding
// would spend the next session's first report on a connection that is gone, and that session would
// then not hear from the egress until a value changed.
func TestEgressReportCheckForAnEndedRuntimeDecidesNothing(t *testing.T) {
	harness := newEgressReportClient(t)
	control := harness.login()
	harness.push(control, egressReportPolicyAt(true, 3))
	harness.ticker()

	// Still enabled, as a runtime read just before its session ended reads; no longer the mesh's.
	stale := newEgressRuntime(log.New(io.Discard, "", 0), nil, nil)
	stale.applyPolicy(testEgressPolicy("203.0.113.0/24"), newEgressContext(), time.Now())
	harness.mesh.checkEgressReport(stale, time.UnixMilli(1_791_000_000_000))

	if reports := control.egressReports(t); len(reports) != 0 {
		t.Errorf("a check for a runtime the mesh no longer runs sent %d egress-reports", len(reports))
	}
	harness.mesh.mu.Lock()
	reporter := harness.mesh.egressReport
	harness.mesh.mu.Unlock()
	if reporter.lastSent != nil || reporter.revision != 0 {
		t.Errorf("the reporter moved on a check that decided nothing: %+v", reporter)
	}
}

// Switched off, the egress says nothing; switched on again, its first check reports even though
// nothing changed.
func TestEgressReportStopsWhileSwitchedOff(t *testing.T) {
	harness := newEgressReportClient(t)
	control := harness.login()
	harness.push(control, egressReportPolicyAt(true, 3))
	ticks := harness.ticker()

	at := time.UnixMilli(1_791_000_000_000)
	ticks <- at
	control.waitForEgressReports(t, 1)

	harness.push(control, egressReportPolicyAt(false, 4))
	ticks <- at.Add(egressReportInterval)
	// The check forgets the last report when it finds the egress off. Waiting for that, rather
	// than handing over another tick, leaves no check running when the egress is switched on.
	harness.waitForReporter("the check while switched off", func(reporter egressReporter) bool {
		return reporter.lastSent == nil
	})
	if reports := control.egressReports(t); len(reports) != 1 {
		t.Fatalf("%d egress-reports while switched off, want still 1", len(reports))
	}

	harness.push(control, egressReportPolicyAt(true, 5))
	again := at.Add(2 * egressReportInterval)
	ticks <- again
	report := checkEgressReportEnvelope(t, control.waitForEgressReports(t, 2)[1])
	wantEgressReport(t, report, again.UnixMilli(), 0, 0, map[string]int64{}, 0, 0)
}

// A runtime that never received an egress-config with enabled true does not report: nothing is
// running for the page to show.
func TestEgressReportIsNotSentByADisabledEgress(t *testing.T) {
	harness := newEgressReportClient(t)
	control := harness.login()
	harness.push(control, egressReportPolicyAt(false, 3))
	ticks := harness.ticker()

	at := time.UnixMilli(1_791_000_000_000)
	ticks <- at
	ticks <- at.Add(egressReportInterval)
	if reports := control.egressReports(t); len(reports) != 0 {
		t.Errorf("a disabled egress sent %d egress-reports", len(reports))
	}
}

// checkEgressReportEnvelope holds a written message to what the server accepts and returns its
// body. The server closes the connection over a target or an identity key, null included.
func checkEgressReportEnvelope(t *testing.T, message protocol.MessageResponse) map[string]any {
	t.Helper()
	if message.MessageType != protocol.MessageTypePeerControl {
		t.Errorf("messageType = %d, want PEER_CONTROL", message.MessageType)
	}
	if message.ToClientName != "" {
		t.Errorf("toClientName = %q, want empty", message.ToClientName)
	}
	if message.ClientName != "egress-node" {
		t.Errorf("sent as %q, want the logged-in client", message.ClientName)
	}
	if len(message.Message) > 8*1024 {
		t.Errorf("the report is %d bytes, over the servers' 8 KiB cap", len(message.Message))
	}
	body, ok := parseJSONNumbers(t, []byte(message.Message)).(map[string]any)
	if !ok {
		t.Fatalf("the report is not a JSON object: %s", message.Message)
	}
	var keys []string
	for key := range body {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	want := []string{"activeFlows", "bytesIn", "bytesOut", "rejectedFlows", "revision", "totalFlows", "type"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("report keys = %v, want exactly %v", keys, want)
	}
	if body["type"] != peerControlTypeEgressReport {
		t.Errorf("type = %v", body["type"])
	}
	return body
}

func wantEgressReport(t *testing.T, body map[string]any, revision, active, total int64,
	rejected map[string]int64, bytesIn, bytesOut int64) {
	t.Helper()
	for field, want := range map[string]int64{
		"revision": revision, "activeFlows": active, "totalFlows": total, "bytesIn": bytesIn, "bytesOut": bytesOut,
	} {
		if got := jsonInt(t, body[field]); got != want {
			t.Errorf("%s = %d, want %d", field, got, want)
		}
	}
	got := map[string]int64{}
	if raw, ok := body["rejectedFlows"].(map[string]any); ok {
		for code, count := range raw {
			got[code] = jsonInt(t, count)
		}
	} else {
		t.Errorf("rejectedFlows = %#v, want an object", body["rejectedFlows"])
	}
	if !reflect.DeepEqual(got, rejected) {
		t.Errorf("rejectedFlows = %v, want %v", got, rejected)
	}
}

// matchesEgressStatus holds a report to the egress section of the status as it reads now.
func matchesEgressStatus(t *testing.T, body map[string]any, mesh *peerMeshClient) {
	t.Helper()
	status := mapSection(t, mesh.egressStatusJSON(), "egress")
	pairs := map[string]string{"activeFlows": "flows", "totalFlows": "totalFlows", "bytesIn": "bytesIn", "bytesOut": "bytesOut"}
	for reported, shown := range pairs {
		if got, want := jsonInt(t, body[reported]), statusInt(status[shown]); got != want {
			t.Errorf("report %s = %d, status %s = %d", reported, got, shown, want)
		}
	}
	refused, _ := status["refused"].(map[string]int64)
	rejected, _ := body["rejectedFlows"].(map[string]any)
	if len(rejected) != len(refused) {
		t.Errorf("report rejectedFlows = %v, status refused = %v", rejected, refused)
	}
	for code, count := range refused {
		if jsonInt(t, rejected[code]) != count {
			t.Errorf("report rejectedFlows[%s] = %v, status refused = %d", code, rejected[code], count)
		}
	}
}

func jsonInt(t *testing.T, value any) int64 {
	t.Helper()
	number, ok := value.(json.Number)
	if !ok {
		t.Fatalf("%#v is not a JSON number", value)
	}
	parsed, err := number.Int64()
	if err != nil {
		t.Fatalf("%s is not an integer: %v", number, err)
	}
	return parsed
}

func statusInt(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	}
	return -1
}

func waitForEgressStats(t *testing.T, runtime *egressRuntime, condition func(runtimeStatusSnapshot) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition(runtime.statusSnapshot()) {
		if time.Now().After(deadline) {
			t.Fatalf("the egress never reached the expected counters: %+v", runtime.statusSnapshot())
		}
		time.Sleep(time.Millisecond)
	}
}
