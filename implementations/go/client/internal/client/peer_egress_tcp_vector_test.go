package client

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The user-space TCP stack as a shared fixture.
//
// P4 ports this stack to Java and .NET, and the issue's completion criterion is that all three
// agree case by case. Hand-porting twenty Go test functions twice would mean three sets of
// assertions that drift independently, so the scenarios are data instead: a list of steps to feed
// and, for each, what the stack produced.
//
// Where the expectations come from matters, and it is not the same story as the authorization
// vector. There the expectations came from an independent Python reference, so matching it means
// each runtime is independently right. Here they are recorded from the Go stack, because writing a
// second full TCP implementation to check the first is out of proportion. So this fixture proves
// agreement, not correctness. Correctness is what peer_egress_tcp_test.go argues, case by case,
// against the RFCs; this file keeps the other two runtimes from disagreeing with the result.
//
// Regenerate with: go test ./internal/client -run TestTCPVector -update

var updateTCPVector = flag.Bool("update", false, "rewrite the shared TCP conformance vector")

const tcpVectorName = "peer-egress-tcp-v1.json"

type tcpVectorFile struct {
	Name    string          `json:"name"`
	Version int             `json:"version"`
	Notes   []string        `json:"notes"`
	Params  tcpVectorParams `json:"params"`
	Cases   []tcpVectorCase `json:"cases"`
}

type tcpVectorParams struct {
	ConsumerIP    string `json:"consumerIp"`
	EgressIP      string `json:"egressIp"`
	ConsumerPort  int    `json:"consumerPort"`
	TargetPort    int    `json:"targetPort"`
	PathMTU       int    `json:"pathMtu"`
	IdleTimeoutMs int    `json:"idleTimeoutMs"`
	ISS           uint32 `json:"iss"`
	PeerISN       uint32 `json:"peerIsn"`
	// EpochMs is the clock the first step runs at. Every step's advanceMs is relative to the
	// step before it, so a port never has to know what "now" means on its own platform.
	EpochMs int64 `json:"epochMs"`
}

type tcpVectorCase struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Steps       []tcpVectorStep `json:"steps"`
}

// tcpVectorStep is one thing done to the stack and everything that came back.
type tcpVectorStep struct {
	// Do is one of: segment, appData, appClose, abort, tick.
	Do        string `json:"do"`
	AdvanceMs int64  `json:"advanceMs,omitempty"`

	// Segment input.
	Seq        uint32   `json:"seq,omitempty"`
	Ack        uint32   `json:"ack,omitempty"`
	Flags      []string `json:"flags,omitempty"`
	Window     int      `json:"window,omitempty"`
	MSS        int      `json:"mss,omitempty"`
	PayloadHex string   `json:"payloadHex,omitempty"`

	// Application input.
	DataHex string `json:"dataHex,omitempty"`

	Expect tcpVectorExpect `json:"expect"`
}

type tcpVectorExpect struct {
	Segments   []tcpVectorSegment `json:"segments"`
	DeliverHex string             `json:"deliverHex,omitempty"`
	CloseApp   bool               `json:"closeApp,omitempty"`
	Done       bool               `json:"done,omitempty"`
	Reset      bool               `json:"reset,omitempty"`
	State      string             `json:"state"`
}

type tcpVectorSegment struct {
	Flags      []string `json:"flags"`
	Seq        uint32   `json:"seq"`
	Ack        uint32   `json:"ack"`
	Window     int      `json:"window"`
	MSS        int      `json:"mss,omitempty"`
	PayloadHex string   `json:"payloadHex,omitempty"`
}

var tcpVectorFlagNames = []struct {
	bit  uint8
	name string
}{
	{tcpFlagFIN, "FIN"}, {tcpFlagSYN, "SYN"}, {tcpFlagRST, "RST"},
	{tcpFlagPSH, "PSH"}, {tcpFlagACK, "ACK"},
}

func tcpVectorFlagsOf(flags uint8) []string {
	names := make([]string, 0, 3)
	for _, entry := range tcpVectorFlagNames {
		if flags&entry.bit != 0 {
			names = append(names, entry.name)
		}
	}
	return names
}

func tcpVectorFlagsFrom(names []string) uint8 {
	var flags uint8
	for _, name := range names {
		for _, entry := range tcpVectorFlagNames {
			if strings.EqualFold(name, entry.name) {
				flags |= entry.bit
			}
		}
	}
	return flags
}

// tcpVectorDriver replays one case's steps. The same driver both records and checks, so a scenario
// cannot be recorded through one code path and asserted through another.
type tcpVectorDriver struct {
	params tcpVectorParams
	conn   *tcpConn
	now    time.Time
	local  uint32
	remote uint32
}

func newTCPVectorDriver(t *testing.T, params tcpVectorParams) *tcpVectorDriver {
	t.Helper()
	return &tcpVectorDriver{
		params: params,
		now:    time.UnixMilli(params.EpochMs).UTC(),
		local:  testAddr(t, params.EgressIP),
		remote: testAddr(t, params.ConsumerIP),
	}
}

// run performs one step and returns what the stack produced.
func (d *tcpVectorDriver) run(t *testing.T, step tcpVectorStep) tcpVectorExpect {
	t.Helper()
	d.now = d.now.Add(time.Duration(step.AdvanceMs) * time.Millisecond)

	var output tcpOutput
	switch step.Do {
	case "segment":
		segment := tcpSegment{
			SourceIP: d.remote, DestinationIP: d.local,
			SourcePort: uint16(d.params.ConsumerPort), DestinationPort: uint16(d.params.TargetPort),
			Seq: step.Seq, Ack: step.Ack, Flags: tcpVectorFlagsFrom(step.Flags),
			Window: uint16(step.Window), MSS: step.MSS,
			Payload: decodeTCPVectorHex(t, step.PayloadHex),
		}
		if d.conn == nil {
			d.conn, output = acceptTCPSyn(segment, d.params.ISS, d.params.PathMTU,
				time.Duration(d.params.IdleTimeoutMs)*time.Millisecond, d.now)
		} else {
			output = d.conn.onSegment(segment, d.now)
		}
	case "appData":
		output = d.conn.onAppData(decodeTCPVectorHex(t, step.DataHex), d.now)
	case "appClose":
		output = d.conn.onAppClose(d.now)
	case "abort":
		output = d.conn.abort()
	case "tick":
		output = d.conn.onTick(d.now)
	default:
		t.Fatalf("unknown step %q", step.Do)
	}

	produced := tcpVectorExpect{
		Segments: make([]tcpVectorSegment, 0, len(output.Segments)),
		CloseApp: output.CloseApp, Done: output.Done, Reset: output.Reset,
		State: d.conn.state.String(),
	}
	if len(output.Deliver) > 0 {
		produced.DeliverHex = hex.EncodeToString(output.Deliver)
	}
	for _, packet := range output.Segments {
		segment, ok := parseTCPSegment(packet)
		if !ok {
			t.Fatal("the stack emitted a segment it cannot parse back")
		}
		entry := tcpVectorSegment{
			Flags: tcpVectorFlagsOf(segment.Flags), Seq: segment.Seq, Ack: segment.Ack,
			Window: int(segment.Window), MSS: segment.MSS,
		}
		if len(segment.Payload) > 0 {
			entry.PayloadHex = hex.EncodeToString(segment.Payload)
		}
		produced.Segments = append(produced.Segments, entry)
	}
	return produced
}

func decodeTCPVectorHex(t *testing.T, value string) []byte {
	t.Helper()
	if value == "" {
		return nil
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("bad hex %q: %v", value, err)
	}
	return raw
}

func tcpVectorPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 8; depth++ {
		candidate := filepath.Join(dir, "protocol", "test-vectors", tcpVectorName)
		if _, err := os.Stat(filepath.Dir(candidate)); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("cannot locate protocol/test-vectors")
	return ""
}

// TestTCPVectorMatchesTheStack replays every case and compares against the recorded fixture. With
// -update it rewrites the fixture instead, which is the only way it is ever produced.
func TestTCPVectorMatchesTheStack(t *testing.T) {
	if !*updateTCPVector {
		// The in-memory scenarios carry no expectations; they are the script, not the answer.
		// Checking is the file's job, so that what the Java and .NET ports read is the same thing
		// this repo asserts against.
		t.Skip("regeneration only; run with -update")
	}
	scenarios := tcpVectorScenarios()
	params := tcpVectorDefaultParams()

	recorded := tcpVectorFile{
		Name:    "peer-egress-tcp-v1",
		Version: 1,
		Notes: []string{
			"出口用户态 TCP 栈的脚本化一致性向量。每个 case 是一串步骤，逐步喂给状态机并断言它产生了什么。",
			"步骤类型：segment（消费端发来的段）、appData（真实 socket 收到的数据）、appClose（socket EOF）、abort、tick。",
			"advanceMs 是相对上一步的增量，各语言不必知道自己平台上的「现在」是什么。",
			"期望值录自 Go 实现，因此本向量证明的是三端一致，不是各自独立正确；正确性由 Go 侧逐条对照 RFC 的用例论证。",
			"Karn 算法这类只影响内部 RTO 估计、不体现在输出上的行为无法脚本化，留在 Go 的白盒用例里。",
		},
		Params: params,
		Cases:  make([]tcpVectorCase, 0, len(scenarios)),
	}

	for _, scenario := range scenarios {
		driver := newTCPVectorDriver(t, params)
		steps := make([]tcpVectorStep, 0, len(scenario.Steps))
		for index, step := range scenario.Steps {
			step.Expect = driver.run(t, step)
			steps = append(steps, step)
			_ = index
		}
		recorded.Cases = append(recorded.Cases, tcpVectorCase{
			Name: scenario.Name, Description: scenario.Description, Steps: steps,
		})
	}

	raw, err := json.MarshalIndent(recorded, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tcpVectorPath(t), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s with %d cases", tcpVectorName, len(recorded.Cases))
}

// TestTCPVectorFileMatchesTheScenarios reads the committed fixture rather than the in-memory
// scenarios, so a fixture that drifted from the code is caught even though both live in this repo.
// It is what the Java and .NET ports will be measured against.
func TestTCPVectorFileMatchesTheScenarios(t *testing.T) {
	var vector tcpVectorFile
	readEgressVector(t, tcpVectorName, &vector)
	if len(vector.Cases) == 0 {
		t.Fatal("the TCP vector carried no cases")
	}
	for _, testCase := range vector.Cases {
		driver := newTCPVectorDriver(t, vector.Params)
		for index, step := range testCase.Steps {
			assertVectorStep(t, testCase.Name, index, step.Expect, driver.run(t, step))
		}
	}
}

func assertVectorStep(t *testing.T, name string, index int, want, got tcpVectorExpect) {
	t.Helper()
	if got.State != want.State || got.DeliverHex != want.DeliverHex ||
		got.CloseApp != want.CloseApp || got.Done != want.Done || got.Reset != want.Reset {
		t.Errorf("%s step %d: state=%s deliver=%s closeApp=%v done=%v reset=%v, want %s/%s/%v/%v/%v",
			name, index, got.State, got.DeliverHex, got.CloseApp, got.Done, got.Reset,
			want.State, want.DeliverHex, want.CloseApp, want.Done, want.Reset)
		return
	}
	if len(got.Segments) != len(want.Segments) {
		t.Errorf("%s step %d: emitted %d segments, want %d", name, index, len(got.Segments), len(want.Segments))
		return
	}
	for position := range got.Segments {
		left, right := got.Segments[position], want.Segments[position]
		if strings.Join(left.Flags, "|") != strings.Join(right.Flags, "|") ||
			left.Seq != right.Seq || left.Ack != right.Ack ||
			left.Window != right.Window || left.MSS != right.MSS ||
			left.PayloadHex != right.PayloadHex {
			t.Errorf("%s step %d segment %d: %+v, want %+v", name, index, position, left, right)
		}
	}
}
