package client

import (
	"bytes"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

// End to end: a hand-written consumer moves real bytes through the egress to a real socket.
//
// Everything between the consumer and the operating system is production code. The consumer builds
// and parses actual TCP segments, wraps them in actual SPEG1 frames, and the egress answers with a
// real connect() to a real listener over a real socket.
//
// One thing is substituted, and it is worth being precise about which. The listener has to live on
// loopback, and loopback is on the forced-deny list, so it cannot also be the destination the
// consumer asks for -- a test that named 127.0.0.1 would only ever prove the refusal. The consumer
// therefore asks for a routable address, authorization runs against that address exactly as it
// would in production, and only the final address translation is redirected to the listener. What
// this proves is the data path; the policy has its own suites.

// testConsumer is the hand-written consumer this phase is measured against. It keeps its own
// sequence space and never reaches into the egress state machine, so what it asserts is what a real
// consumer would observe on the wire.
type testConsumer struct {
	t        *testing.T
	runtime  *egressRuntime
	clientID int64

	consumerIP, remoteIP     uint32
	consumerPort, remotePort uint16

	mu        sync.Mutex
	seq       uint32
	ack       uint32
	received  []byte
	datagrams [][]byte
	finSeen   bool
	resetSeen bool
	rejects   []peerEgressControl
	inbound   []tcpSegment
}

func (c *testConsumer) onFrame(frame []byte) {
	parsed, code := parsePeerEgressFrame(frame)
	if code != "" {
		c.t.Errorf("the egress sent a frame that does not parse: %s", code)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if parsed.Type == peerEgressTypeControl {
		if control, ok := decodePeerEgressControl(parsed.Body); ok {
			c.rejects = append(c.rejects, control)
		}
		return
	}
	if datagram, ok := parseUDPDatagram(parsed.Body); ok {
		c.datagrams = append(c.datagrams, datagram.Payload)
		return
	}
	segment, ok := parseTCPSegment(parsed.Body)
	if !ok {
		c.t.Error("the egress sent a packet that is neither TCP nor UDP")
		return
	}
	c.inbound = append(c.inbound, segment)
	if segment.has(tcpFlagRST) {
		c.resetSeen = true
		return
	}
	if len(segment.Payload) > 0 {
		c.received = append(c.received, segment.Payload...)
		c.ack = segment.Seq + uint32(len(segment.Payload))
	}
	if segment.has(tcpFlagFIN) {
		c.finSeen = true
		c.ack = segment.Seq + segment.segmentLength()
	}
}

func (c *testConsumer) send(flags uint8, payload []byte) {
	c.mu.Lock()
	segment := tcpSegment{
		SourceIP: c.consumerIP, DestinationIP: c.remoteIP,
		SourcePort: c.consumerPort, DestinationPort: c.remotePort,
		Seq: c.seq, Ack: c.ack, Flags: flags, Window: 65535, Payload: payload,
	}
	c.seq += segment.segmentLength()
	c.mu.Unlock()
	c.runtime.handleFrame(c.clientID, encodePeerEgressFrame(peerEgressTypeIPPacket, false,
		buildTCPSegment(segment)), time.Now())
}

func (c *testConsumer) sendDatagram(payload []byte) {
	c.runtime.handleFrame(c.clientID, encodePeerEgressFrame(peerEgressTypeIPPacket, false,
		buildUDPDatagram(udpDatagram{
			SourceIP: c.consumerIP, DestinationIP: c.remoteIP,
			SourcePort: c.consumerPort, DestinationPort: c.remotePort, Payload: payload,
		})), time.Now())
}

func (c *testConsumer) snapshot() (data []byte, fin bool, reset bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.received...), c.finSeen, c.resetSeen
}

func (c *testConsumer) waitFor(what string, condition func() bool) {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	c.t.Fatalf("timed out waiting for %s", what)
}

// completeHandshake takes the flow to ESTABLISHED from the consumer's side.
func (c *testConsumer) completeHandshake() {
	c.t.Helper()
	c.send(tcpFlagSYN, nil)
	c.waitFor("the SYN-ACK", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, segment := range c.inbound {
			if segment.has(tcpFlagSYN) && segment.has(tcpFlagACK) {
				c.ack = segment.Seq + 1
				return true
			}
		}
		return false
	})
	c.send(tcpFlagACK, nil)
}

// startEgressAgainst builds a runtime whose dialer reaches the given listener while the policy and
// the consumer both speak the routable address.
func startEgressAgainst(t *testing.T, target string, destination string) (*egressRuntime, *testConsumer) {
	t.Helper()
	consumer := &testConsumer{
		t: t, clientID: 7,
		consumerIP:   testAddr(t, "100.96.0.1"),
		remoteIP:     testAddr(t, destination),
		consumerPort: 40000, remotePort: 443,
	}
	runtime := newEgressRuntime(log.New(io.Discard, "", 0),
		func(_ int64, frame []byte) error {
			consumer.onFrame(append([]byte(nil), frame...))
			return nil
		},
		func(protocol string, _ string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(protocol, target, timeout)
		})
	consumer.runtime = runtime
	runtime.applyPolicy(testEgressPolicy(destination+"/32"), newEgressContext(), time.Now())
	return runtime, consumer
}

// A byte in each direction and an orderly close, over a real socket.
func TestEgressCarriesTCPEndToEnd(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer listener.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		socket, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer socket.Close()
		buffer := make([]byte, 64)
		read, readErr := socket.Read(buffer)
		if readErr != nil {
			return
		}
		_, _ = socket.Write(append([]byte("echo:"), buffer[:read]...))
	}()

	runtime, consumer := startEgressAgainst(t, listener.Addr().String(), "203.0.113.10")
	defer runtime.shutdown(time.Now())

	consumer.completeHandshake()
	consumer.send(tcpFlagACK|tcpFlagPSH, []byte("hello"))

	consumer.waitFor("the echoed reply", func() bool {
		data, _, _ := consumer.snapshot()
		return bytes.Equal(data, []byte("echo:hello"))
	})
	<-served

	// The listener's handler returned, so its socket closed. That EOF must reach the consumer as a
	// FIN rather than as silence or a reset.
	consumer.waitFor("the FIN", func() bool {
		_, fin, _ := consumer.snapshot()
		return fin
	})
	if _, _, reset := consumer.snapshot(); reset {
		t.Error("an orderly close arrived as a reset")
	}

	consumer.send(tcpFlagACK|tcpFlagFIN, nil)

	// Both sides have now closed, so the flow sits in TIME_WAIT. Nothing outside this stack can
	// bind the four-tuple, but the window still has to outlive stragglers on the mesh path, so the
	// resources come back on the tick after it elapses rather than immediately. The runtime takes
	// its clock as an argument, which is what lets the wait be expressed rather than slept through.
	consumer.waitFor("the flow to reach TIME_WAIT", func() bool {
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		for _, flow := range runtime.flows.flows {
			if handle, ok := flow.Handle.(*egressTCPFlow); ok {
				return handle.conn.state == tcpStateTimeWait
			}
		}
		return runtime.flows.size() == 0
	})
	runtime.onTick(time.Now().Add(tcpTimeWaitDuration + time.Second))
	runtime.mu.Lock()
	remaining := runtime.flows.size()
	runtime.mu.Unlock()
	if remaining != 0 {
		t.Errorf("%d flows survived TIME_WAIT", remaining)
	}
}

// A larger transfer, so the path is exercised across MSS boundaries rather than in one segment.
func TestEgressCarriesTCPAcrossSegmentBoundaries(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer listener.Close()

	payload := bytes.Repeat([]byte("specus-egress-"), 512)
	go func() {
		socket, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer socket.Close()
		_, _ = socket.Write(payload)
	}()

	runtime, consumer := startEgressAgainst(t, listener.Addr().String(), "203.0.113.10")
	defer runtime.shutdown(time.Now())

	consumer.completeHandshake()
	consumer.waitFor("the whole transfer", func() bool {
		data, _, _ := consumer.snapshot()
		if len(data) < len(payload) {
			// Acknowledge what has arrived so the sender's window keeps opening.
			consumer.send(tcpFlagACK, nil)
			return false
		}
		return true
	})
	data, _, _ := consumer.snapshot()
	if !bytes.Equal(data, payload) {
		t.Errorf("received %d bytes, want %d", len(data), len(payload))
	}
	consumer.mu.Lock()
	segments := len(consumer.inbound)
	consumer.mu.Unlock()
	if segments < 3 {
		t.Errorf("the transfer arrived in %d segments; it was not split", segments)
	}
}

func TestEgressCarriesUDPEndToEnd(t *testing.T) {
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback socket available: %v", err)
	}
	defer socket.Close()

	go func() {
		buffer := make([]byte, 512)
		read, from, readErr := socket.ReadFrom(buffer)
		if readErr != nil {
			return
		}
		_, _ = socket.WriteTo(append([]byte("echo:"), buffer[:read]...), from)
	}()

	runtime, consumer := startEgressAgainst(t, socket.LocalAddr().String(), "203.0.113.53")
	defer runtime.shutdown(time.Now())
	consumer.remotePort = 53

	consumer.sendDatagram([]byte("query"))
	consumer.waitFor("the echoed datagram", func() bool {
		consumer.mu.Lock()
		defer consumer.mu.Unlock()
		return len(consumer.datagrams) > 0 && bytes.Equal(consumer.datagrams[0], []byte("echo:query"))
	})
}

// The refusal path over the same real machinery: no socket is opened and the consumer's own stack
// sees the reset, which is what an application actually waits on.
func TestEgressRefusesEndToEndWithoutOpeningASocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		if socket, acceptErr := listener.Accept(); acceptErr == nil {
			accepted <- struct{}{}
			_ = socket.Close()
		}
	}()

	runtime, consumer := startEgressAgainst(t, listener.Addr().String(), "203.0.113.10")
	defer runtime.shutdown(time.Now())
	// Ask for an address the policy does not cover.
	consumer.remoteIP = testAddr(t, "198.51.100.10")

	consumer.send(tcpFlagSYN, nil)
	consumer.waitFor("the reset", func() bool {
		_, _, reset := consumer.snapshot()
		return reset
	})

	consumer.mu.Lock()
	rejects := append([]peerEgressControl(nil), consumer.rejects...)
	consumer.mu.Unlock()
	if len(rejects) != 1 || rejects[0].Code != egressCodeDestinationDenied {
		t.Errorf("flow-reject = %+v", rejects)
	}
	select {
	case <-accepted:
		t.Error("a refused flow reached the listener")
	default:
	}
}
