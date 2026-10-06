package client

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/protocol"
)

var allHTTPRouteFailures = []httpRouteFailure{
	httpRouteFailureRouteNotLoaded, httpRouteFailureTargetInvalid, httpRouteFailureConnectRefused,
	httpRouteFailureConnectTimeout, httpRouteFailureDNSFailed, httpRouteFailureTLSFailed,
	httpRouteFailureUnreachable, httpRouteFailureProtocolError,
}

// The failure names are the contract with every server, which keys its stage codes on them; the
// shared vector lists the closed set.
func TestHTTPRouteFailuresAreTheConnectivityVectorSet(t *testing.T) {
	var vector struct {
		RSTFailures map[string]json.RawMessage `json:"rstFailures"`
	}
	readRepositoryJSON(t, "protocol/test-vectors/service-connectivity-check-v1.json", &vector)
	if len(vector.RSTFailures) != len(allHTTPRouteFailures) {
		t.Fatalf("vector has %d failures, the client %d", len(vector.RSTFailures), len(allHTTPRouteFailures))
	}
	for _, failure := range allHTTPRouteFailures {
		if _, ok := vector.RSTFailures[string(failure)]; !ok {
			t.Errorf("failure %q is not in the vector's rstFailures", failure)
		}
	}
}

func TestLoginEnvironmentAnnouncesHTTPRouteCapability(t *testing.T) {
	encoded, err := json.Marshal(collectEnvironment())
	if err != nil {
		t.Fatalf("marshal environment: %v", err)
	}
	var wire struct {
		Capabilities *struct {
			Version *int `json:"version"`
		} `json:"clientHttpRouteCapabilities"`
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("unmarshal environment: %v", err)
	}
	if wire.Capabilities == nil || wire.Capabilities.Version == nil {
		t.Fatal("the login environment carries no clientHttpRouteCapabilities.version")
	}
	// A server trusts metadata.failure only from a session that announced version 1.
	if *wire.Capabilities.Version != 1 {
		t.Fatalf("clientHttpRouteCapabilities.version = %d, want 1", *wire.Capabilities.Version)
	}
}

// Each case produces the failure for real, on loopback or with an in-process resolver, and
// forwards through the same client the HTTP stream uses.
func TestClassifyUpstreamFailureFromRealErrors(t *testing.T) {
	cases := []struct {
		name   string
		target func(t *testing.T) (string, forwardingDial)
		want   httpRouteFailure
	}{
		{"closed port", func(t *testing.T) (string, forwardingDial) {
			return "http://" + closedLoopbackAddress(t), defaultForwardingDial()
		}, httpRouteFailureConnectRefused},
		{"name that does not resolve", func(t *testing.T) (string, forwardingDial) {
			dial := defaultForwardingDial()
			dial.resolver = nxdomainResolver()
			return "http://specus-connectivity-check.invalid:8080", dial
		}, httpRouteFailureDNSFailed},
		{"connect that never completes", func(t *testing.T) (string, forwardingDial) {
			return "http://" + listeningLoopbackAddress(t, nil), heldConnectDial()
		}, httpRouteFailureConnectTimeout},
		{"TLS handshake that never completes", func(t *testing.T) (string, forwardingDial) {
			dial := defaultForwardingDial()
			dial.connectTimeout = 300 * time.Millisecond
			return "https://" + listeningLoopbackAddress(t, silentUpstream), dial
		}, httpRouteFailureConnectTimeout},
		{"https to a plain HTTP server", func(t *testing.T) (string, forwardingDial) {
			return "https://" + httpServerAddress(t, false), defaultForwardingDial()
		}, httpRouteFailureTLSFailed},
		{"untrusted certificate", func(t *testing.T) (string, forwardingDial) {
			return "https://" + httpServerAddress(t, true), defaultForwardingDial()
		}, httpRouteFailureTLSFailed},
		{"closed before the response head", func(t *testing.T) (string, forwardingDial) {
			return "http://" + listeningLoopbackAddress(t, closingUpstream), defaultForwardingDial()
		}, httpRouteFailureProtocolError},
		{"reset before the response head", func(t *testing.T) (string, forwardingDial) {
			return "http://" + listeningLoopbackAddress(t, resettingUpstream), defaultForwardingDial()
		}, httpRouteFailureProtocolError},
		{"malformed status line", func(t *testing.T) (string, forwardingDial) {
			return "http://" + listeningLoopbackAddress(t, malformedUpstream), defaultForwardingDial()
		}, httpRouteFailureProtocolError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, dial := tc.target(t)
			client := newForwardingHTTPClientWithDial(newUpstreamTLSFactory(UpstreamTLSConfig{}), false, dial)
			progress, err := forwardForTest(t, client, target)
			t.Logf("%T: %v", errors.Unwrap(err), err)
			if got := classifyUpstreamFailure(err, progress); got != tc.want {
				t.Fatalf("classifyUpstreamFailure(%v) = %q, want %q", err, got, tc.want)
			}
		})
	}
}

// A target that connects and then says nothing is not a refused, broken or invalid target, and a
// timeout waiting for its head is left unclassified.
func TestClassifyUpstreamFailureLeavesResponseHeadTimeoutUnclassified(t *testing.T) {
	client := newForwardingHTTPClientWithDial(newUpstreamTLSFactory(UpstreamTLSConfig{}), false,
		defaultForwardingDial())
	client.Transport.(*http.Transport).ResponseHeaderTimeout = 200 * time.Millisecond
	progress, err := forwardForTest(t, client, "http://"+listeningLoopbackAddress(t, silentUpstream))
	if err == nil || !progress.connected.Load() {
		t.Fatalf("expected a timeout after connecting, got %v (connected=%v)", err, progress.connected.Load())
	}
	if got := classifyUpstreamFailure(err, progress); got != "" {
		t.Fatalf("classifyUpstreamFailure(%v) = %q, want none", err, got)
	}
}

// Unreachable networks cannot be produced on loopback; these are the errors the dialer returns,
// built with this platform's errno values.
func TestClassifyDialErrnosOfThisPlatform(t *testing.T) {
	expect := func(errnos []syscall.Errno, want httpRouteFailure) {
		for _, errno := range errnos {
			err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
			if got := classifyUpstreamFailure(err, &upstreamProgress{}); got != want {
				t.Errorf("errno %d: got %q, want %q", errno, got, want)
			}
		}
	}
	expect(connectRefusedErrnos, httpRouteFailureConnectRefused)
	expect(connectTimeoutErrnos, httpRouteFailureConnectTimeout)
	expect(unreachableErrnos, httpRouteFailureUnreachable)
	// An errno outside the tables, such as a local permission failure, is not guessed at.
	other := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EACCES)}
	if got := classifyUpstreamFailure(other, &upstreamProgress{}); got != "" {
		t.Errorf("EACCES: got %q, want none", got)
	}
	if got := classifyUpstreamFailure(errors.New("something else"), &upstreamProgress{}); got != "" {
		t.Errorf("unknown error: got %q, want none", got)
	}
}

// The RST written on the data connection carries the failure next to the value and reason it
// always had; failures outside the set carry no failure key at all.
func TestHTTPStreamResetCarriesFailure(t *testing.T) {
	cases := []struct {
		name    string
		routes  []HTTPSpecusConfig
		dial    func(t *testing.T) forwardingDial
		target  func(t *testing.T) string
		open    map[string]any
		value   uint32
		failure httpRouteFailure
	}{
		{name: "route missing", value: 24, failure: httpRouteFailureRouteNotLoaded},
		{name: "route without target", routes: []HTTPSpecusConfig{{Route: "api"}},
			value: 24, failure: httpRouteFailureRouteNotLoaded},
		{name: "unusable target", routes: []HTTPSpecusConfig{{Route: "api", TargetBaseURL: "ftp://127.0.0.1/"}},
			value: 24, failure: httpRouteFailureTargetInvalid},
		{name: "refused", target: func(t *testing.T) string { return "http://" + closedLoopbackAddress(t) },
			value: 26, failure: httpRouteFailureConnectRefused},
		{name: "name not found", target: func(*testing.T) string { return "http://specus-connectivity-check.invalid" },
			dial: func(*testing.T) forwardingDial {
				dial := defaultForwardingDial()
				dial.resolver = nxdomainResolver()
				return dial
			}, value: 26, failure: httpRouteFailureDNSFailed},
		{name: "connect timeout", target: func(t *testing.T) string { return "http://" + listeningLoopbackAddress(t, nil) },
			dial: func(*testing.T) forwardingDial { return heldConnectDial() }, value: 26,
			failure: httpRouteFailureConnectTimeout},
		{name: "tls", target: func(t *testing.T) string { return "https://" + httpServerAddress(t, false) },
			value: 26, failure: httpRouteFailureTLSFailed},
		{name: "closed before head", target: func(t *testing.T) string {
			return "http://" + listeningLoopbackAddress(t, closingUpstream)
		}, value: 26, failure: httpRouteFailureProtocolError},
		{name: "malformed request", open: map[string]any{"route": "api"}, value: 23},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			specusClient := New(Config{}, log.New(io.Discard, "", 0))
			routes := tc.routes
			if tc.target != nil {
				routes = []HTTPSpecusConfig{{Route: "api", TargetBaseURL: tc.target(t)}}
			}
			specusClient.syncHTTPSpecusConfigs(routes)
			dial := defaultForwardingDial()
			if tc.dial != nil {
				dial = tc.dial(t)
			}
			specusClient.forwardHTTP = newForwardingHTTPClientWithDial(specusClient.upstreamTLSFactory(), false, dial)
			open := tc.open
			if open == nil {
				open = map[string]any{"method": "HEAD", "route": "api", "relativePath": "/"}
			}
			metadata := map[string]any{"source": "http", "phase": "request"}
			for key, value := range open {
				metadata[key] = value
			}

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			streamID := uint32(100 + index)
			specusClient.openNatFlow(streamID)
			specusClient.openHTTPStream(clientConn, streamID, metadata)
			specusClient.finishHTTPRequest(streamID, nil)

			reset := readHTTPStreamReset(t, serverConn, streamID)
			if reset.Value != tc.value {
				t.Errorf("RST value = %d, want %d", reset.Value, tc.value)
			}
			if reason, _ := reset.Metadata["reason"].(string); strings.TrimSpace(reason) == "" {
				t.Errorf("RST lost its reason: %v", reset.Metadata)
			}
			failure, present := reset.Metadata["failure"]
			if tc.failure == "" {
				if present {
					t.Fatalf("RST carries failure %v for an unclassified failure", failure)
				}
				return
			}
			if failure != string(tc.failure) {
				t.Fatalf("RST failure = %v, want %q (metadata %v)", failure, tc.failure, reset.Metadata)
			}
		})
	}
}

func readHTTPStreamReset(t *testing.T, connection net.Conn, streamID uint32) protocol.NatMessage {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		packet, err := protocol.ReadPacket(connection)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if packet.Command != protocol.CommandNatMessage {
			continue
		}
		message, err := protocol.DecodeNatMessage(packet.Body)
		if err != nil {
			t.Fatalf("decode NAT frame: %v", err)
		}
		if message.StreamID != streamID {
			continue
		}
		switch message.Type {
		case protocol.NatRST:
			return message
		case protocol.NatOpen:
			t.Fatalf("stream answered with a response head: %v", message.Metadata)
		}
	}
}

func forwardForTest(t *testing.T, client *http.Client, target string) (*upstreamProgress, error) {
	t.Helper()
	progress := &upstreamProgress{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, progress.trace()),
		http.MethodHead, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err == nil {
		response.Body.Close()
		t.Fatalf("%s answered %d", target, response.StatusCode)
	}
	if ctx.Err() != nil {
		t.Fatalf("test deadline reached: %v", err)
	}
	return progress, err
}

func defaultForwardingDial() forwardingDial {
	return forwardingDial{connectTimeout: upstreamConnectTimeout}
}

// heldConnectDial holds every connect until its deadline has passed, as a SYN that is never
// answered would, so the dialer's own timeout fires.
func heldConnectDial() forwardingDial {
	return forwardingDial{
		connectTimeout: 200 * time.Millisecond,
		control: func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
			<-ctx.Done()
			return nil
		},
	}
}

func closedLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

// listeningLoopbackAddress serves each accepted connection with handle, or leaves it unread.
func listeningLoopbackAddress(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var accepted []net.Conn
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range accepted {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, conn)
			mu.Unlock()
			if handle != nil {
				go handle(conn)
			}
		}
	}()
	return listener.Addr().String()
}

func httpServerAddress(t *testing.T, tls bool) string {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	if tls {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

func silentUpstream(conn net.Conn) {
	_, _ = io.Copy(io.Discard, conn)
}

func readRequestHead(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			return
		}
	}
}

func closingUpstream(conn net.Conn) {
	readRequestHead(conn)
	_ = conn.Close()
}

func resettingUpstream(conn net.Conn) {
	readRequestHead(conn)
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = conn.Close()
}

func malformedUpstream(conn net.Conn) {
	readRequestHead(conn)
	_, _ = conn.Write([]byte("SPECUS-NOT-HTTP\r\n\r\n"))
	_ = conn.Close()
}

// nxdomainResolver is the Go resolver talking to an in-process server that answers every query
// NXDOMAIN, so a lookup fails the way a missing name does without a packet leaving the host.
func nxdomainResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go answerNXDOMAIN(server)
			return client, nil
		},
	}
}

// answerNXDOMAIN serves DNS over a stream connection (two-byte length prefix), echoing each query
// with QR, RA and RCODE 3 set so the question and any EDNS record match what was asked.
func answerNXDOMAIN(conn net.Conn) {
	defer conn.Close()
	for {
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, query); err != nil || len(query) < 12 {
			return
		}
		reply := slices.Clone(query)
		reply[2] = 0x80 | query[2]&0x79 // QR, keep opcode and RD
		reply[3] = 0x80 | 0x03          // RA, NXDOMAIN
		if _, err := conn.Write(append(length[:], reply...)); err != nil {
			return
		}
	}
}
