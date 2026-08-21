package client

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/protocol"
)

func TestRewriteUpstreamAuthorityHeadersMapsPublicOriginToLoopbackTarget(t *testing.T) {
	target, err := url.Parse("http://127.0.0.1:3210/app")
	if err != nil {
		t.Fatal(err)
	}
	headers := make(http.Header)
	headers.Set("Origin", "https://specus.devshuai.com")
	headers.Set("Referer", "https://specus.devshuai.com/http/client/dsh/")
	headers.Set("Sec-Fetch-Site", "cross-site")
	rewriteUpstreamAuthorityHeaders(headers, target)
	if got := headers.Get("Origin"); got != "http://127.0.0.1:3210" {
		t.Fatalf("Origin = %q", got)
	}
	if got := headers.Get("Referer"); got != "http://127.0.0.1:3210/http/client/dsh/" {
		t.Fatalf("Referer = %q", got)
	}
	if got := headers.Get("Sec-Fetch-Site"); got != "same-origin" {
		t.Fatalf("Sec-Fetch-Site = %q", got)
	}
}

func TestBuildTargetRejectsEscapesAndUnsupportedSchemes(t *testing.T) {
	target, err := buildTarget("http://127.0.0.1:8080/base", "/items", "x=1")
	if err != nil || target.String() != "http://127.0.0.1:8080/base/items?x=1" {
		t.Fatalf("buildTarget() = %v, %v", target, err)
	}
	for _, base := range []string{"", "file:///tmp", "http://127.0.0.1/base?x=1"} {
		if _, err := buildTarget(base, "/items", ""); err == nil {
			t.Fatalf("invalid base %q was accepted", base)
		}
	}
	if _, err := buildTarget("http://127.0.0.1/base", "/../admin", ""); err == nil {
		t.Fatal("escaping path was accepted")
	}
}

func TestBoundedRange(t *testing.T) {
	cases := map[string]string{
		"bytes=0-999999999": "bytes=0-8388607",
		"bytes=100-":        "bytes=100-8388707",
		"bytes=-999999999":  "bytes=-8388608",
		"bytes=0-1023":      "bytes=0-1023",
		"bytes=0-1,2-3":     "",
		"items=0-1":         "",
	}
	for input, expected := range cases {
		if actual := boundedRange(input); actual != expected {
			t.Fatalf("boundedRange(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestHTTPStreamForwardsRequestAndStreamsResponse(t *testing.T) {
	requestBody := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBody <- string(body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("streamed-response"))
	}))
	defer upstream.Close()

	specusClient := New(Config{}, log.New(io.Discard, "", 0))
	specusClient.syncHTTPSpecusConfigs([]HTTPSpecusConfig{{Route: "api", TargetBaseURL: upstream.URL}})
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	specusClient.openNatFlow(9)
	specusClient.openHTTPStream(clientConn, 9, map[string]any{
		"source": "http", "phase": "request", "method": "POST", "route": "api",
		"relativePath": "/upload", "rawQuery": "x=1", "headers": []any{"X-Test:yes"},
		"contentLength": 12,
	})
	dataHandled, dataAccepted := specusClient.writeHTTPData(9, []byte("request-body"))
	finHandled, finAccepted := specusClient.finishHTTPRequest(9, nil)
	if !dataHandled || !dataAccepted || !finHandled || !finAccepted {
		t.Fatal("HTTP request stream was not registered")
	}

	_ = serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var status int
	var response strings.Builder
	seenFin := false
	for !seenFin {
		packet, err := protocol.ReadPacket(serverConn)
		if err != nil {
			t.Fatalf("read response frame: %v", err)
		}
		if packet.Command != protocol.CommandNatMessage {
			continue
		}
		message, err := protocol.DecodeNatMessage(packet.Body)
		if err != nil {
			t.Fatalf("decode NAT frame: %v", err)
		}
		switch message.Type {
		case protocol.NatOpen:
			status, _ = metadataInt(message.Metadata, "statusCode")
		case protocol.NatData:
			response.Write(message.Data)
		case protocol.NatFin:
			seenFin = true
		case protocol.NatRST:
			t.Fatalf("HTTP stream reset: %+v", message.Metadata)
		}
	}
	if status != http.StatusCreated || response.String() != "streamed-response" {
		t.Fatalf("response = %d/%q", status, response.String())
	}
	select {
	case body := <-requestBody:
		if body != "request-body" {
			t.Fatalf("upstream body = %q", body)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream request was not received")
	}
}

func TestHTTPWindowUpdateAfterCompleteDoesNotCloseDataConnection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer upstream.Close()

	specusClient := New(Config{}, log.New(io.Discard, "", 0))
	specusClient.syncHTTPSpecusConfigs([]HTTPSpecusConfig{{Route: "dsh", TargetBaseURL: upstream.URL}})
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	specusClient.openNatFlow(12)
	specusClient.openHTTPStream(clientConn, 12, map[string]any{
		"source": "http", "phase": "request", "method": "GET", "route": "dsh",
		"relativePath": "/",
	})
	if handled, accepted := specusClient.finishHTTPRequest(12, nil); !handled || !accepted {
		t.Fatal("HTTP request stream was not registered")
	}

	_ = serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	seenFin := false
	for !seenFin {
		packet, err := protocol.ReadPacket(serverConn)
		if err != nil {
			t.Fatalf("read response frame: %v", err)
		}
		if packet.Command != protocol.CommandNatMessage {
			continue
		}
		message, err := protocol.DecodeNatMessage(packet.Body)
		if err != nil {
			t.Fatalf("decode NAT frame: %v", err)
		}
		if message.Type == protocol.NatRST {
			t.Fatalf("HTTP stream reset: %+v", message.Metadata)
		}
		if message.Type == protocol.NatFin {
			seenFin = true
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for specusClient.hasNatFlow(12) {
		if time.Now().After(deadline) {
			t.Fatal("HTTP stream did not release its NAT flow after FIN")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := handleNatForTest(specusClient, clientConn, protocol.NatMessage{
		Type: protocol.NatWindowUpdate, StreamID: 12, Value: uint32(len("<html>ok</html>")),
	}); err != nil {
		t.Fatalf("WINDOW_UPDATE after HTTP complete closed the data connection: %v", err)
	}
}

func TestRequestBodyReturnsCreditAfterChunkConsumption(t *testing.T) {
	credits := make(chan int, 1)
	body := newHTTPRequestBody(func(bytes int) { credits <- bytes })
	if !body.offer([]byte("hello")) {
		t.Fatal("offer failed")
	}
	body.finish(nil)
	buffer := make([]byte, 2)
	if _, err := body.Read(buffer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-credits:
		t.Fatal("credit returned before the whole chunk was consumed")
	default:
	}
	rest, err := io.ReadAll(body)
	if err != nil || string(append(buffer, rest...)) != "hello" {
		t.Fatalf("body = %q, err=%v", append(buffer, rest...), err)
	}
	select {
	case credit := <-credits:
		if credit != 5 {
			t.Fatalf("credit = %d", credit)
		}
	case <-time.After(time.Second):
		t.Fatal("credit was not returned")
	}
}

func TestHTTPDataEndStreamDeliversBodyBeforeFinishingRequest(t *testing.T) {
	control := &captureConn{}
	client := New(Config{}, log.New(io.Discard, "", 0))
	stream := newHTTPRequestStream(client, control, 10, nil)
	client.httpStreams[10] = stream
	payload := []byte("final-chunk")
	body, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type: protocol.NatData, StreamID: 10, Data: payload,
		Flags: protocol.NatFlagEndStream,
	})
	if err != nil {
		t.Fatalf("encode DATA|END_STREAM: %v", err)
	}

	if err := client.handleNatMessage(control, body); err != nil {
		t.Fatalf("handle DATA|END_STREAM: %v", err)
	}
	actual, err := io.ReadAll(stream.body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	if !bytes.Equal(actual, payload) {
		t.Fatalf("request body = %q, want %q", actual, payload)
	}
	control.Reset()

	duplicate, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type: protocol.NatFin, StreamID: 10,
	})
	if err != nil {
		t.Fatalf("encode duplicate FIN: %v", err)
	}
	if err := client.handleNatMessage(control, duplicate); err != nil {
		t.Fatalf("duplicate HTTP FIN closed the data connection: %v", err)
	}
	assertCapturedRST(t, control, 10)
	client.httpMu.Lock()
	remaining := client.httpStreams[10]
	client.httpMu.Unlock()
	if remaining != nil {
		t.Fatal("duplicate HTTP FIN must reset only the affected HTTP stream")
	}
}
