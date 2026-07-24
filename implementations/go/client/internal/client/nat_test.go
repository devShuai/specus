package client

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

func TestConnectLocalTunnelIgnoresInvalidTcpConnectedLikeJava(t *testing.T) {
	cases := []struct {
		name     string
		metadata map[string]any
	}{
		{
			name:     "missing port",
			metadata: map[string]any{"channelId": "channel-1"},
		},
		{
			name:     "missing channel id",
			metadata: map[string]any{"port": float64(10022)},
		},
		{
			name:     "unknown port",
			metadata: map[string]any{"channelId": "channel-1", "port": float64(10022)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			control := &captureConn{}
			tunnelClient := New(Config{}, log.New(io.Discard, "", 0))

			tunnelClient.openNatFlow(1)
			tunnelClient.connectLocalTunnel(control, 1, tc.metadata)

			if control.Len() != 0 {
				t.Fatalf("control connection wrote %d bytes, want no DISCONNECTED frame", control.Len())
			}
		})
	}
}

func TestNatMetadataHelpersMatchJavaCoercion(t *testing.T) {
	text, err := metadataString(map[string]any{"channelId": 12345}, "channelId")
	if err != nil {
		t.Fatalf("metadataString() error = %v", err)
	}
	if text != "12345" {
		t.Fatalf("metadataString() = %q, want Java toString value", text)
	}

	for _, tc := range []struct {
		name  string
		value any
		want  int
	}{
		{name: "string", value: "10022", want: 10022},
		{name: "json-number", value: json.Number("10023"), want: 10023},
		{name: "float", value: float64(10024.9), want: 10024},
		{name: "int64", value: int64(10025), want: 10025},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := metadataInt(map[string]any{"port": tc.value}, "port")
			if err != nil {
				t.Fatalf("metadataInt() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("metadataInt() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRegisterFailureClearsPortForRetryWithoutClosingSession(t *testing.T) {
	tunnelClient := New(Config{}, log.New(io.Discard, "", 0))
	tunnelClient.registered[19090] = struct{}{}

	tunnelClient.handleNatRegisterResult(map[string]any{
		"port":    19090,
		"success": false,
		"reason":  "address already in use",
	})

	tunnelClient.registeredMu.Lock()
	_, stillRegistered := tunnelClient.registered[19090]
	tunnelClient.registeredMu.Unlock()
	if stillRegistered {
		t.Fatal("failed NAT port must be cleared so a later config refresh can retry it")
	}
}

type captureConn struct {
	bytes.Buffer
}

func (conn *captureConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (conn *captureConn) Close() error {
	return nil
}

func (conn *captureConn) LocalAddr() net.Addr {
	return captureAddr("local")
}

func (conn *captureConn) RemoteAddr() net.Addr {
	return captureAddr("remote")
}

func (conn *captureConn) SetDeadline(_ time.Time) error {
	return nil
}

func (conn *captureConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (conn *captureConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type captureAddr string

func (addr captureAddr) Network() string {
	return string(addr)
}

func (addr captureAddr) String() string {
	return string(addr)
}
