package server

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/protocol"
)

func TestHTTPDataChannelSurvivesUnknownFrameAndStreamsFragmentedResponse(t *testing.T) {
	app, port := startTestApp(t)
	controlConn, dataConn, dataReader := loginHTTPTestChannels(t, app, port)
	defer controlConn.Close()
	defer dataConn.Close()

	// A cancelled HTTP/WS stream can leave an in-flight tail frame. Java ignores it,
	// and a following heartbeat proves Go keeps the authenticated data channel alive.
	if err := protocol.WritePacket(dataConn, protocol.NatMessage{
		Type: protocol.NatData, StreamID: 0x7ffffff0, Data: []byte("late"),
	}); err != nil {
		t.Fatalf("write unknown DATA: %v", err)
	}
	if err := protocol.WritePacket(dataConn, protocol.HeartbeatRequest{}); err != nil {
		t.Fatalf("write data heartbeat: %v", err)
	}
	_ = dataConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		packet, err := readProtocolPacket(dataReader)
		if err != nil {
			t.Fatalf("read data heartbeat: %v", err)
		}
		if _, ok := packet.(protocol.HeartbeatResponse); ok {
			break
		}
	}
	_ = dataConn.SetReadDeadline(time.Time{})

	const responseSize = 1024 * 1024
	wantBody := bytes.Repeat([]byte("0123456789abcdef"), responseSize/16)
	clientErr := make(chan error, 1)
	go func() {
		for {
			packet, err := readProtocolPacket(dataReader)
			if err != nil {
				clientErr <- err
				return
			}
			message, ok := packet.(protocol.NatMessage)
			if !ok || message.Type != protocol.NatOpen ||
				fmt.Sprint(message.Metadata["source"]) != "http" {
				continue
			}
			if err := protocol.WritePacket(dataConn, protocol.NatMessage{
				Type: protocol.NatOpen, StreamID: message.StreamID,
				Metadata: map[string]any{
					"source": "http", "phase": "response", "statusCode": 200,
					"headers": []string{
						"Content-Type:application/octet-stream",
						"Content-Security-Policy:script-src 'self' 'unsafe-eval'",
					},
				},
			}); err != nil {
				clientErr <- err
				return
			}
			for offset := 0; offset < len(wantBody); offset += 4096 {
				end := min(offset+4096, len(wantBody))
				if err := protocol.WritePacket(dataConn, protocol.NatMessage{
					Type: protocol.NatData, StreamID: message.StreamID, Data: wantBody[offset:end],
				}); err != nil {
					clientErr <- err
					return
				}
			}
			clientErr <- protocol.WritePacket(dataConn, protocol.NatMessage{
				Type: protocol.NatFin, StreamID: message.StreamID,
			})
			return
		}
	}()

	_, management := newHTTPTestServer(t, app)
	httpClient := &http.Client{Timeout: 15 * time.Second}
	response, err := httpClient.Get(management.URL + "/http/Demo%20client/web/fragmented")
	if err != nil {
		t.Fatalf("HTTP tunnel request: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read HTTP tunnel response: %v", err)
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, wantBody) {
		t.Fatalf("response status/body = %d/%d bytes, want 200/%d", response.StatusCode, len(body), len(wantBody))
	}
	if got := response.Header.Values("Content-Security-Policy"); len(got) != 1 ||
		got[0] != "script-src 'self' 'unsafe-eval'" {
		t.Fatalf("response CSP = %#v, want only target application policy", got)
	}
	if err := <-clientErr; err != nil {
		t.Fatalf("HTTP data client: %v", err)
	}
}

func loginHTTPTestChannels(
	t *testing.T,
	app *App,
	port int,
) (net.Conn, net.Conn, *bufio.Reader) {
	t.Helper()
	session := issueClientSession(t, app, DemoClientName)
	login := protocol.LoginRequest{
		ClientName:      DemoClientName,
		ClientSessionID: session.ID,
		AccessToken:     session.AccessToken,
		ConnectionRole:  protocol.ConnectionRoleControl,
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	controlConn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial control channel: %v", err)
	}
	if err := protocol.WritePacket(controlConn, login); err != nil {
		controlConn.Close()
		t.Fatalf("write control login: %v", err)
	}
	controlReader := bufio.NewReader(controlConn)
	controlResponse, err := readProtocolPacket(controlReader)
	if err != nil {
		controlConn.Close()
		t.Fatalf("read control login: %v", err)
	}
	if response, ok := controlResponse.(protocol.LoginResponse); !ok || !response.Success {
		controlConn.Close()
		t.Fatalf("control login rejected: %#v", controlResponse)
	}

	dataConn, err := net.Dial("tcp", address)
	if err != nil {
		controlConn.Close()
		t.Fatalf("dial data channel: %v", err)
	}
	login.ConnectionRole = protocol.ConnectionRoleData
	if err := protocol.WritePacket(dataConn, login); err != nil {
		controlConn.Close()
		dataConn.Close()
		t.Fatalf("write data login: %v", err)
	}
	dataReader := bufio.NewReader(dataConn)
	dataResponse, err := readProtocolPacket(dataReader)
	if err != nil {
		controlConn.Close()
		dataConn.Close()
		t.Fatalf("read data login: %v", err)
	}
	if response, ok := dataResponse.(protocol.LoginResponse); !ok || !response.Success {
		controlConn.Close()
		dataConn.Close()
		t.Fatalf("data login rejected: %#v", dataResponse)
	}
	return controlConn, dataConn, dataReader
}

func readProtocolPacket(reader *bufio.Reader) (protocol.Packet, error) {
	command, body, err := protocol.ReadFrame(reader)
	if err != nil {
		return nil, err
	}
	return protocol.Decode(command, body)
}
