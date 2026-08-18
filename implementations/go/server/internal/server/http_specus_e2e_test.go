package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestHTTPDataChannelStreamsFragmentedResponse(t *testing.T) {
	app, port := startTestApp(t)
	account, err := app.db.FindClientByName(context.Background(), DemoClientName)
	if err != nil || account == nil {
		t.Fatalf("load demo client: account=%+v err=%v", account, err)
	}
	now := time.Now().UTC()
	if err := app.db.InsertHTTPRoute(context.Background(), store.HTTPRouteMapping{
		ID: auth.NewClientID(), TenantID: account.TenantID, ClientID: account.ID, ClientName: account.ClientName,
		Route: "web", TargetBaseURL: "http://127.0.0.1:8080", Enabled: true,
		AuthEnabled: true, AuthUsername: "e2e-user", AuthPasswordHash: auth.HashToken("e2e-password"),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("insert protected HTTP route: %v", err)
	}
	controlConn, dataConn, dataReader := loginHTTPTestChannels(t, app, port)
	defer controlConn.Close()
	defer dataConn.Close()

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
	unauthorized, err := httpClient.Get(management.URL + "/http/Demo%20client/web/fragmented")
	if err != nil {
		t.Fatalf("unauthenticated HTTP specus request: %v", err)
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated HTTP specus status = %d, want 401", unauthorized.StatusCode)
	}
	request, err := http.NewRequest(http.MethodGet, management.URL+"/http/Demo%20client/web/fragmented", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("e2e-user", "e2e-password")
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatalf("HTTP specus request: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read HTTP specus response: %v", err)
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

func TestDataChannelResetsUnknownDataAndFinAndIgnoresLateRST(t *testing.T) {
	app, port := startTestApp(t)
	controlConn, dataConn, dataReader := loginHTTPTestChannels(t, app, port)
	defer controlConn.Close()
	defer dataConn.Close()

	const dataStreamID = uint32(0x7ffffff0)
	if err := protocol.WritePacket(dataConn, protocol.NatMessage{
		Type: protocol.NatData, StreamID: dataStreamID, Data: []byte("unknown"),
	}); err != nil {
		t.Fatalf("write unknown DATA: %v", err)
	}
	_ = dataConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	assertDataChannelRST(t, dataReader, dataStreamID)

	const finStreamID = dataStreamID + 1
	if err := protocol.WritePacket(dataConn, protocol.NatMessage{
		Type: protocol.NatFin, StreamID: finStreamID,
	}); err != nil {
		t.Fatalf("write unknown FIN: %v", err)
	}
	assertDataChannelRST(t, dataReader, finStreamID)

	// The RST acknowledges the reset triggered above and must be idempotent.
	if err := protocol.WritePacket(dataConn, protocol.NatMessage{
		Type: protocol.NatRST, StreamID: dataStreamID,
	}); err != nil {
		t.Fatalf("write late RST: %v", err)
	}
	const probeStreamID = dataStreamID + 2
	if err := protocol.WritePacket(dataConn, protocol.NatMessage{
		Type: protocol.NatFin, StreamID: probeStreamID,
	}); err != nil {
		t.Fatalf("write post-RST probe FIN: %v", err)
	}
	assertDataChannelRST(t, dataReader, probeStreamID)
}

func TestDataChannelClosesForRSTOnNeverOpenedStream(t *testing.T) {
	app, port := startTestApp(t)
	controlConn, dataConn, dataReader := loginHTTPTestChannels(t, app, port)
	defer controlConn.Close()
	defer dataConn.Close()

	if err := protocol.WritePacket(dataConn, protocol.NatMessage{
		Type: protocol.NatRST, StreamID: 0x7fffffe0,
	}); err != nil {
		t.Fatalf("write never-opened RST: %v", err)
	}
	_ = dataConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readProtocolPacket(dataReader); err == nil {
		t.Fatal("data channel remained open after RST for a never-opened stream")
	}
}

func assertDataChannelRST(t *testing.T, reader *bufio.Reader, streamID uint32) {
	t.Helper()
	packet, err := readProtocolPacket(reader)
	if err != nil {
		t.Fatalf("read RST for stream %d: %v", streamID, err)
	}
	message, ok := packet.(protocol.NatMessage)
	if !ok || message.Type != protocol.NatRST || message.StreamID != streamID {
		t.Fatalf("response = %#v, want NAT RST for stream %d", packet, streamID)
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
