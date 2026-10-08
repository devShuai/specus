package server

import (
	"bufio"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

// A client that reads data login success may hand the server a public request at once, so the
// response must not leave before the data plane is attached. Otherwise the request finds the
// client online but has no stream namespace to open on (seen in CI as a 502 with no OPEN).
func TestDataLoginResponseWaitsForTheDataPlaneAttach(t *testing.T) {
	app, port := startTestApp(t)
	attaching := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAttach := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAttach)
	app.dispatcher.SetOnDataLoginSuccess(func(*control.Conn) {
		close(attaching)
		<-release
	})

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
	t.Cleanup(func() { controlConn.Close() })
	if err := protocol.WritePacket(controlConn, login); err != nil {
		t.Fatalf("write control login: %v", err)
	}
	if response, ok := readPacket(t, bufio.NewReader(controlConn)).(protocol.LoginResponse); !ok || !response.Success {
		t.Fatalf("control login response = %#v, want success", response)
	}

	dataConn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial data channel: %v", err)
	}
	t.Cleanup(func() { dataConn.Close() })
	login.ConnectionRole = protocol.ConnectionRoleData
	if err := protocol.WritePacket(dataConn, login); err != nil {
		t.Fatalf("write data login: %v", err)
	}
	select {
	case <-attaching:
	case <-time.After(5 * time.Second):
		t.Fatal("data login never reached the data-plane attach hook")
	}

	// The attach hook has not returned, so the response must not be readable yet.
	dataReader := bufio.NewReader(dataConn)
	_ = dataConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	var timeout net.Error
	if _, _, err := protocol.ReadFrame(dataReader); err == nil {
		t.Fatal("data login response was sent before the data plane was attached")
	} else if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read data login response during attach: %v", err)
	}

	releaseAttach()
	_ = dataConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if response, ok := readPacket(t, dataReader).(protocol.LoginResponse); !ok || !response.Success {
		t.Fatalf("data login response = %#v, want success", response)
	}
}
