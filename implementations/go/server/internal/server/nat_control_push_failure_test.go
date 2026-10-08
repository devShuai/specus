package server

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// natControlPushFailureVector is the existingOversize part of
// protocol/test-vectors/nat-control-size-v1.json.
type natControlPushFailureVector struct {
	ErrorContains    string `json:"errorContains"`
	ExistingOversize struct {
		JSONBytes     int `json:"jsonBytesWithEmptyClientName"`
		FillTargetMax int `json:"fillTargetBaseUrlMaxBytes"`
		Steps         []struct {
			Op            string `json:"op"`
			Route         string `json:"route"`
			TargetBaseURL string `json:"targetBaseUrl"`
			Enabled       bool   `json:"enabled"`
			Expect        int    `json:"expect"`
			NatControl    bool   `json:"natControl"`
		} `json:"steps"`
	} `json:"existingOversize"`
}

func readNatControlPushFailureVector(t *testing.T) natControlPushFailureVector {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 8; depth++ {
		data, err := os.ReadFile(filepath.Join(dir, "protocol", "test-vectors", "nat-control-size-v1.json"))
		if err == nil {
			var vector natControlPushFailureVector
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatalf("decode vector: %v", err)
			}
			return vector
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("cannot locate protocol/test-vectors/nat-control-size-v1.json")
	return natControlPushFailureVector{}
}

// controlRecorder keeps what a control connection receives: NAT_CONTROL bodies, PEER_CONTROL
// types, and whether the server closed it.
type controlRecorder struct {
	mu          sync.Mutex
	natControls []string
	peerTypes   []string
	closed      bool
}

func recordControl(reader *bufio.Reader) *controlRecorder {
	recorder := &controlRecorder{}
	go func() {
		for {
			packet, err := readProtocolPacket(reader)
			if err != nil {
				recorder.mu.Lock()
				recorder.closed = true
				recorder.mu.Unlock()
				return
			}
			message, ok := packet.(protocol.MessageResponse)
			if !ok {
				continue
			}
			recorder.mu.Lock()
			switch message.MessageType {
			case protocol.MessageTypeNatControl:
				recorder.natControls = append(recorder.natControls, message.Message)
			case protocol.MessageTypePeerControl:
				var signal struct {
					Type string `json:"type"`
				}
				_ = json.Unmarshal([]byte(message.Message), &signal)
				recorder.peerTypes = append(recorder.peerTypes, signal.Type)
			}
			recorder.mu.Unlock()
		}
	}()
	return recorder
}

func (r *controlRecorder) state() (natControls []string, peerTypes []string, closed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.natControls...), append([]string(nil), r.peerTypes...), r.closed
}

func awaitCondition(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not arrive within 5s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A client whose enabled routes, written straight to the database, take its NAT_CONTROL past the
// 1 MiB MESSAGE body: its control login stands and the Peer Mesh login push still arrives, the
// manual pushes answer 409, route changes are stored and answered as usual, and nothing reaches
// the connection, which stays open, until the configuration is back within the limit. Replays
// existingOversize of protocol/test-vectors/nat-control-size-v1.json.
func TestExistingOversizeNatControlIsNeitherSentNorDisconnecting(t *testing.T) {
	vector := readNatControlPushFailureVector(t)
	scenario := vector.ExistingOversize
	cfg := config.Default()
	cfg.PeerMesh.Enabled = true
	// Strict RFC 5780 without the addresses it needs keeps the STUN/TURN UDP server from starting,
	// so the test binds no UDP port.
	cfg.PeerMesh.StunBehaviorStrict = true
	app, port := startTestAppWithConfig(t, cfg)
	_, ts := newHTTPTestServer(t, app)
	token := adminToken(t, ts)
	ctx := context.Background()
	demo, err := app.db.FindClientByName(ctx, DemoClientName)
	if err != nil || demo == nil {
		t.Fatalf("load demo client: %+v %v", demo, err)
	}

	// Enough routes that their targets alone take the NAT_CONTROL JSON past jsonBytes.
	target := "http://127.0.0.1:8080/"
	target += strings.Repeat("f", scenario.FillTargetMax-len(target))
	count := (scenario.JSONBytes + scenario.FillTargetMax - 1) / scenario.FillTargetMax
	now := time.Now()
	first := store.HTTPRouteMapping{ID: 800_000, TenantID: demo.TenantID, ClientID: demo.ID,
		ClientName: demo.ClientName, Route: "fill-0000", TargetBaseURL: target, Enabled: true,
		CreatedAt: now, UpdatedAt: now}
	if err := app.db.InsertHTTPRoute(ctx, first); err != nil {
		t.Fatalf("insert %s: %v", first.Route, err)
	}
	// The rest are copies of the first in one transaction: one commit each would take minutes.
	direct, err := sql.Open("sqlite", app.cfg.ConnectionString)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	if _, err := direct.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		t.Fatal(err)
	}
	tx, err := direct.Begin()
	if err != nil {
		t.Fatal(err)
	}
	fillIDs := []int64{first.ID}
	for i := 1; i < count; i++ {
		id := first.ID + int64(i)
		if _, err := tx.Exec(`INSERT INTO http_route_mapping
			(id, tenant_id, client_id, client_name, route, target_base_url, enabled, detail_capture_enabled,
			 media_capture_enabled, path_rewrite_enabled, auth_enabled, auth_username, auth_password_hash,
			 created_at, updated_at)
			SELECT ?, tenant_id, client_id, client_name, ?, target_base_url, enabled, detail_capture_enabled,
			 media_capture_enabled, path_rewrite_enabled, auth_enabled, auth_username, auth_password_hash,
			 created_at, updated_at FROM http_route_mapping WHERE id = ?`,
			id, fmt.Sprintf("fill-%04d", i), first.ID); err != nil {
			t.Fatalf("copy route %d: %v", i, err)
		}
		fillIDs = append(fillIDs, id)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var recorder *controlRecorder
	var controlConn, dataConn net.Conn
	defer func() {
		for _, conn := range []net.Conn{controlConn, dataConn} {
			if conn != nil {
				conn.Close()
			}
		}
	}()
	for index, step := range scenario.Steps {
		label := fmt.Sprintf("step %d %s", index, step.Op)
		var response *http.Response
		switch step.Op {
		case "connect":
			session := issueClientSession(t, app, DemoClientName)
			var controlReader, dataReader *bufio.Reader
			controlConn, controlReader, dataConn, dataReader = loginControlAndDataChannels(t, port,
				protocol.LoginRequest{ClientName: DemoClientName, ClientSessionID: session.ID,
					AccessToken: session.AccessToken})
			go func() { _, _ = io.Copy(io.Discard, dataReader) }()
			recorder = recordControl(controlReader)
			awaitCondition(t, label+": the Peer Mesh login push", func() bool {
				_, peerTypes, _ := recorder.state()
				for _, peerType := range peerTypes {
					if peerType == "peer-config" {
						return true
					}
				}
				return false
			})
		case "pushNatControl":
			response = authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(demo.ID)+"/nat-control",
				token, "")
		case "forceRefreshPortMapping":
			response = authRequest(t, ts, http.MethodPost,
				"/api/admin/clients/"+itoa(demo.ID)+"/force-refresh-port-mapping", token, "")
		case "createRoute":
			body, _ := json.Marshal(map[string]any{"route": step.Route, "targetBaseUrl": step.TargetBaseURL,
				"enabled": step.Enabled})
			response = authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(demo.ID)+"/http-routes",
				token, string(body))
		case "deleteFillRoute":
			response = authRequest(t, ts, http.MethodDelete, "/api/admin/http-routes/"+itoa(fillIDs[0]), token, "")
			fillIDs = fillIDs[1:]
		case "shrinkInStore":
			if _, err := direct.Exec(`UPDATE http_route_mapping SET enabled = 0 WHERE id >= ? AND id < ?`,
				first.ID, first.ID+int64(count)); err != nil {
				t.Fatalf("%s: %v", label, err)
			}
		default:
			t.Fatalf("%s: unknown op", label)
		}

		if step.Expect != 0 {
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != step.Expect {
				t.Fatalf("%s: status %d %s, want %d", label, response.StatusCode, body, step.Expect)
			}
			if response.StatusCode == http.StatusConflict {
				var answer struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(body, &answer); err != nil || !strings.Contains(answer.Error, vector.ErrorContains) {
					t.Fatalf("%s: error %s does not name %s", label, body, vector.ErrorContains)
				}
			}
		}
		if recorder == nil {
			t.Fatalf("%s: not connected", label)
		}
		if step.NatControl {
			awaitCondition(t, label+": the NAT_CONTROL", func() bool {
				natControls, _, _ := recorder.state()
				return len(natControls) > 0
			})
			natControls, _, _ := recorder.state()
			var bean struct {
				HTTPRoutes []struct {
					Route string `json:"route"`
				} `json:"httpSpecusConfigList"`
			}
			if err := json.Unmarshal([]byte(natControls[0]), &bean); err != nil {
				t.Fatalf("%s: decode NAT_CONTROL: %v", label, err)
			}
			for _, route := range bean.HTTPRoutes {
				if strings.HasPrefix(route.Route, "fill-") {
					t.Fatalf("%s: the first NAT_CONTROL still lists %s", label, route.Route)
				}
			}
		} else {
			time.Sleep(300 * time.Millisecond)
			if natControls, _, _ := recorder.state(); len(natControls) != 0 {
				t.Fatalf("%s: %d NAT_CONTROL(s) reached the client", label, len(natControls))
			}
		}
		if _, _, closed := recorder.state(); closed {
			t.Fatalf("%s: the control connection was closed", label)
		}
	}
}
