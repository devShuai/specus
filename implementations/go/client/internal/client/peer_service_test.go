package client

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPeerServiceRuntimeDoesNotProbeWhenSharingOff(t *testing.T) {
	port, listener := mustListen(t)
	defer listener.Close()
	sent := &sentReports{}
	runtime := newPeerServiceRuntime(nil, sent.append)
	runtime.setHasAuthorizedOnlinePeer(true)
	runtime.applyConfig(testPeerMeshConfig(false, port, true))
	time.Sleep(40 * time.Millisecond)
	if sent.len() != 0 {
		t.Fatalf("unexpected reports: %v", sent.snapshot())
	}
}

func TestPeerServiceRuntimeDoesNotProbeWithoutOnlinePeer(t *testing.T) {
	port, listener := mustListen(t)
	defer listener.Close()
	sent := &sentReports{}
	runtime := newPeerServiceRuntime(nil, sent.append)
	runtime.setHasAuthorizedOnlinePeer(false)
	runtime.applyConfig(testPeerMeshConfig(true, port, true))
	time.Sleep(40 * time.Millisecond)
	if sent.len() != 0 {
		t.Fatalf("unexpected reports: %v", sent.snapshot())
	}
}

func TestPeerServiceRuntimeReportsReachableServiceWithoutTargetHost(t *testing.T) {
	port, listener := mustListen(t)
	defer listener.Close()
	sent := &sentReports{}
	runtime := newPeerServiceRuntime(nil, sent.append)
	runtime.setRoster(map[int64]peerServiceRosterHint{2: {virtualIP: "100.96.0.2", online: true}})
	runtime.setHasAuthorizedOnlinePeer(true)
	runtime.applyConfig(testPeerMeshConfig(true, port, true))
	waitUntil(t, func() bool { return sent.len() > 0 })
	body := sent.snapshot()[0]
	if !strings.Contains(body, "service-report") || !strings.Contains(body, "svc-http01") {
		t.Fatalf("report = %s", body)
	}
	if strings.Contains(body, "targetHost") {
		t.Fatalf("catalog payload must not include targetHost: %s", body)
	}

	sessionID := int64(9)
	runtime.applyCatalog(peerControlMessage{
		Type:                peerControlTypeServiceCatalog,
		PublisherClientID:   2,
		PublisherClientName: "client-b",
		PublisherSessionID:  &sessionID,
		ExpiresAt:           time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		Services: []peerAdvertisedService{{
			ServiceID: "svc-http01", Name: "web", Transport: "tcp", Application: "http",
			PublishedPort: 8080, Path: "/app",
		}},
	})
	views := runtime.remoteServices()
	if len(views) != 1 {
		t.Fatalf("views = %#v", views)
	}
	if !views[0].Openable || views[0].AccessTarget != "http://100.96.0.2:8080/app" {
		t.Fatalf("view = %#v", views[0])
	}
	if strings.Contains(views[0].AccessTarget, "evil") {
		t.Fatal("access URL must not use advertised hosts")
	}
}

func TestPeerServiceRuntimeEmptyCatalogAndOfflinePublisher(t *testing.T) {
	runtime := newPeerServiceRuntime(nil, func(any) error { return nil })
	runtime.setRoster(map[int64]peerServiceRosterHint{2: {virtualIP: "100.96.0.2", online: false}})
	sessionID := int64(9)
	catalog := peerControlMessage{
		Type:                peerControlTypeServiceCatalog,
		PublisherClientID:   2,
		PublisherClientName: "client-b",
		PublisherSessionID:  &sessionID,
		ExpiresAt:           time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		Services: []peerAdvertisedService{{
			ServiceID: "svc-http01", Name: "web", Transport: "tcp", Application: "http",
			PublishedPort: 8080, Path: "/app",
		}},
	}
	runtime.applyCatalog(catalog)
	if runtime.remoteServices()[0].Openable {
		t.Fatal("offline publisher should disable Open")
	}
	if !strings.Contains(runtime.remoteServices()[0].UnavailableReason, "离线") {
		t.Fatalf("reason = %q", runtime.remoteServices()[0].UnavailableReason)
	}
	catalog.Services = nil
	runtime.applyCatalog(catalog)
	if len(runtime.remoteServices()) != 0 {
		t.Fatal("empty catalog should withdraw")
	}
}

func TestProbeTCPDetectsOpenAndClosedPorts(t *testing.T) {
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	if probeTCP("127.0.0.1", port, 200*time.Millisecond) {
		t.Fatal("closed port should not probe true")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if !probeTCP("127.0.0.1", port, 400*time.Millisecond) {
		t.Fatal("open port should probe true")
	}
}

func TestPeerServiceRuntimeWithdrawsWhenSharingTurnsOff(t *testing.T) {
	port, listener := mustListen(t)
	defer listener.Close()
	sent := &sentReports{}
	runtime := newPeerServiceRuntime(nil, sent.append)
	runtime.setHasAuthorizedOnlinePeer(true)
	runtime.applyConfig(testPeerMeshConfig(true, port, true))
	waitUntil(t, func() bool { return sent.len() > 0 })
	sent.reset()
	runtime.applyConfig(testPeerMeshConfig(false, port, true))
	waitUntil(t, func() bool {
		for _, body := range sent.snapshot() {
			if strings.Contains(body, `"enabled":false`) {
				return true
			}
		}
		return false
	})
}

func TestPeerServiceRuntimeLocalPauseStopsReporting(t *testing.T) {
	port, listener := mustListen(t)
	defer listener.Close()
	sent := &sentReports{}
	runtime := newPeerServiceRuntime(nil, sent.append)
	runtime.setHasAuthorizedOnlinePeer(true)
	runtime.applyConfig(testPeerMeshConfig(true, port, true))
	waitUntil(t, func() bool { return sent.len() > 0 })
	sent.reset()
	runtime.setLocalPublished("svc-http01", false)
	waitUntil(t, func() bool {
		for _, body := range sent.snapshot() {
			if strings.Contains(body, `"enabled":false`) || strings.Contains(body, `"services":[]`) {
				return true
			}
		}
		return false
	})
}

func TestCollectEnvironmentAdvertisesPeerServiceCapabilities(t *testing.T) {
	info := collectEnvironment()
	if info.ClientPeerServiceCapabilities.Version != 1 {
		t.Fatalf("version = %d", info.ClientPeerServiceCapabilities.Version)
	}
	if strings.Join(info.ClientPeerServiceCapabilities.Applications, ",") != "http,https,ssh,tcp,udp" {
		t.Fatalf("apps = %#v", info.ClientPeerServiceCapabilities.Applications)
	}
}

func testPeerMeshConfig(sharing bool, targetPort int, enabled bool) PeerMeshConfig {
	return PeerMeshConfig{
		Enabled:   true,
		VirtualIP: "127.0.0.1",
		ServiceSharing: ServiceSharingStatus{
			DeploymentEnabled: true,
			ConfiguredEnabled: sharing,
			EffectiveEnabled:  sharing,
		},
		LocalServices: []LocalPeerService{{
			ServiceID:     "svc-http01",
			Name:          "web",
			Transport:     "tcp",
			Application:   "http",
			TargetHost:    "127.0.0.1",
			TargetPort:    targetPort,
			PublishedPort: 18080,
			Path:          "/app",
			Enabled:       enabled,
		}},
	}
}

type sentReports struct {
	mu    sync.Mutex
	items []string
}

func (s *sentReports) append(message any) error {
	raw, err := json.Marshal(message)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.items = append(s.items, string(raw))
	s.mu.Unlock()
	return nil
}

func (s *sentReports) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

func (s *sentReports) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.items))
	copy(out, s.items)
	return out
}

func (s *sentReports) reset() {
	s.mu.Lock()
	s.items = nil
	s.mu.Unlock()
}

func mustListen(t *testing.T) (int, net.Listener) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener.Addr().(*net.TCPAddr).Port, listener
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port, nil
}

func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
