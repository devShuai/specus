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
	revision := int64(1)
	runtime.applyCatalog(peerControlMessage{
		Type:                peerControlTypeServiceCatalog,
		PublisherClientID:   2,
		PublisherClientName: "client-b",
		PublisherSessionID:  &sessionID,
		Revision:            &revision,
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
	runtime.applyConfig(testPeerMeshConfig(true, 1, false))
	runtime.setRoster(map[int64]peerServiceRosterHint{2: {virtualIP: "100.96.0.2", online: false}})
	sessionID := int64(9)
	revision := int64(1)
	catalog := peerControlMessage{
		Type:                peerControlTypeServiceCatalog,
		PublisherClientID:   2,
		PublisherClientName: "client-b",
		PublisherSessionID:  &sessionID,
		Revision:            &revision,
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
	revision++
	catalog.Revision = &revision
	runtime.applyCatalog(catalog)
	if len(runtime.remoteServices()) != 0 {
		t.Fatal("empty catalog should withdraw")
	}
}

func TestPeerServiceRuntimeRejectsStaleCatalogAfterWithdrawal(t *testing.T) {
	runtime := newPeerServiceRuntime(nil, func(any) error { return nil })
	runtime.applyConfig(testPeerMeshConfig(true, 1, false))
	sessionID := int64(9)
	revision2 := int64(2)
	catalog := peerControlMessage{
		Type: peerControlTypeServiceCatalog, PublisherClientID: 2, PublisherClientName: "client-b",
		PublisherSessionID: &sessionID, Revision: &revision2,
		ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		Services:  []peerAdvertisedService{{ServiceID: "svc-http01", Application: "http", PublishedPort: 8080}},
	}
	runtime.applyCatalog(catalog)
	revision3 := int64(3)
	catalog.Revision = &revision3
	catalog.Services = nil
	runtime.applyCatalog(catalog)
	catalog.Revision = &revision2
	catalog.Services = []peerAdvertisedService{{ServiceID: "svc-http01", Application: "http", PublishedPort: 8080}}
	runtime.applyCatalog(catalog)
	if len(runtime.remoteServices()) != 0 {
		t.Fatal("stale catalog revived a withdrawn service")
	}
}

func TestPeerServiceRuntimeReconnectAcceptsCurrentCatalogRevision(t *testing.T) {
	runtime := newPeerServiceRuntime(nil, func(any) error { return nil })
	runtime.applyConfig(testPeerMeshConfig(true, 1, false))
	runtime.setRoster(map[int64]peerServiceRosterHint{2: {virtualIP: "100.96.0.2", online: true}})
	runtime.setHasAuthorizedOnlinePeer(true)
	sessionID := int64(9)
	revision := int64(7)
	catalog := peerControlMessage{
		Type: peerControlTypeServiceCatalog, PublisherClientID: 2, PublisherClientName: "client-b",
		PublisherSessionID: &sessionID, Revision: &revision,
		ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		Services:  []peerAdvertisedService{{ServiceID: "svc-http01", Application: "http", PublishedPort: 8080}},
	}
	runtime.applyCatalog(catalog)
	if len(runtime.remoteServices()) != 1 {
		t.Fatal("initial catalog was not accepted")
	}
	runtime.setHasAuthorizedOnlinePeer(false)
	if len(runtime.remoteServices()) != 0 {
		t.Fatal("disconnect must clear the catalog")
	}
	runtime.setHasAuthorizedOnlinePeer(true)
	runtime.applyCatalog(catalog)
	if len(runtime.remoteServices()) != 1 {
		t.Fatal("current catalog revision was rejected after reconnect")
	}
}

func TestPeerServiceRuntimeRenewsUnchangedCatalogAcrossMultipleTTLs(t *testing.T) {
	port, listener := mustListen(t)
	defer listener.Close()
	sent := &sentReports{}
	runtime := newPeerServiceRuntime(nil, sent.append)
	runtime.setHasAuthorizedOnlinePeer(true)
	runtime.applyConfig(testPeerMeshConfig(true, port, true))
	waitUntil(t, func() bool { return sent.len() > 0 })
	sent.reset()
	for elapsedTTLs := 1; elapsedTTLs <= 3; elapsedTTLs++ {
		runtime.mu.Lock()
		runtime.lastReportAt = time.Now().Add(-peerServiceReportRefresh - time.Second)
		runtime.mu.Unlock()
		runtime.probeAndReport()
		if sent.len() != elapsedTTLs {
			t.Fatalf("renewal reports after %d TTLs = %d", elapsedTTLs, sent.len())
		}
	}
}

func TestProbeTCPDetectsOpenAndClosedPorts(t *testing.T) {
	if isLocalServiceTarget("10.255.255.254") {
		t.Fatal("unassigned private address must not be accepted as a local service target")
	}
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

func TestPeerServiceRuntimeOnlineConfigCreatesReplacesAndClosesBridgeWithinFiveSeconds(t *testing.T) {
	_, firstTarget := mustListen(t)
	defer firstTarget.Close()
	_, secondTarget := mustListen(t)
	defer secondTarget.Close()
	firstPublishedPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	secondPublishedPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	runtime := newPeerServiceRuntime(nil, func(any) error { return nil })
	defer runtime.close()
	runtime.setHasAuthorizedOnlinePeer(true)

	first := testPeerMeshConfig(true, firstTarget.Addr().(*net.TCPAddr).Port, true)
	first.LocalServices[0].PublishedPort = firstPublishedPort
	first.LocalServices[0].AllowedPeerVirtualIPs = []string{"127.0.0.1"}
	started := time.Now()
	runtime.applyConfig(first)
	firstCaller, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(firstPublishedPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer firstCaller.Close()
	_ = firstTarget.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	firstForwarded, err := firstTarget.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer firstForwarded.Close()
	if time.Since(started) >= 5*time.Second {
		t.Fatal("online service was not published within five seconds")
	}

	replacement := testPeerMeshConfig(true, secondTarget.Addr().(*net.TCPAddr).Port, true)
	replacement.LocalServices[0].PublishedPort = secondPublishedPort
	replacement.LocalServices[0].AllowedPeerVirtualIPs = []string{"127.0.0.1"}
	runtime.applyConfig(replacement)
	_ = firstCaller.SetReadDeadline(time.Now().Add(time.Second))
	if _, readErr := firstCaller.Read(make([]byte, 1)); readErr == nil {
		t.Fatal("replaced service left the old flow active")
	}
	if retry, retryErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(firstPublishedPort)), time.Second); retryErr == nil {
		retry.Close()
		t.Fatal("replaced service left the old listener open")
	}

	secondCaller, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(secondPublishedPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer secondCaller.Close()
	_ = secondTarget.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	secondForwarded, err := secondTarget.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer secondForwarded.Close()
	replacement.LocalServices[0].Enabled = false
	runtime.applyConfig(replacement)
	_ = secondCaller.SetReadDeadline(time.Now().Add(time.Second))
	if _, readErr := secondCaller.Read(make([]byte, 1)); readErr == nil {
		t.Fatal("disabled service left its active flow open")
	}
	if retry, retryErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(secondPublishedPort)), time.Second); retryErr == nil {
		retry.Close()
		t.Fatal("disabled service accepted a new connection")
	}
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
	if info.ClientPeerServiceCapabilities.Version != 2 {
		t.Fatalf("version = %d", info.ClientPeerServiceCapabilities.Version)
	}
	if strings.Join(info.ClientPeerServiceCapabilities.Applications, ",") != "http,https,ssh,tcp,udp" {
		t.Fatalf("apps = %#v", info.ClientPeerServiceCapabilities.Applications)
	}
}

func TestPeerServiceTCPBridgeEnforcesServerAuthoredSourceACL(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetPort := target.Addr().(*net.TCPAddr).Port
	publishedPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	service := LocalPeerService{
		ServiceID: "svc-acl01", Transport: "tcp", Application: "tcp",
		TargetHost: "127.0.0.1", TargetPort: targetPort, PublishedPort: publishedPort,
		AllowedPeerVirtualIPs: []string{"127.0.0.2"},
	}
	bridge, err := bindPeerServiceBridge("127.0.0.1", service, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()
	unauthorized, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(publishedPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer unauthorized.Close()
	_ = target.(*net.TCPListener).SetDeadline(time.Now().Add(250 * time.Millisecond))
	if forwarded, acceptErr := target.Accept(); acceptErr == nil {
		forwarded.Close()
		t.Fatal("unauthorized source reached local target")
	}

	bridge.close()
	publishedPort, err = freePort()
	if err != nil {
		t.Fatal(err)
	}
	service.PublishedPort = publishedPort
	service.AllowedPeerVirtualIPs = []string{"127.0.0.1"}
	bridge, err = bindPeerServiceBridge("127.0.0.1", service, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()
	authorized, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(publishedPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer authorized.Close()
	_ = target.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	forwarded, err := target.Accept()
	if err != nil {
		t.Fatalf("authorized source did not reach local target: %v", err)
	}
	forwarded.Close()
}

func TestPeerServiceTCPBridgeSeparatesThreePeersAndRevokesActiveFlow(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetPort := target.Addr().(*net.TCPAddr).Port
	publishedPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	service := LocalPeerService{
		ServiceID: "svc-acl-three", Transport: "tcp", Application: "tcp",
		TargetHost: "127.0.0.1", TargetPort: targetPort, PublishedPort: publishedPort,
		AllowedPeerVirtualIPs: []string{"127.0.0.2"},
	}
	bridge, err := bindPeerServiceBridge("127.0.0.1", service, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()

	denied, err := dialPeerServiceFrom("127.0.0.3", publishedPort)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	_ = target.(*net.TCPListener).SetDeadline(time.Now().Add(250 * time.Millisecond))
	if forwarded, acceptErr := target.Accept(); acceptErr == nil {
		forwarded.Close()
		t.Fatal("peer C bypassed the service ACL")
	}

	allowed, err := dialPeerServiceFrom("127.0.0.2", publishedPort)
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	_ = target.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	forwarded, err := target.Accept()
	if err != nil {
		t.Fatalf("peer B did not reach the service: %v", err)
	}
	defer forwarded.Close()

	bridge.close()
	_ = allowed.SetReadDeadline(time.Now().Add(time.Second))
	if _, readErr := allowed.Read(make([]byte, 1)); readErr == nil {
		t.Fatal("revoked peer B flow remained active")
	}
	if retry, retryErr := dialPeerServiceFrom("127.0.0.2", publishedPort); retryErr == nil {
		retry.Close()
		t.Fatal("revoked peer B established a new flow")
	}
}

func TestPeerServiceUDPBridgeAppliesTheSameACLAndRevocationBoundary(t *testing.T) {
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	portProbe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	publishedPort := portProbe.LocalAddr().(*net.UDPAddr).Port
	_ = portProbe.Close()
	service := LocalPeerService{
		ServiceID: "svc-udp-acl", Transport: "udp", Application: "udp",
		TargetHost: "127.0.0.1", TargetPort: target.LocalAddr().(*net.UDPAddr).Port,
		PublishedPort: publishedPort, AllowedPeerVirtualIPs: []string{"127.0.0.2"},
	}
	bridge, err := bindPeerServiceBridge("127.0.0.1", service, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()

	denied, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	allowed, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	destination := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: publishedPort}
	_, _ = denied.WriteToUDP([]byte{1, 2, 3}, destination)
	_ = target.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if _, _, readErr := target.ReadFromUDP(make([]byte, 8)); readErr == nil {
		t.Fatal("unauthorized UDP peer reached the local target")
	}

	_, _ = allowed.WriteToUDP([]byte{1, 2, 3}, destination)
	_ = target.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, readErr := target.ReadFromUDP(make([]byte, 8)); readErr != nil || n != 3 {
		t.Fatalf("authorized UDP peer was not forwarded: n=%d err=%v", n, readErr)
	}

	bridge.close()
	_, _ = allowed.WriteToUDP([]byte{1, 2, 3}, destination)
	_ = target.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if _, _, readErr := target.ReadFromUDP(make([]byte, 8)); readErr == nil {
		t.Fatal("revoked UDP peer remained forwarded")
	}
}

func dialPeerServiceFrom(sourceIP string, targetPort int) (net.Conn, error) {
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(sourceIP)}}
	return dialer.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(targetPort)))
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
