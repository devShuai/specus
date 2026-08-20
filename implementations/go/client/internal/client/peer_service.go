package client

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	peerControlTypeServiceReport  = "service-report"
	peerControlTypeServiceCatalog = "service-catalog"
	peerServiceProbeTimeout       = 400 * time.Millisecond
	peerServiceProbeInterval      = 15 * time.Second
	peerServiceCatalogTTL         = 5 * time.Minute
	peerServiceReportRefresh      = peerServiceCatalogTTL / 2
	peerServiceTCPGlobalLimit     = 256
	peerServiceTCPPerServiceLimit = 64
	peerServiceTCPPerSourceLimit  = 8
	peerServiceUDPGlobalLimit     = 256
	peerServiceUDPPerServiceLimit = 64
	peerServiceUDPPerSourceLimit  = 8
	peerServiceConnectTimeout     = 3 * time.Second
	peerServiceIdleTimeout        = 60 * time.Second
)

var peerServiceResourceBudget = struct {
	sync.Mutex
	tcpGlobal  int
	udpGlobal  int
	tcpSources map[netip.Addr]int
	udpSources map[netip.Addr]int
}{tcpSources: make(map[netip.Addr]int), udpSources: make(map[netip.Addr]int)}

type peerAdvertisedService struct {
	ServiceID     string `json:"serviceId"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	Transport     string `json:"transport"`
	Application   string `json:"application"`
	PublishedPort int    `json:"publishedPort"`
	Path          string `json:"path,omitempty"`
}

type peerServiceReport struct {
	Type            string                  `json:"type"`
	Enabled         bool                    `json:"enabled"`
	Revision        int64                   `json:"revision"`
	InstanceID      string                  `json:"instanceId"`
	GeneratedAt     string                  `json:"generatedAt"`
	ExpiresAt       string                  `json:"expiresAt"`
	Services        []peerAdvertisedService `json:"services"`
	Stats           []peerServiceStats      `json:"stats,omitempty"`
	MdnsCandidates  []peerMdnsCandidate     `json:"mdnsCandidates,omitempty"`
	CreatedAtMillis int64                   `json:"createdAtMillis"`
}

type peerMdnsCandidate struct {
	Name        string `json:"name"`
	Transport   string `json:"transport"`
	Application string `json:"application"`
	TargetHost  string `json:"targetHost"`
	TargetPort  int    `json:"targetPort"`
}

type peerServiceStats struct {
	ServiceID         string `json:"serviceId"`
	BytesIn           int64  `json:"bytesIn"`
	BytesOut          int64  `json:"bytesOut"`
	ActiveConnections int    `json:"activeConnections"`
	TotalConnections  int64  `json:"totalConnections"`
}

type peerServiceRosterHint struct {
	virtualIP string
	online    bool
}

type peerServiceCatalogKey struct {
	publisherClientID  int64
	publisherSessionID int64
}

type peerServiceCatalogSnapshot struct {
	publisherClientID   int64
	publisherClientName string
	publisherSessionID  int64
	revision            int64
	expiresAt           time.Time
	services            []peerAdvertisedService
}

type remotePeerServiceView struct {
	PublisherClientID   int64
	PublisherClientName string
	PublisherSessionID  int64
	VirtualIP           string
	PublisherOnline     bool
	Fresh               bool
	Service             peerAdvertisedService
	AccessTarget        string
	Openable            bool
	Copyable            bool
	UnavailableReason   string
}

type peerServiceRuntime struct {
	mu               sync.Mutex
	logger           *log.Logger
	send             func(any) error
	config           PeerMeshConfig
	instanceID       string
	revision         atomic.Int64
	onlinePeer       atomic.Bool
	catalogs         map[peerServiceCatalogKey]peerServiceCatalogSnapshot
	catalogRevisions map[peerServiceCatalogKey]int64
	bridges          map[string]*peerServiceBridge
	roster           map[int64]peerServiceRosterHint
	probeStop        chan struct{}
	lastReportedIDs  []string
	lastReportAt     time.Time
	locallyPaused    map[string]struct{}
}

type peerServiceBridge struct {
	virtualIP string
	service   LocalPeerService
	listener  net.Listener
	udp       *net.UDPConn
	closed    atomic.Bool
	bytesIn   atomic.Int64
	bytesOut  atomic.Int64
	total     atomic.Int64
	active    atomic.Int64
	connMu    sync.Mutex
	conns     map[net.Conn]struct{}
	tcpSlots  chan struct{}
	udpPeers  sync.Map
	logger    *log.Logger
	auditSeen sync.Map
	auditSize atomic.Int64
}

type peerServiceUDPPeer struct {
	conn    *net.UDPConn
	release func()
	once    sync.Once
}

func (p *peerServiceUDPPeer) close() {
	p.once.Do(func() {
		_ = p.conn.Close()
		p.release()
	})
}

func newPeerServiceRuntime(logger *log.Logger, send func(any) error) *peerServiceRuntime {
	if logger == nil {
		logger = log.Default()
	}
	return &peerServiceRuntime{
		logger:           logger,
		send:             send,
		instanceID:       newPeerMeshKeyEpoch(),
		catalogs:         make(map[peerServiceCatalogKey]peerServiceCatalogSnapshot),
		catalogRevisions: make(map[peerServiceCatalogKey]int64),
		bridges:          make(map[string]*peerServiceBridge),
		roster:           make(map[int64]peerServiceRosterHint),
		locallyPaused:    make(map[string]struct{}),
	}
}

func (r *peerServiceRuntime) setSend(send func(any) error) {
	r.mu.Lock()
	r.send = send
	r.mu.Unlock()
}

func (r *peerServiceRuntime) applyConfig(next PeerMeshConfig) {
	r.mu.Lock()
	r.config = next
	if !r.effectiveSharingLocked() {
		r.stopProbeLocked()
		r.closeBridgesLocked()
		r.catalogs = make(map[peerServiceCatalogKey]peerServiceCatalogSnapshot)
		shouldWithdraw := len(r.lastReportedIDs) > 0 || r.revision.Load() > 0
		r.mu.Unlock()
		if shouldWithdraw {
			r.sendWithdraw()
		}
		return
	}
	r.reconcileBridgesLocked()
	r.scheduleProbeLocked()
	r.mu.Unlock()
	r.probeAndReport()
}

func (r *peerServiceRuntime) setHasAuthorizedOnlinePeer(online bool) {
	previous := r.onlinePeer.Swap(online)
	if previous == online {
		return
	}
	r.mu.Lock()
	if !r.effectiveSharingLocked() || !online {
		r.stopProbeLocked()
		r.closeBridgesLocked()
		r.catalogs = make(map[peerServiceCatalogKey]peerServiceCatalogSnapshot)
		r.catalogRevisions = make(map[peerServiceCatalogKey]int64)
		r.mu.Unlock()
		return
	}
	r.reconcileBridgesLocked()
	r.scheduleProbeLocked()
	r.mu.Unlock()
	r.probeAndReport()
}

func (r *peerServiceRuntime) setRoster(peers map[int64]peerServiceRosterHint) {
	r.mu.Lock()
	next := make(map[int64]peerServiceRosterHint, len(peers))
	for id, hint := range peers {
		next[id] = hint
	}
	r.roster = next
	r.mu.Unlock()
}

func (r *peerServiceRuntime) applyCatalog(message peerControlMessage) {
	if message.PublisherClientID == 0 || message.PublisherSessionID == nil || *message.PublisherSessionID == 0 {
		return
	}
	key := peerServiceCatalogKey{message.PublisherClientID, *message.PublisherSessionID}
	services := append([]peerAdvertisedService(nil), message.Services...)
	r.mu.Lock()
	if !r.effectiveSharingLocked() {
		r.mu.Unlock()
		return
	}
	revision := int64(0)
	if message.Revision != nil {
		revision = *message.Revision
	}
	if _, exists := r.catalogRevisions[key]; !exists && len(r.catalogRevisions) >= 4096 {
		r.mu.Unlock()
		return
	}
	if revision < 1 || revision <= r.catalogRevisions[key] {
		r.mu.Unlock()
		return
	}
	r.catalogRevisions[key] = revision
	if len(services) == 0 {
		delete(r.catalogs, key)
		r.mu.Unlock()
		r.logger.Printf("Peer 服务目录已撤回: publisher=%s session=%d", message.PublisherClientName, *message.PublisherSessionID)
		return
	}
	expiresAt := time.Now().Add(peerServiceCatalogTTL)
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(message.ExpiresAt)); err == nil {
		expiresAt = parsed
	}
	r.catalogs[key] = peerServiceCatalogSnapshot{
		publisherClientID:   message.PublisherClientID,
		publisherClientName: message.PublisherClientName,
		publisherSessionID:  *message.PublisherSessionID,
		revision:            revision,
		expiresAt:           expiresAt,
		services:            services,
	}
	r.mu.Unlock()
	r.logger.Printf("Peer 服务目录已更新: publisher=%s session=%d services=%d",
		message.PublisherClientName, *message.PublisherSessionID, len(services))
	for _, view := range r.remoteServices() {
		r.logger.Printf("  %s %s %s", view.PublisherClientName, view.Service.Application, view.AccessTarget)
	}
}

func (r *peerServiceRuntime) remoteServices() []remotePeerServiceView {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	out := make([]remotePeerServiceView, 0)
	for _, snapshot := range r.catalogs {
		if snapshot.expiresAt.Before(now) {
			continue
		}
		hint := r.roster[snapshot.publisherClientID]
		for _, service := range snapshot.services {
			out = append(out, remoteServiceView(snapshot, hint, service))
		}
	}
	return out
}

func (r *peerServiceRuntime) probeAndReport() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.effectiveSharingLocked() || !r.onlinePeer.Load() {
		r.closeBridgesLocked()
		return
	}
	reachable := make([]peerAdvertisedService, 0)
	for _, local := range r.enabledLocalsLocked() {
		if !probeLocal(local, peerServiceProbeTimeout) {
			continue
		}
		reachable = append(reachable, advertisedFromLocal(local))
	}
	ids := make([]string, 0, len(reachable))
	for _, service := range reachable {
		ids = append(ids, service.ServiceID)
	}
	refreshDue := r.lastReportAt.IsZero() || !time.Now().Before(r.lastReportAt.Add(peerServiceReportRefresh))
	if !refreshDue && equalStringSlice(ids, r.lastReportedIDs) && r.revision.Load() > 0 {
		r.reconcileBridgesLocked()
		return
	}
	r.lastReportedIDs = ids
	r.sendReportLocked(true, reachable)
	r.reconcileBridgesLocked()
}

func (r *peerServiceRuntime) close() {
	r.mu.Lock()
	r.stopProbeLocked()
	r.closeBridgesLocked()
	r.catalogs = make(map[peerServiceCatalogKey]peerServiceCatalogSnapshot)
	r.mu.Unlock()
}

func (r *peerServiceRuntime) effectiveSharingLocked() bool {
	return r.config.ServiceSharing.EffectiveEnabled
}

func (r *peerServiceRuntime) setLocalPublished(serviceID string, published bool) {
	id := strings.TrimSpace(serviceID)
	if id == "" {
		return
	}
	r.mu.Lock()
	if r.locallyPaused == nil {
		r.locallyPaused = make(map[string]struct{})
	}
	if published {
		delete(r.locallyPaused, id)
	} else {
		r.locallyPaused[id] = struct{}{}
	}
	r.mu.Unlock()
	r.probeAndReport()
}

func (r *peerServiceRuntime) enabledLocalsLocked() []LocalPeerService {
	out := make([]LocalPeerService, 0)
	for _, local := range r.config.LocalServices {
		if !local.Enabled || strings.TrimSpace(local.ServiceID) == "" {
			continue
		}
		if _, paused := r.locallyPaused[local.ServiceID]; paused {
			continue
		}
		out = append(out, local)
	}
	return out
}

func (r *peerServiceRuntime) reconcileBridgesLocked() {
	if !r.effectiveSharingLocked() || !r.onlinePeer.Load() || strings.TrimSpace(r.config.VirtualIP) == "" {
		r.closeBridgesLocked()
		return
	}
	desired := make(map[string]LocalPeerService)
	for _, local := range r.enabledLocalsLocked() {
		if probeLocal(local, peerServiceProbeTimeout) {
			desired[local.ServiceID] = local
		}
	}
	for id, bridge := range r.bridges {
		if _, ok := desired[id]; !ok {
			bridge.close()
			delete(r.bridges, id)
		}
	}
	for id, local := range desired {
		if current, ok := r.bridges[id]; ok && current.matches(r.config.VirtualIP, local) {
			continue
		}
		if current, ok := r.bridges[id]; ok {
			current.close()
			delete(r.bridges, id)
		}
		bridge, err := bindPeerServiceBridge(r.config.VirtualIP, local, r.logger)
		if err != nil {
			r.logger.Printf("Peer-only 桥接暂不可用 service=%s: %v", local.ServiceID, err)
			continue
		}
		r.bridges[id] = bridge
		r.logger.Printf("Peer-only 桥接已监听 %s:%d -> %s:%d",
			r.config.VirtualIP, local.PublishedPort, local.TargetHost, local.TargetPort)
	}
}

func (r *peerServiceRuntime) scheduleProbeLocked() {
	r.stopProbeLocked()
	stop := make(chan struct{})
	r.probeStop = stop
	go func() {
		ticker := time.NewTicker(peerServiceProbeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				r.probeAndReport()
			}
		}
	}()
}

func (r *peerServiceRuntime) stopProbeLocked() {
	if r.probeStop != nil {
		close(r.probeStop)
		r.probeStop = nil
	}
}

func (r *peerServiceRuntime) sendWithdraw() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastReportedIDs = nil
	r.sendReportLocked(false, nil)
}

func (r *peerServiceRuntime) sendReportLocked(enabled bool, services []peerAdvertisedService) {
	if services == nil {
		services = []peerAdvertisedService{}
	}
	stats := make([]peerServiceStats, 0, len(r.bridges))
	for _, bridge := range r.bridges {
		stats = append(stats, bridge.stats())
	}
	var mdns []peerMdnsCandidate
	if r.config.ServiceSharing.MdnsImportEnabled {
		mdns = browseMdns(peerServiceProbeTimeout)
	}
	report := peerServiceReport{
		Type:            peerControlTypeServiceReport,
		Enabled:         enabled,
		Revision:        r.revision.Add(1),
		InstanceID:      r.instanceID,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt:       time.Now().UTC().Add(peerServiceCatalogTTL).Format(time.RFC3339Nano),
		Services:        services,
		Stats:           stats,
		MdnsCandidates:  mdns,
		CreatedAtMillis: time.Now().UnixMilli(),
	}
	r.lastReportAt = time.Now()
	send := r.send
	if send == nil {
		return
	}
	if err := send(report); err != nil {
		r.logger.Printf("service-report 发送失败: %v", err)
	}
}

func (r *peerServiceRuntime) closeBridgesLocked() {
	for id, bridge := range r.bridges {
		bridge.close()
		delete(r.bridges, id)
	}
}

func advertisedFromLocal(local LocalPeerService) peerAdvertisedService {
	return peerAdvertisedService{
		ServiceID:     local.ServiceID,
		Name:          local.Name,
		Description:   local.Description,
		Transport:     local.Transport,
		Application:   local.Application,
		PublishedPort: local.PublishedPort,
		Path:          local.Path,
	}
}

func remoteServiceView(snapshot peerServiceCatalogSnapshot, hint peerServiceRosterHint, service peerAdvertisedService) remotePeerServiceView {
	httpLike := service.Application == "http" || service.Application == "https"
	fresh := snapshot.expiresAt.After(time.Now())
	virtualIP := strings.TrimSpace(hint.virtualIP)
	reason := ""
	switch {
	case !fresh:
		reason = "目录已过期"
	case !hint.online:
		reason = "发布端离线"
	case virtualIP == "":
		reason = "缺少虚拟 IP"
	}
	access := ""
	if virtualIP != "" {
		access = peerServiceAccessURL(virtualIP, service)
	}
	return remotePeerServiceView{
		PublisherClientID:   snapshot.publisherClientID,
		PublisherClientName: snapshot.publisherClientName,
		PublisherSessionID:  snapshot.publisherSessionID,
		VirtualIP:           virtualIP,
		PublisherOnline:     hint.online,
		Fresh:               fresh,
		Service:             service,
		AccessTarget:        access,
		Openable:            httpLike && reason == "",
		Copyable:            !httpLike && reason == "",
		UnavailableReason:   reason,
	}
}

func peerServiceAccessURL(virtualIP string, service peerAdvertisedService) string {
	if strings.TrimSpace(virtualIP) == "" {
		return ""
	}
	if service.Application == "http" || service.Application == "https" {
		path := service.Path
		if strings.TrimSpace(path) == "" {
			path = "/"
		}
		return service.Application + "://" + virtualIP + ":" + strconv.Itoa(service.PublishedPort) + path
	}
	return virtualIP + ":" + strconv.Itoa(service.PublishedPort)
}

func probeLocal(service LocalPeerService, timeout time.Duration) bool {
	target, ok := resolveLocalServiceTarget(service.TargetHost)
	if !ok {
		return false
	}
	if strings.EqualFold(service.Transport, "udp") || strings.EqualFold(service.Application, "udp") {
		return probeUDP(target, service.TargetPort, timeout)
	}
	return probeTCP(target, service.TargetPort, timeout)
}

func isLocalServiceTarget(host string) bool {
	_, ok := resolveLocalServiceTarget(host)
	return ok
}

func resolveLocalServiceTarget(host string) (string, bool) {
	value := strings.TrimSpace(host)
	if strings.EqualFold(value, "localhost") {
		value = "127.0.0.1"
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", false
	}
	if ip.IsLoopback() {
		return ip.String(), true
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", false
	}
	for _, raw := range addresses {
		var candidate net.IP
		switch address := raw.(type) {
		case *net.IPNet:
			candidate = address.IP
		case *net.IPAddr:
			candidate = address.IP
		}
		if candidate != nil && candidate.Equal(ip) {
			return ip.String(), true
		}
	}
	return "", false
}

func probeTCP(host string, port int, timeout time.Duration) bool {
	if strings.TrimSpace(host) == "" || port < 1 || port > 65535 {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func probeUDP(host string, port int, timeout time.Duration) bool {
	if strings.TrimSpace(host) == "" || port < 1 || port > 65535 {
		return false
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte{0})
	if err != nil {
		return false
	}
	response := []byte{0}
	n, err := conn.Read(response)
	return err == nil && n > 0
}

func bindPeerServiceBridge(virtualIP string, service LocalPeerService, logger *log.Logger) (*peerServiceBridge, error) {
	target, ok := resolveLocalServiceTarget(service.TargetHost)
	if !ok {
		return nil, errors.New("targetHost is not assigned to this device")
	}
	service.TargetHost = target
	if strings.EqualFold(service.Transport, "udp") || strings.EqualFold(service.Application, "udp") {
		return bindPeerServiceUDP(virtualIP, service, logger)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(virtualIP, strconv.Itoa(service.PublishedPort)))
	if err != nil {
		return nil, err
	}
	bridge := &peerServiceBridge{virtualIP: virtualIP, service: service, listener: listener,
		conns: make(map[net.Conn]struct{}), tcpSlots: make(chan struct{}, peerServiceTCPPerServiceLimit), logger: logger}
	go bridge.acceptLoop(logger)
	return bridge, nil
}

func bindPeerServiceUDP(virtualIP string, service LocalPeerService, logger *log.Logger) (*peerServiceBridge, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(virtualIP, strconv.Itoa(service.PublishedPort)))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	bridge := &peerServiceBridge{virtualIP: virtualIP, service: service, udp: conn,
		tcpSlots: make(chan struct{}, peerServiceTCPPerServiceLimit), logger: logger}
	go bridge.udpLoop(logger)
	return bridge, nil
}

func (b *peerServiceBridge) matches(virtualIP string, service LocalPeerService) bool {
	return b.virtualIP == virtualIP &&
		b.service.ServiceID == service.ServiceID &&
		b.service.PublishedPort == service.PublishedPort &&
		b.service.TargetHost == service.TargetHost &&
		b.service.TargetPort == service.TargetPort &&
		equalNormalizedIPs(b.service.AllowedPeerVirtualIPs, service.AllowedPeerVirtualIPs)
}

func (b *peerServiceBridge) acceptLoop(logger *log.Logger) {
	for !b.closed.Load() {
		inbound, err := b.listener.Accept()
		if err != nil {
			return
		}
		source, sourceOK := peerServiceSourceAddress(inbound.RemoteAddr())
		if !sourceOK || !peerServiceIPAllowed(source, b.service.AllowedPeerVirtualIPs) {
			b.auditAccessOnce("deny", inbound.RemoteAddr(), "source-not-allowed")
			_ = inbound.Close()
			continue
		}
		b.auditAccessOnce("allow", inbound.RemoteAddr(), "acl-authorized")
		select {
		case b.tcpSlots <- struct{}{}:
		default:
			_ = inbound.Close()
			continue
		}
		release, ok := acquirePeerServiceResource(false, source)
		if !ok {
			<-b.tcpSlots
			_ = inbound.Close()
			continue
		}
		go b.splice(inbound, logger, release)
	}
}

func (b *peerServiceBridge) stats() peerServiceStats {
	return peerServiceStats{
		ServiceID:         b.service.ServiceID,
		BytesIn:           b.bytesIn.Load(),
		BytesOut:          b.bytesOut.Load(),
		ActiveConnections: int(b.active.Load()),
		TotalConnections:  b.total.Load(),
	}
}

func (b *peerServiceBridge) udpLoop(_ *log.Logger) {
	buf := make([]byte, 65507)
	target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(b.service.TargetHost, strconv.Itoa(b.service.TargetPort)))
	if err != nil {
		return
	}
	for !b.closed.Load() {
		n, peer, err := b.udp.ReadFromUDP(buf)
		if err != nil {
			break
		}
		peerAddr, ok := netip.AddrFromSlice(peer.IP)
		if !ok || !peerServiceIPAllowed(peerAddr.Unmap(), b.service.AllowedPeerVirtualIPs) {
			b.auditAccessOnce("deny", peer, "source-not-allowed")
			continue
		}
		b.bytesIn.Add(int64(n))
		key := peer.String()
		value, ok := b.udpPeers.Load(key)
		var binding *peerServiceUDPPeer
		if !ok {
			if b.active.Load() >= peerServiceUDPPerServiceLimit {
				continue
			}
			release, acquired := acquirePeerServiceResource(true, peerAddr.Unmap())
			if !acquired {
				continue
			}
			outbound, dialErr := net.DialUDP("udp", nil, target)
			if dialErr != nil {
				release()
				continue
			}
			binding = &peerServiceUDPPeer{conn: outbound, release: release}
			actual, loaded := b.udpPeers.LoadOrStore(key, binding)
			if loaded {
				binding.close()
				binding = actual.(*peerServiceUDPPeer)
			} else {
				_ = binding.conn.SetReadDeadline(time.Now().Add(peerServiceIdleTimeout))
				b.auditAccessOnce("allow", peer, "acl-authorized")
				b.total.Add(1)
				b.active.Add(1)
				go b.udpReply(key, binding, peer)
			}
		} else {
			binding = value.(*peerServiceUDPPeer)
			_ = binding.conn.SetReadDeadline(time.Now().Add(peerServiceIdleTimeout))
		}
		_, _ = binding.conn.Write(buf[:n])
	}
	b.udpPeers.Range(func(_, value any) bool {
		value.(*peerServiceUDPPeer).close()
		return true
	})
}

func (b *peerServiceBridge) auditAccessOnce(action string, source net.Addr, reason string) {
	if b.logger == nil || source == nil || b.auditSize.Load() >= 128 {
		return
	}
	key := action + "|" + source.String()
	if _, loaded := b.auditSeen.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	b.auditSize.Add(1)
	b.logger.Printf("[peer-service-access-audit] action=%s serviceId=%s source=%s reason=%s",
		action, b.service.ServiceID, source.String(), reason)
}

func peerServiceSourceAllowed(remote net.Addr, allowed []string) bool {
	addr, ok := peerServiceSourceAddress(remote)
	return ok && peerServiceIPAllowed(addr, allowed)
}

func peerServiceSourceAddress(remote net.Addr) (netip.Addr, bool) {
	if remote == nil {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return addr.Unmap(), err == nil
}

func peerServiceIPAllowed(addr netip.Addr, allowed []string) bool {
	for _, raw := range allowed {
		candidate, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err == nil && candidate.Unmap() == addr {
			return true
		}
	}
	return false
}

func equalNormalizedIPs(left, right []string) bool {
	normalize := func(values []string) []string {
		out := make([]string, 0, len(values))
		for _, raw := range values {
			if addr, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
				out = append(out, addr.Unmap().String())
			}
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(normalize(left), normalize(right))
}

func (b *peerServiceBridge) udpReply(key string, binding *peerServiceUDPPeer, peer *net.UDPAddr) {
	defer func() {
		b.udpPeers.CompareAndDelete(key, binding)
		binding.close()
		b.active.Add(-1)
	}()
	buf := make([]byte, 65507)
	for !b.closed.Load() {
		n, err := binding.conn.Read(buf)
		if err != nil {
			return
		}
		b.bytesOut.Add(int64(n))
		_, _ = b.udp.WriteToUDP(buf[:n], peer)
	}
}

func (b *peerServiceBridge) splice(inbound net.Conn, logger *log.Logger, release func()) {
	defer func() {
		<-b.tcpSlots
		release()
	}()
	if !b.trackConn(inbound) {
		return
	}
	defer func() {
		b.untrackConn(inbound)
		_ = inbound.Close()
	}()
	b.total.Add(1)
	b.active.Add(1)
	defer b.active.Add(-1)
	outbound, err := net.DialTimeout("tcp", net.JoinHostPort(b.service.TargetHost, strconv.Itoa(b.service.TargetPort)), peerServiceConnectTimeout)
	if err != nil {
		if logger != nil {
			logger.Printf("Peer-only 桥接转发失败 service=%s: %v", b.service.ServiceID, err)
		}
		return
	}
	if !b.trackConn(outbound) {
		_ = outbound.Close()
		return
	}
	defer func() {
		b.untrackConn(outbound)
		_ = outbound.Close()
	}()
	done := make(chan struct{}, 2)
	go func() { copyPeerService(outbound, inbound, &b.bytesIn); done <- struct{}{} }()
	go func() { copyPeerService(inbound, outbound, &b.bytesOut); done <- struct{}{} }()
	<-done
	_ = inbound.Close()
	_ = outbound.Close()
	<-done
}

func (b *peerServiceBridge) trackConn(conn net.Conn) bool {
	b.connMu.Lock()
	defer b.connMu.Unlock()
	if b.closed.Load() {
		_ = conn.Close()
		return false
	}
	b.conns[conn] = struct{}{}
	return true
}

func (b *peerServiceBridge) untrackConn(conn net.Conn) {
	b.connMu.Lock()
	delete(b.conns, conn)
	b.connMu.Unlock()
}

func copyPeerService(dst, src net.Conn, counter *atomic.Int64) {
	buffer := make([]byte, 8192)
	for {
		_ = src.SetReadDeadline(time.Now().Add(peerServiceIdleTimeout))
		n, err := src.Read(buffer)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(peerServiceIdleTimeout))
			written, writeErr := dst.Write(buffer[:n])
			counter.Add(int64(written))
			if writeErr != nil || written != n {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func acquirePeerServiceResource(udp bool, source netip.Addr) (func(), bool) {
	source = source.Unmap()
	peerServiceResourceBudget.Lock()
	global := &peerServiceResourceBudget.tcpGlobal
	sources := peerServiceResourceBudget.tcpSources
	globalLimit := peerServiceTCPGlobalLimit
	sourceLimit := peerServiceTCPPerSourceLimit
	if udp {
		global = &peerServiceResourceBudget.udpGlobal
		sources = peerServiceResourceBudget.udpSources
		globalLimit = peerServiceUDPGlobalLimit
		sourceLimit = peerServiceUDPPerSourceLimit
	}
	if *global >= globalLimit || sources[source] >= sourceLimit {
		peerServiceResourceBudget.Unlock()
		return nil, false
	}
	(*global)++
	sources[source]++
	peerServiceResourceBudget.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			peerServiceResourceBudget.Lock()
			(*global)--
			sources[source]--
			if sources[source] <= 0 {
				delete(sources, source)
			}
			peerServiceResourceBudget.Unlock()
		})
	}, true
}

func (b *peerServiceBridge) close() {
	if !b.closed.CompareAndSwap(false, true) {
		return
	}
	if b.logger != nil {
		b.logger.Printf("[peer-service-access-audit] action=revoke serviceId=%s activeConnections=%d reason=config-withdrawn-or-shutdown",
			b.service.ServiceID, b.active.Load())
	}
	if b.listener != nil {
		_ = b.listener.Close()
	}
	if b.udp != nil {
		_ = b.udp.Close()
	}
	b.udpPeers.Range(func(key, value any) bool {
		if binding, ok := value.(*peerServiceUDPPeer); ok && b.udpPeers.CompareAndDelete(key, binding) {
			binding.close()
		}
		return true
	})
	b.connMu.Lock()
	for conn := range b.conns {
		_ = conn.Close()
	}
	clear(b.conns)
	b.connMu.Unlock()
}

func equalStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
