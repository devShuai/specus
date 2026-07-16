// Package peermesh implements the Java-compatible Peer Mesh control plane for the Go server.
package peermesh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/auth"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/protocol"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/session"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

const (
	TypeCandidates    = "candidates"
	TypeSessionGrant  = "session-grant"
	TypeRoster        = "roster"
	TypeConfig        = "peer-config"
	TypePathReport    = "path-report"
	TypeTrafficReport = "traffic-report"
	TypeDeviceReport  = "device-report"
	TypeClose         = "close"

	PathDirect = "DIRECT"
	PathRelay  = "RELAY"

	StatusNegotiating = "NEGOTIATING"
	StatusActive      = "ACTIVE"
	StatusClosed      = "CLOSED"

	relayAuthorizationCacheTTL = 30 * time.Second
)

// AccessContext is the tiny management-auth shape needed by Peer Mesh.
type AccessContext struct {
	Username string
	TenantID string
	Admin    bool
}

// LoginConfig is the client-auth peerMesh object.
type LoginConfig struct {
	Enabled           bool     `json:"enabled"`
	ClientID          int64    `json:"clientId"`
	ClientName        string   `json:"clientName"`
	VirtualIP         string   `json:"virtualIp"`
	CIDR              string   `json:"cidr"`
	StunHost          string   `json:"stunHost"`
	StunPort          int      `json:"stunPort"`
	TurnHost          string   `json:"turnHost"`
	TurnPort          int      `json:"turnPort"`
	PublicStunServers []string `json:"publicStunServers"`
	IceUsername       string   `json:"iceUsername"`
	IceCredential     string   `json:"iceCredential"`
	IceRealm          string   `json:"iceRealm"`
	IceNonce          string   `json:"iceNonce"`
	ServerPublicKey   string   `json:"serverPublicKey"`
	ClientPublicKey   string   `json:"clientPublicKey"`
	SessionTTLSeconds int64    `json:"sessionTtlSeconds"`
}

type DeviceView struct {
	ID                     int64   `json:"id"`
	ClientID               int64   `json:"clientId"`
	ClientName             string  `json:"clientName"`
	OwnerUsername          string  `json:"ownerUsername"`
	Enabled                bool    `json:"enabled"`
	Online                 bool    `json:"online"`
	VirtualIP              string  `json:"virtualIp"`
	CIDR                   string  `json:"cidr"`
	PublicKey              *string `json:"publicKey,omitempty"`
	NatType                *string `json:"natType,omitempty"`
	NatMappingBehavior     *string `json:"natMappingBehavior,omitempty"`
	NatFilteringBehavior   *string `json:"natFilteringBehavior,omitempty"`
	NatBehaviorDiscovery   *string `json:"natBehaviorDiscovery,omitempty"`
	LastEndpoint           *string `json:"lastEndpoint,omitempty"`
	VirtualDeviceMode      *string `json:"virtualDeviceMode,omitempty"`
	VirtualDeviceName      *string `json:"virtualDeviceName,omitempty"`
	VirtualDeviceStatus    *string `json:"virtualDeviceStatus,omitempty"`
	VirtualDeviceError     *string `json:"virtualDeviceError,omitempty"`
	VirtualDeviceUpdatedAt *string `json:"virtualDeviceUpdatedAt,omitempty"`
	LastSeenAt             *string `json:"lastSeenAt,omitempty"`
	UpdatedAt              string  `json:"updatedAt"`
}

type ACLView struct {
	ID               int64  `json:"id"`
	SourceClientID   int64  `json:"sourceClientId"`
	SourceClientName string `json:"sourceClientName"`
	TargetClientID   int64  `json:"targetClientId"`
	TargetClientName string `json:"targetClientName"`
	Allowed          bool   `json:"allowed"`
	Direction        string `json:"direction"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
}

type SessionView struct {
	ID               int64   `json:"id"`
	SourceClientID   int64   `json:"sourceClientId"`
	SourceClientName string  `json:"sourceClientName"`
	TargetClientID   int64   `json:"targetClientId"`
	TargetClientName string  `json:"targetClientName"`
	PathType         string  `json:"pathType"`
	Status           string  `json:"status"`
	RTTMillis        *int64  `json:"rttMillis,omitempty"`
	LocalEndpoint    *string `json:"localEndpoint,omitempty"`
	RemoteEndpoint   *string `json:"remoteEndpoint,omitempty"`
	DirectBytes      int64   `json:"directBytes"`
	RelayBytes       int64   `json:"relayBytes"`
	LastTrafficAt    *string `json:"lastTrafficAt,omitempty"`
	StartedAt        string  `json:"startedAt"`
	UpdatedAt        string  `json:"updatedAt"`
	ExpiresAt        string  `json:"expiresAt"`
	ClosedAt         *string `json:"closedAt,omitempty"`
}

type SessionPage struct {
	Items      []SessionView `json:"items"`
	Total      int           `json:"total"`
	Page       int           `json:"page"`
	Size       int           `json:"size"`
	TotalPages int           `json:"totalPages"`
}

type PathStatsView struct {
	TotalSessions                int64             `json:"totalSessions"`
	ReportedSessions             int64             `json:"reportedSessions"`
	ActiveSessions               int64             `json:"activeSessions"`
	ActiveDirectSessions         int64             `json:"activeDirectSessions"`
	ActiveRelaySessions          int64             `json:"activeRelaySessions"`
	ActiveDirectRatio            *float64          `json:"activeDirectRatio"`
	PathTypes                    []PathTypeStat    `json:"pathTypes"`
	NatTypes                     []NatTypeStat     `json:"natTypes"`
	NatBehaviorDevices           int64             `json:"natBehaviorDevices"`
	NatBehaviorClassifiedDevices int64             `json:"natBehaviorClassifiedDevices"`
	NatBehaviorSuccessRatio      *float64          `json:"natBehaviorSuccessRatio"`
	NatMappingBehaviors          []NatBehaviorStat `json:"natMappingBehaviors"`
	NatFilteringBehaviors        []NatBehaviorStat `json:"natFilteringBehaviors"`
	NatBehaviorDiscoveries       []NatBehaviorStat `json:"natBehaviorDiscoveries"`
}

type PathTypeStat struct {
	PathType         string   `json:"pathType"`
	Status           string   `json:"status"`
	Sessions         int64    `json:"sessions"`
	ReportedSessions int64    `json:"reportedSessions"`
	AvgRttMillis     *float64 `json:"avgRttMillis"`
	DirectBytes      int64    `json:"directBytes"`
	RelayBytes       int64    `json:"relayBytes"`
}

type NatTypeStat struct {
	NatType string `json:"natType"`
	Devices int64  `json:"devices"`
}

type NatBehaviorStat struct {
	Behavior string `json:"behavior"`
	Devices  int64  `json:"devices"`
}

type PublicStunConfig struct {
	PeerMeshEnabled      bool     `json:"peerMeshEnabled"`
	SelfHostedStunServer string   `json:"selfHostedStunServer"`
	StunServers          []string `json:"stunServers"`
	StunTurnPort         int      `json:"stunTurnPort"`
}

type PublicIceConfig struct {
	PeerMeshEnabled  bool        `json:"peerMeshEnabled"`
	IceServers       []IceServer `json:"iceServers"`
	TurnAuthRequired bool        `json:"turnAuthRequired"`
	StunTurnPort     int         `json:"stunTurnPort"`
}

type IceServer struct {
	URLs       string `json:"urls"`
	Username   string `json:"username"`
	Credential string `json:"credential"`
}

type RosterItem struct {
	ClientID   int64   `json:"clientId"`
	ClientName string  `json:"clientName"`
	VirtualIP  string  `json:"virtualIp"`
	PublicKey  *string `json:"publicKey,omitempty"`
	Online     bool    `json:"online"`
}

type Candidate struct {
	Type       string `json:"type,omitempty"`
	Transport  string `json:"transport,omitempty"`
	Address    string `json:"address,omitempty"`
	Port       int    `json:"port,omitempty"`
	Priority   int64  `json:"priority,omitempty"`
	Foundation string `json:"foundation,omitempty"`
	RelayID    string `json:"relayId,omitempty"`
}

type ControlMessage struct {
	Type                 string       `json:"type"`
	SourceClientID       int64        `json:"sourceClientId,omitempty"`
	SourceClientName     string       `json:"sourceClientName,omitempty"`
	SourceVirtualIP      string       `json:"sourceVirtualIp,omitempty"`
	SourcePublicKey      *string      `json:"sourcePublicKey,omitempty"`
	TargetClientID       int64        `json:"targetClientId,omitempty"`
	TargetClientName     string       `json:"targetClientName,omitempty"`
	TargetVirtualIP      string       `json:"targetVirtualIp,omitempty"`
	TargetPublicKey      *string      `json:"targetPublicKey,omitempty"`
	SessionID            *int64       `json:"sessionId,omitempty"`
	Token                string       `json:"token,omitempty"`
	ExpiresAt            string       `json:"expiresAt,omitempty"`
	PathType             string       `json:"pathType,omitempty"`
	Status               string       `json:"status,omitempty"`
	RTTMillis            *int64       `json:"rttMillis,omitempty"`
	LocalEndpoint        *string      `json:"localEndpoint,omitempty"`
	RemoteEndpoint       *string      `json:"remoteEndpoint,omitempty"`
	DirectBytes          int64        `json:"directBytes,omitempty"`
	RelayBytes           int64        `json:"relayBytes,omitempty"`
	NatType              *string      `json:"natType,omitempty"`
	NatMappingBehavior   *string      `json:"natMappingBehavior,omitempty"`
	NatFilteringBehavior *string      `json:"natFilteringBehavior,omitempty"`
	NatBehaviorDiscovery *string      `json:"natBehaviorDiscovery,omitempty"`
	LastEndpoint         *string      `json:"lastEndpoint,omitempty"`
	VirtualDeviceMode    *string      `json:"virtualDeviceMode,omitempty"`
	VirtualDeviceName    *string      `json:"virtualDeviceName,omitempty"`
	VirtualDeviceStatus  *string      `json:"virtualDeviceStatus,omitempty"`
	VirtualDeviceError   *string      `json:"virtualDeviceError,omitempty"`
	PeerMesh             *LoginConfig `json:"peerMesh,omitempty"`
	Candidates           []Candidate  `json:"candidates,omitempty"`
	Peers                []RosterItem `json:"peers,omitempty"`
	Reason               string       `json:"reason,omitempty"`
	CreatedAtMillis      int64        `json:"createdAtMillis,omitempty"`
}

type DeviceMutation struct {
	Enabled *bool `json:"enabled"`
}

type ACLMutation struct {
	SourceClientID *int64  `json:"sourceClientId"`
	TargetClientID *int64  `json:"targetClientId"`
	Allowed        *bool   `json:"allowed"`
	Direction      *string `json:"direction"`
}

type sessionGrant struct {
	session SessionView
	token   string
}

type Service struct {
	cfg                 config.PeerMeshConfig
	db                  *store.DB
	sessions            *session.Registry
	logger              *slog.Logger
	relayMu             sync.Mutex
	relayAuthorizations map[int64]relayAuthorization
	pendingRelayBytes   map[int64]int64
	turnCredentials     *turnCredentialService
}

type relayAuthorization struct {
	sourceClientID   int64
	targetClientID   int64
	active           bool
	sessionExpiresAt time.Time
	cacheExpiresAt   time.Time
}

func New(cfg config.PeerMeshConfig, db *store.DB, sessions *session.Registry, logger *slog.Logger) *Service {
	if strings.TrimSpace(cfg.CIDR) == "" {
		cfg.CIDR = "100.96.0.0/11"
	}
	if cfg.StunTurnPort <= 0 {
		cfg.StunTurnPort = 3478
	}
	if cfg.SessionTTLSeconds <= 0 {
		cfg.SessionTTLSeconds = 3600
	}
	if cfg.AllocationTTLSeconds <= 0 {
		cfg.AllocationTTLSeconds = 300
	}
	if cfg.SessionCleanupIntervalMs <= 0 {
		cfg.SessionCleanupIntervalMs = 60000
	}
	if cfg.RelayTrafficFlushIntervalMs <= 0 {
		cfg.RelayTrafficFlushIntervalMs = 5000
	}
	if strings.TrimSpace(cfg.TurnRealm) == "" {
		cfg.TurnRealm = "shuai-tunnel"
	}
	if cfg.TurnCredentialTTLSeconds <= 0 {
		cfg.TurnCredentialTTLSeconds = 3600
	}
	credentials := newTurnCredentialService(cfg)
	return &Service{
		cfg: cfg, db: db, sessions: sessions, logger: logger,
		relayAuthorizations: make(map[int64]relayAuthorization),
		pendingRelayBytes:   make(map[int64]int64),
		turnCredentials:     credentials,
	}
}

func (s *Service) Enabled() bool {
	return s != nil && s.cfg.Enabled
}

func (s *Service) AuthorizeRelayFrame(ctx context.Context, header DataFrameHeader, bytes int64) bool {
	if s == nil || bytes <= 0 {
		return false
	}
	now := time.Now()
	if s.authorizeRelayFrameCached(header, bytes, now) {
		return true
	}
	item, err := s.db.GetPeerMeshSession(ctx, header.SessionID)
	if err != nil || item == nil {
		return false
	}
	if s.closeIfExpired(item, now) {
		_ = s.db.UpdatePeerMeshSession(ctx, *item)
		return false
	}
	if item.Status != StatusActive {
		return false
	}
	forward := header.FromClientID == item.SourceClientID && header.ToClientID == item.TargetClientID
	reverse := header.FromClientID == item.TargetClientID && header.ToClientID == item.SourceClientID
	if !forward && !reverse {
		s.removeRelaySession(header.SessionID)
		return false
	}
	s.cacheRelayAuthorization(*item, now)
	s.addPendingRelayBytes(header.SessionID, bytes)
	return true
}

func (s *Service) Run(ctx context.Context) {
	if s == nil {
		return
	}
	sessionTicker := time.NewTicker(time.Duration(s.cfg.SessionCleanupIntervalMs) * time.Millisecond)
	defer sessionTicker.Stop()
	relayTicker := time.NewTicker(time.Duration(s.cfg.RelayTrafficFlushIntervalMs) * time.Millisecond)
	defer relayTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := s.FlushRelayTraffic(context.Background()); err != nil {
				s.logger.Warn("peer mesh relay traffic final flush failed", "err", err)
			}
			return
		case <-sessionTicker.C:
			if n, err := s.expireStaleSessions(ctx, 500); err != nil {
				s.logger.Warn("peer mesh session cleanup failed", "err", err)
			} else if n > 0 {
				s.logger.Debug("peer mesh sessions expired", "count", n)
			}
		case <-relayTicker.C:
			if err := s.FlushRelayTraffic(ctx); err != nil {
				s.logger.Warn("peer mesh relay traffic flush failed", "err", err)
			}
		}
	}
}

func (s *Service) BuildLoginConfig(ctx context.Context, account store.ClientAccount, peerPublicKey, requestHost string) (LoginConfig, error) {
	var device *store.PeerMeshDevice
	var err error
	if s.Enabled() {
		device, err = s.EnsureDevice(ctx, account, peerPublicKey)
		if err != nil {
			return LoginConfig{}, err
		}
	}
	return s.buildConfig(account, device, requestHost), nil
}

func (s *Service) BuildRuntimeConfig(ctx context.Context, account store.ClientAccount) (LoginConfig, error) {
	var device *store.PeerMeshDevice
	var err error
	if s.Enabled() {
		device, err = s.db.FindPeerMeshDeviceByClientID(ctx, account.TenantID, account.ID)
		if err != nil {
			return LoginConfig{}, err
		}
		if device == nil {
			device, err = s.createDevice(ctx, account)
			if err != nil {
				return LoginConfig{}, err
			}
		}
	}
	return s.buildConfig(account, device, ""), nil
}

func (s *Service) buildConfig(account store.ClientAccount, device *store.PeerMeshDevice, requestHost string) LoginConfig {
	cfg := LoginConfig{
		Enabled:           false,
		ClientID:          account.ID,
		ClientName:        account.ClientName,
		CIDR:              s.cfg.CIDR,
		SessionTTLSeconds: s.cfg.SessionTTLSeconds,
	}
	if !s.Enabled() || device == nil {
		return cfg
	}
	cfg.Enabled = device.Enabled
	cfg.VirtualIP = device.VirtualIP
	cfg.StunHost = s.resolveStunHost(requestHost)
	cfg.TurnHost = s.resolvePeerHost(requestHost)
	cfg.StunPort = s.stunPort()
	cfg.TurnPort = s.cfg.StunTurnPort
	cfg.PublicStunServers = s.publicStunServers()
	credential := s.turnCredentials.issue("pm-" + strconv.FormatInt(account.ID, 10))
	cfg.IceUsername = credential.Username
	cfg.IceCredential = credential.Credential
	cfg.IceRealm = credential.Realm
	cfg.IceNonce = credential.Nonce
	cfg.ServerPublicKey = serverPublicKey()
	if device.PublicKey != nil {
		cfg.ClientPublicKey = *device.PublicKey
	}
	return cfg
}

func (s *Service) PublicStunConfig(requestHost string) PublicStunConfig {
	if s == nil {
		return PublicStunConfig{}
	}
	servers := make([]string, 0, 1+len(s.cfg.PublicStunServers))
	seen := make(map[string]struct{})
	selfHosted := ""
	if s.Enabled() || s.hasStandaloneStun() {
		selfHosted = s.selfHostedStunServer(requestHost)
		if selfHosted != "" {
			servers = appendUnique(servers, seen, selfHosted)
		}
	}
	for _, item := range s.publicStunServers() {
		servers = appendUnique(servers, seen, item)
	}
	return PublicStunConfig{
		PeerMeshEnabled:      s.Enabled(),
		SelfHostedStunServer: selfHosted,
		StunServers:          servers,
		StunTurnPort:         s.cfg.StunTurnPort,
	}
}

// PublicIceConfig returns browser-compatible STUN/TURN URLs and short-lived credentials.
func (s *Service) PublicIceConfig(requestHost string) PublicIceConfig {
	stun := s.PublicStunConfig(requestHost)
	servers := make([]IceServer, 0, len(stun.StunServers)+1)
	for _, value := range stun.StunServers {
		servers = append(servers, IceServer{URLs: value})
	}
	if s != nil && s.Enabled() {
		host := normalizeStunHost(s.resolvePeerHost(requestHost))
		if strings.TrimSpace(host) != "" && s.cfg.StunTurnPort > 0 {
			if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
				host = "[" + host + "]"
			}
			credential := s.turnCredentials.issue("public-transfer")
			servers = append(servers, IceServer{
				URLs:       "turn:" + host + ":" + strconv.Itoa(s.cfg.StunTurnPort) + "?transport=udp",
				Username:   credential.Username,
				Credential: credential.Credential,
			})
		}
	}
	return PublicIceConfig{
		PeerMeshEnabled:  stun.PeerMeshEnabled,
		IceServers:       servers,
		TurnAuthRequired: s != nil && s.cfg.TurnAuthRequired,
		StunTurnPort:     stun.StunTurnPort,
	}
}

func (s *Service) EnsureDevice(ctx context.Context, account store.ClientAccount, peerPublicKey string) (*store.PeerMeshDevice, error) {
	device, err := s.db.FindPeerMeshDeviceByClientID(ctx, account.TenantID, account.ID)
	if err != nil {
		return nil, err
	}
	if device == nil {
		device, err = s.createDevice(ctx, account)
		if err != nil {
			return nil, err
		}
	}
	now := time.Now()
	device.ClientName = account.ClientName
	device.OwnerUsername = normalizeOwner(account.OwnerUsername)
	if strings.TrimSpace(peerPublicKey) != "" {
		value := capString(strings.TrimSpace(peerPublicKey), 256)
		device.PublicKey = &value
	}
	device.LastSeenAt = &now
	device.UpdatedAt = now
	return device, s.db.UpdatePeerMeshDevice(ctx, *device)
}

func (s *Service) HandleSignal(ctx context.Context, request protocol.MessageRequest, sourceClientName string) error {
	if !s.Enabled() {
		return errors.New("peer mesh is disabled")
	}
	source, err := s.db.FindClientByName(ctx, sourceClientName)
	if err != nil || source == nil {
		return fmt.Errorf("source client not found: %s", sourceClientName)
	}
	var signal ControlMessage
	if err := json.Unmarshal([]byte(request.Message), &signal); err != nil || strings.TrimSpace(signal.Type) == "" {
		return errors.New("invalid peer signal")
	}
	if err := s.fillSource(ctx, &signal, *source); err != nil {
		return err
	}

	switch signal.Type {
	case TypePathReport:
		_, err := s.ReportPath(ctx, *source, signal)
		return err
	case TypeTrafficReport:
		_, err := s.ReportTraffic(ctx, *source, signal)
		return err
	case TypeDeviceReport:
		_, err := s.ReportDevice(ctx, *source, signal)
		return err
	case TypeClose:
		_, err := s.CloseSessionFromClient(ctx, *source, signal)
		if err != nil || strings.TrimSpace(request.ToClientName) == "" {
			return err
		}
	}

	targetName := strings.TrimSpace(request.ToClientName)
	if targetName == "" {
		return errors.New("toClientName is required")
	}
	target, err := s.db.FindClientByName(ctx, targetName)
	if err != nil || target == nil {
		return fmt.Errorf("target client not found: %s", targetName)
	}
	if ok, err := s.CanPeer(ctx, *source, *target); err != nil || !ok {
		if err != nil {
			return err
		}
		return errors.New("peer access denied")
	}
	targetSession, ok := s.sessions.Find(target.ClientName)
	if !ok || targetSession == nil {
		return fmt.Errorf("target peer is offline: %s", target.ClientName)
	}
	if err := s.enrichTarget(ctx, &signal, *target); err != nil {
		return err
	}
	if signal.SessionID == nil && (signal.Type == TypeCandidates || signal.Type == "offer") {
		grant, err := s.CreateSession(ctx, *source, *target, PathDirect)
		if err != nil {
			return err
		}
		id := grant.session.ID
		signal.SessionID = &id
		signal.Token = grant.token
		signal.ExpiresAt = grant.session.ExpiresAt
		s.sendSessionGrant(*source, *target, grant)
	}
	return s.sendSignal(targetSession, source.ClientName, target.ClientName, signal)
}

func (s *Service) PushRoster(ctx context.Context, account store.ClientAccount) {
	if !s.Enabled() {
		return
	}
	bound, ok := s.sessions.Find(account.ClientName)
	if !ok || bound == nil {
		return
	}
	peers, err := s.AllowedRoster(ctx, account)
	if err != nil {
		s.logger.Warn("build peer roster failed", "client", account.ClientName, "err", err)
		return
	}
	_ = s.sendSignal(bound, "server", account.ClientName, ControlMessage{
		Type: TypeRoster, SourceClientID: account.ID, SourceClientName: account.ClientName,
		Peers: peers, CreatedAtMillis: time.Now().UnixMilli(),
	})
}

func (s *Service) PushConfig(ctx context.Context, account store.ClientAccount) {
	bound, ok := s.sessions.Find(account.ClientName)
	if !ok || bound == nil {
		return
	}
	cfg, err := s.BuildRuntimeConfig(ctx, account)
	if err != nil {
		s.logger.Warn("build peer config failed", "client", account.ClientName, "err", err)
		return
	}
	_ = s.sendSignal(bound, "server", account.ClientName, ControlMessage{
		Type: TypeConfig, SourceClientID: account.ID, SourceClientName: account.ClientName,
		TargetClientID: account.ID, TargetClientName: account.ClientName,
		PeerMesh: &cfg, CreatedAtMillis: time.Now().UnixMilli(),
	})
}

func (s *Service) PushOnLogin(ctx context.Context, account store.ClientAccount) {
	if !s.Enabled() {
		return
	}
	s.PushConfig(ctx, account)
	for _, target := range s.rosterRefreshTargets(ctx, account) {
		s.PushRoster(ctx, target)
	}
}

func (s *Service) RefreshDevice(ctx context.Context, access AccessContext, clientID int64, enabled bool) ([]SessionView, error) {
	account, err := s.findClient(ctx, access, clientID, true)
	if err != nil {
		return nil, err
	}
	s.PushConfig(ctx, *account)
	var closed []SessionView
	if !enabled {
		closed, err = s.CloseOpenSessionsForDevice(ctx, access, clientID)
		if err != nil {
			return nil, err
		}
		for _, item := range closed {
			s.sendClose(item)
		}
	}
	for _, target := range s.rosterRefreshTargets(ctx, *account) {
		s.PushRoster(ctx, target)
	}
	return closed, nil
}

func (s *Service) ListDevices(ctx context.Context, access AccessContext) ([]DeviceView, error) {
	var devices []store.PeerMeshDevice
	var err error
	if access.Admin {
		devices, err = s.db.ListPeerMeshDevicesByTenant(ctx, access.TenantID)
	} else {
		devices, err = s.db.ListPeerMeshDevicesByOwner(ctx, access.TenantID, access.Username)
	}
	if err != nil {
		return nil, err
	}
	views := make([]DeviceView, 0, len(devices))
	for _, device := range devices {
		views = append(views, s.deviceView(device))
	}
	return views, nil
}

func (s *Service) UpdateDevice(ctx context.Context, access AccessContext, clientID int64, mutation DeviceMutation) (DeviceView, error) {
	device, err := s.findAccessibleDevice(ctx, access, clientID)
	if err != nil {
		return DeviceView{}, err
	}
	if mutation.Enabled != nil {
		device.Enabled = *mutation.Enabled
	}
	device.UpdatedAt = time.Now()
	if err := s.db.UpdatePeerMeshDevice(ctx, *device); err != nil {
		return DeviceView{}, err
	}
	if mutation.Enabled != nil {
		_, _ = s.RefreshDevice(ctx, access, clientID, *mutation.Enabled)
	}
	return s.deviceView(*device), nil
}

func (s *Service) ListACLs(ctx context.Context, access AccessContext) ([]ACLView, error) {
	var acls []store.PeerMeshACL
	var err error
	if access.Admin {
		acls, err = s.db.ListPeerMeshACLsByTenant(ctx, access.TenantID)
	} else {
		acls, err = s.db.ListPeerMeshACLsByOwner(ctx, access.TenantID, access.Username)
	}
	if err != nil {
		return nil, err
	}
	views := make([]ACLView, 0, len(acls))
	for _, acl := range acls {
		views = append(views, aclView(acl))
	}
	return views, nil
}

func (s *Service) CreateACL(ctx context.Context, access AccessContext, mutation ACLMutation) (ACLView, error) {
	if mutation.SourceClientID == nil || *mutation.SourceClientID <= 0 {
		return ACLView{}, errors.New("sourceClientId is required")
	}
	if mutation.TargetClientID == nil || *mutation.TargetClientID <= 0 {
		return ACLView{}, errors.New("targetClientId is required")
	}
	source, err := s.findClient(ctx, access, *mutation.SourceClientID, false)
	if err != nil {
		return ACLView{}, err
	}
	target, err := s.findTenantClient(ctx, access.TenantID, *mutation.TargetClientID)
	if err != nil {
		return ACLView{}, err
	}
	if source.ID == target.ID {
		return ACLView{}, errors.New("source and target cannot be the same client")
	}
	if !access.Admin && normalizeOwner(target.OwnerUsername) != access.Username {
		return ACLView{}, errors.New("普通用户不能创建跨用户 peer ACL")
	}
	acl, err := s.db.FindPeerMeshACL(ctx, access.TenantID, source.ID, target.ID)
	if err != nil {
		return ACLView{}, err
	}
	now := time.Now()
	if acl == nil {
		acl = &store.PeerMeshACL{
			ID: auth.NewClientID(), TenantID: access.TenantID,
			Direction: "OUTBOUND", CreatedAt: now,
		}
	}
	allowed := true
	if mutation.Allowed != nil {
		allowed = *mutation.Allowed
	}
	acl.OwnerUsername = access.Username
	acl.SourceClientID = source.ID
	acl.SourceClientName = source.ClientName
	acl.TargetClientID = target.ID
	acl.TargetClientName = target.ClientName
	acl.Allowed = allowed
	if mutation.Direction != nil {
		direction := strings.ToUpper(*mutation.Direction)
		if direction != "OUTBOUND" && direction != "INBOUND" && direction != "BOTH" {
			return ACLView{}, fmt.Errorf("invalid direction: %s", *mutation.Direction)
		}
		acl.Direction = direction
	}
	acl.UpdatedAt = now
	if acl.CreatedAt.IsZero() {
		acl.CreatedAt = now
	}
	if acl.ID == 0 {
		acl.ID = auth.NewClientID()
	}
	if existing, _ := s.db.GetPeerMeshACL(ctx, acl.ID); existing == nil {
		err = s.db.InsertPeerMeshACL(ctx, *acl)
	} else {
		err = s.db.UpdatePeerMeshACL(ctx, *acl)
	}
	if err != nil {
		return ACLView{}, err
	}
	return aclView(*acl), nil
}

func (s *Service) DeleteACL(ctx context.Context, access AccessContext, id int64) error {
	acl, err := s.db.GetPeerMeshACL(ctx, id)
	if err != nil {
		return err
	}
	if acl.TenantID != access.TenantID || (!access.Admin && acl.OwnerUsername != access.Username) {
		return store.ErrNotFound
	}
	return s.db.DeletePeerMeshACL(ctx, id)
}

func (s *Service) ListSessions(ctx context.Context, access AccessContext, limit int) ([]SessionView, error) {
	_, _ = s.expireStaleSessions(ctx, 500)
	var sessions []store.PeerMeshSession
	var err error
	if access.Admin {
		sessions, err = s.db.ListPeerMeshSessions(ctx, access.TenantID, limit)
	} else {
		ids, err := s.visibleClientIDs(ctx, access)
		if err != nil {
			return nil, err
		}
		sessions, err = s.db.ListVisiblePeerMeshSessions(ctx, access.TenantID, ids, limit)
	}
	if err != nil {
		return nil, err
	}
	views := make([]SessionView, 0, len(sessions))
	for _, item := range sessions {
		views = append(views, sessionView(item))
	}
	return views, nil
}

func (s *Service) ListSessionsPage(ctx context.Context, access AccessContext, page, size int, openOnly bool) (SessionPage, error) {
	_, _ = s.expireStaleSessions(ctx, 500)
	if page < 0 {
		page = 0
	}
	if size <= 0 || size > 200 {
		size = 100
	}
	var ids []int64
	filterIDs := false
	if !access.Admin {
		var err error
		ids, err = s.visibleClientIDs(ctx, access)
		if err != nil {
			return SessionPage{}, err
		}
		filterIDs = true
	}
	sessions, total, err := s.db.ListPeerMeshSessionsPage(ctx, access.TenantID, ids, filterIDs, page, size, openOnly, StatusClosed)
	if err != nil {
		return SessionPage{}, err
	}
	views := make([]SessionView, 0, len(sessions))
	for _, item := range sessions {
		views = append(views, sessionView(item))
	}
	return SessionPage{
		Items:      views,
		Total:      total,
		Page:       page,
		Size:       size,
		TotalPages: totalPages(total, size),
	}, nil
}

func (s *Service) PathStats(ctx context.Context, access AccessContext) (PathStatsView, error) {
	_, _ = s.expireStaleSessions(ctx, 500)
	var ids []int64
	filterIDs := false
	var err error
	if !access.Admin {
		ids, err = s.visibleClientIDs(ctx, access)
		if err != nil {
			return PathStatsView{}, err
		}
		filterIDs = true
	}
	pathAggregates, err := s.db.AggregatePeerMeshPathTypes(ctx, access.TenantID, ids, filterIDs)
	if err != nil {
		return PathStatsView{}, err
	}
	natAggregates, err := s.db.AggregatePeerMeshNatTypes(ctx, access.TenantID, access.Username, !access.Admin)
	if err != nil {
		return PathStatsView{}, err
	}
	natBehaviorAggregates, err := s.db.AggregatePeerMeshNatBehaviors(
		ctx,
		access.TenantID,
		access.Username,
		!access.Admin,
	)
	if err != nil {
		return PathStatsView{}, err
	}
	var total, reported, active, activeDirect, activeRelay int64
	pathTypes := make([]PathTypeStat, 0, len(pathAggregates))
	for _, item := range pathAggregates {
		total += item.Sessions
		reported += item.ReportedSessions
		if item.Status == StatusActive {
			active += item.Sessions
			switch item.PathType {
			case PathDirect:
				activeDirect += item.Sessions
			case PathRelay:
				activeRelay += item.Sessions
			}
		}
		pathTypes = append(pathTypes, PathTypeStat{
			PathType:         item.PathType,
			Status:           item.Status,
			Sessions:         item.Sessions,
			ReportedSessions: item.ReportedSessions,
			AvgRttMillis:     item.AvgRttMillis,
			DirectBytes:      item.DirectBytes,
			RelayBytes:       item.RelayBytes,
		})
	}
	natCounts := make(map[string]int64)
	natOrder := make([]string, 0, len(natAggregates))
	for _, item := range natAggregates {
		key := "UNKNOWN"
		if item.NatType != nil && strings.TrimSpace(*item.NatType) != "" {
			key = *item.NatType
		}
		if _, ok := natCounts[key]; !ok {
			natOrder = append(natOrder, key)
		}
		natCounts[key] += item.Devices
	}
	natTypes := make([]NatTypeStat, 0, len(natOrder))
	for _, key := range natOrder {
		natTypes = append(natTypes, NatTypeStat{NatType: key, Devices: natCounts[key]})
	}
	var natBehaviorDevices, natBehaviorClassifiedDevices int64
	mappingCounts := make(map[string]int64)
	filteringCounts := make(map[string]int64)
	discoveryCounts := make(map[string]int64)
	mappingOrder := make([]string, 0)
	filteringOrder := make([]string, 0)
	discoveryOrder := make([]string, 0)
	for _, item := range natBehaviorAggregates {
		if !hasNatBehavior(item.MappingBehavior) &&
			!hasNatBehavior(item.FilteringBehavior) &&
			!hasNatBehavior(item.Discovery) {
			continue
		}
		natBehaviorDevices += item.Devices
		mapping := normalizeNatBehavior(item.MappingBehavior)
		filtering := normalizeNatBehavior(item.FilteringBehavior)
		discovery := normalizeNatBehavior(item.Discovery)
		mergeNatBehavior(mappingCounts, &mappingOrder, mapping, item.Devices)
		mergeNatBehavior(filteringCounts, &filteringOrder, filtering, item.Devices)
		mergeNatBehavior(discoveryCounts, &discoveryOrder, discovery, item.Devices)
		if classifiedNatBehavior(mapping) && classifiedNatBehavior(filtering) {
			natBehaviorClassifiedDevices += item.Devices
		}
	}
	var directRatio *float64
	if active > 0 {
		value := float64(activeDirect) / float64(active)
		directRatio = &value
	}
	var natBehaviorSuccessRatio *float64
	if natBehaviorDevices > 0 {
		value := float64(natBehaviorClassifiedDevices) / float64(natBehaviorDevices)
		natBehaviorSuccessRatio = &value
	}
	return PathStatsView{
		TotalSessions:                total,
		ReportedSessions:             reported,
		ActiveSessions:               active,
		ActiveDirectSessions:         activeDirect,
		ActiveRelaySessions:          activeRelay,
		ActiveDirectRatio:            directRatio,
		PathTypes:                    pathTypes,
		NatTypes:                     natTypes,
		NatBehaviorDevices:           natBehaviorDevices,
		NatBehaviorClassifiedDevices: natBehaviorClassifiedDevices,
		NatBehaviorSuccessRatio:      natBehaviorSuccessRatio,
		NatMappingBehaviors:          natBehaviorStats(mappingCounts, mappingOrder),
		NatFilteringBehaviors:        natBehaviorStats(filteringCounts, filteringOrder),
		NatBehaviorDiscoveries:       natBehaviorStats(discoveryCounts, discoveryOrder),
	}, nil
}

func hasNatBehavior(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}

func normalizeNatBehavior(value *string) string {
	if !hasNatBehavior(value) {
		return "UNKNOWN"
	}
	return strings.TrimSpace(*value)
}

func classifiedNatBehavior(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	return normalized != "" && normalized != "UNKNOWN" && normalized != "UNSUPPORTED"
}

func mergeNatBehavior(counts map[string]int64, order *[]string, key string, devices int64) {
	if _, ok := counts[key]; !ok {
		*order = append(*order, key)
	}
	counts[key] += devices
}

func natBehaviorStats(counts map[string]int64, order []string) []NatBehaviorStat {
	result := make([]NatBehaviorStat, 0, len(order))
	for _, key := range order {
		result = append(result, NatBehaviorStat{Behavior: key, Devices: counts[key]})
	}
	return result
}

func (s *Service) ForceClose(ctx context.Context, access AccessContext, sessionID int64) (SessionView, error) {
	item, err := s.findAccessibleSession(ctx, access, sessionID)
	if err != nil {
		return SessionView{}, err
	}
	s.markClosed(item, time.Now())
	if err := s.db.UpdatePeerMeshSession(ctx, *item); err != nil {
		return SessionView{}, err
	}
	view := sessionView(*item)
	s.sendClose(view)
	return view, nil
}

func (s *Service) CloseOpenSessions(ctx context.Context, access AccessContext) ([]SessionView, error) {
	var ids []int64
	var err error
	if !access.Admin {
		ids, err = s.visibleClientIDs(ctx, access)
		if err != nil {
			return nil, err
		}
	}
	items, err := s.db.ListOpenPeerMeshSessions(ctx, access.TenantID, ids, StatusClosed)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	views := make([]SessionView, 0, len(items))
	for _, item := range items {
		s.markClosed(&item, now)
		if err := s.db.UpdatePeerMeshSession(ctx, item); err != nil {
			return nil, err
		}
		view := sessionView(item)
		views = append(views, view)
		s.sendClose(view)
	}
	return views, nil
}

func (s *Service) CloseOpenSessionsForDevice(ctx context.Context, access AccessContext, clientID int64) ([]SessionView, error) {
	device, err := s.findAccessibleDevice(ctx, access, clientID)
	if err != nil {
		return nil, err
	}
	items, err := s.db.ListOpenPeerMeshSessionsForDevice(ctx, access.TenantID, device.ClientID, StatusClosed)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	views := make([]SessionView, 0, len(items))
	for _, item := range items {
		s.markClosed(&item, now)
		if err := s.db.UpdatePeerMeshSession(ctx, item); err != nil {
			return nil, err
		}
		views = append(views, sessionView(item))
	}
	return views, nil
}

func (s *Service) CanPeer(ctx context.Context, source, target store.ClientAccount) (bool, error) {
	if source.TenantID != target.TenantID {
		return false, nil
	}
	sourceDevice, err := s.db.FindPeerMeshDeviceByClientID(ctx, source.TenantID, source.ID)
	if err != nil || sourceDevice == nil || !sourceDevice.Enabled {
		return false, err
	}
	targetDevice, err := s.db.FindPeerMeshDeviceByClientID(ctx, target.TenantID, target.ID)
	if err != nil || targetDevice == nil || !targetDevice.Enabled {
		return false, err
	}
	if normalizeOwner(source.OwnerUsername) == normalizeOwner(target.OwnerUsername) {
		return true, nil
	}
	forward, err := s.db.FindPeerMeshACL(ctx, source.TenantID, source.ID, target.ID)
	if err != nil {
		return false, err
	}
	if forward != nil && forward.Allowed && (forward.Direction == "OUTBOUND" || forward.Direction == "BOTH") {
		return true, nil
	}
	reverse, err := s.db.FindPeerMeshACL(ctx, source.TenantID, target.ID, source.ID)
	if err != nil {
		return false, err
	}
	return reverse != nil && reverse.Allowed && (reverse.Direction == "INBOUND" || reverse.Direction == "BOTH"), nil
}

func (s *Service) CreateSession(ctx context.Context, source, target store.ClientAccount, pathType string) (sessionGrant, error) {
	ok, err := s.CanPeer(ctx, source, target)
	if err != nil || !ok {
		if err != nil {
			return sessionGrant{}, err
		}
		return sessionGrant{}, errors.New("peer access denied")
	}
	now := time.Now()
	token := s.shortToken(source.ClientName, target.ClientName, strconv.FormatInt(now.UnixMilli(), 10), randomSuffix())
	hash := sha256.Sum256([]byte(token))
	item := store.PeerMeshSession{
		ID:               auth.NewClientID(),
		TenantID:         source.TenantID,
		SourceClientID:   source.ID,
		SourceClientName: source.ClientName,
		TargetClientID:   target.ID,
		TargetClientName: target.ClientName,
		PathType:         firstText(pathType, PathDirect),
		Status:           StatusNegotiating,
		TokenHash:        stringPtr(hex.EncodeToString(hash[:])),
		StartedAt:        now,
		UpdatedAt:        now,
		ExpiresAt:        now.Add(time.Duration(s.cfg.SessionTTLSeconds) * time.Second),
	}
	if err := s.db.InsertPeerMeshSession(ctx, item); err != nil {
		return sessionGrant{}, err
	}
	return sessionGrant{session: sessionView(item), token: token}, nil
}

func (s *Service) ReportPath(ctx context.Context, reporter store.ClientAccount, report ControlMessage) (SessionView, error) {
	item, err := s.findReportableSession(ctx, reporter, report.SessionID)
	if err != nil {
		return SessionView{}, err
	}
	now := time.Now()
	if !s.closeIfExpired(item, now) {
		if strings.TrimSpace(report.PathType) != "" {
			if item.DirectBytes <= 0 && item.RelayBytes <= 0 {
				item.PathType = capString(report.PathType, 40)
			} else {
				item.PathType = effectivePathType(*item)
			}
		}
		if strings.TrimSpace(report.Status) != "" {
			item.Status = capString(report.Status, 40)
		} else {
			item.Status = StatusActive
		}
		item.RTTMillis = report.RTTMillis
		item.LocalEndpoint = capStringPtr(report.LocalEndpoint, 255)
		item.RemoteEndpoint = capStringPtr(report.RemoteEndpoint, 255)
		item.UpdatedAt = now
	}
	if err := s.db.UpdatePeerMeshSession(ctx, *item); err != nil {
		return SessionView{}, err
	}
	return sessionView(*item), nil
}

func (s *Service) ReportTraffic(ctx context.Context, reporter store.ClientAccount, report ControlMessage) (SessionView, error) {
	item, err := s.findReportableSession(ctx, reporter, report.SessionID)
	if err != nil {
		return SessionView{}, err
	}
	now := time.Now()
	if !s.closeIfExpired(item, now) {
		s.applyTraffic(item, maxZero(report.DirectBytes), maxZero(report.RelayBytes), now)
	}
	if err := s.db.UpdatePeerMeshSession(ctx, *item); err != nil {
		return SessionView{}, err
	}
	return sessionView(*item), nil
}

func (s *Service) ReportDevice(ctx context.Context, reporter store.ClientAccount, report ControlMessage) (DeviceView, error) {
	device, err := s.db.FindPeerMeshDeviceByClientID(ctx, reporter.TenantID, reporter.ID)
	if err != nil {
		return DeviceView{}, err
	}
	if device == nil {
		device, err = s.createDevice(ctx, reporter)
		if err != nil {
			return DeviceView{}, err
		}
	}
	now := time.Now()
	device.ClientName = reporter.ClientName
	device.OwnerUsername = normalizeOwner(reporter.OwnerUsername)
	if report.VirtualDeviceMode != nil {
		device.VirtualDeviceMode = capStringPtr(report.VirtualDeviceMode, 80)
	}
	if report.VirtualDeviceName != nil {
		device.VirtualDeviceName = capStringPtr(report.VirtualDeviceName, 80)
	}
	if report.VirtualDeviceStatus != nil {
		device.VirtualDeviceStatus = capStringPtr(report.VirtualDeviceStatus, 80)
	}
	if report.VirtualDeviceError != nil {
		device.VirtualDeviceError = capStringPtr(report.VirtualDeviceError, 512)
	}
	if report.VirtualDeviceMode != nil || report.VirtualDeviceName != nil || report.VirtualDeviceStatus != nil || report.VirtualDeviceError != nil {
		device.VirtualDeviceUpdatedAt = &now
	}
	if report.NatType != nil {
		device.NatType = capStringPtr(report.NatType, 80)
	}
	if report.NatMappingBehavior != nil {
		device.NatMappingBehavior = capStringPtr(report.NatMappingBehavior, 80)
	}
	if report.NatFilteringBehavior != nil {
		device.NatFilteringBehavior = capStringPtr(report.NatFilteringBehavior, 80)
	}
	if report.NatBehaviorDiscovery != nil {
		device.NatBehaviorDiscovery = capStringPtr(report.NatBehaviorDiscovery, 40)
	}
	if report.LastEndpoint != nil {
		device.LastEndpoint = capStringPtr(report.LastEndpoint, 255)
	}
	device.LastSeenAt = &now
	device.UpdatedAt = now
	if err := s.db.UpdatePeerMeshDevice(ctx, *device); err != nil {
		return DeviceView{}, err
	}
	return s.deviceView(*device), nil
}

func (s *Service) CloseSessionFromClient(ctx context.Context, reporter store.ClientAccount, close ControlMessage) (SessionView, error) {
	item, err := s.findReportableSession(ctx, reporter, close.SessionID)
	if err != nil {
		return SessionView{}, err
	}
	s.markClosed(item, time.Now())
	if err := s.db.UpdatePeerMeshSession(ctx, *item); err != nil {
		return SessionView{}, err
	}
	return sessionView(*item), nil
}

func (s *Service) AllowedRoster(ctx context.Context, account store.ClientAccount) ([]RosterItem, error) {
	if !s.Enabled() {
		return nil, nil
	}
	devices, err := s.db.ListEnabledPeerMeshDevicesByOwner(ctx, account.TenantID, normalizeOwner(account.OwnerUsername))
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]store.PeerMeshDevice, len(devices))
	for _, device := range devices {
		byID[device.ClientID] = device
	}
	acls, err := s.db.ListPeerMeshACLsByTenant(ctx, account.TenantID)
	if err != nil {
		return nil, err
	}
	for _, acl := range acls {
		if acl.Allowed && acl.SourceClientID == account.ID {
			if device, err := s.db.FindPeerMeshDeviceByClientID(ctx, account.TenantID, acl.TargetClientID); err == nil && device != nil && device.Enabled {
				byID[device.ClientID] = *device
			}
		}
	}
	delete(byID, account.ID)
	out := make([]RosterItem, 0, len(byID))
	for _, device := range byID {
		_, online := s.sessions.Find(device.ClientName)
		out = append(out, RosterItem{
			ClientID: device.ClientID, ClientName: device.ClientName, VirtualIP: device.VirtualIP,
			PublicKey: device.PublicKey, Online: online,
		})
	}
	return out, nil
}

func (s *Service) createDevice(ctx context.Context, account store.ClientAccount) (*store.PeerMeshDevice, error) {
	now := time.Now()
	device := store.PeerMeshDevice{
		ID:            auth.NewClientID(),
		TenantID:      account.TenantID,
		OwnerUsername: normalizeOwner(account.OwnerUsername),
		ClientID:      account.ID,
		ClientName:    account.ClientName,
		CIDR:          s.cfg.CIDR,
		Enabled:       false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	ip, err := s.allocateVirtualIP(ctx, account)
	if err != nil {
		return nil, err
	}
	device.VirtualIP = ip
	if err := s.db.InsertPeerMeshDevice(ctx, device); err != nil {
		return nil, err
	}
	return &device, nil
}

func (s *Service) allocateVirtualIP(ctx context.Context, account store.ClientAccount) (string, error) {
	prefix, err := netip.ParsePrefix(s.cfg.CIDR)
	if err != nil || !prefix.Addr().Is4() {
		return "", fmt.Errorf("invalid peer mesh cidr: %s", s.cfg.CIDR)
	}
	bits := prefix.Bits()
	capacity := uint64(1) << uint(32-bits)
	if capacity < 4 {
		return "", fmt.Errorf("peer mesh address pool too small: %s", s.cfg.CIDR)
	}
	base := ipv4ToUint32(prefix.Masked().Addr())
	h := fnv.New32a()
	_, _ = h.Write([]byte(account.TenantID + ":" + account.OwnerUsername + ":" + strconv.FormatInt(account.ID, 10)))
	usable := capacity - 2
	seed := uint64(h.Sum32()) % usable
	for i := uint64(1); i <= usable; i++ {
		host := ((seed + i) % usable) + 1
		ip := uint32ToIPv4(base + uint32(host))
		existing, err := s.db.FindPeerMeshDeviceByVirtualIP(ctx, account.TenantID, ip)
		if err != nil {
			return "", err
		}
		if existing == nil {
			return ip, nil
		}
	}
	return "", fmt.Errorf("peer mesh address pool exhausted: %s", s.cfg.CIDR)
}

func (s *Service) fillSource(ctx context.Context, signal *ControlMessage, source store.ClientAccount) error {
	signal.SourceClientID = source.ID
	signal.SourceClientName = source.ClientName
	device, err := s.db.FindPeerMeshDeviceByClientID(ctx, source.TenantID, source.ID)
	if err != nil {
		return err
	}
	if device != nil {
		signal.SourceVirtualIP = device.VirtualIP
		signal.SourcePublicKey = device.PublicKey
	}
	if signal.CreatedAtMillis <= 0 {
		signal.CreatedAtMillis = time.Now().UnixMilli()
	}
	return nil
}

func (s *Service) enrichTarget(ctx context.Context, signal *ControlMessage, target store.ClientAccount) error {
	signal.TargetClientID = target.ID
	signal.TargetClientName = target.ClientName
	device, err := s.db.FindPeerMeshDeviceByClientID(ctx, target.TenantID, target.ID)
	if err != nil {
		return err
	}
	if device != nil {
		signal.TargetVirtualIP = device.VirtualIP
		signal.TargetPublicKey = device.PublicKey
	}
	return nil
}

func (s *Service) sendSessionGrant(source, target store.ClientAccount, grant sessionGrant) {
	bound, ok := s.sessions.Find(source.ClientName)
	if !ok || bound == nil {
		return
	}
	sourceDevice, _ := s.db.FindPeerMeshDeviceByClientID(context.Background(), source.TenantID, source.ID)
	targetDevice, _ := s.db.FindPeerMeshDeviceByClientID(context.Background(), target.TenantID, target.ID)
	msg := ControlMessage{
		Type: TypeSessionGrant, SessionID: &grant.session.ID,
		SourceClientID: source.ID, SourceClientName: source.ClientName,
		TargetClientID: target.ID, TargetClientName: target.ClientName,
		Token: grant.token, ExpiresAt: grant.session.ExpiresAt,
		PathType: grant.session.PathType, Status: grant.session.Status,
		CreatedAtMillis: time.Now().UnixMilli(),
	}
	if sourceDevice != nil {
		msg.SourceVirtualIP = sourceDevice.VirtualIP
		msg.SourcePublicKey = sourceDevice.PublicKey
	}
	if targetDevice != nil {
		msg.TargetVirtualIP = targetDevice.VirtualIP
		msg.TargetPublicKey = targetDevice.PublicKey
	}
	_ = s.sendSignal(bound, "server", source.ClientName, msg)
}

func (s *Service) sendClose(closed SessionView) {
	msg := ControlMessage{
		Type: TypeClose, SessionID: &closed.ID,
		SourceClientID: closed.SourceClientID, SourceClientName: closed.SourceClientName,
		TargetClientID: closed.TargetClientID, TargetClientName: closed.TargetClientName,
		Status: closed.Status, Reason: "admin-force-close", CreatedAtMillis: time.Now().UnixMilli(),
	}
	for _, name := range []string{closed.SourceClientName, closed.TargetClientName} {
		if bound, ok := s.sessions.Find(name); ok && bound != nil {
			_ = s.sendSignal(bound, "server", name, msg)
		}
	}
}

func (s *Service) sendSignal(bound session.Session, sourceClientName, targetClientName string, signal ControlMessage) error {
	data, err := json.Marshal(signal)
	if err != nil {
		return err
	}
	return bound.Send(protocol.MessageResponse{
		ClientName: sourceClientName, ToClientName: targetClientName,
		MessageType: protocol.MessageTypePeerControl, Message: string(data),
	})
}

func (s *Service) findAccessibleDevice(ctx context.Context, access AccessContext, clientID int64) (*store.PeerMeshDevice, error) {
	device, err := s.db.FindPeerMeshDeviceByClientID(ctx, access.TenantID, clientID)
	if err != nil || device == nil {
		if err != nil {
			return nil, err
		}
		return nil, store.ErrNotFound
	}
	if access.Admin || device.OwnerUsername == access.Username {
		return device, nil
	}
	return nil, store.ErrNotFound
}

func (s *Service) findClient(ctx context.Context, access AccessContext, clientID int64, createDevice bool) (*store.ClientAccount, error) {
	account, err := s.findTenantClient(ctx, access.TenantID, clientID)
	if err != nil {
		return nil, err
	}
	if !access.Admin && account.OwnerUsername != access.Username {
		return nil, store.ErrNotFound
	}
	if createDevice {
		if _, err := s.EnsureDevice(ctx, *account, ""); err != nil {
			return nil, err
		}
	}
	return account, nil
}

func (s *Service) findTenantClient(ctx context.Context, tenantID string, clientID int64) (*store.ClientAccount, error) {
	account, err := s.db.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if account.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	return account, nil
}

func (s *Service) visibleClientIDs(ctx context.Context, access AccessContext) ([]int64, error) {
	clients, err := s.db.ListClients(ctx)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for _, client := range clients {
		if client.TenantID == access.TenantID &&
			(access.Admin || client.OwnerUsername == access.Username) {
			ids = append(ids, client.ID)
		}
	}
	return ids, nil
}

func (s *Service) findAccessibleSession(ctx context.Context, access AccessContext, sessionID int64) (*store.PeerMeshSession, error) {
	item, err := s.db.GetPeerMeshSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if item.TenantID != access.TenantID {
		return nil, store.ErrNotFound
	}
	if access.Admin {
		return item, nil
	}
	ids, err := s.visibleClientIDs(ctx, access)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if item.SourceClientID == id || item.TargetClientID == id {
			return item, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Service) findReportableSession(ctx context.Context, reporter store.ClientAccount, sessionID *int64) (*store.PeerMeshSession, error) {
	if sessionID == nil || *sessionID <= 0 {
		return nil, errors.New("sessionId is required")
	}
	item, err := s.db.GetPeerMeshSession(ctx, *sessionID)
	if err != nil {
		return nil, err
	}
	if item.TenantID != reporter.TenantID ||
		(item.SourceClientID != reporter.ID && item.TargetClientID != reporter.ID) {
		return nil, errors.New("peer session report source mismatch")
	}
	return item, nil
}

func (s *Service) rosterRefreshTargets(ctx context.Context, account store.ClientAccount) []store.ClientAccount {
	clients, err := s.db.ListClients(ctx)
	if err != nil {
		return nil
	}
	out := make([]store.ClientAccount, 0, len(clients))
	for _, client := range clients {
		if client.TenantID == account.TenantID {
			out = append(out, client)
		}
	}
	return out
}

func (s *Service) expireStaleSessions(ctx context.Context, limit int) (int, error) {
	items, err := s.db.ListExpiredPeerMeshSessions(ctx, StatusClosed, time.Now(), limit)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	for _, item := range items {
		s.markClosed(&item, now)
		if err := s.db.UpdatePeerMeshSession(ctx, item); err != nil {
			return 0, err
		}
	}
	return len(items), nil
}

// FlushRelayTraffic batches TURN relay byte counters into peer sessions. The relay hot path
// only validates frames and accumulates bytes in memory.
func (s *Service) FlushRelayTraffic(ctx context.Context) error {
	if s == nil {
		return nil
	}
	pending := s.drainPendingRelayBytes()
	if len(pending) == 0 {
		return nil
	}
	now := time.Now()
	for sessionID, bytes := range pending {
		if bytes <= 0 {
			continue
		}
		item, err := s.db.GetPeerMeshSession(ctx, sessionID)
		if err != nil || item == nil {
			s.removeRelaySession(sessionID)
			if err != nil {
				return err
			}
			continue
		}
		if !s.closeIfExpired(item, now) {
			s.applyTraffic(item, 0, bytes, now)
		}
		if err := s.db.UpdatePeerMeshSession(ctx, *item); err != nil {
			s.addPendingRelayBytes(sessionID, bytes)
			return err
		}
	}
	return nil
}

func (s *Service) closeIfExpired(item *store.PeerMeshSession, now time.Time) bool {
	if item.Status == StatusClosed {
		return true
	}
	if item.ExpiresAt.IsZero() || item.ExpiresAt.After(now) {
		return false
	}
	s.markClosed(item, now)
	return true
}

func (s *Service) markClosed(item *store.PeerMeshSession, now time.Time) {
	item.Status = StatusClosed
	if item.ClosedAt == nil {
		item.ClosedAt = &now
	}
	item.UpdatedAt = now
	s.removeRelaySession(item.ID)
}

func (s *Service) applyTraffic(item *store.PeerMeshSession, directBytes, relayBytes int64, now time.Time) {
	if directBytes <= 0 && relayBytes <= 0 {
		return
	}
	item.DirectBytes = saturatedAdd(item.DirectBytes, directBytes)
	item.RelayBytes = saturatedAdd(item.RelayBytes, relayBytes)
	item.PathType = effectivePathType(*item)
	item.LastTrafficAt = &now
	item.UpdatedAt = now
}

func (s *Service) authorizeRelayFrameCached(header DataFrameHeader, bytes int64, now time.Time) bool {
	s.relayMu.Lock()
	authz, ok := s.relayAuthorizations[header.SessionID]
	if !ok || !authz.validAt(now) {
		if ok {
			delete(s.relayAuthorizations, header.SessionID)
		}
		s.relayMu.Unlock()
		return false
	}
	if !authz.matches(header) {
		s.relayMu.Unlock()
		return false
	}
	s.pendingRelayBytes[header.SessionID] += bytes
	s.relayMu.Unlock()
	return true
}

func (s *Service) cacheRelayAuthorization(item store.PeerMeshSession, now time.Time) {
	s.relayMu.Lock()
	s.relayAuthorizations[item.ID] = relayAuthorization{
		sourceClientID:   item.SourceClientID,
		targetClientID:   item.TargetClientID,
		active:           item.Status == StatusActive,
		sessionExpiresAt: item.ExpiresAt,
		cacheExpiresAt:   now.Add(relayAuthorizationCacheTTL),
	}
	s.relayMu.Unlock()
}

func (s *Service) addPendingRelayBytes(sessionID int64, bytes int64) {
	if sessionID <= 0 || bytes <= 0 {
		return
	}
	s.relayMu.Lock()
	s.pendingRelayBytes[sessionID] += bytes
	s.relayMu.Unlock()
}

func (s *Service) drainPendingRelayBytes() map[int64]int64 {
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	if len(s.pendingRelayBytes) == 0 {
		return nil
	}
	pending := s.pendingRelayBytes
	s.pendingRelayBytes = make(map[int64]int64)
	return pending
}

func (s *Service) removeRelaySession(sessionID int64) {
	if sessionID <= 0 {
		return
	}
	s.relayMu.Lock()
	delete(s.relayAuthorizations, sessionID)
	delete(s.pendingRelayBytes, sessionID)
	s.relayMu.Unlock()
}

func (a relayAuthorization) validAt(now time.Time) bool {
	return a.active && a.cacheExpiresAt.After(now) && (a.sessionExpiresAt.IsZero() || a.sessionExpiresAt.After(now))
}

func (a relayAuthorization) matches(header DataFrameHeader) bool {
	forward := header.FromClientID == a.sourceClientID && header.ToClientID == a.targetClientID
	reverse := header.FromClientID == a.targetClientID && header.ToClientID == a.sourceClientID
	return forward || reverse
}

func (s *Service) deviceView(device store.PeerMeshDevice) DeviceView {
	_, online := s.sessions.Find(device.ClientName)
	return DeviceView{
		ID: device.ID, ClientID: device.ClientID, ClientName: device.ClientName,
		OwnerUsername: device.OwnerUsername, Enabled: device.Enabled, Online: online,
		VirtualIP: device.VirtualIP, CIDR: device.CIDR, PublicKey: device.PublicKey,
		NatType: device.NatType, NatMappingBehavior: device.NatMappingBehavior,
		NatFilteringBehavior: device.NatFilteringBehavior,
		NatBehaviorDiscovery: device.NatBehaviorDiscovery, LastEndpoint: device.LastEndpoint,
		VirtualDeviceMode: device.VirtualDeviceMode, VirtualDeviceName: device.VirtualDeviceName,
		VirtualDeviceStatus: device.VirtualDeviceStatus, VirtualDeviceError: device.VirtualDeviceError,
		VirtualDeviceUpdatedAt: timePtrString(device.VirtualDeviceUpdatedAt),
		LastSeenAt:             timePtrString(device.LastSeenAt),
		UpdatedAt:              device.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func aclView(acl store.PeerMeshACL) ACLView {
	return ACLView{
		ID: acl.ID, SourceClientID: acl.SourceClientID, SourceClientName: acl.SourceClientName,
		TargetClientID: acl.TargetClientID, TargetClientName: acl.TargetClientName,
		Allowed: acl.Allowed, Direction: acl.Direction, CreatedAt: acl.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt: acl.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func sessionView(item store.PeerMeshSession) SessionView {
	return SessionView{
		ID: item.ID, SourceClientID: item.SourceClientID, SourceClientName: item.SourceClientName,
		TargetClientID: item.TargetClientID, TargetClientName: item.TargetClientName,
		PathType: effectivePathType(item), Status: item.Status, RTTMillis: item.RTTMillis,
		LocalEndpoint: item.LocalEndpoint, RemoteEndpoint: item.RemoteEndpoint,
		DirectBytes: item.DirectBytes, RelayBytes: item.RelayBytes,
		LastTrafficAt: timePtrString(item.LastTrafficAt), StartedAt: item.StartedAt.Format(time.RFC3339Nano),
		UpdatedAt: item.UpdatedAt.Format(time.RFC3339Nano), ExpiresAt: item.ExpiresAt.Format(time.RFC3339Nano),
		ClosedAt: timePtrString(item.ClosedAt),
	}
}

func effectivePathType(item store.PeerMeshSession) string {
	if item.RelayBytes > item.DirectBytes {
		return PathRelay
	}
	if item.DirectBytes > item.RelayBytes {
		return PathDirect
	}
	if strings.TrimSpace(item.PathType) != "" {
		return item.PathType
	}
	return PathDirect
}

func totalPages(total, size int) int {
	if total <= 0 || size <= 0 {
		return 0
	}
	return (total + size - 1) / size
}

func (s *Service) resolvePeerHost(requestHost string) string {
	if strings.TrimSpace(s.cfg.PublicAddress) != "" {
		return strings.TrimSpace(s.cfg.PublicAddress)
	}
	if host, _, err := net.SplitHostPort(requestHost); err == nil && strings.TrimSpace(host) != "" {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(requestHost)
}

func (s *Service) resolveStunHost(requestHost string) string {
	if s.hasStandaloneStun() {
		return strings.TrimSpace(s.cfg.StandaloneStunAddress)
	}
	return s.resolvePeerHost(requestHost)
}

func (s *Service) stunPort() int {
	if s.hasStandaloneStun() {
		return s.cfg.StandaloneStunPort
	}
	return s.cfg.StunTurnPort
}

func (s *Service) hasStandaloneStun() bool {
	return strings.TrimSpace(s.cfg.StandaloneStunAddress) != "" && s.cfg.StandaloneStunPort > 0
}

func (s *Service) selfHostedStunServer(requestHost string) string {
	host := s.resolveStunHost(requestHost)
	host = normalizeStunHost(host)
	port := s.stunPort()
	if host == "" || port <= 0 {
		return ""
	}
	return "stun:" + bracketIPv6(host) + ":" + strconv.Itoa(port)
}

func (s *Service) publicStunServers() []string {
	if s == nil || len(s.cfg.PublicStunServers) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.cfg.PublicStunServers))
	seen := make(map[string]struct{})
	for _, item := range s.cfg.PublicStunServers {
		normalized := normalizeStunURL(item)
		if normalized != "" {
			out = appendUnique(out, seen, normalized)
		}
	}
	return out
}

func normalizeStunURL(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return ""
	}
	lower := strings.ToLower(normalized)
	if strings.HasPrefix(lower, "stun://") {
		normalized = normalized[len("stun://"):]
	} else if strings.HasPrefix(lower, "stun:") {
		normalized = normalized[len("stun:"):]
	}
	host := normalizeStunHost(normalized)
	if host == "" {
		return ""
	}
	return "stun:" + bracketIPv6(host) + ":" + strconv.Itoa(parseStunPort(normalized, 3478))
}

func normalizeStunHost(value string) string {
	host := strings.TrimSpace(value)
	if host == "" {
		return ""
	}
	if scheme := strings.Index(host, "://"); scheme >= 0 {
		host = host[scheme+3:]
	}
	if slash := strings.IndexByte(host, '/'); slash >= 0 {
		host = host[:slash]
	}
	if strings.HasPrefix(host, "[") {
		if close := strings.IndexByte(host, ']'); close > 0 {
			return strings.TrimSpace(host[1:close])
		}
		return ""
	}
	firstColon := strings.IndexByte(host, ':')
	lastColon := strings.LastIndexByte(host, ':')
	if firstColon > 0 && firstColon == lastColon {
		host = host[:firstColon]
	}
	return strings.TrimSpace(host)
}

func parseStunPort(value string, fallback int) int {
	normalized := strings.TrimSpace(value)
	if scheme := strings.Index(normalized, "://"); scheme >= 0 {
		normalized = normalized[scheme+3:]
	}
	if slash := strings.IndexByte(normalized, '/'); slash >= 0 {
		normalized = normalized[:slash]
	}
	if strings.HasPrefix(normalized, "[") {
		close := strings.IndexByte(normalized, ']')
		if close > 0 && close+2 < len(normalized) && normalized[close+1] == ':' {
			return validStunPort(normalized[close+2:], fallback)
		}
		return fallback
	}
	firstColon := strings.IndexByte(normalized, ':')
	lastColon := strings.LastIndexByte(normalized, ':')
	if firstColon > 0 && firstColon == lastColon && lastColon < len(normalized)-1 {
		return validStunPort(normalized[lastColon+1:], fallback)
	}
	return fallback
}

func validStunPort(value string, fallback int) int {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port <= 0 || port > 65535 {
		return fallback
	}
	return port
}

func bracketIPv6(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func appendUnique(values []string, seen map[string]struct{}, value string) []string {
	if value == "" {
		return values
	}
	key := strings.ToLower(value)
	if _, ok := seen[key]; ok {
		return values
	}
	seen[key] = struct{}{}
	return append(values, value)
}

func (s *Service) shortToken(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return randomSuffix() + "-" + hex.EncodeToString(sum[:])[:16]
}

func randomSuffix() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	return strconv.FormatInt(n.Int64(), 16)
}

func serverPublicKey() string {
	sum := sha256.Sum256([]byte("shuai-tunnel-peer-mesh-server"))
	return hex.EncodeToString(sum[:])
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	raw := addr.As4()
	return uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
}

func uint32ToIPv4(value uint32) string {
	return strconv.Itoa(int(value>>24&0xff)) + "." +
		strconv.Itoa(int(value>>16&0xff)) + "." +
		strconv.Itoa(int(value>>8&0xff)) + "." +
		strconv.Itoa(int(value&0xff))
}

func normalizeOwner(value string) string {
	if strings.TrimSpace(value) == "" {
		return "admin"
	}
	return strings.TrimSpace(value)
}

func firstText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func capString(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func capStringPtr(value *string, max int) *string {
	if value == nil {
		return nil
	}
	capped := capString(*value, max)
	return &capped
}

func stringPtr(value string) *string { return &value }

func timePtrString(value *time.Time) *string {
	if value == nil {
		return nil
	}
	text := value.Format(time.RFC3339Nano)
	return &text
}

func maxZero(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func saturatedAdd(current, delta int64) int64 {
	if delta <= 0 {
		return current
	}
	next := current + delta
	if next < 0 {
		return math.MaxInt64
	}
	return next
}
