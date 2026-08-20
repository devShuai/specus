// Package peermesh implements the Java-compatible Peer Mesh control plane for the Go server.
package peermesh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

const (
	TypeCandidates     = "candidates"
	TypeSessionGrant   = "session-grant"
	TypeRoster         = "roster"
	TypeConfig         = "peer-config"
	TypePathReport     = "path-report"
	TypeTrafficReport  = "traffic-report"
	TypeDeviceReport   = "device-report"
	TypeClose          = "close"
	TypeServiceReport  = "service-report"
	TypeServiceCatalog = "service-catalog"

	// Version 2 adds publisher-side data-plane ACL enforcement.
	peerServiceDiscoveryVersion = 2

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
	Enabled                     bool                 `json:"enabled"`
	ClientID                    int64                `json:"clientId"`
	ClientName                  string               `json:"clientName"`
	VirtualIP                   string               `json:"virtualIp"`
	CIDR                        string               `json:"cidr"`
	StunHost                    string               `json:"stunHost"`
	StunPort                    int                  `json:"stunPort"`
	TurnHost                    string               `json:"turnHost"`
	TurnPort                    int                  `json:"turnPort"`
	PublicStunServers           []string             `json:"publicStunServers"`
	IceUsername                 string               `json:"iceUsername"`
	IceCredential               string               `json:"iceCredential"`
	IceRealm                    string               `json:"iceRealm"`
	IceNonce                    string               `json:"iceNonce"`
	ServerPublicKey             string               `json:"serverPublicKey"`
	ClientPublicKey             string               `json:"clientPublicKey"`
	SessionTTLSeconds           int64                `json:"sessionTtlSeconds"`
	PeerServiceDiscoveryVersion int                  `json:"peerServiceDiscoveryVersion"`
	ServiceSharing              ServiceSharingStatus `json:"serviceSharing"`
	LocalServices               []LocalPeerService   `json:"localServices"`
}

// LocalPeerService is the owner-only definition pushed in login/peer-config.
type LocalPeerService struct {
	ServiceID             string   `json:"serviceId"`
	Name                  string   `json:"name"`
	Description           string   `json:"description,omitempty"`
	Transport             string   `json:"transport"`
	Application           string   `json:"application"`
	TargetHost            string   `json:"targetHost"`
	TargetPort            int      `json:"targetPort"`
	PublishedPort         int      `json:"publishedPort"`
	Path                  string   `json:"path,omitempty"`
	Enabled               bool     `json:"enabled"`
	Visibility            string   `json:"visibility,omitempty"`
	AllowedPeerVirtualIPs []string `json:"allowedPeerVirtualIps"`
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
	TotalSessions                int64               `json:"totalSessions"`
	ReportedSessions             int64               `json:"reportedSessions"`
	ActiveSessions               int64               `json:"activeSessions"`
	ActiveDirectSessions         int64               `json:"activeDirectSessions"`
	ActiveRelaySessions          int64               `json:"activeRelaySessions"`
	ActiveDirectRatio            *float64            `json:"activeDirectRatio"`
	PathTypes                    []PathTypeStat      `json:"pathTypes"`
	AddressFamilies              []AddressFamilyStat `json:"addressFamilies"`
	NatTypes                     []NatTypeStat       `json:"natTypes"`
	NatBehaviorDevices           int64               `json:"natBehaviorDevices"`
	NatBehaviorClassifiedDevices int64               `json:"natBehaviorClassifiedDevices"`
	NatBehaviorSuccessRatio      *float64            `json:"natBehaviorSuccessRatio"`
	NatMappingBehaviors          []NatBehaviorStat   `json:"natMappingBehaviors"`
	NatFilteringBehaviors        []NatBehaviorStat   `json:"natFilteringBehaviors"`
	NatBehaviorDiscoveries       []NatBehaviorStat   `json:"natBehaviorDiscoveries"`
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

type AddressFamilyStat struct {
	AddressFamily    string `json:"addressFamily"`
	Status           string `json:"status"`
	PathType         string `json:"pathType"`
	Sessions         int64  `json:"sessions"`
	ReportedSessions int64  `json:"reportedSessions"`
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
	ClientID                    int64    `json:"clientId"`
	ClientName                  string   `json:"clientName"`
	VirtualIP                   string   `json:"virtualIp"`
	PublicKey                   *string  `json:"publicKey,omitempty"`
	Online                      bool     `json:"online"`
	MessageSendCapable          bool     `json:"messageSendCapable"`
	MessageReceiveCapable       bool     `json:"messageReceiveCapable"`
	MessageAttachmentsCapable   bool     `json:"messageAttachmentsCapable"`
	MessageMediaPreviewCapable  bool     `json:"messageMediaPreviewCapable"`
	MessageMaxAttachmentBytes   int64    `json:"messageMaxAttachmentBytes"`
	PeerServiceDiscoveryVersion int      `json:"peerServiceDiscoveryVersion"`
	PeerServiceApplications     []string `json:"peerServiceApplications"`
}

type ServiceSharingStatus struct {
	DeploymentEnabled bool `json:"deploymentEnabled"`
	ConfiguredEnabled bool `json:"configuredEnabled"`
	EffectiveEnabled  bool `json:"effectiveEnabled"`
	MdnsImportEnabled bool `json:"mdnsImportEnabled"`
}

type MdnsCandidate struct {
	Name        string `json:"name"`
	Transport   string `json:"transport"`
	Application string `json:"application"`
	TargetHost  string `json:"targetHost"`
	TargetPort  int    `json:"targetPort"`
}

type AdvertisedService struct {
	ServiceID     string `json:"serviceId"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	Transport     string `json:"transport"`
	Application   string `json:"application"`
	PublishedPort int    `json:"publishedPort"`
	Path          string `json:"path,omitempty"`
}

type ServiceStats struct {
	ServiceID         string `json:"serviceId"`
	BytesIn           int64  `json:"bytesIn"`
	BytesOut          int64  `json:"bytesOut"`
	ActiveConnections int    `json:"activeConnections"`
	TotalConnections  int64  `json:"totalConnections"`
}

type ServiceInstanceView struct {
	PublisherSessionID int64  `json:"publisherSessionId"`
	InstanceID         string `json:"instanceId"`
	Online             bool   `json:"online"`
	Advertised         bool   `json:"advertised"`
	Revision           int64  `json:"revision"`
	LastReportedAt     string `json:"lastReportedAt"`
	ExpiresAt          string `json:"expiresAt"`
	BytesIn            int64  `json:"bytesIn"`
	BytesOut           int64  `json:"bytesOut"`
	ActiveConnections  int    `json:"activeConnections"`
	TotalConnections   int64  `json:"totalConnections"`
}

type ImportResult struct {
	Created  int                 `json:"created"`
	Skipped  int                 `json:"skipped"`
	Services []SharedServiceView `json:"services"`
}

type AuditEvent struct {
	At        string `json:"at"`
	Action    string `json:"action"`
	TenantID  string `json:"tenantId"`
	ClientID  *int64 `json:"clientId"`
	SessionID *int64 `json:"sessionId"`
	ServiceID string `json:"serviceId"`
	Reason    string `json:"reason"`
}

type SharedServiceView struct {
	ID               int64                 `json:"id"`
	ServiceID        string                `json:"serviceId"`
	ClientID         int64                 `json:"clientId"`
	ClientName       string                `json:"clientName"`
	Name             string                `json:"name"`
	Description      string                `json:"description"`
	Transport        string                `json:"transport"`
	Application      string                `json:"application"`
	TargetHost       *string               `json:"targetHost"`
	TargetPort       int                   `json:"targetPort"`
	PublishedPort    int                   `json:"publishedPort"`
	Path             string                `json:"path"`
	Enabled          bool                  `json:"enabled"`
	Visibility       string                `json:"visibility"`
	AllowedClientIDs []int64               `json:"allowedClientIds"`
	PublishedAddress *string               `json:"publishedAddress"`
	Instances        []ServiceInstanceView `json:"instances"`
	CreatedAt        string                `json:"createdAt"`
	UpdatedAt        string                `json:"updatedAt"`
}

type ServiceMutation struct {
	ClientID         *int64  `json:"clientId"`
	ServiceID        *string `json:"serviceId"`
	Name             *string `json:"name"`
	Description      *string `json:"description"`
	Transport        *string `json:"transport"`
	Application      *string `json:"application"`
	TargetHost       *string `json:"targetHost"`
	TargetPort       *int    `json:"targetPort"`
	PublishedPort    *int    `json:"publishedPort"`
	Path             *string `json:"path"`
	Enabled          *bool   `json:"enabled"`
	Visibility       *string `json:"visibility"`
	AllowedClientIDs []int64 `json:"allowedClientIds"`
}

type SharingMutation struct {
	Enabled           *bool `json:"enabled"`
	MdnsImportEnabled *bool `json:"mdnsImportEnabled"`
}

type ServiceSharingView struct {
	DeploymentEnabled           bool     `json:"deploymentEnabled"`
	ConfiguredEnabled           bool     `json:"configuredEnabled"`
	EffectiveEnabled            bool     `json:"effectiveEnabled"`
	PeerServiceDiscoveryVersion int      `json:"peerServiceDiscoveryVersion"`
	SupportedApplications       []string `json:"supportedApplications"`
	EnabledServiceCount         int64    `json:"enabledServiceCount"`
	UpdatedAt                   *string  `json:"updatedAt"`
	UpdatedBy                   *string  `json:"updatedBy"`
	MdnsImportEnabled           bool     `json:"mdnsImportEnabled"`
}

type Candidate struct {
	Type          string `json:"type,omitempty"`
	Transport     string `json:"transport,omitempty"`
	Address       string `json:"address,omitempty"`
	Port          int    `json:"port,omitempty"`
	Priority      int64  `json:"priority,omitempty"`
	Foundation    string `json:"foundation,omitempty"`
	RelayID       string `json:"relayId,omitempty"`
	AddressFamily string `json:"addressFamily,omitempty"`
}

type ControlMessage struct {
	Type                 string              `json:"type"`
	SourceClientID       int64               `json:"sourceClientId,omitempty"`
	SourceClientName     string              `json:"sourceClientName,omitempty"`
	SourceVirtualIP      string              `json:"sourceVirtualIp,omitempty"`
	SourcePublicKey      *string             `json:"sourcePublicKey,omitempty"`
	TargetClientID       int64               `json:"targetClientId,omitempty"`
	TargetClientName     string              `json:"targetClientName,omitempty"`
	TargetVirtualIP      string              `json:"targetVirtualIp,omitempty"`
	TargetPublicKey      *string             `json:"targetPublicKey,omitempty"`
	SessionID            *int64              `json:"sessionId,omitempty"`
	Token                string              `json:"token,omitempty"`
	ExpiresAt            string              `json:"expiresAt,omitempty"`
	PathType             string              `json:"pathType,omitempty"`
	Status               string              `json:"status,omitempty"`
	RTTMillis            *int64              `json:"rttMillis,omitempty"`
	LocalEndpoint        *string             `json:"localEndpoint,omitempty"`
	RemoteEndpoint       *string             `json:"remoteEndpoint,omitempty"`
	DirectBytes          int64               `json:"directBytes,omitempty"`
	RelayBytes           int64               `json:"relayBytes,omitempty"`
	NatType              *string             `json:"natType,omitempty"`
	NatMappingBehavior   *string             `json:"natMappingBehavior,omitempty"`
	NatFilteringBehavior *string             `json:"natFilteringBehavior,omitempty"`
	NatBehaviorDiscovery *string             `json:"natBehaviorDiscovery,omitempty"`
	LastEndpoint         *string             `json:"lastEndpoint,omitempty"`
	VirtualDeviceMode    *string             `json:"virtualDeviceMode,omitempty"`
	VirtualDeviceName    *string             `json:"virtualDeviceName,omitempty"`
	VirtualDeviceStatus  *string             `json:"virtualDeviceStatus,omitempty"`
	VirtualDeviceError   *string             `json:"virtualDeviceError,omitempty"`
	PeerMesh             *LoginConfig        `json:"peerMesh,omitempty"`
	DataFrameVersion     int                 `json:"dataFrameVersion,omitempty"`
	Candidates           []Candidate         `json:"candidates,omitempty"`
	Peers                []RosterItem        `json:"peers,omitempty"`
	Reason               string              `json:"reason,omitempty"`
	CreatedAtMillis      int64               `json:"createdAtMillis,omitempty"`
	Enabled              *bool               `json:"enabled,omitempty"`
	Revision             *int64              `json:"revision,omitempty"`
	PublisherClientID    int64               `json:"publisherClientId,omitempty"`
	PublisherClientName  string              `json:"publisherClientName,omitempty"`
	PublisherSessionID   *int64              `json:"publisherSessionId,omitempty"`
	InstanceID           string              `json:"instanceId,omitempty"`
	GeneratedAt          string              `json:"generatedAt,omitempty"`
	Services             []AdvertisedService `json:"services,omitempty"`
	Stats                []ServiceStats      `json:"stats,omitempty"`
	MdnsCandidates       []MdnsCandidate     `json:"mdnsCandidates,omitempty"`
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
	// sessionTokenCache 缓存明文 token（按 sessionID），供 reusableSessionGrant 复用。
	// 与 Java PeerMeshService.sessionTokenCache 对齐：create 时 put、close 时 remove。
	sessionTokenCache   map[int64]string
	sessionTokenCacheMu sync.RWMutex
	catalogMu           sync.Mutex
	catalogs            map[catalogKey]catalogSnapshot
	catalogRevisions    map[catalogKey]int64
	serviceReportRates  map[int64][]time.Time
	auditMu             sync.Mutex
	audits              []AuditEvent
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
		cfg.TurnRealm = "specus"
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
		sessionTokenCache:   make(map[int64]string),
		catalogs:            make(map[catalogKey]catalogSnapshot),
		catalogRevisions:    make(map[catalogKey]int64),
		serviceReportRates:  make(map[int64][]time.Time),
		audits:              []AuditEvent{},
	}
}

func (s *Service) Enabled() bool {
	return s != nil && s.cfg.Enabled
}

func (s *Service) AuthorizeRelayFrame(ctx context.Context, header DataFrameHeader, fromClientID, toClientID, bytes int64) bool {
	if s == nil || !validRelayPeers(fromClientID, toClientID) || bytes <= 0 {
		return false
	}
	return s.authorizeRelayFrame(ctx, header, fromClientID, toClientID, bytes, true)
}

func (s *Service) ValidateRelayFrame(ctx context.Context, header DataFrameHeader, fromClientID, toClientID int64) bool {
	if s == nil || !validRelayPeers(fromClientID, toClientID) {
		return false
	}
	return s.authorizeRelayFrame(ctx, header, fromClientID, toClientID, 0, false)
}

func (s *Service) authorizeRelayFrame(ctx context.Context, header DataFrameHeader,
	fromClientID, toClientID, bytes int64, account bool) bool {
	now := time.Now()
	if s.authorizeRelayFrameCached(header, fromClientID, toClientID, bytes, now, account) {
		return true
	}
	if s.db == nil {
		return false
	}
	item, err := s.db.GetPeerMeshSession(ctx, header.SessionID)
	if err != nil || item == nil {
		return false
	}
	if s.closeIfExpired(item, now) {
		_ = s.db.UpdatePeerMeshSession(ctx, *item)
		return false
	}
	if item.Status == StatusClosed {
		s.removeRelaySession(header.SessionID)
		return false
	}
	if !matchesSessionPeers(*item, fromClientID, toClientID) {
		s.removeRelaySession(header.SessionID)
		return false
	}
	// 首个通过身份校验的中继业务帧隐式激活 NEGOTIATING 会话。探针在 NEGOTIATING 就放行，
	// 业务帧却要求 ACTIVE，而 ACTIVE 只能由客户端 path-report 异步写入；客户端探测成功后会
	// 立即 flush 待发数据，这些帧会先于上报到达并被丢弃，peer 应用消息又没有重传，
	// 于是表现为"中继已连通但文件发送失败"。会话身份此时已校验完毕，等待状态上报只会制造竞态。
	if item.Status != StatusActive {
		item.Status = StatusActive
		item.PathType = PathRelay
		item.UpdatedAt = now
		if err := s.db.UpdatePeerMeshSession(ctx, *item); err != nil {
			return false
		}
	}
	s.cacheRelayAuthorization(*item, now)
	if account {
		s.addPendingRelayBytes(header.SessionID, bytes)
	}
	return true
}

// validRelayPeers allows either both identities to be known (TURN auth enabled) or both to be
// zero (auth disabled, the caller cannot determine identity). A single zero is a caller bug.
func validRelayPeers(fromClientID, toClientID int64) bool {
	return (fromClientID > 0 && toClientID > 0) || (fromClientID == 0 && toClientID == 0)
}

// matchesSessionPeers mirrors the Java implementation: 0/0 means the caller could not determine
// the peer identities (TURN auth disabled), which degrades to "session exists and is not closed"
// instead of rejecting everything and making the relay unusable.
func matchesSessionPeers(item store.PeerMeshSession, fromClientID, toClientID int64) bool {
	if fromClientID <= 0 && toClientID <= 0 {
		return true
	}
	forward := fromClientID == item.SourceClientID && toClientID == item.TargetClientID
	reverse := fromClientID == item.TargetClientID && toClientID == item.SourceClientID
	return forward || reverse
}

func (s *Service) AuthorizeRelayProbe(ctx context.Context, probe relayProbe) bool {
	if s == nil || s.db == nil || probe.SessionID <= 0 || probe.FromClientID <= 0 || probe.ToClientID <= 0 ||
		strings.TrimSpace(probe.Token) == "" ||
		(probe.Type != peerProbeTypeCheck && probe.Type != peerProbeTypeCheckResponse) {
		return false
	}
	item, err := s.db.GetPeerMeshSession(ctx, probe.SessionID)
	if err != nil || item == nil {
		return false
	}
	now := time.Now()
	if s.closeIfExpired(item, now) {
		_ = s.db.UpdatePeerMeshSession(ctx, *item)
		return false
	}
	forward := probe.FromClientID == item.SourceClientID && probe.ToClientID == item.TargetClientID
	reverse := probe.FromClientID == item.TargetClientID && probe.ToClientID == item.SourceClientID
	if (!forward && !reverse) || item.Status == StatusClosed || item.TokenHash == nil {
		return false
	}
	actual := sha256.Sum256([]byte(probe.Token))
	expected, err := hex.DecodeString(strings.TrimSpace(*item.TokenHash))
	return err == nil && len(expected) == len(actual) && subtle.ConstantTimeCompare(expected, actual[:]) == 1
}

func (s *Service) Run(ctx context.Context) {
	if s == nil {
		return
	}
	sessionTicker := time.NewTicker(time.Duration(s.cfg.SessionCleanupIntervalMs) * time.Millisecond)
	defer sessionTicker.Stop()
	relayTicker := time.NewTicker(time.Duration(s.cfg.RelayTrafficFlushIntervalMs) * time.Millisecond)
	defer relayTicker.Stop()
	catalogTicker := time.NewTicker(30 * time.Second)
	defer catalogTicker.Stop()
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
		case <-catalogTicker.C:
			s.expireServiceCatalogs(ctx, time.Now())
		}
	}
}

func (s *Service) BuildLoginConfig(ctx context.Context, account store.ClientAccount, peerPublicKey, requestHost string, clientProtocolVersion int) (LoginConfig, error) {
	var device *store.PeerMeshDevice
	var err error
	if s.Enabled() {
		device, err = s.EnsureDevice(ctx, account, peerPublicKey)
		if err != nil {
			return LoginConfig{}, err
		}
	}
	return s.buildConfig(ctx, account, device, requestHost, NormalizePeerServiceVersion(clientProtocolVersion)), nil
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
	clientProtocolVersion := 0
	if online, lookupErr := s.db.GetOnlineClientSession(ctx, account.TenantID, account.ID, auth.StatusNettyOnline); lookupErr != nil {
		return LoginConfig{}, lookupErr
	} else if online != nil {
		clientProtocolVersion = online.PeerServiceDiscoveryVersion
	}
	return s.buildConfig(ctx, account, device, "", clientProtocolVersion), nil
}

func (s *Service) buildConfig(ctx context.Context, account store.ClientAccount, device *store.PeerMeshDevice, requestHost string, clientProtocolVersion int) LoginConfig {
	cfg := LoginConfig{
		Enabled:           false,
		ClientID:          account.ID,
		ClientName:        account.ClientName,
		CIDR:              s.cfg.CIDR,
		SessionTTLSeconds: s.cfg.SessionTTLSeconds,
	}
	cfg.PeerServiceDiscoveryVersion = peerServiceDiscoveryVersion
	cfg.ServiceSharing = s.sharingStatusFor(account, device)
	cfg.LocalServices = s.localServicesFor(ctx, account, clientProtocolVersion)
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

// PublicNatProbeConfig 是 GET /api/public/peer-mesh/nat-probe-config 的响应 DTO。
// 对齐 Java PublicPeerMeshResource.PublicNatProbeConfig。
type PublicNatProbeConfig struct {
	Available       bool                 `json:"available"`
	Protocol        string               `json:"protocol"`
	DiscoveryMethod string               `json:"discoveryMethod"`
	Endpoints       []NatProbeEndpoint   `json:"endpoints"`
	Capabilities    NatProbeCapabilities `json:"capabilities"`
}

// NatProbeEndpoint 描述一个 RFC 5780 NAT 探测端点。
type NatProbeEndpoint struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	AddressSlot string `json:"addressSlot"`
	PortSlot    string `json:"portSlot"`
}

// NatProbeCapabilities 描述 NAT 探测能力。
type NatProbeCapabilities struct {
	Binding                     bool `json:"binding"`
	ChangeRequest               bool `json:"changeRequest"`
	ResponseOrigin              bool `json:"responseOrigin"`
	OtherAddress                bool `json:"otherAddress"`
	ResponsePort                bool `json:"responsePort"`
	Padding                     bool `json:"padding"`
	BrowserMappingObservation   bool `json:"browserMappingObservation"`
	BrowserFilteringObservation bool `json:"browserFilteringObservation"`
}

// PublicNatProbeConfig 构建 NAT 探测配置响应。对齐 Java PublicPeerMeshResource.natProbeConfig。
func (s *Service) PublicNatProbeConfig(requestHost string) PublicNatProbeConfig {
	if s == nil || !s.Enabled() {
		return PublicNatProbeConfig{Protocol: "RFC8489", DiscoveryMethod: "BASIC_STUN"}
	}
	primaryHost := normalizeStunHost(s.resolveStunHost(requestHost))
	primaryPort := s.stunPort()
	alternateHost := normalizeStunHost(s.standaloneAlternateStunHost())
	alternatePort := s.standaloneAlternateStunPort()
	rfc5780 := primaryHost != "" && alternateHost != "" &&
		!strings.EqualFold(primaryHost, alternateHost) &&
		primaryPort > 0 && alternatePort > 0 && primaryPort != alternatePort

	endpoints := make([]NatProbeEndpoint, 0, 4)
	if primaryHost != "" && primaryPort > 0 {
		endpoints = append(endpoints, natProbeEndpoint("A1P1", primaryHost, primaryPort, "PRIMARY", "PRIMARY"))
	}
	if rfc5780 {
		endpoints = append(endpoints, natProbeEndpoint("A1P2", primaryHost, alternatePort, "PRIMARY", "ALTERNATE"))
		endpoints = append(endpoints, natProbeEndpoint("A2P1", alternateHost, primaryPort, "ALTERNATE", "PRIMARY"))
		endpoints = append(endpoints, natProbeEndpoint("A2P2", alternateHost, alternatePort, "ALTERNATE", "ALTERNATE"))
	}

	return PublicNatProbeConfig{
		Available:       len(endpoints) > 0,
		Protocol:        "RFC8489",
		DiscoveryMethod: discoveryMethod(rfc5780),
		Endpoints:       endpoints,
		Capabilities: NatProbeCapabilities{
			Binding:                     true,
			ChangeRequest:               rfc5780,
			ResponseOrigin:              rfc5780,
			OtherAddress:                rfc5780,
			ResponsePort:                rfc5780,
			Padding:                     rfc5780,
			BrowserMappingObservation:   true,
			BrowserFilteringObservation: false,
		},
	}
}

// standaloneAlternateStunHost 返回备用 STUN 主机：优先 StandaloneStunAlternateAddress，
// 回退 StunAlternatePublicAddress。对齐 Java standaloneAlternateStunHost()。
func (s *Service) standaloneAlternateStunHost() string {
	if host := strings.TrimSpace(s.cfg.StandaloneStunAlternateAddress); host != "" {
		return host
	}
	return strings.TrimSpace(s.cfg.StunAlternatePublicAddress)
}

// standaloneAlternateStunPort 返回备用 STUN 端口：优先 StandaloneStunAlternatePort，
// 回退 NatProbeAlternatePort。对齐 Java standaloneAlternateStunPort()。
func (s *Service) standaloneAlternateStunPort() int {
	if s.cfg.StandaloneStunAlternatePort > 0 {
		return s.cfg.StandaloneStunAlternatePort
	}
	return s.cfg.NatProbeAlternatePort
}

func natProbeEndpoint(id, host string, port int, addressSlot, portSlot string) NatProbeEndpoint {
	return NatProbeEndpoint{
		ID:          id,
		URL:         "stun:" + bracketIPv6(host) + ":" + strconv.Itoa(port),
		Host:        host,
		Port:        port,
		AddressSlot: addressSlot,
		PortSlot:    portSlot,
	}
}

func discoveryMethod(rfc5780 bool) string {
	if rfc5780 {
		return "RFC5780"
	}
	return "BASIC_STUN"
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
	return s.HandleSignalSession(ctx, request, sourceClientName, 0)
}

func (s *Service) HandleSignalSession(ctx context.Context, request protocol.MessageRequest, sourceClientName string, publisherSessionID int64) error {
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
	if signal.Type == TypeServiceReport {
		if err := validateServiceReportEnvelope(request); err != nil {
			return err
		}
		return s.handleServiceReport(ctx, *source, signal, publisherSessionID)
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
	case TypeServiceCatalog:
		return errors.New("service-catalog is server-only")
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

func validateServiceReportEnvelope(request protocol.MessageRequest) error {
	if len([]byte(request.Message)) > 16*1024 {
		return errors.New("service-report exceeds 16384 bytes")
	}
	if strings.TrimSpace(request.ToClientName) != "" {
		return errors.New("service-report toClientName must be empty")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(request.Message), &fields); err != nil {
		return errors.New("invalid service-report")
	}
	for _, field := range []string{
		"sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
		"targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey",
		"sessionId", "token", "publisherClientId", "publisherClientName", "publisherSessionId",
	} {
		if _, present := fields[field]; present {
			return fmt.Errorf("service-report %s is server-bound", field)
		}
	}
	return nil
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
	s.pushCurrentCatalogs(ctx, account)
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
		s.withdrawClient(ctx, account.TenantID, account.ID)
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
	if err := s.refreshAuthorization(ctx, access); err != nil {
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
	if err := s.db.DeletePeerMeshACL(ctx, id); err != nil {
		return err
	}
	return s.refreshAuthorization(ctx, access)
}

func (s *Service) refreshAuthorization(ctx context.Context, access AccessContext) error {
	clients, err := s.db.ListClients(ctx)
	if err != nil {
		return err
	}
	byID := make(map[int64]store.ClientAccount)
	for _, client := range clients {
		if client.TenantID == access.TenantID {
			byID[client.ID] = client
			s.PushConfig(ctx, client)
			s.PushRoster(ctx, client)
		}
	}
	open, err := s.db.ListOpenPeerMeshSessions(ctx, access.TenantID, nil, StatusClosed)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, item := range open {
		source, sourceOK := byID[item.SourceClientID]
		target, targetOK := byID[item.TargetClientID]
		allowed := false
		if sourceOK && targetOK {
			allowed, err = s.CanPeer(ctx, source, target)
			if err != nil {
				return err
			}
		}
		if !allowed {
			s.markClosed(&item, now)
			if err := s.db.UpdatePeerMeshSession(ctx, item); err != nil {
				return err
			}
			s.sendClose(sessionView(item))
		}
	}
	s.onAuthorizationChanged(ctx, access.TenantID)
	return nil
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
	addressFamilyAggregates, err := s.db.AggregatePeerMeshAddressFamilies(
		ctx,
		access.TenantID,
		ids,
		filterIDs,
	)
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
	addressFamilies := make([]AddressFamilyStat, 0, len(addressFamilyAggregates))
	for _, item := range addressFamilyAggregates {
		addressFamilies = append(addressFamilies, AddressFamilyStat{
			AddressFamily:    item.AddressFamily,
			Status:           item.Status,
			PathType:         item.PathType,
			Sessions:         item.Sessions,
			ReportedSessions: item.ReportedSessions,
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
		AddressFamilies:              addressFamilies,
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
	// S-9：复用已存在的 open session（与 Java reusableSessionGrant 对齐），避免重复创建。
	if grant, found := s.reusableSessionGrant(ctx, source, target, now); found {
		return grant, nil
	}
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
	s.cacheSessionToken(item.ID, token)
	return sessionGrant{session: sessionView(item), token: token}, nil
}

// reusableSessionGrant 查找两个 client 之间未关闭且未过期的 session，返回缓存的明文 token。
// 与 Java PeerMeshService.reusableSessionGrant 对齐。过期 session 会被关闭并跳过。
func (s *Service) reusableSessionGrant(ctx context.Context, source, target store.ClientAccount, now time.Time) (sessionGrant, bool) {
	sessions, err := s.db.FindOpenSessionBetweenClients(ctx, source.TenantID, source.ID, target.ID, StatusClosed)
	if err != nil {
		return sessionGrant{}, false
	}
	for i := range sessions {
		item := &sessions[i]
		if now.After(item.ExpiresAt) {
			s.markClosed(item, now)
			_ = s.db.UpdatePeerMeshSession(ctx, *item)
			continue
		}
		token, ok := s.getCachedSessionToken(item.ID)
		if !ok || token == "" {
			continue
		}
		return sessionGrant{session: sessionView(*item), token: token}, true
	}
	return sessionGrant{}, false
}

func (s *Service) cacheSessionToken(sessionID int64, token string) {
	s.sessionTokenCacheMu.Lock()
	s.sessionTokenCache[sessionID] = token
	s.sessionTokenCacheMu.Unlock()
}

func (s *Service) getCachedSessionToken(sessionID int64) (string, bool) {
	s.sessionTokenCacheMu.RLock()
	token, ok := s.sessionTokenCache[sessionID]
	s.sessionTokenCacheMu.RUnlock()
	return token, ok
}

func (s *Service) removeCachedSessionToken(sessionID int64) {
	s.sessionTokenCacheMu.Lock()
	delete(s.sessionTokenCache, sessionID)
	s.sessionTokenCacheMu.Unlock()
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
	clientIDs := make([]int64, 0, len(byID))
	for id := range byID {
		clientIDs = append(clientIDs, id)
	}
	onlineSessions, err := s.db.ListClientSessionsByClientIDsAndStatus(ctx, account.TenantID, clientIDs, "NETTY_ONLINE")
	if err != nil {
		return nil, err
	}
	bySession := make(map[int64]store.ClientSession, len(onlineSessions))
	for _, session := range onlineSessions {
		current, ok := bySession[session.ClientID]
		if !ok || session.PeerServiceDiscoveryVersion > current.PeerServiceDiscoveryVersion {
			bySession[session.ClientID] = session
		}
	}
	out := make([]RosterItem, 0, len(byID))
	for _, device := range byID {
		_, online := s.sessions.Find(device.ClientName)
		session := bySession[device.ClientID]
		item := RosterItem{
			ClientID: device.ClientID, ClientName: device.ClientName, VirtualIP: device.VirtualIP,
			PublicKey: device.PublicKey, Online: online,
		}
		if online {
			item.MessageSendCapable = session.MessageSendCapable
			item.MessageReceiveCapable = session.MessageReceiveCapable
			item.MessageAttachmentsCapable = session.MessageAttachmentsCapable
			item.MessageMediaPreviewCapable = session.MessageMediaPreviewCapable
			item.MessageMaxAttachmentBytes = session.MessageMaxAttachmentBytes
			item.PeerServiceDiscoveryVersion = session.PeerServiceDiscoveryVersion
			item.PeerServiceApplications = decodeApplications(session.PeerServiceApplications)
		}
		out = append(out, item)
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
	// 与 Java PeerMeshService.allocateVirtualIp 完全一致：使用 String.hashCode()（非 FNV），
	// 再取 Math.abs，保证跨语言同账号分到同一 VIP。
	hash := javaStringHashCode(account.TenantID + ":" + account.OwnerUsername + ":" + strconv.FormatInt(account.ID, 10))
	seed := uint64(javaMathAbsInt32(hash))
	usable := capacity - 2
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

// javaStringHashCode 复现 Java String.hashCode()：h = 31*h + char，int32 有符号溢出。
// 用于 VIP 分配，确保 Go 与 Java 对同一账号字符串产生相同哈希。
func javaStringHashCode(s string) int32 {
	var h int32
	for _, r := range s {
		if r <= 0xffff {
			h = 31*h + int32(r)
			continue
		}
		// Java String.hashCode() 按 UTF-16 code unit 计算，增补平面字符需要拆成代理对。
		r -= 0x10000
		h = 31*h + int32(0xd800+(r>>10))
		h = 31*h + int32(0xdc00+(r&0x3ff))
	}
	return h
}

// javaMathAbsInt32 复现 Java Math.abs(int)：Integer.MIN_VALUE 返回自身（仍为负），其余取绝对值。
func javaMathAbsInt32(v int32) int32 {
	if v < 0 && v != math.MinInt32 {
		return -v
	}
	return v
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
		DataFrameVersion: 2,
		CreatedAtMillis:  time.Now().UnixMilli(),
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
	s.removeCachedSessionToken(item.ID)
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

func (s *Service) authorizeRelayFrameCached(header DataFrameHeader, fromClientID, toClientID,
	bytes int64, now time.Time, account bool) bool {
	s.relayMu.Lock()
	authz, ok := s.relayAuthorizations[header.SessionID]
	if !ok || !authz.validAt(now) {
		if ok {
			delete(s.relayAuthorizations, header.SessionID)
		}
		s.relayMu.Unlock()
		return false
	}
	if !authz.matches(fromClientID, toClientID) {
		s.relayMu.Unlock()
		return false
	}
	if account {
		s.pendingRelayBytes[header.SessionID] += bytes
	}
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

// matches accepts 0/0 as "identity unknown" (TURN auth disabled), consistent with the slow path.
func (a relayAuthorization) matches(fromClientID, toClientID int64) bool {
	if fromClientID <= 0 && toClientID <= 0 {
		return true
	}
	forward := fromClientID == a.sourceClientID && toClientID == a.targetClientID
	reverse := fromClientID == a.targetClientID && toClientID == a.sourceClientID
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
	sum := sha256.Sum256([]byte("specus-peer-mesh-server"))
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
