package client

import (
	"crypto/ecdh"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	peerControlTypeConfig        = "peer-config"
	peerControlTypeRoster        = "roster"
	peerControlTypeSessionGrant  = "session-grant"
	peerControlTypeCandidates    = "candidates"
	peerControlTypePathReport    = "path-report"
	peerControlTypeTrafficReport = "traffic-report"
	peerControlTypeDeviceReport  = "device-report"
	peerControlTypeClose         = "close"

	peerRelayProbePrimary   = "primary"
	peerRelayProbeAlternate = "alternate"
	peerRelayProbeChanged   = "changed-port"
	publicStunRolePrefix    = "public-stun:"

	peerProbeMagic             = "specus-peer-mesh"
	peerProbeTypeCheck         = "check"
	peerProbeTypeCheckResponse = "check-response"

	peerNatTypeNoNat                = "NO_NAT"
	peerNatTypeSymmetric            = "SYMMETRIC_NAT"
	peerNatTypePortRestricted       = "PORT_RESTRICTED_NAT"
	peerNatTypePortPreserved        = "PORT_PRESERVED_NAT"
	peerNatTypeFullConeOrRestricted = "FULL_CONE_OR_RESTRICTED_NAT"
	peerNatTypeNat                  = "NAT"

	peerPendingPacketTTL          = 30 * time.Second
	peerPendingTurnRequestTTL     = 15 * time.Second
	peerStunRequestInterval       = 60 * time.Second
	peerBehaviorDiscoveryInterval = 60 * time.Second
	peerBehaviorProbeTimeout      = 1600 * time.Millisecond
	peerMaxPendingPackets         = 32
	peerPathPrepareMinInterval    = 2 * time.Second
	peerPortMappingRetry          = 30 * time.Second
	peerPortMappingLease          = 7200
	peerProbeBurstCount           = 3
	peerProbeBurstInterval        = 30 * time.Millisecond
	peerConnectivityCheckPacing   = 20 * time.Millisecond
	peerMaxAdaptivePredictedPorts = 16
	peerMaxAdaptivePortDelta      = 512
	peerDirectKeepaliveInterval   = 25 * time.Second
	peerDirectStaleInterval       = 45 * time.Second
	// H-1：候选回礼节流间隔，避免两端互相触发形成信令循环，对齐 Java
	// CANDIDATE_RECIPROCATE_INTERVAL_MILLIS=2000。
	peerCandidateReciprocateInterval = 2 * time.Second
)

// H-2：session 首次发起连通性检查后的密集退避重试节奏，对齐 Java
// HOLE_PUNCH_RETRY_DELAYS_MILLIS={1k,2k,4k,8k}。把"打洞成功前的丢包窗口"从最坏 30-60s
// maintenance tick 压缩到数秒，不改变最终成功率。打通或过期即停。
// time.Duration 不是编译期常量，因此用 var 而非 const。
var peerHolePunchRetryDelays = [...]time.Duration{
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
}

const (
	peerRttHysteresisMillis = int64(100)
	peerRttEWMAOldWeight    = int64(7)
	peerRttEWMANewWeight    = int64(1)
	peerRttUnsetMillis      = int64(1<<63 - 1)
)

type peerControlSender func(net.Conn, string, any) error

type peerMeshClient struct {
	config Config
	logger *log.Logger

	mu           sync.Mutex
	runtime      RuntimeConfig
	conn         net.Conn
	sender       peerControlSender
	udp          *net.UDPConn
	stopCh       chan struct{}
	peers        map[int64]*peerMeshPeer
	sessions     map[int64]*peerMeshSession
	sessionsByID map[int64]*peerMeshSession
	pending      map[string]pendingPeerProbe
	pendingStun  map[string]pendingStunBinding
	pendingTurn  map[string]pendingTurnRequest
	packets      map[int64][]pendingPeerPacket
	prepared     map[int64]time.Time
	// H-2：记录已排程密集退避重试的 session，防止重复排程；本轮结束后释放以便路径失效后重新进入。
	holePunchRetryScheduled map[int64]bool
	// H-1：记录每个 peer 最近一次候选回礼时间，2s 节流防信令循环。
	candidateReciprocateAt map[int64]time.Time
	srflx                  *peerCandidate
	srflxCandidates        map[string]peerCandidate
	relay                  *peerCandidate
	relayID                string
	relayTTL               time.Time
	portMap                *peerCandidate
	portMapping            *natPortMapping
	portMappingService     *natPortMappingService
	lastPortMapAttempt     time.Time
	lastStunRequest        time.Time
	lastRelayRequest       time.Time
	lastAlternateRequest   time.Time
	lastBehaviorDiscovery  time.Time
	natByRole              map[string]string
	natBehavior            *natBehaviorDiscovery
	natType                string
	natMappingBehavior     string
	natFilteringBehavior   string
	natBehaviorDiscovery   string
	lastEndpoint           string
	turnPermissions        map[string]time.Time
	turnChannelsByPeer     map[string]*turnChannelBinding
	turnChannelsByNumber   map[uint16]*turnChannelBinding
	nextTurnChannel        uint16
	localKey               *ecdh.PrivateKey
	// localKeyEpoch is this process instance's random SPM2 key epoch. It is the anchor for
	// AES-GCM nonce uniqueness: sessionId/token are reused within the server session TTL and
	// X25519 keys are persisted on disk, so only a fresh epoch keeps a restarted client from
	// falling back into the same nonce space once its sequence restarts at 1.
	localKeyEpoch      string
	device             peerVirtualDevice
	dataPlane          *peerDataPlane
	probeLimiter       *peerUDPProbeRateLimiter
	runtimeConfigKey   string
	ignoredPacketLogAt map[string]time.Time
	pathMTUCache       map[string]cachedPeerPathMTU
	messageHandler     func(ClientMessage)
	turnAuth           turnAuthCredentials
	services           *peerServiceRuntime
}

type peerMeshPeer struct {
	ClientID   int64           `json:"clientId"`
	ClientName string          `json:"clientName"`
	VirtualIP  string          `json:"virtualIp"`
	PublicKey  string          `json:"publicKey"`
	KeyEpoch   string          `json:"-"`
	Online     bool            `json:"online"`
	Candidates []peerCandidate `json:"candidates,omitempty"`
}

type peerCandidate struct {
	Type          string `json:"type,omitempty"`
	Transport     string `json:"transport,omitempty"`
	Address       string `json:"address,omitempty"`
	Port          int    `json:"port,omitempty"`
	Priority      int64  `json:"priority,omitempty"`
	Foundation    string `json:"foundation,omitempty"`
	RelayID       string `json:"relayId,omitempty"`
	AddressFamily string `json:"addressFamily,omitempty"`
}

type peerControlMessage struct {
	Type                 string          `json:"type"`
	SourceClientID       int64           `json:"sourceClientId,omitempty"`
	SourceClientName     string          `json:"sourceClientName,omitempty"`
	SourceVirtualIP      string          `json:"sourceVirtualIp,omitempty"`
	SourcePublicKey      string          `json:"sourcePublicKey,omitempty"`
	SourceKeyEpoch       string          `json:"sourceKeyEpoch,omitempty"`
	TargetClientID       int64           `json:"targetClientId,omitempty"`
	TargetClientName     string          `json:"targetClientName,omitempty"`
	TargetVirtualIP      string          `json:"targetVirtualIp,omitempty"`
	TargetPublicKey      string          `json:"targetPublicKey,omitempty"`
	SessionID            *int64          `json:"sessionId,omitempty"`
	Token                string          `json:"token,omitempty"`
	ExpiresAt            string          `json:"expiresAt,omitempty"`
	PathType             string          `json:"pathType,omitempty"`
	Status               string          `json:"status,omitempty"`
	RTTMillis            *int64          `json:"rttMillis,omitempty"`
	LocalEndpoint        string          `json:"localEndpoint,omitempty"`
	RemoteEndpoint       string          `json:"remoteEndpoint,omitempty"`
	DirectBytes          int64           `json:"directBytes,omitempty"`
	RelayBytes           int64           `json:"relayBytes,omitempty"`
	NatType              string          `json:"natType,omitempty"`
	NatMappingBehavior   string          `json:"natMappingBehavior,omitempty"`
	NatFilteringBehavior string          `json:"natFilteringBehavior,omitempty"`
	NatBehaviorDiscovery string          `json:"natBehaviorDiscovery,omitempty"`
	LastEndpoint         string          `json:"lastEndpoint,omitempty"`
	VirtualDeviceMode    string          `json:"virtualDeviceMode,omitempty"`
	VirtualDeviceName    string          `json:"virtualDeviceName,omitempty"`
	VirtualDeviceStatus  string          `json:"virtualDeviceStatus,omitempty"`
	VirtualDeviceError   string          `json:"virtualDeviceError,omitempty"`
	PeerMesh             *PeerMeshConfig `json:"peerMesh,omitempty"`
	Peers                []peerMeshPeer  `json:"peers,omitempty"`
	Candidates           []peerCandidate `json:"candidates,omitempty"`
	DataFrameVersion     int             `json:"dataFrameVersion"`
	Reason               string          `json:"reason,omitempty"`
	CreatedAtMillis      int64           `json:"createdAtMillis,omitempty"`
	Enabled              *bool           `json:"enabled,omitempty"`
	Revision             *int64          `json:"revision,omitempty"`
	PublisherClientID    int64           `json:"publisherClientId,omitempty"`
	PublisherClientName  string          `json:"publisherClientName,omitempty"`
	PublisherSessionID   *int64          `json:"publisherSessionId,omitempty"`
	InstanceID           string          `json:"instanceId,omitempty"`
	GeneratedAt          string          `json:"generatedAt,omitempty"`
	Services             []peerAdvertisedService `json:"services,omitempty"`
}

type peerMeshSession struct {
	ID                      int64
	PeerID                  int64
	PeerName                string
	PeerVirtualIP           string
	PeerPublicKey           string
	Token                   string
	ExpiresAt               time.Time
	RemoteEndpoint          *net.UDPAddr
	RelayTargetAllocationID string
	PathType                string
	LastDirectSuccess       time.Time
	LastDirectKeepalive     time.Time
	LastRelaySuccess        time.Time
	LastPathLog             time.Time
	LastPathReport          time.Time
	LastPathRemoteText      string
	EndpointSuccess         time.Time
	EndpointRTT             int64
	BestDirectRTT           int64
	BestRelayRTT            int64
	AESKey                  []byte
	LocalKeyEpoch           string
	RemoteKeyEpoch          string
	OutboundCodec           *peerDataFrameTrafficCodec
	InboundCodec            *peerDataFrameTrafficCodec
	Sequence                uint64
	Replay                  peerReplayWindow
	DirectBytes             int64
	DirectBytesPending      int64
	PathMTU                 *peerPathMTUDiscovery
}

func (session *peerMeshSession) hasHealthyDirect(now time.Time) bool {
	return session != nil &&
		strings.EqualFold(session.PathType, "DIRECT") &&
		!session.LastDirectSuccess.IsZero() &&
		now.Sub(session.LastDirectSuccess) <= 45*time.Second
}

func (session *peerMeshSession) acceptInboundFrame(frame *peerDataFrame) bool {
	if session == nil || frame == nil {
		return false
	}
	return session.Replay.accept(frame.Sequence)
}

func (session *peerMeshSession) ensureTrafficCodecs(localClientID int64) error {
	if session == nil || len(session.AESKey) != 32 {
		return fmt.Errorf("peer session has no data key")
	}
	if strings.TrimSpace(session.LocalKeyEpoch) == "" || strings.TrimSpace(session.RemoteKeyEpoch) == "" {
		return fmt.Errorf("peer session is missing a key epoch")
	}
	if session.OutboundCodec != nil && session.InboundCodec != nil {
		return nil
	}
	outbound, err := newPeerDataFrameTrafficCodec(
		session.AESKey, session.ID, localClientID, session.PeerID, session.LocalKeyEpoch)
	if err != nil {
		return err
	}
	inbound, err := newPeerDataFrameTrafficCodec(
		session.AESKey, session.ID, session.PeerID, localClientID, session.RemoteKeyEpoch)
	if err != nil {
		return err
	}
	session.OutboundCodec = outbound
	session.InboundCodec = inbound
	return nil
}

// applyRemoteKeyEpoch resets the inbound decryption state when the peer restarts with a new
// epoch. The peer restarts its sequence at 1, so the old replay window would reject every
// new frame and the cached inbound codec would fail to decrypt.
func (session *peerMeshSession) applyRemoteKeyEpoch(epoch string) bool {
	if session == nil || strings.TrimSpace(epoch) == "" || epoch == session.RemoteKeyEpoch {
		return false
	}
	changed := strings.TrimSpace(session.RemoteKeyEpoch) != ""
	session.RemoteKeyEpoch = epoch
	session.InboundCodec = nil
	session.Replay = peerReplayWindow{}
	return changed
}

type pendingPeerProbe struct {
	SessionID int64
	PeerID    int64
	SentAt    time.Time
	Remote    string
	Relay     bool
	RelayID   string
}

type pendingStunBinding struct {
	Role                     string
	TargetEndpoint           *net.UDPAddr
	ExpectedResponseEndpoint *net.UDPAddr
	Request                  stunMessage
	BehaviorProbe            natBehaviorProbe
	BehaviorGeneration       int
	SentAt                   time.Time
}

type pendingTurnRequest struct {
	RequestType           uint16
	Attributes            []stunAttribute
	OriginalTransactionID [stunTransactionIDBytes]byte
	Endpoint              *net.UDPAddr
	Channel               uint16
	Peer                  *net.UDPAddr
	AuthenticationAttempt int
	SentAt                time.Time
}

type turnChannelBinding struct {
	Channel   uint16
	Peer      *net.UDPAddr
	ExpiresAt time.Time
	Active    bool
}

type turnAuthCredentials struct {
	Username   string
	Credential string
	Realm      string
	Nonce      string
}

func (credentials turnAuthCredentials) complete() bool {
	return credentials.Username != "" && credentials.Credential != "" &&
		credentials.Realm != "" && credentials.Nonce != ""
}

type pendingPeerPacket struct {
	Packet []byte
	SentAt time.Time
}

type peerUDPProbe struct {
	Magic        string `json:"magic"`
	Type         string `json:"type"`
	SessionID    int64  `json:"sessionId,omitempty"`
	FromClientID int64  `json:"fromClientId,omitempty"`
	ToClientID   int64  `json:"toClientId,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	Token        string `json:"token,omitempty"`
	SentAtMillis int64  `json:"sentAtMillis,omitempty"`
}

func newPeerMeshClient(config Config, logger *log.Logger) *peerMeshClient {
	if logger == nil {
		logger = log.Default()
	}
	return &peerMeshClient{
		config:             config,
		logger:             logger,
		portMappingService: newNatPortMappingService(logger),
		localKeyEpoch:      newPeerMeshKeyEpoch(),
		services:           newPeerServiceRuntime(logger, nil),
	}
}

// newPeerMeshKeyEpoch returns a 128 bit random epoch for this process instance.
func newPeerMeshKeyEpoch() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		// crypto/rand failure is fatal for the data plane; fall back to a time-based value
		// so the client still starts, and never reuse a constant.
		binary.BigEndian.PutUint64(buffer, uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(buffer[8:], uint64(os.Getpid()))
	}
	return hex.EncodeToString(buffer)
}

func (mesh *peerMeshClient) setMessageHandler(handler func(ClientMessage)) {
	mesh.mu.Lock()
	mesh.messageHandler = handler
	mesh.mu.Unlock()
}

func turnAuthCredentialsFrom(peerMesh PeerMeshConfig) turnAuthCredentials {
	return turnAuthCredentials{
		Username:   strings.TrimSpace(peerMesh.IceUsername),
		Credential: strings.TrimSpace(peerMesh.IceCredential),
		Realm:      strings.TrimSpace(peerMesh.IceRealm),
		Nonce:      strings.TrimSpace(peerMesh.IceNonce),
	}
}

func (mesh *peerMeshClient) updateTurnAuthLocked(peerMesh PeerMeshConfig) bool {
	next := turnAuthCredentialsFrom(peerMesh)
	if mesh.turnAuth == next {
		return false
	}
	mesh.turnAuth = next
	clear(mesh.pendingTurn)
	clear(mesh.turnChannelsByPeer)
	clear(mesh.turnChannelsByNumber)
	mesh.nextTurnChannel = turnChannelMin
	return true
}

func (mesh *peerMeshClient) start(conn net.Conn, runtime RuntimeConfig, sender peerControlSender) {
	mesh.mu.Lock()
	mesh.updateTurnAuthLocked(runtime.PeerMesh)
	mesh.mu.Unlock()
	mesh.ensureServices().setSend(func(msg any) error {
		return sender(conn, "", msg)
	})
	if !runtime.PeerMesh.Enabled {
		mesh.stop()
		mesh.ensureServices().applyConfig(runtime.PeerMesh)
		mesh.ensureServices().setHasAuthorizedOnlinePeer(false)
		return
	}
	nextRuntimeConfigKey := mesh.runtimeConfigKeyFor(runtime.PeerMesh)
	mesh.mu.Lock()
	if mesh.isStartedLocked() &&
		mesh.runtimeConfigKey == nextRuntimeConfigKey &&
		!mesh.shouldRetryVirtualDeviceStartLocked() {
		mesh.runtime = runtime
		mesh.conn = conn
		mesh.sender = sender
		mesh.mu.Unlock()
		mesh.reportDevice(conn, sender, mesh.deviceStatus(), mesh.deviceError(), "", "")
		mesh.syncVirtualDeviceRoutes()
		mesh.tryAcquirePortMappingAsync()
		mesh.requestRelayCandidates()
		mesh.announceCandidates()
		mesh.ensureServices().applyConfig(runtime.PeerMesh)
		return
	}
	mesh.mu.Unlock()

	localKey, keyErr := loadPeerPrivateKey()
	mesh.mu.Lock()
	mesh.stopLocked()
	mesh.runtime = runtime
	mesh.runtimeConfigKey = nextRuntimeConfigKey
	mesh.conn = conn
	mesh.sender = sender
	mesh.peers = make(map[int64]*peerMeshPeer)
	mesh.sessions = make(map[int64]*peerMeshSession)
	mesh.sessionsByID = make(map[int64]*peerMeshSession)
	mesh.pending = make(map[string]pendingPeerProbe)
	mesh.pendingStun = make(map[string]pendingStunBinding)
	mesh.pendingTurn = make(map[string]pendingTurnRequest)
	mesh.packets = make(map[int64][]pendingPeerPacket)
	mesh.prepared = make(map[int64]time.Time)
	mesh.holePunchRetryScheduled = make(map[int64]bool)
	mesh.candidateReciprocateAt = make(map[int64]time.Time)
	mesh.srflxCandidates = make(map[string]peerCandidate)
	mesh.natByRole = make(map[string]string)
	mesh.natBehavior = &natBehaviorDiscovery{}
	mesh.natType = ""
	mesh.natMappingBehavior = ""
	mesh.natFilteringBehavior = ""
	mesh.natBehaviorDiscovery = ""
	mesh.lastEndpoint = ""
	mesh.turnPermissions = make(map[string]time.Time)
	mesh.turnChannelsByPeer = make(map[string]*turnChannelBinding)
	mesh.turnChannelsByNumber = make(map[uint16]*turnChannelBinding)
	mesh.nextTurnChannel = turnChannelMin
	mesh.ignoredPacketLogAt = make(map[string]time.Time)
	mesh.pathMTUCache = make(map[string]cachedPeerPathMTU)
	mesh.localKey = localKey
	if mesh.portMappingService == nil {
		mesh.portMappingService = newNatPortMappingService(mesh.logger)
	}
	mesh.stopCh = make(chan struct{})
	udp, err := listenPeerUDP()
	if err != nil {
		mesh.mu.Unlock()
		mesh.logger.Printf("Peer Mesh UDP socket open failed: %v", err)
		mesh.reportDevice(conn, sender, "NOOP", fmt.Sprintf("Go client Peer Mesh UDP socket failed: %v", err), "", "")
		return
	}
	mesh.udp = udp
	if mesh.dataPlane == nil {
		mesh.dataPlane = newPeerDataPlane(defaultPeerDataPlaneWorkers(), peerDataPlaneQueueCapacity,
			mesh.handlePeerDataFrame)
	}
	if mesh.probeLimiter == nil {
		mesh.probeLimiter = newPeerUDPProbeRateLimiter()
	}
	stopCh := mesh.stopCh
	mesh.mu.Unlock()

	device := newPeerVirtualDevice(mesh.config, runtime.PeerMesh, mesh.logger)
	deviceErr := ""
	if keyErr != nil {
		deviceErr = fmt.Sprintf("Peer Mesh X25519 key unavailable: %v", keyErr)
	}
	if startErr := device.Start(stopCh, mesh.handleVirtualPacket); startErr != nil {
		deviceErr = firstNonEmpty(deviceErr, startErr.Error())
	}
	mesh.mu.Lock()
	mesh.device = device
	mesh.mu.Unlock()

	mesh.reportDevice(conn, sender, device.Status(), firstNonEmpty(deviceErr, device.Error()), "", "")
	mesh.syncVirtualDeviceRoutes()
	go mesh.udpLoop(udp, stopCh)
	go mesh.maintenanceLoop(stopCh)
	mesh.tryAcquirePortMappingAsync()
	mesh.requestRelayCandidates()
	mesh.announceCandidates()
	mesh.ensureServices().applyConfig(runtime.PeerMesh)
}

func (mesh *peerMeshClient) ensureServices() *peerServiceRuntime {
	if mesh.services == nil {
		mesh.services = newPeerServiceRuntime(mesh.logger, nil)
	}
	return mesh.services
}

func (mesh *peerMeshClient) stop() {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	mesh.stopLocked()
}

func (mesh *peerMeshClient) stopLocked() {
	if mesh.stopCh != nil {
		close(mesh.stopCh)
		mesh.stopCh = nil
	}
	if mesh.udp != nil {
		_ = mesh.udp.Close()
		mesh.udp = nil
	}
	if mesh.device != nil {
		_ = mesh.device.Close()
		mesh.device = nil
	}
	// close() only signals; waiting here would deadlock against a worker blocked on mesh.mu.
	mesh.dataPlane.close()
	mesh.dataPlane = nil
	mesh.conn = nil
	mesh.sender = nil
	mesh.peers = nil
	mesh.sessions = nil
	mesh.sessionsByID = nil
	mesh.pending = nil
	mesh.pendingStun = nil
	mesh.pendingTurn = nil
	mesh.packets = nil
	mesh.prepared = nil
	mesh.srflx = nil
	mesh.srflxCandidates = nil
	mesh.relay = nil
	mesh.relayID = ""
	mesh.relayTTL = time.Time{}
	if mesh.portMappingService != nil && mesh.portMapping != nil {
		mesh.portMappingService.releaseMapping(*mesh.portMapping)
	}
	mesh.portMap = nil
	mesh.portMapping = nil
	mesh.lastPortMapAttempt = time.Time{}
	mesh.lastStunRequest = time.Time{}
	mesh.lastRelayRequest = time.Time{}
	mesh.lastAlternateRequest = time.Time{}
	mesh.lastBehaviorDiscovery = time.Time{}
	mesh.natByRole = nil
	mesh.natBehavior = nil
	mesh.natType = ""
	mesh.natMappingBehavior = ""
	mesh.natFilteringBehavior = ""
	mesh.natBehaviorDiscovery = ""
	mesh.lastEndpoint = ""
	mesh.turnPermissions = nil
	mesh.turnChannelsByPeer = nil
	mesh.turnChannelsByNumber = nil
	mesh.nextTurnChannel = turnChannelMin
	mesh.ignoredPacketLogAt = nil
	mesh.localKey = nil
	mesh.runtimeConfigKey = ""
}

func (mesh *peerMeshClient) isStartedLocked() bool {
	return mesh.udp != nil && mesh.stopCh != nil && mesh.runtime.PeerMesh.Enabled
}

func (mesh *peerMeshClient) shouldRetryVirtualDeviceStartLocked() bool {
	if mesh.device == nil {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(mesh.config.PeerMeshDevice))
	if mode == "" || mode == "noop" {
		return false
	}
	return strings.EqualFold(mesh.device.Status(), "ERROR")
}

func (mesh *peerMeshClient) runtimeConfigKeyFor(peerMesh PeerMeshConfig) string {
	publicStunServers := append([]string(nil), peerMesh.PublicStunServers...)
	sort.Strings(publicStunServers)
	parts := []string{
		strings.TrimSpace(mesh.config.PeerMeshDevice),
		strings.TrimSpace(mesh.config.PeerMeshTunName),
		fmt.Sprintf("%d", mesh.config.PeerMeshMTU),
		fmt.Sprintf("%d", peerMesh.ClientID),
		strings.TrimSpace(peerMesh.ClientName),
		strings.TrimSpace(peerMesh.VirtualIP),
		strings.TrimSpace(peerMesh.CIDR),
		strings.TrimSpace(peerMesh.StunHost),
		fmt.Sprintf("%d", peerMesh.StunPort),
		strings.TrimSpace(peerMesh.TurnHost),
		fmt.Sprintf("%d", peerMesh.TurnPort),
		strings.TrimSpace(peerMesh.ClientPublicKey),
		strings.TrimSpace(peerMesh.ServerPublicKey),
		strings.Join(publicStunServers, ","),
	}
	return strings.Join(parts, "|")
}

func (mesh *peerMeshClient) handleControl(conn net.Conn, payload string, base RuntimeConfig, sender peerControlSender) {
	if strings.TrimSpace(payload) == "" {
		return
	}
	var message peerControlMessage
	if err := json.Unmarshal([]byte(payload), &message); err != nil {
		mesh.logger.Printf("decode PEER_CONTROL failed: %v", err)
		return
	}
	switch message.Type {
	case peerControlTypeConfig:
		runtime := base
		if message.PeerMesh != nil {
			runtime.PeerMesh = *message.PeerMesh
		}
		mesh.start(conn, runtime, sender)
	case peerControlTypeRoster:
		mesh.mergeRoster(message.Peers)
		mesh.announceCandidates()
	case peerControlTypeSessionGrant:
		mesh.mergeSession(message)
		mesh.announceCandidates()
	case peerControlTypeCandidates:
		mesh.mergePeerFromSignal(message)
		mesh.mergeSession(message)
		mesh.sendConnectivityChecks(message)
		// H-1 候选回礼：port-restricted 组合下打洞要求双方几乎同时互射，本端无健康 direct
		// 路径时立刻回发自身候选，把双端 burst 窗口对齐到一个信令 RTT 内。
		mesh.reciprocateCandidates(mesh.peerIDFromControl(message))
	case peerControlTypeClose:
		mesh.closeSession(message)
	case peerControlTypeServiceCatalog:
		mesh.ensureServices().applyCatalog(message)
	default:
		mesh.logger.Printf("ignored peer-control message type=%q", message.Type)
	}
}

func (mesh *peerMeshClient) udpLoop(conn *net.UDPConn, stopCh <-chan struct{}) {
	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			mesh.logger.Printf("Peer Mesh UDP read failed: %v", err)
			return
		}
		payload := append([]byte(nil), buf[:n]...)
		mesh.handleUDP(payload, remote)
	}
}

func (mesh *peerMeshClient) maintenanceLoop(stopCh <-chan struct{}) {
	maintenanceTicker := time.NewTicker(15 * time.Second)
	defer maintenanceTicker.Stop()
	keepaliveTicker := time.NewTicker(5 * time.Second)
	defer keepaliveTicker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-maintenanceTicker.C:
			mesh.cleanupProbes()
			mesh.cleanupProbeRateLimiter()
			mesh.cleanupPendingPackets()
			mesh.renewPortMappingIfNeeded()
			mesh.requestRelayCandidates()
			mesh.announceCandidates()
			mesh.probeKnownCandidates()
			mesh.reportTrafficDeltas()
		case <-keepaliveTicker.C:
			mesh.keepaliveDirectPaths()
			mesh.fallbackStaleDirectPaths()
		}
	}
}

func (mesh *peerMeshClient) handleUDP(payload []byte, remote *net.UDPAddr) {
	if len(payload) == 0 {
		return
	}
	// Classify on a successful parse, never on the channel range alone. The SPM2 data-frame magic
	// 0x53504d32 opens with 0x5350, which sits inside the TURN ChannelData range 0x4000-0x7fff, so a
	// range-only test claimed every direct data frame and then dropped it when the ChannelData length
	// failed to add up. Java parses first for exactly this reason.
	if frame, err := parseTurnChannelData(payload); err == nil {
		mesh.mu.Lock()
		binding := mesh.turnChannelsByNumber[frame.Channel]
		valid := binding != nil && binding.Active && binding.ExpiresAt.After(time.Now())
		var peer *net.UDPAddr
		if valid {
			peer = cloneUDPAddr(binding.Peer)
		}
		mesh.mu.Unlock()
		if valid && sameUDPEndpoint(mesh.relayEndpoint(), remote) {
			mesh.handleRelayedPayload(frame.Payload, remote, peer)
			return
		}
		// An unbound channel or a foreign source is not ChannelData we own; fall through so a data
		// frame that happens to parse as ChannelData still reaches its own handler.
	}
	if looksLikeStun(payload) {
		message, err := parseStunMessage(payload)
		if err == nil {
			mesh.handleStunTurnMessage(*message, remote)
		}
		return
	}
	if looksLikePeerDataFrame(payload) {
		mesh.dispatchPeerDataFrame(payload, remote, "")
		return
	}
	// Probes are unauthenticated and each one costs a decode plus a reply, so they are rate limited
	// before being parsed, per source and globally.
	if !mesh.allowProbeFrom(remote) {
		return
	}
	var probe peerUDPProbe
	if err := json.Unmarshal(payload, &probe); err != nil || probe.Magic != peerProbeMagic {
		return
	}
	mesh.handleProbe(probe, remote, "")
}

// allowProbeFrom applies the shared probe budget. The source is the observed datagram origin, which
// for relayed traffic is the peer address the relay reported.
func (mesh *peerMeshClient) allowProbeFrom(remote *net.UDPAddr) bool {
	mesh.mu.Lock()
	limiter := mesh.probeLimiter
	mesh.mu.Unlock()
	if limiter == nil {
		return true
	}
	var source net.IP
	if remote != nil {
		source = remote.IP
	}
	return limiter.tryAcquire(source, time.Now())
}

func (mesh *peerMeshClient) handleStunTurnMessage(message stunMessage, remote *net.UDPAddr) {
	switch message.Type {
	case stunBindingSuccess:
		mesh.handleStunBindingSuccess(message, remote)
	case stunBindingError:
		mesh.handleStunBindingError(message, remote)
	case stunAllocateSuccess:
		_, _ = mesh.completeTurnRequest(message, remote)
		mesh.handleTurnAllocated(message, remote)
	case stunRefreshSuccess:
		_, _ = mesh.completeTurnRequest(message, remote)
		mesh.mu.Lock()
		mesh.relayTTL = time.Now().Add(time.Duration(maxInt64(30, message.lifetimeSeconds(300))) * time.Second)
		mesh.mu.Unlock()
	case stunCreatePermissionSuccess:
		_, _ = mesh.completeTurnRequest(message, remote)
		return
	case stunChannelBindSuccess:
		pending, ok := mesh.completeTurnRequest(message, remote)
		if ok {
			mesh.activateTurnChannel(pending)
		}
		return
	case stunAllocateError, stunRefreshError, stunCreatePermissionError, stunChannelBindError:
		mesh.handleTurnError(message, remote)
	case stunDataIndication:
		peer, okPeer := message.xorPeerAddress()
		inner, okData := message.data()
		if !okPeer || !okData {
			return
		}
		mesh.handleRelayedPayload(inner, remote, peer)
	}
}

func (mesh *peerMeshClient) handleRelayedPayload(inner []byte, remote, peer *net.UDPAddr) {
	relayFrom := endpointKeyUDP(peer)
	if looksLikePeerDataFrame(inner) {
		mesh.dispatchPeerDataFrame(inner, remote, relayFrom)
		return
	}
	if !mesh.allowProbeFrom(peer) {
		return
	}
	var probe peerUDPProbe
	if err := json.Unmarshal(inner, &probe); err == nil && probe.Magic == peerProbeMagic {
		mesh.handleProbe(probe, remote, relayFrom)
	}
}

func (mesh *peerMeshClient) completeTurnRequest(message stunMessage, remote *net.UDPAddr) (pendingTurnRequest, bool) {
	tx := stunTransactionHex(message.TransactionID)
	mesh.mu.Lock()
	pending, ok := mesh.pendingTurn[tx]
	if ok && sameUDPEndpoint(pending.Endpoint, remote) {
		delete(mesh.pendingTurn, tx)
		mesh.mu.Unlock()
		return pending, true
	}
	mesh.mu.Unlock()
	return pendingTurnRequest{}, false
}

func (mesh *peerMeshClient) activateTurnChannel(pending pendingTurnRequest) {
	if pending.RequestType != stunChannelBindRequest || pending.Channel < turnChannelMin || pending.Peer == nil {
		return
	}
	mesh.mu.Lock()
	binding := mesh.turnChannelsByNumber[pending.Channel]
	if binding != nil && sameUDPEndpoint(binding.Peer, pending.Peer) {
		binding.Active = true
		binding.ExpiresAt = time.Now().Add(9 * time.Minute)
	}
	mesh.mu.Unlock()
}

func (mesh *peerMeshClient) handleTurnError(message stunMessage, remote *net.UDPAddr) {
	tx := stunTransactionHex(message.TransactionID)
	errorCode := message.errorCode()
	mesh.mu.Lock()
	pending, ok := mesh.pendingTurn[tx]
	delete(mesh.pendingTurn, tx)
	if !ok || !sameUDPEndpoint(pending.Endpoint, remote) {
		mesh.mu.Unlock()
		mesh.logger.Printf("Peer Mesh TURN error ignored: type=0x%x code=%d tx=%s", message.Type, errorCode, tx)
		return
	}
	if errorCode != 401 && errorCode != 438 || pending.AuthenticationAttempt >= 1 || !mesh.applyTurnChallengeLocked(message) {
		mesh.removeFailedTurnChannelLocked(pending)
		mesh.mu.Unlock()
		mesh.logger.Printf("Peer Mesh TURN request failed: type=0x%x code=%d authAttempt=%d",
			pending.RequestType, errorCode, pending.AuthenticationAttempt)
		return
	}
	mesh.mu.Unlock()

	retryTx := newStunTransactionID()
	retryAttributes := remapTransactionAttributes(pending.Attributes, pending.OriginalTransactionID, retryTx)
	retry := newStunMessage(pending.RequestType, retryTx, retryAttributes...)
	mesh.logger.Printf("Peer Mesh TURN auth challenge received, retrying once: type=0x%x code=%d",
		pending.RequestType, errorCode)
	mesh.sendStunRequestAttempt(retry, pending.Endpoint, pending.AuthenticationAttempt+1)
}

func (mesh *peerMeshClient) removeFailedTurnChannelLocked(pending pendingTurnRequest) {
	if pending.RequestType != stunChannelBindRequest || pending.Channel < turnChannelMin {
		return
	}
	binding := mesh.turnChannelsByNumber[pending.Channel]
	if binding != nil {
		delete(mesh.turnChannelsByPeer, endpointKeyUDP(binding.Peer))
		delete(mesh.turnChannelsByNumber, pending.Channel)
	}
}

func remapTransactionAttributes(attributes []stunAttribute, oldTx, newTx [stunTransactionIDBytes]byte) []stunAttribute {
	result := cloneStunAttributes(attributes)
	for index := range result {
		if result[index].Type != stunAttrXorPeerAddress {
			continue
		}
		if peer, ok := decodeStunXorAddress(result[index].Value, oldTx); ok {
			result[index] = newStunAttrXorPeerAddress(peer, newTx)
		}
	}
	return result
}

func (mesh *peerMeshClient) applyTurnChallengeLocked(message stunMessage) bool {
	if code := message.errorCode(); code != 401 && code != 438 {
		return false
	}
	credentials := mesh.turnAuth
	if credentials.Username == "" || credentials.Credential == "" {
		return false
	}
	realm := strings.TrimSpace(message.text(stunAttrRealm))
	if realm == "" {
		realm = credentials.Realm
	}
	nonce := strings.TrimSpace(message.text(stunAttrNonce))
	if nonce == "" {
		nonce = credentials.Nonce
	}
	next := turnAuthCredentials{
		Username: credentials.Username, Credential: credentials.Credential,
		Realm: realm, Nonce: nonce,
	}
	if !next.complete() {
		return false
	}
	mesh.turnAuth = next
	return true
}

func sameUDPEndpoint(expected, actual *net.UDPAddr) bool {
	if expected == nil || actual == nil || expected.Port != actual.Port {
		return false
	}
	if expected.IP != nil && actual.IP != nil {
		return expected.IP.Equal(actual.IP)
	}
	return strings.EqualFold(expected.String(), actual.String())
}

func (mesh *peerMeshClient) handleStunBindingSuccess(message stunMessage, observedRemote *net.UDPAddr) {
	mapped, ok := message.xorMappedAddress()
	if !ok {
		mapped, ok = message.mappedAddress()
	}
	if !ok || mapped == nil || mapped.IP == nil || mapped.Port <= 0 {
		return
	}
	tx := stunTransactionHex(message.TransactionID)
	mesh.mu.Lock()
	binding, pending := mesh.pendingStun[tx]
	if !pending {
		mesh.mu.Unlock()
		if mesh.logger != nil {
			mesh.logger.Printf("Peer Mesh STUN Binding response ignored without pending transaction: tx=%s", tx)
		}
		return
	}
	if !sameUDPEndpoint(binding.ExpectedResponseEndpoint, observedRemote) {
		mesh.mu.Unlock()
		if mesh.logger != nil {
			mesh.logger.Printf("Peer Mesh STUN Binding response source mismatch: role=%s expected=%v actual=%v",
				binding.Role, binding.ExpectedResponseEndpoint, observedRemote)
		}
		return
	}
	delete(mesh.pendingStun, tx)
	if mesh.srflxCandidates == nil {
		mesh.srflxCandidates = make(map[string]peerCandidate)
	}
	role := binding.Role
	publicStun := strings.HasPrefix(role, publicStunRolePrefix)
	endpoint := endpointKeyUDP(mapped)
	candidate := peerCandidate{
		Type:          "srflx",
		Transport:     "udp",
		Address:       mapped.IP.String(),
		Port:          mapped.Port,
		Priority:      800,
		Foundation:    "standard-stun",
		AddressFamily: peerAddressFamily(mapped.IP),
	}
	if candidate.AddressFamily == "IPv6" {
		candidate.Priority = 900
	}
	if publicStun {
		candidate.Foundation = "public-stun"
	}
	candidateKey := candidateEndpointKey(candidate)
	_, candidateKnown := mesh.srflxCandidates[candidateKey]
	previousPrimary := ""
	if mesh.srflx != nil {
		previousPrimary = candidateEndpointKey(*mesh.srflx)
	}
	mesh.srflxCandidates[candidateKey] = candidate
	behaviorProbe := binding.BehaviorProbe
	discovery := mesh.natBehavior
	natType := ""
	if !publicStun && behaviorProbe == "" {
		mesh.natByRole[role] = endpoint
		mesh.srflx = &candidate
		natType = mesh.natTypeLocked()
		mesh.natType = natType
		mesh.lastEndpoint = endpoint
		if mesh.natBehaviorDiscovery != natDiscoveryRFC5780 || mesh.natMappingBehavior == "" {
			mesh.natMappingBehavior = ""
			mesh.natFilteringBehavior = ""
			mesh.natBehaviorDiscovery = natDiscoveryBasic
		}
	} else if !publicStun {
		mesh.srflx = &candidate
	}
	announce := !candidateKnown || (!publicStun && previousPrimary != candidateKey)
	mesh.mu.Unlock()

	if behaviorProbe != "" {
		if discovery != nil {
			mesh.handleNatBehaviorTransition(discovery.succeeded(
				binding.BehaviorGeneration,
				behaviorProbe,
				mapped))
		}
	} else if !publicStun {
		mesh.reportDevice(nil, nil, mesh.deviceStatus(), mesh.deviceError(), natType, endpoint)
		if role == peerRelayProbePrimary {
			if other, standard := resolveStandardOtherAddress(message, observedRemote); standard {
				mesh.startNatBehaviorDiscovery(observedRemote, mapped, other)
			} else if other, available := resolveOtherAddress(message, observedRemote); available {
				mesh.requestAlternateProbe(role, other, observedRemote)
			}
		}
	}
	if announce {
		mesh.announceCandidates()
	}
}

func (mesh *peerMeshClient) handleStunBindingError(message stunMessage, observedRemote *net.UDPAddr) {
	tx := stunTransactionHex(message.TransactionID)
	mesh.mu.Lock()
	binding, ok := mesh.pendingStun[tx]
	if !ok || !sameUDPEndpoint(binding.TargetEndpoint, observedRemote) {
		mesh.mu.Unlock()
		return
	}
	delete(mesh.pendingStun, tx)
	discovery := mesh.natBehavior
	mesh.mu.Unlock()

	if binding.BehaviorProbe == "" || discovery == nil {
		if mesh.logger != nil {
			mesh.logger.Printf("Peer Mesh STUN Binding request failed: role=%s code=%d",
				binding.Role, message.errorCode())
		}
		return
	}
	unknown := message.unknownAttributes()
	unsupported := message.errorCode() == 420 &&
		(len(unknown) == 0 || containsUint16(unknown, stunAttrChangeRequest))
	mesh.handleNatBehaviorTransition(discovery.failed(
		binding.BehaviorGeneration,
		binding.BehaviorProbe,
		unsupported))
}

func (mesh *peerMeshClient) startNatBehaviorDiscovery(
	primaryEndpoint *net.UDPAddr,
	mappedEndpoint *net.UDPAddr,
	otherEndpoint *net.UDPAddr,
) {
	now := time.Now()
	mesh.mu.Lock()
	if !mesh.lastBehaviorDiscovery.IsZero() &&
		now.Sub(mesh.lastBehaviorDiscovery) < peerBehaviorDiscoveryInterval {
		mesh.mu.Unlock()
		return
	}
	mesh.lastBehaviorDiscovery = now
	discovery := mesh.natBehavior
	if discovery == nil {
		discovery = &natBehaviorDiscovery{}
		mesh.natBehavior = discovery
	}
	mesh.mu.Unlock()

	transition, err := discovery.begin(primaryEndpoint, mappedEndpoint, otherEndpoint)
	if err != nil {
		if mesh.logger != nil {
			mesh.logger.Printf("Peer Mesh RFC 5780 topology ignored: %v", err)
		}
		return
	}
	mesh.handleNatBehaviorTransition(transition)
}

func (mesh *peerMeshClient) handleNatBehaviorTransition(transition natBehaviorTransition) {
	if !transition.Accepted {
		return
	}
	if transition.Snapshot.Complete {
		mesh.reportNatBehavior(transition.Snapshot)
	}
	if transition.NextProbe != nil {
		mesh.sendBehaviorProbe(*transition.NextProbe)
	}
}

func (mesh *peerMeshClient) reportNatBehavior(snapshot natBehaviorSnapshot) {
	if !snapshot.Complete || snapshot.MappedEndpoint == nil {
		return
	}
	endpoint := endpointKeyUDP(snapshot.MappedEndpoint)
	mesh.mu.Lock()
	natType := mesh.compatibleNatTypeLocked(snapshot)
	mesh.natType = natType
	mesh.natMappingBehavior = snapshot.MappingBehavior
	mesh.natFilteringBehavior = snapshot.FilteringBehavior
	mesh.natBehaviorDiscovery = snapshot.Discovery
	mesh.lastEndpoint = endpoint
	mesh.mu.Unlock()
	mesh.reportDevice(nil, nil, mesh.deviceStatus(), mesh.deviceError(), natType, endpoint)
}

func (mesh *peerMeshClient) compatibleNatTypeLocked(snapshot natBehaviorSnapshot) string {
	if snapshot.MappedEndpoint != nil && mesh.isNoNatLocked(endpointKeyUDP(snapshot.MappedEndpoint)) {
		return peerNatTypeNoNat
	}
	switch snapshot.MappingBehavior {
	case natBehaviorAddressDependent, natBehaviorAddressAndPortDependent:
		return peerNatTypeSymmetric
	case natBehaviorEndpointIndependent:
		switch snapshot.FilteringBehavior {
		case natBehaviorAddressAndPortDependent:
			return peerNatTypePortRestricted
		case natBehaviorEndpointIndependent, natBehaviorAddressDependent:
			return peerNatTypeFullConeOrRestricted
		}
	}
	fallback := mesh.natTypeLocked()
	if fallback != "" {
		return fallback
	}
	return peerNatTypeNat
}

func resolveStandardOtherAddress(
	message stunMessage,
	observedRemote *net.UDPAddr,
) (*net.UDPAddr, bool) {
	if observedRemote == nil || observedRemote.IP == nil {
		return nil, false
	}
	origin, originOK := message.responseOrigin()
	other, otherOK := message.otherAddress()
	if !originOK || !otherOK ||
		!sameUDPEndpoint(origin, observedRemote) ||
		other == nil ||
		other.IP == nil ||
		other.IP.Equal(observedRemote.IP) ||
		other.Port == observedRemote.Port {
		return nil, false
	}
	return other, true
}

func resolveOtherAddress(
	message stunMessage,
	observedRemote *net.UDPAddr,
) (*net.UDPAddr, bool) {
	if other, ok := resolveStandardOtherAddress(message, observedRemote); ok {
		return other, true
	}
	if origin, ok := message.legacyXorResponseOrigin(); ok &&
		sameUDPEndpoint(origin, observedRemote) {
		if other, otherOK := message.legacyXorOtherAddress(); otherOK {
			return other, true
		}
	}
	return message.otherAddress()
}

func containsUint16(values []uint16, expected uint16) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (mesh *peerMeshClient) handleTurnAllocated(message stunMessage, remote *net.UDPAddr) {
	relayed, ok := message.xorRelayedAddress()
	if !ok || relayed == nil || relayed.IP == nil || relayed.Port <= 0 {
		return
	}
	endpoint := mesh.relayEndpoint()
	if endpoint == nil {
		return
	}
	relayID := endpointKeyUDP(relayed)
	mesh.mu.Lock()
	relayChanged := mesh.relayID != relayID ||
		mesh.relay == nil ||
		mesh.relay.Address != endpoint.IP.String() ||
		mesh.relay.Port != endpoint.Port
	mesh.relayID = relayID
	mesh.relayTTL = time.Now().Add(time.Duration(maxInt64(30, message.lifetimeSeconds(300))) * time.Second)
	mesh.relay = &peerCandidate{
		Type:          "relay",
		Transport:     "udp",
		Address:       endpoint.IP.String(),
		Port:          endpoint.Port,
		Priority:      100,
		Foundation:    "standard-turn",
		RelayID:       relayID,
		AddressFamily: peerAddressFamily(endpoint.IP),
	}
	if relayChanged {
		clear(mesh.turnPermissions)
		clear(mesh.turnChannelsByPeer)
		clear(mesh.turnChannelsByNumber)
		mesh.nextTurnChannel = turnChannelMin
	}
	mesh.mu.Unlock()
	_ = remote
	if relayChanged {
		mesh.announceCandidates()
	}
}

func (mesh *peerMeshClient) handleProbe(probe peerUDPProbe, remote *net.UDPAddr, relayFrom string) {
	mesh.mu.Lock()
	runtime := mesh.runtime
	mesh.mu.Unlock()
	if runtime.PeerMesh.ClientID <= 0 || probe.ToClientID != runtime.PeerMesh.ClientID {
		return
	}
	if relayFrom == "" && mesh.shouldAvoidDirectPath() {
		return
	}
	switch probe.Type {
	case peerProbeTypeCheck:
		mesh.replyProbe(probe, remote, relayFrom)
	case peerProbeTypeCheckResponse:
		mesh.completeProbe(probe, remote, relayFrom)
	}
}

func (mesh *peerMeshClient) replyProbe(probe peerUDPProbe, remote *net.UDPAddr, relayFrom string) {
	mesh.mu.Lock()
	session := mesh.sessions[probe.FromClientID]
	udp := mesh.udp
	mesh.mu.Unlock()
	if session == nil || session.Token != probe.Token || udp == nil {
		return
	}
	mesh.markPathFromInboundCheck(session, remote, relayFrom)
	response := peerUDPProbe{
		Magic:        peerProbeMagic,
		Type:         peerProbeTypeCheckResponse,
		SessionID:    probe.SessionID,
		FromClientID: probe.ToClientID,
		ToClientID:   probe.FromClientID,
		Nonce:        probe.Nonce,
		Token:        probe.Token,
		SentAtMillis: probe.SentAtMillis,
	}
	body, _ := json.Marshal(response)
	if relayFrom != "" {
		_ = mesh.sendRelayPayload(relayFrom, body)
		return
	}
	_, _ = udp.WriteToUDP(body, remote)
}

// dispatchPeerDataFrame hands the frame to the bounded data-plane workers so decryption and the
// virtual-device write stay off the receive loop. Falling back to inline handling keeps behaviour
// intact for callers that run before the workers exist (tests, and the window before startOrUpdate).
func (mesh *peerMeshClient) dispatchPeerDataFrame(payload []byte, remote *net.UDPAddr, relayFrom string) {
	mesh.mu.Lock()
	plane := mesh.dataPlane
	mesh.mu.Unlock()
	if plane == nil {
		mesh.handlePeerDataFrame(payload, remote, relayFrom)
		return
	}
	sessionID, ok := peerDataFrameSessionID(payload)
	if !ok {
		return
	}
	if !plane.submit(sessionID, peerDataFrameTask{payload: payload, remote: remote, relayFrom: relayFrom}) {
		mesh.logDroppedPeerDataFrame(sessionID, plane)
	}
}

func (mesh *peerMeshClient) handlePeerDataFrame(payload []byte, remote *net.UDPAddr, relayFrom string) {
	if relayFrom == "" && (mesh.shouldAvoidDirectPath() || mesh.isMeshEndpoint(remote)) {
		return
	}
	sessionID, ok := peerDataFrameSessionID(payload)
	if !ok {
		return
	}
	mesh.mu.Lock()
	runtime := mesh.runtime
	session := mesh.sessionsByID[sessionID]
	if session != nil {
		_ = session.ensureTrafficCodecs(runtime.PeerMesh.ClientID)
	}
	if session == nil || session.InboundCodec == nil {
		mesh.mu.Unlock()
		return
	}
	inboundCodec := session.InboundCodec
	peerID := session.PeerID
	device := mesh.device
	mesh.mu.Unlock()
	if runtime.PeerMesh.ClientID <= 0 || device == nil {
		return
	}
	frame, err := inboundCodec.decode(payload, sessionID)
	if err != nil {
		return
	}
	if frame.SessionID != sessionID {
		return
	}
	mesh.mu.Lock()
	current := mesh.sessionsByID[sessionID]
	if current == nil || current.PeerID != peerID || time.Now().After(current.ExpiresAt) {
		mesh.mu.Unlock()
		return
	}
	if !current.acceptInboundFrame(frame) {
		mesh.mu.Unlock()
		return
	}
	if relayFrom != "" {
		current.PathType = "RELAY"
		current.RelayTargetAllocationID = relayFrom
		current.RemoteEndpoint = nil
		current.LastRelaySuccess = time.Now()
	} else {
		current.PathType = "DIRECT"
		current.RemoteEndpoint = remote
		current.RelayTargetAllocationID = ""
		current.LastDirectSuccess = time.Now()
		current.EndpointSuccess = time.Now()
		current.DirectBytes += int64(len(payload))
		current.DirectBytesPending += int64(len(payload))
	}
	mesh.mu.Unlock()
	mesh.flushPendingPackets(current)
	if mesh.handlePeerPathMTU(frame.Payload, current) {
		return
	}
	if mesh.handlePeerAppMessage(frame, current, runtime) {
		return
	}
	if _, noop := device.(*noopPeerVirtualDevice); !noop {
		if err := device.WritePacket(frame.Payload); err != nil {
			mesh.logger.Printf("Peer Mesh write virtual packet failed: session=%d peer=%d err=%v", frame.SessionID, peerID, err)
		}
		return
	}
	if reply := peerPacketICMPEchoReplyFor(frame.Payload, runtime.PeerMesh.VirtualIP); len(reply) > 0 {
		if err := mesh.sendEncryptedPayload(current, reply); err == nil {
			return
		}
	}
	if err := device.WritePacket(frame.Payload); err != nil {
		mesh.logger.Printf("Peer Mesh write virtual packet failed: session=%d peer=%d err=%v", frame.SessionID, peerID, err)
	}
}

func (mesh *peerMeshClient) handlePeerAppMessage(frame *peerDataFrame, session *peerMeshSession, runtime RuntimeConfig) bool {
	if !looksLikePeerAppMessage(frame.Payload) {
		return false
	}
	message, ok := decodePeerAppMessage(frame.Payload)
	if !ok {
		mesh.logger.Printf("Peer Mesh app message decode failed: session=%d from=%d", frame.SessionID, session.PeerID)
		return true
	}
	if strings.EqualFold(message.Type, peerAppMessageTypeAck) {
		return true
	}
	if !strings.EqualFold(message.Type, peerAppMessageTypeMessage) {
		return true
	}
	if message.FromClientID != 0 && message.FromClientID != session.PeerID {
		return true
	}
	if message.ToClientID != 0 && message.ToClientID != runtime.PeerMesh.ClientID {
		return true
	}
	fromName := strings.TrimSpace(message.FromClientName)
	if fromName == "" {
		fromName = fmt.Sprint(session.PeerID)
	}
	mesh.logger.Printf("Peer message from %s: %s", fromName, message.Message)
	mesh.mu.Lock()
	handler := mesh.messageHandler
	mesh.mu.Unlock()
	if handler != nil {
		handler(ClientMessage{
			FromClientName: fromName,
			ToClientName:   message.ToClientName,
			Message:        message.Message,
		})
	}
	if strings.TrimSpace(message.ID) == "" {
		return true
	}
	ack, err := encodePeerAppMessage(peerAppMessage{
		Type:            peerAppMessageTypeAck,
		ID:              message.ID,
		FromClientID:    runtime.PeerMesh.ClientID,
		FromClientName:  runtime.PeerMesh.ClientName,
		ToClientID:      session.PeerID,
		ToClientName:    firstNonEmpty(strings.TrimSpace(message.FromClientName), session.PeerName),
		CreatedAtMillis: time.Now().UnixMilli(),
	})
	if err == nil {
		_ = mesh.sendEncryptedPayload(session, ack)
	}
	return true
}

func (mesh *peerMeshClient) markPathFromInboundCheck(session *peerMeshSession, remote *net.UDPAddr, relayFrom string) {
	if session == nil || time.Now().After(session.ExpiresAt) || len(session.AESKey) == 0 {
		return
	}
	mesh.mu.Lock()
	current := mesh.sessions[session.PeerID]
	if current == nil || time.Now().After(current.ExpiresAt) || len(current.AESKey) == 0 {
		mesh.mu.Unlock()
		return
	}
	if relayFrom != "" {
		current.PathType = "RELAY"
		current.RelayTargetAllocationID = relayFrom
		current.RemoteEndpoint = nil
		current.LastRelaySuccess = time.Now()
		mesh.mu.Unlock()
		mesh.flushPendingPackets(current)
		return
	}
	if remote == nil || mesh.shouldAvoidDirectPathLocked() || inCIDR(remote.IP, mesh.runtime.PeerMesh.CIDR) {
		mesh.mu.Unlock()
		return
	}
	now := time.Now()
	currentEndpoint := current.RemoteEndpoint
	if udpAddrEqual(remote, currentEndpoint) {
		current.EndpointSuccess = now
	} else if !(strings.EqualFold(current.PathType, "DIRECT") &&
		currentEndpoint != nil &&
		!current.EndpointSuccess.IsZero() &&
		now.Sub(current.EndpointSuccess) <= peerDirectStaleInterval) {
		current.RemoteEndpoint = remote
		current.RelayTargetAllocationID = ""
		current.EndpointSuccess = now
		current.EndpointRTT = peerRttUnsetMillis
	}
	current.PathType = "DIRECT"
	current.LastDirectSuccess = now
	mesh.mu.Unlock()
	mesh.flushPendingPackets(current)
}

func (mesh *peerMeshClient) handleVirtualPacket(packet []byte) {
	targetIP := peerPacketDestinationIPv4(packet)
	if targetIP == "" {
		return
	}
	if mesh.shouldIgnoreVirtualPacketTarget(targetIP) {
		mesh.logIgnoredVirtualPacket(targetIP, "non-peer-unicast")
		return
	}
	mesh.mu.Lock()
	var session *peerMeshSession
	for _, candidate := range mesh.sessions {
		if candidate.PeerVirtualIP == targetIP {
			session = candidate
			break
		}
	}
	var peer *peerMeshPeer
	for _, candidate := range mesh.peers {
		if candidate.VirtualIP != targetIP {
			continue
		}
		if candidate.Online {
			peer = candidate
			break
		}
		if peer == nil {
			peer = candidate
		}
	}
	udp := mesh.udp
	runtime := mesh.runtime
	mesh.mu.Unlock()
	if peer == nil || !peer.Online {
		mesh.logIgnoredVirtualPacket(targetIP, "unknown-peer-route")
		return
	}
	if session == nil || udp == nil || runtime.PeerMesh.ClientID <= 0 {
		if peer != nil {
			mesh.queuePendingPacket(peer.ClientID, packet)
			mesh.preparePathForPeer(peer, session)
		}
		return
	}
	if err := mesh.sendEncryptedPayload(session, packet); err != nil {
		mesh.queuePendingPacket(session.PeerID, packet)
		if peer == nil {
			mesh.mu.Lock()
			peer = mesh.peers[session.PeerID]
			mesh.mu.Unlock()
		}
		mesh.preparePathForPeer(peer, session)
		mesh.logger.Printf("Peer Mesh send virtual packet failed: peer=%d target=%s flow=%s err=%v", session.PeerID, targetIP, peerPacketFlowKey(packet), err)
	}
}

func (mesh *peerMeshClient) shouldIgnoreVirtualPacketTarget(targetVirtualIP string) bool {
	ipv4 := net.ParseIP(targetVirtualIP).To4()
	if ipv4 == nil {
		return true
	}
	firstOctet := int(ipv4[0])
	if firstOctet >= 224 || firstOctet == 0 || targetVirtualIP == "255.255.255.255" {
		return true
	}
	mesh.mu.Lock()
	virtualIP := strings.TrimSpace(mesh.runtime.PeerMesh.VirtualIP)
	cidr := mesh.runtime.PeerMesh.CIDR
	mesh.mu.Unlock()
	if targetVirtualIP == virtualIP {
		return true
	}
	return isMeshBoundaryAddress(targetVirtualIP, cidr)
}

// isMeshBoundaryAddress reports whether the target is the network or broadcast
// address of the mesh CIDR; /31 and /32 have no such boundary addresses.
func isMeshBoundaryAddress(targetVirtualIP, cidr string) bool {
	if strings.TrimSpace(cidr) == "" {
		return false
	}
	ipv4 := net.ParseIP(targetVirtualIP).To4()
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ipv4 == nil {
		return false
	}
	networkIPv4 := network.IP.To4()
	if networkIPv4 == nil || len(network.Mask) != 4 {
		return false
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones >= 31 {
		return false
	}
	ipValue := binary.BigEndian.Uint32(ipv4)
	networkValue := binary.BigEndian.Uint32(networkIPv4)
	mask := binary.BigEndian.Uint32(network.Mask)
	broadcast := networkValue | ^mask
	return ipValue == networkValue || ipValue == broadcast
}

func (mesh *peerMeshClient) logIgnoredVirtualPacket(targetVirtualIP, reason string) {
	now := time.Now()
	key := "ignored|" + targetVirtualIP + "|" + reason
	mesh.mu.Lock()
	if mesh.ignoredPacketLogAt == nil {
		mesh.ignoredPacketLogAt = make(map[string]time.Time)
	}
	if previous, ok := mesh.ignoredPacketLogAt[key]; ok && now.Sub(previous) < 30*time.Second {
		mesh.mu.Unlock()
		return
	}
	mesh.ignoredPacketLogAt[key] = now
	peerCount := len(mesh.peers)
	sessionCount := len(mesh.sessions)
	mesh.mu.Unlock()
	mesh.logger.Printf("Peer Mesh ignored non-peer virtual packet: target=%s reason=%s peers=%d sessions=%d",
		targetVirtualIP, reason, peerCount, sessionCount)
}

// logDroppedPeerDataFrame reports data-plane saturation at most once every 30s per session: a
// saturated shard means a burst of drops, and one line per dropped datagram would itself become the
// bottleneck.
func (mesh *peerMeshClient) logDroppedPeerDataFrame(sessionID int64, plane *peerDataPlane) {
	now := time.Now()
	key := fmt.Sprintf("dropped-data-frame|%d", sessionID)
	mesh.mu.Lock()
	if mesh.ignoredPacketLogAt == nil {
		mesh.ignoredPacketLogAt = make(map[string]time.Time)
	}
	if previous, ok := mesh.ignoredPacketLogAt[key]; ok && now.Sub(previous) < 30*time.Second {
		mesh.mu.Unlock()
		return
	}
	mesh.ignoredPacketLogAt[key] = now
	mesh.mu.Unlock()
	stats := plane.stats()
	mesh.logger.Printf("Peer Mesh dropped peer data frame, data plane saturated: session=%d workers=%d depth=%d highWater=%d rejected=%d",
		sessionID, stats.Workers, stats.Depth, stats.HighWater, stats.Rejected)
}

func (mesh *peerMeshClient) cleanupProbeRateLimiter() {
	mesh.mu.Lock()
	limiter := mesh.probeLimiter
	mesh.mu.Unlock()
	limiter.cleanup(time.Now())
}

func (mesh *peerMeshClient) syncVirtualDeviceRoutes() {
	mesh.mu.Lock()
	device := mesh.device
	selfVirtualIP := strings.TrimSpace(mesh.runtime.PeerMesh.VirtualIP)
	routeSet := make(map[string]struct{}, len(mesh.peers))
	for _, peer := range mesh.peers {
		if peer == nil || !peer.Online {
			continue
		}
		virtualIP := strings.TrimSpace(peer.VirtualIP)
		if virtualIP == "" || virtualIP == selfVirtualIP {
			continue
		}
		routeSet[virtualIP] = struct{}{}
	}
	mesh.mu.Unlock()
	if device == nil {
		return
	}
	routeIPs := make([]string, 0, len(routeSet))
	for routeIP := range routeSet {
		routeIPs = append(routeIPs, routeIP)
	}
	sort.Strings(routeIPs)
	device.SyncPeerRoutes(routeIPs)
}

func (mesh *peerMeshClient) queuePendingPacket(peerID int64, packet []byte) {
	if peerID <= 0 || len(packet) == 0 {
		return
	}
	now := time.Now()
	copyPacket := append([]byte(nil), packet...)
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	if mesh.packets == nil {
		mesh.packets = make(map[int64][]pendingPeerPacket)
	}
	queue := mesh.packets[peerID]
	filtered := queue[:0]
	for _, item := range queue {
		if now.Sub(item.SentAt) <= peerPendingPacketTTL {
			filtered = append(filtered, item)
		}
	}
	for len(filtered) >= peerMaxPendingPackets {
		filtered = filtered[1:]
	}
	filtered = append(filtered, pendingPeerPacket{Packet: copyPacket, SentAt: now})
	mesh.packets[peerID] = filtered
}

func (mesh *peerMeshClient) flushPendingPackets(session *peerMeshSession) {
	if session == nil {
		return
	}
	now := time.Now()
	mesh.mu.Lock()
	queue := mesh.packets[session.PeerID]
	delete(mesh.packets, session.PeerID)
	mesh.mu.Unlock()
	flushed := 0
	for _, item := range queue {
		if now.Sub(item.SentAt) > peerPendingPacketTTL {
			continue
		}
		if err := mesh.sendEncryptedPayload(session, item.Packet); err == nil {
			flushed++
		}
	}
	if flushed > 0 {
		mesh.logger.Printf("Peer Mesh pending virtual packet flushed: peer=%d count=%d", session.PeerID, flushed)
	}
}

func (mesh *peerMeshClient) cleanupPendingPackets() {
	now := time.Now()
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	for peerID, queue := range mesh.packets {
		filtered := queue[:0]
		for _, item := range queue {
			if now.Sub(item.SentAt) <= peerPendingPacketTTL {
				filtered = append(filtered, item)
			}
		}
		if len(filtered) == 0 {
			delete(mesh.packets, peerID)
		} else {
			mesh.packets[peerID] = filtered
		}
	}
}

func (mesh *peerMeshClient) preparePathForPeer(peer *peerMeshPeer, session *peerMeshSession) {
	if peer == nil || !peer.Online || strings.TrimSpace(peer.ClientName) == "" {
		return
	}
	now := time.Now()
	mesh.mu.Lock()
	if mesh.prepared == nil {
		mesh.prepared = make(map[int64]time.Time)
	}
	if previous := mesh.prepared[peer.ClientID]; !previous.IsZero() && now.Sub(previous) < peerPathPrepareMinInterval {
		mesh.mu.Unlock()
		return
	}
	mesh.prepared[peer.ClientID] = now
	candidates := append([]peerCandidate(nil), peer.Candidates...)
	mesh.mu.Unlock()

	mesh.requestRelayCandidates()
	mesh.announceCandidates()
	if session != nil && len(candidates) > 0 {
		mesh.sendConnectivityChecks(peerControlMessage{
			SourceClientID: peer.ClientID,
			Candidates:     candidates,
		})
	}
}

func (mesh *peerMeshClient) sendEncryptedPayload(session *peerMeshSession, payload []byte) error {
	mesh.ensurePeerPathMTU(session)
	if peerPacketDestinationIPv4(payload) != "" && session != nil && session.PathMTU != nil {
		pathMTU := session.PathMTU.effectiveMTU(mesh.config.PeerMeshMTU)
		payload = peerPacketClampTCPMSS(payload, pathMTU)
		if len(payload) > pathMTU {
			mesh.injectPeerPacketTooBig(payload, pathMTU)
			return nil
		}
	}
	mesh.mu.Lock()
	current := mesh.sessions[session.PeerID]
	udp := mesh.udp
	if current != nil {
		_ = current.ensureTrafficCodecs(mesh.runtime.PeerMesh.ClientID)
	}
	if current == nil || current.OutboundCodec == nil {
		mesh.mu.Unlock()
		return fmt.Errorf("peer session is not ready")
	}
	if time.Now().After(current.ExpiresAt) {
		mesh.mu.Unlock()
		return fmt.Errorf("peer session expired")
	}
	current.Sequence++
	sequence := current.Sequence
	outboundCodec := current.OutboundCodec
	sessionID := current.ID
	peerID := current.PeerID
	remote := current.RemoteEndpoint
	relayID := current.RelayTargetAllocationID
	avoidDirect := mesh.shouldAvoidDirectPathLocked()
	mesh.mu.Unlock()

	frame, err := outboundCodec.encode(sessionID, sequence, payload)
	if err != nil {
		return err
	}
	if relayID != "" {
		if err := mesh.sendRelayPayload(relayID, frame); err != nil {
			return err
		}
		return nil
	}
	if udp == nil || remote == nil {
		return fmt.Errorf("missing direct peer endpoint")
	}
	if avoidDirect || mesh.isMeshEndpoint(remote) {
		return fmt.Errorf("direct peer endpoint disabled")
	}
	if _, err := udp.WriteToUDP(frame, remote); err != nil {
		return err
	}
	mesh.mu.Lock()
	if current := mesh.sessions[peerID]; current != nil {
		current.DirectBytes += int64(len(frame))
		current.DirectBytesPending += int64(len(frame))
	}
	mesh.mu.Unlock()
	return nil
}

func (mesh *peerMeshClient) ensurePeerPathMTU(session *peerMeshSession) {
	if session == nil || session.PathMTU == nil {
		return
	}
	mesh.mu.Lock()
	if mesh.sessions[session.PeerID] != session {
		mesh.mu.Unlock()
		return
	}
	pathKey := peerPathMTUKey(session)
	now := time.Now()
	var cached *cachedPeerPathMTU
	if item, ok := mesh.pathMTUCache[pathKey]; ok {
		if now.Before(item.ValidUntil) {
			copy := item
			cached = &copy
		} else {
			delete(mesh.pathMTUCache, pathKey)
		}
	}
	configuredMTU := mesh.config.PeerMeshMTU
	mesh.mu.Unlock()
	if pathKey == "" {
		return
	}
	mesh.applyPeerPathMTUTransition(session, session.PathMTU.activate(pathKey, configuredMTU, cached, now))
}

func (mesh *peerMeshClient) handlePeerPathMTU(payload []byte, session *peerMeshSession) bool {
	if !looksLikePeerPathMTU(payload) {
		return false
	}
	message, ok := decodePeerPathMTU(payload)
	if !ok || session == nil || session.PathMTU == nil {
		return true
	}
	if message.Probe {
		_ = mesh.sendRawPeerPayload(session, encodePeerPathMTUAck(message.Nonce, message.InnerMTU))
		return true
	}
	mesh.applyPeerPathMTUTransition(
		session, session.PathMTU.acknowledge(message.Nonce, message.InnerMTU, time.Now()))
	return true
}

func (mesh *peerMeshClient) applyPeerPathMTUTransition(session *peerMeshSession, transition peerPathMTUTransition) {
	if session == nil || session.PathMTU == nil {
		return
	}
	if transition.CompletedMTU > 0 {
		pathKey := session.PathMTU.currentPathKey()
		if pathKey != "" {
			mesh.mu.Lock()
			if mesh.pathMTUCache == nil {
				mesh.pathMTUCache = make(map[string]cachedPeerPathMTU)
			}
			mesh.pathMTUCache[pathKey] = cachedPeerPathMTU{
				InnerMTU: transition.CompletedMTU, ValidUntil: time.Now().Add(peerPathMTUCacheTTL)}
			mesh.mu.Unlock()
			mesh.logger.Printf("Peer Mesh path MTU discovered: session=%d peer=%d path=%s mtu=%d",
				session.ID, session.PeerID, pathKey, transition.CompletedMTU)
		}
	}
	if transition.Probe != nil {
		mesh.sendPeerPathMTUProbe(session, transition.Probe)
	}
}

func (mesh *peerMeshClient) sendPeerPathMTUProbe(session *peerMeshSession, probe *peerPathMTUProbe) {
	if session == nil || probe == nil {
		return
	}
	_ = mesh.sendRawPeerPayload(session, encodePeerPathMTUProbe(probe.Nonce, probe.InnerMTU))
	sessionID := session.ID
	nonce := probe.Nonce
	time.AfterFunc(peerPathMTUProbeTimeout, func() {
		mesh.mu.Lock()
		current := mesh.sessionsByID[sessionID]
		mesh.mu.Unlock()
		if current == nil || current.PathMTU == nil || time.Now().After(current.ExpiresAt) {
			return
		}
		mesh.applyPeerPathMTUTransition(current, current.PathMTU.timeout(nonce, time.Now()))
	})
}

func (mesh *peerMeshClient) sendRawPeerPayload(session *peerMeshSession, payload []byte) error {
	if session == nil || len(payload) == 0 {
		return fmt.Errorf("empty peer payload")
	}
	mesh.mu.Lock()
	current := mesh.sessions[session.PeerID]
	udp := mesh.udp
	if current != nil {
		_ = current.ensureTrafficCodecs(mesh.runtime.PeerMesh.ClientID)
	}
	if current != session || udp == nil || current.OutboundCodec == nil || time.Now().After(current.ExpiresAt) {
		mesh.mu.Unlock()
		return fmt.Errorf("peer session is not ready")
	}
	current.Sequence++
	sequence := current.Sequence
	outboundCodec := current.OutboundCodec
	sessionID := current.ID
	peerID := current.PeerID
	remote := current.RemoteEndpoint
	relayID := current.RelayTargetAllocationID
	mesh.mu.Unlock()

	frame, err := outboundCodec.encode(sessionID, sequence, payload)
	if err != nil {
		return err
	}
	if relayID != "" {
		return mesh.sendRelayPayload(relayID, frame)
	}
	if remote == nil || mesh.isMeshEndpoint(remote) {
		return fmt.Errorf("missing direct peer endpoint")
	}
	if _, err = udp.WriteToUDP(frame, remote); err != nil {
		return err
	}
	mesh.mu.Lock()
	if current := mesh.sessions[peerID]; current != nil {
		current.DirectBytes += int64(len(frame))
		current.DirectBytesPending += int64(len(frame))
	}
	mesh.mu.Unlock()
	return nil
}

func peerPathMTUKey(session *peerMeshSession) string {
	if session == nil {
		return ""
	}
	if session.RelayTargetAllocationID != "" {
		return "relay|" + session.RelayTargetAllocationID
	}
	if session.RemoteEndpoint == nil {
		return ""
	}
	return "direct|" + endpointKeyUDP(session.RemoteEndpoint)
}

func (mesh *peerMeshClient) injectPeerPacketTooBig(packet []byte, pathMTU int) {
	response := peerPacketICMPFragmentationNeededFor(packet, pathMTU)
	if len(response) == 0 {
		return
	}
	mesh.mu.Lock()
	device := mesh.device
	mesh.mu.Unlock()
	if device != nil {
		_ = device.WritePacket(response)
	}
}

func (mesh *peerMeshClient) completeProbe(probe peerUDPProbe, remote *net.UDPAddr, relayFrom string) {
	now := time.Now()
	mesh.mu.Lock()
	pending, ok := mesh.pending[probe.Nonce]
	if ok {
		delete(mesh.pending, probe.Nonce)
	}
	session := mesh.sessions[pending.PeerID]
	if !ok || session == nil || session.ID != probe.SessionID || session.Token != probe.Token {
		mesh.mu.Unlock()
		return
	}
	if len(session.AESKey) == 0 {
		sessionID := session.ID
		peerID := session.PeerID
		mesh.mu.Unlock()
		mesh.logger.Printf("Peer Mesh UDP path checked but session key is unavailable: session=%d peer=%d", sessionID, peerID)
		return
	}
	rtt := time.Since(pending.SentAt).Milliseconds()
	pathType := "DIRECT"
	remoteText := remote.String()
	if pending.Relay || relayFrom != "" {
		pathType = "RELAY"
		remoteText = "relay:" + firstNonEmpty(relayFrom, pending.RelayID)
	}
	if pathType == "DIRECT" && (mesh.shouldAvoidDirectPathLocked() || mesh.isMeshEndpointLocked(remote)) {
		mesh.mu.Unlock()
		return
	}
	shouldLog := false
	shouldReport := false
	previousPath := session.PathType
	previousRemote := session.LastPathRemoteText
	if pending.Relay {
		if session.hasHealthyDirect(now) && !mesh.shouldAvoidDirectPathLocked() {
			mesh.mu.Unlock()
			return
		}
		session.BestRelayRTT = smoothPeerRTT(session.BestRelayRTT, rtt)
		session.PathType = pathType
		session.RelayTargetAllocationID = pending.RelayID
		session.LastRelaySuccess = now
	} else {
		session.BestDirectRTT = smoothPeerRTT(session.BestDirectRTT, rtt)
		adoptEndpoint := true
		currentEndpoint := session.RemoteEndpoint
		if udpAddrEqual(remote, currentEndpoint) {
			session.EndpointSuccess = now
			session.EndpointRTT = rtt
		} else if strings.EqualFold(session.PathType, "DIRECT") &&
			currentEndpoint != nil &&
			!session.EndpointSuccess.IsZero() &&
			now.Sub(session.EndpointSuccess) <= peerDirectStaleInterval &&
			session.EndpointRTT > 0 &&
			session.EndpointRTT != peerRttUnsetMillis &&
			rtt+peerRttHysteresisMillis >= session.EndpointRTT {
			adoptEndpoint = false
		}
		session.PathType = pathType
		if adoptEndpoint {
			session.RemoteEndpoint = remote
			session.RelayTargetAllocationID = ""
			session.EndpointSuccess = now
			session.EndpointRTT = rtt
		} else {
			remoteText = previousRemote
		}
		session.LastDirectSuccess = now
	}
	pathChanged := previousRemote != remoteText || !strings.EqualFold(previousPath, pathType)
	if pathChanged || session.LastPathLog.IsZero() || now.Sub(session.LastPathLog) >= time.Minute {
		shouldLog = true
		session.LastPathLog = now
	}
	if pathChanged || session.LastPathReport.IsZero() || now.Sub(session.LastPathReport) >= time.Minute {
		shouldReport = true
		session.LastPathReport = now
	}
	session.LastPathRemoteText = remoteText
	mesh.mu.Unlock()
	if shouldLog {
		mesh.logger.Printf("Peer Mesh %s UDP path active: session=%d peer=%d remote=%s rtt=%dms",
			strings.ToLower(pathType), session.ID, session.PeerID, remoteText, rtt)
	}
	if shouldReport {
		mesh.reportPath(session, pathType, mesh.localEndpoint(), remoteText, rtt)
	}
	mesh.flushPendingPackets(session)
}

func (mesh *peerMeshClient) mergeRoster(items []peerMeshPeer) {
	mesh.mu.Lock()
	// Roster 推送只带身份与在线状态；清空重建让被移出 roster 的 peer 立即消失，
	// 同时保留仍在 roster 中 peer 已学到的 candidates，避免 probeKnownCandidates 失效。
	previous := mesh.peers
	next := make(map[int64]*peerMeshPeer, len(items))
	for _, item := range items {
		if item.ClientID <= 0 {
			continue
		}
		copy := item
		if existing := previous[item.ClientID]; existing != nil && len(copy.Candidates) == 0 {
			copy.Candidates = existing.Candidates
		}
		next[item.ClientID] = &copy
	}
	mesh.peers = next
	hints := make(map[int64]peerServiceRosterHint, len(next))
	onlinePeer := false
	for id, peer := range next {
		hints[id] = peerServiceRosterHint{virtualIP: peer.VirtualIP, online: peer.Online}
		if peer.Online {
			onlinePeer = true
		}
	}
	mesh.mu.Unlock()
	mesh.ensureServices().setRoster(hints)
	mesh.ensureServices().setHasAuthorizedOnlinePeer(onlinePeer)
	mesh.syncVirtualDeviceRoutes()
}

func (mesh *peerMeshClient) mergePeerFromSignal(message peerControlMessage) {
	if mesh.applyPeerFromSignal(message) {
		mesh.syncVirtualDeviceRoutes()
	}
}

func (mesh *peerMeshClient) applyPeerFromSignal(message peerControlMessage) bool {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	if mesh.peers == nil {
		mesh.peers = make(map[int64]*peerMeshPeer)
	}
	runtimeID := mesh.runtime.PeerMesh.ClientID
	var peer peerMeshPeer
	if message.SourceClientID != 0 && message.SourceClientID != runtimeID {
		peer = peerMeshPeer{ClientID: message.SourceClientID, ClientName: message.SourceClientName, VirtualIP: message.SourceVirtualIP, PublicKey: message.SourcePublicKey, Online: true}
	} else if message.TargetClientID != 0 && message.TargetClientID != runtimeID {
		peer = peerMeshPeer{ClientID: message.TargetClientID, ClientName: message.TargetClientName, VirtualIP: message.TargetVirtualIP, PublicKey: message.TargetPublicKey, Online: true}
	}
	if peer.ClientID <= 0 {
		return false
	}
	if existing := mesh.peers[peer.ClientID]; existing != nil {
		if peer.ClientName == "" {
			peer.ClientName = existing.ClientName
		}
		if peer.VirtualIP == "" {
			peer.VirtualIP = existing.VirtualIP
		}
		if peer.PublicKey == "" {
			peer.PublicKey = existing.PublicKey
		}
		if peer.KeyEpoch == "" {
			peer.KeyEpoch = existing.KeyEpoch
		}
	}
	peer.Candidates = append([]peerCandidate(nil), message.Candidates...)
	mesh.peers[peer.ClientID] = &peer
	if session := mesh.sessions[peer.ClientID]; session != nil && peer.KeyEpoch != "" {
		if session.applyRemoteKeyEpoch(peer.KeyEpoch) {
			mesh.logger.Printf("Peer Mesh remote key epoch changed, inbound state reset: peer=%d", peer.ClientID)
		}
	}
	return true
}

func (mesh *peerMeshClient) mergeSession(message peerControlMessage) {
	if message.SessionID == nil || *message.SessionID <= 0 || message.Token == "" {
		return
	}
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	peerID := message.TargetClientID
	peerName := message.TargetClientName
	peerVirtualIP := message.TargetVirtualIP
	peerPublicKey := message.TargetPublicKey
	if peerID == 0 || peerID == mesh.runtime.PeerMesh.ClientID {
		peerID = message.SourceClientID
		peerName = message.SourceClientName
		peerVirtualIP = message.SourceVirtualIP
		peerPublicKey = message.SourcePublicKey
	}
	if peerID <= 0 || peerID == mesh.runtime.PeerMesh.ClientID {
		return
	}
	if peer := mesh.peers[peerID]; peer != nil {
		if peerName == "" {
			peerName = peer.ClientName
		}
		if peerVirtualIP == "" {
			peerVirtualIP = peer.VirtualIP
		}
		if peerPublicKey == "" {
			peerPublicKey = peer.PublicKey
		}
	}
	previous := mesh.sessions[peerID]
	if previous != nil {
		if peerName == "" {
			peerName = previous.PeerName
		}
		if peerVirtualIP == "" {
			peerVirtualIP = previous.PeerVirtualIP
		}
		if peerPublicKey == "" {
			peerPublicKey = previous.PeerPublicKey
		}
	}
	expiresAt := time.Now().Add(time.Hour)
	if parsed, err := time.Parse(time.RFC3339Nano, message.ExpiresAt); err == nil {
		expiresAt = parsed
	}
	sameSession := previous != nil && previous.ID == *message.SessionID
	session := &peerMeshSession{Replay: peerReplayWindow{}, PathMTU: &peerPathMTUDiscovery{}}
	if previous != nil {
		if sameSession {
			session.Sequence = previous.Sequence
			session.Replay = previous.Replay
		}
		session.RemoteEndpoint = previous.RemoteEndpoint
		session.RelayTargetAllocationID = previous.RelayTargetAllocationID
		session.PathType = previous.PathType
		session.LastDirectSuccess = previous.LastDirectSuccess
		session.LastDirectKeepalive = previous.LastDirectKeepalive
		session.LastRelaySuccess = previous.LastRelaySuccess
		session.LastPathLog = previous.LastPathLog
		session.LastPathReport = previous.LastPathReport
		session.LastPathRemoteText = previous.LastPathRemoteText
		session.EndpointSuccess = previous.EndpointSuccess
		session.EndpointRTT = previous.EndpointRTT
		session.BestDirectRTT = previous.BestDirectRTT
		session.BestRelayRTT = previous.BestRelayRTT
		session.DirectBytes = previous.DirectBytes
		session.DirectBytesPending = previous.DirectBytesPending
	}
	if message.DataFrameVersion != 2 {
		mesh.logger.Printf("Peer Mesh session rejected: required dataFrameVersion=2 received=%d", message.DataFrameVersion)
		return
	}
	session.ID = *message.SessionID
	session.PeerID = peerID
	session.PeerName = peerName
	session.PeerVirtualIP = peerVirtualIP
	session.PeerPublicKey = peerPublicKey
	session.Token = message.Token
	session.ExpiresAt = expiresAt
	session.LocalKeyEpoch = mesh.localKeyEpoch
	if message.SourceKeyEpoch != "" && message.SourceClientID == peerID {
		session.applyRemoteKeyEpoch(message.SourceKeyEpoch)
	}
	if session.RemoteKeyEpoch == "" {
		if known := mesh.peers[peerID]; known != nil {
			session.applyRemoteKeyEpoch(known.KeyEpoch)
		}
	}
	if strings.TrimSpace(message.PathType) != "" {
		session.PathType = message.PathType
	}
	if len(session.AESKey) == 0 && mesh.localKey != nil && strings.TrimSpace(peerPublicKey) != "" {
		aesKey, err := derivePeerMeshAESKey(mesh.localKey, peerPublicKey, session.ID, session.Token, mesh.runtime.PeerMesh.ClientID, peerID)
		if err != nil {
			mesh.logger.Printf("Peer Mesh session key derive failed: session=%d peer=%d err=%v", session.ID, peerID, err)
		} else {
			session.AESKey = aesKey
			err = session.ensureTrafficCodecs(mesh.runtime.PeerMesh.ClientID)
			if err != nil {
				session.AESKey = nil
				session.OutboundCodec = nil
				session.InboundCodec = nil
				mesh.logger.Printf("Peer Mesh traffic codec initialization failed: session=%d peer=%d err=%v", session.ID, peerID, err)
			}
		}
	}
	if mesh.sessionsByID == nil {
		mesh.sessionsByID = make(map[int64]*peerMeshSession)
	}
	if previous != nil {
		delete(mesh.sessionsByID, previous.ID)
	}
	mesh.sessions[peerID] = session
	mesh.sessionsByID[session.ID] = session
}

func (mesh *peerMeshClient) closeSession(message peerControlMessage) {
	if message.SessionID == nil {
		return
	}
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	for peerID, session := range mesh.sessions {
		if session.ID == *message.SessionID {
			delete(mesh.sessions, peerID)
			delete(mesh.sessionsByID, session.ID)
		}
	}
}

func (mesh *peerMeshClient) reusableSessionLocked(peerID int64, now time.Time) *peerMeshSession {
	if mesh.sessions == nil {
		return nil
	}
	session := mesh.sessions[peerID]
	if session == nil {
		return nil
	}
	if now.After(session.ExpiresAt) {
		delete(mesh.sessions, peerID)
		if mesh.sessionsByID != nil {
			delete(mesh.sessionsByID, session.ID)
		}
		return nil
	}
	return session
}

func (mesh *peerMeshClient) announceCandidates() {
	candidates := mesh.gatherCandidates()
	if len(candidates) == 0 {
		mesh.requestRelayCandidates()
		candidates = mesh.gatherCandidates()
	}
	if len(candidates) == 0 {
		return
	}
	mesh.mu.Lock()
	conn := mesh.conn
	sender := mesh.sender
	runtime := mesh.runtime
	if sender == nil {
		mesh.mu.Unlock()
		return
	}
	type announceTarget struct {
		peer    peerMeshPeer
		session *peerMeshSession
	}
	now := time.Now()
	peers := make([]announceTarget, 0, len(mesh.peers))
	for _, peer := range mesh.peers {
		if peer.Online && strings.TrimSpace(peer.ClientName) != "" {
			peers = append(peers, announceTarget{
				peer:    *peer,
				session: mesh.reusableSessionLocked(peer.ClientID, now),
			})
		}
	}
	mesh.mu.Unlock()
	for _, target := range peers {
		message := peerControlMessage{
			Type:             peerControlTypeCandidates,
			SourceClientID:   runtime.PeerMesh.ClientID,
			SourceClientName: runtime.PeerMesh.ClientName,
			SourceVirtualIP:  runtime.PeerMesh.VirtualIP,
			SourcePublicKey:  runtime.PeerMesh.ClientPublicKey,
			SourceKeyEpoch:   mesh.localKeyEpoch,
			TargetClientID:   target.peer.ClientID,
			TargetClientName: target.peer.ClientName,
			TargetVirtualIP:  target.peer.VirtualIP,
			TargetPublicKey:  target.peer.PublicKey,
			Candidates:       candidates,
			DataFrameVersion: 2,
			CreatedAtMillis:  time.Now().UnixMilli(),
		}
		if target.session != nil {
			sessionID := target.session.ID
			message.SessionID = &sessionID
			message.Token = target.session.Token
			message.ExpiresAt = target.session.ExpiresAt.Format(time.RFC3339Nano)
		}
		if err := sender(conn, target.peer.ClientName, message); err != nil {
			mesh.logger.Printf("Peer Mesh candidates send failed: peer=%s err=%v", target.peer.ClientName, err)
		}
	}
}

func (mesh *peerMeshClient) sendConnectivityChecks(message peerControlMessage) {
	mesh.mu.Lock()
	runtimeID := mesh.runtime.PeerMesh.ClientID
	peerID := message.SourceClientID
	if peerID == runtimeID {
		peerID = message.TargetClientID
	}
	session := mesh.sessions[peerID]
	mesh.mu.Unlock()
	if session == nil {
		return
	}
	// H-3：按 priority 降序排序后再探测，让 host/port-map（高优先级）先命中。
	// H-6：同 NAT 的 reflexive 候选降到最低优先级而非剪除，避免把 hairpin NAT 下可用的
	// srflx 路径永久丢弃；relay 兜底已保留。降权后再交给 priority 排序自然排到末尾。
	candidates := mesh.sortedConnectivityCandidates(message.Candidates)
	delay := time.Duration(0)
	for _, candidate := range candidates {
		if strings.ToLower(candidate.Transport) != "udp" || candidate.Address == "" || candidate.Port <= 0 {
			continue
		}
		if mesh.shouldSkipDirectCandidate(candidate) {
			continue
		}
		mesh.sendProbePaced(session, candidate, delay)
		delay += peerConnectivityCheckPacing
		for _, predictedPort := range mesh.adaptivePredictedPorts(candidate, candidates) {
			predicted := candidate
			predicted.Port = predictedPort
			predicted.Foundation = "adaptive-port-predict"
			mesh.sendProbePaced(session, predicted, delay)
			delay += peerConnectivityCheckPacing
		}
	}
	mesh.scheduleHolePunchRetries(session)
}

func (mesh *peerMeshClient) probeKnownCandidates() {
	mesh.mu.Lock()
	peers := make([]peerMeshPeer, 0, len(mesh.peers))
	for _, peer := range mesh.peers {
		if peer.Online && len(peer.Candidates) > 0 {
			peers = append(peers, *peer)
		}
	}
	mesh.mu.Unlock()
	for _, peer := range peers {
		message := peerControlMessage{SourceClientID: peer.ClientID, Candidates: peer.Candidates}
		mesh.sendConnectivityChecks(message)
	}
}

// scheduleHolePunchRetries 在 session 首次发起连通性检查后按 1s/2s/4s/8s 退避重试，
// 而不是等 15s maintenance tick。已建立健康 direct 路径时自动停止。本轮结束后释放标记，
// 路径后续失效时可以重新进入密集重试。对齐 Java scheduleHolePunchRetries。
func (mesh *peerMeshClient) scheduleHolePunchRetries(session *peerMeshSession) {
	if session == nil {
		return
	}
	sessionID := session.ID
	mesh.mu.Lock()
	if mesh.holePunchRetryScheduled == nil {
		mesh.mu.Unlock()
		return
	}
	if _, scheduled := mesh.holePunchRetryScheduled[sessionID]; scheduled {
		mesh.mu.Unlock()
		return
	}
	mesh.holePunchRetryScheduled[sessionID] = true
	stopCh := mesh.stopCh
	mesh.mu.Unlock()
	if stopCh == nil {
		mesh.mu.Lock()
		delete(mesh.holePunchRetryScheduled, sessionID)
		mesh.mu.Unlock()
		return
	}
	for _, delay := range peerHolePunchRetryDelays {
		delay := delay
		time.AfterFunc(delay, func() {
			select {
			case <-stopCh:
				return
			default:
			}
			mesh.retryHolePunch(sessionID)
		})
	}
	// 本轮结束后释放标记，路径后续失效时可以重新进入密集重试。
	lastDelay := peerHolePunchRetryDelays[len(peerHolePunchRetryDelays)-1]
	time.AfterFunc(lastDelay+time.Second, func() {
		mesh.mu.Lock()
		delete(mesh.holePunchRetryScheduled, sessionID)
		mesh.mu.Unlock()
	})
}

// retryHolePunch 是 H-2 退避重试的实际执行体：重新查找 session，过期或已打通则停止。
func (mesh *peerMeshClient) retryHolePunch(sessionID int64) {
	now := time.Now()
	mesh.mu.Lock()
	session := mesh.sessionsByID[sessionID]
	if session == nil || now.After(session.ExpiresAt) {
		delete(mesh.holePunchRetryScheduled, sessionID)
		mesh.mu.Unlock()
		return
	}
	if session.hasHealthyDirect(now) {
		delete(mesh.holePunchRetryScheduled, sessionID)
		mesh.mu.Unlock()
		return
	}
	peerID := session.PeerID
	peer := mesh.peers[peerID]
	if peer == nil || !peer.Online || len(peer.Candidates) == 0 {
		mesh.mu.Unlock()
		return
	}
	candidates := make([]peerCandidate, len(peer.Candidates))
	copy(candidates, peer.Candidates)
	mesh.mu.Unlock()
	message := peerControlMessage{SourceClientID: peerID, Candidates: candidates}
	mesh.sendConnectivityChecks(message)
}

// reciprocateCandidates 是 H-1 候选回礼：收到对端候选后，若本端尚无健康 direct 路径，
// 立即回发自身候选，把双端打洞窗口从最坏 15s maintenance tick 压到一个信令 RTT 内对齐。
// 带 2s 节流防两端互触发形成信令循环。对齐 Java reciprocateCandidates。
func (mesh *peerMeshClient) reciprocateCandidates(peerID int64) {
	if peerID <= 0 {
		return
	}
	now := time.Now()
	mesh.mu.Lock()
	session := mesh.sessions[peerID]
	if session != nil && session.hasHealthyDirect(now) {
		mesh.mu.Unlock()
		return
	}
	if previous, ok := mesh.candidateReciprocateAt[peerID]; ok && now.Sub(previous) < peerCandidateReciprocateInterval {
		mesh.mu.Unlock()
		return
	}
	mesh.candidateReciprocateAt[peerID] = now
	mesh.mu.Unlock()
	mesh.announceCandidatesToPeer(peerID)
}

// announceCandidatesToPeer 向单个 peer 回发本端候选，是 announceCandidates 的单 peer 版本，
// 供 H-1 候选回礼复用，避免向所有在线 peer 广播。
func (mesh *peerMeshClient) announceCandidatesToPeer(peerID int64) {
	candidates := mesh.gatherCandidates()
	if len(candidates) == 0 {
		return
	}
	mesh.mu.Lock()
	conn := mesh.conn
	sender := mesh.sender
	runtime := mesh.runtime
	if sender == nil {
		mesh.mu.Unlock()
		return
	}
	peer := mesh.peers[peerID]
	if peer == nil || !peer.Online || strings.TrimSpace(peer.ClientName) == "" {
		mesh.mu.Unlock()
		return
	}
	targetPeer := *peer
	session := mesh.reusableSessionLocked(peerID, time.Now())
	mesh.mu.Unlock()
	message := peerControlMessage{
		Type:             peerControlTypeCandidates,
		SourceClientID:   runtime.PeerMesh.ClientID,
		SourceClientName: runtime.PeerMesh.ClientName,
		SourceVirtualIP:  runtime.PeerMesh.VirtualIP,
		SourcePublicKey:  runtime.PeerMesh.ClientPublicKey,
		SourceKeyEpoch:   mesh.localKeyEpoch,
		TargetClientID:   targetPeer.ClientID,
		TargetClientName: targetPeer.ClientName,
		TargetVirtualIP:  targetPeer.VirtualIP,
		TargetPublicKey:  targetPeer.PublicKey,
		Candidates:       candidates,
		DataFrameVersion: 2,
		CreatedAtMillis:  time.Now().UnixMilli(),
	}
	if session != nil {
		sessionID := session.ID
		message.SessionID = &sessionID
		message.Token = session.Token
		message.ExpiresAt = session.ExpiresAt.Format(time.RFC3339Nano)
	}
	if err := sender(conn, targetPeer.ClientName, message); err != nil {
		mesh.logger.Printf("Peer Mesh reciprocated candidates send failed: peer=%s err=%v", targetPeer.ClientName, err)
	}
}

// sortedConnectivityCandidates 先做 H-6 同 NAT reflexive 降权（priority=1），再做 H-3
// priority 降序排序。降权在前保证被降权的候选自然排到末尾，与 Java
// demoteSameNatReflexiveCandidates -> sortedCandidates 的顺序一致。
func (mesh *peerMeshClient) sortedConnectivityCandidates(candidates []peerCandidate) []peerCandidate {
	demoted := mesh.demoteSameNatReflexiveCandidates(candidates)
	sorted := make([]peerCandidate, len(demoted))
	copy(sorted, demoted)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})
	return sorted
}

// demoteSameNatReflexiveCandidates 是 H-6：把与本地 STUN 观测公网地址相同的对端 reflexive
// 候选（srflx 或 port-map）降到 priority=1，而不是从候选集中删除。同 NAT 下 host 未必可达
// （AP 隔离、同 NAT 不同子网），而支持 hairpin 的 NAT 上 srflx 反而能通；直接剪除会把这条
// 可用路径永久丢弃。对齐 Java demoteSameNatReflexiveCandidates。
func (mesh *peerMeshClient) demoteSameNatReflexiveCandidates(candidates []peerCandidate) []peerCandidate {
	if len(candidates) == 0 {
		return candidates
	}
	mesh.mu.Lock()
	localAddresses := make(map[string]struct{})
	if mesh.srflx != nil && mesh.srflx.Address != "" {
		localAddresses[mesh.srflx.Address] = struct{}{}
	}
	for _, candidate := range mesh.srflxCandidates {
		if candidate.Address != "" {
			localAddresses[candidate.Address] = struct{}{}
		}
	}
	mesh.mu.Unlock()
	if len(localAddresses) == 0 {
		return candidates
	}
	demoted := make([]peerCandidate, len(candidates))
	for index, candidate := range candidates {
		if isReflexiveCandidate(candidate) {
			if _, same := localAddresses[candidate.Address]; same {
				candidate.Priority = 1
			}
		}
		demoted[index] = candidate
	}
	return demoted
}

// isReflexiveCandidate 判断候选是否为反射型（srflx 或端口映射），同 NAT 检测只针对这类候选。
func isReflexiveCandidate(candidate peerCandidate) bool {
	if strings.EqualFold(candidate.Type, "srflx") {
		return true
	}
	return strings.HasPrefix(candidate.Foundation, "port-map-")
}

// peerIDFromControl 从控制消息中解析对端 clientId：本端是 source 时取 target，否则取 source。
func (mesh *peerMeshClient) peerIDFromControl(message peerControlMessage) int64 {
	mesh.mu.Lock()
	runtimeID := mesh.runtime.PeerMesh.ClientID
	mesh.mu.Unlock()
	peerID := message.SourceClientID
	if peerID == runtimeID {
		peerID = message.TargetClientID
	}
	return peerID
}

func (mesh *peerMeshClient) keepaliveDirectPaths() {
	now := time.Now()
	type keepalive struct {
		session  *peerMeshSession
		endpoint *net.UDPAddr
	}
	items := make([]keepalive, 0)
	mesh.mu.Lock()
	for _, session := range mesh.sessions {
		if !session.hasHealthyDirect(now) || now.After(session.ExpiresAt) {
			continue
		}
		if since := now.Sub(session.LastDirectKeepalive); !session.LastDirectKeepalive.IsZero() && since < peerDirectKeepaliveInterval {
			continue
		}
		endpoint := session.RemoteEndpoint
		if endpoint == nil {
			continue
		}
		items = append(items, keepalive{session: session, endpoint: endpoint})
	}
	mesh.mu.Unlock()
	for _, item := range items {
		if mesh.isMeshEndpoint(item.endpoint) {
			continue
		}
		if mesh.sendDirectKeepalive(item.session, item.endpoint) {
			mesh.mu.Lock()
			item.session.LastDirectKeepalive = time.Now()
			mesh.mu.Unlock()
		}
	}
}

func (mesh *peerMeshClient) sendProbePaced(session *peerMeshSession, candidate peerCandidate, delay time.Duration) {
	if delay <= 0 {
		mesh.sendProbe(session, candidate)
		return
	}
	sessionID := session.ID
	peerID := session.PeerID
	time.AfterFunc(delay, func() {
		mesh.mu.Lock()
		current := mesh.sessions[peerID]
		running := mesh.udp != nil
		mesh.mu.Unlock()
		if !running || current == nil || current.ID != sessionID || time.Now().After(current.ExpiresAt) {
			return
		}
		mesh.sendProbe(current, candidate)
	})
}

func (mesh *peerMeshClient) sendProbe(session *peerMeshSession, candidate peerCandidate) {
	mesh.mu.Lock()
	udp := mesh.udp
	runtime := mesh.runtime
	mesh.mu.Unlock()
	if udp == nil || session == nil || time.Now().After(session.ExpiresAt) {
		return
	}
	nonce := randomHex(12)
	probe := peerUDPProbe{
		Magic:        peerProbeMagic,
		Type:         peerProbeTypeCheck,
		SessionID:    session.ID,
		FromClientID: runtime.PeerMesh.ClientID,
		ToClientID:   session.PeerID,
		Nonce:        nonce,
		Token:        session.Token,
		SentAtMillis: time.Now().UnixMilli(),
	}
	body, _ := json.Marshal(probe)
	relay := strings.EqualFold(candidate.Type, "relay")
	if !relay && mesh.shouldSkipDirectCandidate(candidate) {
		return
	}
	remoteText := net.JoinHostPort(candidate.Address, fmt.Sprintf("%d", candidate.Port))
	mesh.mu.Lock()
	mesh.pending[nonce] = pendingPeerProbe{SessionID: session.ID, PeerID: session.PeerID, SentAt: time.Now(), Remote: remoteText, Relay: relay, RelayID: candidate.RelayID}
	mesh.mu.Unlock()
	if relay {
		if err := mesh.sendRelayPayload(candidate.RelayID, body); err != nil {
			mesh.mu.Lock()
			delete(mesh.pending, nonce)
			mesh.mu.Unlock()
		}
		return
	}
	addr, err := net.ResolveUDPAddr("udp", remoteText)
	if err != nil {
		return
	}
	if _, err := udp.WriteToUDP(body, addr); err != nil {
		mesh.mu.Lock()
		delete(mesh.pending, nonce)
		mesh.mu.Unlock()
		return
	}
	mesh.scheduleProbeBurst(udp, body, addr, nonce)
}

func (mesh *peerMeshClient) sendDirectKeepalive(session *peerMeshSession, endpoint *net.UDPAddr) bool {
	mesh.mu.Lock()
	udp := mesh.udp
	runtime := mesh.runtime
	mesh.mu.Unlock()
	if udp == nil || session == nil || endpoint == nil || time.Now().After(session.ExpiresAt) {
		return false
	}
	nonce := randomHex(12)
	probe := peerUDPProbe{
		Magic:        peerProbeMagic,
		Type:         peerProbeTypeCheck,
		SessionID:    session.ID,
		FromClientID: runtime.PeerMesh.ClientID,
		ToClientID:   session.PeerID,
		Nonce:        nonce,
		Token:        session.Token,
		SentAtMillis: time.Now().UnixMilli(),
	}
	body, _ := json.Marshal(probe)
	mesh.mu.Lock()
	mesh.pending[nonce] = pendingPeerProbe{SessionID: session.ID, PeerID: session.PeerID, SentAt: time.Now(), Remote: endpoint.String()}
	mesh.mu.Unlock()
	if _, err := udp.WriteToUDP(body, endpoint); err != nil {
		mesh.mu.Lock()
		delete(mesh.pending, nonce)
		mesh.mu.Unlock()
		mesh.logger.Printf("Peer Mesh direct keepalive send failed: session=%d remote=%s err=%v", session.ID, endpoint, err)
		return false
	}
	mesh.scheduleProbeBurst(udp, body, endpoint, nonce)
	return true
}

func (mesh *peerMeshClient) scheduleProbeBurst(udp *net.UDPConn, body []byte, addr *net.UDPAddr, nonce string) {
	if udp == nil || addr == nil || peerProbeBurstCount <= 1 {
		return
	}
	for i := 1; i < peerProbeBurstCount; i++ {
		delay := time.Duration(i) * peerProbeBurstInterval
		time.AfterFunc(delay, func() {
			mesh.mu.Lock()
			_, pending := mesh.pending[nonce]
			running := mesh.stopCh != nil
			mesh.mu.Unlock()
			if !pending || !running {
				return
			}
			_, _ = udp.WriteToUDP(body, addr)
		})
	}
}

func (mesh *peerMeshClient) adaptivePredictedPorts(candidate peerCandidate, allCandidates []peerCandidate) []int {
	if candidate.Port <= 0 || candidate.Port > 65535 || candidate.Address == "" || strings.EqualFold(candidate.Type, "relay") {
		return nil
	}
	deltas := adaptivePortDeltas(candidate, allCandidates)
	if len(deltas) == 0 {
		deltas = mesh.localSrflxPortDeltas()
	}
	if len(deltas) == 0 {
		return nil
	}
	ports := make([]int, 0, peerMaxAdaptivePredictedPorts)
	for _, delta := range deltas {
		if delta <= 0 || delta > peerMaxAdaptivePortDelta {
			continue
		}
		ports = addPredictedPort(ports, candidate.Port+delta, candidate.Port)
		ports = addPredictedPort(ports, candidate.Port-delta, candidate.Port)
		if len(ports) >= peerMaxAdaptivePredictedPorts {
			break
		}
	}
	return ports
}

func adaptivePortDeltas(candidate peerCandidate, allCandidates []peerCandidate) []int {
	if len(allCandidates) == 0 {
		return nil
	}
	seen := make(map[int]struct{})
	ports := make([]int, 0, len(allCandidates))
	for _, item := range allCandidates {
		if item.Address != candidate.Address || item.Port <= 0 || item.Port > 65535 || strings.EqualFold(item.Type, "relay") {
			continue
		}
		if _, ok := seen[item.Port]; ok {
			continue
		}
		seen[item.Port] = struct{}{}
		ports = append(ports, item.Port)
	}
	return deltasFromPorts(ports)
}

func (mesh *peerMeshClient) localSrflxPortDeltas() []int {
	mesh.mu.Lock()
	candidates := make([]peerCandidate, 0, len(mesh.srflxCandidates))
	for _, candidate := range mesh.srflxCandidates {
		candidates = append(candidates, candidate)
	}
	mesh.mu.Unlock()
	seen := make(map[int]struct{})
	ports := make([]int, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Port <= 0 || candidate.Port > 65535 {
			continue
		}
		if _, ok := seen[candidate.Port]; ok {
			continue
		}
		seen[candidate.Port] = struct{}{}
		ports = append(ports, candidate.Port)
	}
	return deltasFromPorts(ports)
}

func deltasFromPorts(ports []int) []int {
	if len(ports) < 2 {
		return nil
	}
	sort.Ints(ports)
	deltas := make([]int, 0, len(ports)-1)
	seen := make(map[int]struct{})
	for i := 1; i < len(ports); i++ {
		delta := ports[i] - ports[i-1]
		if delta <= 0 || delta > peerMaxAdaptivePortDelta {
			continue
		}
		if _, ok := seen[delta]; ok {
			continue
		}
		seen[delta] = struct{}{}
		deltas = append(deltas, delta)
	}
	return deltas
}

func addPredictedPort(ports []int, port, basePort int) []int {
	if port <= 0 || port > 65535 || port == basePort {
		return ports
	}
	for _, existing := range ports {
		if existing == port {
			return ports
		}
	}
	return append(ports, port)
}

func (mesh *peerMeshClient) fallbackStaleDirectPaths() {
	now := time.Now()
	type fallbackPeer struct {
		peer    *peerMeshPeer
		session *peerMeshSession
	}
	var items []fallbackPeer
	mesh.mu.Lock()
	for _, peer := range mesh.peers {
		if peer == nil || !peer.Online {
			continue
		}
		session := mesh.sessions[peer.ClientID]
		if session == nil || now.After(session.ExpiresAt) || !strings.EqualFold(session.PathType, "DIRECT") || session.hasHealthyDirect(now) {
			continue
		}
		session.RemoteEndpoint = nil
		items = append(items, fallbackPeer{peer: peer, session: session})
	}
	mesh.mu.Unlock()
	for _, item := range items {
		mesh.preparePathForPeer(item.peer, item.session)
	}
}

func (mesh *peerMeshClient) gatherCandidates() []peerCandidate {
	mesh.mu.Lock()
	udp := mesh.udp
	runtime := mesh.runtime
	srflx := mesh.srflx
	srflxCandidates := make([]peerCandidate, 0, len(mesh.srflxCandidates))
	for _, candidate := range mesh.srflxCandidates {
		srflxCandidates = append(srflxCandidates, candidate)
	}
	relay := mesh.relay
	portMap := mesh.portMap
	avoidDirect := mesh.shouldAvoidDirectPathLocked()
	mesh.mu.Unlock()
	if udp == nil {
		return nil
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	candidates := make([]peerCandidate, 0, 4)
	if !avoidDirect {
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range ifaces {
				if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
					continue
				}
				addrs, _ := iface.Addrs()
				for _, addr := range addrs {
					ip := ipFromAddr(addr)
					if !usablePeerHostIP(ip, runtime.PeerMesh.CIDR) {
						continue
					}
					family := peerAddressFamily(ip)
					priority := int64(1000)
					if family == "IPv6" {
						priority = 1200
					}
					candidates = append(candidates, peerCandidate{
						Type:          "host",
						Transport:     "udp",
						Address:       ip.String(),
						Port:          port,
						Priority:      priority,
						Foundation:    iface.Name,
						AddressFamily: family,
					})
				}
			}
		}
	}
	if srflx != nil && !avoidDirect {
		candidates = append(candidates, *srflx)
	}
	if !avoidDirect {
		for _, candidate := range srflxCandidates {
			if srflx != nil && candidateEndpointKey(candidate) == candidateEndpointKey(*srflx) {
				continue
			}
			candidates = append(candidates, candidate)
		}
	}
	if portMap != nil {
		candidates = append(candidates, *portMap)
	}
	if relay != nil {
		candidates = append(candidates, *relay)
	}
	return candidates
}

func (mesh *peerMeshClient) tryAcquirePortMappingAsync() {
	mesh.mu.Lock()
	udp := mesh.udp
	if mesh.portMapping != nil {
		mesh.mu.Unlock()
		return
	}
	now := time.Now()
	if !mesh.lastPortMapAttempt.IsZero() && now.Sub(mesh.lastPortMapAttempt) < peerPortMappingRetry {
		mesh.mu.Unlock()
		return
	}
	mesh.lastPortMapAttempt = now
	service := mesh.portMappingService
	mesh.mu.Unlock()
	if udp == nil {
		return
	}
	local, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok || local.Port <= 0 {
		return
	}
	if service == nil {
		service = newNatPortMappingService(mesh.logger)
		mesh.mu.Lock()
		if mesh.portMappingService == nil {
			mesh.portMappingService = service
		}
		mesh.mu.Unlock()
	}
	go mesh.attemptPortMapping(service, local.Port)
}

func (mesh *peerMeshClient) attemptPortMapping(service *natPortMappingService, internalPort int) {
	mapping, err := service.tryAcquireMapping(internalPort, internalPort, peerPortMappingLease, "specus peer mesh")
	if err != nil {
		mesh.logger.Printf("Peer Mesh NAT port mapping failed: %v", err)
		return
	}
	if mapping == nil || mapping.ExternalAddress == "" || mapping.ExternalPort <= 0 {
		return
	}
	candidate := peerCandidate{
		Type:          "srflx",
		Transport:     "udp",
		Address:       mapping.ExternalAddress,
		Port:          mapping.ExternalPort,
		Priority:      900,
		Foundation:    "port-map-" + strings.ToLower(string(mapping.Protocol)),
		AddressFamily: peerAddressFamily(net.ParseIP(mapping.ExternalAddress)),
	}
	mesh.mu.Lock()
	if mesh.udp == nil {
		mesh.mu.Unlock()
		service.releaseMapping(*mapping)
		return
	}
	changed := mesh.portMap == nil || candidateEndpointKey(*mesh.portMap) != candidateEndpointKey(candidate)
	mesh.portMapping = mapping
	mesh.portMap = &candidate
	mesh.mu.Unlock()
	mesh.logger.Printf("Peer Mesh NAT port mapping active: protocol=%s external=%s:%d internal=%d lease=%ds",
		mapping.Protocol, mapping.ExternalAddress, mapping.ExternalPort, mapping.InternalPort, mapping.LeaseSeconds)
	if changed {
		mesh.announceCandidates()
	}
}

func (mesh *peerMeshClient) renewPortMappingIfNeeded() {
	mesh.mu.Lock()
	current := mesh.portMapping
	service := mesh.portMappingService
	mesh.mu.Unlock()
	if current == nil {
		mesh.tryAcquirePortMappingAsync()
		return
	}
	if !current.shouldRenew(time.Now()) {
		return
	}
	if service == nil {
		service = newNatPortMappingService(mesh.logger)
	}
	renewed, err := service.renewMapping(*current, peerPortMappingLease, "specus peer mesh")
	if err != nil || renewed == nil {
		mesh.logger.Printf("Peer Mesh NAT port mapping renew failed, will retry: %v", err)
		mesh.mu.Lock()
		mesh.portMapping = nil
		mesh.portMap = nil
		mesh.lastPortMapAttempt = time.Time{}
		mesh.mu.Unlock()
		return
	}
	mesh.mu.Lock()
	mesh.portMapping = renewed
	if mesh.portMap != nil {
		mesh.portMap.Address = renewed.ExternalAddress
		mesh.portMap.Port = renewed.ExternalPort
	}
	mesh.mu.Unlock()
}

func (mesh *peerMeshClient) requestStunCandidates() {
	endpoint := mesh.stunEndpoint()
	mesh.mu.Lock()
	hasPublicStun := len(mesh.runtime.PeerMesh.PublicStunServers) > 0
	now := time.Now()
	if endpoint == nil && !hasPublicStun {
		mesh.mu.Unlock()
		return
	}
	if !mesh.lastStunRequest.IsZero() &&
		now.Sub(mesh.lastStunRequest) < peerStunRequestInterval {
		mesh.mu.Unlock()
		return
	}
	mesh.lastStunRequest = now
	mesh.mu.Unlock()

	if endpoint != nil {
		mesh.sendStunBinding(endpoint, peerRelayProbePrimary)
	}
	mesh.requestPublicStunBindings()
}

func (mesh *peerMeshClient) requestRelayCandidates() {
	mesh.requestStunCandidates()
	endpoint := mesh.relayEndpoint()
	if endpoint == nil {
		return
	}
	now := time.Now()
	mesh.mu.Lock()
	allocationFresh := mesh.relayID != "" && time.Until(mesh.relayTTL) > time.Minute
	allocationExpiring := mesh.relayID == "" || time.Until(mesh.relayTTL) <= time.Minute
	sessionTTL := mesh.runtime.PeerMesh.SessionTTLSeconds
	if !allocationExpiring && now.Sub(mesh.lastRelayRequest) < time.Minute {
		mesh.mu.Unlock()
		return
	}
	if allocationExpiring && now.Sub(mesh.lastRelayRequest) < 15*time.Second {
		mesh.mu.Unlock()
		return
	}
	mesh.lastRelayRequest = now
	mesh.mu.Unlock()
	if allocationFresh {
		mesh.sendStunRequest(newStunMessage(stunRefreshRequest, newStunTransactionID(),
			stunAttrLifetimeValue(runtimeSessionTTL(sessionTTL))), endpoint)
		return
	}
	mesh.sendStunRequest(newStunMessage(stunAllocateRequest, newStunTransactionID(),
		stunAttrRequestedUDPTransport()), endpoint)
}

func (mesh *peerMeshClient) requestAlternateProbe(role string, alternate *net.UDPAddr, observed *net.UDPAddr) {
	if role != peerRelayProbePrimary || alternate == nil || alternate.Port <= 0 || observed == nil {
		return
	}
	now := time.Now()
	mesh.mu.Lock()
	if now.Sub(mesh.lastAlternateRequest) < 15*time.Second {
		mesh.mu.Unlock()
		return
	}
	mesh.mu.Unlock()
	if alternate.IP == nil || alternate.IP.IsUnspecified() {
		alternate = &net.UDPAddr{IP: observed.IP, Port: alternate.Port}
	}
	if alternate.Port == observed.Port {
		return
	}
	mesh.mu.Lock()
	mesh.lastAlternateRequest = now
	mesh.mu.Unlock()
	mesh.sendStunBinding(alternate, peerRelayProbeAlternate)
}

func (mesh *peerMeshClient) requestPublicStunBindings() {
	mesh.mu.Lock()
	servers := append([]string(nil), mesh.runtime.PeerMesh.PublicStunServers...)
	mesh.removePublicStunCandidatesLocked()
	mesh.mu.Unlock()
	sent := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		endpoint := parseStunServer(server)
		if endpoint == nil {
			continue
		}
		key := endpointKeyUDP(endpoint)
		if _, ok := sent[key]; ok {
			continue
		}
		sent[key] = struct{}{}
		mesh.sendStunBinding(endpoint, publicStunRolePrefix+key)
	}
}

func (mesh *peerMeshClient) removePublicStunCandidatesLocked() {
	for key, candidate := range mesh.srflxCandidates {
		if strings.EqualFold(candidate.Foundation, "public-stun") {
			delete(mesh.srflxCandidates, key)
		}
	}
}

func (mesh *peerMeshClient) sendStunBinding(endpoint *net.UDPAddr, role string) {
	tx := newStunTransactionID()
	request := newStunMessage(
		stunBindingRequest,
		tx,
		stunAttrSoftwareValue("specus-peer-client"))
	mesh.mu.Lock()
	if mesh.pendingStun == nil {
		mesh.pendingStun = make(map[string]pendingStunBinding)
	}
	mesh.pendingStun[stunTransactionHex(tx)] = pendingStunBinding{
		Role:                     role,
		TargetEndpoint:           cloneUDPAddr(endpoint),
		ExpectedResponseEndpoint: cloneUDPAddr(endpoint),
		Request:                  request,
		SentAt:                   time.Now(),
	}
	mesh.mu.Unlock()
	mesh.sendStunRequest(request, endpoint)
}

func (mesh *peerMeshClient) sendBehaviorProbe(probe natBehaviorProbeRequest) {
	if probe.TargetEndpoint == nil || probe.ExpectedResponseEndpoint == nil {
		return
	}
	tx := newStunTransactionID()
	attributes := []stunAttribute{stunAttrSoftwareValue("specus-peer-client")}
	if probe.ChangeIP || probe.ChangePort {
		attributes = append(attributes, stunAttrChangeRequestValue(probe.ChangeIP, probe.ChangePort))
	}
	request := newStunMessage(stunBindingRequest, tx, attributes...)
	pending := pendingStunBinding{
		Role:                     string(probe.Probe),
		TargetEndpoint:           cloneUDPAddr(probe.TargetEndpoint),
		ExpectedResponseEndpoint: cloneUDPAddr(probe.ExpectedResponseEndpoint),
		Request:                  request,
		BehaviorProbe:            probe.Probe,
		BehaviorGeneration:       probe.Generation,
		SentAt:                   time.Now(),
	}
	transactionKey := stunTransactionHex(tx)
	mesh.mu.Lock()
	if mesh.pendingStun == nil || mesh.udp == nil {
		mesh.mu.Unlock()
		return
	}
	mesh.pendingStun[transactionKey] = pending
	stopCh := mesh.stopCh
	mesh.mu.Unlock()
	mesh.sendStunRequest(request, probe.TargetEndpoint)

	go func() {
		started := time.Now()
		for _, retryAt := range []time.Duration{250 * time.Millisecond, 750 * time.Millisecond} {
			if !waitPeerTimer(stopCh, retryAt-time.Since(started)) {
				return
			}
			mesh.retryBehaviorProbe(transactionKey, pending)
		}
		if !waitPeerTimer(stopCh, peerBehaviorProbeTimeout-time.Since(started)) {
			return
		}
		mesh.timeoutBehaviorProbe(transactionKey, pending)
	}()
}

func (mesh *peerMeshClient) retryBehaviorProbe(
	transactionKey string,
	expected pendingStunBinding,
) {
	mesh.mu.Lock()
	current, ok := mesh.pendingStun[transactionKey]
	active := ok &&
		current.BehaviorProbe == expected.BehaviorProbe &&
		current.BehaviorGeneration == expected.BehaviorGeneration
	mesh.mu.Unlock()
	if active {
		mesh.sendStunRequest(expected.Request, expected.TargetEndpoint)
	}
}

func (mesh *peerMeshClient) timeoutBehaviorProbe(
	transactionKey string,
	expected pendingStunBinding,
) {
	mesh.mu.Lock()
	current, ok := mesh.pendingStun[transactionKey]
	if !ok ||
		current.BehaviorProbe != expected.BehaviorProbe ||
		current.BehaviorGeneration != expected.BehaviorGeneration {
		mesh.mu.Unlock()
		return
	}
	delete(mesh.pendingStun, transactionKey)
	discovery := mesh.natBehavior
	mesh.mu.Unlock()
	if discovery != nil {
		mesh.handleNatBehaviorTransition(discovery.timedOut(
			expected.BehaviorGeneration,
			expected.BehaviorProbe))
	}
}

func waitPeerTimer(stopCh <-chan struct{}, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	if stopCh == nil {
		<-timer.C
		return true
	}
	select {
	case <-stopCh:
		return false
	case <-timer.C:
		return true
	}
}

func (mesh *peerMeshClient) sendStunRequest(message stunMessage, endpoint *net.UDPAddr) {
	mesh.sendStunRequestAttempt(message, endpoint, 0)
}

func (mesh *peerMeshClient) sendStunRequestAttempt(message stunMessage, endpoint *net.UDPAddr, authenticationAttempt int) {
	mesh.mu.Lock()
	udp := mesh.udp
	credentials := mesh.turnAuth
	baseAttributes := withoutTurnAuthenticationAttributes(message.Attributes)
	message.Attributes = baseAttributes
	authenticated := turnRequestRequiresAuthentication(message.Type) && credentials.complete()
	tx := stunTransactionHex(message.TransactionID)
	if authenticated {
		if mesh.pendingTurn == nil {
			mesh.pendingTurn = make(map[string]pendingTurnRequest)
		}
		mesh.pendingTurn[tx] = pendingTurnRequest{
			RequestType: message.Type, Attributes: cloneStunAttributes(baseAttributes),
			OriginalTransactionID: message.TransactionID,
			Endpoint:              cloneUDPAddr(endpoint), AuthenticationAttempt: authenticationAttempt, SentAt: time.Now(),
		}
		if channel, ok := message.channelNumber(); ok {
			mesh.pendingTurn[tx] = pendingTurnRequest{
				RequestType: message.Type, Attributes: cloneStunAttributes(baseAttributes),
				OriginalTransactionID: message.TransactionID,
				Endpoint:              cloneUDPAddr(endpoint), Channel: channel,
				AuthenticationAttempt: authenticationAttempt, SentAt: time.Now(),
			}
			if peer, ok := message.xorPeerAddress(); ok {
				pending := mesh.pendingTurn[tx]
				pending.Peer = cloneUDPAddr(peer)
				mesh.pendingTurn[tx] = pending
			}
		}
	}
	mesh.mu.Unlock()
	if udp == nil || endpoint == nil {
		if authenticated {
			mesh.mu.Lock()
			delete(mesh.pendingTurn, tx)
			mesh.mu.Unlock()
		}
		return
	}
	body := message.bytes()
	if authenticated {
		message = authenticatedTurnMessageWithCredentials(message, credentials)
		body = message.bytesWithIntegrity(turnCredentialsIntegrityKey(credentials))
	}
	if _, err := udp.WriteToUDP(body, endpoint); err != nil && authenticated {
		mesh.mu.Lock()
		delete(mesh.pendingTurn, tx)
		mesh.mu.Unlock()
	}
}

func (mesh *peerMeshClient) authenticatedTurnMessage(message stunMessage) stunMessage {
	mesh.mu.Lock()
	credentials := mesh.turnAuth
	if credentials == (turnAuthCredentials{}) {
		credentials = turnAuthCredentialsFrom(mesh.runtime.PeerMesh)
	}
	mesh.mu.Unlock()
	return authenticatedTurnMessageWithCredentials(message, credentials)
}

func authenticatedTurnMessageWithCredentials(message stunMessage, credentials turnAuthCredentials) stunMessage {
	message.Attributes = withoutTurnAuthenticationAttributes(message.Attributes)
	if !credentials.complete() {
		return message
	}
	message.Attributes = append(message.Attributes,
		stunAttrUsernameValue(credentials.Username),
		stunAttrRealmValue(credentials.Realm),
		stunAttrNonceValue(credentials.Nonce))
	return message
}

func turnMessageIntegrityKey(peerMesh PeerMeshConfig) []byte {
	return turnCredentialsIntegrityKey(turnAuthCredentialsFrom(peerMesh))
}

func turnCredentialsIntegrityKey(credentials turnAuthCredentials) []byte {
	if credentials.Username == "" || credentials.Credential == "" || credentials.Realm == "" {
		return nil
	}
	digest := md5.Sum([]byte(credentials.Username + ":" + credentials.Realm + ":" + credentials.Credential))
	return digest[:]
}

func turnRequestRequiresAuthentication(messageType uint16) bool {
	return messageType == stunAllocateRequest || messageType == stunRefreshRequest ||
		messageType == stunCreatePermissionRequest || messageType == stunChannelBindRequest
}

func withoutTurnAuthenticationAttributes(attributes []stunAttribute) []stunAttribute {
	result := make([]stunAttribute, 0, len(attributes))
	for _, attribute := range attributes {
		switch attribute.Type {
		case stunAttrUsername, stunAttrRealm, stunAttrNonce, stunAttrMessageIntegrity:
			continue
		default:
			result = append(result, stunAttribute{Type: attribute.Type, Value: append([]byte(nil), attribute.Value...)})
		}
	}
	return result
}

func cloneStunAttributes(attributes []stunAttribute) []stunAttribute {
	result := make([]stunAttribute, len(attributes))
	for index, attribute := range attributes {
		result[index] = stunAttribute{Type: attribute.Type, Value: append([]byte(nil), attribute.Value...)}
	}
	return result
}

func cloneUDPAddr(value *net.UDPAddr) *net.UDPAddr {
	if value == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), value.IP...), Port: value.Port, Zone: value.Zone}
}

func (mesh *peerMeshClient) sendRelayPayload(targetRelayEndpoint string, payload []byte) error {
	if targetRelayEndpoint == "" {
		return fmt.Errorf("missing relay endpoint")
	}
	endpoint := mesh.relayEndpoint()
	if endpoint == nil {
		return fmt.Errorf("missing relay endpoint")
	}
	peer, err := parseEndpointUDP(targetRelayEndpoint)
	if err != nil {
		return err
	}
	mesh.mu.Lock()
	localRelayID := mesh.relayID
	localRelayTTL := mesh.relayTTL
	mesh.mu.Unlock()
	if localRelayID == "" || time.Now().After(localRelayTTL) {
		return fmt.Errorf("missing relay allocation")
	}
	mesh.ensureTurnPermission(peer)
	if binding := mesh.ensureTurnChannel(peer); binding != nil && binding.Active {
		body, encodeErr := encodeTurnChannelData(binding.Channel, payload)
		if encodeErr != nil {
			return encodeErr
		}
		mesh.mu.Lock()
		udp := mesh.udp
		mesh.mu.Unlock()
		if udp == nil {
			return fmt.Errorf("peer UDP socket is not available")
		}
		_, err = udp.WriteToUDP(body, endpoint)
		return err
	}
	tx := newStunTransactionID()
	mesh.sendStunRequest(newStunMessage(stunSendIndication, tx,
		newStunAttrXorPeerAddress(peer, tx),
		stunAttrDataValue(payload)), endpoint)
	return nil
}

func (mesh *peerMeshClient) ensureTurnChannel(peer *net.UDPAddr) *turnChannelBinding {
	if peer == nil {
		return nil
	}
	endpoint := mesh.relayEndpoint()
	if endpoint == nil {
		return nil
	}
	now := time.Now()
	peerKey := endpointKeyUDP(peer)
	mesh.mu.Lock()
	if mesh.turnChannelsByPeer == nil {
		mesh.turnChannelsByPeer = make(map[string]*turnChannelBinding)
		mesh.turnChannelsByNumber = make(map[uint16]*turnChannelBinding)
		mesh.nextTurnChannel = turnChannelMin
	}
	if existing := mesh.turnChannelsByPeer[peerKey]; existing != nil && existing.ExpiresAt.After(now.Add(30*time.Second)) {
		copy := *existing
		mesh.mu.Unlock()
		return &copy
	}
	channel := mesh.allocateTurnChannelLocked(now)
	if channel == 0 {
		mesh.mu.Unlock()
		return nil
	}
	binding := &turnChannelBinding{Channel: channel, Peer: cloneUDPAddr(peer), ExpiresAt: now.Add(30 * time.Second)}
	mesh.turnChannelsByPeer[peerKey] = binding
	mesh.turnChannelsByNumber[channel] = binding
	mesh.mu.Unlock()
	tx := newStunTransactionID()
	mesh.sendStunRequest(newStunMessage(stunChannelBindRequest, tx,
		stunAttrChannelNumberValue(channel), newStunAttrXorPeerAddress(peer, tx)), endpoint)
	copy := *binding
	return &copy
}

func (mesh *peerMeshClient) allocateTurnChannelLocked(now time.Time) uint16 {
	start := mesh.nextTurnChannel
	if start < turnChannelMin || start > turnChannelMax {
		start = turnChannelMin
	}
	channel := start
	for {
		binding := mesh.turnChannelsByNumber[channel]
		if binding == nil || binding.ExpiresAt.Before(now) {
			mesh.nextTurnChannel = channel + 1
			if mesh.nextTurnChannel > turnChannelMax {
				mesh.nextTurnChannel = turnChannelMin
			}
			return channel
		}
		channel++
		if channel > turnChannelMax {
			channel = turnChannelMin
		}
		if channel == start {
			return 0
		}
	}
}

func (mesh *peerMeshClient) ensureTurnPermission(peer *net.UDPAddr) {
	if peer == nil {
		return
	}
	endpoint := mesh.relayEndpoint()
	if endpoint == nil {
		return
	}
	key := endpointKeyUDP(peer)
	now := time.Now()
	mesh.mu.Lock()
	if mesh.turnPermissions == nil {
		mesh.turnPermissions = make(map[string]time.Time)
	}
	if expires := mesh.turnPermissions[key]; expires.After(now.Add(30 * time.Second)) {
		mesh.mu.Unlock()
		return
	}
	mesh.turnPermissions[key] = now.Add(4 * time.Minute)
	mesh.mu.Unlock()
	tx := newStunTransactionID()
	mesh.sendStunRequest(newStunMessage(stunCreatePermissionRequest, tx,
		newStunAttrXorPeerAddress(peer, tx)), endpoint)
}

func (mesh *peerMeshClient) stunEndpoint() *net.UDPAddr {
	mesh.mu.Lock()
	runtime := mesh.runtime
	mesh.mu.Unlock()
	host := firstNonEmpty(runtime.PeerMesh.StunHost, runtime.PeerMesh.TurnHost)
	port := runtime.PeerMesh.StunPort
	if port <= 0 {
		port = runtime.PeerMesh.TurnPort
	}
	if host == "" || port <= 0 {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		if mesh.logger != nil {
			mesh.logger.Printf("Peer Mesh STUN endpoint resolve failed: %s:%d %v", host, port, err)
		}
		return nil
	}
	return addr
}

func (mesh *peerMeshClient) relayEndpoint() *net.UDPAddr {
	mesh.mu.Lock()
	runtime := mesh.runtime
	mesh.mu.Unlock()
	host := firstNonEmpty(runtime.PeerMesh.TurnHost, runtime.PeerMesh.StunHost)
	port := runtime.PeerMesh.TurnPort
	if port <= 0 {
		port = runtime.PeerMesh.StunPort
	}
	if host == "" || port <= 0 {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		mesh.logger.Printf("Peer Mesh relay endpoint resolve failed: %s:%d %v", host, port, err)
		return nil
	}
	return addr
}

func (mesh *peerMeshClient) reportDevice(conn net.Conn, sender peerControlSender, status, errText, natType, endpoint string) {
	mesh.mu.Lock()
	if conn == nil {
		conn = mesh.conn
	}
	if sender == nil {
		sender = mesh.sender
	}
	runtime := mesh.runtime
	if natType == "" {
		natType = mesh.natType
	}
	if endpoint == "" {
		endpoint = mesh.lastEndpoint
	}
	natMappingBehavior := mesh.natMappingBehavior
	natFilteringBehavior := mesh.natFilteringBehavior
	natBehaviorDiscovery := mesh.natBehaviorDiscovery
	mesh.mu.Unlock()
	if conn == nil || sender == nil || runtime.PeerMesh.ClientID <= 0 {
		return
	}
	message := peerControlMessage{
		Type:                 peerControlTypeDeviceReport,
		SourceClientID:       runtime.PeerMesh.ClientID,
		SourceClientName:     runtime.PeerMesh.ClientName,
		SourceVirtualIP:      runtime.PeerMesh.VirtualIP,
		SourcePublicKey:      runtime.PeerMesh.ClientPublicKey,
		VirtualDeviceMode:    mesh.config.PeerMeshDevice,
		VirtualDeviceName:    mesh.config.PeerMeshTunName,
		VirtualDeviceStatus:  status,
		VirtualDeviceError:   errText,
		NatType:              natType,
		NatMappingBehavior:   natMappingBehavior,
		NatFilteringBehavior: natFilteringBehavior,
		NatBehaviorDiscovery: natBehaviorDiscovery,
		LastEndpoint:         endpoint,
		CreatedAtMillis:      time.Now().UnixMilli(),
	}
	if sendErr := sender(conn, "", message); sendErr != nil {
		mesh.logger.Printf("Peer Mesh device report failed: %v", sendErr)
	}
}

func (mesh *peerMeshClient) reportPath(session *peerMeshSession, pathType, local, remote string, rttMillis int64) {
	mesh.mu.Lock()
	conn := mesh.conn
	sender := mesh.sender
	runtime := mesh.runtime
	peer := mesh.peers[session.PeerID]
	mesh.mu.Unlock()
	if conn == nil || sender == nil {
		return
	}
	message := peerControlMessage{
		Type:             peerControlTypePathReport,
		SessionID:        &session.ID,
		SourceClientID:   runtime.PeerMesh.ClientID,
		SourceClientName: runtime.PeerMesh.ClientName,
		SourceVirtualIP:  runtime.PeerMesh.VirtualIP,
		SourcePublicKey:  runtime.PeerMesh.ClientPublicKey,
		TargetClientID:   session.PeerID,
		TargetClientName: session.PeerName,
		PathType:         pathType,
		Status:           "ACTIVE",
		RTTMillis:        &rttMillis,
		LocalEndpoint:    local,
		RemoteEndpoint:   remote,
		CreatedAtMillis:  time.Now().UnixMilli(),
	}
	if peer != nil {
		message.TargetVirtualIP = peer.VirtualIP
		message.TargetPublicKey = peer.PublicKey
	}
	if err := sender(conn, "", message); err != nil {
		mesh.logger.Printf("Peer Mesh path report failed: %v", err)
	}
}

func (mesh *peerMeshClient) reportTrafficDeltas() {
	type trafficDelta struct {
		SessionID   int64
		PeerID      int64
		PeerName    string
		VirtualIP   string
		PublicKey   string
		DirectBytes int64
	}
	mesh.mu.Lock()
	conn := mesh.conn
	sender := mesh.sender
	runtime := mesh.runtime
	deltas := make([]trafficDelta, 0, len(mesh.sessions))
	for _, session := range mesh.sessions {
		if session.DirectBytesPending == 0 {
			continue
		}
		deltas = append(deltas, trafficDelta{
			SessionID:   session.ID,
			PeerID:      session.PeerID,
			PeerName:    session.PeerName,
			VirtualIP:   session.PeerVirtualIP,
			PublicKey:   session.PeerPublicKey,
			DirectBytes: session.DirectBytesPending,
		})
		session.DirectBytesPending = 0
	}
	mesh.mu.Unlock()
	if conn == nil || sender == nil || runtime.PeerMesh.ClientID <= 0 {
		return
	}
	for _, delta := range deltas {
		message := peerControlMessage{
			Type:             peerControlTypeTrafficReport,
			SessionID:        &delta.SessionID,
			SourceClientID:   runtime.PeerMesh.ClientID,
			SourceClientName: runtime.PeerMesh.ClientName,
			SourceVirtualIP:  runtime.PeerMesh.VirtualIP,
			SourcePublicKey:  runtime.PeerMesh.ClientPublicKey,
			SourceKeyEpoch:   mesh.localKeyEpoch,
			TargetClientID:   delta.PeerID,
			TargetClientName: delta.PeerName,
			TargetVirtualIP:  delta.VirtualIP,
			TargetPublicKey:  delta.PublicKey,
			DirectBytes:      delta.DirectBytes,
			CreatedAtMillis:  time.Now().UnixMilli(),
		}
		if err := sender(conn, "", message); err != nil {
			mesh.logger.Printf("Peer Mesh traffic report failed: session=%d err=%v", delta.SessionID, err)
		}
	}
}

func (mesh *peerMeshClient) cleanupProbes() {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	now := time.Now()
	for nonce, pending := range mesh.pending {
		if now.Sub(pending.SentAt) > 30*time.Second {
			delete(mesh.pending, nonce)
		}
	}
	for tx, pending := range mesh.pendingStun {
		if now.Sub(pending.SentAt) > 30*time.Second {
			delete(mesh.pendingStun, tx)
		}
	}
	for tx, pending := range mesh.pendingTurn {
		if now.Sub(pending.SentAt) > peerPendingTurnRequestTTL {
			mesh.removeFailedTurnChannelLocked(pending)
			delete(mesh.pendingTurn, tx)
		}
	}
	for channel, binding := range mesh.turnChannelsByNumber {
		if binding == nil || !binding.ExpiresAt.After(now) {
			if binding != nil {
				delete(mesh.turnChannelsByPeer, endpointKeyUDP(binding.Peer))
			}
			delete(mesh.turnChannelsByNumber, channel)
		}
	}
	for peerID, session := range mesh.sessions {
		if now.After(session.ExpiresAt) {
			delete(mesh.sessions, peerID)
			delete(mesh.sessionsByID, session.ID)
		}
	}
}

func (mesh *peerMeshClient) localEndpoint() string {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	if mesh.udp == nil {
		return ""
	}
	return mesh.udp.LocalAddr().String()
}

func (mesh *peerMeshClient) deviceStatus() string {
	mesh.mu.Lock()
	device := mesh.device
	mesh.mu.Unlock()
	if device != nil {
		return device.Status()
	}
	if strings.EqualFold(mesh.config.PeerMeshDevice, "noop") {
		return "NOOP"
	}
	return "UDP_READY"
}

func (mesh *peerMeshClient) deviceError() string {
	mesh.mu.Lock()
	device := mesh.device
	mesh.mu.Unlock()
	if device != nil {
		return device.Error()
	}
	if strings.EqualFold(mesh.config.PeerMeshDevice, "noop") {
		return ""
	}
	return fmt.Sprintf("Go client Peer Mesh UDP control plane is active, but %s virtual device is not started", mesh.config.PeerMeshDevice)
}

func (mesh *peerMeshClient) natTypeLocked() string {
	primary := mesh.natByRole[peerRelayProbePrimary]
	alternate := mesh.natByRole[peerRelayProbeAlternate]
	changed := mesh.natByRole[peerRelayProbeChanged]
	if primary != "" && alternate != "" && primary != alternate {
		return peerNatTypeSymmetric
	}
	base := firstNonEmpty(primary, alternate, changed)
	if base == "" {
		return ""
	}
	if mesh.isNoNatLocked(base) {
		return peerNatTypeNoNat
	}
	if primary != "" && alternate != "" {
		if changed != "" {
			return peerNatTypeFullConeOrRestricted
		}
		return peerNatTypePortRestricted
	}
	if primary != "" && changed != "" {
		return peerNatTypeFullConeOrRestricted
	}
	if mesh.isPortPreservedLocked(base) {
		return peerNatTypePortPreserved
	}
	return peerNatTypeNat
}

func (mesh *peerMeshClient) shouldAvoidDirectPath() bool {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	return mesh.shouldAvoidDirectPathLocked()
}

func (mesh *peerMeshClient) shouldAvoidDirectPathLocked() bool {
	return false
}

func (mesh *peerMeshClient) shouldSkipDirectCandidate(candidate peerCandidate) bool {
	if strings.EqualFold(candidate.Type, "relay") {
		return false
	}
	if mesh.shouldAvoidDirectPath() {
		return true
	}
	ip := net.ParseIP(candidate.Address)
	if ip == nil {
		return false
	}
	mesh.mu.Lock()
	cidr := mesh.runtime.PeerMesh.CIDR
	mesh.mu.Unlock()
	return inCIDR(ip, cidr)
}

func (mesh *peerMeshClient) isMeshEndpoint(endpoint *net.UDPAddr) bool {
	if endpoint == nil {
		return false
	}
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	return mesh.isMeshEndpointLocked(endpoint)
}

func (mesh *peerMeshClient) isMeshEndpointLocked(endpoint *net.UDPAddr) bool {
	if endpoint == nil {
		return false
	}
	return inCIDR(endpoint.IP, mesh.runtime.PeerMesh.CIDR)
}

func (mesh *peerMeshClient) isNoNatLocked(endpoint string) bool {
	host, _, ok := splitEndpoint(endpoint)
	if !ok {
		return false
	}
	return mesh.isPortPreservedLocked(endpoint) && isLocalIPv4(host)
}

func (mesh *peerMeshClient) isPortPreservedLocked(endpoint string) bool {
	_, port, ok := splitEndpoint(endpoint)
	if !ok || mesh.udp == nil {
		return false
	}
	local, ok := mesh.udp.LocalAddr().(*net.UDPAddr)
	return ok && local.Port > 0 && local.Port == port
}

func parseStunServer(value string) *net.UDPAddr {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return nil
	}
	normalized = strings.TrimPrefix(normalized, "stun:")
	normalized = strings.TrimPrefix(normalized, "turn:")
	normalized = strings.TrimPrefix(normalized, "//")
	if _, _, ok := splitEndpoint(normalized); !ok {
		normalized = net.JoinHostPort(normalized, "3478")
	}
	addr, err := parseEndpointUDP(normalized)
	if err != nil {
		return nil
	}
	return addr
}

func parseEndpointUDP(value string) (*net.UDPAddr, error) {
	host, port, ok := splitEndpoint(value)
	if !ok {
		return nil, fmt.Errorf("invalid UDP endpoint %q", value)
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}

func endpointKeyUDP(endpoint *net.UDPAddr) string {
	if endpoint == nil {
		return ""
	}
	return net.JoinHostPort(endpoint.IP.String(), fmt.Sprintf("%d", endpoint.Port))
}

func udpAddrEqual(left, right *net.UDPAddr) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Port == right.Port && left.IP.Equal(right.IP)
}

func candidateEndpointKey(candidate peerCandidate) string {
	return strings.ToLower(candidate.Type) + "|" + strings.ToLower(candidate.Transport) + "|" +
		net.JoinHostPort(candidate.Address, fmt.Sprintf("%d", candidate.Port))
}

func smoothPeerRTT(previous, sample int64) int64 {
	if sample < 0 {
		return previous
	}
	if previous <= 0 || previous == peerRttUnsetMillis {
		return sample
	}
	return ((previous * peerRttEWMAOldWeight) + (sample * peerRttEWMANewWeight)) /
		(peerRttEWMAOldWeight + peerRttEWMANewWeight)
}

func runtimeSessionTTL(value int64) int64 {
	if value <= 0 {
		return 300
	}
	return value
}

func splitEndpoint(endpoint string) (string, int, bool) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		host, portText, err = net.SplitHostPort("[" + endpoint + "]")
	}
	if err != nil {
		if index := strings.LastIndex(endpoint, ":"); index > 0 {
			host = endpoint[:index]
			portText = endpoint[index+1:]
		} else {
			return "", 0, false
		}
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil || port <= 0 {
		return "", 0, false
	}
	return host, port, true
}

func isLocalIPv4(host string) bool {
	target := net.ParseIP(host)
	if target == nil {
		return false
	}
	target = target.To4()
	if target == nil {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip := ipFromAddr(addr)
			if ip != nil && ip.To4() != nil && ip.Equal(target) {
				return true
			}
		}
	}
	return false
}

func ipFromAddr(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

func listenPeerUDP() (*net.UDPConn, error) {
	// The generic network lets Go select a dual-stack wildcard socket where the
	// platform supports IPv4-mapped IPv6, and falls back to IPv4 otherwise.
	return net.ListenUDP("udp", &net.UDPAddr{Port: 0})
}

func peerAddressFamily(ip net.IP) string {
	if ip != nil && ip.To4() == nil {
		return "IPv6"
	}
	return "IPv4"
}

func usablePeerHostIP(ip net.IP, meshCIDR string) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || inCIDR(ip, meshCIDR) {
		return false
	}
	if ip.To4() != nil {
		return true
	}
	if len(ip) != net.IPv6len {
		ip = ip.To16()
	}
	if ip == nil {
		return false
	}
	// ULA and IPv4-mapped/compatible addresses are not globally reachable host candidates.
	return ip[0]&0xfe != 0xfc && !isIPv4EmbeddedIPv6(ip)
}

func isIPv4EmbeddedIPv6(ip net.IP) bool {
	value := ip.To16()
	if value == nil {
		return false
	}
	allZero := true
	for _, current := range value[:10] {
		if current != 0 {
			allZero = false
			break
		}
	}
	return allZero && ((value[10] == 0 && value[11] == 0) || (value[10] == 0xff && value[11] == 0xff))
}

func inCIDR(ip net.IP, cidr string) bool {
	if strings.TrimSpace(cidr) == "" {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	return err == nil && network.Contains(ip)
}

func maxInt64(minimum, value int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
