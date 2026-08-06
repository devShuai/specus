package server

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/redis/go-redis/v9"
	"golang.org/x/text/unicode/norm"
)

const (
	clusterEventKindRoster      byte = 1
	clusterEventKindText        byte = 2
	clusterEventKindBinary      byte = 3
	clusterEventKindManagement  byte = 4
	clusterEventFlagExclude     byte = 1
	clusterEventHeaderBytes          = 26
	clusterEventMaxGroupBytes        = 128
	clusterEventMaxIDBytes           = 512
	clusterEventMaxPayloadBytes      = 256 * 1024
	clusterRevisionTTL               = 7 * 24 * time.Hour
)

// Cluster visibility is net-scoped ("merged LAN visibility"): participants behind the
// same public egress address see each other across rooms and token rooms, while
// same-roomKey members stay visible across nets. Presence/members stay keyed by
// groupID; nets:<netID> indexes the groupIDs present on a net, and roster revisions are
// the sum of the group and net counters so they stay monotonic whenever either
// dimension of a recipient's merged roster changes. Aligned with the Java coordination
// service: mixed old/new nodes (or nodes without the nets index and net-scoped
// revisions) corrupt the keyspace, so deploy all cluster nodes together or bump
// RedisKeyPrefix.
var (
	// KEYS: 1=presence:<group>:<member> 2=name:<digest> 3=members:<group>
	//       4=revision:<group> 5=revision:<net> 6=nets:<net>
	// ARGV: 1=peerValue 2=nameValue 3=memberId 4=leaseMs 5=limit 6=presencePrefix(group)
	//       7=revisionTtlMs 8=groupId 9=presenceBasePrefix
	clusterRegisterScript = redis.NewScript(`
local members = redis.call('SMEMBERS', KEYS[3])
local count = 0
for _, member in ipairs(members) do
  if redis.call('EXISTS', ARGV[6] .. member) == 1 then
    count = count + 1
  else
    redis.call('SREM', KEYS[3], member)
  end
end
if redis.call('EXISTS', KEYS[1]) == 1 then return {-1, 0} end
for _, group in ipairs(redis.call('SMEMBERS', KEYS[6])) do
  if redis.call('EXISTS', ARGV[9] .. group .. ':' .. ARGV[3]) == 1 then return {-1, 0} end
end
if redis.call('EXISTS', KEYS[2]) == 1 then return {-2, 0} end
if count >= tonumber(ARGV[5]) then return {-3, 0} end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[4])
redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[4])
redis.call('SADD', KEYS[3], ARGV[3])
redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[4]) * 3)
redis.call('SADD', KEYS[6], ARGV[8])
redis.call('PEXPIRE', KEYS[6], tonumber(ARGV[4]) * 3)
local groupRevision = redis.call('INCR', KEYS[4])
redis.call('PEXPIRE', KEYS[4], ARGV[7])
local netRevision = redis.call('INCR', KEYS[5])
redis.call('PEXPIRE', KEYS[5], ARGV[7])
return {1, groupRevision + netRevision}`)
	// KEYS: 1=presence:<group>:<member> 2=name:<digest> 3=members:<group> 4=nets:<net>
	clusterRefreshScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
redis.call('PEXPIRE', KEYS[1], ARGV[3])
redis.call('PEXPIRE', KEYS[2], ARGV[3])
redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[3]) * 3)
redis.call('PEXPIRE', KEYS[4], tonumber(ARGV[3]) * 3)
return 1`)
	// KEYS: 1=presence:<group>:<member> 2=name:<digest> 3=members:<group>
	//       4=revision:<group> 5=revision:<net> 6=nets:<net>
	// ARGV: 1=peerValue 2=nameValue 3=memberId 4=revisionTtlMs 5=groupId
	clusterUnregisterScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('DEL', KEYS[1])
if redis.call('GET', KEYS[2]) == ARGV[2] then redis.call('DEL', KEYS[2]) end
redis.call('SREM', KEYS[3], ARGV[3])
if redis.call('SCARD', KEYS[3]) == 0 then redis.call('SREM', KEYS[6], ARGV[5]) end
local groupRevision = redis.call('INCR', KEYS[4])
redis.call('PEXPIRE', KEYS[4], ARGV[4])
local netRevision = redis.call('INCR', KEYS[5])
redis.call('PEXPIRE', KEYS[5], ARGV[4])
return groupRevision + netRevision`)
	// KEYS: 1=members:<group> 2=revision:<group> 3=revision:<net> 4=nets:<net>
	// ARGV: 1=presencePrefix(group) 2=revisionTtlMs 3=groupId
	clusterCleanupScript = redis.NewScript(`
local removed = 0
local members = redis.call('SMEMBERS', KEYS[1])
for _, member in ipairs(members) do
  if redis.call('EXISTS', ARGV[1] .. member) == 0 then
    redis.call('SREM', KEYS[1], member)
    removed = removed + 1
  end
end
if redis.call('SCARD', KEYS[1]) == 0 then redis.call('SREM', KEYS[4], ARGV[3]) end
local groupRevision = tonumber(redis.call('GET', KEYS[2]) or '0')
local netRevision = tonumber(redis.call('GET', KEYS[3]) or '0')
if removed > 0 then
  groupRevision = redis.call('INCR', KEYS[2])
  redis.call('PEXPIRE', KEYS[2], ARGV[2])
  netRevision = redis.call('INCR', KEYS[3])
  redis.call('PEXPIRE', KEYS[3], ARGV[2])
end
return {removed, groupRevision + netRevision}`)
	clusterRateScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
if count > tonumber(ARGV[1]) then return 0 end
return 1`)
)

type publicTransferClusterEvent struct {
	kind          byte
	excludeSource bool
	revision      uint64
	groupID       string
	targetPeerID  string
	sourceLeaseID string
	payload       []byte
}

type clusterParticipant struct {
	LeaseID       string `json:"leaseId"`
	PeerID        string `json:"peerId"`
	DisplayName   string `json:"displayName"`
	RoomID        string `json:"roomId"`
	PublicAddress string `json:"publicAddress"`
	RoomKey       string `json:"roomKey"`
	RoomRole      string `json:"roomRole"`
	SharedRoom    bool   `json:"sharedRoom"`
	ConnectedAt   string `json:"connectedAt"`
}

func (p clusterParticipant) groupID() string {
	return publicTransferGroupID(p.RoomID, p.RoomKey)
}

func (p clusterParticipant) netID() string {
	return publicTransferNetID(p.PublicAddress)
}

type clusterRegistration struct {
	err      string
	revision uint64
}

type clusterRoster struct {
	revision     uint64
	participants []clusterParticipant
}

type publicTransferCoordination struct {
	cfg       config.PublicTransferConfig
	logger    *slog.Logger
	client    *redis.Client
	pubsub    *redis.PubSub
	cancel    context.CancelFunc
	closeOnce sync.Once
	listenerM sync.RWMutex
	listeners []func(publicTransferClusterEvent)
}

func newPublicTransferCoordination(cfg config.PublicTransferConfig, logger *slog.Logger) (*publicTransferCoordination, error) {
	coordination := &publicTransferCoordination{cfg: cfg, logger: logger}
	if !cfg.ClusterEnabled {
		return coordination, nil
	}
	if strings.TrimSpace(cfg.RedisURI) == "" {
		return nil, errors.New("public transfer Redis URI is required in cluster mode")
	}
	options, err := redis.ParseURL(strings.TrimSpace(cfg.RedisURI))
	if err != nil {
		return nil, fmt.Errorf("parse public transfer Redis URI: %w", err)
	}
	timeout := coordination.commandTimeout()
	options.DialTimeout = timeout
	options.ReadTimeout = timeout
	options.WriteTimeout = timeout
	coordination.client = redis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := coordination.client.Ping(ctx).Err(); err != nil {
		_ = coordination.client.Close()
		return nil, fmt.Errorf("connect public transfer Redis: %w", err)
	}
	coordination.pubsub = coordination.client.Subscribe(ctx, coordination.eventChannel())
	if _, err := coordination.pubsub.Receive(ctx); err != nil {
		_ = coordination.pubsub.Close()
		_ = coordination.client.Close()
		return nil, fmt.Errorf("subscribe public transfer Redis channel: %w", err)
	}
	eventContext, eventCancel := context.WithCancel(context.Background())
	coordination.cancel = eventCancel
	go coordination.consumeEvents(eventContext)
	logger.Info("public transfer Redis coordination enabled", "prefix", coordination.keyPrefix())
	return coordination, nil
}

func (c *publicTransferCoordination) enabled() bool {
	return c != nil && c.cfg.ClusterEnabled
}

func (c *publicTransferCoordination) setListener(listener func(publicTransferClusterEvent)) {
	c.addListener(listener)
}

func (c *publicTransferCoordination) addListener(listener func(publicTransferClusterEvent)) {
	if listener == nil {
		return
	}
	c.listenerM.Lock()
	c.listeners = append(c.listeners, listener)
	c.listenerM.Unlock()
}

func (c *publicTransferCoordination) register(ctx context.Context, participant clusterParticipant, configuredLimit int) (clusterRegistration, error) {
	memberID := digestString(participant.PeerID)
	groupID := participant.groupID()
	netID := participant.netID()
	peerValue, err := encodeClusterParticipant(participant)
	if err != nil {
		return clusterRegistration{}, err
	}
	nameValue := participant.LeaseID + "\n" + participant.PeerID
	result, err := c.run(ctx, clusterRegisterScript, []string{
		c.presenceKey(groupID, memberID), c.nameKey(participant.DisplayName),
		c.membersKey(groupID), c.revisionKey(groupID), c.revisionKey(netID), c.netsKey(netID),
	}, peerValue, nameValue, memberID, c.lease().Milliseconds(), maxInt(1, configuredLimit),
		c.presencePrefix(groupID), clusterRevisionTTL.Milliseconds(), groupID, c.presenceBasePrefix())
	if err != nil {
		return clusterRegistration{}, err
	}
	values, ok := result.([]any)
	if !ok || len(values) != 2 {
		return clusterRegistration{}, errors.New("invalid public transfer registration result")
	}
	code, ok := redisInt64(values[0])
	if !ok {
		return clusterRegistration{}, errors.New("invalid public transfer registration code")
	}
	revision, _ := redisInt64(values[1])
	switch code {
	case 1:
		return clusterRegistration{revision: uint64(revision)}, nil
	case -1:
		return clusterRegistration{err: duplicateDiscoveryPeerError}, nil
	case -2:
		return clusterRegistration{err: "client name is already in use"}, nil
	case -3:
		return clusterRegistration{err: "room is full"}, nil
	default:
		return clusterRegistration{}, errors.New("unexpected public transfer registration result")
	}
}

func (c *publicTransferCoordination) refresh(ctx context.Context, participant clusterParticipant) (bool, error) {
	memberID := digestString(participant.PeerID)
	groupID := participant.groupID()
	peerValue, err := encodeClusterParticipant(participant)
	if err != nil {
		return false, err
	}
	result, err := c.run(ctx, clusterRefreshScript, []string{
		c.presenceKey(groupID, memberID), c.nameKey(participant.DisplayName), c.membersKey(groupID),
		c.netsKey(participant.netID()),
	}, peerValue, participant.LeaseID+"\n"+participant.PeerID, c.lease().Milliseconds())
	if err != nil {
		return false, err
	}
	value, ok := redisInt64(result)
	return ok && value == 1, nil
}

func (c *publicTransferCoordination) unregister(ctx context.Context, participant clusterParticipant) (uint64, error) {
	memberID := digestString(participant.PeerID)
	groupID := participant.groupID()
	peerValue, err := encodeClusterParticipant(participant)
	if err != nil {
		return 0, err
	}
	result, err := c.run(ctx, clusterUnregisterScript, []string{
		c.presenceKey(groupID, memberID), c.nameKey(participant.DisplayName),
		c.membersKey(groupID), c.revisionKey(groupID), c.revisionKey(participant.netID()),
		c.netsKey(participant.netID()),
	}, peerValue, participant.LeaseID+"\n"+participant.PeerID, memberID,
		clusterRevisionTTL.Milliseconds(), groupID)
	if err != nil {
		return 0, err
	}
	value, _ := redisInt64(result)
	return uint64(value), nil
}

// roster reads the merged roster for recipient: everyone in the recipient's token room
// plus everyone on the recipient's network (same public egress address, regardless of
// roomID), deduplicated by peerID. The returned revision is the sum of the group and
// net revision counters, so it increases monotonically whenever either dimension
// changes.
func (c *publicTransferCoordination) roster(ctx context.Context, recipient clusterParticipant) (clusterRoster, error) {
	groupID := recipient.groupID()
	netID := recipient.netID()
	groups, err := c.netGroups(ctx, netID, groupID)
	if err != nil {
		return clusterRoster{}, err
	}
	// Hygiene pass: prune stale members of the own group and of every group on the net
	// (also drops emptied groups from the nets index and bumps both revision counters so
	// presence expiries surface to merged-roster recipients in a timely manner).
	removedAny := false
	var cleanupRevision uint64
	for _, group := range groups {
		removed, revision, err := c.cleanup(ctx, group, netID)
		if err != nil {
			return clusterRoster{}, err
		}
		if removed > 0 {
			removedAny = true
			cleanupRevision = revision
		}
	}
	if removedAny {
		_ = c.publishRoster(ctx, groupID, cleanupRevision)
		_ = c.publishRoster(ctx, netID, cleanupRevision)
	}
	for attempt := 0; attempt < 2; attempt++ {
		beforeGroup, err := c.revision(ctx, groupID)
		if err != nil {
			return clusterRoster{}, err
		}
		beforeNet, err := c.revision(ctx, netID)
		if err != nil {
			return clusterRoster{}, err
		}
		groups, err := c.netGroups(ctx, netID, groupID)
		if err != nil {
			return clusterRoster{}, err
		}
		participants, err := c.readMergedParticipants(ctx, recipient, groups)
		if err != nil {
			return clusterRoster{}, err
		}
		afterGroup, err := c.revision(ctx, groupID)
		if err != nil {
			return clusterRoster{}, err
		}
		afterNet, err := c.revision(ctx, netID)
		if err != nil {
			return clusterRoster{}, err
		}
		if attempt == 1 || beforeGroup == afterGroup && beforeNet == afterNet {
			sort.Slice(participants, func(i, j int) bool {
				return participants[i].ConnectedAt < participants[j].ConnectedAt
			})
			return clusterRoster{revision: afterGroup + afterNet, participants: participants}, nil
		}
	}
	return clusterRoster{}, errors.New("could not read stable public transfer roster")
}

// findPeer locates a visible peer by peerID within the recipient's merged visibility
// domain (same room or same network). Directed messages are routed to the resolved
// target's group; a nil result means the target is not visible to the recipient.
func (c *publicTransferCoordination) findPeer(ctx context.Context, recipient clusterParticipant, peerID string) (*clusterParticipant, error) {
	if strings.TrimSpace(peerID) == "" {
		return nil, nil
	}
	groups, err := c.netGroups(ctx, recipient.netID(), recipient.groupID())
	if err != nil {
		return nil, err
	}
	participants, err := c.readMergedParticipants(ctx, recipient, groups)
	if err != nil {
		return nil, err
	}
	for _, participant := range participants {
		if participant.PeerID == peerID {
			resolved := participant
			return &resolved, nil
		}
	}
	return nil, nil
}

// netGroups lists the groups readable for one net: every group indexed under
// nets:<netID>, plus groupID itself (a group always spans the nets of its members even
// when the nets index entry aged out).
func (c *publicTransferCoordination) netGroups(ctx context.Context, netID, groupID string) ([]string, error) {
	groups, err := c.client.SMembers(ctx, c.netsKey(netID)).Result()
	if err != nil {
		return nil, c.wrap(err)
	}
	result := make([]string, 0, len(groups)+1)
	seen := make(map[string]struct{}, len(groups)+1)
	for _, group := range groups {
		if _, ok := seen[group]; !ok {
			seen[group] = struct{}{}
			result = append(result, group)
		}
	}
	if _, ok := seen[groupID]; !ok {
		result = append(result, groupID)
	}
	return result, nil
}

// readMergedParticipants unions the live presence of the given groups and keeps only
// records visible to recipient: same group (same roomID and roomKey) or same net (same
// public egress address, regardless of roomID; the empty/"unknown" fallback address
// never matches). The presence JSON carries roomKey/publicAddress, so visibility is
// re-checked in memory rather than trusting the members sets (a group's members can
// span nets).
func (c *publicTransferCoordination) readMergedParticipants(ctx context.Context, recipient clusterParticipant,
	groups []string) ([]clusterParticipant, error) {
	participants := make([]clusterParticipant, 0)
	seen := make(map[string]struct{})
	for _, groupID := range groups {
		members, err := c.client.SMembers(ctx, c.membersKey(groupID)).Result()
		if err != nil {
			return nil, c.wrap(err)
		}
		if len(members) == 0 {
			continue
		}
		keys := make([]string, 0, len(members))
		for _, member := range members {
			keys = append(keys, c.presenceKey(groupID, member))
		}
		values, err := c.client.MGet(ctx, keys...).Result()
		if err != nil {
			return nil, c.wrap(err)
		}
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				continue
			}
			participant, ok := decodeClusterParticipant(text)
			if !ok || participant.groupID() != groupID {
				continue
			}
			visible := participant.RoomID == recipient.RoomID && participant.RoomKey == recipient.RoomKey ||
				publicAddressKnown(participant.PublicAddress) && participant.PublicAddress == recipient.PublicAddress
			if !visible {
				continue
			}
			if _, dup := seen[participant.PeerID]; dup {
				continue
			}
			seen[participant.PeerID] = struct{}{}
			participants = append(participants, participant)
		}
	}
	return participants, nil
}

func (c *publicTransferCoordination) sweep(ctx context.Context, groupID, netID string) error {
	removed, revision, err := c.cleanup(ctx, groupID, netID)
	if err != nil {
		return err
	}
	if removed > 0 {
		if err := c.publishRoster(ctx, groupID, revision); err != nil {
			return err
		}
		return c.publishRoster(ctx, netID, revision)
	}
	return nil
}

func (c *publicTransferCoordination) isClientNameAvailable(ctx context.Context, displayName,
	excludePeerID string) (bool, error) {
	owner, err := c.client.Get(ctx, c.nameKey(displayName)).Result()
	if errors.Is(err, redis.Nil) {
		return true, nil
	}
	if err != nil {
		return false, c.wrap(err)
	}
	separator := strings.IndexByte(owner, '\n')
	peerID := ""
	if separator >= 0 {
		peerID = owner[separator+1:]
	}
	return strings.TrimSpace(excludePeerID) != "" && peerID == strings.TrimSpace(excludePeerID), nil
}

func (c *publicTransferCoordination) allowRate(ctx context.Context, bucket, identity string, limit int, window time.Duration) (bool, error) {
	result, err := c.run(ctx, clusterRateScript,
		[]string{c.rateKey(bucket, identity)}, maxInt(1, limit), maxDuration(time.Second, window).Milliseconds())
	if err != nil {
		return false, err
	}
	value, ok := redisInt64(result)
	return ok && value == 1, nil
}

func (c *publicTransferCoordination) publishRoster(ctx context.Context, groupID string, revision uint64) error {
	return c.publish(ctx, publicTransferClusterEvent{kind: clusterEventKindRoster, revision: revision, groupID: groupID})
}

func (c *publicTransferCoordination) publishText(ctx context.Context, groupID, targetPeerID, sourceLeaseID string, excludeSource bool, payload []byte) error {
	return c.publish(ctx, publicTransferClusterEvent{kind: clusterEventKindText, excludeSource: excludeSource,
		groupID: groupID, targetPeerID: targetPeerID, sourceLeaseID: sourceLeaseID, payload: payload})
}

func (c *publicTransferCoordination) publishBinary(ctx context.Context, groupID, targetPeerID string, payload []byte) error {
	return c.publish(ctx, publicTransferClusterEvent{kind: clusterEventKindBinary,
		groupID: groupID, targetPeerID: targetPeerID, payload: payload})
}

func (c *publicTransferCoordination) publishManagement(ctx context.Context, tenantID string, payload []byte) error {
	return c.publish(ctx, publicTransferClusterEvent{kind: clusterEventKindManagement,
		groupID: managementGroupID(tenantID), payload: payload})
}

func managementGroupID(tenantID string) string {
	return digestString(strings.TrimSpace(tenantID))
}

func (c *publicTransferCoordination) publish(ctx context.Context, event publicTransferClusterEvent) error {
	encoded, err := encodePublicTransferClusterEvent(event)
	if err != nil {
		return err
	}
	if err := c.client.Publish(ctx, c.eventChannel(), encoded).Err(); err != nil {
		return c.wrap(err)
	}
	return nil
}

// cleanup removes expired members of one group and prunes the nets index entry when the
// group empties. It returns the summed group+net revision (bumped when anything was
// removed) so callers can fan a roster publish out to both audiences.
func (c *publicTransferCoordination) cleanup(ctx context.Context, groupID, netID string) (int64, uint64, error) {
	result, err := c.run(ctx, clusterCleanupScript,
		[]string{c.membersKey(groupID), c.revisionKey(groupID), c.revisionKey(netID), c.netsKey(netID)},
		c.presencePrefix(groupID), clusterRevisionTTL.Milliseconds(), groupID)
	if err != nil {
		return 0, 0, err
	}
	values, ok := result.([]any)
	if !ok || len(values) != 2 {
		return 0, 0, errors.New("invalid public transfer cleanup result")
	}
	removed, ok := redisInt64(values[0])
	if !ok {
		return 0, 0, errors.New("invalid public transfer cleanup count")
	}
	revision, _ := redisInt64(values[1])
	return removed, uint64(revision), nil
}

func (c *publicTransferCoordination) revision(ctx context.Context, id string) (uint64, error) {
	value, err := c.client.Get(ctx, c.revisionKey(id)).Result()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, c.wrap(err)
	}
	var revision uint64
	if _, err := fmt.Sscan(value, &revision); err != nil {
		return 0, fmt.Errorf("invalid public transfer room revision: %w", err)
	}
	return revision, nil
}

func (c *publicTransferCoordination) run(ctx context.Context, script *redis.Script, keys []string, args ...any) (any, error) {
	result, err := script.Run(ctx, c.client, keys, args...).Result()
	if err != nil {
		return nil, c.wrap(err)
	}
	return result, nil
}

func (c *publicTransferCoordination) consumeEvents(ctx context.Context) {
	channel := c.pubsub.Channel(redis.WithChannelSize(4096))
	for {
		select {
		case <-ctx.Done():
			return
		case message, ok := <-channel:
			if !ok {
				return
			}
			event, err := decodePublicTransferClusterEvent([]byte(message.Payload))
			if err != nil {
				c.logger.Warn("discarding invalid public transfer cluster event", "err", err)
				continue
			}
			c.listenerM.RLock()
			listeners := append([]func(publicTransferClusterEvent){}, c.listeners...)
			c.listenerM.RUnlock()
			for _, listener := range listeners {
				listener(event)
			}
		}
	}
}

func (c *publicTransferCoordination) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		if c.pubsub != nil {
			if err := c.pubsub.Close(); err != nil {
				closeErr = err
			}
		}
		if c.client != nil {
			if err := c.client.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	})
	return closeErr
}

// keyPrefix namespaces every public-transfer key. The net-merged visibility indexes
// (nets:<netID>, net-scoped revisions and routing) are incompatible with pre-merge
// nodes: a mixed cluster reads and routes rosters inconsistently, so all nodes must
// deploy together or RedisKeyPrefix must be bumped to force a clean keyspace.
func (c *publicTransferCoordination) keyPrefix() string {
	value := strings.TrimRight(strings.TrimSpace(c.cfg.RedisKeyPrefix), ":")
	if value == "" {
		return "specus:v2:public-transfer"
	}
	return value
}

func (c *publicTransferCoordination) eventChannel() string { return c.keyPrefix() + ":events" }
func (c *publicTransferCoordination) presenceBasePrefix() string {
	return c.keyPrefix() + ":presence:"
}
func (c *publicTransferCoordination) presencePrefix(groupID string) string {
	return c.presenceBasePrefix() + groupID + ":"
}
func (c *publicTransferCoordination) presenceKey(groupID, memberID string) string {
	return c.presencePrefix(groupID) + memberID
}
func (c *publicTransferCoordination) membersKey(groupID string) string {
	return c.keyPrefix() + ":members:" + groupID
}
func (c *publicTransferCoordination) netsKey(netID string) string {
	return c.keyPrefix() + ":nets:" + netID
}
func (c *publicTransferCoordination) revisionKey(id string) string {
	return c.keyPrefix() + ":revision:" + id
}
func (c *publicTransferCoordination) nameKey(displayName string) string {
	normalized := strings.ToLower(norm.NFC.String(strings.TrimSpace(displayName)))
	return c.keyPrefix() + ":name:" + digestString(normalized)
}
func (c *publicTransferCoordination) rateKey(bucket, identity string) string {
	return c.keyPrefix() + ":rate:" + digestString(bucket+"\x00"+identity)
}
func (c *publicTransferCoordination) lease() time.Duration {
	return time.Duration(maxInt64(5, c.cfg.PresenceLeaseSeconds)) * time.Second
}
func (c *publicTransferCoordination) commandTimeout() time.Duration {
	return time.Duration(maxInt64(100, c.cfg.RedisCommandTimeoutMs)) * time.Millisecond
}
func (c *publicTransferCoordination) wrap(err error) error {
	return fmt.Errorf("public transfer Redis coordination unavailable: %w", err)
}

func publicTransferGroupID(roomID, roomKey string) string {
	return digestString(roomID + "\x00" + roomKey)
}

// publicTransferNetID scopes the merged LAN visibility: everyone behind the same public
// egress address, regardless of roomID. It travels in the opaque groupID field of STCE
// events.
func publicTransferNetID(publicAddress string) string {
	return digestString(publicAddress)
}

func encodeClusterParticipant(participant clusterParticipant) (string, error) {
	encoded, err := json.Marshal(participant)
	if err != nil {
		return "", fmt.Errorf("encode public transfer participant: %w", err)
	}
	return participant.LeaseID + "\n" + string(encoded), nil
}

func decodeClusterParticipant(encoded string) (clusterParticipant, bool) {
	separator := strings.IndexByte(encoded, '\n')
	if separator <= 0 {
		return clusterParticipant{}, false
	}
	var participant clusterParticipant
	if json.Unmarshal([]byte(encoded[separator+1:]), &participant) != nil ||
		encoded[:separator] != participant.LeaseID {
		return clusterParticipant{}, false
	}
	return participant, true
}

func encodePublicTransferClusterEvent(event publicTransferClusterEvent) ([]byte, error) {
	group := []byte(event.groupID)
	target := []byte(event.targetPeerID)
	sourceLease := []byte(event.sourceLeaseID)
	if event.kind < clusterEventKindRoster || event.kind > clusterEventKindManagement {
		return nil, errors.New("unsupported cluster event kind")
	}
	if len(group) == 0 || len(group) > clusterEventMaxGroupBytes || !utf8.Valid(group) {
		return nil, errors.New("invalid cluster event group")
	}
	if len(target) > clusterEventMaxIDBytes || !utf8.Valid(target) ||
		len(sourceLease) > clusterEventMaxIDBytes || !utf8.Valid(sourceLease) {
		return nil, errors.New("invalid cluster event identity")
	}
	if len(event.payload) > clusterEventMaxPayloadBytes {
		return nil, errors.New("cluster event payload is too large")
	}
	if event.kind == clusterEventKindRoster && len(event.payload) != 0 {
		return nil, errors.New("roster event payload must be empty")
	}
	if event.kind == clusterEventKindBinary && len(target) == 0 {
		return nil, errors.New("binary event target is required")
	}
	if event.kind == clusterEventKindManagement && (len(event.payload) == 0 || len(target) != 0 ||
		len(sourceLease) != 0 || event.revision != 0 || event.excludeSource) {
		return nil, errors.New("management event shape is invalid")
	}
	result := make([]byte, clusterEventHeaderBytes+len(group)+len(target)+len(sourceLease)+len(event.payload))
	copy(result[:4], "STCE")
	result[4] = 2
	result[5] = event.kind
	if event.excludeSource {
		result[6] = clusterEventFlagExclude
	}
	binary.BigEndian.PutUint64(result[8:16], event.revision)
	binary.BigEndian.PutUint16(result[16:18], uint16(len(group)))
	binary.BigEndian.PutUint16(result[18:20], uint16(len(target)))
	binary.BigEndian.PutUint16(result[20:22], uint16(len(sourceLease)))
	binary.BigEndian.PutUint32(result[22:26], uint32(len(event.payload)))
	offset := clusterEventHeaderBytes
	offset += copy(result[offset:], group)
	offset += copy(result[offset:], target)
	offset += copy(result[offset:], sourceLease)
	copy(result[offset:], event.payload)
	return result, nil
}

func decodePublicTransferClusterEvent(encoded []byte) (publicTransferClusterEvent, error) {
	if len(encoded) < clusterEventHeaderBytes || string(encoded[:4]) != "STCE" || encoded[4] != 2 {
		return publicTransferClusterEvent{}, errors.New("unsupported or truncated cluster event")
	}
	kind := encoded[5]
	flags := encoded[6]
	if kind < clusterEventKindRoster || kind > clusterEventKindManagement ||
		flags&^clusterEventFlagExclude != 0 || encoded[7] != 0 {
		return publicTransferClusterEvent{}, errors.New("invalid cluster event header")
	}
	groupLength := int(binary.BigEndian.Uint16(encoded[16:18]))
	targetLength := int(binary.BigEndian.Uint16(encoded[18:20]))
	sourceLength := int(binary.BigEndian.Uint16(encoded[20:22]))
	payloadLength := int(binary.BigEndian.Uint32(encoded[22:26]))
	if groupLength == 0 || groupLength > clusterEventMaxGroupBytes ||
		targetLength > clusterEventMaxIDBytes || sourceLength > clusterEventMaxIDBytes ||
		payloadLength > clusterEventMaxPayloadBytes ||
		clusterEventHeaderBytes+groupLength+targetLength+sourceLength+payloadLength != len(encoded) {
		return publicTransferClusterEvent{}, errors.New("cluster event length mismatch")
	}
	offset := clusterEventHeaderBytes
	group := encoded[offset : offset+groupLength]
	offset += groupLength
	target := encoded[offset : offset+targetLength]
	offset += targetLength
	source := encoded[offset : offset+sourceLength]
	offset += sourceLength
	if !utf8.Valid(group) || !utf8.Valid(target) || !utf8.Valid(source) {
		return publicTransferClusterEvent{}, errors.New("cluster event contains invalid UTF-8")
	}
	payload := append([]byte(nil), encoded[offset:]...)
	if kind == clusterEventKindRoster && len(payload) != 0 {
		return publicTransferClusterEvent{}, errors.New("roster event payload must be empty")
	}
	if kind == clusterEventKindBinary && len(target) == 0 {
		return publicTransferClusterEvent{}, errors.New("binary event target is required")
	}
	revision := binary.BigEndian.Uint64(encoded[8:16])
	if kind == clusterEventKindManagement && (len(payload) == 0 || len(target) != 0 ||
		len(source) != 0 || revision != 0 || flags&clusterEventFlagExclude != 0) {
		return publicTransferClusterEvent{}, errors.New("management event shape is invalid")
	}
	return publicTransferClusterEvent{
		kind: kind, excludeSource: flags&clusterEventFlagExclude != 0,
		revision: revision, groupID: string(group),
		targetPeerID: string(target), sourceLeaseID: string(source), payload: payload,
	}, nil
}

func redisInt64(value any) (int64, bool) {
	switch item := value.(type) {
	case int64:
		return item, true
	case uint64:
		return int64(item), true
	case string:
		var parsed int64
		_, err := fmt.Sscan(item, &parsed)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}
