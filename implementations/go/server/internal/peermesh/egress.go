package peermesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/peeregress"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Egress authorization: storage-backed policy, management mutations and the payloads pushed to
// clients. Kept in its own file because it answers a different question from the mesh ACL: that one
// decides whether two devices may see each other, this one decides whether one of them may be used
// as a way out to the wider network. Effective permission is the intersection.

// Control message types defined by protocol/spec/peer-egress.md.
const (
	ControlTypeEgressConfig  = "egress-config"
	ControlTypeEgressCatalog = "egress-catalog"
	ControlTypeEgressReport  = "egress-report"
)

// MaxEgressDestinationRules caps a stored allowlist; enforced before persisting.
const MaxEgressDestinationRules = 64

// MaxEgressDestinationRulesBytes matches the column width in every schema dialect.
const MaxEgressDestinationRulesBytes = 4096

// egressRevisions is bumped on every push so a client can ignore a snapshot it has already applied.
var egressRevisions atomic.Int64

// EgressCatalogEntry is one entry of egress-catalog.
//
// The catalogue deliberately omits the egress node's destination allowlist. A consumer does not
// need it to route, and shipping it would hand every peer a map of that node's reachable network.
type EgressCatalogEntry struct {
	ClientID            int64    `json:"clientId"`
	ClientName          string   `json:"clientName"`
	Online              bool     `json:"online"`
	Scope               string   `json:"scope"`
	Protocols           []string `json:"protocols"`
	DomainTargetCapable bool     `json:"domainTargetCapable"`
	IPv6TargetCapable   bool     `json:"ipv6TargetCapable"`
}

// EgressCapabilities is the environment.clientEgressCapabilities object.
type EgressCapabilities struct {
	Version             int  `json:"version"`
	ConsumerCapable     bool `json:"consumerCapable"`
	EgressCapable       bool `json:"egressCapable"`
	DomainTargetCapable bool `json:"domainTargetCapable"`
	IPv6TargetCapable   bool `json:"ipv6TargetCapable"`
}

// EgressPolicyMutation is accepted by the management API; absent fields keep their stored value.
type EgressPolicyMutation struct {
	EgressClientID           *int64                       `json:"egressClientId"`
	Enabled                  *bool                        `json:"enabled"`
	Scope                    *string                      `json:"scope"`
	AllowedConsumerClientIDs []int64                      `json:"allowedConsumerClientIds"`
	DestinationRules         []peeregress.DestinationRule `json:"destinationRules"`
	MaxConcurrentFlows       *int                         `json:"maxConcurrentFlows"`
	MaxFlowsPerConsumer      *int                         `json:"maxFlowsPerConsumer"`
	IdleTimeoutSeconds       *int                         `json:"idleTimeoutSeconds"`
}

// EgressPolicyView is the management projection.
//
// EffectiveConsumerClientIDs is the configured allowlist already intersected with the base Peer
// ACL, so an operator sees which devices the policy actually grants rather than which it names.
type EgressPolicyView struct {
	ID                         int64                        `json:"id"`
	EgressClientID             int64                        `json:"egressClientId"`
	EgressClientName           string                       `json:"egressClientName"`
	Enabled                    bool                         `json:"enabled"`
	Scope                      string                       `json:"scope"`
	AllowedConsumerClientIDs   []int64                      `json:"allowedConsumerClientIds"`
	EffectiveConsumerClientIDs []int64                      `json:"effectiveConsumerClientIds"`
	DestinationRules           []peeregress.DestinationRule `json:"destinationRules"`
	MaxConcurrentFlows         int                          `json:"maxConcurrentFlows"`
	MaxFlowsPerConsumer        int                          `json:"maxFlowsPerConsumer"`
	IdleTimeoutSeconds         int                          `json:"idleTimeoutSeconds"`
	CreatedAt                  string                       `json:"createdAt"`
	UpdatedAt                  string                       `json:"updatedAt"`
}

// EgressSupported reports whether a client can take part at all. Version 0 or absent means the
// server must not push egress-config or egress-catalog to it.
func EgressSupported(capabilities *EgressCapabilities) bool {
	return capabilities != nil && capabilities.Version >= 1
}

// EgressProtocolVersion is the split-routing version this server speaks.
const EgressProtocolVersion = 1

// NormalizeEgressVersion clamps a client-announced version to what this server understands.
func NormalizeEgressVersion(version int) int {
	if version < 1 {
		return 0
	}
	if version > EgressProtocolVersion {
		return EgressProtocolVersion
	}
	return version
}

// egressCapabilitiesFor reads what the client announced at login. A client with no online session,
// or one that announced nothing, gets no egress payloads at all.
func (s *Service) egressCapabilitiesFor(ctx context.Context, account store.ClientAccount) *EgressCapabilities {
	online, err := s.db.GetOnlineClientSession(ctx, account.TenantID, account.ID, auth.StatusNettyOnline)
	if err != nil || online == nil || online.ClientEgressVersion < 1 {
		return nil
	}
	return &EgressCapabilities{Version: online.ClientEgressVersion}
}

// PushEgress sends the current egress-config and egress-catalog to one device.
//
// Called on login and after every policy mutation, so revoking a grant or switching an egress off
// takes effect immediately rather than at the peer's next login.
func (s *Service) PushEgress(ctx context.Context, account store.ClientAccount) {
	bound, ok := s.sessions.Find(account.ClientName)
	if !ok || bound == nil {
		return
	}
	capabilities := s.egressCapabilitiesFor(ctx, account)
	if !EgressSupported(capabilities) {
		return
	}
	if config, err := s.BuildEgressConfig(ctx, account, capabilities); err != nil {
		s.logger.Warn("build egress config failed", "client", account.ClientName, "err", err)
	} else if config != nil {
		config.SourceClientID = account.ID
		config.SourceClientName = account.ClientName
		config.TargetClientID = account.ID
		config.TargetClientName = account.ClientName
		config.CreatedAtMillis = time.Now().UnixMilli()
		_ = s.sendSignal(bound, "server", account.ClientName, *config)
	}
	if catalog, err := s.BuildEgressCatalog(ctx, account, capabilities); err != nil {
		s.logger.Warn("build egress catalog failed", "client", account.ClientName, "err", err)
	} else if catalog != nil {
		catalog.SourceClientID = account.ID
		catalog.SourceClientName = account.ClientName
		catalog.TargetClientID = account.ID
		catalog.TargetClientName = account.ClientName
		catalog.CreatedAtMillis = time.Now().UnixMilli()
		_ = s.sendSignal(bound, "server", account.ClientName, *catalog)
	}
}

// pushTenantEgress refreshes every online device in the tenant.
//
// A policy change moves two things at once: what the egress node itself will accept, and which
// egresses its peers can see. Both sides are refreshed together so the catalogue never advertises
// an egress that has already stopped accepting the viewer.
func (s *Service) pushTenantEgress(ctx context.Context, tenantID string) {
	clients, err := s.db.ListClients(ctx)
	if err != nil {
		return
	}
	for _, client := range clients {
		if client.TenantID == tenantID {
			s.PushEgress(ctx, client)
		}
	}
}

// ListEgressPolicies returns every policy in the tenant as a management view.
func (s *Service) ListEgressPolicies(ctx context.Context, access AccessContext) ([]EgressPolicyView, error) {
	rows, err := s.db.ListPeerMeshEgressPolicies(ctx, access.TenantID, false)
	if err != nil {
		return nil, err
	}
	views := make([]EgressPolicyView, 0, len(rows))
	for _, row := range rows {
		view, err := s.egressPolicyView(ctx, row)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, nil
}

// UpsertEgressPolicy creates or updates the policy for one egress device.
func (s *Service) UpsertEgressPolicy(ctx context.Context, access AccessContext, mutation EgressPolicyMutation) (EgressPolicyView, error) {
	if !access.Admin {
		return EgressPolicyView{}, errors.New("只有租户 ADMIN 可以管理出口授权")
	}
	if mutation.EgressClientID == nil || *mutation.EgressClientID <= 0 {
		return EgressPolicyView{}, errors.New("egressClientId is required")
	}
	egress, err := s.findTenantClient(ctx, access.TenantID, *mutation.EgressClientID)
	if err != nil {
		return EgressPolicyView{}, err
	}
	existing, err := s.db.FindPeerMeshEgressPolicyByClient(ctx, access.TenantID, egress.ID)
	if err != nil {
		return EgressPolicyView{}, err
	}
	now := time.Now()
	insert := existing == nil
	policy := store.PeerMeshEgressPolicy{
		ID: auth.NewClientID(), TenantID: access.TenantID, CreatedAt: now,
		Scope: peeregress.ScopePublic, DestinationRules: "[]",
		MaxConcurrentFlows: 256, MaxFlowsPerConsumer: 64, IdleTimeoutSeconds: 60,
	}
	if existing != nil {
		policy = *existing
	}
	policy.OwnerUsername = access.Username
	policy.EgressClientID = egress.ID
	policy.EgressClientName = egress.ClientName

	if mutation.Enabled != nil {
		policy.Enabled = *mutation.Enabled
	}
	if mutation.Scope != nil {
		scope := strings.ToUpper(strings.TrimSpace(*mutation.Scope))
		if scope != peeregress.ScopePublic && scope != peeregress.ScopeLAN {
			return EgressPolicyView{}, fmt.Errorf("invalid scope: %s", *mutation.Scope)
		}
		policy.Scope = scope
	}
	if mutation.AllowedConsumerClientIDs != nil {
		encoded, err := encodeClientIDs(mutation.AllowedConsumerClientIDs)
		if err != nil {
			return EgressPolicyView{}, err
		}
		policy.AllowedConsumerClientIDs = encoded
	}
	if mutation.DestinationRules != nil {
		encoded, err := EncodeEgressDestinationRules(mutation.DestinationRules)
		if err != nil {
			return EgressPolicyView{}, err
		}
		policy.DestinationRules = encoded
	}
	if mutation.MaxConcurrentFlows != nil {
		if *mutation.MaxConcurrentFlows <= 0 {
			return EgressPolicyView{}, errors.New("maxConcurrentFlows must be positive")
		}
		policy.MaxConcurrentFlows = *mutation.MaxConcurrentFlows
	}
	if mutation.MaxFlowsPerConsumer != nil {
		if *mutation.MaxFlowsPerConsumer <= 0 {
			return EgressPolicyView{}, errors.New("maxFlowsPerConsumer must be positive")
		}
		policy.MaxFlowsPerConsumer = *mutation.MaxFlowsPerConsumer
	}
	if mutation.IdleTimeoutSeconds != nil {
		if *mutation.IdleTimeoutSeconds <= 0 {
			return EgressPolicyView{}, errors.New("idleTimeoutSeconds must be positive")
		}
		policy.IdleTimeoutSeconds = *mutation.IdleTimeoutSeconds
	}
	policy.UpdatedAt = now

	if insert {
		err = s.db.InsertPeerMeshEgressPolicy(ctx, policy)
	} else {
		err = s.db.UpdatePeerMeshEgressPolicy(ctx, policy)
	}
	if err != nil {
		return EgressPolicyView{}, err
	}
	s.pushTenantEgress(ctx, access.TenantID)
	return s.egressPolicyView(ctx, policy)
}

// DeleteEgressPolicy removes a policy.
func (s *Service) DeleteEgressPolicy(ctx context.Context, access AccessContext, id int64) error {
	if !access.Admin {
		return errors.New("只有租户 ADMIN 可以管理出口授权")
	}
	policy, err := s.db.GetPeerMeshEgressPolicy(ctx, access.TenantID, id)
	if err != nil {
		return err
	}
	if policy == nil {
		return fmt.Errorf("egress policy not found: %d", id)
	}
	if err := s.db.DeletePeerMeshEgressPolicy(ctx, access.TenantID, id); err != nil {
		return err
	}
	s.pushTenantEgress(ctx, access.TenantID)
	return nil
}

// BuildEgressConfig produces the egress-config pushed to an egress device. It returns nil when the
// client cannot take part, so callers never push a half-formed policy to a runtime that would not
// understand it.
func (s *Service) BuildEgressConfig(ctx context.Context, account store.ClientAccount, capabilities *EgressCapabilities) (*ControlMessage, error) {
	if !EgressSupported(capabilities) {
		return nil, nil
	}
	revision := egressRevisions.Add(1)
	disabled := false
	message := &ControlMessage{Type: ControlTypeEgressConfig, Revision: &revision}

	policy, err := s.db.FindPeerMeshEgressPolicyByClient(ctx, account.TenantID, account.ID)
	if err != nil {
		return nil, err
	}
	if policy == nil || !policy.Enabled || !s.Enabled() {
		message.Enabled = &disabled
		message.AllowedConsumerClientIDs = []int64{}
		message.DestinationRules = []peeregress.DestinationRule{}
		return message, nil
	}
	consumers, err := s.allowedEgressConsumerIDs(ctx, account, *policy)
	if err != nil {
		return nil, err
	}
	enabled := true
	message.Enabled = &enabled
	message.Scope = policy.Scope
	message.AllowedConsumerClientIDs = consumers
	message.DestinationRules = DecodeEgressDestinationRules(policy.DestinationRules, s.logger)
	message.Limits = &peeregress.Limits{
		MaxConcurrentFlows:  policy.MaxConcurrentFlows,
		MaxFlowsPerConsumer: policy.MaxFlowsPerConsumer,
		IdleTimeoutSeconds:  policy.IdleTimeoutSeconds,
	}
	return message, nil
}

// BuildEgressCatalog produces the egress-catalog pushed to a consumer device.
func (s *Service) BuildEgressCatalog(ctx context.Context, account store.ClientAccount, capabilities *EgressCapabilities) (*ControlMessage, error) {
	if !EgressSupported(capabilities) {
		return nil, nil
	}
	revision := egressRevisions.Add(1)
	message := &ControlMessage{Type: ControlTypeEgressCatalog, Revision: &revision, Egresses: []EgressCatalogEntry{}}
	if !s.Enabled() {
		return message, nil
	}
	policies, err := s.db.ListPeerMeshEgressPolicies(ctx, account.TenantID, true)
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		if policy.EgressClientID == account.ID {
			continue
		}
		egress, err := s.findTenantClient(ctx, account.TenantID, policy.EgressClientID)
		if err != nil || egress == nil {
			continue
		}
		allowed, err := s.CanPeer(ctx, account, *egress)
		if err != nil || !allowed {
			continue
		}
		consumers, err := s.allowedEgressConsumerIDs(ctx, *egress, policy)
		if err != nil {
			return nil, err
		}
		if !containsInt64(consumers, account.ID) {
			continue
		}
		device, err := s.db.FindPeerMeshDeviceByClientID(ctx, account.TenantID, policy.EgressClientID)
		online := err == nil && device != nil && device.Enabled
		message.Egresses = append(message.Egresses, EgressCatalogEntry{
			ClientID:   policy.EgressClientID,
			ClientName: policy.EgressClientName,
			Online:     online,
			Scope:      policy.Scope,
			Protocols:  egressProtocols(DecodeEgressDestinationRules(policy.DestinationRules, s.logger)),
			// Both stay false until domain rules and an IPv6 data plane ship.
			DomainTargetCapable: false,
			IPv6TargetCapable:   false,
		})
	}
	return message, nil
}

// allowedEgressConsumerIDs intersects the policy allowlist with the base Peer ACL.
//
// Taking the intersection here, rather than only on the egress node, keeps the two failure modes
// aligned: a device that cannot see the egress in its catalogue also cannot reach it on the data
// plane.
func (s *Service) allowedEgressConsumerIDs(ctx context.Context, egress store.ClientAccount, policy store.PeerMeshEgressPolicy) ([]int64, error) {
	if !policy.Enabled {
		return []int64{}, nil
	}
	explicit := decodeClientIDs(policy.AllowedConsumerClientIDs)
	if len(explicit) == 0 {
		// An empty consumer allowlist grants nothing. Note this is the opposite of the shared
		// service default, where an empty list means "everyone the mesh ACL already allows".
		// Egress has to be chosen on both sides: reading a blank field as "anyone" would turn a
		// device into the whole tenant's way out.
		return []int64{}, nil
	}
	accounts, err := s.db.ListClients(ctx)
	if err != nil {
		return nil, err
	}
	allowed := make([]int64, 0, len(explicit))
	seen := make(map[int64]struct{}, len(explicit))
	for _, candidate := range accounts {
		if candidate.TenantID != egress.TenantID || candidate.ID == egress.ID {
			continue
		}
		if !containsInt64(explicit, candidate.ID) {
			continue
		}
		if _, done := seen[candidate.ID]; done {
			continue
		}
		ok, err := s.CanPeer(ctx, candidate, egress)
		if err != nil || !ok {
			continue
		}
		seen[candidate.ID] = struct{}{}
		allowed = append(allowed, candidate.ID)
	}
	return allowed, nil
}

func (s *Service) egressPolicyView(ctx context.Context, policy store.PeerMeshEgressPolicy) (EgressPolicyView, error) {
	effective := []int64{}
	if egress, err := s.findTenantClient(ctx, policy.TenantID, policy.EgressClientID); err == nil && egress != nil {
		if ids, err := s.allowedEgressConsumerIDs(ctx, *egress, policy); err == nil {
			effective = ids
		}
	}
	configured := decodeClientIDs(policy.AllowedConsumerClientIDs)
	if configured == nil {
		configured = []int64{}
	}
	return EgressPolicyView{
		ID:                         policy.ID,
		EgressClientID:             policy.EgressClientID,
		EgressClientName:           policy.EgressClientName,
		Enabled:                    policy.Enabled,
		Scope:                      policy.Scope,
		AllowedConsumerClientIDs:   configured,
		EffectiveConsumerClientIDs: effective,
		DestinationRules:           DecodeEgressDestinationRules(policy.DestinationRules, s.logger),
		MaxConcurrentFlows:         policy.MaxConcurrentFlows,
		MaxFlowsPerConsumer:        policy.MaxFlowsPerConsumer,
		IdleTimeoutSeconds:         policy.IdleTimeoutSeconds,
		CreatedAt:                  policy.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:                  policy.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

// EncodeEgressDestinationRules serialises an allowlist for storage.
func EncodeEgressDestinationRules(rules []peeregress.DestinationRule) (string, error) {
	if len(rules) == 0 {
		return "[]", nil
	}
	if len(rules) > MaxEgressDestinationRules {
		return "", fmt.Errorf("too many destination rules: %d", len(rules))
	}
	encoded, err := json.Marshal(rules)
	if err != nil {
		return "", err
	}
	if len(encoded) > MaxEgressDestinationRulesBytes {
		return "", errors.New("destination rules exceed the storage limit")
	}
	return string(encoded), nil
}

// DecodeEgressDestinationRules reads a stored allowlist. A row that cannot be parsed denies
// everything rather than falling back to something permissive.
func DecodeEgressDestinationRules(raw string, logger interface{ Warn(string, ...any) }) []peeregress.DestinationRule {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return []peeregress.DestinationRule{}
	}
	var rules []peeregress.DestinationRule
	if err := json.Unmarshal([]byte(trimmed), &rules); err != nil {
		if logger != nil {
			logger.Warn("peer egress destination rules are unreadable; treating the policy as deny-all")
		}
		return []peeregress.DestinationRule{}
	}
	if rules == nil {
		return []peeregress.DestinationRule{}
	}
	return rules
}

func egressProtocols(rules []peeregress.DestinationRule) []string {
	protocols := make([]string, 0, 2)
	seen := make(map[string]struct{}, 2)
	for _, rule := range rules {
		for _, protocol := range rule.Protocols {
			if _, done := seen[protocol]; done {
				continue
			}
			seen[protocol] = struct{}{}
			protocols = append(protocols, protocol)
		}
	}
	return protocols
}

func containsInt64(values []int64, want int64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
