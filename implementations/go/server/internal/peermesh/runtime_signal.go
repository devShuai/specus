package peermesh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Only this entry is used by the physical control route. Legacy helper entry points are
// internal callers, not a wire authentication mode or a fallback for missing runtime proof.
func (s *Service) HandleSignalBound(ctx context.Context, request protocol.MessageRequest, original store.RuntimeClientReference) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.db.CheckPeerRuntimeCurrent(ctx, original); err != nil {
		return fmt.Errorf("%w: %w", ErrUndeliverable, err)
	}
	return s.handleSignalSession(ctx, request, original.ClientName, original.SessionID, &original)
}

func runtimeOf(bound session.Session) (store.RuntimeClientReference, bool) {
	if bound == nil {
		return store.RuntimeClientReference{}, false
	}
	proof, ok := bound.(interface {
		RuntimeReference() (store.RuntimeClientReference, bool)
	})
	if !ok {
		return store.RuntimeClientReference{}, false
	}
	return proof.RuntimeReference()
}

func (s *Service) relayRuntimeSignal(ctx context.Context, original store.RuntimeClientReference, source, target store.ClientAccount, signal ControlMessage) error {
	sourceSession, sourceOnline := s.sessions.Find(source.ClientName)
	targetSession, targetOnline := s.sessions.Find(target.ClientName)
	sourceRuntime, sourceProof := runtimeOf(sourceSession)
	targetRuntime, targetProof := runtimeOf(targetSession)
	if !sourceOnline || !targetOnline || !sourceProof || !targetProof || sourceRuntime != original || targetRuntime.PeerClient() != peerClientReference(target) {
		return fmt.Errorf("%w: original peer transport changed", ErrUndeliverable)
	}
	var created *sessionGrant
	if signal.SessionID == nil && (signal.Type == TypeCandidates || signal.Type == "offer") {
		grant, err := s.createRuntimeSession(ctx, sourceRuntime, targetRuntime, source, target)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUndeliverable, err)
		}
		created = &grant
		signal.SessionID = &grant.session.ID
		signal.Token = grant.token
	}
	id := int64(0)
	tokenHash := ""
	if signal.SessionID != nil {
		id = *signal.SessionID
		if id <= 0 {
			return fmt.Errorf("%w: invalid peer grant", ErrUndeliverable)
		}
		if signal.Token == "" {
			signal.Token, _ = s.getCachedSessionToken(id)
		}
		if signal.Token == "" {
			return fmt.Errorf("%w: missing peer grant token", ErrUndeliverable)
		}
		hash := sha256.Sum256([]byte(signal.Token))
		tokenHash = hex.EncodeToString(hash[:])
	} else {
		signal.Token = ""
	}
	err := s.db.PublishPeerSignal(ctx, sourceRuntime, targetRuntime, id, tokenHash, func(current store.PeerSignalPublication) error {
		// Pair lifecycle leases in the dispatcher keep local replacement ordered. This extra
		// identity check also fences direct internal callbacks and failed/unbound transports.
		if !s.sessions.IsBound(sourceSession) || !s.sessions.IsBound(targetSession) {
			return errors.New("original peer transport is no longer bound")
		}
		signal.SourceClientID = current.Source.ID
		signal.SourceClientName = current.Source.ClientName
		signal.SourceVirtualIP = current.SourceDevice.VirtualIP
		signal.SourcePublicKey = current.SourceDevice.PublicKey
		signal.TargetClientID = current.Target.ID
		signal.TargetClientName = current.Target.ClientName
		signal.TargetVirtualIP = current.TargetDevice.VirtualIP
		signal.TargetPublicKey = current.TargetDevice.PublicKey
		signal.DataFrameVersion = 2
		if current.Session != nil {
			signal.ExpiresAt = current.Session.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		if created != nil {
			grant := ControlMessage{Type: TypeSessionGrant, SessionID: signal.SessionID, Token: signal.Token, ExpiresAt: current.Session.ExpiresAt.UTC().Format(time.RFC3339Nano), SourceClientID: current.Source.ID, SourceClientName: current.Source.ClientName, SourceVirtualIP: current.SourceDevice.VirtualIP, SourcePublicKey: current.SourceDevice.PublicKey, TargetClientID: current.Target.ID, TargetClientName: current.Target.ClientName, TargetVirtualIP: current.TargetDevice.VirtualIP, TargetPublicKey: current.TargetDevice.PublicKey, DataFrameVersion: 2, PathType: current.Session.PathType, Status: current.Session.Status, CreatedAtMillis: time.Now().UnixMilli()}
			if err := s.sendPeerSignalBounded(ctx, sourceSession, "server", source.ClientName, grant); err != nil {
				return err
			}
		}
		return s.sendPeerSignalBounded(ctx, targetSession, source.ClientName, target.ClientName, signal)
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUndeliverable, err)
	}
	return nil
}

func (s *Service) createRuntimeSession(ctx context.Context, sourceRuntime, targetRuntime store.RuntimeClientReference, source, target store.ClientAccount) (sessionGrant, error) {
	candidates, hashes := map[int64]string{}, map[int64]string{}
	open, err := s.db.FindOpenSessionBetweenClients(ctx, source.TenantID, source.ID, target.ID, StatusClosed)
	if err != nil {
		return sessionGrant{}, err
	}
	for _, row := range open {
		if token, ok := s.getCachedSessionToken(row.ID); ok && token != "" {
			candidates[row.ID] = token
			hash := sha256.Sum256([]byte(token))
			hashes[row.ID] = hex.EncodeToString(hash[:])
		}
	}
	token := s.shortToken(source.ClientName, target.ClientName, strconv.FormatInt(time.Now().UnixMilli(), 10), randomSuffix())
	hash := sha256.Sum256([]byte(token))
	out, err := s.db.AdmitRuntimePeerMeshSession(ctx, sourceRuntime, targetRuntime, store.PeerSessionSeed{ID: auth.NewClientID(), PathType: PathDirect, TokenHash: hex.EncodeToString(hash[:]), TTL: time.Duration(s.cfg.SessionTTLSeconds) * time.Second, ReusableTokenHashes: hashes})
	if err != nil {
		return sessionGrant{}, err
	}
	for _, id := range out.ClosedIDs {
		s.removeRelaySession(id)
		s.removeCachedSessionToken(id)
	}
	if out.Created {
		s.cacheSessionToken(out.Session.ID, token)
	} else {
		token = candidates[out.Session.ID]
	}
	return sessionGrant{session: sessionView(out.Session), token: token}, nil
}

func (s *Service) sendPeerSignalBounded(ctx context.Context, bound session.Session, source, name string, signal ControlMessage) error {
	sender, ok := bound.(interface {
		SendContext(context.Context, protocol.Packet) error
	})
	if !ok {
		return errors.New("peer publication requires bounded transport delivery")
	}
	data, err := json.Marshal(signal)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return sender.SendContext(ctx, protocol.MessageResponse{ClientName: source, ToClientName: name, MessageType: protocol.MessageTypePeerControl, Message: string(data)})
}
