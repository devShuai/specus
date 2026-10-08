// Package nat implements server-side NAT TCP forwarding: pushing specus configuration to
// clients (NAT_CONTROL), managing public-port listeners, bridging external TCP connections
// over the control channel, and tracking traffic. It mirrors the C# Nat namespace.
package nat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// ControlService builds and pushes NAT_CONTROL messages from the persisted specus/HTTP-route
// configuration. Mirrors the C# NatControlService.
type ControlService struct {
	db            *store.DB
	sessions      *session.Registry
	remotePort    int
	publicAddress string
}

// NewControlService builds the NAT control push service.
func NewControlService(db *store.DB, sessions *session.Registry, remotePort int, publicAddress string) *ControlService {
	return &ControlService{db: db, sessions: sessions, remotePort: remotePort, publicAddress: publicAddress}
}

// PushResult reports how many entries were pushed.
type PushResult struct {
	SpecusMappings int
	HTTPRoutes     int
}

// PushToName pushes the current snapshot to an online client by name; returns false if offline.
// An error wrapping ErrNatControlNotSent means the client is online but its NAT_CONTROL was not sent;
// one wrapping ErrNatControlWriteFailed means its control connection could not be written.
func (s *ControlService) PushToName(ctx context.Context, clientName string) (PushResult, bool, error) {
	account, err := s.db.FindClientByName(ctx, clientName)
	if err != nil {
		return PushResult{}, false, err
	}
	if account == nil {
		return PushResult{}, false, nil
	}
	return s.pushSnapshot(ctx, account.ID, clientName)
}

// PushToID pushes the current snapshot to an online client by id; returns false if offline.
func (s *ControlService) PushToID(ctx context.Context, clientID int64, clientName string) (PushResult, bool, error) {
	return s.pushSnapshot(ctx, clientID, clientName)
}

func (s *ControlService) pushSnapshot(ctx context.Context, clientID int64, clientName string) (PushResult, bool, error) {
	mappings, err := s.db.ListEnabledSpecusMappings(ctx, clientID)
	if err != nil {
		return PushResult{}, false, err
	}
	httpRoutes, err := s.db.ListEnabledHTTPRoutes(ctx, clientID)
	if err != nil {
		return PushResult{}, false, err
	}

	bound, ok := s.sessions.Find(clientName)
	if !ok {
		return PushResult{}, false, nil
	}
	message, err := s.buildMessage(clientName, mappings, httpRoutes)
	if err != nil {
		return PushResult{}, true, fmt.Errorf("%w: %v", ErrNatControlNotSent, err)
	}
	// A NAT_CONTROL that does not fit one MESSAGE is not handed to the connection at all, so it
	// is never written in part and the connection stays as it is. See "NAT_CONTROL 的大小" in
	// protocol/spec/control-protocol.md.
	body, err := protocol.EncodeBody(message)
	if err != nil {
		return PushResult{}, true, fmt.Errorf("%w: %v", ErrNatControlNotSent, err)
	}
	if len(body) > MessageBodyLimit {
		return PushResult{}, true, fmt.Errorf("%w: %d tcp + %d http route(s) take %d bytes, over the %d-byte MESSAGE body limit",
			ErrNatControlNotSent, len(mappings), len(httpRoutes), len(body), MessageBodyLimit)
	}
	// A NAT_CONTROL within the MESSAGE body limit always fits the frame limit (netty.maxFrameSize is
	// at least the header plus that body), so what fails here is the write itself.
	if err := bound.Send(message); err != nil {
		return PushResult{}, false, fmt.Errorf("%w: %v", ErrNatControlWriteFailed, err)
	}
	return PushResult{SpecusMappings: len(mappings), HTTPRoutes: len(httpRoutes)}, true, nil
}

func (s *ControlService) buildMessage(clientName string, mappings []store.SpecusMapping,
	httpRoutes []store.HTTPRouteMapping) (protocol.MessageResponse, error) {
	payload, err := s.MessageJSON(clientName, mappings, httpRoutes)
	if err != nil {
		return protocol.MessageResponse{}, err
	}
	return protocol.MessageResponse{
		ClientName:  clientName,
		MessageType: protocol.MessageTypeNatControl,
		Message:     string(payload),
	}, nil
}

// MessageJSON is the JSON text of clientName's NAT_CONTROL.
func (s *ControlService) MessageJSON(clientName string, mappings []store.SpecusMapping,
	httpRoutes []store.HTTPRouteMapping) ([]byte, error) {
	specusConfigList := make([]map[string]any, 0, len(mappings))
	for _, mapping := range mappings {
		specusConfigList = append(specusConfigList, map[string]any{
			"port":          mapping.ListenPort,
			"specusAddress": mapping.TargetAddress,
			"specusPort":    mapping.TargetPort,
		})
	}

	bean := map[string]any{
		"clientName":       clientName,
		"remotePort":       s.remotePort,
		"specusConfigList": specusConfigList,
	}
	if trimmed := strings.TrimSpace(s.publicAddress); trimmed != "" {
		bean["remoteAddress"] = trimmed
	} else {
		bean["remoteAddress"] = nil
	}
	// The HTTP route list is always the full set, even when empty: older clients keep the list
	// they have when the field is missing, so omitting it after the last route was deleted left
	// that route forwarding on the client until it reconnected.
	httpList := make([]map[string]any, 0, len(httpRoutes))
	for _, route := range httpRoutes {
		httpList = append(httpList, map[string]any{
			"route":         route.Route,
			"targetBaseUrl": route.TargetBaseURL,
		})
	}
	bean["httpSpecusConfigList"] = httpList

	payload, err := json.Marshal(bean)
	if err != nil {
		return nil, fmt.Errorf("encode NAT_CONTROL: %w", err)
	}
	return payload, nil
}

// MessageBodyLimit is the 1 MiB MESSAGE body of protocol/spec/control-protocol.md that a
// NAT_CONTROL travels in.
const MessageBodyLimit = 1024 * 1024

// clientNameReserveCharacters is the longest client name a rename allows.
const clientNameReserveCharacters = 120

// ErrNatControlTooLarge refuses a mapping or route change after which the client's NAT_CONTROL
// would no longer fit one MESSAGE; the management API answers it with 400.
var ErrNatControlTooLarge = errors.New(
	"客户端的 TCP 映射和 HTTP route 将超过单条 NAT_CONTROL 消息 1 MiB 的上限，无法下发给客户端")

// ErrNatControlNotSent is wrapped by a push whose NAT_CONTROL, as stored, does not fit one MESSAGE
// or cannot be encoded. Nothing was written and the connection is kept; the manual push answers it
// with 409 and every other push only logs it.
var ErrNatControlNotSent = errors.New(
	"客户端的 TCP 映射和 HTTP route 超过单条 NAT_CONTROL 消息 1 MiB 的上限，未下发给客户端")

// ErrNatControlWriteFailed is wrapped by a push whose write to the client's control connection
// failed, the connection being closed, reset or otherwise gone. The manual push answers it as an
// offline client, with 409, and every other push only logs it. See "NAT_CONTROL 写失败与数据库错误"
// in protocol/spec/control-protocol.md.
var ErrNatControlWriteFailed = errors.New("NAT_CONTROL write to the control connection failed")

// The client's name when a NAT_CONTROL is sized: 120 characters of 4 UTF-8 bytes each in the
// clientName field, and of a 6-byte \uXXXX escape each in the JSON. No name a rename allows takes
// more in either place, so no later rename pushes an accepted configuration over.
var (
	longestFieldName = strings.Repeat("\U00010000", clientNameReserveCharacters)
	longestJSONName  = strings.Repeat("\x01", clientNameReserveCharacters)
)

// ReservedBodyBytes is the MESSAGE body of a NAT_CONTROL carrying these entries, encoded as it is
// sent, with the client's name counted at the longest a rename allows. See "NAT_CONTROL 的大小" in
// protocol/spec/control-protocol.md.
func (s *ControlService) ReservedBodyBytes(mappings []store.SpecusMapping,
	httpRoutes []store.HTTPRouteMapping) (int, error) {
	payload, err := s.MessageJSON(longestJSONName, mappings, httpRoutes)
	if err != nil {
		return 0, err
	}
	body, err := protocol.EncodeBody(protocol.MessageResponse{
		ClientName:  longestFieldName,
		MessageType: protocol.MessageTypeNatControl,
		Message:     string(payload),
	})
	if err != nil {
		return 0, err
	}
	return len(body), nil
}

// CheckFits returns ErrNatControlTooLarge when the client's NAT_CONTROL would no longer fit one
// MESSAGE once mapping or route, as the change leaves it, takes the place of the stored entry with
// its id or joins the list. It counts the client's enabled entries, whether or not the client is
// enabled. The kind the change does not touch is passed as nil.
func (s *ControlService) CheckFits(ctx context.Context, clientID int64, mapping *store.SpecusMapping,
	route *store.HTTPRouteMapping) error {
	mappings, err := s.db.ListEnabledSpecusMappings(ctx, clientID)
	if err != nil {
		return err
	}
	httpRoutes, err := s.db.ListEnabledHTTPRoutes(ctx, clientID)
	if err != nil {
		return err
	}
	if mapping != nil {
		kept := make([]store.SpecusMapping, 0, len(mappings)+1)
		for _, stored := range mappings {
			if stored.ID != mapping.ID {
				kept = append(kept, stored)
			}
		}
		if mapping.Enabled {
			kept = append(kept, *mapping)
		}
		mappings = kept
	}
	if route != nil {
		kept := make([]store.HTTPRouteMapping, 0, len(httpRoutes)+1)
		for _, stored := range httpRoutes {
			if stored.ID != route.ID {
				kept = append(kept, stored)
			}
		}
		if route.Enabled {
			kept = append(kept, *route)
		}
		httpRoutes = kept
	}
	size, err := s.ReservedBodyBytes(mappings, httpRoutes)
	if err != nil {
		return err
	}
	if size > MessageBodyLimit {
		return ErrNatControlTooLarge
	}
	return nil
}
