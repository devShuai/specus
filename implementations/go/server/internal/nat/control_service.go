// Package nat implements server-side NAT TCP forwarding: pushing specus configuration to
// clients (NAT_CONTROL), managing public-port listeners, bridging external TCP connections
// over the control channel, and tracking traffic. It mirrors the C# Nat namespace.
package nat

import (
	"context"
	"encoding/json"
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

// PushResult reports how many entries were pushed. HTTPRoutes is -1 when HTTP routes are
// unmanaged for the client (the httpSpecusConfigList key is omitted entirely).
type PushResult struct {
	SpecusMappings    int
	HTTPRoutes int
}

// PushToName pushes the current snapshot to an online client by name; returns false if offline.
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
	httpManaged, err := s.db.CountHTTPRoutes(ctx, clientID)
	if err != nil {
		return PushResult{}, false, err
	}
	var httpRoutes []store.HTTPRouteMapping
	if httpManaged > 0 {
		httpRoutes, err = s.db.ListEnabledHTTPRoutes(ctx, clientID)
		if err != nil {
			return PushResult{}, false, err
		}
	}

	bound, ok := s.sessions.Find(clientName)
	if !ok {
		return PushResult{}, false, nil
	}
	message, err := s.buildMessage(clientName, mappings, httpManaged > 0, httpRoutes)
	if err != nil {
		return PushResult{}, false, err
	}
	if err := bound.Send(message); err != nil {
		return PushResult{}, false, err
	}
	result := PushResult{SpecusMappings: len(mappings), HTTPRoutes: -1}
	if httpManaged > 0 {
		result.HTTPRoutes = len(httpRoutes)
	}
	return result, true, nil
}

func (s *ControlService) buildMessage(clientName string, mappings []store.SpecusMapping,
	httpManaged bool, httpRoutes []store.HTTPRouteMapping) (protocol.MessageResponse, error) {
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
	if httpManaged {
		httpList := make([]map[string]any, 0, len(httpRoutes))
		for _, route := range httpRoutes {
			httpList = append(httpList, map[string]any{
				"route":         route.Route,
				"targetBaseUrl": route.TargetBaseURL,
			})
		}
		bean["httpSpecusConfigList"] = httpList
	}

	payload, err := json.Marshal(bean)
	if err != nil {
		return protocol.MessageResponse{}, fmt.Errorf("encode NAT_CONTROL: %w", err)
	}
	return protocol.MessageResponse{
		ClientName:  clientName,
		MessageType: protocol.MessageTypeNatControl,
		Message:     string(payload),
	}, nil
}
