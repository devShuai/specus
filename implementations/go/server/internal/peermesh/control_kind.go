package peermesh

import (
	"encoding/json"
	"strings"
)

func serverOnlyControlType(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case TypeConfig, TypeRoster, TypeSessionGrant, TypeServiceCatalog, ControlTypeEgressConfig, ControlTypeEgressCatalog:
		return true
	}
	return false
}

// SignalTargetsPeer selects lifecycle leases, not authorization. Reports and close are
// server operations regardless of an untrusted ToClientName; invalid/server-only messages
// must still reach the service's protocol validation, without an unrelated target gate.
func SignalTargetsPeer(body string) bool {
	var header struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(body), &header) != nil || serverOnlyControlType(header.Type) {
		return false
	}
	switch header.Type {
	case TypePathReport, TypeTrafficReport, TypeDeviceReport, TypeServiceReport, ControlTypeEgressReport, TypeClose:
		return false
	}
	return strings.TrimSpace(header.Type) != ""
}
