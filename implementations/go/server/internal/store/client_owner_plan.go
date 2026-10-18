package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

const OwnerScopeSingle = "single"
const OwnerScopeGroup = "credential-group"

type OwnerTransferError struct {
	Status int
	Code   string
}

func (e *OwnerTransferError) Error() string    { return e.Code }
func ownerError(status int, code string) error { return &OwnerTransferError{status, code} }
func invalidOwnerTransfer() error              { return ownerError(400, "INVALID_TRANSFER_REQUEST") }
func inconsistentOwnerTransfer() error         { return ownerError(409, "INCONSISTENT_CREDENTIAL_GROUP") }

type OwnerAffectedClient struct {
	ID            int64   `json:"id"`
	ClientName    *string `json:"clientName"`
	OwnerUsername *string `json:"ownerUsername"`
	Enabled       bool    `json:"enabled"`
}
type OwnerTransferPreview struct {
	Scope                   string                `json:"scope"`
	ClientID                *int64                `json:"clientId"`
	CredentialID            *int64                `json:"credentialId"`
	CredentialOwnerUsername *string               `json:"credentialOwnerUsername"`
	CredentialEnabled       *bool                 `json:"credentialEnabled"`
	AffectedClients         []OwnerAffectedClient `json:"affectedClients"`
	AffectedClientCount     int                   `json:"affectedClientCount"`
	CanTransfer             bool                  `json:"canTransfer"`
	ConflictCode            *string               `json:"conflictCode"`
	Revision                *string               `json:"revision"`
	AccessRetained          bool                  `json:"accessRetained"`
}

func ValidateOwnerTransferPath(p ManagementWriteActor, id int64) error {
	if !p.Admin {
		return ownerError(403, "FORBIDDEN")
	}
	if id <= 0 || id > 9_007_199_254_740_991 {
		return invalidOwnerTransfer()
	}
	return nil
}

func ParseOwnerTransferID(p ManagementWriteActor, text string) (int64, error) {
	// Role comes first, including when the path isn't a legal integer.
	if err := ValidateOwnerTransferPath(p, 1); err != nil {
		return 0, err
	}
	if len(text) == 0 || len(text) > 19 {
		return 0, invalidOwnerTransfer()
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return 0, invalidOwnerTransfer()
		}
	}
	id, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, invalidOwnerTransfer()
	}
	return id, ValidateOwnerTransferPath(p, id)
}

func requireOwnerTransferResource(p ManagementWriteActor, scope string, id int64, data OwnerTransferSnapshot) error {
	if scope == OwnerScopeSingle {
		for _, row := range data.Clients {
			if row.ID == id && row.TenantID == p.TenantID {
				return nil
			}
		}
	} else if scope == OwnerScopeGroup {
		for _, row := range data.Credentials {
			if row.ID == id && row.TenantID == p.TenantID {
				return nil
			}
		}
	} else {
		return invalidOwnerTransfer()
	}
	return ownerError(404, "RESOURCE_NOT_FOUND")
}

func PreviewOwnerTransfer(p ManagementWriteActor, scope string, id int64, data OwnerTransferSnapshot) (OwnerTransferPreview, error) {
	if err := ValidateOwnerTransferPath(p, id); err != nil {
		return OwnerTransferPreview{}, err
	}
	if err := requireOwnerTransferResource(p, scope, id, data); err != nil {
		return OwnerTransferPreview{}, err
	}
	return buildOwnerTransferPreview(p.TenantID, scope, id, data)
}

// Pure validation through contract steps 1–8 ONLY, never resolves a target or writes.
// Public POST uses the database-coordinated writer; this pure planner alone is not a write API.
func PrepareOwnerTransfer(p ManagementWriteActor, scope string, id int64, request any, data OwnerTransferSnapshot) (OwnerTransferPreview, string, error) {
	var empty OwnerTransferPreview
	if err := ValidateOwnerTransferPath(p, id); err != nil {
		return empty, "", err
	}
	body, ok := request.(map[string]any)
	if !ok || body == nil {
		return empty, "", invalidOwnerTransfer()
	}
	if err := requireOwnerTransferResource(p, scope, id, data); err != nil {
		return empty, "", err
	}
	if requested, ok := body["scope"].(string); !ok || requested != scope {
		return empty, "", invalidOwnerTransfer()
	}
	for _, name := range []string{"targetUsername", "expectedRevision"} {
		if value, exists := body[name]; exists {
			if _, ok := value.(string); !ok {
				return empty, "", invalidOwnerTransfer()
			}
		}
	}
	preview, err := buildOwnerTransferPreview(p.TenantID, scope, id, data)
	if err != nil {
		return empty, "", err
	}
	if !preview.CanTransfer {
		return empty, "", ownerError(409, "CREDENTIAL_SHARED")
	}
	target, _ := body["targetUsername"].(string)
	revision, _ := body["expectedRevision"].(string)
	if strings.TrimSpace(target) == "" || strings.TrimSpace(revision) == "" {
		return empty, "", invalidOwnerTransfer()
	}
	if preview.Revision == nil || revision != *preview.Revision {
		return empty, "", ownerError(409, "TRANSFER_PREVIEW_CHANGED")
	}
	return preview, strings.TrimSpace(target), nil
}

func buildOwnerTransferPreview(tenant, scope string, pathID int64, data OwnerTransferSnapshot) (OwnerTransferPreview, error) {
	var result OwnerTransferPreview
	var credentialID *int64
	if scope == OwnerScopeGroup {
		credentialID = &pathID
	} else {
		for _, edge := range data.Identities {
			if edge.ClientID != pathID {
				continue
			}
			if edge.TenantID != tenant || (credentialID != nil && *credentialID != edge.CredentialID) {
				return result, inconsistentOwnerTransfer()
			}
			value := edge.CredentialID
			credentialID = &value
		}
	}
	var credential *OwnerTransferCredential
	identities := make([]OwnerTransferIdentity, 0)
	clientIDs := make(map[int64]bool)
	if credentialID != nil {
		if *credentialID <= 0 || *credentialID > 9_007_199_254_740_991 {
			return result, inconsistentOwnerTransfer()
		}
		for _, row := range data.Credentials {
			if row.ID == *credentialID {
				if credential != nil || row.TenantID != tenant {
					return result, inconsistentOwnerTransfer()
				}
				value := row
				credential = &value
			}
		}
		if credential == nil {
			return result, inconsistentOwnerTransfer()
		}
		identityIDs := make(map[int64]bool)
		for _, edge := range data.Identities {
			if edge.CredentialID != *credentialID {
				continue
			}
			if edge.TenantID != tenant || identityIDs[edge.ID] {
				return result, inconsistentOwnerTransfer()
			}
			identityIDs[edge.ID] = true
			identities = append(identities, edge)
			clientIDs[edge.ClientID] = true
		}
	} else {
		clientIDs[pathID] = true
	}
	byID := make(map[int64][]OwnerTransferClient)
	for _, row := range data.Clients {
		byID[row.ID] = append(byID[row.ID], row)
	}
	clients := make([]OwnerTransferClient, 0, len(clientIDs))
	for id := range clientIDs {
		found := byID[id]
		if id <= 0 || id > 9_007_199_254_740_991 || len(found) != 1 || found[0].TenantID != tenant {
			return result, inconsistentOwnerTransfer()
		}
		clients = append(clients, found[0])
	}
	for _, edge := range data.Identities {
		if clientIDs[edge.ClientID] && (edge.TenantID != tenant || credentialID == nil || edge.CredentialID != *credentialID) {
			return result, inconsistentOwnerTransfer()
		}
	}
	peers := make([]OwnerTransferPeer, 0)
	peerIDs, peerClients := make(map[int64]bool), make(map[int64]bool)
	for _, row := range data.Peers {
		if row.TenantID != tenant || !clientIDs[row.ClientID] {
			continue
		}
		if peerIDs[row.ID] || peerClients[row.ClientID] {
			return result, inconsistentOwnerTransfer()
		}
		peerIDs[row.ID], peerClients[row.ClientID] = true, true
		peers = append(peers, row)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	sort.Slice(identities, func(i, j int) bool { return identities[i].ID < identities[j].ID })
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
	result = OwnerTransferPreview{Scope: scope, CredentialID: credentialID, AffectedClients: make([]OwnerAffectedClient, 0, len(clients)), AffectedClientCount: len(clients), CanTransfer: true, AccessRetained: true}
	if scope == OwnerScopeSingle {
		result.ClientID = &pathID
	}
	if credential != nil {
		result.CredentialOwnerUsername = credential.OwnerUsername
		result.CredentialEnabled = &credential.Enabled
	}
	for _, row := range clients {
		result.AffectedClients = append(result.AffectedClients, OwnerAffectedClient{row.ID, row.ClientName, row.OwnerUsername, row.Enabled})
	}
	if scope == OwnerScopeSingle && len(clients) > 1 {
		conflict := "CREDENTIAL_SHARED"
		result.CanTransfer, result.ConflictCode = false, &conflict
	} else {
		// Canonical sorted structured JSON preserves null/empty and text boundaries. A digest is
		// stateless across same-runtime instances, not an authorization token or a write lock.
		canonical := struct {
			Version    string
			Tenant     string
			Scope      string
			PathID     int64
			Credential *OwnerTransferCredential
			Clients    []OwnerTransferClient
			Identities []OwnerTransferIdentity
			Peers      []OwnerTransferPeer
		}{"specus-owner-transfer-go-v1", tenant, scope, pathID, credential, clients, identities, peers}
		encoded, err := json.Marshal(canonical)
		if err != nil {
			return OwnerTransferPreview{}, err
		}
		digest := sha256.Sum256(encoded)
		revision := hex.EncodeToString(digest[:])
		result.Revision = &revision
	}
	return result, nil
}
