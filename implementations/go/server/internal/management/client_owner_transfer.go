package management

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

const ownerScopeSingle = "single"
const ownerScopeGroup = "credential-group"

type ownerTransferError struct {
	Status int
	Code   string
}

func (e *ownerTransferError) Error() string    { return e.Code }
func ownerError(status int, code string) error { return &ownerTransferError{status, code} }
func invalidOwnerTransfer() error              { return ownerError(400, "INVALID_TRANSFER_REQUEST") }
func inconsistentOwnerTransfer() error         { return ownerError(409, "INCONSISTENT_CREDENTIAL_GROUP") }

type ownerAffectedClient struct {
	ID            int64   `json:"id"`
	ClientName    *string `json:"clientName"`
	OwnerUsername *string `json:"ownerUsername"`
	Enabled       bool    `json:"enabled"`
}
type ownerTransferPreview struct {
	Scope                   string                `json:"scope"`
	ClientID                *int64                `json:"clientId"`
	CredentialID            *int64                `json:"credentialId"`
	CredentialOwnerUsername *string               `json:"credentialOwnerUsername"`
	CredentialEnabled       *bool                 `json:"credentialEnabled"`
	AffectedClients         []ownerAffectedClient `json:"affectedClients"`
	AffectedClientCount     int                   `json:"affectedClientCount"`
	CanTransfer             bool                  `json:"canTransfer"`
	ConflictCode            *string               `json:"conflictCode"`
	Revision                *string               `json:"revision"`
	AccessRetained          bool                  `json:"accessRetained"`
}

func validateOwnerTransferPath(p managementPrincipal, id int64) error {
	if !p.Admin {
		return ownerError(403, "FORBIDDEN")
	}
	if id <= 0 || id > 9_007_199_254_740_991 {
		return invalidOwnerTransfer()
	}
	return nil
}

func parseOwnerTransferID(p managementPrincipal, text string) (int64, error) {
	// Role comes first, including when the path isn't a legal integer.
	if err := validateOwnerTransferPath(p, 1); err != nil {
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
	return id, validateOwnerTransferPath(p, id)
}

func requireOwnerTransferResource(p managementPrincipal, scope string, id int64, data store.OwnerTransferSnapshot) error {
	if scope == ownerScopeSingle {
		for _, row := range data.Clients {
			if row.ID == id && row.TenantID == p.TenantID {
				return nil
			}
		}
	} else if scope == ownerScopeGroup {
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

func previewOwnerTransfer(p managementPrincipal, scope string, id int64, data store.OwnerTransferSnapshot) (ownerTransferPreview, error) {
	if err := validateOwnerTransferPath(p, id); err != nil {
		return ownerTransferPreview{}, err
	}
	if err := requireOwnerTransferResource(p, scope, id, data); err != nil {
		return ownerTransferPreview{}, err
	}
	return buildOwnerTransferPreview(p.TenantID, scope, id, data)
}

// Pure validation through contract steps 1–8 ONLY, never resolves a target or writes.
// No POST route calls this until login/edit/delete/Peer/target races are database-coordinated.
func prepareOwnerTransfer(p managementPrincipal, scope string, id int64, request any, data store.OwnerTransferSnapshot) (ownerTransferPreview, string, error) {
	var empty ownerTransferPreview
	if err := validateOwnerTransferPath(p, id); err != nil {
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

func buildOwnerTransferPreview(tenant, scope string, pathID int64, data store.OwnerTransferSnapshot) (ownerTransferPreview, error) {
	var result ownerTransferPreview
	var credentialID *int64
	if scope == ownerScopeGroup {
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
	var credential *store.OwnerTransferCredential
	identities := make([]store.OwnerTransferIdentity, 0)
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
	byID := make(map[int64][]store.OwnerTransferClient)
	for _, row := range data.Clients {
		byID[row.ID] = append(byID[row.ID], row)
	}
	clients := make([]store.OwnerTransferClient, 0, len(clientIDs))
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
	peers := make([]store.OwnerTransferPeer, 0)
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
	result = ownerTransferPreview{Scope: scope, CredentialID: credentialID, AffectedClients: make([]ownerAffectedClient, 0, len(clients)), AffectedClientCount: len(clients), CanTransfer: true, AccessRetained: true}
	if scope == ownerScopeSingle {
		result.ClientID = &pathID
	}
	if credential != nil {
		result.CredentialOwnerUsername = credential.OwnerUsername
		result.CredentialEnabled = &credential.Enabled
	}
	for _, row := range clients {
		result.AffectedClients = append(result.AffectedClients, ownerAffectedClient{row.ID, row.ClientName, row.OwnerUsername, row.Enabled})
	}
	if scope == ownerScopeSingle && len(clients) > 1 {
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
			Credential *store.OwnerTransferCredential
			Clients    []store.OwnerTransferClient
			Identities []store.OwnerTransferIdentity
			Peers      []store.OwnerTransferPeer
		}{"specus-owner-transfer-go-v1", tenant, scope, pathID, credential, clients, identities, peers}
		encoded, err := json.Marshal(canonical)
		if err != nil {
			return ownerTransferPreview{}, err
		}
		digest := sha256.Sum256(encoded)
		revision := hex.EncodeToString(digest[:])
		result.Revision = &revision
	}
	return result, nil
}

func (a *API) handleClientOwnerTransferPreview(w http.ResponseWriter, r *http.Request) {
	a.handleOwnerTransferPreview(w, r, ownerScopeSingle)
}
func (a *API) handleCredentialOwnerTransferPreview(w http.ResponseWriter, r *http.Request) {
	a.handleOwnerTransferPreview(w, r, ownerScopeGroup)
}
func (a *API) handleOwnerTransferPreview(w http.ResponseWriter, r *http.Request, scope string) {
	p, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := parseOwnerTransferID(p, r.PathValue("id"))
	if err != nil {
		a.writeOwnerTransferError(w, err)
		return
	}
	data, err := a.db.LoadOwnerTransferSnapshot(r.Context(), p.TenantID, scope, id)
	if err != nil {
		a.fail(w, err)
		return
	}
	preview, err := previewOwnerTransfer(p, scope, id, data)
	if err != nil {
		a.writeOwnerTransferError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}
func (a *API) writeOwnerTransferError(w http.ResponseWriter, err error) {
	if problem, ok := err.(*ownerTransferError); ok {
		writeJSON(w, problem.Status, map[string]string{"error": problem.Code, "code": problem.Code})
		return
	}
	a.fail(w, err)
}
