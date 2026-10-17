package management

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

const ownerScopeSingle = store.OwnerScopeSingle
const ownerScopeGroup = store.OwnerScopeGroup

type ownerTransferError = store.OwnerTransferError
type ownerAffectedClient = store.OwnerAffectedClient
type ownerTransferPreview = store.OwnerTransferPreview

func ownerWriteActor(p managementPrincipal) store.ManagementWriteActor {
	return store.ManagementWriteActor{Username: p.Username, TenantID: p.TenantID, AccountKey: p.AccountKey,
		Admin: p.Admin, BuiltIn: p.BuiltIn, OIDCIdentityKey: p.OIDCIdentityKey, OIDCIssuer: p.OIDCIssuer, OIDCSubject: p.OIDCSubject}
}
func parseOwnerTransferID(p managementPrincipal, text string) (int64, error) {
	return store.ParseOwnerTransferID(ownerWriteActor(p), text)
}
func previewOwnerTransfer(p managementPrincipal, scope string, id int64, data store.OwnerTransferSnapshot) (ownerTransferPreview, error) {
	return store.PreviewOwnerTransfer(ownerWriteActor(p), scope, id, data)
}
func prepareOwnerTransfer(p managementPrincipal, scope string, id int64, request any, data store.OwnerTransferSnapshot) (ownerTransferPreview, string, error) {
	return store.PrepareOwnerTransfer(ownerWriteActor(p), scope, id, request, data)
}

// AuditID is allocated by the server, never from request JSON. The audit and owner
// writes commit atomically; the process-wide journal consumer retries runtime convergence.
func (a *API) commitOwnerTransfer(ctx context.Context, p managementPrincipal, scope, textID string, body any) (store.OwnerTransferOutcome, error) {
	id, err := parseOwnerTransferID(p, textID)
	if err != nil {
		return store.OwnerTransferOutcome{}, err
	}
	request := store.OwnerTransferWrite{Actor: ownerWriteActor(p), Scope: scope, PathID: id, Body: body, AuditID: auth.NewClientID()}
	request.BuiltInTarget.Username = a.adminUsername()
	request.BuiltInTarget.TenantID = a.defaultTenant()
	request.BuiltInTarget.Enabled = a.tokens.PasswordLoginEnabled()
	outcome, err := a.db.TransferClientOwnership(ctx, request)
	if err == nil && outcome.AuditID != nil && a.ownerNotifications != nil {
		a.ownerNotifications.Committed()
	}
	return outcome, err
}

func (a *API) handleClientOwnerTransfer(w http.ResponseWriter, r *http.Request) {
	a.handleOwnerTransfer(w, r, ownerScopeSingle)
}
func (a *API) handleCredentialOwnerTransfer(w http.ResponseWriter, r *http.Request) {
	a.handleOwnerTransfer(w, r, ownerScopeGroup)
}
func (a *API) handleOwnerTransfer(w http.ResponseWriter, r *http.Request, scope string) {
	p, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	// Role precedes malformed JSON/path; resource and request-field precedence
	// then comes from the same coordinated writer used by internal callers.
	if _, err := parseOwnerTransferID(p, r.PathValue("id")); err != nil {
		a.writeOwnerTransferError(w, err)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	decoder.UseNumber()
	var body any
	if err := decoder.Decode(&body); err != nil {
		a.writeOwnerTransferError(w, &ownerTransferError{Status: 400, Code: "INVALID_TRANSFER_REQUEST"})
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		a.writeOwnerTransferError(w, &ownerTransferError{Status: 400, Code: "INVALID_TRANSFER_REQUEST"})
		return
	}
	outcome, err := a.commitOwnerTransfer(r.Context(), p, scope, r.PathValue("id"), body)
	if err != nil {
		a.writeOwnerTransferError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, outcome.Response)
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
