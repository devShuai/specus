package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// OwnerTransferWrite is constructed by the management service, never decoded from client JSON.
// BuiltInTarget is the existing configured password-login identity, not an extra auth mode.
type OwnerTransferWrite struct {
	Actor         ManagementWriteActor
	Scope         string
	PathID        int64
	Body          any
	AuditID       int64
	BuiltInTarget struct {
		Username, TenantID string
		Enabled            bool
	}
}

type OwnerTransferResult struct {
	Scope             string  `json:"scope"`
	TargetUsername    string  `json:"targetUsername"`
	CredentialID      *int64  `json:"credentialId"`
	AffectedClientIDs []int64 `json:"affectedClientIds"`
	Changed           bool    `json:"changed"`
	AccessRetained    bool    `json:"accessRetained"`
}

// AuditID is internal orchestration metadata. Commit proves durable ownership/audit, never
// cache invalidation, client delivery, or key revocation. No callback/network effect runs here.
type OwnerTransferOutcome struct {
	Response OwnerTransferResult
	AuditID  *int64 `json:"-"`
}

var errOwnerRangeChanged = errors.New("ownership range changed while acquiring locks")

type ownerTargetBinding struct {
	resolved bool
	key      string
}

// TransferClientOwnership is the internal write core. Public POST stays unregistered until
// ordinary CRUD, grant creation and durable runtime reconciliation join the same boundary.
func (db *DB) TransferClientOwnership(ctx context.Context, request OwnerTransferWrite) (OwnerTransferOutcome, error) {
	binding := &ownerTargetBinding{}
	for range 4 {
		outcome, err := db.transferClientOwnershipOnce(ctx, request, binding)
		if !errors.Is(err, errOwnerRangeChanged) || ctx.Err() != nil {
			return outcome, err
		}
	}
	return OwnerTransferOutcome{}, errOwnerRangeChanged
}

func (db *DB) transferClientOwnershipOnce(ctx context.Context, request OwnerTransferWrite, binding *ownerTargetBinding) (OwnerTransferOutcome, error) {
	var empty OwnerTransferOutcome
	if err := ValidateOwnerTransferPath(request.Actor, 1); err != nil {
		return empty, err
	}
	if request.Actor.BuiltIn && (!request.BuiltInTarget.Enabled || request.Actor.Username != request.BuiltInTarget.Username ||
		defaultTenant(request.Actor.TenantID) != defaultTenant(request.BuiltInTarget.TenantID)) {
		return empty, ErrManagementActorChanged
	}
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	hint := ""
	if body, ok := request.Body.(map[string]any); ok {
		hint, _ = body["targetUsername"].(string)
	}
	builtin := request.BuiltInTarget.Enabled && strings.TrimSpace(request.BuiltInTarget.Username) != "" &&
		defaultTenant(request.BuiltInTarget.TenantID) == defaultTenant(request.Actor.TenantID) &&
		NormalizeLoginName(hint) == NormalizeLoginName(request.BuiltInTarget.Username)
	actor, target, err := db.lockOwnerTransferActors(ctx, tx, request.Actor, hint, builtin, binding)
	if err != nil {
		return empty, err
	}
	if err := ValidateOwnerTransferPath(actor, request.PathID); err != nil {
		return empty, err
	}
	if _, ok := request.Body.(map[string]any); !ok || request.Body == nil {
		return empty, invalidOwnerTransfer()
	}
	locked, err := db.lockOwnerTransferRange(ctx, tx, actor.TenantID, request.Scope, request.PathID)
	if err != nil {
		return empty, err
	}
	current := locked.current
	preview, requestedTarget, err := PrepareOwnerTransfer(actor, request.Scope, request.PathID, request.Body, current)
	if err != nil {
		return empty, err
	}
	// Logical validation errors above keep their specified precedence. A newly discovered row
	// is never mutated without its ordered prerequisite lock; retry from a new transaction.
	if !locked.complete() {
		return empty, errOwnerRangeChanged
	}
	canonicalTarget := ""
	if builtin {
		canonicalTarget = request.BuiltInTarget.Username
	} else if target != nil && target.Enabled && target.TenantID == actor.TenantID &&
		NormalizeLoginName(target.Username) == NormalizeLoginName(requestedTarget) {
		canonicalTarget = target.Username
	}
	if canonicalTarget == "" {
		return empty, ownerError(400, "INVALID_TARGET_OWNER")
	}
	ids := make([]int64, 0, len(preview.AffectedClients))
	changed := false
	for _, client := range preview.AffectedClients {
		ids = append(ids, client.ID)
	}
	different := func(owner *string) bool { return owner == nil || *owner != canonicalTarget }
	for _, row := range current.Clients {
		changed = changed || different(row.OwnerUsername)
	}
	for _, row := range current.Credentials {
		changed = changed || different(row.OwnerUsername)
	}
	for _, row := range current.Peers {
		changed = changed || different(row.OwnerUsername)
	}
	outcome := OwnerTransferOutcome{Response: OwnerTransferResult{request.Scope, canonicalTarget, preview.CredentialID, ids, changed, true}}
	if !changed {
		if err := tx.Commit(); err != nil {
			return empty, err
		}
		return outcome, nil
	}
	if request.AuditID <= 0 {
		return empty, errors.New("server-generated ownership audit id required")
	}
	now := formatTime(time.Now().UTC())
	for _, row := range current.Clients {
		if err := db.writeOwnerOn(ctx, tx, "specus_client_account", actor.TenantID, row.ID, canonicalTarget, now); err != nil {
			return empty, err
		}
	}
	for _, row := range current.Credentials {
		if err := db.writeOwnerOn(ctx, tx, "specus_client_credential", actor.TenantID, row.ID, canonicalTarget, now); err != nil {
			return empty, err
		}
	}
	for _, row := range current.Peers {
		if err := db.writeOwnerOn(ctx, tx, "peer_mesh_device", actor.TenantID, row.ID, canonicalTarget, now); err != nil {
			return empty, err
		}
	}
	detail, err := json.Marshal(struct {
		Clients           []OwnerTransferClient     `json:"clients"`
		Credentials       []OwnerTransferCredential `json:"credentials"`
		Peers             []OwnerTransferPeer       `json:"peerDevices"`
		AffectedClientIDs []int64                   `json:"affectedClientIds"`
	}{current.Clients, current.Credentials, current.Peers, ids})
	if err != nil {
		return empty, err
	}
	if _, err := tx.ExecContext(ctx, db.rebind(`INSERT INTO client_owner_transfer_audit
		(id,tenant_id,occurred_at,actor,scope,path_id,target_username,credential_id,detail_json)
		VALUES(?,?,?,?,?,?,?,?,?)`), request.AuditID, actor.TenantID, now, actor.Username, request.Scope,
		request.PathID, canonicalTarget, preview.CredentialID, string(detail)); err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	auditID := request.AuditID
	outcome.AuditID = &auditID
	return outcome, nil
}

func (db *DB) lockOwnerTransferActors(ctx context.Context, tx *sql.Tx, actor ManagementWriteActor, requested string, builtin bool, binding *ownerTargetBinding) (ManagementWriteActor, *ManagementUser, error) {
	var err error
	if !binding.resolved {
		if !builtin && strings.TrimSpace(requested) != "" {
			hint, err := db.findManagementUserByLogin(ctx, tx, actor.TenantID, requested)
			if err != nil {
				return actor, nil, err
			}
			if hint != nil && hint.TenantID == defaultTenant(actor.TenantID) {
				binding.key = hint.AccountKey
			}
		}
		binding.resolved = true
	}
	keys := make(map[string]bool)
	if !actor.BuiltIn && actor.AccountKey != "" {
		keys[actor.AccountKey] = true
	}
	if binding.key != "" {
		keys[binding.key] = true
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	locked := make(map[string]*ManagementUser)
	for _, key := range ordered {
		user, err := db.lockManagementUserKey(ctx, tx, actor.TenantID, key)
		if err != nil {
			return actor, nil, err
		}
		locked[key] = user
	}
	actor, err = currentManagementWriteActor(actor, locked[actor.AccountKey])
	if err != nil {
		return actor, nil, err
	}
	if !actor.Admin {
		return actor, nil, ownerError(403, "FORBIDDEN")
	}
	var target *ManagementUser
	if binding.key != "" {
		target = locked[binding.key]
	}
	// Do not rebind a deleted/replaced/renamed target by its reusable public login name.
	if target != nil && NormalizeLoginName(target.Username) != NormalizeLoginName(requested) {
		target = nil
	}
	return actor, target, nil
}

func sortedOwnerIDs(values []int64) []int64 {
	set := make(map[int64]bool)
	for _, id := range values {
		set[id] = true
	}
	result := make([]int64, 0, len(set))
	for id := range set {
		result = append(result, id)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

type lockedOwnerRange struct {
	current                                 OwnerTransferSnapshot
	credentials, clients, identities, peers map[int64]bool
}

func (r lockedOwnerRange) complete() bool {
	for _, row := range r.current.Credentials {
		if !r.credentials[row.ID] {
			return false
		}
	}
	for _, row := range r.current.Clients {
		if !r.clients[row.ID] {
			return false
		}
	}
	for _, row := range r.current.Identities {
		if !r.identities[row.ID] {
			return false
		}
	}
	for _, row := range r.current.Peers {
		if !r.peers[row.ID] {
			return false
		}
	}
	return true
}

func (db *DB) lockOwnerTransferRange(ctx context.Context, tx *sql.Tx, tenant, scope string, id int64) (lockedOwnerRange, error) {
	var empty lockedOwnerRange
	hints, err := db.loadOwnerTransferSnapshotOn(ctx, tx, tenant, scope, id)
	if err != nil {
		return empty, err
	}
	credentials := make([]int64, 0)
	if scope == OwnerScopeGroup {
		credentials = append(credentials, id)
	}
	for _, row := range hints.Credentials {
		credentials = append(credentials, row.ID)
	}
	for _, row := range hints.Identities {
		credentials = append(credentials, row.CredentialID)
	}
	lockedCredentials := make(map[int64]bool)
	for _, key := range sortedOwnerIDs(credentials) {
		if _, err := db.lockCredentialForOwnership(ctx, tx, tenant, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return empty, err
		}
		lockedCredentials[key] = true
	}
	// Credential-locked discovery includes any login that committed before our credential lock.
	current, err := db.loadOwnerTransferSnapshotOn(ctx, tx, tenant, scope, id)
	if err != nil {
		return empty, err
	}
	clients := make([]int64, 0)
	if scope == OwnerScopeSingle {
		clients = append(clients, id)
	}
	for _, row := range current.Clients {
		clients = append(clients, row.ID)
	}
	for _, row := range current.Identities {
		clients = append(clients, row.ClientID)
	}
	lockedClients := make(map[int64]bool)
	for _, key := range sortedOwnerIDs(clients) {
		if _, err := db.lockClientForOwnership(ctx, tx, tenant, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return empty, err
		}
		lockedClients[key] = true
	}
	// Parents now exclude concurrent device creation/rename/delete. Child locks never precede
	// parent locks and no credential is discovered/locked after a child lock.
	current, err = db.loadOwnerTransferSnapshotOn(ctx, tx, tenant, scope, id)
	if err != nil {
		return empty, err
	}
	identityIDs := make([]int64, 0)
	peerIDs := make([]int64, 0)
	for _, row := range current.Identities {
		identityIDs = append(identityIDs, row.ID)
	}
	for _, row := range current.Peers {
		peerIDs = append(peerIDs, row.ID)
	}
	for _, key := range sortedOwnerIDs(identityIDs) {
		if err := db.lockOwnerChild(ctx, tx, "specus_client_identity", tenant, key); err != nil {
			return empty, err
		}
	}
	for _, key := range sortedOwnerIDs(peerIDs) {
		if err := db.lockOwnerChild(ctx, tx, "peer_mesh_device", tenant, key); err != nil {
			return empty, err
		}
	}
	current, err = db.loadOwnerTransferSnapshotOn(ctx, tx, tenant, scope, id)
	if err != nil {
		return empty, err
	}
	identitySet, peerSet := make(map[int64]bool), make(map[int64]bool)
	for _, key := range identityIDs {
		identitySet[key] = true
	}
	for _, key := range peerIDs {
		peerSet[key] = true
	}
	return lockedOwnerRange{current, lockedCredentials, lockedClients, identitySet, peerSet}, nil
}

func (db *DB) lockOwnerChild(ctx context.Context, tx *sql.Tx, table, tenant string, id int64) error {
	var found int64
	err := tx.QueryRowContext(ctx, db.rebind(`SELECT id FROM `+table+` WHERE id=? AND tenant_id=?`+db.ownershipLockSuffix()), id, tenant).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}

func (db *DB) writeOwnerOn(ctx context.Context, tx *sql.Tx, table, tenant string, id int64, target, now string) error {
	// Table identifiers come only from the three internal literal call sites above.
	if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE `+table+` SET owner_username=?,updated_at=? WHERE id=? AND tenant_id=?`), target, now, id, tenant); err != nil {
		return err
	}
	var storedTenant, storedOwner string
	err := tx.QueryRowContext(ctx, db.rebind(`SELECT tenant_id,owner_username FROM `+table+` WHERE id=? AND tenant_id=?`+db.ownershipLockSuffix()), id, tenant).Scan(&storedTenant, &storedOwner)
	if err != nil {
		return err
	}
	if storedTenant != tenant || storedOwner != target {
		return fmt.Errorf("ownership write postcondition failed")
	}
	return nil
}
