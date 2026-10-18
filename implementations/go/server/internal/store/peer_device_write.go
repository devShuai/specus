package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"
)

// PeerDeviceSeed allocates IDs outside the transaction. CandidateIP must be a pure computation
// using the current locked parent and zero-based probe: no SQL, network I/O, or mutable caches.
// The store, not the callback, checks occupancy and owns all writes. Existing VIPs never change.
type PeerDeviceSeed struct {
	ID          int64
	CIDR        string
	Now         time.Time
	CandidateIP func(ClientAccount, uint64) (string, error)
}

const peerDeviceWriteColumns = `id, tenant_id, owner_username, client_id, client_name, virtual_ip, cidr,
	public_key, nat_type, nat_mapping_behavior, nat_filtering_behavior, nat_behavior_discovery,
	last_endpoint, virtual_device_mode, virtual_device_name, virtual_device_status,
	virtual_device_error, virtual_device_updated_at, enabled, last_seen_at, created_at, updated_at`

func (db *DB) peerDeviceForWrite(ctx context.Context, tx *sql.Tx, tenant string, clientID int64) (*PeerMeshDevice, error) {
	device, err := scanPeerMeshDevice(tx.QueryRowContext(ctx, db.rebind(`SELECT `+peerDeviceWriteColumns+
		` FROM peer_mesh_device WHERE tenant_id = ? AND client_id = ?`+db.ownershipLockSuffix()), defaultTenant(tenant), clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &device, nil
}

// ObservePeerMeshDevice coordinates runtime observations with rename/transfer/delete. The
// observer receives a current row and must be pure. It cannot change owner/name, enabled, IDs,
// VIP/CIDR or creation time: those fields are sealed again before writing. No network happens
// under the transaction. A missing parent fails closed instead of creating an orphan device.
func (db *DB) ObservePeerMeshDevice(ctx context.Context, tenant string, clientID int64, seed PeerDeviceSeed,
	observe func(*PeerMeshDevice)) (*PeerMeshDevice, error) {
	if observe == nil {
		return nil, errors.New("peer observation is required")
	}
	var lastErr error
	for range 4 {
		device, err := db.observePeerMeshDeviceOnce(ctx, tenant, clientID, seed, observe)
		if err == nil || !isUniqueConstraintError(err) || ctx.Err() != nil {
			return device, err
		}
		// Two different parent locks can choose one free VIP on a row-locking database.
		// Roll back the failed insert (essential on PostgreSQL), then inspect current occupancy.
		lastErr = err
	}
	return nil, lastErr
}

func (db *DB) observePeerMeshDeviceOnce(ctx context.Context, tenant string, clientID int64,
	seed PeerDeviceSeed, observe func(*PeerMeshDevice)) (*PeerMeshDevice, error) {
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	parent, err := db.lockClientForOwnership(ctx, tx, tenant, clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if parent.TenantID != defaultTenant(tenant) {
		return nil, ErrNotFound
	}
	device, err := db.peerDeviceForWrite(ctx, tx, parent.TenantID, parent.ID)
	if err != nil {
		return nil, err
	}
	created := device == nil
	if created {
		if seed.ID <= 0 || seed.CandidateIP == nil {
			return nil, errors.New("invalid peer device seed")
		}
		prefix, err := netip.ParsePrefix(seed.CIDR)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() > 30 {
			return nil, errors.New("invalid peer device address pool")
		}
		var ip string
		usable := (uint64(1) << uint(32-prefix.Bits())) - 2
		for probe := uint64(0); ; probe++ {
			if probe >= usable {
				return nil, errors.New("peer device address pool exhausted")
			}
			ip, err = seed.CandidateIP(*parent, probe)
			if err != nil {
				return nil, err
			}
			address, err := netip.ParseAddr(ip)
			if err != nil || !address.Is4() || !prefix.Contains(address) || address == prefix.Masked().Addr() || !prefix.Contains(address.Next()) {
				return nil, errors.New("peer address candidate outside configured pool")
			}
			var occupied int64
			err = tx.QueryRowContext(ctx, db.rebind(`SELECT id FROM peer_mesh_device WHERE tenant_id = ? AND virtual_ip = ?`), parent.TenantID, ip).Scan(&occupied)
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			if err != nil {
				return nil, err
			}
		}
		device = &PeerMeshDevice{ID: seed.ID, TenantID: parent.TenantID, ClientID: parent.ID,
			VirtualIP: ip, CIDR: seed.CIDR, CreatedAt: seed.Now, UpdatedAt: seed.Now, Enabled: false}
	}
	sealed := *device
	observe(device)
	device.ID, device.TenantID, device.ClientID = sealed.ID, sealed.TenantID, sealed.ClientID
	device.VirtualIP, device.CIDR = sealed.VirtualIP, sealed.CIDR
	device.Enabled, device.CreatedAt = sealed.Enabled, sealed.CreatedAt
	device.OwnerUsername, device.ClientName = defaultOwner(parent.OwnerUsername), parent.ClientName
	if created {
		err = db.insertPeerMeshDeviceOn(ctx, tx, *device)
	} else {
		err = db.updatePeerMeshDeviceOn(ctx, tx, *device)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return device, nil
}

// SetPeerMeshDeviceEnabled revalidates the current management actor and parent owner before
// applying only the requested flag to a locked, current device. Runtime metadata is preserved.
func (db *DB) SetPeerMeshDeviceEnabled(ctx context.Context, actor ManagementWriteActor, clientID int64,
	enabled *bool, now time.Time) (*PeerMeshDevice, error) {
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err = db.lockManagementWriteActor(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	parent, err := db.lockClientForOwnership(ctx, tx, actor.TenantID, clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if parent.TenantID != defaultTenant(actor.TenantID) || (!actor.Admin && parent.OwnerUsername != actor.Username) {
		return nil, ErrNotFound
	}
	device, err := db.peerDeviceForWrite(ctx, tx, parent.TenantID, parent.ID)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, ErrNotFound
	}
	if enabled != nil {
		device.Enabled = *enabled
	}
	device.OwnerUsername, device.ClientName = defaultOwner(parent.OwnerUsername), parent.ClientName
	device.UpdatedAt = now
	if err := db.updatePeerMeshDeviceOn(ctx, tx, *device); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return device, nil
}
