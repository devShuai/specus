// Package ownership consumes committed ownership audits independently in every process.
package ownership

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type Reconciler interface {
	ReconcileOwnership(context.Context, string, []int64) error
}

type Notifications struct {
	db         *store.DB
	reconciler Reconciler
	logger     *slog.Logger
	node       string
	busy       atomic.Bool
	after      int64 // fairness only; wrap on an empty page, never a durable high-water mark
	wake       chan struct{}
}

func New(db *store.DB, reconciler Reconciler, logger *slog.Logger) (*Notifications, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	if db == nil || reconciler == nil {
		return nil, errors.New("ownership notification dependencies required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Notifications{db: db, reconciler: reconciler, logger: logger, node: hex.EncodeToString(id[:]), wake: make(chan struct{}, 1)}, nil
}

// A request may be cancelled just after commit. This hint does not inherit its context;
// the durable audit and periodic polling are the retry if a hint is coalesced or lost.
func (n *Notifications) Committed() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

func affectedClients(event store.OwnerTransferEvent) ([]int64, error) {
	var payload struct {
		IDs *[]json.RawMessage `json:"affectedClientIds"`
	}
	if err := json.Unmarshal([]byte(event.DetailJSON), &payload); err != nil || payload.IDs == nil {
		return nil, errors.New("invalid ownership journal client list")
	}
	seen := map[int64]bool{}
	for _, value := range *payload.IDs {
		id, err := strconv.ParseInt(strings.TrimSpace(string(value)), 10, 64)
		if err != nil || id <= 0 || id > 9007199254740991 {
			return nil, errors.New("invalid ownership journal client ID")
		}
		seen[id] = true
	}
	ids := []int64{}
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func (n *Notifications) Drain(ctx context.Context) error {
	if !n.busy.CompareAndSwap(false, true) {
		return nil
	}
	defer n.busy.Store(false)
	events, err := n.db.PendingOwnerTransferEvents(ctx, n.node, n.after)
	if err != nil {
		return err
	}
	if len(events) == 0 && n.after != 0 {
		n.after = 0
		events, err = n.db.PendingOwnerTransferEvents(ctx, n.node, 0)
		if err != nil {
			return err
		}
	}
	var failures []error
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		n.after = event.ID
		ids, err := affectedClients(event)
		if err == nil {
			err = n.reconciler.ReconcileOwnership(ctx, event.TenantID, ids)
		}
		if err == nil {
			err = n.db.AcknowledgeOwnerTransferEvent(ctx, n.node, event)
		}
		if err != nil {
			// Never log the historical JSON or raw database/connection error payload.
			n.logger.Warn("ownership reconciliation remains pending", "event", event.ID, "errorClass", fmt.Sprintf("%T", err))
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (n *Notifications) Run(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := n.Drain(ctx); err != nil && ctx.Err() == nil {
			n.logger.Warn("ownership journal scan incomplete", "errorClass", fmt.Sprintf("%T", err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-n.wake:
		}
	}
}
