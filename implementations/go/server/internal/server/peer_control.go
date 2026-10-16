package server

import (
	"context"
	"errors"
	"log/slog"

	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// peerSignalHandler is the part of the peer mesh the PEER_CONTROL route needs.
type peerSignalHandler interface {
	HandleSignalBound(ctx context.Context, request protocol.MessageRequest, original store.RuntimeClientReference) error
}

// peerControlHandler routes a client's PEER_CONTROL message into the mesh.
//
// The read loop closes a connection on any error its handler returns, which is right for a
// message that breaks the protocol and wrong for one that merely could not be delivered. A peer
// that has just gone offline is not the sender's doing, and every client still signalling it --
// announcing candidates, answering a probe -- was being disconnected for it. So an undeliverable
// signal is dropped here and everything else still closes, now with the reason in the log instead
// of only as IO_ERROR on the connection record.
func peerControlHandler(mesh peerSignalHandler, logger *slog.Logger) func(*control.Conn, protocol.MessageRequest) error {
	return func(conn *control.Conn, request protocol.MessageRequest) error {
		original, ok := conn.RuntimeReference()
		if !ok {
			return errors.New("peer control lacks original authenticated runtime")
		}
		return routePeerSignal(mesh, logger, conn.Context(), request, original)
	}
}

func routePeerSignal(mesh peerSignalHandler, logger *slog.Logger, ctx context.Context,
	request protocol.MessageRequest, original store.RuntimeClientReference) error {
	clientName := original.ClientName
	err := mesh.HandleSignalBound(ctx, request, original)
	if err == nil {
		return nil
	}
	if errors.Is(err, peermesh.ErrUndeliverable) {
		logger.Debug("dropped undeliverable peer signal",
			"client", clientName, "to", request.ToClientName, "err", err)
		return nil
	}
	logger.Warn("peer signal rejected; closing the sender's connection",
		"client", clientName, "to", request.ToClientName, "err", err)
	return err
}
