package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

type fakeSignalMesh struct{ err error }

func (m fakeSignalMesh) HandleSignalSession(context.Context, protocol.MessageRequest, string, int64) error {
	return m.err
}

// The read loop closes a connection on any error its handler returns. A signal to a peer that has
// just gone must not be one: every client still signalling it was being disconnected for it.
func TestUndeliverablePeerSignalDoesNotCloseTheSender(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	request := protocol.MessageRequest{ToClientName: "gone", MessageType: protocol.MessageTypePeerControl}

	offline := fmt.Errorf("%w: target peer is offline: gone", peermesh.ErrUndeliverable)
	if err := routePeerSignal(fakeSignalMesh{offline}, logger, context.Background(), request, "sender", 1); err != nil {
		t.Errorf("an undeliverable signal returned %v, which would close the sender's connection", err)
	}

	violation := errors.New("toClientName is required")
	if err := routePeerSignal(fakeSignalMesh{violation}, logger, context.Background(), request, "sender", 1); !errors.Is(err, violation) {
		t.Errorf("a protocol violation returned %v, want it passed on so the connection closes", err)
	}
}
