package connectivity

import (
	"context"
	"errors"
	"fmt"

	"github.com/devShuai/specus/implementations/go/server/internal/directhttp"
	"github.com/devShuai/specus/implementations/go/server/internal/nat"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
)

// NatDevice reaches devices through this process's session registry and NAT coordinator: the same
// HTTP stream path as public requests, without the public entry (no route Basic auth, no path
// rewrite, no traffic accounting or detail rows) and without the reconnect grace.
type NatDevice struct {
	Sessions    *session.Registry
	Coordinator *nat.Coordinator
}

// Presence reports the bound control session and data connection of clientName.
func (d NatDevice) Presence(clientName string) (bool, bool) {
	if d.Sessions == nil {
		return false, false
	}
	_, control := d.Sessions.Find(clientName)
	_, data := d.Sessions.FindData(clientName)
	return control, data
}

// Open writes OPEN and the request FIN of one probe on the client's data connection.
func (d NatDevice) Open(clientName string, metadata map[string]any) (Probe, error) {
	if d.Coordinator == nil {
		return nil, errors.New("NAT coordinator unavailable")
	}
	stream, err := d.Coordinator.OpenHTTPStream(clientName, metadata)
	if err != nil {
		if errors.Is(err, nat.ErrTooManyNatStreams) {
			return nil, ErrStreamLimit
		}
		return nil, err
	}
	if err := stream.FinishRequest(nil); err != nil {
		stream.Close()
		return nil, err
	}
	return natProbe{stream: stream}, nil
}

type natProbe struct{ stream *nat.HTTPStream }

func (p natProbe) Capability() int { return p.stream.HTTPRouteCapability() }

func (p natProbe) Await(ctx context.Context) (int, error) {
	head, err := p.stream.WaitResponseHead(ctx)
	if err != nil {
		var reset *directhttp.StreamResetError
		switch {
		case errors.As(err, &reset):
			return 0, &ResetError{Failure: reset.Failure}
		case ctx.Err() != nil:
			return 0, ctx.Err()
		default:
			// The data connection closed or was replaced, which resets every stream on it.
			return 0, fmt.Errorf("%w: %v", ErrLinkLost, err)
		}
	}
	// The NAT layer accepts a head only with a statusCode in 100..599; 0 would be reported as a
	// protocol error, never as an answer.
	status, _ := nat.ResponseStatus(head)
	return status, nil
}

func (p natProbe) Abandon() { p.stream.Abandon(probeResetCode, probeResetReason) }
