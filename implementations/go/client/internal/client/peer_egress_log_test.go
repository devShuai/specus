package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// The egress logs why a dial failed and never where it went: the error texts carry the address.
func TestEgressConnectReasonNamesTheCauseWithoutTheAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().String()
	_ = listener.Close()
	_, refused := net.DialTimeout("tcp4", closed, 5*time.Second)
	if refused == nil {
		t.Skip("a closed local port accepted a connection")
	}
	if !strings.Contains(refused.Error(), "127.0.0.1") {
		t.Logf("precondition: the dial error no longer names the address: %v", refused)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	_, timedOut := (&net.Dialer{}).DialContext(ctx, "tcp4", "192.0.2.1:9")

	cases := map[string]error{
		"refused":                     refused,
		"no route outside the tunnel": fmt.Errorf("bind egress socket for 203.0.113.10: %w", errEgressNoPhysicalRoute),
		"error":                       errors.New("203.0.113.10:80: something else"),
		"no socket":                   nil,
	}
	if timedOut != nil {
		cases["timed out"] = timedOut
	}
	for want, cause := range cases {
		if got := egressConnectReason(cause); got != want {
			t.Errorf("reason for %v = %q, want %q", cause, got, want)
		}
	}
}
