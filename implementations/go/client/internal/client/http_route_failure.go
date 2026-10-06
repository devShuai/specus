package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptrace"
	"os"
	"slices"
	"sync/atomic"
	"syscall"
)

// httpRouteCapabilityVersion is environment.clientHttpRouteCapabilities.version.
const httpRouteCapabilityVersion = 1

// httpRouteFailure says why an HTTP route stream failed before its response OPEN. It travels as
// metadata.failure on the NAT RST, next to the unchanged value and reason, and lets the
// connectivity check name the stage that failed (protocol/spec/service-connectivity-check.md
// section 6.2).
//
// The set is closed. Anything the client cannot place is sent without the key, which a server
// reports as TARGET_UNVERIFIED: an unclassified reset is better than a wrong diagnosis.
type httpRouteFailure string

const (
	httpRouteFailureRouteNotLoaded httpRouteFailure = "route-not-loaded"
	httpRouteFailureTargetInvalid  httpRouteFailure = "target-invalid"
	httpRouteFailureConnectRefused httpRouteFailure = "connect-refused"
	httpRouteFailureConnectTimeout httpRouteFailure = "connect-timeout"
	httpRouteFailureDNSFailed      httpRouteFailure = "dns-failed"
	httpRouteFailureTLSFailed      httpRouteFailure = "tls-failed"
	httpRouteFailureUnreachable    httpRouteFailure = "unreachable"
	httpRouteFailureProtocolError  httpRouteFailure = "protocol-error"
)

// upstreamTLSError is a failed TLS handshake with the forwarding target, after the TCP connect
// succeeded. Wrapping it is what keeps the handshake apart: by the time http.Client returns, an EOF
// from a handshake and an EOF from a response that never came look the same.
type upstreamTLSError struct{ err error }

func (e *upstreamTLSError) Error() string { return e.err.Error() }
func (e *upstreamTLSError) Unwrap() error { return e.err }

// upstreamProgress records how far a forwarded request got, from the transport's own trace hooks.
// A failure after the connection was up is the target breaking the exchange, which no error type
// says for every case: a malformed status line, for one, is an unexported net/http error.
type upstreamProgress struct {
	connected     atomic.Bool
	responseBytes atomic.Bool
}

func (progress *upstreamProgress) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn:              func(httptrace.GotConnInfo) { progress.connected.Store(true) },
		GotFirstResponseByte: func() { progress.responseBytes.Store(true) },
	}
}

// classifyUpstreamFailure places an error from forwarding a request to the target, before any
// response head, in the failure set. It reads error types, errno values and how far the request
// got, never the message text, which changes with the platform, its language and Go releases.
// It returns "" for what it cannot place, including a timeout waiting for the response head:
// that is neither a refused connect nor a broken response.
func classifyUpstreamFailure(err error, progress *upstreamProgress) httpRouteFailure {
	if err == nil {
		return ""
	}
	var handshake *upstreamTLSError
	if errors.As(err, &handshake) {
		// The connect timeout spans the handshake, as it did with tls.Dialer and as
		// SocketsHttpHandler's ConnectTimeout does, so expiring there is still the connect timeout.
		if isDeadline(handshake.err) {
			return httpRouteFailureConnectTimeout
		}
		return httpRouteFailureTLSFailed
	}
	var dial *net.OpError
	if errors.As(err, &dial) && dial.Op == "dial" {
		return classifyDialFailure(dial.Err)
	}
	if progress == nil || !progress.connected.Load() {
		return ""
	}
	if isTimeout(err) {
		return ""
	}
	// The target sent part of a response head and the transport could not use it, or it closed or
	// reset the connection before sending one.
	if progress.responseBytes.Load() || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return httpRouteFailureProtocolError
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && slices.Contains(upstreamResetErrnos, errno) {
		return httpRouteFailureProtocolError
	}
	return ""
}

// classifyDialFailure places the error inside a dial *net.OpError: the name lookup and the TCP
// connect.
func classifyDialFailure(err error) httpRouteFailure {
	// The dialer's deadline is the only one on the connect, so it is the client's connect timeout
	// whether it expired resolving the name or connecting. A resolver that gives up on its own
	// reports a *net.DNSError that does not unwrap to a deadline, and is a lookup failure.
	if isDeadline(err) {
		return httpRouteFailureConnectTimeout
	}
	var lookup *net.DNSError
	if errors.As(err, &lookup) {
		return httpRouteFailureDNSFailed
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return ""
	}
	switch {
	case slices.Contains(connectRefusedErrnos, errno):
		return httpRouteFailureConnectRefused
	case slices.Contains(connectTimeoutErrnos, errno):
		return httpRouteFailureConnectTimeout
	case slices.Contains(unreachableErrnos, errno):
		return httpRouteFailureUnreachable
	}
	return ""
}

// isTimeout reports whether any error in the chain says it is a timeout. *url.Error answers only
// for the error it wraps directly, which is not always the one that timed out.
func isTimeout(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
			return true
		}
	}
	return false
}

// isDeadline reports a context deadline, or a socket deadline set from one: when the poller wins
// the race with the context, the connect returns os.ErrDeadlineExceeded, which does not match
// context.DeadlineExceeded.
func isDeadline(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
}
