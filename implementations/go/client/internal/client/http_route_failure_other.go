//go:build !windows

package client

import "syscall"

var (
	connectRefusedErrnos = []syscall.Errno{syscall.ECONNREFUSED}
	// The operating system gives up on a SYN long after the client's own connect timeout, but
	// when it does it is the same failure.
	connectTimeoutErrnos = []syscall.Errno{syscall.ETIMEDOUT}
	unreachableErrnos    = []syscall.Errno{
		syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN, syscall.EHOSTDOWN,
		syscall.ECONNRESET,
	}
	// Once connected, a reset or abort from the target before the response head.
	upstreamResetErrnos = []syscall.Errno{syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE}
)
