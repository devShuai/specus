//go:build windows

package client

import "syscall"

// Winsock error codes, which is what Go reports for socket failures on Windows: ConnectEx and
// WSARecv complete through WSAGetOverlappedResult. syscall names only the two reset codes, and its
// ECONNREFUSED and friends are invented values no Windows call returns.
const (
	wsaENETDOWN     syscall.Errno = 10050
	wsaENETUNREACH  syscall.Errno = 10051
	wsaETIMEDOUT    syscall.Errno = 10060
	wsaECONNREFUSED syscall.Errno = 10061
	wsaEHOSTDOWN    syscall.Errno = 10064
	wsaEHOSTUNREACH syscall.Errno = 10065
)

var (
	connectRefusedErrnos = []syscall.Errno{wsaECONNREFUSED}
	connectTimeoutErrnos = []syscall.Errno{wsaETIMEDOUT}
	unreachableErrnos    = []syscall.Errno{
		wsaENETUNREACH, wsaEHOSTUNREACH, wsaENETDOWN, wsaEHOSTDOWN, syscall.WSAECONNRESET,
	}
	// Once connected, a reset or abort from the target before the response head.
	upstreamResetErrnos = []syscall.Errno{syscall.WSAECONNRESET, syscall.WSAECONNABORTED}
)
