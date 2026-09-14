//go:build windows

package client

import (
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"
)

// Binding an egress socket to an interface on Windows, with IP_UNICAST_IF.
//
// The table is read natively on every connect; see peer_egress_bind_windows_parse.go for why.

var (
	iphlpapiBind            = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIpForwardTable2  = iphlpapiBind.NewProc("GetIpForwardTable2")
	procGetIpInterfaceTable = iphlpapiBind.NewProc("GetIpInterfaceTable")
	procFreeMibTable        = iphlpapiBind.NewProc("FreeMibTable")
)

func newEgressSocketBinder(tunnel func() string) *egressSocketBinder {
	return &egressSocketBinder{tunnel: tunnel, routes: readWindowsBindRoutes, tunnelKey: windowsInterfaceKey}
}

// windowsInterfaceKey resolves an adapter's name to its index, the form the table carries.
//
// Go's interface names on Windows are the adapters' friendly names, which is what the Wintun
// adapter was created with.
func windowsInterfaceKey(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	return strconv.Itoa(iface.Index)
}

func (binder *egressSocketBinder) control(_ string, address string, connection syscall.RawConn) error {
	chosen, err := binder.choose(address)
	if err != nil {
		return err
	}
	index, err := strconv.ParseUint(chosen, 10, 32)
	if err != nil {
		return fmt.Errorf("bind egress socket: interface %q is not an index", chosen)
	}
	option := windowsUnicastInterfaceOption(uint32(index))
	var setErr error
	if err := connection.Control(func(handle uintptr) {
		setErr = syscall.Setsockopt(syscall.Handle(handle), syscall.IPPROTO_IP, windowsIPUnicastIf,
			&option[0], int32(len(option)))
	}); err != nil {
		return err
	}
	if setErr != nil {
		return fmt.Errorf("bind egress socket to interface %d: %w", index, setErr)
	}
	return nil
}

func readWindowsBindRoutes() ([]egressBindRoute, error) {
	forwardRaw, err := readWindowsMibTable(procGetIpForwardTable2, windowsForwardRowSize)
	if err != nil {
		return nil, err
	}
	interfaceRaw, err := readWindowsMibTable(procGetIpInterfaceTable, windowsInterfaceRowSize)
	if err != nil {
		return nil, err
	}
	forward, ok := parseWindowsForwardTable(forwardRaw)
	if !ok {
		return nil, fmt.Errorf("GetIpForwardTable2 returned a table shorter than its count")
	}
	interfaces, ok := parseWindowsInterfaceTable(interfaceRaw)
	if !ok {
		return nil, fmt.Errorf("GetIpInterfaceTable returned a table shorter than its count")
	}
	return windowsBindRoutes(forward, interfaces), nil
}

// readWindowsMibTable copies one IPv4 MIB table out of the memory the API allocated, then frees it.
//
// The out parameter is a typed pointer rather than a uintptr, so the address never passes through an
// integer on its way back to a pointer.
func readWindowsMibTable(proc *syscall.LazyProc, rowSize int) ([]byte, error) {
	var table *uint32
	status, _, _ := proc.Call(uintptr(syscall.AF_INET), uintptr(unsafe.Pointer(&table)))
	if status != 0 {
		return nil, fmt.Errorf("%s: %w", proc.Name, syscall.Errno(status))
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))
	size := windowsMibTableHeader + int(*table)*rowSize
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(table)), size)...), nil
}
