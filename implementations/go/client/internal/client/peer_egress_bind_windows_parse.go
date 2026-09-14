package client

import (
	"encoding/binary"
	"net/netip"
	"strconv"
)

// Reading the Windows routing table as GetIpForwardTable2 and GetIpInterfaceTable return it.
//
// Not named _windows.go: the parsers are driven by the shared vectors on every platform, and only
// the calls that fetch the bytes are Windows-only.
//
// Read natively rather than through Get-NetRoute because the choice is made on every connect. A
// PowerShell query costs 419 ms; the two calls cost microseconds and need no cache, so the next
// connect after a network change already sees it.
//
// The offsets are the SDK's MIB_IPFORWARD_ROW2 and MIB_IPINTERFACE_ROW on 64-bit Windows, measured
// against Get-NetRoute and Get-NetIPInterface, and checked against them again on every Windows CI
// run by TestWindowsBindTablesMatchGetNetRoute.
const (
	windowsMibTableHeader = 8

	windowsForwardRowSize        = 104
	windowsForwardInterfaceIndex = 8
	windowsForwardPrefixFamily   = 12
	windowsForwardPrefixAddress  = 16
	windowsForwardPrefixLength   = 40
	windowsForwardMetric         = 84

	windowsInterfaceRowSize              = 168
	windowsInterfaceFamily               = 0
	windowsInterfaceIndex                = 16
	windowsInterfaceMetric               = 148
	windowsInterfaceConnected            = 156
	windowsInterfaceDisableDefaultRoutes = 166

	windowsAddressFamilyIPv4 = 2

	// windowsIPUnicastIf is IP_UNICAST_IF, at level IPPROTO_IP.
	windowsIPUnicastIf = 31
)

type windowsForwardRow struct {
	InterfaceIndex uint32
	Prefix         string
	Metric         uint32
}

type windowsInterfaceRow struct {
	InterfaceIndex       uint32
	Metric               uint32
	Connected            bool
	DisableDefaultRoutes bool
}

// windowsMibRows cuts a MIB table into its rows: a ULONG count, padding to offset 8, then the rows.
//
// A buffer shorter than the count claims is refused whole. Reading the rows it does hold would be
// reading a table that is not the one the system returned.
func windowsMibRows(raw []byte, size int) ([][]byte, bool) {
	if len(raw) < windowsMibTableHeader {
		return nil, false
	}
	count := uint64(binary.LittleEndian.Uint32(raw))
	if uint64(len(raw)) < uint64(windowsMibTableHeader)+count*uint64(size) {
		return nil, false
	}
	rows := make([][]byte, 0, count)
	for i := uint64(0); i < count; i++ {
		start := windowsMibTableHeader + int(i)*size
		rows = append(rows, raw[start:start+size])
	}
	return rows, true
}

// parseWindowsForwardTable reads the IPv4 rows of a MIB_IPFORWARD_TABLE2, prefixes masked.
func parseWindowsForwardTable(raw []byte) ([]windowsForwardRow, bool) {
	rows, ok := windowsMibRows(raw, windowsForwardRowSize)
	if !ok {
		return nil, false
	}
	parsed := make([]windowsForwardRow, 0, len(rows))
	for _, row := range rows {
		if binary.LittleEndian.Uint16(row[windowsForwardPrefixFamily:]) != windowsAddressFamilyIPv4 {
			continue
		}
		length := int(row[windowsForwardPrefixLength])
		if length > 32 {
			continue
		}
		address := netip.AddrFrom4([4]byte(row[windowsForwardPrefixAddress : windowsForwardPrefixAddress+4]))
		parsed = append(parsed, windowsForwardRow{
			InterfaceIndex: binary.LittleEndian.Uint32(row[windowsForwardInterfaceIndex:]),
			Prefix:         netip.PrefixFrom(address, length).Masked().String(),
			Metric:         binary.LittleEndian.Uint32(row[windowsForwardMetric:]),
		})
	}
	return parsed, true
}

// parseWindowsInterfaceTable reads the IPv4 rows of a MIB_IPINTERFACE_TABLE.
func parseWindowsInterfaceTable(raw []byte) ([]windowsInterfaceRow, bool) {
	rows, ok := windowsMibRows(raw, windowsInterfaceRowSize)
	if !ok {
		return nil, false
	}
	parsed := make([]windowsInterfaceRow, 0, len(rows))
	for _, row := range rows {
		if binary.LittleEndian.Uint16(row[windowsInterfaceFamily:]) != windowsAddressFamilyIPv4 {
			continue
		}
		parsed = append(parsed, windowsInterfaceRow{
			InterfaceIndex:       binary.LittleEndian.Uint32(row[windowsInterfaceIndex:]),
			Metric:               binary.LittleEndian.Uint32(row[windowsInterfaceMetric:]),
			Connected:            row[windowsInterfaceConnected] != 0,
			DisableDefaultRoutes: row[windowsInterfaceDisableDefaultRoutes] != 0,
		})
	}
	return parsed, true
}

// windowsBindRoutes joins the two tables into candidate routes.
//
// Windows ranks two routes of equal length by the route's metric plus its interface's metric. A
// route on an interface that is not connected is not used, nor is a default route on an interface
// that sets DisableDefaultRoutes -- which a VPN does to keep its default from taking over. A route
// whose interface has no IPv4 row is not used either: there is nothing to say it is up.
func windowsBindRoutes(forward []windowsForwardRow, interfaces []windowsInterfaceRow) []egressBindRoute {
	byIndex := make(map[uint32]windowsInterfaceRow, len(interfaces))
	for _, row := range interfaces {
		byIndex[row.InterfaceIndex] = row
	}
	routes := make([]egressBindRoute, 0, len(forward))
	for _, row := range forward {
		route := egressBindRoute{
			Prefix:    row.Prefix,
			Interface: strconv.FormatUint(uint64(row.InterfaceIndex), 10),
			Metric:    int64(row.Metric),
		}
		if iface, ok := byIndex[row.InterfaceIndex]; ok {
			route.Metric += int64(iface.Metric)
			route.Usable = iface.Connected && !(row.Prefix == "0.0.0.0/0" && iface.DisableDefaultRoutes)
		}
		routes = append(routes, route)
	}
	return routes
}

// windowsUnicastInterfaceOption is the IP_UNICAST_IF value: the index in network byte order.
//
// In host order setsockopt refuses it outright, so the mistake is loud; macOS takes the same kind of
// value in host order, which is why the two are spelled out rather than shared.
func windowsUnicastInterfaceOption(index uint32) []byte {
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], index)
	return value[:]
}
