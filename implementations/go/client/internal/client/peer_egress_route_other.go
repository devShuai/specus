//go:build !linux

package client

import "errors"

// Route takeover is Linux-only in phase one.
//
// Refusing rather than doing nothing: a consumer that silently installed no routes would send every
// destination out locally while reporting that its rules were applied, which is the leak this whole
// feature exists to prevent. Windows and macOS takeover is P5.
type unsupportedEgressRouteCommander struct{}

var errEgressRoutesUnsupported = errors.New("egress route takeover is not implemented on this platform")

func newEgressRouteCommanderForPlatform(_ string) egressRouteCommander {
	return unsupportedEgressRouteCommander{}
}

func (unsupportedEgressRouteCommander) Conflict(egressRoute) (bool, string) { return false, "" }
func (unsupportedEgressRouteCommander) Install(egressRoute) error           { return errEgressRoutesUnsupported }
func (unsupportedEgressRouteCommander) Remove(egressRoute) error            { return errEgressRoutesUnsupported }
