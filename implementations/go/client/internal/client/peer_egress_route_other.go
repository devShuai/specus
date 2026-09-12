//go:build !linux && !windows && !darwin

package client

import "errors"

// Route takeover on the platforms that do not have it.
//
// Linux, Windows and macOS all have it now, so what is left is whatever else this ever builds for.
//
// Refusing rather than doing nothing: a consumer that silently installed no routes would send every
// destination out locally while reporting that its rules were applied, which is the leak this whole
// feature exists to prevent.
type unsupportedEgressRouteCommander struct{}

var errEgressRoutesUnsupported = errors.New("egress route takeover is not implemented on this platform")

func newEgressRouteCommanderForPlatform(_ string) egressRouteCommander {
	return unsupportedEgressRouteCommander{}
}

func (unsupportedEgressRouteCommander) Conflict(egressRoute) (bool, string) { return false, "" }
func (unsupportedEgressRouteCommander) Install(egressRoute) error           { return errEgressRoutesUnsupported }
func (unsupportedEgressRouteCommander) Remove(egressRoute) error            { return errEgressRoutesUnsupported }
