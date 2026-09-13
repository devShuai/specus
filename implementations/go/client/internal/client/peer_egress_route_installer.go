package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Installing routes without leaving any behind.
//
// Two problems this file exists to solve. A partial install has to come back out, or a failure
// halfway through a rule set leaves the machine routing some traffic into a tunnel that was never
// finished being set up. And a route this feature owns has to be distinguishable from one the user
// or another tool installed, across a clean exit, a crash and a restart, because withdrawing
// someone else's route is worse than leaving our own behind.
//
// The journal is what answers the second question. It records what was installed, on disk, before
// the install is attempted. Written first on purpose: a journal entry for a route that failed to
// install costs one harmless removal attempt at cleanup, while a route installed without a journal
// entry is one nobody will ever take back.

// egressRouteCommander is the platform's routing table. Injected so the failure and rollback paths
// can be driven without touching the real one.
type egressRouteCommander interface {
	// Conflict reports an existing route for this exact prefix that this feature does not own.
	// The description is what an operator reads, so it should say what is already there.
	Conflict(route egressRoute) (bool, string)
	Install(route egressRoute) error
	Remove(route egressRoute) error
}

// egressRouteJournal is the on-disk record of what this feature installed.
type egressRouteJournal struct {
	Version int           `json:"version"`
	Routes  []egressRoute `json:"routes"`
}

const egressRouteJournalVersion = 1

// egressRouteInstaller applies plans and owns the journal.
//
// Not safe for concurrent use; the caller that owns the rule configuration drives it.
type egressRouteInstaller struct {
	commander egressRouteCommander
	path      string
	installed []egressRoute
}

// egressRouteApplyResult says what happened, in enough detail for an operator to act.
type egressRouteApplyResult struct {
	Added   []egressRoute
	Removed []egressRoute
	// Conflicts are routes refused because something else already owns the prefix. The rest of
	// the plan is applied regardless: one contested prefix should not disable every other rule.
	Conflicts []egressRouteConflict
	// RolledBack is set when an install failed for a reason other than a conflict and the
	// additions from this call were undone.
	RolledBack bool
	Err        error
}

type egressRouteConflict struct {
	Route    egressRoute
	Existing string
}

func newEgressRouteInstaller(commander egressRouteCommander, journalPath string) *egressRouteInstaller {
	return &egressRouteInstaller{commander: commander, path: journalPath}
}

// load reads the journal from a previous run. A missing or unreadable journal yields an empty set:
// there is nothing to be gained by refusing to start, and the alternative to an empty set is
// guessing which of the machine's routes might have been ours.
func (installer *egressRouteInstaller) load() error {
	installer.installed = nil
	if installer.path == "" {
		return nil
	}
	raw, err := os.ReadFile(installer.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var journal egressRouteJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		return err
	}
	if journal.Version != egressRouteJournalVersion {
		// A journal from a version that wrote entries differently cannot be trusted to describe
		// what is actually installed, and acting on it would mean removing prefixes by guess.
		return fmt.Errorf("egress route journal version %d is not %d", journal.Version, egressRouteJournalVersion)
	}
	installer.installed = journal.Routes
	sortEgressRoutes(installer.installed)
	return nil
}

func (installer *egressRouteInstaller) save() error {
	if installer.path == "" {
		return nil
	}
	if len(installer.installed) == 0 {
		if err := os.Remove(installer.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	sortEgressRoutes(installer.installed)
	raw, err := json.MarshalIndent(egressRouteJournal{
		Version: egressRouteJournalVersion, Routes: installer.installed,
	}, "", "  ")
	if err != nil {
		return err
	}
	if directory := filepath.Dir(installer.path); directory != "" && directory != "." {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
	}
	// Written through a temporary file: a journal truncated by a crash mid-write would describe
	// fewer routes than are installed, and the difference is what gets left behind.
	temporary := installer.path + ".tmp"
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, installer.path)
}

// apply moves the routing table to the desired set.
//
// Withdrawals happen first, so a prefix that changed kind loses its old entry before the new one
// goes in. Then additions, each preceded by a conflict check.
func (installer *egressRouteInstaller) apply(desired []egressRoute) egressRouteApplyResult {
	var result egressRouteApplyResult
	remove, add := diffEgressRoutes(installer.installed, desired)

	for _, route := range remove {
		if err := installer.commander.Remove(route); err != nil {
			// A route we cannot remove is dropped from the journal anyway. Keeping it would
			// mean retrying forever against a table that no longer has it, which is the more
			// likely explanation than a table refusing us.
			result.Err = err
		}
		installer.forget(route)
		result.Removed = append(result.Removed, route)
	}

	var appliedThisCall []egressRoute
	for _, route := range add {
		if conflicted, existing := installer.commander.Conflict(route); conflicted {
			// Phase one does not preempt and does not compare metrics. Refusing one prefix and
			// telling the operator beats quietly winning an argument with their own routing.
			result.Conflicts = append(result.Conflicts, egressRouteConflict{Route: route, Existing: existing})
			continue
		}
		// Journal before install, so a crash between the two leaves a removable record rather
		// than an unowned route.
		installer.installed = append(installer.installed, route)
		if err := installer.save(); err != nil {
			installer.forget(route)
			result.Err = err
			result.RolledBack = true
			installer.rollback(appliedThisCall, &result)
			return result
		}
		if err := installer.commander.Install(route); err != nil {
			installer.forget(route)
			_ = installer.save()
			result.Err = err
			result.RolledBack = true
			installer.rollback(appliedThisCall, &result)
			return result
		}
		appliedThisCall = append(appliedThisCall, route)
		result.Added = append(result.Added, route)
	}

	if err := installer.save(); err != nil && result.Err == nil {
		result.Err = err
	}
	return result
}

// rollback withdraws the additions from the current call only.
//
// Only this call's, because routes from earlier calls are still wanted; a failure now is not a
// reason to tear down a configuration that was working a minute ago.
func (installer *egressRouteInstaller) rollback(applied []egressRoute, result *egressRouteApplyResult) {
	for index := len(applied) - 1; index >= 0; index-- {
		route := applied[index]
		_ = installer.commander.Remove(route)
		installer.forget(route)
	}
	result.Added = nil
	_ = installer.save()
}

// withdrawAll removes every route this feature owns, for shutdown or for a restart that found a
// journal from a previous run.
func (installer *egressRouteInstaller) withdrawAll() []egressRoute {
	owned := append([]egressRoute(nil), installer.installed...)
	// Reverse order, so the bypass entries that keep the transport working outlive the routes
	// that point into the tunnel.
	sortEgressRoutes(owned)
	for index := len(owned) - 1; index >= 0; index-- {
		_ = installer.commander.Remove(owned[index])
	}
	installer.installed = nil
	_ = installer.save()
	return owned
}

func (installer *egressRouteInstaller) forget(route egressRoute) {
	kept := installer.installed[:0]
	for _, existing := range installer.installed {
		if existing.key() != route.key() {
			kept = append(kept, existing)
		}
	}
	installer.installed = kept
}

// owns reports whether a prefix is one of ours, which is what keeps a conflict check from treating
// this feature's own route as somebody else's.
// installedRoutes is what this feature currently believes it owns, for the status surface.
//
// A copy, because the caller is a diagnostic reader and the installer goes on mutating its own
// slice. Returned in journal order, which is the order they were installed.
func (installer *egressRouteInstaller) installedRoutes() []egressRoute {
	return append([]egressRoute(nil), installer.installed...)
}

func (installer *egressRouteInstaller) owns(cidr string) bool {
	for _, route := range installer.installed {
		if route.CIDR == cidr {
			return true
		}
	}
	return false
}
