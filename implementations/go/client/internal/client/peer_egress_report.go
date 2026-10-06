package client

import (
	"maps"
	"time"
)

// What an egress tells the server about itself: protocol/spec/peer-egress.md, egress-report.
//
// The server keeps the latest report of each egress for the management page, each one replacing the
// one before, and ignores a report whose revision is below the one it holds. Three rules follow.
//
// A report carries running totals, the numbers the egress section of the local status shows, read
// from the same snapshot. Counts for an interval would leave the page describing "since the last
// report", and stuck there whenever no new report came.
//
// The revision is the wall clock in milliseconds, kept strictly increasing. A counter starting at one
// would be below the stored revision after a restart, and the restarted egress would go unheard.
//
// A check runs every minute while the egress runs, and sends only when a value changed or nothing
// went out yet in this control session: the server behind a new session may have restarted.
//
// Shared vector: protocol/test-vectors/peer-egress-report-v1.json.

const (
	peerControlTypeEgressReport = "egress-report"

	// egressReportInterval is how often a running egress checks whether to report. The server
	// takes twenty reports a minute from one control session; this is one.
	egressReportInterval = 60 * time.Second
)

// egressReportMessage is the report as it goes on the wire.
//
// It has no field that could carry identity or routing, so none can be sent. The server binds the
// reporter to the authenticated control connection, and treats any sourceClient*, targetClient*,
// sessionId or token key in the body as a violation, null included.
type egressReportMessage struct {
	Type          string           `json:"type"`
	Revision      int64            `json:"revision"`
	ActiveFlows   int64            `json:"activeFlows"`
	TotalFlows    int64            `json:"totalFlows"`
	RejectedFlows map[string]int64 `json:"rejectedFlows"`
	BytesIn       int64            `json:"bytesIn"`
	BytesOut      int64            `json:"bytesOut"`
}

// egressReportCounters are the values a check reads, named as the status names them.
type egressReportCounters struct {
	Flows      int64
	TotalFlows int64
	Refused    map[string]int64
	BytesIn    int64
	BytesOut   int64
}

// egressReportCountersOf reads a check's values from the snapshot the status section is built from,
// so the page and `specus-client egress` cannot disagree.
func egressReportCountersOf(snapshot runtimeStatusSnapshot) egressReportCounters {
	return egressReportCounters{
		Flows:      int64(snapshot.Flows),
		TotalFlows: snapshot.Stats.TotalFlows,
		Refused:    snapshot.Refused,
		BytesIn:    snapshot.Stats.BytesIn,
		BytesOut:   snapshot.Stats.BytesOut,
	}
}

// egressReporter decides whether a check sends a report, and numbers the reports it sends.
//
// One per process, not per control session or per runtime, since both end on every reconnect and
// the revision has to keep rising across them. It reads no clock, so the shared vector drives it
// with the one it gives.
type egressReporter struct {
	revision int64
	// lastSent is the last report sent in this control session while the egress ran: nil before
	// the first, after a new session begins, and once the egress is switched off.
	lastSent *egressReportMessage
}

// newSession makes the next check report whatever it finds. The server at the other end of a new
// control session may have restarted and lost the report it held.
func (r *egressReporter) newSession() {
	r.lastSent = nil
}

// check runs one check at wallMs and returns the report to send, or nil when there is nothing to
// say: the egress is not running, or no value changed since the last report this session.
//
// A report counts as sent once it is returned. One that fails to go out is not retried; the next
// check sends only if something changed by then.
func (r *egressReporter) check(wallMs int64, active bool, counters egressReportCounters) *egressReportMessage {
	if !active {
		// The first check after the egress is switched on again reports, changed or not.
		r.lastSent = nil
		return nil
	}
	// A zero count is left out, the way the status leaves it out: a row of zeros buries the one
	// code that happened.
	rejected := make(map[string]int64, len(counters.Refused))
	for code, count := range counters.Refused {
		if count > 0 {
			rejected[code] = count
		}
	}
	report := egressReportMessage{
		Type:          peerControlTypeEgressReport,
		ActiveFlows:   counters.Flows,
		TotalFlows:    counters.TotalFlows,
		RejectedFlows: rejected,
		BytesIn:       counters.BytesIn,
		BytesOut:      counters.BytesOut,
	}
	if r.lastSent != nil && sameEgressReportValues(*r.lastSent, report) {
		return nil
	}
	// A wall clock stepped back must not number this report below the last one.
	r.revision = max(r.revision+1, wallMs)
	report.Revision = r.revision
	sent := report
	r.lastSent = &sent
	return &report
}

func sameEgressReportValues(left, right egressReportMessage) bool {
	return left.ActiveFlows == right.ActiveFlows && left.TotalFlows == right.TotalFlows &&
		left.BytesIn == right.BytesIn && left.BytesOut == right.BytesOut &&
		maps.Equal(left.RejectedFlows, right.RejectedFlows)
}

// announcesEgress says whether this build's login announces the egress role. The egress runs only
// when it does: the server refuses a report from a session that did not, and closes the control
// connection over it.
func announcesEgress() bool {
	capabilities := currentEgressCapabilities()
	return capabilities.Version >= 1 && capabilities.EgressCapable
}

// newEgressReportTickerLocked makes the ticker one runtime's report checks run on. Called with the
// mesh lock held.
func (mesh *peerMeshClient) newEgressReportTickerLocked() (<-chan time.Time, func()) {
	if mesh.egressReportTicks != nil {
		return mesh.egressReportTicks()
	}
	ticker := time.NewTicker(egressReportInterval)
	return ticker.C, ticker.Stop
}

// egressReportLoop runs a check on every tick for as long as the runtime it was started with. A
// tick carries the wall clock it fired at, and that is the time the check reads.
func (mesh *peerMeshClient) egressReportLoop(runtime *egressRuntime, ticks <-chan time.Time, stop func(),
	done chan struct{}) {
	defer stop()
	for {
		select {
		case <-done:
			return
		case now := <-ticks:
			mesh.checkEgressReport(runtime, now)
		}
	}
}

// checkEgressReport runs one check at now and sends the report it produces to the server. Called
// with no lock held: the snapshot takes the plane's lock, and the send writes to the control
// connection.
//
// The egress runs while an egress-config with enabled true is in force -- the status's active -- and
// this login announced the role.
func (mesh *peerMeshClient) checkEgressReport(runtime *egressRuntime, now time.Time) {
	snapshot := runtime.statusSnapshot()
	mesh.mu.Lock()
	send := mesh.egressReportSend
	if mesh.egress != runtime || send == nil {
		// The control session this runtime served has ended, and what it read belongs to that
		// session. Deciding on it could spend the next session's first report on a connection
		// that is gone.
		mesh.mu.Unlock()
		return
	}
	report := mesh.egressReport.check(now.UnixMilli(), snapshot.Enabled && announcesEgress(),
		egressReportCountersOf(snapshot))
	mesh.mu.Unlock()
	if report == nil {
		return
	}
	// Logged and left, never retried: the report is for display, and the next check goes on as
	// usual.
	if err := send(*report); err != nil {
		mesh.logger.Printf("[peer-egress] egress-report not sent: %v", err)
	}
}
