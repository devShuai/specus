package client

import (
	"testing"
	"time"
)

// Rate limiting governs what an operator reads. It must never govern what the report counts, or a
// busy period would look like the refusals had stopped.
func TestRejectionLogCountsEveryRefusalRegardlessOfLimiting(t *testing.T) {
	log := newEgressRejectionLog()
	emitted := 0
	for attempt := 0; attempt < egressRejectionsPerWindow*3; attempt++ {
		if write, _ := log.record(7, egressCodeDestinationDenied, flowEpoch); write {
			emitted++
		}
	}
	if emitted != egressRejectionsPerWindow {
		t.Errorf("emitted %d lines, want the window limit of %d", emitted, egressRejectionsPerWindow)
	}
	counts := log.drainCounts()
	if counts[egressCodeDestinationDenied] != int64(egressRejectionsPerWindow*3) {
		t.Errorf("aggregate = %d, want every refusal counted",
			counts[egressCodeDestinationDenied])
	}
}

// The spec limits by subject and reason together. One consumer hammering one rule must not silence
// a different rule, or a different consumer.
func TestRejectionLogLimitsPerSubjectAndReason(t *testing.T) {
	log := newEgressRejectionLog()
	for attempt := 0; attempt < egressRejectionsPerWindow; attempt++ {
		log.record(7, egressCodeDestinationDenied, flowEpoch)
	}
	if write, _ := log.record(7, egressCodeDestinationDenied, flowEpoch); write {
		t.Error("the exhausted subject and reason still emitted")
	}
	if write, _ := log.record(7, egressCodePortDenied, flowEpoch); !write {
		t.Error("a different reason was silenced by an exhausted one")
	}
	if write, _ := log.record(9, egressCodeDestinationDenied, flowEpoch); !write {
		t.Error("a different consumer was silenced by another consumer's traffic")
	}
}

// A gap in the log with no explanation reads as the problem having gone away, so the next line that
// does get written says how many it stands for.
func TestRejectionLogReportsWhatItSuppressed(t *testing.T) {
	log := newEgressRejectionLog()
	for attempt := 0; attempt < egressRejectionsPerWindow; attempt++ {
		if _, suppressed := log.record(7, egressCodeDestinationDenied, flowEpoch); suppressed != 0 {
			t.Fatalf("reported %d suppressed before anything was dropped", suppressed)
		}
	}
	for attempt := 0; attempt < 5; attempt++ {
		log.record(7, egressCodeDestinationDenied, flowEpoch)
	}

	write, suppressed := log.record(7, egressCodeDestinationDenied, flowEpoch.Add(egressRejectionWindow))
	if !write {
		t.Fatal("the window did not roll over")
	}
	if suppressed != 5 {
		t.Errorf("suppressed = %d, want 5", suppressed)
	}
	// The count belongs to the line that carried it, so the line after starts clean.
	if _, suppressed = log.record(7, egressCodeDestinationDenied, flowEpoch.Add(egressRejectionWindow)); suppressed != 0 {
		t.Errorf("the suppression count was reported twice: %d", suppressed)
	}
}

// A peer that varies its identity would otherwise turn the limiter into a memory leak, which is a
// worse outcome than the flooding the limiter exists to prevent.
func TestRejectionLogBoundsItsSubjectTable(t *testing.T) {
	log := newEgressRejectionLog()
	for consumer := int64(0); consumer < egressRejectionMaxSubjects+500; consumer++ {
		log.record(consumer, egressCodeConsumerDenied, flowEpoch)
	}
	if len(log.recent) > egressRejectionMaxSubjects {
		t.Errorf("subject table held %d entries, above the cap of %d",
			len(log.recent), egressRejectionMaxSubjects)
	}
	if !log.limited {
		t.Error("hitting the cap was not recorded")
	}
	// Reaching the cap costs diagnostic lines, never accuracy.
	counts := log.drainCounts()
	if counts[egressCodeConsumerDenied] != int64(egressRejectionMaxSubjects+500) {
		t.Errorf("aggregate = %d, want every refusal counted even at the cap",
			counts[egressCodeConsumerDenied])
	}
}

// Once the windows behind those entries elapse, the cap must stop biting rather than leaving the
// limiter permanently full.
func TestRejectionLogRecoversAfterTheWindowElapses(t *testing.T) {
	log := newEgressRejectionLog()
	for consumer := int64(0); consumer < egressRejectionMaxSubjects; consumer++ {
		log.record(consumer, egressCodeConsumerDenied, flowEpoch)
	}
	later := flowEpoch.Add(egressRejectionWindow + time.Second)
	if write, _ := log.record(999999, egressCodeConsumerDenied, later); !write {
		t.Error("a new subject was refused a line after every stale window had elapsed")
	}
}

// Consecutive reports have to describe consecutive intervals. A running total would leave the
// server differencing values it was never told were cumulative.
func TestRejectionLogDrainResetsTheInterval(t *testing.T) {
	log := newEgressRejectionLog()
	log.record(7, egressCodeDestinationDenied, flowEpoch)
	log.record(7, egressCodePortDenied, flowEpoch)

	first := log.drainCounts()
	if first[egressCodeDestinationDenied] != 1 || first[egressCodePortDenied] != 1 {
		t.Fatalf("first interval = %v", first)
	}
	if second := log.drainCounts(); second != nil {
		t.Errorf("an interval with no refusals returned %v, want nothing to send", second)
	}

	log.record(7, egressCodeDestinationDenied, flowEpoch)
	third := log.drainCounts()
	if third[egressCodeDestinationDenied] != 1 {
		t.Errorf("third interval = %v, want only the refusal from that interval", third)
	}
}
