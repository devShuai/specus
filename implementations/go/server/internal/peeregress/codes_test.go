package peeregress

import "testing"

// Refusal counts a client reports are kept only for codes this build knows, so a code the clients
// return but the server does not list disappears from the activity page without a trace.
func TestEveryCodeClientsReportIsKnown(t *testing.T) {
	for _, code := range []string{
		CodeRuleDisabled, CodeConsumerDisabled,
		CodeNameUnresolved, CodeNameUnsupported, CodeRuleFakeIPOverlap,
		CodeFakeIPPoolInvalid, CodeRuleEgressNoDomain,
	} {
		if !IsKnownCode(code) {
			t.Errorf("%s is not a known code", code)
		}
	}
	if IsKnownCode("EGRESS_MADE_UP") {
		t.Error("an undefined code was accepted")
	}
	if len(knownCodes) != 33 {
		t.Errorf("%d known codes, want the 33 protocol/spec/peer-egress.md lists", len(knownCodes))
	}
}
