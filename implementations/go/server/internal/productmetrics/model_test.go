package productmetrics

import "testing"

const sampleEvent = `{"mode":"device","path":"direct","sizeBucket":"lt1m","attempt":"first","outcome":"success"}`

// Cases beyond the shared vector: the closed schema also refuses duplicated keys, non-integer
// spellings of 1 and trailing content.
func TestParseIngestRefusesWhatTheClosedSchemaDoesNotAllow(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate top-level key": `{"schemaVersion":1,"schemaVersion":1,"events":[` + sampleEvent + `]}`,
		"duplicate event key": `{"schemaVersion":1,"events":[{"mode":"device","mode":"device","path":"direct",` +
			`"sizeBucket":"lt1m","attempt":"first","outcome":"success"}]}`,
		"fractional version":  `{"schemaVersion":1.0,"events":[` + sampleEvent + `]}`,
		"exponent version":    `{"schemaVersion":1e0,"events":[` + sampleEvent + `]}`,
		"trailing value":      `{"schemaVersion":1,"events":[` + sampleEvent + `]} {}`,
		"nested event value":  `{"schemaVersion":1,"events":[{"mode":{"x":1},"path":"direct","sizeBucket":"lt1m","attempt":"first","outcome":"success"}]}`,
		"invalid utf-8":       "{\"schemaVersion\":1,\"events\":[\xff]}",
		"empty body":          ``,
		"events before close": `{"schemaVersion":1,"events":[` + sampleEvent,
	} {
		if events, code := ParseIngest([]byte(body)); code != CodeInvalid || events != nil {
			t.Fatalf("%s: got %v %q", name, events, code)
		}
	}
	events, code := ParseIngest([]byte(" \n{\"events\":[" + sampleEvent + "],\"schemaVersion\":1}\n"))
	if code != "" || len(events) != 1 || events[0].Path != "direct" {
		t.Fatalf("surrounding whitespace: %v %q", events, code)
	}
}

func TestParseSettingsUpdate(t *testing.T) {
	for name, body := range map[string]string{
		"missing enabled":     `{"disclosureVersion":1}`,
		"string enabled":      `{"enabled":"true"}`,
		"boolean disclosure":  `{"enabled":true,"disclosureVersion":true}`,
		"fractional version":  `{"enabled":true,"disclosureVersion":1.5}`,
		"extra field":         `{"enabled":false,"tenantId":"t2"}`,
		"duplicate enabled":   `{"enabled":false,"enabled":true}`,
		"not an object":       `[true]`,
		"trailing content":    `{"enabled":false}x`,
		"null disclosure":     `{"enabled":true,"disclosureVersion":null}`,
		"empty object":        `{}`,
		"string disclosure":   `{"enabled":true,"disclosureVersion":"1"}`,
		"disclosure exponent": `{"enabled":true,"disclosureVersion":1e0}`,
	} {
		if _, ok := ParseSettingsUpdate([]byte(body)); ok {
			t.Fatalf("%s accepted", name)
		}
	}
	update, ok := ParseSettingsUpdate([]byte(`{"disclosureVersion":2,"enabled":true}`))
	if !ok || !update.Enabled || update.Disclosure == nil || *update.Disclosure != "2" {
		t.Fatalf("valid body: %+v %v", update, ok)
	}
	update, ok = ParseSettingsUpdate([]byte(`{"enabled":false}`))
	if !ok || update.Enabled || update.Disclosure != nil {
		t.Fatalf("disable body: %+v %v", update, ok)
	}
}

func TestLimiterRefusesWithoutCharging(t *testing.T) {
	l := newLimiter(Limits{PerUserEventsPerMinute: 30, PerTenantEventsPerMinute: 50})
	minute := int64(1_000) * 60_000
	if !l.admit("t1", "alice", 20, minute) || l.admit("t1", "alice", 11, minute+1) {
		t.Fatal("per-user budget")
	}
	if !l.admit("t1", "alice", 10, minute+2) || !l.admit("t1", "bob", 20, minute+3) {
		t.Fatal("a refused batch must not consume the budget")
	}
	if l.admit("t1", "carol", 1, minute+4) || !l.admit("t2", "carol", 1, minute+5) {
		t.Fatal("per-tenant budget")
	}
	if !l.admit("t1", "carol", 1, minute+60_000) {
		t.Fatal("a new minute starts a new window")
	}
}
