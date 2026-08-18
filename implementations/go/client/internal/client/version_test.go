package client

import "testing"

// The login handshake must report the version injected at package time, and must stay empty for
// embedders that never set one (the previous wire behaviour).
func TestClientVersionIsReportedInHandshakeEnvironment(t *testing.T) {
	original := currentClientVersion()
	t.Cleanup(func() { SetVersion(original) })

	SetVersion("  1.2.3  ")
	if got := currentClientVersion(); got != "1.2.3" {
		t.Fatalf("currentClientVersion() = %q, want trimmed 1.2.3", got)
	}
	if got := collectEnvironment().ClientVersion; got != "1.2.3" {
		t.Fatalf("environment clientVersion = %q, want 1.2.3", got)
	}

	SetVersion("")
	if got := collectEnvironment().ClientVersion; got != "" {
		t.Fatalf("environment clientVersion = %q, want empty when unset", got)
	}
}
