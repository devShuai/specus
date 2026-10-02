package client

import (
	"os"
	"testing"
)

// TestMain keeps every test in this package away from the machine's own DNS: a mesh without a fake
// host gets one that refuses every command, and the takeover journal's home is a temporary
// directory, so no test reads or writes a user's own journal.
func TestMain(m *testing.M) {
	egressDNSSystemAllowed = false
	home, err := os.MkdirTemp("", "specus-dns-journal-")
	if err != nil {
		panic(err)
	}
	egressDNSJournalHome = func() (string, error) { return home, nil }
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
