package management

import (
	"strings"
	"testing"
)

func TestClientMutationLimitsMatchJava(t *testing.T) {
	if name, err := requireClientName(strings.Repeat("😀", 60)); err != nil || name == "" {
		t.Fatalf("120 UTF-16-unit name rejected: name=%q err=%v", name, err)
	}
	if _, err := requireClientName(strings.Repeat("😀", 61)); err == nil {
		t.Fatal("122 UTF-16-unit name should be rejected")
	}
	for _, value := range []int{-1, 10001} {
		value := value
		if _, err := normalizeConnectionRateLimit(&value, 30); err == nil {
			t.Fatalf("rate limit %d should be rejected", value)
		}
	}
	for _, value := range []int{0, 10000} {
		value := value
		if got, err := normalizeConnectionRateLimit(&value, 30); err != nil || got != value {
			t.Fatalf("rate limit %d rejected: got=%d err=%v", value, got, err)
		}
	}
}
