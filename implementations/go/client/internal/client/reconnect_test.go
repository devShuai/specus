package client

import (
	"io"
	"log"
	"testing"
	"time"
)

func TestReconnectDelayForAttemptMatchesJava(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 0, want: 2 * time.Second},
		{attempt: 1, want: 2 * time.Second},
		{attempt: 2, want: 4 * time.Second},
		{attempt: 3, want: 8 * time.Second},
		{attempt: 4, want: 16 * time.Second},
		{attempt: 5, want: 32 * time.Second},
		{attempt: 6, want: 60 * time.Second},
		{attempt: 7, want: 60 * time.Second},
	}

	for _, test := range tests {
		if got := reconnectDelayForAttempt(test.attempt); got != test.want {
			t.Fatalf("reconnectDelayForAttempt(%d) = %s, want %s", test.attempt, got, test.want)
		}
	}
}

func TestResetReconnectBackoffRestartsAtFirstDelay(t *testing.T) {
	tunnelClient := New(Config{}, log.New(io.Discard, "", 0))

	attempt, delay := tunnelClient.nextReconnectDelay()
	if attempt != 1 || delay != 2*time.Second {
		t.Fatalf("first reconnect = attempt %d delay %s, want attempt 1 delay 2s", attempt, delay)
	}
	attempt, delay = tunnelClient.nextReconnectDelay()
	if attempt != 2 || delay != 4*time.Second {
		t.Fatalf("second reconnect = attempt %d delay %s, want attempt 2 delay 4s", attempt, delay)
	}

	if previous := tunnelClient.resetReconnectBackoff(); previous != 2 {
		t.Fatalf("resetReconnectBackoff() = %d, want 2", previous)
	}
	attempt, delay = tunnelClient.nextReconnectDelay()
	if attempt != 1 || delay != 2*time.Second {
		t.Fatalf("after reset reconnect = attempt %d delay %s, want attempt 1 delay 2s", attempt, delay)
	}
}

func TestHTTPLoginBackoffResetIsConsumedOnce(t *testing.T) {
	tunnelClient := New(Config{}, log.New(io.Discard, "", 0))
	tunnelClient.nextReconnectDelay()
	tunnelClient.nextReconnectDelay()
	tunnelClient.resetReconnectBackoffAfterNextHTTPLogin()

	if previous := tunnelClient.consumeHTTPLoginBackoffReset(); previous != 2 {
		t.Fatalf("first consumeHTTPLoginBackoffReset() = %d, want 2", previous)
	}
	if previous := tunnelClient.consumeHTTPLoginBackoffReset(); previous != -1 {
		t.Fatalf("second consumeHTTPLoginBackoffReset() = %d, want -1", previous)
	}
	attempt, delay := tunnelClient.nextReconnectDelay()
	if attempt != 1 || delay != 2*time.Second {
		t.Fatalf("after HTTP login reset reconnect = attempt %d delay %s, want attempt 1 delay 2s", attempt, delay)
	}
}

func TestClassifyControlLoginFailureMatchesJava(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   controlLoginAction
	}{
		{name: "token expired", reason: "客户端访问令牌已过期", want: controlLoginRefreshImmediately},
		{name: "busy", reason: "服务器繁忙，请稍后再试", want: controlLoginBackoff},
		{name: "rate limited", reason: "连接频率超过限制", want: controlLoginBackoff},
		{name: "blank", reason: "", want: controlLoginStop},
		{name: "policy", reason: "客户端已被禁用", want: controlLoginStop},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyControlLoginFailure(test.reason); got != test.want {
				t.Fatalf("classifyControlLoginFailure(%q) = %d, want %d", test.reason, got, test.want)
			}
		})
	}
}

func TestControlIdleDurationsMatchJava(t *testing.T) {
	if controlWriteIdleHeartbeat != 5*time.Second {
		t.Fatalf("controlWriteIdleHeartbeat = %s, want 5s", controlWriteIdleHeartbeat)
	}
	if controlReadIdleTimeout != 60*time.Second {
		t.Fatalf("controlReadIdleTimeout = %s, want 60s", controlReadIdleTimeout)
	}
	if controlIdleTickInterval != time.Second {
		t.Fatalf("controlIdleTickInterval = %s, want 1s", controlIdleTickInterval)
	}
}
