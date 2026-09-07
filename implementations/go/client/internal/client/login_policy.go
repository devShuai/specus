package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// LoginFailure is shared by the CLI and embedders. Its text never contains an HTTP body.
type LoginFailure struct {
	Code       int
	Retryable  bool
	RetryAfter time.Duration
	Message    string
}

func (e *LoginFailure) Error() string { return e.Message }
func ExitCode(err error) int {
	var failure *LoginFailure
	if errors.As(err, &failure) {
		return failure.Code
	}
	var rejected *controlLoginRejectedError
	if errors.As(err, &rejected) && rejected.action == controlLoginStop {
		return 3
	}
	return 1
}
func loginStatusFailure(status int, retryAfter string) *LoginFailure {
	retry := status == 408 || status == 425 || status == 429 || status >= 500 && status <= 599
	code := 1
	action := "Check serverBaseUrl and server/client compatibility."
	if status == 400 || status == 401 || status == 403 || status == 409 {
		code = 3
		action = "Check apiKey/secret, system clock, account permissions and gateway access rules."
	}
	if retry {
		action = "Check network/server availability."
	}
	wait := time.Duration(0)
	if seconds, err := strconv.ParseInt(retryAfter, 10, 64); err == nil && seconds > 0 {
		wait = time.Duration(min(seconds, 3600)) * time.Second
	} else if at, err := http.ParseTime(retryAfter); err == nil {
		wait = min(max(time.Until(at), 0), time.Hour)
	}
	return &LoginFailure{Code: code, Retryable: retry, RetryAfter: wait, Message: fmt.Sprintf("HTTP login failed (HTTP %d). %s", status, action)}
}
func (client *Client) SetInitialLoginTimeout(timeout time.Duration) {
	client.initialLoginTimeout = timeout
}
func (client *Client) login(ctx context.Context) (RuntimeConfig, error) {
	if client.authenticated.Load() {
		return client.loginOnce(ctx)
	}
	budget := client.initialLoginTimeout
	if budget <= 0 {
		budget = 60 * time.Second
	}
	initial, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	delay := time.Second
	for {
		result, err := client.loginOnce(initial)
		if err == nil {
			client.authenticated.Store(true)
			return result, nil
		}
		if ctx.Err() != nil {
			return RuntimeConfig{}, ctx.Err()
		}
		if initial.Err() != nil {
			return RuntimeConfig{}, &LoginFailure{Code: 4, Message: "Initial HTTP login timeout. Check network/server availability or increase --login-timeout (seconds)."}
		}
		var failure *LoginFailure
		if !errors.As(err, &failure) || !failure.Retryable {
			return RuntimeConfig{}, err
		}
		wait := max(delay, failure.RetryAfter)
		client.logger.Printf("%s Retrying in %s within the initial login budget.", failure.Message, wait)
		timer := time.NewTimer(wait)
		select {
		case <-initial.Done():
			timer.Stop()
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return RuntimeConfig{}, ctx.Err()
		}
		if initial.Err() != nil {
			return RuntimeConfig{}, &LoginFailure{Code: 4, Message: "Initial HTTP login timeout. Check network/server availability or increase --login-timeout (seconds)."}
		}
		delay = min(delay*2, 5*time.Second)
	}
}
