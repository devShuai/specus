//go:build !windows

package client

import (
	"errors"
	"time"
)

func waitForProcessExitPlatform(int, time.Duration) error {
	return errors.New("deferred update process waiting is only supported on Windows")
}
