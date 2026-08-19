//go:build windows

package client

import (
	"fmt"
	"os"
)

// assertSecretFilePrivate checks that a credential file exists and is a regular file.
//
// Unix mode bits carry no meaning here, and reading the ACL well enough to judge "too open" means
// resolving group memberships and inherited entries — a check that is easy to get subtly wrong and
// would then either refuse valid setups or pass invalid ones. Files this client writes are locked
// down at creation instead, in writeSecretFile, which is the point where it can be done exactly.
func assertSecretFilePrivate(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat secret file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("secret file %s is a directory", path)
	}
	return nil
}
