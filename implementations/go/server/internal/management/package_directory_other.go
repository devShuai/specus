//go:build !windows

package management

import "os"

func clientPackageDirectoryIsReparsePoint(info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}
