package nat

import (
	"crypto/rand"
	"encoding/hex"
)

// randomHex16 returns a 32-character hex channel id (16 random bytes, no dashes), matching
// the C# Guid.ToString("N") form used for NAT channel ids.
func randomHex16() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}
