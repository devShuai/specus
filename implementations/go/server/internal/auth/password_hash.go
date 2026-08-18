package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// Human passwords are stored with a salted, iterated KDF in a self-describing format shared by
// every implementation:
//
//	$pbkdf2-sha256$v=1$i=<iterations>$<base64 salt>$<base64 derived key>
//
// Unsalted single-round SHA-256, which this replaces, gives an attacker who reads the database the
// whole password list at rainbow-table speed. The parameters travel with each hash so the cost can
// be raised later without invalidating stored credentials: an old hash still verifies, and the
// caller is told to write back a fresh one.
//
// PBKDF2-HMAC-SHA256 is the choice rather than Argon2id because it is available in the standard
// library of all four implementations. Sharing one format matters more than the extra memory
// hardness here, since a divergent format means an account that works on one server and not another.
const (
	passwordHashAlgorithm = "pbkdf2-sha256"
	passwordHashVersion   = 1
	// DefaultPasswordIterations is the cost applied to new and upgraded hashes.
	DefaultPasswordIterations = 210_000
	// MinPasswordIterations rejects stored hashes claiming a cost low enough to be meaningless.
	MinPasswordIterations = 1_000
	passwordSaltBytes     = 16
	passwordKeyBytes      = 32
	legacyHashHexLength   = 64
)

// HashPassword derives a new salted hash at the current cost.
func HashPassword(plaintext string) string {
	return hashPasswordWithIterations(plaintext, DefaultPasswordIterations)
}

func hashPasswordWithIterations(plaintext string, iterations int) string {
	salt := make([]byte, passwordSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		// Without a secure random source any salt we invent is predictable, which silently
		// reintroduces the very weakness this format exists to remove.
		panic("auth: secure random source unavailable: " + err.Error())
	}
	derived := pbkdf2SHA256([]byte(plaintext), salt, iterations, passwordKeyBytes)
	return fmt.Sprintf("$%s$v=%d$i=%d$%s$%s",
		passwordHashAlgorithm, passwordHashVersion, iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(derived))
}

// PasswordVerification reports whether the password matched and whether the stored hash should be
// replaced. Rehashing is how legacy hashes and outdated costs are retired: the plaintext is only
// available during a successful login, so that is the one moment an upgrade can happen.
type PasswordVerification struct {
	Matches        bool
	NeedsUpgrade   bool
	UpgradedHash   string
	StoredIsLegacy bool
}

// VerifyPassword checks a password against either the current format or a legacy SHA-256 hash.
func VerifyPassword(plaintext, storedHash string) PasswordVerification {
	stored := strings.TrimSpace(storedHash)
	if stored == "" {
		return PasswordVerification{}
	}
	if !strings.HasPrefix(stored, "$") {
		if !legacySHA256Matches(plaintext, stored) {
			return PasswordVerification{StoredIsLegacy: true}
		}
		return PasswordVerification{
			Matches:        true,
			NeedsUpgrade:   true,
			UpgradedHash:   HashPassword(plaintext),
			StoredIsLegacy: true,
		}
	}

	parsed, err := parsePasswordHash(stored)
	if err != nil {
		return PasswordVerification{}
	}
	derived := pbkdf2SHA256([]byte(plaintext), parsed.salt, parsed.iterations, len(parsed.key))
	if subtle.ConstantTimeCompare(derived, parsed.key) != 1 {
		return PasswordVerification{}
	}
	if parsed.iterations < DefaultPasswordIterations {
		return PasswordVerification{
			Matches:      true,
			NeedsUpgrade: true,
			UpgradedHash: HashPassword(plaintext),
		}
	}
	return PasswordVerification{Matches: true}
}

// IsLegacyPasswordHash reports whether the stored value predates the salted format. Callers use it
// to report how much of the database still needs a login to be migrated.
func IsLegacyPasswordHash(storedHash string) bool {
	stored := strings.TrimSpace(storedHash)
	return stored != "" && !strings.HasPrefix(stored, "$")
}

type parsedPasswordHash struct {
	iterations int
	salt       []byte
	key        []byte
}

func parsePasswordHash(stored string) (parsedPasswordHash, error) {
	parts := strings.Split(stored, "$")
	// A leading "$" makes the first field empty: "", algorithm, version, iterations, salt, key.
	if len(parts) != 6 || parts[0] != "" {
		return parsedPasswordHash{}, fmt.Errorf("malformed password hash")
	}
	if parts[1] != passwordHashAlgorithm {
		return parsedPasswordHash{}, fmt.Errorf("unsupported password hash algorithm %q", parts[1])
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || version != passwordHashVersion {
		return parsedPasswordHash{}, fmt.Errorf("unsupported password hash version")
	}
	iterations, err := strconv.Atoi(strings.TrimPrefix(parts[3], "i="))
	if err != nil || iterations < MinPasswordIterations {
		return parsedPasswordHash{}, fmt.Errorf("invalid password hash iterations")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return parsedPasswordHash{}, fmt.Errorf("invalid password hash salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return parsedPasswordHash{}, fmt.Errorf("invalid password hash key")
	}
	return parsedPasswordHash{iterations: iterations, salt: salt, key: key}, nil
}

func legacySHA256Matches(plaintext, storedHash string) bool {
	if len(storedHash) != legacyHashHexLength {
		return false
	}
	sum := sha256.Sum256([]byte(plaintext))
	expected := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(storedHash)), []byte(expected)) == 1
}

// pbkdf2SHA256 implements PBKDF2 (RFC 8018) over HMAC-SHA256. It is a few lines, which is cheaper
// than taking a dependency for it and keeps the four implementations reading the same way.
func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	mac := hmac.New(sha256.New, password)
	hashLength := mac.Size()
	blocks := (keyLength + hashLength - 1) / hashLength
	derived := make([]byte, 0, blocks*hashLength)
	buffer := make([]byte, 4)

	for block := 1; block <= blocks; block++ {
		mac.Reset()
		mac.Write(salt)
		buffer[0] = byte(block >> 24)
		buffer[1] = byte(block >> 16)
		buffer[2] = byte(block >> 8)
		buffer[3] = byte(block)
		mac.Write(buffer)
		current := mac.Sum(nil)
		accumulated := make([]byte, hashLength)
		copy(accumulated, current)
		for iteration := 1; iteration < iterations; iteration++ {
			current = macSum(mac, current)
			for i := range accumulated {
				accumulated[i] ^= current[i]
			}
		}
		derived = append(derived, accumulated...)
	}
	return derived[:keyLength]
}

func macSum(mac hash.Hash, data []byte) []byte {
	mac.Reset()
	mac.Write(data)
	return mac.Sum(nil)
}
