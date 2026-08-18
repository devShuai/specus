package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestHashPasswordProducesSaltedSelfDescribingHashes(t *testing.T) {
	first := HashPassword("correct horse battery staple")
	second := HashPassword("correct horse battery staple")

	if first == second {
		t.Fatal("two hashes of the same password must differ; the salt is what stops rainbow tables")
	}
	for _, hash := range []string{first, second} {
		if !strings.HasPrefix(hash, "$pbkdf2-sha256$v=1$i=210000$") {
			t.Fatalf("hash does not carry its own parameters: %s", hash)
		}
		if len(strings.Split(hash, "$")) != 6 {
			t.Fatalf("unexpected hash shape: %s", hash)
		}
	}
	if !VerifyPassword("correct horse battery staple", first).Matches {
		t.Fatal("a freshly written hash must verify")
	}
	if VerifyPassword("correct horse battery stapl", first).Matches {
		t.Fatal("a near-miss password must not verify")
	}
	if VerifyPassword("", first).Matches {
		t.Fatal("an empty password must not verify")
	}
}

func TestVerifyPasswordDoesNotAskForAnUpgradeAtTheCurrentCost(t *testing.T) {
	result := VerifyPassword("s3cret", HashPassword("s3cret"))
	if !result.Matches {
		t.Fatal("expected a match")
	}
	if result.NeedsUpgrade || result.UpgradedHash != "" {
		t.Fatalf("a current-cost hash must not be rewritten: %+v", result)
	}
	if result.StoredIsLegacy {
		t.Fatal("a current hash is not legacy")
	}
}

// Existing databases hold bare SHA-256. Those users must still be able to log in, and that login is
// the one moment the plaintext exists, so it is where the hash gets replaced.
func TestLegacySHA256VerifiesAndIsUpgraded(t *testing.T) {
	sum := sha256.Sum256([]byte("legacy-password"))
	legacy := hex.EncodeToString(sum[:])

	if !IsLegacyPasswordHash(legacy) {
		t.Fatal("a bare hex digest must be recognised as legacy")
	}
	result := VerifyPassword("legacy-password", legacy)
	if !result.Matches {
		t.Fatal("an existing user must not be locked out by the new format")
	}
	if !result.NeedsUpgrade || result.UpgradedHash == "" {
		t.Fatalf("a legacy hash must be scheduled for replacement: %+v", result)
	}
	if !result.StoredIsLegacy {
		t.Fatal("the caller needs to know the stored value was legacy")
	}
	if !strings.HasPrefix(result.UpgradedHash, "$pbkdf2-sha256$") {
		t.Fatalf("the upgrade must use the new format: %s", result.UpgradedHash)
	}
	// The replacement verifies, and does so without asking for another upgrade.
	next := VerifyPassword("legacy-password", result.UpgradedHash)
	if !next.Matches || next.NeedsUpgrade {
		t.Fatalf("the upgraded hash must be final: %+v", next)
	}

	// Uppercase hex is the same digest.
	if !VerifyPassword("legacy-password", strings.ToUpper(legacy)).Matches {
		t.Fatal("legacy hashes must compare case-insensitively")
	}
	if VerifyPassword("wrong", legacy).Matches {
		t.Fatal("a wrong password must not verify against a legacy hash")
	}
}

// A hash whose cost has fallen behind is upgraded on the next successful login, which is what makes
// raising the cost possible without invalidating stored credentials.
func TestUnderCostHashesAreUpgraded(t *testing.T) {
	weak := hashPasswordWithIterations("s3cret", MinPasswordIterations)
	result := VerifyPassword("s3cret", weak)

	if !result.Matches {
		t.Fatal("an old-cost hash must still verify")
	}
	if !result.NeedsUpgrade {
		t.Fatal("an old-cost hash must be scheduled for replacement")
	}
	if !strings.Contains(result.UpgradedHash, "i=210000$") {
		t.Fatalf("the upgrade must apply the current cost: %s", result.UpgradedHash)
	}
}

func TestMalformedStoredHashesNeverVerify(t *testing.T) {
	for _, stored := range []string{
		"",
		"   ",
		"$",
		"$pbkdf2-sha256$v=1$i=210000$onlythree",
		"$pbkdf2-sha256$v=2$i=210000$c2FsdA$a2V5",     // unknown version
		"$argon2id$v=1$i=210000$c2FsdA$a2V5",          // unknown algorithm
		"$pbkdf2-sha256$v=1$i=1$c2FsdA$a2V5",          // cost below the floor
		"$pbkdf2-sha256$v=1$i=notanumber$c2FsdA$a2V5", // unparsable cost
		"$pbkdf2-sha256$v=1$i=210000$!!!$a2V5",        // unparsable salt
		"$pbkdf2-sha256$v=1$i=210000$c2FsdA$!!!",      // unparsable key
		"$pbkdf2-sha256$v=1$i=210000$$a2V5",           // empty salt
		strings.Repeat("a", 63),                       // wrong-length legacy digest
		strings.Repeat("z", 64),                       // right length, not hex
	} {
		if VerifyPassword("anything", stored).Matches {
			t.Fatalf("malformed hash verified: %q", stored)
		}
	}
}

// Tokens are generated with full entropy, so they keep a plain digest; running a slow KDF on every
// request would buy nothing. The two must stay distinguishable.
func TestTokenAndPasswordHashingAreDifferentPrimitives(t *testing.T) {
	token := HashToken("a-high-entropy-token")
	if len(token) != legacyHashHexLength {
		t.Fatalf("token hash = %q, want a %d-character hex digest", token, legacyHashHexLength)
	}
	if HashToken("a-high-entropy-token") != token {
		t.Fatal("token hashing must be deterministic; it is used as a lookup key")
	}
	if strings.HasPrefix(token, "$") {
		t.Fatal("a token digest must not be confused with a password hash")
	}
	if DigestKey("issuer\x00subject") != HashToken("issuer\x00subject") {
		t.Fatal("index keys and token digests share one primitive")
	}
}

func TestPBKDF2MatchesAKnownAnswer(t *testing.T) {
	// RFC 6070 is defined for HMAC-SHA1; this vector is the SHA-256 analogue widely used for
	// PBKDF2-HMAC-SHA256, and pins the implementation against accidental drift.
	derived := pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32)
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if got := hex.EncodeToString(derived); got != want {
		t.Fatalf("pbkdf2(password, salt, 1) = %s, want %s", got, want)
	}

	derived = pbkdf2SHA256([]byte("password"), []byte("salt"), 2, 32)
	want = "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
	if got := hex.EncodeToString(derived); got != want {
		t.Fatalf("pbkdf2(password, salt, 2) = %s, want %s", got, want)
	}

	// A key longer than one SHA-256 block exercises the multi-block path.
	derived = pbkdf2SHA256([]byte("passwordPASSWORDpassword"),
		[]byte("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, 40)
	want = "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"
	if got := hex.EncodeToString(derived); got != want {
		t.Fatalf("pbkdf2 multi-block = %s, want %s", got, want)
	}
}

// A hash written by one implementation must verify on the others, so the format is pinned to a
// vector produced by an independent PBKDF2-HMAC-SHA256 implementation rather than by this code.
// Java and .NET assert the same two strings.
func TestSharedCrossLanguagePasswordVector(t *testing.T) {
	const password = "specus-shared-password"
	for _, vector := range []string{
		"$pbkdf2-sha256$v=1$i=1000$AAECAwQFBgcICQoLDA0ODw$vnwYtUA8UXxNgCLy7OdAY+f7T+TtG4qdlahTjY1KU5g",
		"$pbkdf2-sha256$v=1$i=210000$AAECAwQFBgcICQoLDA0ODw$BiTFCvEUdO2zrZt0s1Zd0ipbGH5+WaSosMi6WavHxbI",
	} {
		if !VerifyPassword(password, vector).Matches {
			t.Fatalf("shared vector failed to verify: %s", vector)
		}
		if VerifyPassword(password+"x", vector).Matches {
			t.Fatalf("shared vector verified a wrong password: %s", vector)
		}
	}
}
