package security

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
)

// verifyRS256 checks an RSA PKCS#1 v1.5 SHA-256 signature over the JWT signing input.
func verifyRS256(key *rsa.PublicKey, signingInput string, signature []byte) bool {
	hashed := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature) == nil
}
