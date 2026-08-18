package client

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const peerPrivateKeyFileName = "peer-x25519.key"

func loadPeerPrivateKey() (*ecdh.PrivateKey, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, peerPrivateKeyFileName)
	if data, err := os.ReadFile(path); err == nil {
		raw, decodeErr := decodeX25519PrivateKey(strings.TrimSpace(string(data)))
		if decodeErr != nil {
			return nil, decodeErr
		}
		key, keyErr := ecdh.X25519().NewPrivateKey(raw)
		if keyErr != nil {
			return nil, fmt.Errorf("load peer private key: %w", keyErr)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read peer private key: %w", err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate peer private key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key.Bytes())
	// Atomic and owner-only: a truncated key would cost this client its peer identity, and
	// mode bits alone leave the file readable by other accounts on Windows.
	if err := writeSecretFile(path, []byte(encoded+"\n")); err != nil {
		return nil, fmt.Errorf("write peer private key: %w", err)
	}
	return key, nil
}

func peerPublicKeyBase64() string {
	key, err := loadPeerPrivateKey()
	if err != nil {
		return ""
	}
	return encodeX25519PublicKeyDER(key.PublicKey())
}

func configDir() (string, error) {
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".specus"), nil
	}
	return "", os.ErrNotExist
}
