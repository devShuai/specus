package client

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// The machine credential is this client's identity to the server. It used to live as plaintext in
// the config file with nothing checking who else could read it, which is the whole exposure: a
// config file gets copied to a new host, checked into a repository, or left group-readable on a
// shared machine, and the credential travels with it.
//
// Two things address that, and it is worth being clear about which does the work.
//
// Keeping the secret out of the config file is the larger of the two. It can be named indirectly —
// from the environment, or from a file of its own — so the file that gets copied around carries a
// reference rather than the credential.
//
// Refusing to read a secret that other local accounts can also read is what protects it on disk.
// Encrypting the file would not: the key would have to live somewhere this process can reach
// unaided, so anyone running as this user could decrypt it too, and anyone who could not read the
// file could not read the key either. File permissions are the mechanism that actually
// distinguishes those cases, which is why OpenSSH refuses an over-permissive private key rather
// than encrypting it by default.
const (
	envSecretPrefix  = "env:"
	fileSecretPrefix = "file:"
)

// ErrSecretFileTooOpen reports a credential file other local accounts can read.
var ErrSecretFileTooOpen = errors.New("credential file is readable by other accounts")

// resolveSecret turns the configured value into the secret itself.
//
// A plain string is the secret, which keeps existing configurations working. "env:NAME" reads it
// from the environment, and "file:PATH" reads it from a file that must not be readable by anyone
// else.
func resolveSecret(configured string) (string, error) {
	value := strings.TrimSpace(configured)
	switch {
	case strings.HasPrefix(value, envSecretPrefix):
		name := strings.TrimSpace(strings.TrimPrefix(value, envSecretPrefix))
		if name == "" {
			return "", errors.New("secret env reference names no variable")
		}
		secret := strings.TrimSpace(os.Getenv(name))
		if secret == "" {
			return "", fmt.Errorf("secret environment variable %s is empty or unset", name)
		}
		return secret, nil

	case strings.HasPrefix(value, fileSecretPrefix):
		path := strings.TrimSpace(strings.TrimPrefix(value, fileSecretPrefix))
		if path == "" {
			return "", errors.New("secret file reference names no path")
		}
		return readSecretFile(path)

	default:
		return value, nil
	}
}

// readSecretFile reads a credential file, refusing one that other accounts can read.
func readSecretFile(path string) (string, error) {
	if err := assertSecretFilePrivate(path); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return secret, nil
}

// secretIsIndirect reports whether the configured value points at the secret rather than being it.
// Callers use it to tell an operator that their credential is still sitting in the config file.
func secretIsIndirect(configured string) bool {
	value := strings.TrimSpace(configured)
	return strings.HasPrefix(value, envSecretPrefix) || strings.HasPrefix(value, fileSecretPrefix)
}
