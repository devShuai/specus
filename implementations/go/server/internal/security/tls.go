package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"golang.org/x/crypto/pkcs12"
)

// LoadTLSConfig builds a *tls.Config from the configured TLS mode, or nil when disabled.
// Supported modes: "disabled" (nil), "file" (PKCS12/PFX or PEM cert+key), "self-signed" (generated at startup).
func LoadTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "", "disabled":
		return nil, nil
	case "file", "pem":
		cert, err := loadTLSCertificate(cfg)
		if err != nil {
			return nil, fmt.Errorf("load TLS keypair: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	case "self-signed", "selfsigned":
		cert, err := generateSelfSigned()
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	default:
		return nil, fmt.Errorf("unknown TLS mode %q (use disabled, file, or self-signed)", cfg.Mode)
	}
}

func loadTLSCertificate(cfg config.TLSConfig) (tls.Certificate, error) {
	if strings.TrimSpace(cfg.Keystore) != "" {
		return loadPKCS12Certificate(cfg.Keystore, cfg.KeystorePassword)
	}
	return tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
}

func loadPKCS12Certificate(path string, password string) (tls.Certificate, error) {
	pfx, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	blocks, err := pkcs12.ToPEM(pfx, password)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{}
	for _, block := range blocks {
		switch block.Type {
		case "CERTIFICATE":
			cert.Certificate = append(cert.Certificate, block.Bytes)
		case "PRIVATE KEY":
			key, err := parsePKCS12PrivateKey(block.Bytes)
			if err != nil {
				return tls.Certificate{}, err
			}
			if cert.PrivateKey != nil {
				return tls.Certificate{}, fmt.Errorf("PKCS12 keystore contains multiple private keys")
			}
			cert.PrivateKey = key
		}
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, fmt.Errorf("PKCS12 keystore contains no certificate")
	}
	if cert.PrivateKey == nil {
		return tls.Certificate{}, fmt.Errorf("PKCS12 keystore contains no private key")
	}
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		cert.Leaf = leaf
	}
	return cert, nil
}

func parsePKCS12PrivateKey(der []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported PKCS12 private key type")
}

func generateSelfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "shuai-tunnel-go"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
