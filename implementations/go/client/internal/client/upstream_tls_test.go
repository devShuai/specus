package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSignedServer starts a TLS server with a certificate no system root will vouch for, which is
// exactly the situation the old code accepted unconditionally.
func selfSignedServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server
}

// The default has to be refusal. Anyone able to answer on the target address would otherwise be
// accepted, and the tunnel would carry the result to a remote user who cannot tell.
func TestUpstreamTLSRejectsAnUntrustedCertificateByDefault(t *testing.T) {
	server := selfSignedServer(t)
	client := newForwardingHTTPClient(newUpstreamTLSFactory(UpstreamTLSConfig{}))

	response, err := client.Get(server.URL)
	if err == nil {
		response.Body.Close()
		t.Fatal("a self-signed upstream must not be accepted without being configured")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("error should name the certificate problem, got: %v", err)
	}
}

// The opt-out still works, because some deployments genuinely cannot do better. It just has to be
// written down.
func TestUpstreamTLSAcceptsAnUntrustedCertificateWhenExplicitlyAllowed(t *testing.T) {
	server := selfSignedServer(t)
	client := newForwardingHTTPClient(newUpstreamTLSFactory(UpstreamTLSConfig{
		InsecureSkipVerify: true,
	}))

	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("an explicit opt-out must connect: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.StatusCode)
	}
}

// Naming the issuing CA is the right answer when the operator runs their own.
func TestUpstreamTLSTrustsAConfiguredCertificateAuthority(t *testing.T) {
	server := selfSignedServer(t)
	pemPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(pemPath, certificatePEM(t, server), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	client := newForwardingHTTPClient(newUpstreamTLSFactory(UpstreamTLSConfig{
		CACertificatePath: pemPath,
	}))
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("a configured CA must be trusted: %v", err)
	}
	defer response.Body.Close()
}

// Pinning suits a single self-signed target with no CA at all, and must reject anything else.
func TestUpstreamTLSPinningAcceptsOnlyThePinnedCertificate(t *testing.T) {
	server := selfSignedServer(t)
	leaf := server.Certificate().Raw
	digest := sha256.Sum256(leaf)

	matching := newForwardingHTTPClient(newUpstreamTLSFactory(UpstreamTLSConfig{
		PinnedCertificateSHA256: []string{hex.EncodeToString(digest[:])},
	}))
	response, err := matching.Get(server.URL)
	if err != nil {
		t.Fatalf("the pinned certificate must be accepted: %v", err)
	}
	response.Body.Close()

	// A server holding a genuinely different certificate, pinned to the first one's fingerprint,
	// must be refused. httptest reuses one built-in certificate for every server, so this one is
	// generated rather than taken from another httptest instance.
	other := distinctlyCertifiedServer(t)
	response, err = matching.Get(other.URL)
	if err == nil {
		response.Body.Close()
		t.Fatal("a certificate that does not match the pin must be refused")
	}
	if !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("error should name the pin, got: %v", err)
	}
}

// A fingerprint copied out of a tool usually has colons and uppercase; both forms are the same pin.
func TestUpstreamTLSAcceptsFingerprintsInTheFormToolsPrint(t *testing.T) {
	server := selfSignedServer(t)
	digest := sha256.Sum256(server.Certificate().Raw)
	hexDigest := hex.EncodeToString(digest[:])

	var colonised strings.Builder
	for i := 0; i < len(hexDigest); i += 2 {
		if i > 0 {
			colonised.WriteByte(':')
		}
		colonised.WriteString(strings.ToUpper(hexDigest[i : i+2]))
	}

	client := newForwardingHTTPClient(newUpstreamTLSFactory(UpstreamTLSConfig{
		PinnedCertificateSHA256: []string{colonised.String()},
	}))
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("a colon-separated uppercase fingerprint must work: %v", err)
	}
	response.Body.Close()
}

// Misconfiguration must fail loudly rather than quietly falling back to trusting everything.
func TestUpstreamTLSRejectsUnusableConfiguration(t *testing.T) {
	missing := newUpstreamTLSFactory(UpstreamTLSConfig{CACertificatePath: "no-such-file.pem"})
	if _, err := missing.forHost("example.test"); err == nil {
		t.Fatal("a missing CA file must be an error, not a silent fallback")
	}

	notPEM := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	if _, err := newUpstreamTLSFactory(UpstreamTLSConfig{CACertificatePath: notPEM}).forHost("x"); err == nil {
		t.Fatal("a CA file with no certificate in it must be an error")
	}

	shortPin := newUpstreamTLSFactory(UpstreamTLSConfig{PinnedCertificateSHA256: []string{"abcd"}})
	if _, err := shortPin.forHost("example.test"); err == nil {
		t.Fatal("a fingerprint that is not a SHA-256 digest must be an error")
	}

	notHex := newUpstreamTLSFactory(UpstreamTLSConfig{
		PinnedCertificateSHA256: []string{strings.Repeat("z", 64)},
	})
	if _, err := notHex.forHost("example.test"); err == nil {
		t.Fatal("a non-hex fingerprint must be an error")
	}
}

func TestUpstreamTLSSetsAFloorOnTheProtocolVersion(t *testing.T) {
	config, err := newUpstreamTLSFactory(UpstreamTLSConfig{}).forHost("example.test")
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if config.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want at least TLS 1.2", config.MinVersion)
	}
	if config.ServerName != "example.test" {
		t.Fatalf("ServerName = %q, want the dialled host so the name is actually checked",
			config.ServerName)
	}
	if config.InsecureSkipVerify {
		t.Fatal("the default configuration must verify")
	}
}

func certificatePEM(t *testing.T, server *httptest.Server) []byte {
	t.Helper()
	raw := server.Certificate().Raw
	encoded := "-----BEGIN CERTIFICATE-----\n"
	body := base64Wrap(raw)
	encoded += body + "-----END CERTIFICATE-----\n"
	return []byte(encoded)
}

func base64Wrap(raw []byte) string {
	const lineLength = 64
	encoded := base64.StdEncoding.EncodeToString(raw)
	var builder strings.Builder
	for start := 0; start < len(encoded); start += lineLength {
		end := start + lineLength
		if end > len(encoded) {
			end = len(encoded)
		}
		builder.WriteString(encoded[start:end])
		builder.WriteByte('\n')
	}
	return builder.String()
}

// distinctlyCertifiedServer starts a TLS server holding a freshly generated certificate, so it
// differs from the one httptest reuses across instances.
func distinctlyCertifiedServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "other.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
