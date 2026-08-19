package client

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Upstream TLS is the connection from this client to the service it forwards to. It used to be
// established with verification disabled outright, on the reasoning that an operator's LAN target
// may present a self-signed certificate. That reasoning trades a real guarantee for a convenience:
// anyone able to answer on that address, or to sit between us and it, is accepted silently, and
// the tunnel then carries the result to a remote user who has no way to notice.
//
// Verification is now the default. A self-signed target is still supported, but only by saying so:
// point at the CA that issued it, pin its certificate, or state plainly that this target is not to
// be verified.
type UpstreamTLSConfig struct {
	// InsecureSkipVerify accepts any certificate. It exists because some deployments genuinely
	// cannot do better; it has to be written down rather than assumed.
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
	// CACertificatePath trusts a private CA in addition to the system roots, which is the right
	// answer when the operator runs their own issuer.
	CACertificatePath string `json:"caCertificatePath"`
	// PinnedCertificateSHA256 accepts exactly these leaf certificates, as lowercase hex SHA-256
	// fingerprints. Pinning suits a single self-signed target that has no CA at all.
	PinnedCertificateSHA256 []string `json:"pinnedCertificateSha256"`
}

// upstreamTLSFactory builds the tls.Config for upstream connections, loading any configured trust
// material once rather than on every request.
type upstreamTLSFactory struct {
	once     sync.Once
	config   UpstreamTLSConfig
	roots    *x509.CertPool
	pinned   map[string]struct{}
	loadErr  error
	insecure bool
}

func newUpstreamTLSFactory(config UpstreamTLSConfig) *upstreamTLSFactory {
	return &upstreamTLSFactory{config: config, insecure: config.InsecureSkipVerify}
}

func (f *upstreamTLSFactory) load() {
	f.once.Do(func() {
		if path := strings.TrimSpace(f.config.CACertificatePath); path != "" {
			pem, err := os.ReadFile(path)
			if err != nil {
				f.loadErr = fmt.Errorf("read upstream CA certificate: %w", err)
				return
			}
			// Start from the system roots so naming a private CA adds trust rather than
			// replacing it; a target with a public certificate keeps working.
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				f.loadErr = fmt.Errorf("upstream CA certificate %s contains no usable certificate", path)
				return
			}
			f.roots = pool
		}

		for _, fingerprint := range f.config.PinnedCertificateSHA256 {
			normalized := normalizeFingerprint(fingerprint)
			if normalized == "" {
				continue
			}
			if len(normalized) != sha256.Size*2 {
				f.loadErr = fmt.Errorf("pinned certificate fingerprint %q is not a SHA-256 digest", fingerprint)
				return
			}
			if _, err := hex.DecodeString(normalized); err != nil {
				f.loadErr = fmt.Errorf("pinned certificate fingerprint %q is not hex", fingerprint)
				return
			}
			if f.pinned == nil {
				f.pinned = make(map[string]struct{})
			}
			f.pinned[normalized] = struct{}{}
		}
	})
}

// forHost returns the TLS configuration to use when dialling serverName.
func (f *upstreamTLSFactory) forHost(serverName string) (*tls.Config, error) {
	f.load()
	if f.loadErr != nil {
		return nil, f.loadErr
	}

	config := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	if f.insecure {
		config.InsecureSkipVerify = true
		return config, nil
	}
	if f.roots != nil {
		config.RootCAs = f.roots
	}
	if len(f.pinned) > 0 {
		// Pinning replaces chain verification for this connection: a pinned target usually has no
		// chain to verify. The pin itself is the check, and it is stricter than a chain.
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = f.verifyPin
	}
	return config, nil
}

var errNoPinnedCertificate = errors.New("upstream presented no certificate to match against the pin")

func (f *upstreamTLSFactory) verifyPin(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errNoPinnedCertificate
	}
	// Only the leaf is pinned; intermediates are free to change.
	digest := sha256.Sum256(rawCerts[0])
	if _, ok := f.pinned[hex.EncodeToString(digest[:])]; ok {
		return nil
	}
	return fmt.Errorf("upstream certificate %s does not match any pinned fingerprint",
		hex.EncodeToString(digest[:]))
}

func normalizeFingerprint(value string) string {
	// Tools print fingerprints as colon-separated uppercase pairs; accept that form too.
	replacer := strings.NewReplacer(":", "", " ", "", "-", "")
	return strings.ToLower(replacer.Replace(strings.TrimSpace(value)))
}

// upstreamTLSFactory returns the client's trust policy, building it on first use so a client
// constructed in a test without going through the normal setup still behaves securely.
func (c *Client) upstreamTLSFactory() *upstreamTLSFactory {
	c.upstreamTLSOnce.Do(func() {
		if c.upstreamTLS == nil {
			c.upstreamTLS = newUpstreamTLSFactory(c.config.UpstreamTLS)
		}
	})
	return c.upstreamTLS
}

// forwardingHTTPClient returns the shared HTTP client used to reach forwarding targets.
func (c *Client) forwardingHTTPClient() *http.Client {
	c.forwardHTTPOnce.Do(func() {
		if c.forwardHTTP == nil {
			c.forwardHTTP = newForwardingHTTPClient(c.upstreamTLSFactory())
		}
	})
	return c.forwardHTTP
}
