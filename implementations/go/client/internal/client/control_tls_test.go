package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControlTLSEnabledFollowsRuntimeUnlessOverriddenOrConfigured(t *testing.T) {
	enabled := true
	disabled := false
	tests := []struct {
		name       string
		baseURL    string
		override   *bool
		runtime    bool
		serverName string
		wantTLS    bool
	}{
		{name: "runtime advertises TLS", baseURL: "http://server.example", runtime: true, wantTLS: true},
		{name: "HTTPS management URL does not imply TCP TLS", baseURL: "https://server.example", wantTLS: false},
		{name: "runtime TLS explicitly disabled", baseURL: "https://server.example", override: &disabled, runtime: true, wantTLS: false},
		{name: "plain runtime explicitly enabled", baseURL: "http://server.example", override: &enabled, wantTLS: true},
		{name: "TLS option implies enabled", baseURL: "http://server.example", serverName: "server.example", wantTLS: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Config{
				ServerBaseURL: test.baseURL,
				ControlTLS:    ControlTLSConfig{Enabled: test.override, ServerName: test.serverName},
			}
			if got := config.controlTLSEnabled(test.runtime); got != test.wantTLS {
				t.Fatalf("controlTLSEnabled() = %t, want %t", got, test.wantTLS)
			}
		})
	}
}

func TestLoadConfigAcceptsNullableControlTLS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jsonc")
	content := `{
  "serverBaseUrl": "https://server.example",
  "apiKey": "demo",
  "secret": "test1234",
  "controlTls": {
    "enabled": null,
    "caCertificatePath": "",
    "serverName": "",
    "insecureSkipVerify": false,
  },
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.ControlTLS.Enabled != nil {
		t.Fatalf("controlTls.enabled = %v, want nil", *config.ControlTLS.Enabled)
	}
	if config.controlTLSEnabled(false) {
		t.Fatal("HTTPS management URL must not implicitly enable raw TCP TLS")
	}
	tlsConfig, err := config.buildControlTLSConfig(true)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig == nil || tlsConfig.InsecureSkipVerify {
		t.Fatalf("unexpected default TLS config: %#v", tlsConfig)
	}
	if tlsConfig.RootCAs != nil {
		t.Fatal("default TLS config should leave RootCAs nil to use system roots")
	}
}

func TestControlTLSValidationRejectsInvalidOptionsAndCA(t *testing.T) {
	tempDir := t.TempDir()
	badPEMPath := filepath.Join(tempDir, "bad-ca.pem")
	if err := os.WriteFile(badPEMPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	disabled := false
	tests := []struct {
		name       string
		baseURL    string
		controlTLS ControlTLSConfig
		wantError  string
	}{
		{
			name:       "CA while disabled",
			baseURL:    "http://server.example",
			controlTLS: ControlTLSConfig{Enabled: &disabled, CACertificatePath: badPEMPath},
			wantError:  "caCertificatePath requires control TLS to be enabled",
		},
		{
			name:       "server name while explicitly disabled",
			baseURL:    "https://server.example",
			controlTLS: ControlTLSConfig{Enabled: &disabled, ServerName: "server.example"},
			wantError:  "serverName requires control TLS to be enabled",
		},
		{
			name:       "insecure verify while disabled",
			baseURL:    "http://server.example",
			controlTLS: ControlTLSConfig{Enabled: &disabled, InsecureSkipVerify: true},
			wantError:  "insecureSkipVerify requires control TLS to be enabled",
		},
		{
			name:       "server name contains port",
			baseURL:    "https://server.example",
			controlTLS: ControlTLSConfig{ServerName: "server.example:443"},
			wantError:  "serverName must not include a port",
		},
		{
			name:       "missing CA file",
			baseURL:    "https://server.example",
			controlTLS: ControlTLSConfig{CACertificatePath: filepath.Join(tempDir, "missing.pem")},
			wantError:  "read controlTls.caCertificatePath",
		},
		{
			name:       "invalid CA PEM",
			baseURL:    "https://server.example",
			controlTLS: ControlTLSConfig{CACertificatePath: badPEMPath},
			wantError:  "does not contain a valid PEM certificate",
		},
		{
			name:       "custom CA with verification disabled",
			baseURL:    "https://server.example",
			controlTLS: ControlTLSConfig{CACertificatePath: badPEMPath, InsecureSkipVerify: true},
			wantError:  "caCertificatePath cannot be combined with controlTls.insecureSkipVerify",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Config{
				ServerBaseURL: test.baseURL,
				APIKey:        "demo",
				Secret:        "test1234",
				ControlTLS:    test.controlTLS,
			}
			err := config.Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestDialServerConnectionUsesCustomCAAndHostnameVerification(t *testing.T) {
	caPath, serverConfig := newLocalTLSTestCertificate(t)
	configuredRoots, err := (Config{
		ServerBaseURL: "https://login.example",
		ControlTLS:    ControlTLSConfig{CACertificatePath: caPath, ServerName: "localhost"},
	}).buildControlTLSConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	subjectCount := 0
	if configuredRoots.RootCAs != nil {
		subjectCount = len(configuredRoots.RootCAs.Subjects())
	}
	if subjectCount != 1 {
		t.Fatalf("custom CA should be the exclusive trust root, subjects = %d", subjectCount)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErrors := make(chan error, 1)
	go func() {
		for index := byte(0); index < 2; index++ {
			rawConnection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverErrors <- acceptErr
				return
			}
			connection := tls.Server(rawConnection, serverConfig)
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			if handshakeErr := connection.Handshake(); handshakeErr != nil {
				_ = connection.Close()
				serverErrors <- handshakeErr
				return
			}
			_, writeErr := connection.Write([]byte{index + 1})
			_ = connection.Close()
			if writeErr != nil {
				serverErrors <- writeErr
				return
			}
		}
		serverErrors <- nil
	}()

	specusClient := New(Config{
		ServerBaseURL: "https://login.example",
		ControlTLS: ControlTLSConfig{
			CACertificatePath: caPath,
			ServerName:        "localhost",
		},
	}, log.New(io.Discard, "", 0))
	for index := byte(0); index < 2; index++ {
		connection, dialErr := specusClient.dialServerConnection(
			context.Background(), listener.Addr().String(), time.Second, false)
		if dialErr != nil {
			t.Fatalf("TLS dial %d failed: %v", index+1, dialErr)
		}
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		response := []byte{0}
		_, readErr := io.ReadFull(connection, response)
		_ = connection.Close()
		if readErr != nil {
			t.Fatalf("TLS dial %d read failed: %v", index+1, readErr)
		}
		if response[0] != index+1 {
			t.Fatalf("TLS dial %d response = %d", index+1, response[0])
		}
	}
	if err := <-serverErrors; err != nil {
		t.Fatalf("TLS server failed: %v", err)
	}
}

func TestDialServerConnectionRejectsHostnameMismatch(t *testing.T) {
	caPath, serverConfig := newLocalTLSTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		rawConnection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		connection := tls.Server(rawConnection, serverConfig)
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		_ = connection.Handshake()
		_ = connection.Close()
	}()

	specusClient := New(Config{
		ServerBaseURL: "https://login.example",
		ControlTLS: ControlTLSConfig{
			CACertificatePath: caPath,
			ServerName:        "other.example",
		},
	}, log.New(io.Discard, "", 0))
	connection, err := specusClient.dialServerConnection(
		context.Background(), listener.Addr().String(), time.Second, false)
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "certificate is valid for localhost") {
		t.Fatalf("TLS dial error = %v, want hostname verification failure", err)
	}
	<-serverDone
}

func TestDialServerConnectionTimeoutIncludesTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	specusClient := New(Config{
		ServerBaseURL: "https://login.example",
		ControlTLS:    ControlTLSConfig{InsecureSkipVerify: true},
	}, log.New(io.Discard, "", 0))
	started := time.Now()
	connection, err := specusClient.dialServerConnection(
		context.Background(), listener.Addr().String(), 100*time.Millisecond, false)
	elapsed := time.Since(started)
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil {
		t.Fatal("TLS dial unexpectedly completed without a server handshake")
	}
	if elapsed > time.Second {
		t.Fatalf("TLS handshake timeout took %s, want no more than 1s", elapsed)
	}
	select {
	case serverConnection := <-accepted:
		_ = serverConnection.Close()
	case <-time.After(time.Second):
		t.Fatal("test server did not accept TLS connection")
	}
}

func TestDialServerConnectionUsesPlainTCPWhenTLSDisabled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		_, writeErr := connection.Write([]byte("P"))
		_ = connection.Close()
		serverDone <- writeErr
	}()

	specusClient := New(Config{ServerBaseURL: "http://login.example"}, log.New(io.Discard, "", 0))
	connection, err := specusClient.dialServerConnection(
		context.Background(), listener.Addr().String(), time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	response := []byte{0}
	_, err = io.ReadFull(connection, response)
	_ = connection.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response[0] != 'P' {
		t.Fatalf("plain TCP response = %q", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialServerConnectionRejectsNonPositiveTimeout(t *testing.T) {
	specusClient := New(Config{}, log.New(io.Discard, "", 0))
	connection, err := specusClient.dialServerConnection(
		context.Background(), "127.0.0.1:1", 0, false)
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "timeout must be positive") {
		t.Fatalf("dial error = %v", err)
	}
}

func newLocalTLSTestCertificate(t *testing.T) (string, *tls.Config) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath, &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certificateDER},
			PrivateKey:  privateKey,
		}},
	}
}
