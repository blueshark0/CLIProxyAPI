package upstreamtls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// writeTestCACert generates a self-signed CA certificate and writes it as PEM to
// a temp file, returning the file path.
func writeTestCACert(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err = os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}

func TestApplyDisabledClearsPool(t *testing.T) {
	t.Cleanup(func() { currentPool.Store(nil) })

	// Seed a non-nil pool first.
	currentPool.Store(x509.NewCertPool())

	if err := Apply(&config.Config{}); err != nil {
		t.Fatalf("Apply with disabled config returned error: %v", err)
	}
	if RootCAs() != nil {
		t.Fatalf("expected nil pool when trusted CA disabled")
	}
}

func TestApplyEnabledLoadsPool(t *testing.T) {
	t.Cleanup(func() { currentPool.Store(nil) })

	path := writeTestCACert(t)
	cfg := &config.Config{}
	cfg.TrustedCACert.Enable = true
	cfg.TrustedCACert.Path = path

	if err := Apply(cfg); err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if RootCAs() == nil {
		t.Fatalf("expected non-nil pool after loading trusted CA")
	}
}

func TestApplyEnabledEmptyPathClearsPool(t *testing.T) {
	t.Cleanup(func() { currentPool.Store(nil) })

	currentPool.Store(x509.NewCertPool())

	cfg := &config.Config{}
	cfg.TrustedCACert.Enable = true
	cfg.TrustedCACert.Path = "   "

	if err := Apply(cfg); err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if RootCAs() != nil {
		t.Fatalf("expected nil pool when path is empty")
	}
}

func TestApplyBadPathKeepsPreviousPool(t *testing.T) {
	t.Cleanup(func() { currentPool.Store(nil) })

	prev := x509.NewCertPool()
	currentPool.Store(prev)

	cfg := &config.Config{}
	cfg.TrustedCACert.Enable = true
	cfg.TrustedCACert.Path = filepath.Join(t.TempDir(), "does-not-exist.pem")

	if err := Apply(cfg); err == nil {
		t.Fatalf("expected error for missing certificate file")
	}
	if RootCAs() != prev {
		t.Fatalf("expected previous pool to remain after failed reload")
	}
}

func TestApplyInvalidPEMReturnsError(t *testing.T) {
	t.Cleanup(func() { currentPool.Store(nil) })

	path := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	cfg := &config.Config{}
	cfg.TrustedCACert.Enable = true
	cfg.TrustedCACert.Path = path

	if err := Apply(cfg); err == nil {
		t.Fatalf("expected error for PEM with no certificates")
	}
}
