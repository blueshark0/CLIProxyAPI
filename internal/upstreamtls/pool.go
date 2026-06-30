// Package upstreamtls maintains an in-process trust pool used when the proxy
// connects to upstream providers. Go caches the result of x509.SystemCertPool
// for the lifetime of the process, so installing a certificate into the system
// trust store at runtime does not affect already-running clients. To make the
// running application trust an additional CA immediately, all upstream HTTP
// clients consult RootCAs(): when an extra CA is configured, it returns a pool
// containing the system roots plus the extra certificate; otherwise it returns
// nil so clients keep using the default system trust store.
package upstreamtls

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	log "github.com/sirupsen/logrus"
)

// currentPool stores the active trust pool. A nil pointer means no additional
// CA is trusted and clients should fall back to the system trust store.
var currentPool atomic.Pointer[x509.CertPool]

// RootCAs returns the active trust pool for upstream requests, or nil when no
// additional CA certificate is configured. A nil result instructs TLS clients
// to use the default system trust store.
func RootCAs() *x509.CertPool {
	return currentPool.Load()
}

// Apply rebuilds the in-process trust pool from the provided configuration.
// When the trusted CA is disabled or unset, the pool is cleared and clients
// revert to the system trust store. When enabled, the PEM file is loaded and
// merged with the system roots. An error is returned when the certificate
// cannot be read or contains no usable certificates; in that case the previous
// pool is left untouched so a bad reload does not break upstream connectivity.
func Apply(cfg *config.Config) error {
	if cfg == nil || !cfg.TrustedCACert.Enable {
		currentPool.Store(nil)
		return nil
	}

	path := strings.TrimSpace(cfg.TrustedCACert.Path)
	if path == "" {
		currentPool.Store(nil)
		return nil
	}

	pool, err := buildPool(path)
	if err != nil {
		return err
	}
	currentPool.Store(pool)
	log.Infof("upstream trust pool updated with additional CA certificate: %s", path)
	return nil
}

// buildPool reads the PEM file at path and returns a certificate pool that
// combines the system trust store with the additional certificate.
func buildPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trusted ca cert: %w", err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// Fall back to an empty pool when the system store is unavailable.
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("trusted ca cert contains no PEM certificates")
	}
	return pool, nil
}
