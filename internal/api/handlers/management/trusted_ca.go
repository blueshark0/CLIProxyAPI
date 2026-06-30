package management

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/upstreamtls"
	log "github.com/sirupsen/logrus"
)

const (
	// systemCACertDir is the directory scanned by update-ca-certificates on
	// Debian/Ubuntu/Alpine based systems. Certificates dropped here become part
	// of the system trust store after update-ca-certificates runs.
	systemCACertDir = "/usr/local/share/ca-certificates"
	// trustedCACertFileName is the file name used for the proxy-managed CA cert.
	// update-ca-certificates only picks up files with a .crt extension.
	trustedCACertFileName = "cliproxy-trusted-ca.crt"
	// updateCACertificatesTimeout bounds the best-effort system trust refresh so
	// a misbehaving command cannot block the management request indefinitely.
	updateCACertificatesTimeout = 30 * time.Second
)

// GetTrustedCACert returns the current trusted CA certificate configuration.
func (h *Handler) GetTrustedCACert(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusOK, gin.H{"enable": false, "path": ""})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"enable": h.cfg.TrustedCACert.Enable,
		"path":   strings.TrimSpace(h.cfg.TrustedCACert.Path),
	})
}

// UploadTrustedCACert accepts a PEM-encoded CA certificate (multipart file field
// "file", or raw request body), stores it, installs it into the system trust
// store on a best-effort basis, and trusts it in-process for upstream requests.
func (h *Handler) UploadTrustedCACert(c *gin.Context) {
	pemBytes, err := h.readUploadedCACert(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err = validateCACertPEM(pemBytes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	storedPath, systemInstalled, err := h.storeTrustedCACert(pemBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.cfg.TrustedCACert.Enable = true
	h.cfg.TrustedCACert.Path = storedPath

	// Apply to the in-process trust pool first: this is what makes the running
	// application trust the certificate immediately and must always succeed.
	if errApply := upstreamtls.Apply(h.cfg); errApply != nil {
		// Roll back the config change so we do not persist an unusable state.
		h.cfg.TrustedCACert.Enable = false
		h.cfg.TrustedCACert.Path = ""
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to trust certificate: %v", errApply)})
		return
	}

	if !h.persistLocked(c) {
		return
	}

	log.Infof("trusted CA certificate stored at %s (system trust installed=%v)", storedPath, systemInstalled)
}

// DeleteTrustedCACert disables and removes the trusted CA certificate.
func (h *Handler) DeleteTrustedCACert(c *gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	prevPath := strings.TrimSpace(h.cfg.TrustedCACert.Path)

	h.cfg.TrustedCACert.Enable = false
	h.cfg.TrustedCACert.Path = ""

	if err := upstreamtls.Apply(h.cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update trust pool: %v", err)})
		return
	}

	// Best-effort cleanup of the stored certificate and the system trust entry.
	if prevPath != "" {
		if errRemove := os.Remove(prevPath); errRemove != nil && !os.IsNotExist(errRemove) {
			log.WithError(errRemove).Warnf("failed to remove trusted CA certificate file %s", prevPath)
		}
	}
	systemPath := filepath.Join(systemCACertDir, trustedCACertFileName)
	if systemPath != prevPath {
		if errRemove := os.Remove(systemPath); errRemove != nil && !os.IsNotExist(errRemove) {
			log.WithError(errRemove).Debugf("failed to remove system trusted CA certificate file %s", systemPath)
		}
	}
	runUpdateCACertificates()

	if !h.persistLocked(c) {
		return
	}
	log.Info("trusted CA certificate removed")
}

// readUploadedCACert extracts PEM bytes from a multipart upload or the raw body.
func (h *Handler) readUploadedCACert(c *gin.Context) ([]byte, error) {
	if c.ContentType() == "multipart/form-data" {
		fileHeader, err := c.FormFile("file")
		if err != nil {
			return nil, fmt.Errorf("missing uploaded certificate file: %w", err)
		}
		src, errOpen := fileHeader.Open()
		if errOpen != nil {
			return nil, fmt.Errorf("failed to open uploaded file: %w", errOpen)
		}
		defer func() {
			if errClose := src.Close(); errClose != nil {
				log.WithError(errClose).Debug("failed to close uploaded CA cert file")
			}
		}()
		data, errRead := io.ReadAll(io.LimitReader(src, 1<<20))
		if errRead != nil {
			return nil, fmt.Errorf("failed to read uploaded file: %w", errRead)
		}
		return data, nil
	}

	data, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("empty certificate payload")
	}
	return data, nil
}

// validateCACertPEM ensures the payload contains at least one parseable
// certificate so we never persist garbage that would break the trust pool.
func validateCACertPEM(pemBytes []byte) error {
	rest := pemBytes
	found := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("invalid certificate: %w", err)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("no PEM-encoded certificate found in upload")
	}
	return nil
}

// storeTrustedCACert writes the certificate to the system CA directory when
// possible (so update-ca-certificates and other tools also trust it) and falls
// back to an application-writable location otherwise. It returns the path that
// should be recorded in the config for in-process trust, and whether the system
// trust store was updated.
func (h *Handler) storeTrustedCACert(pemBytes []byte) (string, bool, error) {
	// Attempt system trust store installation (Linux, best-effort).
	if runtime.GOOS == "linux" {
		systemPath := filepath.Join(systemCACertDir, trustedCACertFileName)
		if err := os.MkdirAll(systemCACertDir, 0o755); err == nil {
			if errWrite := os.WriteFile(systemPath, pemBytes, 0o644); errWrite == nil {
				runUpdateCACertificates()
				return systemPath, true, nil
			} else {
				log.WithError(errWrite).Warnf("failed to write CA cert to %s; falling back to application directory", systemPath)
			}
		} else {
			log.WithError(err).Debugf("failed to prepare %s; falling back to application directory", systemCACertDir)
		}
	}

	// Fall back to an application-writable directory; in-process trust still works.
	fallbackDir := h.trustedCACertFallbackDir()
	if errMkdir := os.MkdirAll(fallbackDir, 0o755); errMkdir != nil {
		return "", false, fmt.Errorf("failed to prepare certificate directory: %w", errMkdir)
	}
	fallbackPath := filepath.Join(fallbackDir, trustedCACertFileName)
	if errWrite := os.WriteFile(fallbackPath, pemBytes, 0o644); errWrite != nil {
		return "", false, fmt.Errorf("failed to store certificate: %w", errWrite)
	}
	return fallbackPath, false, nil
}

// trustedCACertFallbackDir resolves a writable directory for the certificate
// when the system trust directory is not usable.
func (h *Handler) trustedCACertFallbackDir() string {
	if h != nil {
		if cfgPath := strings.TrimSpace(h.configFilePath); cfgPath != "" {
			return filepath.Join(filepath.Dir(cfgPath), "certs")
		}
		if h.cfg != nil {
			if authDir := strings.TrimSpace(h.cfg.AuthDir); authDir != "" {
				return filepath.Join(authDir, "certs")
			}
		}
	}
	return filepath.Join(".", "certs")
}

// runUpdateCACertificates refreshes the system trust store on a best-effort
// basis. Failures (missing binary, non-root, non-Linux) are logged and ignored
// because in-process trust is the authoritative mechanism for upstream requests.
func runUpdateCACertificates() {
	if runtime.GOOS != "linux" {
		return
	}
	binary, err := exec.LookPath("update-ca-certificates")
	if err != nil {
		log.WithError(err).Debug("update-ca-certificates not found; skipping system trust refresh")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), updateCACertificatesTimeout)
	defer cancel()
	out, errRun := exec.CommandContext(ctx, binary).CombinedOutput()
	if errRun != nil {
		log.WithError(errRun).Warnf("update-ca-certificates failed: %s", strings.TrimSpace(string(out)))
		return
	}
	log.Debug("system CA trust store refreshed via update-ca-certificates")
}
