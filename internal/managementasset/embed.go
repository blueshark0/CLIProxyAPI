// Package managementasset serves the bundled management control panel.
//
// The panel (management.html) is built from the separate management center
// project and embedded into the binary at compile time. This package previously
// downloaded the asset from GitHub at runtime and kept it up to date in the
// background; that remote source and auto-updater have been removed in favor of
// a self-contained embedded asset.
package managementasset

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

// managementAssetName is the public file name of the control panel asset.
const managementAssetName = "management.html"

// ManagementFileName exposes the control panel asset filename.
const ManagementFileName = managementAssetName

//go:embed management.html
var managementHTML []byte

// ManagementHTML returns the embedded management control panel document.
func ManagementHTML() []byte {
	return managementHTML
}

// StaticDir resolves the directory that stores an optional external management
// control panel asset. When empty, the embedded asset is used instead.
func StaticDir(configFilePath string) string {
	if override := strings.TrimSpace(os.Getenv("MANAGEMENT_STATIC_PATH")); override != "" {
		cleaned := filepath.Clean(override)
		if strings.EqualFold(filepath.Base(cleaned), managementAssetName) {
			return filepath.Dir(cleaned)
		}
		return cleaned
	}

	if writable := util.WritablePath(); writable != "" {
		return filepath.Join(writable, "static")
	}

	configFilePath = strings.TrimSpace(configFilePath)
	if configFilePath == "" {
		return ""
	}

	base := filepath.Dir(configFilePath)
	fileInfo, err := os.Stat(configFilePath)
	if err == nil {
		if fileInfo.IsDir() {
			base = configFilePath
		}
	}

	return filepath.Join(base, "static")
}

// FilePath resolves the absolute path to an external management control panel
// asset when one is configured or already present on disk. It returns an empty
// string when the caller should fall back to the embedded asset.
func FilePath(configFilePath string) string {
	if override := strings.TrimSpace(os.Getenv("MANAGEMENT_STATIC_PATH")); override != "" {
		cleaned := filepath.Clean(override)
		if strings.EqualFold(filepath.Base(cleaned), managementAssetName) {
			return cleaned
		}
		return filepath.Join(cleaned, ManagementFileName)
	}

	dir := StaticDir(configFilePath)
	if dir == "" {
		return ""
	}
	candidate := filepath.Join(dir, ManagementFileName)
	if _, err := os.Stat(candidate); err != nil {
		// No external asset on disk: the embedded asset serves the panel.
		return ""
	}
	return candidate
}
