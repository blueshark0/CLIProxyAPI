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
