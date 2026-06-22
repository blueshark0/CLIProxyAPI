package executor

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"regexp"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	claudeCCHPrime64_1 uint64 = 0x9E3779B185EBCA87
	claudeCCHPrime64_2 uint64 = 0xC2B2AE3D27D4EB4F
	claudeCCHPrime64_3 uint64 = 0x165667B19E3779F9
	claudeCCHPrime64_4 uint64 = 0x85EBCA77C2B2AE63
	claudeCCHPrime64_5 uint64 = 0x27D4EB2F165667C5

	// CCH attestation lanes for SEED_2_1_138.
	// Extracted via oracle approach from Claude Code ARM64 macOS binaries.
	// Reference: https://github.com/BYK/loreai
	claudeCCHAttestV1 uint64 = 0xAE4FBA0790EAE83E
	claudeCCHAttestV2 uint64 = 0x101840560AFF1DB7
	claudeCCHAttestV3 uint64 = 0x4D659218E32A3268 // SEED_2_1_138 (used 2.1.138-2.1.185+)
	claudeCCHAttestV4 uint64 = 0xAF2E18675D3E67E1

	claudeCCHWorkerVersion = "2.1.185"

	// Named seed constants for version mapping
	claudeSeed_2_1_37  uint64 = 0x6E52736AC806831E
	claudeSeed_2_1_138 uint64 = 0x4D659218E32A3268 // Same as AttestV3
)

// versionSeeds maps Claude Code versions to their xxHash64 seeds.
// Seeds extracted via oracle approach from ARM64 macOS binaries.
// Claude Code reuses the same seed across many consecutive versions.
var versionSeeds = map[string]uint64{
	"2.1.37":  claudeSeed_2_1_37,
	"2.1.138": claudeSeed_2_1_138,
	"2.1.139": claudeSeed_2_1_138,
	"2.1.140": claudeSeed_2_1_138,
	"2.1.141": claudeSeed_2_1_138,
	"2.1.142": claudeSeed_2_1_138,
	"2.1.143": claudeSeed_2_1_138,
	"2.1.144": claudeSeed_2_1_138,
	"2.1.145": claudeSeed_2_1_138,
	"2.1.146": claudeSeed_2_1_138,
	"2.1.147": claudeSeed_2_1_138,
	"2.1.148": claudeSeed_2_1_138,
	"2.1.149": claudeSeed_2_1_138,
	"2.1.150": claudeSeed_2_1_138,
	"2.1.152": claudeSeed_2_1_138,
	"2.1.153": claudeSeed_2_1_138,
	"2.1.154": claudeSeed_2_1_138,
	"2.1.156": claudeSeed_2_1_138,
	"2.1.157": claudeSeed_2_1_138,
	"2.1.158": claudeSeed_2_1_138,
	"2.1.159": claudeSeed_2_1_138,
	"2.1.160": claudeSeed_2_1_138,
	"2.1.161": claudeSeed_2_1_138,
	"2.1.162": claudeSeed_2_1_138,
	"2.1.163": claudeSeed_2_1_138,
	"2.1.165": claudeSeed_2_1_138,
	"2.1.166": claudeSeed_2_1_138,
	"2.1.167": claudeSeed_2_1_138,
	"2.1.168": claudeSeed_2_1_138,
	"2.1.169": claudeSeed_2_1_138,
	"2.1.170": claudeSeed_2_1_138,
	// 2.1.172+: seed UNCHANGED, but the cch hash preimage changed - the binary
	// strips the model value and the max_tokens field before hashing. See
	// cchPreimage() for details.
	"2.1.172": claudeSeed_2_1_138,
	"2.1.173": claudeSeed_2_1_138,
	"2.1.175": claudeSeed_2_1_138,
	"2.1.176": claudeSeed_2_1_138,
	"2.1.177": claudeSeed_2_1_138,
	"2.1.178": claudeSeed_2_1_138,
	"2.1.179": claudeSeed_2_1_138,
	"2.1.181": claudeSeed_2_1_138,
	"2.1.182": claudeSeed_2_1_138,
	"2.1.183": claudeSeed_2_1_138,
	"2.1.185": claudeSeed_2_1_138,
	// Future versions: extract and add entries here
}

var (
	claudeBillingHeaderCCHPattern = regexp.MustCompile(`\bcch=([0-9a-fA-F]{5});`)
	claudeBillingHeaderPattern    = regexp.MustCompile(`^x-anthropic-billing-header:\s*cc_version=[^;]*;\s*cc_entrypoint=[^;]*;(?:\s*cch=[0-9a-fA-F]{5};)?`)
)

// ccVersionPattern extracts the version from the billing header
// Format: cc_version=2.1.172.abc or cc_version=2.1.172
var ccVersionPattern = regexp.MustCompile(`cc_version=(\d+\.\d+\.\d+)`)

// Regular expressions for CCH preimage transformation (Claude Code >= 2.1.172)
var (
	// modelValueRE clears the model value: `"model":"<value>"` -> `"model":""`
	// Matches the first occurrence only.
	modelValueRE = regexp.MustCompile(`("model":")[^"]*(")`)

	// maxTokensFieldRE removes the max_tokens field (key + integer value + one adjacent comma).
	// Claude Code always emits max_tokens mid-object, so the trailing-comma form is standard.
	// We match an optional LEADING comma as defensive fallback for last-key position.
	// The alternation removes exactly ONE comma: trailing (standard) or leading (fallback).
	maxTokensFieldRE = regexp.MustCompile(`"max_tokens":\d+,|,"max_tokens":\d+`)
)

const billingMarker = "x-anthropic-billing-header:"

// extractVersionFromBillingHeader extracts the Claude Code version from the
// billing header. Returns empty string if version not found.
//
// Example: "cc_version=2.1.172.abc; ..." -> "2.1.172"
func extractVersionFromBillingHeader(billingHeader string) string {
	matches := ccVersionPattern.FindStringSubmatch(billingHeader)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// shouldApplyPreimage determines whether to apply preimage transformation
// based on the Claude Code version extracted from the billing header.
//
// Version behavior:
//   - <= 2.1.170: hash raw body (no preimage)
//   - >= 2.1.172: hash preimage (strip model value, remove max_tokens)
//   - 2.1.171: unknown (assume raw body for safety)
//   - no version: apply preimage (assume latest behavior)
func shouldApplyPreimage(version string) bool {
	if version == "" {
		// No version found: assume latest behavior (with preimage)
		// This handles cases where billing header format doesn't include version
		return true
	}

	// Parse semver
	var major, minor, patch int
	if _, err := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch); err != nil {
		// Parse error: default to preimage for safety
		return true
	}

	// Version comparison: >= 2.1.172 uses preimage
	if major > 2 {
		return true
	}
	if major == 2 && minor > 1 {
		return true
	}
	if major == 2 && minor == 1 && patch >= 172 {
		return true
	}

	// <= 2.1.170 (and 2.1.171 for safety)
	return false
}

func cchSeedForVersion(version string) uint64 {
	if seed, ok := versionSeeds[version]; ok {
		return seed
	}
	return versionSeeds[claudeCCHWorkerVersion]
}

func claudeCCHKeyedXXHash64Seed(body []byte, seed uint64) uint64 {
	return claudeCCHKeyedXXHash64(
		body,
		seed+claudeCCHPrime64_1+claudeCCHPrime64_2,
		seed+claudeCCHPrime64_2,
		seed,
		seed-claudeCCHPrime64_1,
	)
}

// cchPreimage transforms a serialized request body into the exact byte sequence
// Claude Code (>= 2.1.172) feeds to xxHash64 when computing the cch billing hash.
//
// Discovered by capturing live hash input under a debugger: the binary does NOT
// hash the raw wire body. It hashes the body with three edits applied:
//  1. cch=<5hex> -> cch=00000 (the placeholder; callers usually pre-apply this)
//  2. the model VALUE removed: `"model":"sonnet-4"` -> `"model":""`
//  3. the max_tokens field removed: `"max_tokens":64000,` -> "" (with comma)
//
// The seed (0x4D659218E32A3268) and algorithm (XXHash64) are unchanged from
// 2.1.166; only the preimage changed. Versions <= 2.1.170 hashed the whole body.
// Both edits are no-ops when the field is absent (e.g. test bodies or worker
// requests without max_tokens), keeping the function safe to apply unconditionally.
//
// Reference: https://github.com/BYK/loreai/blob/main/packages/gateway/src/cch.ts
func cchPreimage(body []byte) []byte {
	s := string(body)
	// Clear model value: "model":"<value>" -> "model":""
	s = modelValueRE.ReplaceAllString(s, "$1$2")
	// Remove max_tokens field entirely (including one adjacent comma)
	s = maxTokensFieldRE.ReplaceAllString(s, "")
	return []byte(s)
}

// verifyBillingHeaderUnique checks that the body contains exactly ONE
// billing header marker. Multiple markers could cause first-match regex
// to sign the wrong token (e.g. an LTM entry documenting the header format).
//
// Both signAnthropicMessagesBody and any future resignBody use first-match
// .ReplaceAll and trust that the single match is the real header (always
// system[0], nothing precedes it). That trust is only safe when the marker
// is unique.
//
// This is report-only: signing proceeds unchanged, but we log a warning
// as an early warning signal. In practice this should never fire.
func verifyBillingHeaderUnique(body []byte, caller string) {
	count := strings.Count(string(body), billingMarker)
	if count <= 1 {
		return // Unique or absent - invariant holds
	}

	logrus.WithFields(logrus.Fields{
		"caller":      caller,
		"markerCount": count,
		"bodyLength":  len(body),
	}).Warn("CCH: billing-header first-block invariant violated - " +
		"first-match may sign wrong token and bust prompt cache")
}

func signAnthropicMessagesBody(body []byte) []byte {
	verifyBillingHeaderUnique(body, "signAnthropicMessagesBody")
	billingHeader := gjson.GetBytes(body, "system.0.text").String()
	if !strings.HasPrefix(billingHeader, "x-anthropic-billing-header:") {
		return body
	}
	if !claudeBillingHeaderPattern.MatchString(billingHeader) {
		return body
	}
	headerRange := claudeBillingHeaderPattern.FindStringIndex(billingHeader)
	if headerRange == nil {
		return body
	}

	unsignedBillingHeader := billingHeader
	unsignedHeaderPrefix := unsignedBillingHeader[:headerRange[1]]
	unsignedHeaderSuffix := unsignedBillingHeader[headerRange[1]:]
	if claudeBillingHeaderCCHPattern.MatchString(unsignedHeaderPrefix) {
		unsignedHeaderPrefix = claudeBillingHeaderCCHPattern.ReplaceAllString(unsignedHeaderPrefix, "cch=00000;")
	} else {
		unsignedHeaderPrefix += " cch=00000;"
	}
	unsignedBillingHeader = unsignedHeaderPrefix + unsignedHeaderSuffix
	unsignedBody, err := sjson.SetBytes(body, "system.0.text", unsignedBillingHeader)
	if err != nil {
		return body
	}

	// Extract version to determine preimage behavior
	version := extractVersionFromBillingHeader(billingHeader)
	cch := computeClaudeCCHWithVersion(unsignedBody, version)
	signedBillingHeader := claudeBillingHeaderCCHPattern.ReplaceAllString(unsignedHeaderPrefix, "cch="+cch+";") + unsignedHeaderSuffix
	signedBody, err := sjson.SetBytes(unsignedBody, "system.0.text", signedBillingHeader)
	if err != nil {
		return unsignedBody
	}
	return signedBody
}

func computeClaudeCCHWithVersion(body []byte, version string) string {
	// Apply preimage transformation conditionally based on version
	var hashInput []byte
	if shouldApplyPreimage(version) {
		hashInput = cchPreimage(body)
	} else {
		hashInput = body
	}

	h := claudeCCHKeyedXXHash64Seed(hashInput, cchSeedForVersion(version))
	return fmt.Sprintf("%05x", h&0xFFFFF)
}

// computeClaudeCCH computes CCH hash assuming latest version behavior (with preimage).
// Deprecated: Use computeClaudeCCHWithVersion for version-aware hashing.
func computeClaudeCCH(body []byte) string {
	// Apply preimage transformation (Claude Code >= 2.1.172)
	// This clears the model value and removes max_tokens field before hashing.
	// Safe to apply unconditionally: no-op when fields are absent.
	preimage := cchPreimage(body)
	h := claudeCCHKeyedXXHash64Seed(preimage, claudeSeed_2_1_138)
	return fmt.Sprintf("%05x", h&0xFFFFF)
}

func claudeCCHXXHRound(state, lane uint64) uint64 {
	state += lane * claudeCCHPrime64_2
	state = bits.RotateLeft64(state, 31)
	state *= claudeCCHPrime64_1
	return state
}

func claudeCCHXXHMergeRound(acc, val uint64) uint64 {
	val = claudeCCHXXHRound(0, val)
	acc ^= val
	return acc*claudeCCHPrime64_1 + claudeCCHPrime64_4
}

func claudeCCHKeyedXXHash64(body []byte, v1, v2, v3, v4 uint64) uint64 {
	n := len(body)
	i := 0
	var h uint64

	if n >= 32 {
		for i+32 <= n {
			v1 = claudeCCHXXHRound(v1, binary.LittleEndian.Uint64(body[i:]))
			v2 = claudeCCHXXHRound(v2, binary.LittleEndian.Uint64(body[i+8:]))
			v3 = claudeCCHXXHRound(v3, binary.LittleEndian.Uint64(body[i+16:]))
			v4 = claudeCCHXXHRound(v4, binary.LittleEndian.Uint64(body[i+24:]))
			i += 32
		}
		h = bits.RotateLeft64(v1, 1) +
			bits.RotateLeft64(v2, 7) +
			bits.RotateLeft64(v3, 12) +
			bits.RotateLeft64(v4, 18)
		h = claudeCCHXXHMergeRound(h, v1)
		h = claudeCCHXXHMergeRound(h, v2)
		h = claudeCCHXXHMergeRound(h, v3)
		h = claudeCCHXXHMergeRound(h, v4)
	} else {
		h = v3 + claudeCCHPrime64_5
	}
	h += uint64(n)

	for i+8 <= n {
		k := binary.LittleEndian.Uint64(body[i:])
		k = claudeCCHXXHRound(0, k)
		h ^= k
		h = bits.RotateLeft64(h, 27)*claudeCCHPrime64_1 + claudeCCHPrime64_4
		i += 8
	}
	for i+4 <= n {
		k := uint64(binary.LittleEndian.Uint32(body[i:]))
		h ^= k * claudeCCHPrime64_1
		h = bits.RotateLeft64(h, 23)*claudeCCHPrime64_2 + claudeCCHPrime64_3
		i += 4
	}
	for i < n {
		h ^= uint64(body[i]) * claudeCCHPrime64_5
		h = bits.RotateLeft64(h, 11) * claudeCCHPrime64_1
		i++
	}

	h ^= h >> 33
	h *= claudeCCHPrime64_2
	h ^= h >> 29
	h *= claudeCCHPrime64_3
	h ^= h >> 32
	return h
}

func resolveClaudeKeyConfig(cfg *config.Config, auth *cliproxyauth.Auth) *config.ClaudeKey {
	if cfg == nil || auth == nil {
		return nil
	}

	apiKey, baseURL := claudeCreds(auth)
	if apiKey == "" {
		return nil
	}

	for i := range cfg.ClaudeKey {
		entry := &cfg.ClaudeKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if !strings.EqualFold(cfgKey, apiKey) {
			continue
		}
		if baseURL != "" && cfgBase != "" && !strings.EqualFold(cfgBase, baseURL) {
			continue
		}
		return entry
	}

	return nil
}

// resolveClaudeKeyCloakConfig finds the matching ClaudeKey config and returns its CloakConfig.
func resolveClaudeKeyCloakConfig(cfg *config.Config, auth *cliproxyauth.Auth) *config.CloakConfig {
	entry := resolveClaudeKeyConfig(cfg, auth)
	if entry == nil {
		return nil
	}
	return entry.Cloak
}

func experimentalCCHSigningEnabled(cfg *config.Config, auth *cliproxyauth.Auth) bool {
	entry := resolveClaudeKeyConfig(cfg, auth)
	return entry != nil && entry.ExperimentalCCHSigning
}
