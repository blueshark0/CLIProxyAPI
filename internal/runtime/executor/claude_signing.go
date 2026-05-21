package executor

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"regexp"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	claudeCCHPrime64_1 uint64 = 0x9E3779B185EBCA87
	claudeCCHPrime64_2 uint64 = 0xC2B2AE3D27D4EB4F
	claudeCCHPrime64_3 uint64 = 0x165667B19E3779F9
	claudeCCHPrime64_4 uint64 = 0x85EBCA77C2B2AE63
	claudeCCHPrime64_5 uint64 = 0x27D4EB2F165667C5

	claudeCCHAttestV1 uint64 = 0xAE4FBA0790EAE83E
	claudeCCHAttestV2 uint64 = 0x101840560AFF1DB7
	claudeCCHAttestV3 uint64 = 0x4D659218E32A3268
	claudeCCHAttestV4 uint64 = 0xAF2E18675D3E67E1
)

var claudeBillingHeaderCCHPattern = regexp.MustCompile(`\bcch=([0-9a-f]{5});`)

func signAnthropicMessagesBody(body []byte) []byte {
	billingHeader := gjson.GetBytes(body, "system.0.text").String()
	if !strings.HasPrefix(billingHeader, "x-anthropic-billing-header:") {
		return body
	}
	if !claudeBillingHeaderCCHPattern.MatchString(billingHeader) {
		return body
	}

	unsignedBillingHeader := claudeBillingHeaderCCHPattern.ReplaceAllString(billingHeader, "cch=00000;")
	unsignedBody, err := sjson.SetBytes(body, "system.0.text", unsignedBillingHeader)
	if err != nil {
		return body
	}

	cch := computeClaudeCCH(unsignedBody)
	signedBillingHeader := claudeBillingHeaderCCHPattern.ReplaceAllString(unsignedBillingHeader, "cch="+cch+";")
	signedBody, err := sjson.SetBytes(unsignedBody, "system.0.text", signedBillingHeader)
	if err != nil {
		return unsignedBody
	}
	return signedBody
}

func computeClaudeCCH(body []byte) string {
	h := claudeCCHKeyedXXHash64(body, claudeCCHAttestV1, claudeCCHAttestV2, claudeCCHAttestV3, claudeCCHAttestV4)
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
