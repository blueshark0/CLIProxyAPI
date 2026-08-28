package helps

import "net/http"

// proxyTraceHeaderNames lists proxy-chain trace headers that must never reach
// the upstream provider. Reverse proxies and CDNs append them on every hop, so
// forwarding them would leak the caller network topology to the provider.
var proxyTraceHeaderNames = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Real-IP",
	"Forwarded",
	"Via",
	"Cdn-Loop",
	"Eo-Connecting-Ip",
	"Eo-Log-Uuid",
	"CF-Connecting-IP",
	"CF-Ray",
	"CF-Visitor",
	"True-Client-IP",
}

// ScrubProxyTraceHeaders removes proxy-chain trace headers from the request.
func ScrubProxyTraceHeaders(r *http.Request) {
	if r == nil {
		return
	}
	for _, name := range proxyTraceHeaderNames {
		r.Header.Del(name)
	}
}
