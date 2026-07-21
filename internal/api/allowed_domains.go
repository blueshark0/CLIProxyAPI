package api

import (
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

type allowedDomainFilter struct {
	domains atomic.Value
}

type allowedDomainSet struct {
	enabled bool
	values  map[string]struct{}
}

func newAllowedDomainFilter(domains []string) *allowedDomainFilter {
	filter := &allowedDomainFilter{}
	filter.Set(domains)
	return filter
}

func (f *allowedDomainFilter) Set(domains []string) {
	allowed := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		if normalized := normalizeHost(domain); normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}
	f.domains.Store(allowedDomainSet{enabled: len(domains) > 0, values: allowed})
}

func (f *allowedDomainFilter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		allowed, _ := f.domains.Load().(allowedDomainSet)
		if !allowed.enabled {
			c.Next()
			return
		}

		if _, ok := allowed.values[normalizeHost(c.Request.Host)]; !ok {
			c.String(http.StatusNotFound, "404 page not found\n")
			c.Abort()
			return
		}

		c.Next()
	}
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
