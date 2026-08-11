package resolve

import (
	"net"
	"strings"
	"time"

	"github.com/reloadlife/dnsd/pkg/api"
)

// ClientAllowed reports whether a client may be served.
//
// An empty list allows everyone — stock dnsd is a normal resolver and must not
// start refusing on upgrade. Callers that are not an IP at all ("api", the
// local /v1/resolve caller) are always allowed; the ACL guards the network,
// not the control plane.
func ClientAllowed(cidrs []string, client string) bool {
	if len(cidrs) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(client))
	if ip == nil {
		if host, _, err := net.SplitHostPort(client); err == nil {
			ip = net.ParseIP(host)
		}
	}
	if ip == nil {
		return true
	}
	return IPInAny(cidrs, ip)
}

// IPInAny reports membership in any CIDR. A bare IP is treated as a /32 (/128).
func IPInAny(cidrs []string, ip net.IP) bool {
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if one := net.ParseIP(c); one != nil && one.Equal(ip) {
				return true
			}
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// MatchRoute returns the first enabled route matching name, or nil.
func MatchRoute(routes []api.SniRoute, name string) *api.SniRoute {
	for i := range routes {
		r := routes[i]
		if !r.Enabled {
			continue
		}
		if MatchName(r.Match, r.Pattern, name) {
			return &r
		}
	}
	return nil
}

// MatchName exposes the rule matcher (exact / suffix / glob) to other packages.
func MatchName(kind api.MatchKind, pattern, name string) bool {
	return matchName(kind, pattern, name)
}

// OutboundDialer builds a dialer pinned to a source IP and/or exit interface —
// the same selector semantics upstreams use, reused by the SNI relay.
func OutboundDialer(bindIP, bindIface string, timeout time.Duration) *net.Dialer {
	return outboundDialer(api.Upstream{BindIP: bindIP, BindIface: bindIface}, timeout)
}
