package collect

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the address to attribute the visit to.
//
// Forwarding headers are only honoured when the immediate peer is a configured
// trusted proxy. Otherwise any client could self-assign an origin by sending
// CF-Connecting-IP, which would poison both the artifact and any IP-based
// filtering downstream.
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	ip := net.ParseIP(peer)
	if ip == nil {
		return peer
	}
	if !inAny(ip, trusted) {
		return ip.String()
	}

	if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
		if p := net.ParseIP(v); p != nil {
			return p.String()
		}
	}

	// X-Forwarded-For is append-only: each proxy appends the address it
	// received from. Walk right to left and take the first hop that is not a
	// trusted proxy. The leftmost entries are whatever the client chose to
	// send, so scanning from the left is spoofable by construction.
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		p := net.ParseIP(strings.TrimSpace(hops[i]))
		if p == nil || inAny(p, trusted) {
			continue
		}
		return p.String()
	}
	return ip.String()
}

func inAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRs is a convenience for turning config strings into the form
// ClientIP expects. Invalid entries are returned rather than skipped so
// misconfiguration fails at startup instead of silently widening trust.
func ParseCIDRs(values []string) ([]*net.IPNet, []error) {
	var out []*net.IPNet
	var errs []error
	for _, v := range values {
		_, n, err := net.ParseCIDR(strings.TrimSpace(v))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, n)
	}
	return out, errs
}
