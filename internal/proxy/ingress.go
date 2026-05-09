package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ParseAllowedClientCIDRs parses the SECRET_PROXY_ALLOWED_CLIENT_CIDRS env /
// --allowed-client-cidrs flag value. Bare IPv4 addresses become /32, bare
// IPv6 addresses become /128. Returns nil for an empty input (allowlist
// disabled).
func ParseAllowedClientCIDRs(entries []string) ([]netip.Prefix, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(entries))
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := parseCIDROrIP(raw)
		if err != nil {
			return nil, fmt.Errorf("allowed_client_cidrs: %q: %w", raw, err)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func parseCIDROrIP(raw string) (netip.Prefix, error) {
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if addr.Is6() && !addr.Is4In6() {
		bits = 128
	}
	return netip.PrefixFrom(addr.Unmap(), bits), nil
}

// clientIPFromRequest returns the IP to match against the ingress allowlist.
// When trustTerminator is true, it uses the rightmost X-Forwarded-For entry
// (the hop the trusted terminator added). Otherwise, it falls back to the
// TCP peer address. See §5.1 footgun #9.
func clientIPFromRequest(r *http.Request, trustTerminator bool) (netip.Addr, error) {
	if trustTerminator {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			candidate := strings.TrimSpace(parts[len(parts)-1])
			if candidate != "" {
				return parseIPMaybePort(candidate)
			}
		}
	}
	return parseIPMaybePort(r.RemoteAddr)
}

func parseIPMaybePort(s string) (netip.Addr, error) {
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	addr, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse client ip %q: %w", s, err)
	}
	return addr.Unmap(), nil
}

func ipInPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
