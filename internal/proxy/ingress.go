package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// CFConnectingIPHeader is the Cloudflare-set header carrying the real client
// IP. Cloudflare's edge unconditionally strips any client-supplied value and
// rewrites it with the IP it observed at TCP, so the header is trustworthy
// only when the proxy is unreachable except via Cloudflare. See §5.1 footgun #9.
const CFConnectingIPHeader = "CF-Connecting-IP"

// CloudflareTrustHeaders is the set of CF-* / True-Client-IP headers that the
// proxy strips from upstream requests when SECRET_PROXY_TRUST_CLOUDFLARE_HEADERS
// is set. Without stripping, these would leak to the vendor API and disclose
// the proxy's edge topology.
var CloudflareTrustHeaders = []string{
	CFConnectingIPHeader,
	"CF-Ray",
	"CF-IPCountry",
	"CF-Visitor",
	"True-Client-IP",
}

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
// Resolution order:
//  1. trustCloudflare=true → CF-Connecting-IP. The flag is a declaration that
//     the proxy is unreachable except via Cloudflare; the header is not
//     validated against Cloudflare's IP list. Missing or unparseable values
//     fail closed.
//  2. trustTerminator=true → rightmost X-Forwarded-For entry (the hop the
//     trusted terminator added).
//  3. Otherwise → the TCP peer address.
//
// See §5.1 footgun #9.
func clientIPFromRequest(r *http.Request, trustTerminator, trustCloudflare bool) (netip.Addr, error) {
	if trustCloudflare {
		cfIP := strings.TrimSpace(r.Header.Get(CFConnectingIPHeader))
		if cfIP == "" {
			return netip.Addr{}, errors.New("cf-connecting-ip absent (trust_cloudflare_headers is set)")
		}
		return parseIPMaybePort(cfIP)
	}
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
