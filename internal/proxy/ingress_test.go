package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/yugui923/secretproxy/internal/seal"
)

func TestParseAllowedClientCIDRs_empty(t *testing.T) {
	for _, in := range [][]string{nil, {}, {""}, {"  ", ""}} {
		got, err := ParseAllowedClientCIDRs(in)
		if err != nil {
			t.Fatalf("expected no error for %v, got %v", in, err)
		}
		if got != nil {
			t.Fatalf("expected nil for %v, got %v", in, got)
		}
	}
}

func TestParseAllowedClientCIDRs_mixed(t *testing.T) {
	got, err := ParseAllowedClientCIDRs([]string{"10.0.0.0/8", "203.0.113.7", "2001:db8::/32", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 prefixes, got %d", len(got))
	}
	if b := got[1].Bits(); b != 32 {
		t.Errorf("bare IPv4 should become /32, got /%d", b)
	}
	if b := got[3].Bits(); b != 128 {
		t.Errorf("bare IPv6 should become /128, got /%d", b)
	}
}

func TestParseAllowedClientCIDRs_bad(t *testing.T) {
	if _, err := ParseAllowedClientCIDRs([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error on bad input")
	}
	if _, err := ParseAllowedClientCIDRs([]string{"10.0.0.0/64"}); err == nil {
		t.Fatal("expected error on out-of-range mask")
	}
}

func TestClientIPFromRequest_remoteAddrOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.RemoteAddr = "203.0.113.7:51000"
	addr, err := clientIPFromRequest(req, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "203.0.113.7" {
		t.Fatalf("want 203.0.113.7, got %s", addr)
	}
}

func TestClientIPFromRequest_xffRightmostWhenTrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.RemoteAddr = "10.0.0.1:443" // edge LB, should be ignored
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.9, 203.0.113.7")
	addr, err := clientIPFromRequest(req, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "203.0.113.7" {
		t.Fatalf("want rightmost XFF 203.0.113.7, got %s", addr)
	}
}

func TestClientIPFromRequest_xffIgnoredWhenUntrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	addr, err := clientIPFromRequest(req, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "10.0.0.1" {
		t.Fatalf("untrusted terminator must use RemoteAddr, got %s", addr)
	}
}

// TestClientIPFromRequest_xffMultipleHeaderLines locks down the rule that the
// rightmost-of-rightmost rule walks ALL X-Forwarded-For header lines, not just
// the first. HTTP/1.1 allows multiple X-Forwarded-For lines and Go's net/http
// preserves them as separate Header values. An attacker who can inject a
// header line into the request would otherwise send their forged XFF first
// and have the terminator append the real IP as a new line; Header.Get only
// returned the first (attacker-controlled) line.
func TestClientIPFromRequest_xffMultipleHeaderLines(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.RemoteAddr = "10.0.0.1:443"                  // edge LB
	req.Header.Add("X-Forwarded-For", "1.2.3.4")     // attacker-supplied first line
	req.Header.Add("X-Forwarded-For", "203.0.113.7") // terminator-appended second line
	addr, err := clientIPFromRequest(req, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "203.0.113.7" {
		t.Fatalf("want rightmost-of-rightmost 203.0.113.7 (terminator-set), got %s — attacker's first XFF won", addr)
	}
}

// TestClientIPFromRequest_xffMultipleHeaderLinesWithChain combines the multi-
// line case with a chained value in the last line (e.g. terminator appended
// "client, intermediate" rather than just one IP). Rightmost-of-rightmost
// still picks the trustworthy hop.
func TestClientIPFromRequest_xffMultipleHeaderLinesWithChain(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Add("X-Forwarded-For", "spoofed.first.line.bytes")
	req.Header.Add("X-Forwarded-For", "1.2.3.4, 198.51.100.9, 203.0.113.7")
	addr, err := clientIPFromRequest(req, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "203.0.113.7" {
		t.Fatalf("want rightmost-of-rightmost 203.0.113.7, got %s", addr)
	}
}

// TestClientIPFromRequest_xffTrailingCommaFailsClosed prevents a regression
// where "1.2.3.4, " (trailing comma — common from misconfigured terminators)
// used to fall through to RemoteAddr. Behind a terminator RemoteAddr is the
// terminator itself, almost always inside the operator's allowlist — net
// effect was silent allow of an unknown source.
func TestClientIPFromRequest_xffTrailingCommaFailsClosed(t *testing.T) {
	for _, xff := range []string{"1.2.3.4, ", "1.2.3.4,", "1.2.3.4,   ", " "} {
		req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
		req.RemoteAddr = "10.0.0.1:443" // terminator addr — would sit inside the allowlist
		req.Header.Set("X-Forwarded-For", xff)
		_, err := clientIPFromRequest(req, true, false)
		if err == nil {
			t.Errorf("xff %q: expected error (must fail closed), got nil", xff)
		}
	}
}

func TestClientIPFromRequest_ipv4MappedNormalized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.RemoteAddr = "[::ffff:203.0.113.7]:51000"
	addr, err := clientIPFromRequest(req, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "203.0.113.7" {
		t.Fatalf("want unmapped 203.0.113.7, got %s", addr)
	}
}

func TestClientIPFromRequest_cloudflareConnectingIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.RemoteAddr = "10.0.0.1:443"
	// XFF rightmost is a CF egress IP; the spoofed values must all be ignored.
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 173.245.48.1")
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	addr, err := clientIPFromRequest(req, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "203.0.113.7" {
		t.Fatalf("want CF-Connecting-IP 203.0.113.7, got %s", addr)
	}
}

func TestClientIPFromRequest_cloudflareMissingHeaderFailsClosed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 173.245.48.1")
	// CF-Connecting-IP intentionally absent.
	if _, err := clientIPFromRequest(req, true, true); err == nil {
		t.Fatal("expected error when CF-Connecting-IP is missing")
	}
}

func TestClientIPFromRequest_cloudflareMalformedHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.Header.Set("CF-Connecting-IP", "not-an-ip")
	if _, err := clientIPFromRequest(req, true, true); err == nil {
		t.Fatal("expected parse error on malformed CF-Connecting-IP")
	}
}

func TestClientIPFromRequest_cloudflareDisabledIgnoresHeader(t *testing.T) {
	// With trust_cloudflare=false, a spoofed CF-Connecting-IP must be ignored
	// even if the attacker also crafted XFF — rightmost XFF wins.
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.9")
	req.Header.Set("CF-Connecting-IP", "127.0.0.1")
	addr, err := clientIPFromRequest(req, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "198.51.100.9" {
		t.Fatalf("CF header must be ignored when trust_cloudflare=false; got %s", addr)
	}
}

func TestIPInPrefixes(t *testing.T) {
	prefixes, err := ParseAllowedClientCIDRs([]string{"10.0.0.0/8", "203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"10.1.2.3":        true,
		"203.0.113.7":     true,
		"203.0.113.8":     false,
		"8.8.8.8":         false,
		"::ffff:10.0.0.1": true, // v4-mapped should match the v4 prefix after Unmap
	}
	for in, want := range cases {
		addr, err := netip.ParseAddr(in)
		if err != nil {
			t.Fatalf("bad test input %q: %v", in, err)
		}
		if got := ipInPrefixes(addr, prefixes); got != want {
			t.Errorf("%s: want %v, got %v", in, want, got)
		}
	}
}

func TestHandler_ingressAllowlist_rejects(t *testing.T) {
	_, priv, _ := seal.GenerateKeypair()
	prefixes, err := ParseAllowedClientCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		PrivateKey:         &priv,
		AllowedClientCIDRs: prefixes,
		Logger:             discardLogger(),
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Forward request from outside the allowlist: 403, no header inspection.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/forward", strings.NewReader(""))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forward without allowed IP: want 403, got %d", resp.StatusCode)
	}

	// /healthz and /public-key must remain reachable regardless of allowlist.
	for _, path := range []string{"/healthz", "/readyz", "/public-key"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: want 200, got %d", path, resp.StatusCode)
		}
	}
}

func TestHandler_ingressAllowlist_xffMatch(t *testing.T) {
	_, priv, _ := seal.GenerateKeypair()
	prefixes, err := ParseAllowedClientCIDRs([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		PrivateKey:         &priv,
		AllowedClientCIDRs: prefixes,
		TrustTLSTerminator: true,
		Logger:             discardLogger(),
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// XFF rightmost is 203.0.113.42 (in allowlist). The request will get
	// past the ingress check, then fail with 400 because it has no
	// X-Upstream-URL — which proves the ingress check passed.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/forward", strings.NewReader(""))
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.42")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("xff-allowed request should reach the forward handler (400 missing X-Upstream-URL), got %d", resp.StatusCode)
	}
}

func TestHandler_ingressAllowlist_cloudflareConnectingIPMatch(t *testing.T) {
	_, priv, _ := seal.GenerateKeypair()
	prefixes, err := ParseAllowedClientCIDRs([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		PrivateKey:             &priv,
		AllowedClientCIDRs:     prefixes,
		TrustTLSTerminator:     true,
		TrustCloudflareHeaders: true,
		Logger:                 discardLogger(),
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// CF-Connecting-IP is in the allowlist; XFF rightmost is a Cloudflare
	// egress that would NOT match. Reaching 400 (missing X-Upstream-URL)
	// proves the gate was opened by CF-Connecting-IP, not by XFF.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/forward", strings.NewReader(""))
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 173.245.48.1")
	req.Header.Set("CF-Connecting-IP", "203.0.113.42")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cf-connecting-ip-allowed request should reach the forward handler (400 missing X-Upstream-URL), got %d", resp.StatusCode)
	}
}

func TestHandler_ingressAllowlist_cloudflareMissingHeaderRejected(t *testing.T) {
	_, priv, _ := seal.GenerateKeypair()
	prefixes, err := ParseAllowedClientCIDRs([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		PrivateKey:             &priv,
		AllowedClientCIDRs:     prefixes,
		TrustTLSTerminator:     true,
		TrustCloudflareHeaders: true,
		Logger:                 discardLogger(),
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Even with XFF rightmost in the allowlist, a missing CF-Connecting-IP
	// must fail closed — the operator declared CF-fronting, so a request
	// without the CF header is anomalous.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/forward", strings.NewReader(""))
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.42")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CF-Connecting-IP should 403, got %d", resp.StatusCode)
	}
}
