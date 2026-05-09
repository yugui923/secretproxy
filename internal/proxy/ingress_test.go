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
	addr, err := clientIPFromRequest(req, false)
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
	addr, err := clientIPFromRequest(req, true)
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
	addr, err := clientIPFromRequest(req, false)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "10.0.0.1" {
		t.Fatalf("untrusted terminator must use RemoteAddr, got %s", addr)
	}
}

func TestClientIPFromRequest_ipv4MappedNormalized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", nil)
	req.RemoteAddr = "[::ffff:203.0.113.7]:51000"
	addr, err := clientIPFromRequest(req, false)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "203.0.113.7" {
		t.Fatalf("want unmapped 203.0.113.7, got %s", addr)
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
