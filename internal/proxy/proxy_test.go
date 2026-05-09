package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yugui923/secretproxy/internal/seal"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestParseProxySecret_blobOnly(t *testing.T) {
	blob, override, err := parseProxySecret("abc==")
	if err != nil {
		t.Fatal(err)
	}
	if blob != "abc==" {
		t.Fatalf("blob mismatch: %q", blob)
	}
	if override != nil {
		t.Fatalf("expected nil override, got %v", override)
	}
}

func TestParseProxySecret_withOverride(t *testing.T) {
	blob, override, err := parseProxySecret(`abc== ; {"format":"%s"}`)
	if err != nil {
		t.Fatal(err)
	}
	if blob != "abc==" {
		t.Fatalf("blob mismatch: %q", blob)
	}
	if v, ok := override["format"].(string); !ok || v != "%s" {
		t.Fatalf("override format wrong: %v", override)
	}
}

func TestParseProxySecret_empty(t *testing.T) {
	if _, _, err := parseProxySecret(""); err == nil {
		t.Fatal("expected error for empty header")
	}
}

func TestParseProxySecret_badJSON(t *testing.T) {
	if _, _, err := parseProxySecret("abc==;{not json}"); err == nil {
		t.Fatal("expected JSON error")
	}
}

func TestExtractBearer_bearer(t *testing.T) {
	v, ok := extractBearer("Bearer xyz")
	if !ok || v != "xyz" {
		t.Fatalf("bearer parse: %v %v", v, ok)
	}
}

// TestExtractBearer_basic verifies the §2.3 contract that the password half is
// compared (not the base64 user:pass blob).
func TestExtractBearer_basic(t *testing.T) {
	cred := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	v, ok := extractBearer("Basic " + cred)
	if !ok || v != "s3cret" {
		t.Fatalf("basic parse: %v %v", v, ok)
	}
}

func TestExtractBearer_basicMalformed(t *testing.T) {
	if _, ok := extractBearer("Basic !!!"); ok {
		t.Fatal("malformed base64 should not parse")
	}
	bad := base64.StdEncoding.EncodeToString([]byte("nopassword"))
	if _, ok := extractBearer("Basic " + bad); ok {
		t.Fatal("missing colon should not parse")
	}
}

func TestExtractBearer_unprefixed(t *testing.T) {
	if _, ok := extractBearer("xyz"); ok {
		t.Fatal("expected false for unprefixed")
	}
}

func TestResolveProcessor_acceptedFormat(t *testing.T) {
	ih := &seal.InjectHeader{Token: "tok", AllowedFormats: []string{"%s"}}
	format, hn, err := resolveProcessor(ih, map[string]any{"format": "%s"})
	if err != nil {
		t.Fatal(err)
	}
	if format != "%s" || hn != "Authorization" {
		t.Fatalf("got format=%q header=%q", format, hn)
	}
	// Ensure the seal was NOT mutated.
	if ih.Format != "" {
		t.Fatal("resolveProcessor must not mutate the seal")
	}
}

func TestResolveProcessor_rejectedFormat(t *testing.T) {
	ih := &seal.InjectHeader{Token: "tok", AllowedFormats: []string{"%s"}}
	if _, _, err := resolveProcessor(ih, map[string]any{"format": "Bearer %s"}); err == nil {
		t.Fatal("expected reject for format outside allowed_formats")
	}
}

func TestResolveProcessor_alreadySet(t *testing.T) {
	ih := &seal.InjectHeader{Token: "tok", Format: "Bearer %s", AllowedFormats: []string{"X-%s"}}
	if _, _, err := resolveProcessor(ih, map[string]any{"format": "X-%s"}); err == nil {
		t.Fatal("expected reject when seal already set format")
	}
}

func TestResolveProcessor_unknownKey(t *testing.T) {
	ih := &seal.InjectHeader{Token: "tok"}
	if _, _, err := resolveProcessor(ih, map[string]any{"token": "x"}); err == nil {
		t.Fatal("expected reject for non-overridable key")
	}
}

func TestResolveProcessor_defaults(t *testing.T) {
	ih := &seal.InjectHeader{Token: "tok"}
	format, hn, err := resolveProcessor(ih, nil)
	if err != nil {
		t.Fatal(err)
	}
	if format != "Bearer %s" || hn != "Authorization" {
		t.Fatalf("expected defaults, got %q / %q", format, hn)
	}
}

func TestValidateHost_exact(t *testing.T) {
	s := &seal.Secret{AllowedHosts: []string{"api.stripe.com"}}
	if err := validateHost("api.stripe.com", s); err != nil {
		t.Fatalf("expected match: %v", err)
	}
	if err := validateHost("evil.com", s); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestValidateHost_pattern(t *testing.T) {
	s := &seal.Secret{AllowedHostPattern: "^api\\.stripe\\.com$"}
	if err := validateHost("api.stripe.com", s); err != nil {
		t.Fatalf("expected pattern match: %v", err)
	}
	if err := validateHost("apixstripeycom", s); err == nil {
		t.Fatal("expected pattern mismatch")
	}
}

// TestRejectNonStandardPort closes the bypass where seal+request both use a
// non-443 port: validation passed but the dial silently rewrote to 443.
func TestRejectNonStandardPort(t *testing.T) {
	cases := map[string]bool{
		"api.stripe.com":      true,
		"api.stripe.com:443":  true,
		"api.stripe.com:80":   false,
		"api.stripe.com:8080": false,
		"":                    false,
	}
	for in, ok := range cases {
		err := rejectNonStandardPort(in)
		got := err == nil
		if got != ok {
			t.Errorf("rejectNonStandardPort(%q): want ok=%v, got %v (err=%v)", in, ok, got, err)
		}
	}
}

func TestValidatePath_segmentAware(t *testing.T) {
	s := &seal.Secret{AllowedPathPrefixes: []string{"/v1/charges"}}
	cases := map[string]bool{
		"/v1/charges":          true,
		"/v1/charges/abc":      true,
		"/v1/charges/abc/def":  true,
		"/v1/charges-list":     false,
		"/v1/charges-list/foo": false,
		"/v1/refunds":          false,
	}
	for path, want := range cases {
		err := validatePath(path, s)
		got := err == nil
		if got != want {
			t.Errorf("path %q: want %v, got %v (err=%v)", path, want, got, err)
		}
	}
}

func TestValidatePath_noConstraint(t *testing.T) {
	s := &seal.Secret{}
	if err := validatePath("/anything", s); err != nil {
		t.Fatal(err)
	}
}

func TestValidateMethod(t *testing.T) {
	s := &seal.Secret{AllowedMethods: []string{"POST"}}
	if err := validateMethod("POST", s); err != nil {
		t.Fatal(err)
	}
	if err := validateMethod("GET", s); err == nil {
		t.Fatal("expected reject")
	}
	if err := validateMethod("post", s); err == nil {
		t.Fatal("case-sensitive check should reject lowercase")
	}
}

func TestIsPrivateOrLocal(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1":     true,
		"172.16.0.1":   true,
		"192.168.1.1":  true,
		"127.0.0.1":    true,
		"169.254.0.1":  true,
		"::1":          true,
		"8.8.8.8":      false,
		"1.1.1.1":      false,
		"203.0.113.10": false,
		"2606:4700::1": false,
	}
	for s, want := range cases {
		got := isPrivateOrLocal(net.ParseIP(s))
		if got != want {
			t.Errorf("%s: want %v, got %v", s, want, got)
		}
	}
}

func TestGuardedDial_blocksLoopback(t *testing.T) {
	s := &Server{SelfHostnames: map[string]struct{}{}}
	s.init()
	_, err := s.guardedDial(context.Background(), "tcp", "127.0.0.1:443")
	if err == nil {
		t.Fatal("expected egress guard to block 127.0.0.1")
	}
	if !strings.Contains(err.Error(), "egress guard") {
		t.Fatalf("expected egress guard error, got %v", err)
	}
}

func TestGuardedDial_blocksSelf(t *testing.T) {
	s := &Server{SelfHostnames: map[string]struct{}{"myhost.example.com": {}}}
	s.init()
	_, err := s.guardedDial(context.Background(), "tcp", "myhost.example.com:443")
	if err == nil || !strings.Contains(err.Error(), "self-loop") {
		t.Fatalf("expected self-loop refusal, got %v", err)
	}
}

func TestStripPort(t *testing.T) {
	cases := map[string]string{
		"api.stripe.com":     "api.stripe.com",
		"api.stripe.com:80":  "api.stripe.com",
		"api.stripe.com:443": "api.stripe.com",
		"":                   "",
	}
	for in, want := range cases {
		if got := stripPort(in); got != want {
			t.Errorf("stripPort(%q): want %q, got %q", in, want, got)
		}
	}
}

func TestHandler_publicKey(t *testing.T) {
	_, priv, _ := seal.GenerateKeypair()
	s := &Server{PrivateKey: &priv, Logger: discardLogger()}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/public-key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 64 {
		t.Fatalf("public key length: %d (%q)", len(body), body)
	}
	if string(body) != priv.Public().Hex() {
		t.Fatalf("public key mismatch")
	}
}

func TestHandler_health(t *testing.T) {
	_, priv, _ := seal.GenerateKeypair()
	s := &Server{PrivateKey: &priv, Logger: discardLogger()}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
	}
}

// TestStatusWriter_capturesUpstreamStatus verifies the access-log status field
// reflects whatever ReverseProxy actually wrote, not a hard-coded 200.
func TestStatusWriter_capturesUpstreamStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := newStatusWriter(rec)
	sw.WriteHeader(503)
	if sw.status != 503 {
		t.Fatalf("expected 503, got %d", sw.status)
	}
	// Subsequent WriteHeader is ignored, like Go's stdlib behavior.
	sw.WriteHeader(200)
	if sw.status != 503 {
		t.Fatalf("status changed after first WriteHeader: %d", sw.status)
	}
}

func TestStatusWriter_defaultsTo200OnBareWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := newStatusWriter(rec)
	_, _ = sw.Write([]byte("body"))
	if sw.status != 200 {
		t.Fatalf("expected default 200, got %d", sw.status)
	}
}
