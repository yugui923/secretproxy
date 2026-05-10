package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/yugui923/secretproxy/internal/seal"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestParseSealedHeader_blobOnly(t *testing.T) {
	blob, override, err := parseSealedHeader("abc==")
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

func TestParseSealedHeader_withOverride(t *testing.T) {
	blob, override, err := parseSealedHeader(`abc== ; {"format":"%s"}`)
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

func TestParseSealedHeader_empty(t *testing.T) {
	if _, _, err := parseSealedHeader(""); err == nil {
		t.Fatal("expected error for empty header")
	}
}

func TestParseSealedHeader_badJSON(t *testing.T) {
	if _, _, err := parseSealedHeader("abc==;{not json}"); err == nil {
		t.Fatal("expected JSON error")
	}
}

func TestExtractBearer_bearer(t *testing.T) {
	v, ok := extractBearer("Bearer xyz")
	if !ok || v != "xyz" {
		t.Fatalf("bearer parse: %v %v", v, ok)
	}
}

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

// TestValidateHost_caseInsensitive locks the FIND-003 fix: DNS hostnames are
// case-insensitive, so the seal's allowlist (and pattern) must match
// regardless of the case of either side. Without this, sealing
// api.stripe.com and sending Api.Stripe.com fails closed and operators
// reach for unanchored regex (FIND-009) to "fix" the surprise. The pattern
// matcher prepends (?i) so operators can author the pattern in any case,
// including with shorthand classes (\D, \W, \S) whose meaning would
// change if the pattern itself were Lowercased.
func TestValidateHost_caseInsensitive(t *testing.T) {
	listSeal := &seal.Secret{AllowedHosts: []string{"API.Stripe.com"}}
	patSeals := []*seal.Secret{
		{AllowedHostPattern: "^api\\.stripe\\.com$"},
		{AllowedHostPattern: "^API\\.Stripe\\.com$"},
		{AllowedHostPattern: "^[a-z]+\\.stripe\\.com$"},
	}
	for _, host := range []string{"api.stripe.com", "Api.Stripe.com", "API.STRIPE.COM"} {
		if err := validateHost(host, listSeal); err != nil {
			t.Errorf("list mode: host %q should match: %v", host, err)
		}
		for i, pat := range patSeals {
			if err := validateHost(host, pat); err != nil {
				t.Errorf("pattern mode #%d (%q): host %q should match: %v", i, pat.AllowedHostPattern, host, err)
			}
		}
	}
}

func TestRejectNonStandardPort(t *testing.T) {
	cases := map[string]bool{
		"api.stripe.com":      true,
		"api.stripe.com:443":  true,
		"[::1]:443":           true, // IPv6 bracketed, valid form
		"api.stripe.com:80":   false,
		"api.stripe.com:8080": false,
		"":                    false,
		// Post-review: malformed bracketed forms used to fall through to
		// "no port = OK" and pass validation. Refuse instead.
		"[::1":           false,
		"[::1]":          false, // bracket without explicit port
		"api:stripe:com": false, // multiple colons, ambiguous
		"::1":            false, // unbracketed IPv6 — ambiguous to SplitHostPort
		"[fe80::1%eth0]": false, // zone ID without port
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

// TestValidatePath_rejectsTraversalSegments closes the hole where url.Parse
// keeps ".." literal in u.Path (and even decodes %2e%2e into "..") so a naive
// prefix/regex check would admit /v1/charges/../admin while the upstream
// resolves it to /admin. Reject unconditionally — and exercise the case
// where no path allowlist is set so the guard's defense-in-depth posture
// is locked in.
func TestValidatePath_rejectsTraversalSegments(t *testing.T) {
	cases := []struct {
		name string
		s    *seal.Secret
	}{
		{"with_prefix_allowlist", &seal.Secret{AllowedPathPrefixes: []string{"/v1/charges"}}},
		{"with_pattern_allowlist", &seal.Secret{AllowedPathPattern: ".*"}},
		{"no_path_allowlist_at_all", &seal.Secret{}},
	}
	bad := []string{
		"/v1/charges/../admin",
		"/v1/charges/../../admin",
		"/v1/charges/./list",
		"/v1/charges/..",
		"/..",
		"/./",
		"..",
	}
	for _, c := range cases {
		for _, p := range bad {
			if err := validatePath(p, c.s); err == nil {
				t.Errorf("[%s] validatePath(%q) must reject dot segment, got nil", c.name, p)
			}
		}
	}
}

// TestValidatePath_percentDecodedTraversal demonstrates that the proxy guard
// must run on url.URL.Path (post-decode), not on the raw header string.
// %2e%2e/%2E%2E should both surface as ".." after parsing and be refused.
func TestValidatePath_percentDecodedTraversal(t *testing.T) {
	for _, raw := range []string{
		"https://api.example.com/v1/charges/%2e%2e/admin",
		"https://api.example.com/v1/charges/%2E%2E/admin",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		s := &seal.Secret{AllowedPathPrefixes: []string{"/v1/charges"}}
		if err := validatePath(u.Path, s); err == nil {
			t.Errorf("percent-encoded traversal %q must be rejected (decoded path = %q)", raw, u.Path)
		}
	}
}

// TestValidatePath_doubleEncodedTraversal locks the FIND-004 fix: an
// attacker double-encodes %2F as %252F and the literal ".." as %252E%252E.
// url.Parse runs one round of decoding so upstream.Path becomes
// /v1/charges/abc%2F..%2Fadmin (or %2E%2E for the dot-segment variant) —
// which has NO ".." segment after split-on-"/". Some upstreams URL-decode
// again and resolve to /admin. refuseDotSegments must unescape until
// stable and refuse on any intermediate form that exposes the traversal.
func TestValidatePath_doubleEncodedTraversal(t *testing.T) {
	cases := []string{
		// Double-encoded slash + literal ".." — collapses on second decode.
		"/v1/charges/abc%2F..%2Fadmin",
		// Double-encoded ".." — collapses on second decode.
		"/v1/charges/%252E%252E/admin",
		// Triple-encoded — within the maxDecodes safety bound.
		"/v1/charges/%25252E%25252E/admin",
		// Mixed: encoded slash and encoded dot segments.
		"/v1/charges/%252F%252E%252E/admin",
	}
	s := &seal.Secret{AllowedPathPrefixes: []string{"/v1/charges"}}
	for _, raw := range cases {
		u, err := url.Parse("https://api.example.com" + raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if err := validatePath(u.Path, s); err == nil {
			t.Errorf("double-encoded traversal %q must be rejected (Path = %q)", raw, u.Path)
		}
	}
}

// TestRefuseDotSegments_overlongAndBackslash exercises edge cases the
// iterative-decode guard must NOT silently allow. Overlong UTF-8
// encodings (%C0%AE for ".") are not decoded by url.PathUnescape, so they
// reach the upstream as opaque bytes — the guard correctly does not
// recognize them as ".", and that's the documented contract: vendor APIs
// do not legitimately use such encodings, and Go's url.PathUnescape's
// stdlib semantics are the contract surface. Backslash variants
// (%5C..%5C) are likewise opaque to Go's "/"-only segment splitter; the
// proxy does not promise Windows-style separator collapsing because no
// real vendor URL needs it.
func TestRefuseDotSegments_overlongAndBackslash(t *testing.T) {
	for _, p := range []string{"/v1/foo/%C0%AE%C0%AE/bar", "/v1/foo/%5C..%5C/bar"} {
		// These should NOT be refused by refuseDotSegments — Go does not
		// decode them into "..". Lock in the absence-of-spurious-rejection.
		if err := refuseDotSegments(p); err != nil {
			t.Errorf("refuseDotSegments(%q) should not refuse opaque non-/ separators, got %v", p, err)
		}
	}
}

// TestRefuseDotSegments_runaway lock the safety bound. Construct a path
// that re-introduces "%" via repeated decoding and verify the guard
// errors out rather than looping. This shape doesn't appear in
// validatePath today via url.Parse output, but the helper is exported in
// scope to refuseDotSegments and a future caller could feed it directly.
func TestRefuseDotSegments_runaway(t *testing.T) {
	// "%2525252525252e%2525252525252e" decodes one "%25" per round; far
	// more than the 4-round cap.
	p := "/v1/foo/%2525252525252e%2525252525252e/bar"
	err := refuseDotSegments(p)
	if err == nil {
		t.Fatal("expected refusal: input requires more decodes than the safety bound")
	}
	if !strings.Contains(err.Error(), "did not stabilize") && !strings.Contains(err.Error(), "..") {
		t.Fatalf("expected stabilization or dot-segment error, got %v", err)
	}
}

// TestValidatePath_legitimatePercentEncoded confirms the iterative-decode
// guard does NOT regress on legitimate single-decoded percent characters
// (spaces in identifiers, UTF-8 bytes, etc.). The guard refuses dot
// segments specifically, not any "%" appearance.
func TestValidatePath_legitimatePercentEncoded(t *testing.T) {
	s := &seal.Secret{}
	cases := []struct {
		name string
		raw  string
	}{
		{"already_decoded_space", "/v1/customers/cus%20123"},
		{"encoded_utf8_checkmark", "/v1/things/%E2%9C%93/active"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse("https://api.example.com" + tc.raw)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v — test premise broken", tc.raw, err)
			}
			if err := validatePath(u.Path, s); err != nil {
				t.Errorf("legit path %q (Path=%q) wrongly refused: %v", tc.raw, u.Path, err)
			}
		})
	}
}

// TestRefuseDotSegments_invalidPercentEncoding asserts the helper refuses
// rather than silently accepts on input whose percent-encoding fails to
// decode. url.Parse rejects "%zz" at the input boundary today, so the
// proxy doesn't see it via the wire path — but the helper is exposed in
// scope and a future caller could feed it raw bytes (e.g., a
// pkg/client-side validation). Refusing closed is the documented
// contract; this test locks it in.
func TestRefuseDotSegments_invalidPercentEncoding(t *testing.T) {
	err := refuseDotSegments("/v1/items/abc%zz")
	if err == nil {
		t.Fatal("expected refusal for invalid percent-encoding")
	}
	if !strings.Contains(err.Error(), "invalid percent-encoding") {
		t.Fatalf("expected invalid-percent-encoding error, got %v", err)
	}
}

// Case-insensitivity is locked in by TestValidateHost_caseInsensitive above
// (FIND-003). Mismatches must still be rejected on different hostnames, not
// on case differences alone.
func TestValidateHost_rejectsDifferentHost(t *testing.T) {
	s := &seal.Secret{AllowedHosts: []string{"api.stripe.com"}}
	for _, mismatch := range []string{"api.evil.com", "stripe.com", "api.stripe.com.evil.com"} {
		if err := validateHost(mismatch, s); err == nil {
			t.Errorf("expected reject for %q", mismatch)
		}
	}
}

func TestResolveProcessor_acceptedHeaderName(t *testing.T) {
	ih := &seal.InjectHeader{Token: "tok", AllowedHeaderNames: []string{"X-API-Key"}}
	format, hn, err := resolveProcessor(ih, map[string]any{"header_name": "X-API-Key"})
	if err != nil {
		t.Fatal(err)
	}
	if hn != "X-API-Key" || format != "Bearer %s" {
		t.Fatalf("got header=%q format=%q", hn, format)
	}
}

func TestResolveProcessor_rejectedHeaderName(t *testing.T) {
	ih := &seal.InjectHeader{Token: "tok", AllowedHeaderNames: []string{"X-API-Key"}}
	if _, _, err := resolveProcessor(ih, map[string]any{"header_name": "Authorization"}); err == nil {
		t.Fatal("expected reject for header_name outside allowed_header_names")
	}
}

func TestResolveProcessor_headerNameAlreadySet(t *testing.T) {
	ih := &seal.InjectHeader{Token: "tok", HeaderName: "Authorization", AllowedHeaderNames: []string{"X-Custom"}}
	if _, _, err := resolveProcessor(ih, map[string]any{"header_name": "X-Custom"}); err == nil {
		t.Fatal("expected reject when seal already pinned header_name")
	}
}

func TestResolveProcessor_overrideValueTypeRejected(t *testing.T) {
	ih := &seal.InjectHeader{Token: "tok", AllowedFormats: []string{"%s"}}
	if _, _, err := resolveProcessor(ih, map[string]any{"format": 42}); err == nil {
		t.Fatal("non-string override value must be rejected")
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
		"10.0.0.1":    true,
		"172.16.0.1":  true,
		"192.168.1.1": true,
		"127.0.0.1":   true,
		"169.254.0.1": true,
		"::1":         true,
		// FIND-006: RFC 6598 CGNAT (used by Calico, EKS Fargate pods).
		// Range is 100.64.0.0/10 (100.64.0.0 – 100.127.255.255).
		"100.64.0.1":    true,
		"100.127.255.1": true,
		"100.63.255.1":  false, // just outside the bottom of the range
		"100.128.0.1":   false, // just outside the top of the range
		// Post-review: 0.0.0.0/8 and 240.0.0.0/4 close two more SSRF
		// vectors. 0.0.0.1 routes to loopback on Linux in many configs.
		"0.0.0.1":         true,
		"0.255.255.255":   true,
		"240.0.0.1":       true,
		"255.255.255.255": true,
		"239.255.255.255": false, // just outside 240/4
		"8.8.8.8":         false,
		"1.1.1.1":         false,
		"203.0.113.10":    false,
		"2606:4700::1":    false,
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
	if !errors.Is(err, ErrEgressRefused) {
		t.Fatalf("loopback error must wrap ErrEgressRefused so the ErrorHandler can return 403, got %v", err)
	}
}

func TestGuardedDial_blocksSelf(t *testing.T) {
	s := &Server{SelfHostnames: map[string]struct{}{"my.host.example.com": {}}}
	s.init()
	_, err := s.guardedDial(context.Background(), "tcp", "my.host.example.com:443")
	if err == nil {
		t.Fatal("expected self-loop refusal")
	}
	if !errors.Is(err, ErrEgressRefused) {
		t.Fatalf("self-loop error must wrap ErrEgressRefused, got %v", err)
	}
	if !strings.Contains(err.Error(), "self-loop") {
		t.Fatalf("self-loop error message should name the reason, got %v", err)
	}
}

// TestGuardedDial_blocksSelfCaseInsensitive locks the FIND-002 fix: an
// uppercase variant of the proxy's own hostname must still trigger the
// self-loop refusal. Without case folding, the map lookup misses, the
// IP-based check resolves a public IP, and the dial proceeds.
func TestGuardedDial_blocksSelfCaseInsensitive(t *testing.T) {
	cases := []string{
		"MY.HOST.EXAMPLE.COM",
		"My.Host.Example.Com",
		"my.HOST.example.com",
	}
	for _, host := range cases {
		t.Run(host, func(t *testing.T) {
			s := &Server{SelfHostnames: AutoSelfHostnames([]string{"my.host.example.com"})}
			s.init()
			_, err := s.guardedDial(context.Background(), "tcp", host+":443")
			if err == nil {
				t.Fatalf("expected self-loop refusal for %q", host)
			}
			if !errors.Is(err, ErrEgressRefused) {
				t.Fatalf("self-loop error must wrap ErrEgressRefused, got %v", err)
			}
			if !strings.Contains(err.Error(), "self-loop") {
				t.Fatalf("self-loop error message should name the reason, got %v", err)
			}
		})
	}
}

// TestAutoSelfHostnames_lowercases asserts the operator-supplied entries
// (and os.Hostname) are normalized to lowercase before being stored. The
// guardedDial lookup also lowercases — both sides must agree.
func TestAutoSelfHostnames_lowercases(t *testing.T) {
	got := AutoSelfHostnames([]string{"PROXY.Example.COM", "Other.Host"})
	for _, want := range []string{"proxy.example.com", "other.host", "localhost", "127.0.0.1", "::1"} {
		if _, ok := got[want]; !ok {
			t.Errorf("AutoSelfHostnames missing key %q; got %v", want, got)
		}
	}
	for k := range got {
		if k != strings.ToLower(k) {
			t.Errorf("AutoSelfHostnames key %q is not lowercase", k)
		}
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

// TestHandler_panicsWithoutPrivateKey locks in fail-fast behavior: a Server
// constructed without PrivateKey must panic at the first Handler() call so the
// misconfiguration surfaces at startup rather than as a runtime nil-deref on
// the first request to /public-key (while /healthz keeps replying OK and
// observers think the box is fine).
func TestHandler_panicsWithoutPrivateKey(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when PrivateKey is nil")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "PrivateKey is nil") {
			t.Fatalf("panic message should mention nil PrivateKey, got %v", r)
		}
	}()
	s := &Server{Logger: discardLogger()}
	_ = s.Handler()
}

func TestHandler_unknownPath404(t *testing.T) {
	_, priv, _ := seal.GenerateKeypair()
	s := &Server{PrivateKey: &priv, Logger: discardLogger()}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/no/such/path")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestStatusWriter_capturesUpstreamStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := newStatusWriter(rec)
	sw.WriteHeader(503)
	if sw.status != 503 {
		t.Fatalf("expected 503, got %d", sw.status)
	}
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
