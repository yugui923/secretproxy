// Package proxy implements the relative-endpoint forward handler from §3.1
// of the design spec.
//
// Wire protocol (v1):
//
//	<METHOD> /v1/forward HTTP/1.1
//	Host: <proxy-host>
//	X-Upstream-URL: https://<vendor>/<path>?<query>
//	X-Sealed-Secret: <base64> [; <json-override>]
//	X-Auth-Bearer: Bearer <token>      (or Basic <b64(user:pass)>)
//	<original body>
//
// The method on the proxy mirrors the upstream method. Body streams 1:1.
// The proxy unseals, validates host/path/method against the seal, runs the
// processor (typically inject_header for an upstream Authorization), and
// forwards over TLS to the upstream. The relative-URL form was chosen so
// the proxy traverses reverse-proxy CDNs (Render, Cloud Run, Heroku, etc.)
// — those reject absolute-form HTTP_PROXY-style requests.
package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/yugui923/secretproxy/internal/seal"
)

const (
	HeaderUpstreamURL  = "X-Upstream-URL"
	HeaderSealedSecret = "X-Sealed-Secret"
	HeaderAuthBearer   = "X-Auth-Bearer"

	PublicKeyPath = "/public-key"
	HealthPath    = "/healthz"
	ReadyPath     = "/readyz"
	ForwardPath   = "/v1/forward"

	UpstreamPort = "443"
)

// hopByHopHeaders lists every header the proxy strips before forwarding to
// upstream. RFC 7230 §6.1 hop-by-hop set, plus our control headers.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	HeaderUpstreamURL,
	HeaderSealedSecret,
	HeaderAuthBearer,
}

var errMissingSecret = errors.New("missing X-Sealed-Secret header")

// ErrEgressRefused is returned by guardedDial when the proxy refuses to dial a
// host as a matter of policy (self-loop guard or private/loopback/link-local
// IP). The forwardTo ErrorHandler distinguishes this from genuine upstream
// failures so SSRF rejects return 403 (and aggregate as a separate signal in
// dashboards) instead of being bucketed with vendor TLS handshake errors as
// 502s.
var ErrEgressRefused = errors.New("egress refused")

type Server struct {
	PrivateKey         *seal.PrivateKey
	PreviousPrivateKey *seal.PrivateKey
	AllowNoAuth        bool
	AllowPassthrough   bool
	FilteredHeaders    []string
	SelfHostnames      map[string]struct{}
	Logger             *slog.Logger

	// AllowedClientCIDRs gates ingress to /v1/forward. Empty = off.
	AllowedClientCIDRs []netip.Prefix
	// TrustTLSTerminator mirrors --trust-tls-terminator and tells the
	// ingress check to read the rightmost X-Forwarded-For entry.
	TrustTLSTerminator bool
	// TrustCloudflareHeaders mirrors --trust-cloudflare-headers. When set,
	// the ingress allowlist matches CF-Connecting-IP instead of rightmost
	// X-Forwarded-For, and the CF-* / True-Client-IP headers are stripped
	// from upstream requests. The flag is a declaration that the proxy is
	// unreachable except via Cloudflare — see §5.1 footgun #9.
	TrustCloudflareHeaders bool

	// MaxRequestBytes caps the per-request body size. Zero disables the cap.
	// Requests with a known Content-Length above the cap are refused with
	// 413 before any forwarding work; chunked bodies are bounded mid-stream
	// via http.MaxBytesReader, which closes the upstream connection on
	// overflow.
	MaxRequestBytes int64

	Transport http.RoundTripper

	DisableEgressGuard bool

	once sync.Once
}

func (s *Server) init() {
	s.once.Do(func() {
		if s.Transport == nil {
			t := http.DefaultTransport.(*http.Transport).Clone()
			t.DialContext = s.guardedDial
			s.Transport = t
		}
		if s.Logger == nil {
			s.Logger = slog.Default()
		}
	})
}

func (s *Server) Handler() http.Handler {
	// Fail fast on misconfiguration at the real entry point. Without this,
	// /healthz keeps replying OK while /public-key panics on first request,
	// so an observer wiring readiness off /healthz never learns the box is
	// broken. handleForward's seal.Open call also nil-derefs s.PrivateKey.
	if s.PrivateKey == nil {
		panic("proxy: Server.PrivateKey is nil; cannot serve")
	}
	s.init()
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case PublicKeyPath:
		s.handlePublicKey(w, r)
	case HealthPath, ReadyPath:
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	case ForwardPath:
		s.handleForward(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handlePublicKey(w http.ResponseWriter, _ *http.Request) {
	pub := s.PrivateKey.Public()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, pub.Hex())
}

func (s *Server) handleForward(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if s.MaxRequestBytes > 0 {
		if r.ContentLength > s.MaxRequestBytes {
			s.respondError(w, r, http.StatusRequestEntityTooLarge, "request body too large", fmt.Errorf("content-length %d exceeds %d", r.ContentLength, s.MaxRequestBytes), start, nil)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.MaxRequestBytes)
	}

	if len(s.AllowedClientCIDRs) > 0 {
		ip, err := clientIPFromRequest(r, s.TrustTLSTerminator, s.TrustCloudflareHeaders)
		if err != nil {
			s.respondError(w, r, http.StatusForbidden, "client ip not allowed", err, start, nil)
			return
		}
		if !ipInPrefixes(ip, s.AllowedClientCIDRs) {
			s.respondError(w, r, http.StatusForbidden, "client ip not allowed", fmt.Errorf("ip %s not in allowlist", ip), start, []any{"client_ip", ip.String()})
			return
		}
	}

	upstreamRaw := r.Header.Get(HeaderUpstreamURL)
	if upstreamRaw == "" {
		s.respondError(w, r, http.StatusBadRequest, "missing X-Upstream-URL", nil, start, nil)
		return
	}
	upstream, err := url.Parse(upstreamRaw)
	if err != nil || upstream.Host == "" {
		s.respondError(w, r, http.StatusBadRequest, "bad X-Upstream-URL", err, start, nil)
		return
	}

	logFields := []any{
		"method", r.Method,
		"host", upstream.Host,
		"path", upstream.Path,
		"query_keys", queryKeys(upstream),
	}

	if vals := r.Header.Values(HeaderSealedSecret); len(vals) > 1 {
		s.respondError(w, r, http.StatusBadRequest, "multiple X-Sealed-Secret headers (chaining deferred)", nil, start, logFields)
		return
	}

	blob, override, err := parseSealedHeader(r.Header.Get(HeaderSealedSecret))
	if err != nil {
		if errors.Is(err, errMissingSecret) && s.AllowPassthrough {
			s.passthrough(w, r, upstream, start, logFields)
			return
		}
		s.respondError(w, r, http.StatusBadRequest, "invalid X-Sealed-Secret", err, start, logFields)
		return
	}

	var fallback []seal.PrivateKey
	if s.PreviousPrivateKey != nil {
		fallback = []seal.PrivateKey{*s.PreviousPrivateKey}
	}
	secret, usedFallback, err := seal.Open(blob, *s.PrivateKey, fallback...)
	if err != nil {
		s.respondError(w, r, http.StatusUnauthorized, "seal open failed", err, start, logFields)
		return
	}
	logFields = append(logFields,
		"auth", secret.AuthKind(),
		"processor", secret.ProcessorKind(),
		"seal_euid", secret.EUID,
		"seal_name", secret.Name,
	)
	if usedFallback {
		s.Logger.Warn("seal_opened_via_previous_key", logFields...)
	}

	switch {
	case secret.BearerAuth != nil:
		bearer, ok := extractBearer(r.Header.Get(HeaderAuthBearer))
		if !ok || !secret.BearerAuth.VerifyBearer(bearer) {
			s.respondError(w, r, http.StatusUnauthorized, "bearer mismatch", nil, start, logFields)
			return
		}
	case secret.NoAuth != nil:
		if !s.AllowNoAuth {
			s.respondError(w, r, http.StatusUnauthorized, "no_auth refused (server lacks --allow-no-auth)", nil, start, logFields)
			return
		}
	}

	format, headerName, err := resolveProcessor(secret.InjectHeader, override)
	if err != nil {
		s.respondError(w, r, http.StatusBadRequest, "override rejected", err, start, logFields)
		return
	}

	if err := rejectNonStandardPort(upstream.Host); err != nil {
		s.respondError(w, r, http.StatusForbidden, "request not permitted", err, start, logFields)
		return
	}
	if err := validateHost(upstream.Host, secret); err != nil {
		s.respondError(w, r, http.StatusForbidden, "request not permitted", err, start, logFields)
		return
	}
	if err := validatePath(upstream.Path, secret); err != nil {
		s.respondError(w, r, http.StatusForbidden, "request not permitted", err, start, logFields)
		return
	}
	if err := validateMethod(r.Method, secret); err != nil {
		s.respondError(w, r, http.StatusForbidden, "request not permitted", err, start, logFields)
		return
	}

	sw := newStatusWriter(w)
	copyErr := s.forwardTo(sw, r, upstream, secret.InjectHeader, format, headerName)
	s.logForwardOutcome("proxied", copyErr, sw.status, start, logFields)
}

func (s *Server) passthrough(w http.ResponseWriter, r *http.Request, upstream *url.URL, start time.Time, logFields []any) {
	if err := rejectNonStandardPort(upstream.Host); err != nil {
		s.respondError(w, r, http.StatusForbidden, "request not permitted", err, start, logFields)
		return
	}
	sw := newStatusWriter(w)
	copyErr := s.forwardTo(sw, r, upstream, nil, "", "")
	s.logForwardOutcome("passthrough", copyErr, sw.status, start, logFields)
}

// logForwardOutcome emits the per-request log line. If the body copy errored
// after headers were already flushed (sw.status != 0 and copyErr != nil), log
// "proxied_truncated" / "passthrough_truncated" at WARN — the operator-facing
// signal that the response the client received was incomplete. Otherwise log
// the normal success line at INFO.
func (s *Server) logForwardOutcome(event string, copyErr error, status int, start time.Time, fields []any) {
	tail := append(fields, "status", status, "dur_ms", time.Since(start).Milliseconds())
	if copyErr != nil {
		s.Logger.Warn(event+"_truncated", append(tail, "error", copyErr.Error())...)
		return
	}
	s.Logger.Info(event, tail...)
}

func (s *Server) forwardTo(w http.ResponseWriter, r *http.Request, upstream *url.URL, ih *seal.InjectHeader, format, headerName string) (copyErr error) {
	target := *upstream
	target.Scheme = "https"
	target.Host = stripPort(upstream.Host)
	if target.Host == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return nil
	}

	director := func(req *http.Request) {
		req.URL = &target
		req.Host = target.Host
		req.RequestURI = ""
		for _, h := range hopByHopHeaders {
			req.Header.Del(h)
		}
		if s.TrustCloudflareHeaders {
			for _, h := range CloudflareTrustHeaders {
				req.Header.Del(h)
			}
		}
		for _, h := range s.FilteredHeaders {
			req.Header.Del(h)
		}
		if ih != nil {
			req.Header.Set(headerName, fmt.Sprintf(format, ih.Token))
		}
	}

	// Wrap the upstream response body in ModifyResponse so a read error
	// during the body-copy phase (upstream connection drops mid-stream after
	// the proxy already flushed headers to the client) is captured here
	// rather than disappearing into httputil's recovered-panic path. Without
	// this, a truncated response logs as success because the status code
	// statusWriter recorded was already written. ErrorHandler still owns
	// the dial-time / pre-body failures.
	bodyTrack := &bodyReadTracker{}
	rp := &httputil.ReverseProxy{
		Director:  director,
		Transport: s.Transport,
		ModifyResponse: func(resp *http.Response) error {
			bodyTrack.wrap(resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			if errors.Is(err, ErrEgressRefused) {
				// Policy refusal — separate signal from upstream availability
				// problems so an SSRF attempt cannot hide in the same log /
				// metric bucket as a vendor outage.
				s.Logger.Warn("egress_refused_at_dial", "error", err.Error())
				http.Error(w, "egress refused", http.StatusForbidden)
				return
			}
			// MaxBytesReader trips here when a chunked body overflows mid-
			// stream (the Content-Length path is rejected earlier in
			// handleForward). Without the explicit detect, a client-driven
			// overflow lands in the upstream_error / 502 bucket alongside
			// real vendor outages — same observability problem the egress-
			// refused split solves.
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				s.Logger.Warn("request_too_large_streamed", "limit", mbe.Limit, "error", err.Error())
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			s.Logger.Warn("upstream_error", "error", err.Error())
			http.Error(w, "upstream error", http.StatusBadGateway)
		},
	}
	// httputil.ReverseProxy panics with http.ErrAbortHandler when the body
	// copy fails after the response status has been written (net/http's
	// server.go recovers ErrAbortHandler silently). Without recovering it
	// here, the panic propagates past handleForward's logForwardOutcome
	// call, so the truncation never makes it into the per-request log line.
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if r != http.ErrAbortHandler {
			panic(r)
		}
		if e := bodyTrack.err(); e != nil {
			copyErr = e
			return
		}
		copyErr = errors.New("response body copy aborted (httputil ErrAbortHandler)")
	}()
	rp.ServeHTTP(w, r)
	return bodyTrack.err()
}

// bodyReadTracker wraps an upstream response body so a non-EOF read error
// during the body-copy phase is captured for the per-request log line. The
// wrapper is single-goroutine — httputil.ReverseProxy's copyBuffer reads
// sequentially within ServeHTTP — so no synchronization is needed.
type bodyReadTracker struct {
	body    io.ReadCloser
	readErr error
}

func (b *bodyReadTracker) wrap(resp *http.Response) {
	b.body = resp.Body
	resp.Body = b
}

func (b *bodyReadTracker) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		b.readErr = err
	}
	return n, err
}

func (b *bodyReadTracker) Close() error { return b.body.Close() }

func (b *bodyReadTracker) err() error { return b.readErr }

func (s *Server) respondError(w http.ResponseWriter, r *http.Request, code int, msg string, cause error, start time.Time, fields []any) {
	if cause != nil {
		fields = append(fields, "error", cause.Error())
	}
	fields = append(fields, "status", code, "dur_ms", time.Since(start).Milliseconds(), "reason", msg)
	s.Logger.Warn("proxy_reject", fields...)
	http.Error(w, msg, code)
}

type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func newStatusWriter(w http.ResponseWriter) *statusWriter {
	return &statusWriter{ResponseWriter: w, status: http.StatusOK}
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.written {
		s.status = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.written {
		s.status = http.StatusOK
		s.written = true
	}
	return s.ResponseWriter.Write(b)
}

// parseSealedHeader splits an X-Sealed-Secret value of "<blob> ; <json>" into
// the base64 blob and the optional JSON override map (§2.5).
func parseSealedHeader(raw string) (blob string, override map[string]any, err error) {
	if raw == "" {
		return "", nil, errMissingSecret
	}
	parts := strings.SplitN(raw, ";", 2)
	blob = strings.TrimSpace(parts[0])
	if blob == "" {
		return "", nil, errMissingSecret
	}
	if len(parts) == 2 {
		override = map[string]any{}
		dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(parts[1])))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&override); err != nil {
			return "", nil, fmt.Errorf("override JSON: %w", err)
		}
	}
	return blob, override, nil
}

// extractBearer accepts "Bearer <token>" or "Basic <base64(user:pass)>". For
// Basic, the password half is returned (matches §2.3).
func extractBearer(h string) (string, bool) {
	const bearerPrefix = "Bearer "
	if strings.HasPrefix(h, bearerPrefix) {
		return strings.TrimSpace(h[len(bearerPrefix):]), true
	}
	const basicPrefix = "Basic "
	if strings.HasPrefix(h, basicPrefix) {
		raw := strings.TrimSpace(h[len(basicPrefix):])
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", false
		}
		_, pass, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return "", false
		}
		return pass, true
	}
	return "", false
}

func resolveProcessor(ih *seal.InjectHeader, override map[string]any) (format, headerName string, err error) {
	if ih == nil {
		return "", "", errors.New("no processor in seal")
	}
	format = ih.Format
	if format == "" {
		format = "Bearer %s"
	}
	headerName = ih.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}
	for k, v := range override {
		s, ok := v.(string)
		if !ok {
			return "", "", fmt.Errorf("override %q: must be string", k)
		}
		switch k {
		case "format":
			if ih.Format != "" {
				return "", "", errors.New("override forbidden: format already set in seal")
			}
			if !contains(ih.AllowedFormats, s) {
				return "", "", fmt.Errorf("override format %q not in allowed_formats", s)
			}
			format = s
		case "header_name":
			if ih.HeaderName != "" {
				return "", "", errors.New("override forbidden: header_name already set in seal")
			}
			if !contains(ih.AllowedHeaderNames, s) {
				return "", "", fmt.Errorf("override header_name %q not in allowed_header_names", s)
			}
			headerName = s
		default:
			return "", "", fmt.Errorf("override key %q not allowed", k)
		}
	}
	return format, headerName, nil
}

func rejectNonStandardPort(host string) error {
	if host == "" {
		return errors.New("empty host")
	}
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		return nil
	}
	if port != UpstreamPort {
		return fmt.Errorf("non-443 port %q rejected (per-host port passthrough deferred)", port)
	}
	return nil
}

func validateHost(host string, secret *seal.Secret) error {
	// DNS hostnames are case-insensitive. For the allowlist, fold both
	// sides. For the pattern, prepend the RE2 case-insensitive flag (?i)
	// so operator-authored patterns work whether the operator typed them
	// in lower- or mixed-case — without this, Lowercasing only the input
	// creates a silent fail-closed footgun for any pattern that contains
	// uppercase regex literals (^API\.Stripe\.com$) or shorthand classes
	// like \D / \W / \S where Lowercasing the pattern itself would change
	// the meaning. Idempotent if the operator already wrote (?i).
	hostLower := strings.ToLower(host)
	if len(secret.AllowedHosts) > 0 {
		for _, h := range secret.AllowedHosts {
			if strings.ToLower(h) == hostLower {
				return nil
			}
		}
		return fmt.Errorf("host %q not in allowed_hosts", host)
	}
	if secret.AllowedHostPattern != "" {
		ok, err := regexp.MatchString("(?i)"+secret.AllowedHostPattern, host)
		if err != nil {
			return fmt.Errorf("allowed_host_pattern: %w", err)
		}
		if !ok {
			return fmt.Errorf("host %q does not match allowed_host_pattern", host)
		}
		return nil
	}
	return errors.New("seal has no host allowlist")
}

func validatePath(path string, secret *seal.Secret) error {
	// Reject "." and ".." segments before consulting the allowlist. Go's
	// url.Parse does not normalize these (and decodes %2e%2e to ".." in the
	// Path field), so a literal prefix or regex match against
	// allowed_path_prefixes / allowed_path_pattern would otherwise admit a
	// path like /v1/charges/../admin which the upstream could then resolve to
	// /admin. Refused unconditionally — no legitimate vendor URL needs dot
	// segments.
	//
	// Iterative unescape closes the double-encoded variant: an attacker
	// who sends /v1/charges/abc%252F..%252Fadmin gets a one-round
	// url.Parse decode to /v1/charges/abc%2F..%2Fadmin (no dot segment
	// after split-on-"/"), which then survives the surface check. Some
	// upstreams URL-decode again (or treat %2F as a path separator) and
	// resolve back to /admin. Decode until stable, refusing on any
	// intermediate form that exposes a dot segment. The allowlist
	// matching that follows still runs against the wire-form path (the
	// one url.Parse produced) — that is the form actually forwarded to
	// the upstream, so it is the correct surface to scope.
	if err := refuseDotSegments(path); err != nil {
		return err
	}
	if len(secret.AllowedPathPrefixes) > 0 {
		for _, p := range secret.AllowedPathPrefixes {
			if path == p {
				return nil
			}
			prefix := p
			if !strings.HasSuffix(prefix, "/") {
				prefix += "/"
			}
			if strings.HasPrefix(path, prefix) {
				return nil
			}
		}
		return fmt.Errorf("path %q not permitted", path)
	}
	if secret.AllowedPathPattern != "" {
		ok, err := regexp.MatchString(secret.AllowedPathPattern, path)
		if err != nil {
			return fmt.Errorf("allowed_path_pattern: %w", err)
		}
		if !ok {
			return fmt.Errorf("path %q does not match allowed_path_pattern", path)
		}
	}
	return nil
}

// refuseDotSegments unescapes path repeatedly and rejects the first form
// that contains a "." or ".." segment. Caps the iteration count so a
// malicious input that doesn't converge can't burn CPU. Vendor URLs in
// practice never need more than one decode; the cap is a safety bound.
func refuseDotSegments(path string) error {
	const maxDecodes = 4
	current := path
	for i := 0; i <= maxDecodes; i++ {
		for _, seg := range strings.Split(current, "/") {
			if seg == "." || seg == ".." {
				return fmt.Errorf("path %q contains %q segment after %d decodes", path, seg, i)
			}
		}
		next, err := url.PathUnescape(current)
		if err != nil {
			return fmt.Errorf("path %q: invalid percent-encoding: %w", path, err)
		}
		if next == current {
			return nil
		}
		current = next
	}
	return fmt.Errorf("path %q: percent-encoding decode did not stabilize within %d rounds", path, maxDecodes)
}

func validateMethod(method string, secret *seal.Secret) error {
	if len(secret.AllowedMethods) == 0 {
		return nil
	}
	for _, m := range secret.AllowedMethods {
		if m == method {
			return nil
		}
	}
	return fmt.Errorf("method %q not in allowed_methods", method)
}

func (s *Server) guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// Lowercase before lookup: DNS hostnames are case-insensitive, but a Go
	// map lookup is not. Without normalizing, an attacker who tweaks the case
	// of the proxy's own hostname (SECRET-PROXY.EXAMPLE.COM) bypasses the
	// self-loop guard, the IP-based check then resolves a public IP, and the
	// dial proceeds. The map is built lowercase in AutoSelfHostnames.
	if _, isSelf := s.SelfHostnames[strings.ToLower(host)]; isSelf {
		s.Logger.Warn("egress_refused", "reason", "self_loop", "host", host)
		return nil, fmt.Errorf("%w: self-loop (%s)", ErrEgressRefused, host)
	}
	dialAddr := addr
	if !s.DisableEgressGuard {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("egress guard: no IPs for %s", host)
		}
		for _, ip := range ips {
			if isPrivateOrLocal(ip.IP) {
				s.Logger.Warn("egress_refused", "reason", "private_ip", "host", host, "ip", ip.IP.String())
				return nil, fmt.Errorf("%w: %s resolves to %s", ErrEgressRefused, host, ip.IP)
			}
		}
		dialAddr = net.JoinHostPort(ips[0].IP.String(), port)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, dialAddr)
}

func isPrivateOrLocal(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func stripPort(host string) string {
	if host == "" {
		return ""
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

func queryKeys(u *url.URL) []string {
	if u.RawQuery == "" {
		return nil
	}
	keys := []string{}
	for k := range u.Query() {
		keys = append(keys, k)
	}
	return keys
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func AutoSelfHostnames(extra []string) map[string]struct{} {
	// Keys are stored lowercase so guardedDial's lookup (also lowercased) is
	// case-insensitive — DNS hostnames are case-insensitive but Go's map
	// keys are not. Without this, SECRET-PROXY.EXAMPLE.COM bypasses the
	// self-loop check.
	out := map[string]struct{}{
		"localhost": {},
		"127.0.0.1": {},
		"::1":       {},
	}
	if h, err := osHostname(); err == nil && h != "" {
		out[strings.ToLower(h)] = struct{}{}
	}
	for _, e := range extra {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			out[e] = struct{}{}
		}
	}
	return out
}
