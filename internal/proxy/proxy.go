// Package proxy implements the forward HTTP proxy handler from §3.1 of the
// design spec: header parsing, sealed-secret validation, processor execution,
// egress guard, and upstream forwarding.
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
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/yugui923/secretproxy/internal/seal"
)

const (
	HeaderProxySecret = "Proxy-Secret"
	HeaderProxyAuth   = "Proxy-Authorization"
	PublicKeyPath     = "/public-key"
	HealthPath        = "/healthz"
	ReadyPath         = "/readyz"
	UpstreamPort      = "443"
)

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	HeaderProxySecret,
	HeaderProxyAuth,
}

var errMissingSecret = errors.New("missing Proxy-Secret header")

type Server struct {
	PrivateKey         *seal.PrivateKey
	PreviousPrivateKey *seal.PrivateKey
	AllowNoAuth        bool
	AllowPassthrough   bool
	FilteredHeaders    []string
	SelfHostnames      map[string]struct{}
	Logger             *slog.Logger

	// Transport overrides the upstream RoundTripper. Tests use this to inject a
	// trust-anything TLS config or a non-guarded dialer. If nil, the server
	// constructs a guarded transport with the system trust store.
	Transport http.RoundTripper

	// DisableEgressGuard skips the RFC1918/loopback/link-local egress check.
	// Tests flip this so they can dial httptest servers on 127.0.0.1.
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
	s.init()
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == PublicKeyPath && r.URL.Host == "" {
		s.handlePublicKey(w, r)
		return
	}
	if (r.URL.Path == HealthPath || r.URL.Path == ReadyPath) && r.URL.Host == "" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	s.handleProxy(w, r)
}

func (s *Server) handlePublicKey(w http.ResponseWriter, _ *http.Request) {
	pub := s.PrivateKey.Public()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, pub.Hex())
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	logFields := []any{
		"method", r.Method,
		"host", r.Host,
		"path", r.URL.Path,
		"query_keys", queryKeys(r.URL),
	}

	if vals := r.Header.Values(HeaderProxySecret); len(vals) > 1 {
		s.respondError(w, r, http.StatusBadRequest, "multiple Proxy-Secret headers (chaining deferred at v1)", nil, start, logFields)
		return
	}

	blob, override, err := parseProxySecret(r.Header.Get(HeaderProxySecret))
	if err != nil {
		if errors.Is(err, errMissingSecret) && s.AllowPassthrough {
			s.passthrough(w, r, start, logFields)
			return
		}
		s.respondError(w, r, http.StatusBadRequest, "invalid Proxy-Secret", err, start, logFields)
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
	logFields = append(logFields, "auth", secret.AuthKind(), "processor", secret.ProcessorKind())
	if usedFallback {
		s.Logger.Warn("seal_opened_via_previous_key", logFields...)
	}

	switch {
	case secret.BearerAuth != nil:
		bearer, ok := extractBearer(r.Header.Get(HeaderProxyAuth))
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

	if err := validateRequest(r, secret); err != nil {
		s.respondError(w, r, http.StatusForbidden, "request not permitted", err, start, logFields)
		return
	}

	sw := newStatusWriter(w)
	s.forward(sw, r, secret.InjectHeader, format, headerName)
	s.Logger.Info("proxied",
		append(logFields, "status", sw.status, "dur_ms", time.Since(start).Milliseconds())...)
}

func (s *Server) passthrough(w http.ResponseWriter, r *http.Request, start time.Time, logFields []any) {
	if err := rejectNonStandardPort(r.Host); err != nil {
		s.respondError(w, r, http.StatusForbidden, "request not permitted", err, start, logFields)
		return
	}
	sw := newStatusWriter(w)
	s.forward(sw, r, nil, "", "")
	s.Logger.Info("passthrough",
		append(logFields, "status", sw.status, "dur_ms", time.Since(start).Milliseconds())...)
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, ih *seal.InjectHeader, format, headerName string) {
	target := *r.URL
	target.Scheme = "https"
	target.Host = stripPort(r.Host)
	if target.Host == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}

	director := func(req *http.Request) {
		req.URL = &target
		req.Host = target.Host
		req.RequestURI = ""
		for _, h := range hopByHopHeaders {
			req.Header.Del(h)
		}
		for _, h := range s.FilteredHeaders {
			req.Header.Del(h)
		}
		if ih != nil {
			req.Header.Set(headerName, fmt.Sprintf(format, ih.Token))
		}
	}

	rp := &httputil.ReverseProxy{
		Director:  director,
		Transport: s.Transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.Logger.Warn("upstream_error", "error", err.Error())
			http.Error(w, "upstream error", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

func (s *Server) respondError(w http.ResponseWriter, r *http.Request, code int, msg string, cause error, start time.Time, fields []any) {
	if cause != nil {
		fields = append(fields, "error", cause.Error())
	}
	fields = append(fields, "status", code, "dur_ms", time.Since(start).Milliseconds(), "reason", msg)
	s.Logger.Warn("proxy_reject", fields...)
	http.Error(w, msg, code)
}

// statusWriter wraps an http.ResponseWriter to capture the status code that
// downstream code (e.g. httputil.ReverseProxy) writes, so the access log line
// reflects the real upstream/error status instead of an assumed 200.
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

func parseProxySecret(raw string) (blob string, override map[string]any, err error) {
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

// extractBearer pulls the credential to compare against the sealed digest from
// a Proxy-Authorization header. For Basic, the spec (§2.3) says the password
// half is compared, so we base64-decode and split on ":". Bearer is taken raw.
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

// resolveProcessor returns the (format, headerName) pair after applying any
// runtime overrides from the Proxy-Secret JSON suffix. It does not mutate the
// sealed *InjectHeader — the secret is conceptually immutable once decrypted.
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

func validateRequest(r *http.Request, secret *seal.Secret) error {
	if err := rejectNonStandardPort(r.Host); err != nil {
		return err
	}
	if err := validateHost(r.Host, secret); err != nil {
		return err
	}
	if err := validatePath(r.URL.Path, secret); err != nil {
		return err
	}
	return validateMethod(r.Method, secret)
}

// rejectNonStandardPort enforces the §3.2 invariant that proxy → upstream is
// always TLS to port 443. The dial code rewrites the dial port unconditionally,
// so a request whose host carries a non-443 port would otherwise be silently
// redirected — exactly the bypass the agent flagged.
func rejectNonStandardPort(host string) error {
	if host == "" {
		return errors.New("empty host")
	}
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		return nil // no port present, defaults to 443 at dial time
	}
	if port != UpstreamPort {
		return fmt.Errorf("non-443 port %q rejected (per-host port passthrough deferred)", port)
	}
	return nil
}

func validateHost(host string, secret *seal.Secret) error {
	if len(secret.AllowedHosts) > 0 {
		for _, h := range secret.AllowedHosts {
			if h == host {
				return nil
			}
		}
		return fmt.Errorf("host %q not in allowed_hosts", host)
	}
	if secret.AllowedHostPattern != "" {
		ok, err := regexp.MatchString(secret.AllowedHostPattern, host)
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

// guardedDial blocks RFC 1918 / loopback / link-local destinations and
// self-loops. It dials the resolved IP rather than the hostname to defeat DNS
// rebinding (TOCTOU between the policy check and the dial).
func (s *Server) guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if _, isSelf := s.SelfHostnames[host]; isSelf {
		s.Logger.Warn("egress_refused", "reason", "self_loop", "host", host)
		return nil, fmt.Errorf("egress guard: self-loop refused (%s)", host)
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
				return nil, fmt.Errorf("egress guard: refusing dial to %s (%s)", host, ip.IP)
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

// AutoSelfHostnames returns a default self-loop-guard set: localhost, loopback
// IPs, and os.Hostname(). Operators can extend this via config.
func AutoSelfHostnames(extra []string) map[string]struct{} {
	out := map[string]struct{}{
		"localhost": {},
		"127.0.0.1": {},
		"::1":       {},
	}
	if h, err := osHostname(); err == nil && h != "" {
		out[h] = struct{}{}
	}
	for _, e := range extra {
		e = strings.TrimSpace(e)
		if e != "" {
			out[e] = struct{}{}
		}
	}
	return out
}
