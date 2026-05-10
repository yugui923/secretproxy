package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yugui923/secretproxy/internal/seal"
	"github.com/yugui923/secretproxy/pkg/client"
)

type capturedRequest struct {
	method  string
	path    string
	headers http.Header
	body    string
	host    string
}

func newUpstream(t *testing.T) (*httptest.Server, <-chan *capturedRequest) {
	t.Helper()
	ch := make(chan *capturedRequest, 16)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ch <- &capturedRequest{
			method:  r.Method,
			path:    r.URL.Path,
			headers: r.Header.Clone(),
			body:    string(body),
			host:    r.Host,
		}
		w.Header().Set("X-Upstream", "ok")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	return srv, ch
}

func hijackingTransport(upstreamAddr string, upstreamCert *tls.Config) http.RoundTripper {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig:   upstreamCert,
		ForceAttemptHTTP2: false,
	}
}

func startProxy(t *testing.T, srv *Server) (proxyURL string, stop func()) {
	t.Helper()
	dir := t.TempDir()
	cert, key, err := GenerateSelfSignedTLS(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{
		Handler: srv.Handler(),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"},
		},
		// Mirror production (cmd/secret-proxy/main.go): disable HTTP/2 on
		// the listener. httputil.ReverseProxy panics with ErrAbortHandler
		// on body-copy errors under HTTP/2 (and that panic is silently
		// recovered by net/http), so the ErrorLog hook the proxy relies on
		// only fires under HTTP/1.1.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	done := make(chan error, 1)
	go func() { done <- httpSrv.ServeTLS(listener, cert, key) }()

	stop = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}

	for i := 0; i < 20; i++ {
		c, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	return "https://" + listener.Addr().String(), stop
}

type proxySetup struct {
	pub  seal.PublicKey
	priv seal.PrivateKey
	srv  *Server
	url  string
	stop func()
}

func setupProxy(t *testing.T, upstream *httptest.Server) *proxySetup {
	t.Helper()
	pub, priv, err := seal.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	upstreamTLS := &tls.Config{InsecureSkipVerify: true}
	srv := &Server{
		PrivateKey:         &priv,
		Transport:          hijackingTransport(upstream.Listener.Addr().String(), upstreamTLS),
		DisableEgressGuard: true,
		Logger:             discardLogger(),
		SelfHostnames:      map[string]struct{}{},
	}
	url, stop := startProxy(t, srv)
	return &proxySetup{pub: pub, priv: priv, srv: srv, url: url, stop: stop}
}

func sealStripeLike(t *testing.T, pub seal.PublicKey) string {
	t.Helper()
	s := &seal.Secret{
		BearerAuth: &seal.BearerAuth{Digest: seal.HashBearer("client-token")},
		InjectHeader: &seal.InjectHeader{
			Token:      "sk_live_xxx",
			Format:     "Bearer %s",
			HeaderName: "Authorization",
		},
		AllowedHosts:        []string{"api.example.com"},
		AllowedPathPrefixes: []string{"/v1/charges"},
		AllowedMethods:      []string{"POST"},
	}
	blob, err := seal.Seal(s, pub)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestIntegration_HappyPath(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	blob := sealStripeLike(t, p.pub)
	rt, err := client.NewTransport(p.url,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("POST", "https://api.example.com/v1/charges", strings.NewReader("amount=4200"))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}

	select {
	case got := <-captured:
		if got.headers.Get("Authorization") != "Bearer sk_live_xxx" {
			t.Errorf("upstream Authorization: %q", got.headers.Get("Authorization"))
		}
		for _, leaked := range []string{"X-Upstream-URL", "X-Sealed-Secret", "X-Auth-Bearer"} {
			if got.headers.Get(leaked) != "" {
				t.Errorf("%s leaked to upstream: %q", leaked, got.headers.Get(leaked))
			}
		}
		if got.method != "POST" || got.path != "/v1/charges" {
			t.Errorf("upstream got %s %s", got.method, got.path)
		}
		if got.body != "amount=4200" {
			t.Errorf("body lost: %q", got.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received the request")
	}
}

func TestIntegration_WrongHost(t *testing.T) {
	upstream, _ := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	blob := sealStripeLike(t, p.pub)
	rt, _ := client.NewTransport(p.url,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("POST", "https://evil.example.com/v1/charges", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestIntegration_WrongMethod(t *testing.T) {
	upstream, _ := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	blob := sealStripeLike(t, p.pub)
	rt, _ := client.NewTransport(p.url,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	resp, err := c.Get("https://api.example.com/v1/charges")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestIntegration_WrongBearer(t *testing.T) {
	upstream, _ := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	blob := sealStripeLike(t, p.pub)
	rt, _ := client.NewTransport(p.url,
		client.WithSealedSecret(blob),
		client.WithAuth("wrong-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("POST", "https://api.example.com/v1/charges", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestIntegration_DualKeyRotation(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()

	pubA, privA, _ := seal.GenerateKeypair()
	_, privB, _ := seal.GenerateKeypair()

	srv := &Server{
		PrivateKey:         &privB,
		PreviousPrivateKey: &privA,
		Transport:          hijackingTransport(upstream.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}),
		DisableEgressGuard: true,
		Logger:             discardLogger(),
		SelfHostnames:      map[string]struct{}{},
	}
	url, stop := startProxy(t, srv)
	defer stop()

	blob, err := seal.Seal(&seal.Secret{
		BearerAuth: &seal.BearerAuth{Digest: seal.HashBearer("client-token")},
		InjectHeader: &seal.InjectHeader{
			Token: "rotation-token", Format: "Bearer %s", HeaderName: "Authorization",
		},
		AllowedHosts:   []string{"api.example.com"},
		AllowedMethods: []string{"GET"},
	}, pubA)
	if err != nil {
		t.Fatal(err)
	}

	rt, _ := client.NewTransport(url,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}
	resp, err := c.Get("https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 via fallback key, got %d", resp.StatusCode)
	}
	select {
	case got := <-captured:
		if got.headers.Get("Authorization") != "Bearer rotation-token" {
			t.Errorf("Authorization: %q", got.headers.Get("Authorization"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received request")
	}
}

func TestIntegration_NoSealAndNoPassthrough_rejected(t *testing.T) {
	upstream, _ := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	rt, _ := client.NewTransport(p.url,
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	resp, err := c.Get("https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 missing seal, got %d", resp.StatusCode)
	}
}

func TestIntegration_PassthroughWithoutSeal(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()

	_, priv, _ := seal.GenerateKeypair()
	srv := &Server{
		PrivateKey:         &priv,
		AllowPassthrough:   true,
		Transport:          hijackingTransport(upstream.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}),
		DisableEgressGuard: true,
		Logger:             discardLogger(),
		SelfHostnames:      map[string]struct{}{},
	}
	url, stop := startProxy(t, srv)
	defer stop()

	rt, _ := client.NewTransport(url,
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}
	resp, err := c.Get("https://api.example.com/whatever")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("passthrough should reach upstream, got %d", resp.StatusCode)
	}
	select {
	case got := <-captured:
		if got.headers.Get("Authorization") != "" {
			t.Errorf("passthrough should not inject Authorization: %q", got.headers.Get("Authorization"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received request")
	}
}

// TestIntegration_MultipleSealedSecretRejected verifies the chaining-deferred
// guard. We use a raw http.Transport so we can add two X-Sealed-Secret values;
// pkg/client uses Header.Set which would collapse them.
func TestIntegration_MultipleSealedSecretRejected(t *testing.T) {
	upstream, _ := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	blob := sealStripeLike(t, p.pub)
	proxyURL, _ := url.Parse(p.url)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	forwardURL := *proxyURL
	forwardURL.Path = ForwardPath
	req, _ := http.NewRequest("POST", forwardURL.String(), nil)
	req.Header.Set("X-Upstream-URL", "https://api.example.com/v1/charges")
	req.Header.Add("X-Sealed-Secret", blob)
	req.Header.Add("X-Sealed-Secret", "extra-blob")
	req.Header.Set("X-Auth-Bearer", "Bearer client-token")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for chained X-Sealed-Secret, got %d", resp.StatusCode)
	}
}

// TestIntegration_PathTraversal_Rejected closes the bypass where the seal
// allowlist matches the literal path prefix /v1/charges but the upstream URL
// contains a ".." segment that would resolve to a different endpoint server-
// side. Uses a raw http.Transport so the dot segment travels intact (pkg/client
// would reuse the std lib, which preserves it too — but going raw makes the
// attack shape obvious in the test).
func TestIntegration_PathTraversal_Rejected(t *testing.T) {
	upstream, _ := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	blob := sealStripeLike(t, p.pub) // allows only /v1/charges
	proxyURL, _ := url.Parse(p.url)
	c := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   5 * time.Second,
	}

	for _, attack := range []string{
		"https://api.example.com/v1/charges/../admin/users",
		"https://api.example.com/v1/charges/%2e%2e/admin",
		"https://api.example.com/v1/charges/./list",
	} {
		fwd := *proxyURL
		fwd.Path = ForwardPath
		req, _ := http.NewRequest(http.MethodPost, fwd.String(), nil)
		req.Header.Set("X-Upstream-URL", attack)
		req.Header.Set("X-Sealed-Secret", blob)
		req.Header.Set("X-Auth-Bearer", "Bearer client-token")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", attack, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: expected 403, got %d", attack, resp.StatusCode)
		}
	}
}

// TestIntegration_NoAuth_RejectedWithoutFlag verifies the §2.3 rule that a
// no_auth seal MUST be refused unless the server explicitly opts in. This is
// the load-bearing distinction between "the proxy enforces auth" and "the
// operator deliberately turned that off".
func TestIntegration_NoAuth_RejectedWithoutFlag(t *testing.T) {
	upstream, _ := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream) // AllowNoAuth defaults false
	defer p.stop()

	blob, err := seal.Seal(&seal.Secret{
		NoAuth: &seal.NoAuth{},
		InjectHeader: &seal.InjectHeader{
			Token: "tok", Format: "Bearer %s", HeaderName: "Authorization",
		},
		AllowedHosts:   []string{"api.example.com"},
		AllowedMethods: []string{"GET"},
	}, p.pub)
	if err != nil {
		t.Fatal(err)
	}

	rt, _ := client.NewTransport(p.url,
		client.WithSealedSecret(blob),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Get("https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for no_auth without --allow-no-auth, got %d", resp.StatusCode)
	}
}

func TestIntegration_NoAuth_AllowedWithFlag(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()
	pub, priv, _ := seal.GenerateKeypair()
	srv := &Server{
		PrivateKey:         &priv,
		AllowNoAuth:        true,
		Transport:          hijackingTransport(upstream.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}),
		DisableEgressGuard: true,
		Logger:             discardLogger(),
		SelfHostnames:      map[string]struct{}{},
	}
	pURL, stop := startProxy(t, srv)
	defer stop()

	blob, err := seal.Seal(&seal.Secret{
		NoAuth: &seal.NoAuth{},
		InjectHeader: &seal.InjectHeader{
			Token: "tok-no-auth", Format: "Bearer %s", HeaderName: "Authorization",
		},
		AllowedHosts:   []string{"api.example.com"},
		AllowedMethods: []string{"GET"},
	}, pub)
	if err != nil {
		t.Fatal(err)
	}

	rt, _ := client.NewTransport(pURL,
		client.WithSealedSecret(blob),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Get("https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 with --allow-no-auth, got %d", resp.StatusCode)
	}
	select {
	case got := <-captured:
		if got.headers.Get("Authorization") != "Bearer tok-no-auth" {
			t.Errorf("upstream Authorization: %q", got.headers.Get("Authorization"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received request")
	}
}

// TestIntegration_HopByHopHeadersStripped guards the proxy's RFC 7230 §6.1
// hop-by-hop strip set. A client that sends Connection / Keep-Alive / Trailer
// / Transfer-Encoding must not have those leak to the upstream — they describe
// the hop, not the message.
func TestIntegration_HopByHopHeadersStripped(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	blob := sealStripeLike(t, p.pub)
	proxyURL, _ := url.Parse(p.url)
	c := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   5 * time.Second,
	}

	fwd := *proxyURL
	fwd.Path = ForwardPath
	req, _ := http.NewRequest(http.MethodPost, fwd.String(), strings.NewReader("amount=1"))
	req.Header.Set("X-Upstream-URL", "https://api.example.com/v1/charges")
	req.Header.Set("X-Sealed-Secret", blob)
	req.Header.Set("X-Auth-Bearer", "Bearer client-token")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Trailer", "X-Trailer-Hint")
	req.Header.Set("X-App-Trace", "trace-abc") // non-hop, must pass through
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	got := <-captured
	for _, h := range []string{
		"X-Upstream-URL", "X-Sealed-Secret", "X-Auth-Bearer",
		"Keep-Alive", "Trailer", "Proxy-Connection", "Te",
	} {
		if v := got.headers.Get(h); v != "" {
			t.Errorf("%s leaked to upstream: %q", h, v)
		}
	}
	if got.headers.Get("X-App-Trace") != "trace-abc" {
		t.Errorf("non-hop header X-App-Trace must pass through, got %q", got.headers.Get("X-App-Trace"))
	}
}

// TestIntegration_FilteredHeadersRemoved exercises the operator-configurable
// strip list. Silent failure here is dangerous — an operator who set
// SECRET_PROXY_FILTERED_HEADERS=Cookie in the belief that cookies wouldn't
// leak deserves to know if the config doesn't actually work.
func TestIntegration_FilteredHeadersRemoved(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()
	pub, priv, _ := seal.GenerateKeypair()
	srv := &Server{
		PrivateKey:         &priv,
		FilteredHeaders:    []string{"X-Internal-Tag", "Cookie"},
		Transport:          hijackingTransport(upstream.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}),
		DisableEgressGuard: true,
		Logger:             discardLogger(),
		SelfHostnames:      map[string]struct{}{},
	}
	pURL, stop := startProxy(t, srv)
	defer stop()

	blob, _ := seal.Seal(&seal.Secret{
		BearerAuth: &seal.BearerAuth{Digest: seal.HashBearer("client-token")},
		InjectHeader: &seal.InjectHeader{
			Token: "sk_live_xxx", Format: "Bearer %s", HeaderName: "Authorization",
		},
		AllowedHosts:   []string{"api.example.com"},
		AllowedMethods: []string{"POST"},
	}, pub)
	rt, _ := client.NewTransport(pURL,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/charges", nil)
	req.Header.Set("X-Internal-Tag", "should-be-stripped")
	req.Header.Set("Cookie", "session=should-be-stripped")
	req.Header.Set("X-App-Allowed", "should-pass")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	got := <-captured
	if v := got.headers.Get("X-Internal-Tag"); v != "" {
		t.Errorf("X-Internal-Tag leaked: %q", v)
	}
	if v := got.headers.Get("Cookie"); v != "" {
		t.Errorf("Cookie leaked: %q", v)
	}
	if got.headers.Get("X-App-Allowed") != "should-pass" {
		t.Errorf("non-filtered header X-App-Allowed must pass, got %q", got.headers.Get("X-App-Allowed"))
	}
}

// TestIntegration_ClientAuthorizationOverwritten guards against credential
// smuggling: a client that ships its own Authorization header alongside the
// proxy contract must not have that header survive — the seal's injected
// value must replace it. Any other behavior would let the caller bypass the
// sealed token and present arbitrary credentials to the vendor.
func TestIntegration_ClientAuthorizationOverwritten(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	blob := sealStripeLike(t, p.pub)
	rt, _ := client.NewTransport(p.url,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/charges", nil)
	req.Header.Set("Authorization", "Bearer attacker-supplied-token")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	got := <-captured
	if got.headers.Get("Authorization") != "Bearer sk_live_xxx" {
		t.Errorf("client-supplied Authorization smuggled through: %q", got.headers.Get("Authorization"))
	}
	if vals := got.headers.Values("Authorization"); len(vals) != 1 {
		t.Errorf("Authorization should be set exactly once, got %d values: %v", len(vals), vals)
	}
}

// TestIntegration_LogRedactsSecretsIncludesEUID locks the spec §4.3 promise
// that tokens, digests, sealed blobs, and private keys never appear in logs,
// and the §2.2 promise that the seal_euid / seal_name observability fields do.
func TestIntegration_LogRedactsSecretsIncludesEUID(t *testing.T) {
	upstream, _ := newUpstream(t)
	defer upstream.Close()

	var logBuf bytes.Buffer
	pub, priv, _ := seal.GenerateKeypair()
	srv := &Server{
		PrivateKey:         &priv,
		Transport:          hijackingTransport(upstream.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}),
		DisableEgressGuard: true,
		SelfHostnames:      map[string]struct{}{},
		Logger:             slog.New(slog.NewJSONHandler(&logBuf, nil)),
	}
	pURL, stop := startProxy(t, srv)
	defer stop()

	const (
		clientBearer = "client-bearer-MUST-NEVER-LEAK-1234"
		upstreamTok  = "TOKEN-MUST-NEVER-LEAK-5678"
		credName     = "stripe-test-cred"
	)
	in := &seal.Secret{
		BearerAuth: &seal.BearerAuth{Digest: seal.HashBearer(clientBearer)},
		InjectHeader: &seal.InjectHeader{
			Token: upstreamTok, Format: "Bearer %s", HeaderName: "Authorization",
		},
		AllowedHosts:   []string{"api.example.com"},
		AllowedMethods: []string{"GET"},
		Name:           credName,
	}
	blob, err := seal.Seal(in, pub)
	if err != nil {
		t.Fatal(err)
	}

	rt, _ := client.NewTransport(pURL,
		client.WithSealedSecret(blob),
		client.WithAuth(clientBearer),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Get("https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	logs := logBuf.String()
	for _, secret := range []string{
		upstreamTok,
		clientBearer,
		seal.HashBearer(clientBearer), // bearer digest
		priv.Hex(),                    // proxy private key hex
		blob,                          // entire sealed envelope
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("log leaked sensitive material: %q\nlogs:\n%s", secret, logs)
		}
	}
	if !strings.Contains(logs, in.EUID) {
		t.Errorf("log missing seal_euid %q\nlogs:\n%s", in.EUID, logs)
	}
	if !strings.Contains(logs, credName) {
		t.Errorf("log missing seal_name %q\nlogs:\n%s", credName, logs)
	}
}

// TestIntegration_BodyTruncationLoggedAsTruncated locks down the rule that a
// mid-stream upstream failure (response headers flushed, body cut short) is
// logged as proxied_truncated at WARN, not as a normal proxied success at
// INFO. Without this, an operator wiring alerts off the proxied success line
// would never see truncated responses.
//
// Strategy: an upstream that advertises a Content-Length larger than the body
// it actually writes, then closes the connection. ReverseProxy's body copy
// surfaces the read error via ErrorLog, the new copyErrSink captures it, and
// logForwardOutcome routes to the truncated branch.
func TestIntegration_BodyTruncationLoggedAsTruncated(t *testing.T) {
	// HTTP/1.1 only on the upstream — Hijack is not supported under HTTP/2,
	// and hijacking is the simplest way to cut the connection mid-body.
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial body"))
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("response writer not a Hijacker (upstream must be HTTP/1.1)")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}))
	upstream.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	upstream.StartTLS()
	defer upstream.Close()

	var logBuf bytes.Buffer
	pub, priv, _ := seal.GenerateKeypair()
	srv := &Server{
		PrivateKey:         &priv,
		Transport:          hijackingTransport(upstream.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}),
		DisableEgressGuard: true,
		SelfHostnames:      map[string]struct{}{},
		Logger:             slog.New(slog.NewJSONHandler(&logBuf, nil)),
	}
	pURL, stop := startProxy(t, srv)
	defer stop()

	blob := sealStripeLike(t, pub)
	rt, _ := client.NewTransport(pURL,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/charges", nil)
	resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Do(req)
	if err == nil {
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	logs := logBuf.String()
	if !strings.Contains(logs, `"msg":"proxied_truncated"`) {
		t.Errorf("expected proxied_truncated WARN log line, got:\n%s", logs)
	}
	if !strings.Contains(logs, `"level":"WARN"`) {
		t.Errorf("truncation must log at WARN, not INFO; got:\n%s", logs)
	}
	if strings.Contains(logs, `"msg":"proxied"`) {
		t.Errorf("truncated response must NOT also log as success-shaped 'proxied'; got:\n%s", logs)
	}
}

// TestIntegration_EgressRefusalReturns403NotBadGateway proves that an SSRF
// attempt — a seal that allowlists a host whose DNS resolves to a private IP
// — surfaces as 403 with "egress refused", not 502 "upstream error". Without
// this distinction an SSRF attempt aggregates into the same log/metric bucket
// as a vendor outage, making real attacks invisible.
func TestIntegration_EgressRefusalReturns403NotBadGateway(t *testing.T) {
	upstream, _ := newUpstream(t)
	defer upstream.Close()
	pub, priv, _ := seal.GenerateKeypair()
	srv := &Server{
		PrivateKey:    &priv,
		Logger:        discardLogger(),
		SelfHostnames: map[string]struct{}{"self.example.com": {}},
		// DisableEgressGuard intentionally false — we want the dial guard
		// to fire. SelfHostnames covers the self-loop branch without
		// touching DNS.
	}
	pURL, stop := startProxy(t, srv)
	defer stop()

	blob, err := seal.Seal(&seal.Secret{
		BearerAuth: &seal.BearerAuth{Digest: seal.HashBearer("client-token")},
		InjectHeader: &seal.InjectHeader{
			Token: "tok", Format: "Bearer %s", HeaderName: "Authorization",
		},
		AllowedHosts:   []string{"self.example.com"},
		AllowedMethods: []string{"GET"},
	}, pub)
	if err != nil {
		t.Fatal(err)
	}

	rt, _ := client.NewTransport(pURL,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Get("https://self.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("egress refusal must return 403, got %d (body=%q)", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "egress refused") {
		t.Errorf("response body should name the refusal reason, got %q", body)
	}
}

// TestIntegration_NonStandardPortRejected closes the bypass where seal allows a
// non-443 port but the dial would silently rewrite to :443.
func TestIntegration_NonStandardPortRejected(t *testing.T) {
	upstream, _ := newUpstream(t)
	defer upstream.Close()
	pub, priv, _ := seal.GenerateKeypair()
	srv := &Server{
		PrivateKey:         &priv,
		Transport:          hijackingTransport(upstream.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}),
		DisableEgressGuard: true,
		Logger:             discardLogger(),
		SelfHostnames:      map[string]struct{}{},
	}
	pURL, stop := startProxy(t, srv)
	defer stop()

	blob, err := seal.Seal(&seal.Secret{
		BearerAuth: &seal.BearerAuth{Digest: seal.HashBearer("client-token")},
		InjectHeader: &seal.InjectHeader{
			Token: "tok", Format: "Bearer %s", HeaderName: "Authorization",
		},
		AllowedHosts: []string{"api.example.com:8080"},
	}, pub)
	if err != nil {
		t.Fatal(err)
	}

	rt, _ := client.NewTransport(pURL,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", "http://api.example.com:8080/", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-443 port, got %d", resp.StatusCode)
	}
}

// TestIntegration_UpstreamSNIMatchesSealHost is the FIND-016 regression
// guard: when the proxy dials an upstream by IP (after resolving the
// hostname), the TLS handshake's ServerName (SNI) MUST track the seal's
// hostname, not the resolved IP. Today httputil.ReverseProxy sets
// req.Host = target.Host, so SNI carries api.example.com — we assert
// that. A future refactor that passed `addr` (the IP) into the dial
// would silently break SNI / cert validation; this test pins the
// invariant.
func TestIntegration_UpstreamSNIMatchesSealHost(t *testing.T) {
	const expectedSNI = "api.example.com"
	// SNI is captured in the TLS handshake goroutine and read in the
	// test goroutine; pass via a buffered channel to avoid a data race
	// (go test -race would flag a shared string).
	sniCh := make(chan string, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	upstream.TLS = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			select {
			case sniCh <- hello.ServerName:
			default:
				// Channel already has the first SNI; ignore reuse.
			}
			cert, err := selfSignedAnyName()
			if err != nil {
				return nil, err
			}
			return cert, nil
		},
	}
	upstream.StartTLS()
	defer upstream.Close()

	pub, priv, _ := seal.GenerateKeypair()
	srv := &Server{
		PrivateKey:         &priv,
		Transport:          hijackingTransport(upstream.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}),
		DisableEgressGuard: true,
		Logger:             discardLogger(),
		SelfHostnames:      map[string]struct{}{},
	}
	pURL, stop := startProxy(t, srv)
	defer stop()

	s := &seal.Secret{
		BearerAuth:          &seal.BearerAuth{Digest: seal.HashBearer("client-token")},
		InjectHeader:        &seal.InjectHeader{Token: "vendor-secret", HeaderName: "Authorization", Format: "Bearer %s"},
		AllowedHosts:        []string{expectedSNI},
		AllowedPathPrefixes: []string{"/v1"},
		AllowedMethods:      []string{"GET"},
	}
	blob, err := seal.Seal(s, pub)
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := client.NewTransport(pURL,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", "https://"+expectedSNI+"/v1/ping", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	select {
	case capturedSNI := <-sniCh:
		if capturedSNI != expectedSNI {
			t.Fatalf("upstream SNI = %q, want %q (the seal's host, not the dialed IP)", capturedSNI, expectedSNI)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS handshake did not capture SNI within 1s")
	}
}

// selfSignedAnyName mints an Ed25519 self-signed cert with
// SubjectAltName = "*" / 0.0.0.0 / ::0 so the test client accepts it
// regardless of which SNI was offered. Used by
// TestIntegration_UpstreamSNIMatchesSealHost.
func selfSignedAnyName() (*tls.Certificate, error) {
	dir, err := os.MkdirTemp("", "secret-proxy-sni-test-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	certPath, keyPath, err := GenerateSelfSignedTLS(dir, []string{"api.example.com", "127.0.0.1"})
	if err != nil {
		return nil, err
	}
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// TestIntegration_StripsClientAuthorization_OnCustomHeaderName locks the
// FIND-005 fix: when the seal injects to a non-Authorization header
// (e.g. X-API-Key), any client-supplied Authorization is stripped before
// upstream forwarding. Without this, a vendor that honors either header
// could see two distinct identities side-by-side.
func TestIntegration_StripsClientAuthorization_OnCustomHeaderName(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	s := &seal.Secret{
		BearerAuth: &seal.BearerAuth{Digest: seal.HashBearer("client-token")},
		InjectHeader: &seal.InjectHeader{
			Token:      "vendor-secret",
			Format:     "%s",
			HeaderName: "X-API-Key",
		},
		AllowedHosts:        []string{"api.example.com"},
		AllowedPathPrefixes: []string{"/v1/charges"},
		AllowedMethods:      []string{"POST"},
	}
	blob, err := seal.Seal(s, p.pub)
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := client.NewTransport(p.url,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("POST", "https://api.example.com/v1/charges", nil)
	// Client tries to smuggle their own Authorization and Proxy-Authorization
	// in addition to the proxy's X-API-Key injection.
	req.Header.Set("Authorization", "Bearer attacker-token")
	req.Header.Set("Proxy-Authorization", "Bearer attacker-proxy-token")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	select {
	case got := <-captured:
		if got.headers.Get("Authorization") != "" {
			t.Errorf("client Authorization leaked to upstream: %q", got.headers.Get("Authorization"))
		}
		if got.headers.Get("Proxy-Authorization") != "" {
			t.Errorf("client Proxy-Authorization leaked to upstream: %q", got.headers.Get("Proxy-Authorization"))
		}
		if got.headers.Get("X-API-Key") != "vendor-secret" {
			t.Errorf("X-API-Key not injected: %q", got.headers.Get("X-API-Key"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received the request")
	}
}

// TestIntegration_StripsClientAuthorization_OnDefaultAuthorizationInjection
// is a regression guard for the Del-then-Set ordering: when the seal
// targets the default "Authorization" header, the proxy still injects its
// own value rather than leaving the client's value through. (Set after
// Del is a no-op then Set, which is correct, but the "Del strips its own
// upcoming Set" anti-pattern is the kind of refactor mistake worth pinning.)
func TestIntegration_StripsClientAuthorization_OnDefaultAuthorizationInjection(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()

	blob := sealStripeLike(t, p.pub) // injects to "Authorization"
	rt, _ := client.NewTransport(p.url,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("POST", "https://api.example.com/v1/charges", nil)
	req.Header.Set("Authorization", "Bearer attacker-token")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	select {
	case got := <-captured:
		if got.headers.Get("Authorization") != "Bearer sk_live_xxx" {
			t.Errorf("expected proxy-injected Authorization, got %q", got.headers.Get("Authorization"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received the request")
	}
}

// TestIntegration_MaxRequestBytes_ContentLengthRefused confirms a request
// with a Content-Length over the cap is refused with 413 before any forwarding
// work runs. Without the cap, footgun #8 (slowloris on body) is wide open.
func TestIntegration_MaxRequestBytes_ContentLengthRefused(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()
	p.srv.MaxRequestBytes = 1024

	blob := sealStripeLike(t, p.pub)
	rt, _ := client.NewTransport(p.url,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	body := bytes.Repeat([]byte("A"), 2048)
	req, _ := http.NewRequest("POST", "https://api.example.com/v1/charges", bytes.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", resp.StatusCode)
	}
	select {
	case got := <-captured:
		t.Fatalf("upstream should not have received the request, got %s %s", got.method, got.path)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestIntegration_MaxRequestBytes_StreamedOverflow confirms that a chunked
// (no Content-Length) body which exceeds the cap mid-stream fails closed —
// the proxy does NOT forward the full body successfully. The upstream may
// or may not see a partial; what it MUST NOT see is a fully-relayed request
// that completed normally past the cap.
func TestIntegration_MaxRequestBytes_StreamedOverflow(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()
	p := setupProxy(t, upstream)
	defer p.stop()
	const cap = 512
	const overflow = 4096
	p.srv.MaxRequestBytes = cap

	blob := sealStripeLike(t, p.pub)
	rt, _ := client.NewTransport(p.url,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		// Stream chunked > cap; if MaxBytesReader is wired, the upstream copy
		// stops before all bytes flow.
		_, _ = pw.Write(bytes.Repeat([]byte("A"), overflow))
	}()
	req, _ := http.NewRequest("POST", "https://api.example.com/v1/charges", pr)
	req.ContentLength = -1
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for over-cap streamed body, got %d", resp.StatusCode)
	}
	// Belt-and-suspenders: if upstream did somehow receive the full body, the
	// cap silently no-op'd and that's a regression worth flagging even with a
	// 413 status (e.g., 413 came from somewhere else).
	select {
	case got := <-captured:
		if len(got.body) > cap {
			t.Fatalf("upstream got %d bytes (cap=%d); MaxRequestBytes did not bound chunked body", len(got.body), cap)
		}
	case <-time.After(500 * time.Millisecond):
	}
}

// TestIntegration_CloudflareHeadersStrippedFromUpstream confirms that with
// TrustCloudflareHeaders=true, the CF-* / True-Client-IP set is removed from
// the request before it reaches the vendor API. Otherwise the proxy would
// disclose its edge topology to every upstream it talks to.
func TestIntegration_CloudflareHeadersStrippedFromUpstream(t *testing.T) {
	upstream, captured := newUpstream(t)
	defer upstream.Close()

	pub, priv, _ := seal.GenerateKeypair()
	srv := &Server{
		PrivateKey:             &priv,
		Transport:              hijackingTransport(upstream.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}),
		DisableEgressGuard:     true,
		Logger:                 discardLogger(),
		SelfHostnames:          map[string]struct{}{},
		TrustTLSTerminator:     true,
		TrustCloudflareHeaders: true,
	}
	pURL, stop := startProxy(t, srv)
	defer stop()

	blob := sealStripeLike(t, pub)
	rt, _ := client.NewTransport(pURL,
		client.WithSealedSecret(blob),
		client.WithAuth("client-token"),
		client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("POST", "https://api.example.com/v1/charges", nil)
	// Simulate what Cloudflare's edge would inject ahead of the proxy.
	req.Header.Set("CF-Connecting-IP", "203.0.113.42")
	req.Header.Set("CF-Ray", "9f941d583926378a-YYZ")
	req.Header.Set("CF-IPCountry", "CA")
	req.Header.Set("CF-Visitor", `{"scheme":"https"}`)
	req.Header.Set("True-Client-IP", "203.0.113.42")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}

	select {
	case got := <-captured:
		for _, leaked := range CloudflareTrustHeaders {
			if v := got.headers.Get(leaked); v != "" {
				t.Errorf("%s leaked to upstream: %q", leaked, v)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received the request")
	}
}
