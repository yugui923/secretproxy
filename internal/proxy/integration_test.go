package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		},
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
