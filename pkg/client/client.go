// Package client provides an http.RoundTripper that drives requests through
// the Secret Proxy via the v2 relative-endpoint mode (§3.1):
//
//	POST /v1/forward HTTP/1.1
//	Host: secret-proxy.example.com
//	X-Upstream-URL: https://api.stripe.com/v1/charges
//	X-Sealed-Secret: <base64>
//	X-Auth-Bearer: Bearer <token>
//	<body>
//
// The proxy unseals, validates, injects the configured credential, and
// forwards to the upstream. Method mirrors (a GET upstream is a GET to
// /v1/forward; same body bytes; same response). Works through any
// reverse-proxy CDN (Render, Cloud Run, Heroku) — the wire is a normal
// relative-URL POST, not absolute-form HTTP.
package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
)

const ForwardPath = "/v1/forward"

type Option func(*transport)

type transport struct {
	base         *http.Transport
	proxyURL     *url.URL
	sealedSecret string
	auth         string
}

func WithSealedSecret(blob string) Option {
	return func(t *transport) { t.sealedSecret = blob }
}

func WithAuth(token string) Option {
	return func(t *transport) { t.auth = token }
}

func WithProxyTLS(cfg *tls.Config) Option {
	return func(t *transport) { t.base.TLSClientConfig = cfg }
}

func NewTransport(proxyURL string, opts ...Option) (http.RoundTripper, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("client: parse proxy URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("client: proxy URL scheme must be http or https, got %q", u.Scheme)
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	t := &transport{base: base, proxyURL: u}
	for _, o := range opts {
		o(t)
	}
	return t, nil
}

// RoundTrip rewrites the request to target the proxy's /v1/forward endpoint
// and tucks the original URL, sealed blob, and bearer into headers. Method,
// body, and non-control headers pass through unchanged so the upstream sees
// the user's request mostly intact (proxy headers stripped server-side).
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	upstreamURL := req.URL.String()

	clone := req.Clone(req.Context())

	forwardURL := *t.proxyURL
	forwardURL.Path = ForwardPath
	forwardURL.RawQuery = ""
	forwardURL.Fragment = ""
	clone.URL = &forwardURL
	clone.Host = t.proxyURL.Host
	clone.RequestURI = ""

	clone.Header.Set("X-Upstream-URL", upstreamURL)
	if t.sealedSecret != "" {
		clone.Header.Set("X-Sealed-Secret", t.sealedSecret)
	}
	if t.auth != "" {
		clone.Header.Set("X-Auth-Bearer", "Bearer "+t.auth)
	}

	return t.base.RoundTrip(clone)
}
