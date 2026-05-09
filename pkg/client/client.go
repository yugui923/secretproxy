// Package client provides an http.RoundTripper that drives requests through
// the Secret Proxy: it injects Proxy-Secret + Proxy-Authorization headers and
// rewrites https:// target URLs to http:// so the proxy sees plaintext.
package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
)

type Option func(*transport)

type transport struct {
	base         *http.Transport
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
	base.Proxy = http.ProxyURL(u)
	t := &transport{base: base}
	for _, o := range opts {
		o(t)
	}
	return t, nil
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if clone.URL.Scheme == "https" {
		newURL := *clone.URL
		newURL.Scheme = "http"
		clone.URL = &newURL
	}
	if t.sealedSecret != "" {
		clone.Header.Set("Proxy-Secret", t.sealedSecret)
	}
	if t.auth != "" {
		clone.Header.Set("Proxy-Authorization", "Bearer "+t.auth)
	}
	return t.base.RoundTrip(clone)
}
