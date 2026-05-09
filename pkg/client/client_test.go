package client_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/yugui923/secretproxy/pkg/client"
)

func TestNewTransport_invalidScheme(t *testing.T) {
	if _, err := client.NewTransport("ftp://localhost:21"); err == nil {
		t.Fatal("expected scheme rejection")
	}
}

func TestRoundTrip_setsHeadersAndRewritesScheme(t *testing.T) {
	var got atomic.Pointer[http.Request]

	// httptest.NewServer is plain HTTP; it acts as the proxy in this test.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Clone(r.Context()))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer proxy.Close()

	rt, err := client.NewTransport(proxy.URL,
		client.WithSealedSecret("blob=="),
		client.WithAuth("tkn"),
	)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: rt}

	resp, err := c.Get("https://api.example.com/foo?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	r := got.Load()
	if r == nil {
		t.Fatal("proxy never received the request")
	}
	if r.URL.Scheme != "http" {
		t.Errorf("scheme not rewritten: %q", r.URL.Scheme)
	}
	if r.URL.Host != "api.example.com" {
		t.Errorf("host changed: %q", r.URL.Host)
	}
	if r.Header.Get("Proxy-Secret") != "blob==" {
		t.Errorf("Proxy-Secret missing: %q", r.Header.Get("Proxy-Secret"))
	}
	if r.Header.Get("Proxy-Authorization") != "Bearer tkn" {
		t.Errorf("Proxy-Authorization wrong: %q", r.Header.Get("Proxy-Authorization"))
	}
}
