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

// TestRoundTrip_v1Forward verifies the v1 wire envelope: a normal relative-URL
// POST to /v1/forward with X-Upstream-URL, X-Sealed-Secret, X-Auth-Bearer.
// Method mirrors and the original target URL travels in the header.
func TestRoundTrip_v1Forward(t *testing.T) {
	var got atomic.Pointer[http.Request]

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
	if r.URL.Path != client.ForwardPath {
		t.Errorf("path: %q (expected %q)", r.URL.Path, client.ForwardPath)
	}
	if r.Method != http.MethodGet {
		t.Errorf("method: %q (expected GET — should mirror upstream)", r.Method)
	}
	if r.Header.Get("X-Upstream-URL") != "https://api.example.com/foo?x=1" {
		t.Errorf("X-Upstream-URL: %q", r.Header.Get("X-Upstream-URL"))
	}
	if r.Header.Get("X-Sealed-Secret") != "blob==" {
		t.Errorf("X-Sealed-Secret: %q", r.Header.Get("X-Sealed-Secret"))
	}
	if r.Header.Get("X-Auth-Bearer") != "Bearer tkn" {
		t.Errorf("X-Auth-Bearer: %q", r.Header.Get("X-Auth-Bearer"))
	}
}
