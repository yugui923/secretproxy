package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIsDevCert_genTLSCertMintedRecognized confirms the FIND-008 contract:
// a cert minted by GenerateSelfSignedTLS carries CN = DevCertCommonName,
// and IsDevCert spots it. Without this, an operator who copies dev key
// material into production would silently bind a TLS listener with an
// untrusted self-signed cert.
func TestIsDevCert_genTLSCertMintedRecognized(t *testing.T) {
	dir := t.TempDir()
	certPath, _, err := GenerateSelfSignedTLS(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !IsDevCert(certPath) {
		t.Fatalf("gen-tls-cert output must be detected as a dev cert (CN=%q)", DevCertCommonName)
	}
}

// TestIsDevCert_realCertNotFlagged confirms IsDevCert does not false-
// positive on legitimate (non-dev) certs. We mint a cert with a
// production-style CN and assert IsDevCert returns false.
func TestIsDevCert_realCertNotFlagged(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "real.pem")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "secret-proxy.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if IsDevCert(certPath) {
		t.Fatal("real cert with non-dev CN must not be flagged as a dev cert")
	}
}

// TestIsDevCert_missingOrMalformed exercises the safe-fall-through:
// IsDevCert returns false on read or parse failure, letting the regular
// TLS load path surface a clearer error.
func TestIsDevCert_missingOrMalformed(t *testing.T) {
	if IsDevCert("/nonexistent/path/cert.pem") {
		t.Fatal("missing file must not be flagged as a dev cert")
	}
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if IsDevCert(junk) {
		t.Fatal("malformed PEM must not be flagged as a dev cert")
	}
}
