package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// DevCertCommonName is the CN stamped into self-signed certs by
// gen-tls-cert. The serve command refuses to bind a listener whose cert
// matches this CN unless --allow-dev-cert is set, so an operator who
// copies dev material into production fails fast instead of silently
// running with an untrusted cert that any TLS handshaker will reject.
const DevCertCommonName = "secret-proxy-dev"

// ErrDevCertWithoutAllowFlag is returned when the configured TLS cert
// was minted by gen-tls-cert and --allow-dev-cert was not set.
var ErrDevCertWithoutAllowFlag = errors.New("tls: cert is the gen-tls-cert dev material; pass --allow-dev-cert to use it intentionally, or provision a real cert")

func osHostname() (string, error) {
	return os.Hostname()
}

// GenerateSelfSignedTLS writes a self-signed Ed25519 cert + key pair to outDir
// and returns the two file paths. SANs include localhost, 127.0.0.1, ::1, plus
// extras. Validity 90 days. Dev-only — never use in production.
func GenerateSelfSignedTLS(outDir string, extraSANs []string) (certPath, keyPath string, err error) {
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", "", err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}

	dnsNames := []string{"localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, s := range extraSANs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, s)
		}
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "secret-proxy-dev"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return "", "", err
	}

	certPath = filepath.Join(outDir, "cert.pem")
	keyPath = filepath.Join(outDir, "key.pem")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", "", err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}

// LoadCert is a thin wrapper that returns a useful error if either file is missing.
func LoadCert(certPath, keyPath string) (string, string, error) {
	if _, err := os.Stat(certPath); err != nil {
		return "", "", fmt.Errorf("tls: cert file %q: %w", certPath, err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return "", "", fmt.Errorf("tls: key file %q: %w", keyPath, err)
	}
	return certPath, keyPath, nil
}

// IsDevCert returns true if the PEM at certPath is a self-signed cert
// minted by gen-tls-cert (CN = DevCertCommonName). Used by the serve
// command to refuse the dev material unless --allow-dev-cert is set.
// Returns false on any read or parse error so a malformed file falls
// through to the regular TLS load path which surfaces a clearer error.
func IsDevCert(certPath string) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return c.Subject.CommonName == DevCertCommonName
}
