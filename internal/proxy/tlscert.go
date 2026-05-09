package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

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
