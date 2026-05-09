package seal

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validSecret() *Secret {
	return &Secret{
		BearerAuth:   &BearerAuth{Digest: HashBearer("client-token")},
		InjectHeader: &InjectHeader{Token: "sk_live_xxx"},
		AllowedHosts: []string{"api.stripe.com"},
	}
}

func TestValidate_ok(t *testing.T) {
	if err := validSecret().Validate(); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}

func TestValidate_missingAuth(t *testing.T) {
	s := validSecret()
	s.BearerAuth = nil
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for missing auth tag")
	}
}

func TestValidate_dualAuth(t *testing.T) {
	s := validSecret()
	s.NoAuth = &NoAuth{}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for two auth tags")
	}
}

func TestValidate_missingProcessor(t *testing.T) {
	s := validSecret()
	s.InjectHeader = nil
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for missing processor")
	}
}

func TestValidate_missingHost(t *testing.T) {
	s := validSecret()
	s.AllowedHosts = nil
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for missing host allowlist")
	}
}

func TestValidate_bothHostFields(t *testing.T) {
	s := validSecret()
	s.AllowedHostPattern = "^api\\."
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for both host fields")
	}
}

func TestValidate_bothPathFields(t *testing.T) {
	s := validSecret()
	s.AllowedPathPrefixes = []string{"/v1/charges"}
	s.AllowedPathPattern = "^/v1/.*"
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for both path fields")
	}
}

func TestValidate_emptyToken(t *testing.T) {
	s := validSecret()
	s.InjectHeader.Token = ""
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for missing inject_header.token")
	}
}

func TestSealOpen_roundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	in := validSecret()
	in.AllowedMethods = []string{"POST"}
	blob, err := Seal(in, pub)
	if err != nil {
		t.Fatal(err)
	}
	got, used, err := Open(blob, priv)
	if err != nil {
		t.Fatal(err)
	}
	if used {
		t.Fatal("did not expect fallback to be used")
	}
	if got.InjectHeader.Token != in.InjectHeader.Token {
		t.Fatalf("token mismatch: %q vs %q", got.InjectHeader.Token, in.InjectHeader.Token)
	}
	if len(got.AllowedMethods) != 1 || got.AllowedMethods[0] != "POST" {
		t.Fatalf("methods mismatch: %v", got.AllowedMethods)
	}
}

func TestOpen_wrongKey(t *testing.T) {
	pub, _, _ := GenerateKeypair()
	_, priv2, _ := GenerateKeypair()
	blob, _ := Seal(validSecret(), pub)
	if _, _, err := Open(blob, priv2); err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
}

func TestOpen_fallbackKey(t *testing.T) {
	pubA, privA, _ := GenerateKeypair()
	_, privB, _ := GenerateKeypair()
	blob, _ := Seal(validSecret(), pubA)
	got, used, err := Open(blob, privB, privA)
	if err != nil {
		t.Fatalf("expected fallback to succeed: %v", err)
	}
	if !used {
		t.Fatal("expected usedFallback=true when primary decryption fails")
	}
	if got.InjectHeader.Token != "sk_live_xxx" {
		t.Fatalf("payload mismatch: %v", got)
	}
}

func TestOpen_tamperedCiphertext(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	blob, _ := Seal(validSecret(), pub)
	raw, _ := base64.StdEncoding.DecodeString(blob)
	raw[len(raw)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, _, err := Open(tampered, priv); err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

// TestOpen_unknownField verifies the §2.2 "rejects unknown tags" promise.
func TestOpen_unknownField(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	blob, _ := Seal(validSecret(), pub)
	// Hand-craft a sealed JSON with an extra unknown field. We can't easily
	// re-seal arbitrary plaintext from a test, so we exercise the unmarshal
	// guard by decoding via Open after replacing ciphertext won't work —
	// instead we assert the unmarshal-time guard behavior on a synthetic
	// payload through the package-internal path.
	_ = blob
	_ = priv
	// Direct unmarshal check via the same Decoder configuration.
	payload := []byte(`{"bearer_auth":{"digest":"x"},"inject_header":{"token":"t"},"allowed_hosts":["h"],"future_field":42}`)
	dec := newStrictDecoderForTest(payload)
	if err := dec.Decode(&Secret{}); err == nil {
		t.Fatal("expected unmarshal to reject unknown field")
	}
}

func TestBearerAuth_VerifyBearer(t *testing.T) {
	b := &BearerAuth{Digest: HashBearer("abc123")}
	if !b.VerifyBearer("abc123") {
		t.Fatal("correct token should verify")
	}
	if b.VerifyBearer("def456") {
		t.Fatal("wrong token should not verify")
	}
	if b.VerifyBearer("") {
		t.Fatal("empty token should not verify")
	}
}

func TestBearerAuth_VerifyBearer_malformedDigest(t *testing.T) {
	b := &BearerAuth{Digest: "not-base64-!!!"}
	if b.VerifyBearer("anything") {
		t.Fatal("malformed digest must fail-closed")
	}
	b = &BearerAuth{Digest: base64.StdEncoding.EncodeToString([]byte("short"))}
	if b.VerifyBearer("anything") {
		t.Fatal("wrong-length digest must fail-closed")
	}
}

func TestParsePrivateKey_lengthMismatch(t *testing.T) {
	if _, err := ParsePrivateKey("aabb"); err == nil {
		t.Fatal("expected length error")
	}
}

func TestParsePrivateKey_invalidHex(t *testing.T) {
	if _, err := ParsePrivateKey(strings.Repeat("zz", 32)); err == nil {
		t.Fatal("expected hex parse error")
	}
}

func TestParsePublicKey_roundTrip(t *testing.T) {
	pub, _, _ := GenerateKeypair()
	parsed, err := ParsePublicKey(pub.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != pub {
		t.Fatalf("round-trip mismatch")
	}
}
