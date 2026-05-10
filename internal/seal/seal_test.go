package seal

import (
	"encoding/base64"
	"regexp"
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

// TestValidate_refusesControlCharsInHeaderValues locks the FIND-007 fix:
// CR / LF / NUL in any value that flows into an outbound HTTP header is
// refused at seal time. Without this, an operator pasting a stray newline
// into --token (common when copying from a multi-line secret store dump)
// would land a seal that crashes the proxy at request time with a Go
// header-write panic, surfacing as a 500-style server error rather than
// a clean seal-time validation failure.
func TestValidate_refusesControlCharsInHeaderValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Secret)
	}{
		{"token_with_LF", func(s *Secret) { s.InjectHeader.Token = "sk_live_xxx\nattacker: header" }},
		{"token_with_CR", func(s *Secret) { s.InjectHeader.Token = "sk_live_xxx\rattacker" }},
		{"token_with_NUL", func(s *Secret) { s.InjectHeader.Token = "sk_live_xxx\x00more" }},
		{"token_with_SOH", func(s *Secret) { s.InjectHeader.Token = "sk_live_xxx\x01more" }},
		{"token_with_DEL", func(s *Secret) { s.InjectHeader.Token = "sk_live_xxx\x7Fmore" }},
		{"format_with_LF", func(s *Secret) { s.InjectHeader.Format = "Bearer %s\n" }},
		{"header_name_with_CR", func(s *Secret) { s.InjectHeader.HeaderName = "X-Auth\r" }},
		{"allowed_formats_LF", func(s *Secret) { s.InjectHeader.AllowedFormats = []string{"%s", "Bearer %s\n"} }},
		{"allowed_header_names_NUL", func(s *Secret) {
			s.InjectHeader.AllowedHeaderNames = []string{"X-Auth\x00"}
		}},
		{"allowed_header_names_DEL", func(s *Secret) {
			s.InjectHeader.AllowedHeaderNames = []string{"X-Auth\x7F"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := validSecret()
			tc.mutate(s)
			if err := s.Validate(); err == nil {
				t.Fatal("expected refusal")
			}
		})
	}
}

// TestValidate_acceptsHighBitAndPunctuation confirms the control-char
// guard does not over-reach: high-bit UTF-8 bytes and ASCII punctuation
// that legitimately appear in tokens (=, /, +, .) must not be refused.
// Tab is also accepted because net/http permits it in header values.
func TestValidate_acceptsHighBitAndPunctuation(t *testing.T) {
	for _, tok := range []string{
		"sk_live_AbCdEf-1234567890",
		"Bearer-style+token=padded/safe",
		"vendor.utf8.é.中",
		"token\twith\ttabs", // tab is allowed per RFC 7230
	} {
		s := validSecret()
		s.InjectHeader.Token = tok
		if err := s.Validate(); err != nil {
			t.Errorf("legitimate token %q rejected: %v", tok, err)
		}
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

// TestValidate_refusesUnanchoredPatterns locks the FIND-009 fix: an
// allowed_host_pattern or allowed_path_pattern that lacks ^ at the start
// or $ at the end is refused at seal time, because RE2's MatchString
// behavior on an unanchored pattern admits any host/path containing the
// substring (e.g. ^stripe\.com$ matches "evil.example.com.stripe.com").
func TestValidate_refusesUnanchoredPatterns(t *testing.T) {
	cases := []struct {
		name string
		set  func(*Secret)
	}{
		{"host_no_caret", func(s *Secret) {
			s.AllowedHosts = nil
			s.AllowedHostPattern = "api\\.stripe\\.com$"
		}},
		{"host_no_dollar", func(s *Secret) {
			s.AllowedHosts = nil
			s.AllowedHostPattern = "^api\\.stripe\\.com"
		}},
		{"host_neither_anchor", func(s *Secret) {
			s.AllowedHosts = nil
			s.AllowedHostPattern = "stripe\\.com"
		}},
		{"path_no_caret", func(s *Secret) { s.AllowedPathPattern = "/v1/charges/.*$" }},
		{"path_no_dollar", func(s *Secret) { s.AllowedPathPattern = "^/v1/charges/.*" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := validSecret()
			c.set(s)
			if err := s.Validate(); err == nil {
				t.Fatal("expected anchored-pattern refusal")
			}
		})
	}
}

// TestValidate_acceptsAnchoredPatternWithFlagGroup confirms a leading
// (?i) inline flag group does not confuse the anchor check. RE2 docs
// give patterns starting with such a group, and operators copy them
// verbatim; refusing those would push them toward the unsafe alternative.
func TestValidate_acceptsAnchoredPatternWithFlagGroup(t *testing.T) {
	// Note: RE2 (Go's regexp) supports flags i, m, s, U; x (extended) is
	// unsupported. The mixed-flag tests use only RE2-valid combinations.
	for _, pat := range []string{
		"(?i)^api\\.stripe\\.com$",
		"(?is)^api\\.stripe\\.com$",
		"(?ismU)^api\\.stripe\\.com$",
		"(?-i)^api\\.stripe\\.com$",
		`\A^api\.stripe\.com$\z`,
	} {
		s := validSecret()
		s.AllowedHosts = nil
		s.AllowedHostPattern = pat
		if err := s.Validate(); err != nil {
			t.Errorf("anchored pattern %q rejected: %v", pat, err)
		}
	}
}

// TestValidate_refusesEscapedDollarOrCharClassDollar — the AST-based
// check must NOT be tricked by patterns that look anchored at the string
// level but aren't semantically anchored: an escaped \$ is a literal
// dollar, not the end-of-line anchor; [$] is a character class. Both
// would let an attacker append to the matched substring.
func TestValidate_refusesEscapedDollarOrCharClassDollar(t *testing.T) {
	for _, pat := range []string{
		`^api\.stripe\.com\$`,
		`^api\.stripe\.com[$]`,
		`^api\.stripe\.com$\.attacker\.com`, // anchor in middle of pattern
	} {
		s := validSecret()
		s.AllowedHosts = nil
		s.AllowedHostPattern = pat
		if err := s.Validate(); err == nil {
			t.Errorf("non-anchored pattern %q must be refused", pat)
		}
	}
}

// TestValidate_acceptsCapturedAnchoredPattern locks the AST recursion:
// a top-level capture group whose body is anchored at both ends counts
// as anchored. Operators sometimes write (^api\.stripe\.com$) for legacy
// portability; the AST walker descends through OpCapture.
func TestValidate_acceptsCapturedAnchoredPattern(t *testing.T) {
	s := validSecret()
	s.AllowedHosts = nil
	s.AllowedHostPattern = `(^api\.stripe\.com$)`
	if err := s.Validate(); err != nil {
		t.Fatalf("captured anchored pattern rejected: %v", err)
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

var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestSeal_autoGeneratesEUID(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	in := validSecret()
	if in.EUID != "" {
		t.Fatal("test fixture should start without EUID")
	}
	blob, err := Seal(in, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !uuidV4Pattern.MatchString(in.EUID) {
		t.Fatalf("Seal did not stamp UUIDv4 EUID, got %q", in.EUID)
	}
	got, _, err := Open(blob, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got.EUID != in.EUID {
		t.Fatalf("EUID round-trip mismatch: %q vs %q", got.EUID, in.EUID)
	}
}

func TestSeal_preservesProvidedEUIDAndName(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	in := validSecret()
	in.EUID = "fixed-euid-for-test"
	in.Name = "stripe-prod-charges"
	blob, err := Seal(in, pub)
	if err != nil {
		t.Fatal(err)
	}
	if in.EUID != "fixed-euid-for-test" {
		t.Fatalf("Seal overwrote provided EUID: %q", in.EUID)
	}
	got, _, err := Open(blob, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "stripe-prod-charges" || got.EUID != "fixed-euid-for-test" {
		t.Fatalf("name/euid round-trip mismatch: %+v", got)
	}
}

// TestSeal_doesNotMutateCallerOnValidationFailure locks down the rule that a
// failed Seal leaves the caller's *Secret unchanged. Otherwise a retry would
// carry the EUID stamped during the failed attempt and silently shift the
// per-credential identifier on the second attempt.
//
// Seeded with a sentinel EUID so the assertion also catches a regression
// where Seal overwrites an existing non-empty EUID — not just one where
// it stamps onto a blank caller.
func TestSeal_doesNotMutateCallerOnValidationFailure(t *testing.T) {
	pub, _, _ := GenerateKeypair()
	const preexistingEUID = "test-preexisting-euid-must-not-change"
	bad := validSecret()
	bad.AllowedHosts = nil // makes Validate() fail (no host allowlist)
	bad.EUID = preexistingEUID
	if _, err := Seal(bad, pub); err == nil {
		t.Fatal("expected Seal to fail validation for missing host allowlist")
	}
	if bad.EUID != preexistingEUID {
		t.Fatalf("Seal mutated caller EUID on validation failure: was %q, now %q", preexistingEUID, bad.EUID)
	}
}

func TestNewEUID_uniquePerCall(t *testing.T) {
	seen := map[string]struct{}{}
	for range 64 {
		id, err := NewEUID()
		if err != nil {
			t.Fatal(err)
		}
		if !uuidV4Pattern.MatchString(id) {
			t.Fatalf("not a UUIDv4: %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate EUID: %q", id)
		}
		seen[id] = struct{}{}
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
