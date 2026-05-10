// Command secret-proxy is the entry point for the Secret Proxy daemon and CLI.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yugui923/secretproxy/internal/proxy"
	"github.com/yugui923/secretproxy/internal/seal"
	"github.com/yugui923/secretproxy/pkg/client"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "seal":
		err = runSeal(args)
	case "unseal":
		err = runUnseal(args)
	case "request":
		err = runRequest(args)
	case "gen-tls-cert":
		err = runGenTLSCert(args)
	case "gen-keypair":
		err = runGenKeypair(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: secret-proxy <subcommand> [flags]

Subcommands:
  serve         Run the HTTPS forward proxy daemon.
  seal          Seal a credential against the proxy public key.
  unseal        Decrypt and pretty-print a sealed secret (debug).
  request       One-shot test request through the proxy.
  gen-tls-cert  Generate a self-signed TLS cert + key (dev only).
  gen-keypair   Generate a Curve25519 keypair and print hex private + public.`)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	logLevel := envOr("SECRET_PROXY_LOG_LEVEL", "info")
	allowNoAuth := envBool("SECRET_PROXY_ALLOW_NO_AUTH")
	allowPass := envBool("SECRET_PROXY_ALLOW_PASSTHROUGH")
	filteredEnv := os.Getenv("SECRET_PROXY_FILTERED_HEADERS")
	selfHostsEnv := os.Getenv("SECRET_PROXY_SELF_HOSTNAMES")
	allowedCIDRsEnv := os.Getenv("SECRET_PROXY_ALLOWED_CLIENT_CIDRS")

	privKeyFile := fs.String("private-key-file", os.Getenv("SECRET_PROXY_PRIVATE_KEY_FILE"), "Path to PEM/hex Curve25519 private key")
	privKeyHex := fs.String("private-key", os.Getenv("SECRET_PROXY_PRIVATE_KEY"), "Hex-encoded Curve25519 private key (dev only)")
	prevKeyFile := fs.String("previous-private-key-file", os.Getenv("SECRET_PROXY_PREVIOUS_PRIVATE_KEY_FILE"), "Optional second private key file (rotation)")
	prevKeyHex := fs.String("previous-private-key", os.Getenv("SECRET_PROXY_PREVIOUS_PRIVATE_KEY"), "Optional inline second private key (rotation; PaaS-only)")
	tlsCertFile := fs.String("tls-cert-file", os.Getenv("SECRET_PROXY_TLS_CERT_FILE"), "Path to TLS cert PEM")
	tlsKeyFile := fs.String("tls-key-file", os.Getenv("SECRET_PROXY_TLS_KEY_FILE"), "Path to TLS key PEM")
	listenAddr := fs.String("listen-address", defaultListenAddr(), "Bind address (defaults to :$PORT if PORT set, else :8443)")
	logLevelFlag := fs.String("log-level", logLevel, "debug | info | warn | error")
	allowNoAuthFlag := fs.Bool("allow-no-auth", allowNoAuth, "Permit no_auth sealed secrets")
	allowPassFlag := fs.Bool("allow-passthrough", allowPass, "Forward requests without a sealed secret")
	filteredFlag := fs.String("filtered-headers", filteredEnv, "Comma-separated extra request headers to strip")
	selfHostsFlag := fs.String("self-hostnames", selfHostsEnv, "Comma-separated extra self-loop-guard hostnames")
	trustTermFlag := fs.Bool("trust-tls-terminator", envBool("SECRET_PROXY_TRUST_TLS_TERMINATOR"), "Listen plaintext (only safe when fronted by a TLS terminator: PaaS edge LB, mesh, ingress)")
	allowedCIDRsFlag := fs.String("allowed-client-cidrs", allowedCIDRsEnv, "Comma-separated ingress IP allowlist on /v1/forward (CIDR or bare IP)")
	trustCFFlag := fs.Bool("trust-cloudflare-headers", envBool("SECRET_PROXY_TRUST_CLOUDFLARE_HEADERS"), "Behind Cloudflare: read CF-Connecting-IP for the ingress allowlist and strip CF-* trust headers from upstream forwarding. Requires --trust-tls-terminator.")
	maxBytesDefault, err := envInt64("SECRET_PROXY_MAX_REQUEST_BYTES", 10*1024*1024)
	if err != nil {
		return err
	}
	maxBytesFlag := fs.Int64("max-request-bytes", maxBytesDefault, "Per-request body size cap in bytes; 0 disables")
	readTimeoutDefault, err := envDuration("SECRET_PROXY_READ_TIMEOUT", 60*time.Second)
	if err != nil {
		return err
	}
	readTimeoutFlag := fs.Duration("read-timeout", readTimeoutDefault, "Per-request read timeout (header + body); 0 disables. Default 60s. Tune up for large slow uploads.")
	idleTimeoutDefault, err := envDuration("SECRET_PROXY_IDLE_TIMEOUT", 120*time.Second)
	if err != nil {
		return err
	}
	idleTimeoutFlag := fs.Duration("idle-timeout", idleTimeoutDefault, "Keep-alive idle timeout; 0 disables. Default 120s.")
	allowDevCertFlag := fs.Bool("allow-dev-cert", envBool("SECRET_PROXY_ALLOW_DEV_CERT"), "Bind even if the TLS cert was minted by gen-tls-cert (dev material). Required to use the self-signed dev cert in serve mode.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *trustCFFlag && !*trustTermFlag {
		return errors.New("--trust-cloudflare-headers requires --trust-tls-terminator (CDN-fronted deployments terminate TLS at the edge)")
	}

	priv, err := loadPrivateKey(*privKeyFile, *privKeyHex)
	if err != nil {
		return err
	}
	prev, err := loadPreviousPrivateKey(*prevKeyFile, *prevKeyHex)
	if err != nil {
		return err
	}
	if !*trustTermFlag {
		if *tlsCertFile == "" || *tlsKeyFile == "" {
			return errors.New("--tls-cert-file and --tls-key-file are required (or set --trust-tls-terminator if behind a TLS terminator like a PaaS edge LB)")
		}
		if _, _, err := proxy.LoadCert(*tlsCertFile, *tlsKeyFile); err != nil {
			return err
		}
		// Dev-cert refusal must run AFTER LoadCert (which surfaces a
		// missing/unreadable file as a clearer error). IsDevCert
		// silently returns false on read failure, so reordering would
		// turn that into a silent bypass.
		if proxy.IsDevCert(*tlsCertFile) && !*allowDevCertFlag {
			return proxy.ErrDevCertWithoutAllowFlag
		}
	}

	allowedCIDRs, err := proxy.ParseAllowedClientCIDRs(splitCSV(*allowedCIDRsFlag))
	if err != nil {
		return err
	}

	logger := newLogger(*logLevelFlag)
	srv := &proxy.Server{
		PrivateKey:             &priv,
		PreviousPrivateKey:     prev,
		AllowNoAuth:            *allowNoAuthFlag,
		AllowPassthrough:       *allowPassFlag,
		FilteredHeaders:        splitCSV(*filteredFlag),
		SelfHostnames:          proxy.AutoSelfHostnames(splitCSV(*selfHostsFlag)),
		AllowedClientCIDRs:     allowedCIDRs,
		TrustTLSTerminator:     *trustTermFlag,
		TrustCloudflareHeaders: *trustCFFlag,
		MaxRequestBytes:        *maxBytesFlag,
		Logger:                 logger,
	}

	// ReadTimeout bounds the full request read (header + body) by wall clock
	// and closes the slowloris-on-body vector that ReadHeaderTimeout alone
	// leaves open. The trade-off: a legitimate slow/large upload (multi-MB
	// body, slow client link) is also cut off at the deadline. Tune via
	// --read-timeout / SECRET_PROXY_READ_TIMEOUT, or pass 0 to disable when
	// the deployment expects long-running uploads and accepts the slowloris
	// risk (combine with --max-request-bytes to keep the byte ceiling).
	// IdleTimeout reaps keep-alive sockets from disappeared clients.
	// WriteTimeout is intentionally unset — bounding it would cap legitimate
	// streamed responses (server-sent events, large vendor downloads).
	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       *readTimeoutFlag,
		IdleTimeout:       *idleTimeoutFlag,
	}
	if !*trustTermFlag {
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"},
		}
		// HTTP/1.1 only on the listener. Under HTTP/2 the stdlib's
		// httputil.ReverseProxy panics with http.ErrAbortHandler on body-copy
		// failure and net/http's server.go silently recovers it, hiding the
		// truncation from per-request logs (see spec §3.2 / §4.3
		// proxied_truncated). HTTP/1.1 keeps that signal observable.
		server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}

	// FIND-011: passthrough is a foot-revealer. With it set, requests
	// without X-Sealed-Secret are forwarded after only the egress guard
	// (private/loopback IPs, port 443) and the self-loop check — there
	// is no host allowlist, so a typo'd env var (SECRET_PROXY_ALLOW_PASSTHROUGH=1
	// added by accident) silently turns the deployment into an open
	// egress relay. Surface a clear WARN at startup, and a louder one
	// when no ingress allowlist is also set, so the wrong setting is
	// visible in any dashboard / log digest.
	if *allowPassFlag {
		if len(allowedCIDRs) == 0 {
			logger.Warn("startup_passthrough_open", "allow_passthrough", true, "allowed_client_cidrs", "(empty)", "reason", "passthrough+no-ingress-allowlist = generic egress relay; verify this is intentional")
		} else {
			logger.Warn("startup_passthrough_enabled", "allow_passthrough", true, "allowed_client_cidrs_count", len(allowedCIDRs))
		}
	}
	if *allowNoAuthFlag {
		logger.Warn("startup_no_auth_enabled", "allow_no_auth", true, "reason", "no_auth seals are accepted; verify this is intentional")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		if *trustTermFlag {
			logger.Info("listening", "addr", *listenAddr, "tls", "behind-terminator", "passthrough", *allowPassFlag)
			errCh <- server.ListenAndServe()
		} else {
			logger.Info("listening", "addr", *listenAddr, "tls", "1.3", "passthrough", *allowPassFlag)
			errCh <- server.ListenAndServeTLS(*tlsCertFile, *tlsKeyFile)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		shutdownErr := server.Shutdown(shutdownCtx)
		// Drain the listener goroutine so a real listener failure isn't masked.
		select {
		case listenErr := <-errCh:
			if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
				return listenErr
			}
		case <-time.After(5 * time.Second):
		}
		return shutdownErr
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// defaultListenAddr honors SECRET_PROXY_LISTEN_ADDRESS, falls back to PORT
// (set by Render / Heroku / Cloud Run / App Runner), then :8443.
func defaultListenAddr() string {
	if v := os.Getenv("SECRET_PROXY_LISTEN_ADDRESS"); v != "" {
		return v
	}
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8443"
}

func loadPreviousPrivateKey(file, hexStr string) (*seal.PrivateKey, error) {
	if file != "" {
		k, err := seal.ReadPrivateKeyFile(file)
		if err != nil {
			return nil, fmt.Errorf("previous-private-key-file: %w", err)
		}
		return &k, nil
	}
	if hexStr != "" {
		k, err := seal.ParsePrivateKey(hexStr)
		if err != nil {
			return nil, fmt.Errorf("previous-private-key: %w", err)
		}
		return &k, nil
	}
	return nil, nil
}

func runSeal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	token := fs.String("token", "", "Upstream credential to seal (required)")
	authBearer := fs.String("auth-bearer", "", "Client bearer token (sealed as digest)")
	noAuth := fs.Bool("no-auth", false, "Use no_auth (server must allow)")
	allowHosts := fs.String("allow-host", "", "Comma-separated allowed_hosts")
	allowHostPattern := fs.String("allow-host-pattern", "", "Regex for allowed_host_pattern")
	allowPathPrefix := fs.String("allow-path-prefix", "", "Comma-separated allowed_path_prefixes")
	allowPathPattern := fs.String("allow-path-pattern", "", "Regex for allowed_path_pattern")
	allowMethod := fs.String("allow-method", "", "Comma-separated allowed_methods")
	processor := fs.String("processor", "inject-header", "Processor (only inject-header at v1)")
	format := fs.String("format", "", "Header format (default empty -> 'Bearer %s' at runtime)")
	headerName := fs.String("header-name", "", "Header name (default empty -> 'Authorization' at runtime)")
	allowedFormat := fs.String("allowed-format", "", "Comma-separated allowed_formats")
	allowedHeaderName := fs.String("allowed-header-name", "", "Comma-separated allowed_header_names")
	publicKey := fs.String("public-key", "", "Hex public key")
	publicKeyURL := fs.String("public-key-url", "", "URL serving the public key as text/plain hex (must be https://)")
	name := fs.String("name", "", "Optional human label for this sealed credential (logged on every request)")
	euid := fs.String("euid", "", "Per-seal identifier (random UUIDv4 generated when empty; logged on every request)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *token == "" {
		return errors.New("--token required")
	}
	if *processor != "inject-header" {
		return fmt.Errorf("unsupported --processor %q (only inject-header at v1)", *processor)
	}
	if *authBearer != "" && *noAuth {
		return errors.New("--auth-bearer and --no-auth are mutually exclusive")
	}

	pub, err := resolvePublicKey(*publicKey, *publicKeyURL)
	if err != nil {
		return err
	}

	s := &seal.Secret{
		InjectHeader: &seal.InjectHeader{
			Token:              *token,
			Format:             *format,
			HeaderName:         *headerName,
			AllowedFormats:     splitCSV(*allowedFormat),
			AllowedHeaderNames: splitCSV(*allowedHeaderName),
		},
		AllowedHosts:        splitCSV(*allowHosts),
		AllowedHostPattern:  *allowHostPattern,
		AllowedPathPrefixes: splitCSV(*allowPathPrefix),
		AllowedPathPattern:  *allowPathPattern,
		AllowedMethods:      splitCSV(*allowMethod),
		Name:                *name,
		EUID:                *euid,
	}
	switch {
	case *noAuth:
		s.NoAuth = &seal.NoAuth{}
	case *authBearer != "":
		s.BearerAuth = &seal.BearerAuth{Digest: seal.HashBearer(*authBearer)}
	default:
		return errors.New("provide --auth-bearer or --no-auth")
	}

	blob, err := seal.Seal(s, pub)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "euid: %s\n", s.EUID)
	if s.Name != "" {
		fmt.Fprintf(os.Stderr, "name: %s\n", s.Name)
	}
	fmt.Println(blob)
	return nil
}

func runUnseal(args []string) error {
	fs := flag.NewFlagSet("unseal", flag.ContinueOnError)
	tok := fs.String("token", "", "Sealed secret blob (else stdin)")
	privFile := fs.String("private-key-file", os.Getenv("SECRET_PROXY_PRIVATE_KEY_FILE"), "Path to PEM/hex private key")
	privHex := fs.String("private-key", os.Getenv("SECRET_PROXY_PRIVATE_KEY"), "Hex-encoded private key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, err := loadPrivateKey(*privFile, *privHex)
	if err != nil {
		return err
	}

	blob := strings.TrimSpace(*tok)
	if blob == "" {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		blob = strings.TrimSpace(string(raw))
	}

	s, _, err := seal.Open(blob, priv)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func runRequest(args []string) error {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	proxyURL := fs.String("proxy-url", "https://localhost:8443", "Proxy URL")
	target := fs.String("url", "", "Target URL (required)")
	method := fs.String("method", "GET", "HTTP method")
	body := fs.String("body", "", "Request body")
	insecure := fs.Bool("proxy-insecure", false, "Skip proxy TLS verification (dev only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return errors.New("--url required")
	}

	sealedSecret := os.Getenv("SEALED_SECRET")
	authToken := os.Getenv("AUTH_TOKEN")

	opts := []client.Option{client.WithSealedSecret(sealedSecret), client.WithAuth(authToken)}
	if *insecure {
		opts = append(opts, client.WithProxyTLS(&tls.Config{InsecureSkipVerify: true}))
	}
	rt, err := client.NewTransport(*proxyURL, opts...)
	if err != nil {
		return err
	}

	c := &http.Client{Transport: rt, Timeout: 30 * time.Second}
	req, err := http.NewRequest(*method, *target, strings.NewReader(*body))
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("status: %s\n", resp.Status)
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		return err
	}
	return nil
}

func runGenTLSCert(args []string) error {
	fs := flag.NewFlagSet("gen-tls-cert", flag.ContinueOnError)
	outDir := fs.String("out-dir", ".", "Directory to write cert.pem and key.pem")
	sansFlag := fs.String("san", "", "Comma-separated extra SANs (DNS names or IPs)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cert, key, err := proxy.GenerateSelfSignedTLS(*outDir, splitCSV(*sansFlag))
	if err != nil {
		return err
	}
	fmt.Println("cert:", cert)
	fmt.Println("key:", key)
	return nil
}

func runGenKeypair(args []string) error {
	fs := flag.NewFlagSet("gen-keypair", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, priv, err := seal.GenerateKeypair()
	if err != nil {
		return err
	}
	fmt.Printf("private: %s\npublic: %s\n", priv.Hex(), pub.Hex())
	return nil
}

func loadPrivateKey(file, hexStr string) (seal.PrivateKey, error) {
	if file != "" {
		return seal.ReadPrivateKeyFile(file)
	}
	if hexStr != "" {
		return seal.ParsePrivateKey(hexStr)
	}
	return seal.PrivateKey{}, errors.New("private key required (use --private-key-file, --private-key, or env)")
}

// resolvePublicKey honors the spec's three sources: --public-key (hex literal),
// --public-key-url (must be https), or SECRET_PROXY_PUBLIC_KEY env. Sealing
// against an attacker-controlled key would expose the upstream credential, so
// we refuse plaintext URLs and any non-200 fetch.
func resolvePublicKey(hexStr, urlStr string) (seal.PublicKey, error) {
	if hexStr == "" {
		hexStr = os.Getenv("SECRET_PROXY_PUBLIC_KEY")
	}
	if hexStr == "" && urlStr != "" {
		u, err := url.Parse(urlStr)
		if err != nil {
			return seal.PublicKey{}, fmt.Errorf("--public-key-url: %w", err)
		}
		if u.Scheme != "https" {
			return seal.PublicKey{}, errors.New("--public-key-url must use https://")
		}
		c := &http.Client{Timeout: 10 * time.Second}
		resp, err := c.Get(urlStr)
		if err != nil {
			return seal.PublicKey{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return seal.PublicKey{}, fmt.Errorf("--public-key-url returned %s", resp.Status)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return seal.PublicKey{}, err
		}
		hexStr = strings.TrimSpace(string(raw))
	}
	if hexStr == "" {
		return seal.PublicKey{}, errors.New("public key required (--public-key, --public-key-url, or SECRET_PROXY_PUBLIC_KEY)")
	}
	return seal.ParsePublicKey(hexStr)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	v := strings.ToLower(os.Getenv(key))
	return v == "1" || v == "true" || v == "yes"
}

// envInt64 returns the parsed env value when set, the fallback when unset,
// and an error when set-but-unparseable. Failing fast on a typo (e.g.
// "10mb") beats silently booting with a default that doesn't match what the
// operator wrote in the dashboard.
func envInt64(key string, fallback int64) (int64, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", key, v, err)
	}
	return n, nil
}

// envDuration mirrors envInt64 for time.ParseDuration values (e.g. "60s",
// "2m"). Same fail-fast contract.
func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", key, v, err)
	}
	return d, nil
}
