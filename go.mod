module github.com/yugui923/secretproxy

go 1.25.0

// Pin the toolchain at the 1.25.12 patch release that fixes the earlier
// 1.25.x stdlib issues plus GO-2026-5856 (crypto/tls), GO-2026-5039
// (net/textproto), and GO-2026-5037 (crypto/x509). Anyone running an
// older 1.25.x will auto-upgrade via Go's toolchain switch.
toolchain go1.25.12

require golang.org/x/crypto v0.51.0

require golang.org/x/sys v0.44.0 // indirect
