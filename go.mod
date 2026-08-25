module github.com/yugui923/secretproxy

go 1.25.0

// Pin the toolchain at the 1.25.13 patch release that fixes GO-2026-6218
// (net/url), GO-2026-6090 (crypto/tls), GO-2026-6089 and GO-2026-5026
// (net/http), and GO-2026-5972 (encoding/asn1). Older 1.25.x installs
// auto-upgrade via Go's toolchain switch.
toolchain go1.25.13

require golang.org/x/crypto v0.52.0

require golang.org/x/sys v0.45.0 // indirect
