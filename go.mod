module github.com/yugui923/secretproxy

go 1.25.0

// Pin the toolchain at the 1.25.10 patch release that fixes
// GO-2026-4976 (httputil.ReverseProxy query forwarding), GO-2026-4971
// (net.Dial NUL panic on Windows), and GO-2026-4918 (HTTP/2 transport
// infinite loop on bad SETTINGS_MAX_FRAME_SIZE). Anyone running an
// older 1.25.x will auto-upgrade via Go's toolchain switch.
toolchain go1.25.10

require golang.org/x/crypto v0.51.0

require golang.org/x/sys v0.44.0 // indirect
