#!/usr/bin/env bash
# Re-render docs/architecture-*.svg from their .mmd sources.
# Requires npx + node 22+. Uses @mermaid-js/mermaid-cli (mmdc).
#
# Usage:  ./docs/render-diagrams.sh
set -euo pipefail

cd "$(dirname "$0")"

PUP_CFG="$(mktemp -t pup-XXXXXX.json)"
trap 'rm -f "$PUP_CFG"' EXIT
cat > "$PUP_CFG" <<'JSON'
{ "args": ["--no-sandbox", "--disable-setuid-sandbox"] }
JSON

for src in architecture-runtime.mmd architecture-sealing.mmd; do
  out="${src%.mmd}.svg"
  echo "rendering $src -> $out"
  npx --yes -p @mermaid-js/mermaid-cli mmdc \
    --input "$src" \
    --output "$out" \
    --puppeteerConfigFile "$PUP_CFG" \
    --backgroundColor white \
    --theme default
done

echo "done."
