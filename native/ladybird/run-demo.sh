#!/usr/bin/env bash
# Run the koschei demo recipient and page, drive Ladybird headless at /native and /native-directive,
# and save screenshots. The proof is the recipient's `sealed-input.unseal` log lines on stderr.
# Usage: LADYBIRD_DIR=/path/to/ladybird native/ladybird/run-demo.sh
set -euo pipefail
: "${LADYBIRD_DIR:?set LADYBIRD_DIR to a built Ladybird checkout}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${OUT_DIR:-$root/docs/research/assets}"
mkdir -p "$out"
cd "$root"
npm run build >/dev/null
node demo/serve.ts 2> "$out/native-demo.jsonl" &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
sleep 1
bin="$LADYBIRD_DIR/Build/release/bin/Ladybird.app/Contents/MacOS/Ladybird"
[ -x "$bin" ] || bin="$LADYBIRD_DIR/Build/release/bin/Ladybird"
for page in native native-directive; do
  timeout 60 "$bin" --headless=screenshot --screenshot-delay 5 --temporary-profile --expose-internals-object \
    --window-width 720 --window-height 320 --screenshot-path "$out/ladybird-$page.png" "http://localhost:4780/$page"
done
echo "--- unseal outcomes ---"
grep -o '"event":"sealed-input.unseal","outcome":"[a-z-]*"' "$out/native-demo.jsonl" || { echo "no unseal events logged" >&2; exit 1; }
grep -q '"outcome":"ok"' "$out/native-demo.jsonl"
