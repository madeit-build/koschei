#!/usr/bin/env bash
# Apply the koschei patch series to a Ladybird checkout pinned at 1010a932 and build it.
# Usage: LADYBIRD_DIR=/path/to/ladybird native/ladybird/apply-and-build.sh
set -euo pipefail
: "${LADYBIRD_DIR:?set LADYBIRD_DIR to a Ladybird checkout}"
here="$(cd "$(dirname "$0")" && pwd)"
cd "$LADYBIRD_DIR"
if [ "$(git rev-parse HEAD)" != "$(git rev-parse 1010a932^{commit})" ]; then
  echo "expected HEAD at 1010a932; got $(git rev-parse --short HEAD). Check out 1010a932 first." >&2
  exit 1
fi
git checkout -q -b koschei-sealedinput
git am "$here"/*.patch
# Reverse order: each prepend lands at the front of PATH, so the last one
# prepended here (rustup) ends up first, matching the original fixed string.
for prefix in /opt/homebrew/bin /opt/homebrew/opt/ccache/libexec /opt/homebrew/opt/rustup/bin; do
  [ -d "$prefix" ] || continue
  PATH="$prefix:$PATH"
done
export PATH
./Meta/ladybird.py build
./Build/release/bin/TestHPKE
./Build/release/bin/test-web --test-path Tests/LibWeb --filter "*sealed*"
