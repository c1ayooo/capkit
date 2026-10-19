#!/usr/bin/env bash
# Repair the active Go toolchain when it ships without the `covdata` tool.
#
# Some toolchain distributions fetched into the module cache (notably the
# go1.25.x / go1.26.x golang.org/toolchain@... packages served by the local
# proxy) omit the prebuilt covdata binary. Without it, `go test -cover ./...`
# aborts with `go: no such tool "covdata"` and the M1 acceptance criterion
# "go test -cover ./... 正常输出，无 0% 的 kit" cannot be checked.
#
# Go builds a missing tool from its own source on demand, but only when GOROOT
# is writable — a module-cache GOROOT is read-only, so it fails instead. This
# script performs that one-time build into the toolchain's own tool directory.
#
# Idempotent: a no-op when covdata is already present.
set -euo pipefail

export PATH=/home/c1ay/.local/go/bin:$PATH

goroot=$(go env GOROOT)
tool_dir="$goroot/pkg/tool/$(go env GOOS)_$(go env GOARCH)"
target="$tool_dir/covdata"

if [ -x "$target" ]; then
  echo "covdata present: $target"
  exit 0
fi

if [ ! -d "$goroot/src/cmd/covdata" ]; then
  echo "no covdata source under $goroot/src/cmd/covdata — cannot repair" >&2
  exit 1
fi

go_bin="$goroot/bin/go"
[ -x "$go_bin" ] || go_bin=go

# The module cache (and the toolchain inside it) is read-only by design; make
# the tool directory writable so the freshly built binary can be dropped in.
chmod -R u+w "$goroot" 2>/dev/null || true

# Build with the toolchain's own go, from GOROOT/src (no go.mod there, so no
# toolchain re-exec): this guarantees a covdata compatible with the toolchain.
( cd "$goroot/src" && GOROOT="$goroot" GOTOOLCHAIN=local "$go_bin" build -o "$target" cmd/covdata )

echo "installed covdata: $target"
