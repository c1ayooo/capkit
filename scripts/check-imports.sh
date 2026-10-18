#!/usr/bin/env bash
# Fails if a kit imports another kit or a host module. Third-party dependencies
# are unrestricted (see DEPENDENCIES.md); only the kit/host boundary is enforced.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# 1) Kit-to-kit / host imports (direct imports only). A kit may import its own
# subpackages (e.g. shellkit/payload -> shellkit/protocol), but not another kit.
for pkg in $(go list ./kits/...); do
  kit_root=$(echo "$pkg" | sed -E 's#(github.com/c1ayooo/capkit/kits/[^/]+).*#\1#')
  imports=$(go list -f '{{join .Imports "\n"}}' "$pkg")
  bad=$(echo "$imports" | grep '^github.com/c1ayooo/capkit/kits/' | grep -v "^$kit_root/" || true)
  if [ -n "$bad" ]; then
    echo "forbidden cross-kit import in $pkg:" >&2
    echo "$bad" >&2
    fail=1
  fi
  if echo "$imports" | grep -q '^github.com/c1ayooo/4zrec'; then
    echo "forbidden host import in $pkg" >&2
    fail=1
  fi
done

# 2) License boundary. GPL/AGPL/SSPL code must never be imported into this
# module — such tools are invoked as subprocesses through capkit.ProcessRunner
# instead (docs §8: "无 GPL/AGPL 代码被 import"). The inventory of copyleft
# module roots lives in scripts/copyleft.txt.
copyleft_file="scripts/copyleft.txt"
if [ ! -f "$copyleft_file" ]; then
  echo "missing $copyleft_file (copyleft module inventory)" >&2
  exit 1
fi

imported_roots=$(go list -deps ./... 2>/dev/null | grep '\.' | grep -v '^github.com/c1ayooo/capkit' \
  | awk -F/ 'NF>=3 {print $1"/"$2"/"$3}' | sort -u || true)
while IFS= read -r repo; do
  [ -z "$repo" ] && continue
  if grep -qxF "$repo" "$copyleft_file"; then
    echo "copyleft dependency imported: $repo — invoke it as a subprocess instead" >&2
    fail=1
  fi
done <<< "$imported_roots"

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "import boundaries OK"
