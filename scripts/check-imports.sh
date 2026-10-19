#!/usr/bin/env bash
# Enforces the import boundaries:
#   1. no kit imports another kit or a host module
#   2. no copyleft (GPL/AGPL/SSPL) module is imported anywhere
#   3. a kit may only import third-party modules allowlisted for it, and the
#      capkit root package stays standard-library only
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

# 3) SDK allowlist. Every third-party module imported anywhere in the module must
# be allowlisted for the directory that imports it, and the capkit root package
# must stay standard-library only (docs "依赖方向单向：kits → capkit 根"). Adding
# a dependency means adding a line to scripts/sdk-allowlist.txt and a row to
# DEPENDENCIES.md in the same change; this check is what makes that enforceable
# rather than aspirational.
#
# Both sides are prefix matches on path segments, which is what makes the check
# correct for Go's module layout: `github.com/aws/aws-sdk-go-v2/service/ec2` must
# resolve to the module root `github.com/aws/aws-sdk-go-v2`, while
# `github.com/jackc/pgx/v5/stdlib` must resolve to `github.com/jackc/pgx/v5` and
# not to the truncated `github.com/jackc/pgx`. Ask the allowlist for the longest
# root that prefixes the import instead of truncating the import path.
allowlist_file="scripts/sdk-allowlist.txt"
if [ ! -f "$allowlist_file" ]; then
  echo "missing $allowlist_file (SDK allowlist)" >&2
  exit 1
fi

allow_dirs=()
allow_roots=()
while read -r dir root rest; do
  case "${dir:-}" in ""|\#*) continue ;; esac
  [ -z "${root:-}" ] && continue
  allow_dirs+=("$dir")
  allow_roots+=("$root")
done < "$allowlist_file"

# check_pkg <import-path> <module-relative dir>. Direct, test and external-test
# imports are all checked: a test-only import of a copyleft or unlisted module
# is as much a dependency as a production one.
check_pkg() {
  local pkg="$1" rel="$2"
  local deps dep root_seen dir_ok i r d
  deps=$(go list -f '{{join .Imports "\n"}}' "$pkg")
  deps="$deps
$(go list -f '{{join .TestImports "\n"}}{{"\n"}}{{join .XTestImports "\n"}}' "$pkg")"
  while IFS= read -r dep; do
    [ -z "$dep" ] && continue
    # The capkit contracts themselves are always allowed.
    case "$dep" in
      github.com/c1ayooo/capkit*) continue ;;
    esac
    # Standard library: no dot in the first path element.
    case "${dep%%/*}" in
      *.*) ;;
      *) continue ;;
    esac
    root_seen=""; dir_ok=0
    for i in "${!allow_roots[@]}"; do
      r="${allow_roots[$i]}"
      d="${allow_dirs[$i]}"
      if [ "$dep" = "$r" ] || [[ "$dep" == "$r"/* ]]; then
        if [ -z "$root_seen" ] || [ ${#r} -gt ${#root_seen} ]; then
          root_seen="$r"
        fi
        if [ "$rel" = "$d" ] || [[ "$rel" == "$d"/* ]]; then
          dir_ok=1
        fi
      fi
    done
    if [ -z "$root_seen" ]; then
      echo "unallowlisted third-party import in $pkg: $dep" >&2
      echo "  (add a '<dir> <module-root>' line to scripts/sdk-allowlist.txt and a row to DEPENDENCIES.md)" >&2
      fail=1
    elif [ "$dir_ok" -ne 1 ]; then
      if [ "$rel" = "." ]; then
        echo "forbidden third-party import in the capkit root package: $dep" >&2
        echo "  (the root package must stay standard-library only; put SDK code in a kit)" >&2
      else
        echo "import allowlisted elsewhere but not for $rel: $dep" >&2
        echo "  (list $root_seen under $rel in scripts/sdk-allowlist.txt)" >&2
      fi
      fail=1
    fi
  done <<< "$deps"
}

module="github.com/c1ayooo/capkit"
for pkg in $(go list ./...); do
  rel="."
  if [ "$pkg" != "$module" ]; then
    rel="${pkg#"$module"/}"
  fi
  check_pkg "$pkg" "$rel"
done

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "import boundaries OK"

