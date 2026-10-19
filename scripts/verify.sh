#!/usr/bin/env bash
# 一键验收。任何一项失败，就是没做完。
set -uo pipefail

export PATH=/home/c1ay/.local/go/bin:$PATH
cd "$(dirname "$0")/.."

# The 1.25/1.26 module-cache toolchains ship without `covdata`, which makes
# `go test -cover ./...` abort. Repair is idempotent and non-fatal here: it does
# not gate build/vet/test, it only makes `-cover` usable.
bash scripts/repair-covdata.sh >/dev/null 2>&1 || true

fail=0
run() {
  local label="$1"; shift
  printf '== %-28s ' "$label"
  if out=$("$@" 2>&1); then
    printf 'OK\n'
  else
    printf 'FAIL\n'
    printf '%s\n' "$out" | tail -20
    fail=1
  fi
}

run "build"            go build ./...
run "vet"              go vet ./...
run "test"             go test ./...
run "contract envelope" go test -run TestContractEnvelope ./core
run "import boundaries" bash scripts/check-imports.sh

# 契约测试必须真的覆盖到工具，不能因为注册表为空而假绿
covered=$(go test -run TestContractEnvelope -v ./core 2>/dev/null | grep -cE '^\s+--- PASS')
printf '== %-28s %s tools\n' "contract coverage" "$covered"
if [ "$covered" -lt 70 ]; then
  echo "FAIL: contract test covered only $covered tools (expected >= 70). A kit probably lost its Manifest."
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "VERIFY FAILED — 任务未完成，不要提交。"
  exit 1
fi

echo
echo "VERIFY PASSED"
