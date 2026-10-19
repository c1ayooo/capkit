#!/usr/bin/env bash
# capkit 自治进度看门狗。
# 正常时输出为空（no_agent cron 不会推送）；只在停滞或验收变红时输出，触发飞书告警。
set -uo pipefail

export PATH=/home/c1ay/.local/go/bin:$PATH
cd /home/c1ay/capkit 2>/dev/null || { echo "ALERT: capkit 仓库不存在"; exit 0; }

alerts=""

now=$(date +%s)
last_commit=$(git log -1 --format=%ct 2>/dev/null || echo 0)
idle_min=$(( (now - last_commit) / 60 ))

# 120 分钟无提交视为停滞；一次长任务跑两小时属正常，所以阈值放宽
if [ "$idle_min" -gt 120 ]; then
  alerts="${alerts}STALL: 已 ${idle_min} 分钟无新提交\n"
  alerts="${alerts}最后提交: $(git log -1 --oneline 2>/dev/null)\n"
  alerts="${alerts}工作区改动: $(git status --short 2>/dev/null | wc -l) 个文件\n"
fi

# 验收变红立即报
out=$(timeout 300 bash scripts/verify.sh 2>&1)
if ! printf '%s' "$out" | grep -q "VERIFY PASSED"; then
  alerts="${alerts}VERIFY_FAILED:\n$(printf '%s\n' "$out" | tail -10)\n"
fi

# 契约工具数跌破下限（说明 kit 丢了 Manifest）
cov=$(go test -run TestContractEnvelope -v . 2>/dev/null | grep -cE '^\s+--- PASS')
if [ "${cov:-0}" -lt 70 ]; then
  alerts="${alerts}CONTRACT_TOOLS_DROP: 契约覆盖只剩 ${cov:-0} 个工具（下限 70）\n"
fi

if [ -n "$alerts" ]; then
  printf 'capkit 看门狗\n'
  printf "$alerts"
fi
