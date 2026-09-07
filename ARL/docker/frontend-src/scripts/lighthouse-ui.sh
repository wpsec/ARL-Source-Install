#!/usr/bin/env bash
# Lighthouse 基础验收（计划 4·性能/可访问性基线）。
# 依赖外部 lighthouse CLI + Chrome——项目不隐式引入该依赖：
#   安装（用户决策）: npm i -g lighthouse   或仓库内 npx --no-install 已缓存版本
#   Chrome: 默认自动探测，可用 CHROME_PATH 覆盖；容器内加 CHROME_FLAGS="--no-sandbox"。
# 用法: bash scripts/lighthouse-ui.sh   （dist 需已构建；SKIP_BUILD=1 复用现有 dist）
# 退出码: 0=达标, 1=未达标/执行失败, 77=工具缺失(SKIP，调用方按环境处置)。
# 证据: reports/lighthouse.json + 控制台分数对比表。
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUMMARY_DIR="${SUMMARY_DIR:-$SRC_DIR/reports}"
BUDGET_FILE="$SRC_DIR/lighthouse/budget.json"
DIST_DIR="$SRC_DIR/dist"
PORT="${LIGHTHOUSE_PORT:-18099}"

mkdir -p "$SUMMARY_DIR"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
    (cd "$SRC_DIR" && npm run build >/dev/null) || { echo "[ERROR] 前端构建失败" >&2; exit 1; }
fi
[ -f "$DIST_DIR/index.html" ] || { echo "[ERROR] dist 不存在，先构建" >&2; exit 1; }

resolve_lighthouse() {
    if command -v lighthouse >/dev/null 2>&1; then
        echo "lighthouse"
    elif (cd "$SRC_DIR" && npx --no-install lighthouse --version >/dev/null 2>&1); then
        echo "npx --no-install lighthouse"
    else
        echo ""
    fi
}

LIGHTHOUSE_CMD="$(resolve_lighthouse)"
if [ -z "$LIGHTHOUSE_CMD" ]; then
    echo "[SKIP] lighthouse CLI 不可用（npm i -g lighthouse 后重试；不隐式下载依赖）"
    exit 77
fi

# 本地静态服务（不经过 Basic Auth/后端，测前端壳首屏）。
SERVE_PID=""
cleanup() { [ -n "$SERVE_PID" ] && kill "$SERVE_PID" >/dev/null 2>&1 || true; }
trap cleanup EXIT
node "$SRC_DIR/scripts/serve-static.mjs" "$PORT" "$DIST_DIR" > "$SUMMARY_DIR/lighthouse-serve.log" 2>&1 &
SERVE_PID=$!
READY=0
for _ in $(seq 1 20); do
    if curl -sf -o /dev/null "http://127.0.0.1:$PORT/"; then READY=1; break; fi
    sleep 0.3
done
[ "$READY" = "1" ] || { echo "[ERROR] 静态服务未就绪" >&2; exit 1; }

REPORT_JSON="$SUMMARY_DIR/lighthouse.json"
rm -f "$REPORT_JSON"
# shellcheck disable=SC2086
$LIGHTHOUSE_CMD "http://127.0.0.1:$PORT/" \
    --output=json \
    --output-path="$REPORT_JSON" \
    --only-categories=performance,accessibility,best-practices \
    --chrome-flags="${CHROME_FLAGS:---headless=new}" \
    ${CHROME_PATH:+--chrome-path="$CHROME_PATH"}

node -e '
const fs = require("fs");
const report = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const budget = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
let fail = 0;
for (const [cat, min] of Object.entries(budget)) {
  const score = report.categories[cat]?.score;
  if (score === undefined) { console.log(`[FAIL] ${cat}: 报告缺失类目`); fail = 1; continue; }
  const ok = score >= min;
  if (!ok) fail = 1;
  console.log(`[${ok ? "PASS" : "FAIL"}] ${cat}: ${(score * 100).toFixed(1)} >= ${min * 100}`);
}
process.exit(fail);
' "$REPORT_JSON" "$BUDGET_FILE"

echo "[INFO] 报告: $REPORT_JSON"
