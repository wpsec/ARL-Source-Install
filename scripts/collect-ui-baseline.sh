#!/usr/bin/env bash
# 采集前端重构基线指标（docs/04 第四节数据唯一来源；重构各阶段前后各跑一次对照）
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FE="$ROOT_DIR/ARL/docker/frontend-src"
SRC="$FE/src"

count_lines() { cat "$@" 2>/dev/null | wc -l | tr -d ' '; }

echo "=== UI baseline @ $(date '+%F %T') ==="
echo "git_rev=$(cd "$ROOT_DIR" && git rev-parse --short HEAD)"
echo "App_tsx_lines=$(wc -l < "$SRC/App.tsx" | tr -d ' ')"
echo "components_files=$(find "$SRC/components" -name '*.tsx' | wc -l | tr -d ' ')"
echo "src_total_lines=$(find "$SRC" -name '*.tsx' -o -name '*.ts' | xargs cat 2>/dev/null | wc -l | tr -d ' ')"
echo "brand_class_lines=$(grep -c "brand-" "$SRC/App.tsx" || true)"
echo "overflow_usages=$(grep -cE "overflow-(x|y|auto|hidden|scroll)" "$SRC/App.tsx" || true)"
echo "inline_modal_blocks=$(grep -cE "fixed inset-0 z-[0-9]+ bg-black" "$SRC/App.tsx" || true)"
echo "use_effect_sites=$(grep -c "useEffect(" "$SRC/App.tsx" || true)"
echo "fetch_call_sites=$(grep -cE "fetch\(|apiFetch\(" "$SRC/App.tsx" || true)"
if [ -d "$FE/dist/assets" ]; then
  JS=$(find "$FE/dist/assets" -maxdepth 1 -name '*.js' -exec ls -la {} \; | sort -k5 -rn | head -1)
  echo "largest_js_bytes=$(echo "$JS" | awk '{print $5}')"
  echo "largest_js_name=$(echo "$JS" | awk '{print $NF}')"
else
  echo "largest_js_bytes=NO_DIST (先 npm run build)"
fi
echo "=== end ==="
