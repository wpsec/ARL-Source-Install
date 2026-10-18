#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$#" -ne 0 ]]; then
  echo "用法：bash scripts/run-container-regression.sh" >&2
  echo "平台与固定容器名参数已取消；完整离线回归统一由 run-offline-tests.sh 执行。" >&2
  exit 2
fi

exec bash "${ROOT}/scripts/run-offline-tests.sh"
