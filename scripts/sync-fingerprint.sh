#!/usr/bin/env bash
set -euo pipefail

# 将 /code/tools/finger.json 导入数据库，保证容器使用最新指纹。
# 用法:
#   ./scripts/sync-fingerprint.sh
#   ARL_WEB_CONTAINER_NAME=arl_web ./scripts/sync-fingerprint.sh

CONTAINER_NAME="${ARL_WEB_CONTAINER_NAME:-arl_web}"
FINGERPRINT_FILE="${ARL_FINGERPRINT_FILE:-/code/tools/finger.json}"
MAX_RETRY="${ARL_FINGERPRINT_SYNC_RETRY:-30}"
SLEEP_SECONDS="${ARL_FINGERPRINT_SYNC_INTERVAL:-2}"

if ! command -v docker >/dev/null 2>&1; then
  echo "[WARN] docker command not found, skip fingerprint sync"
  exit 0
fi

if ! docker ps --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
  echo "[WARN] container ${CONTAINER_NAME} is not running, skip fingerprint sync"
  exit 0
fi

echo "Syncing fingerprint file into ${CONTAINER_NAME}..."

attempt=1
while [ "${attempt}" -le "${MAX_RETRY}" ]; do
  if docker exec "${CONTAINER_NAME}" sh -lc "[ -f '${FINGERPRINT_FILE}' ]"; then
    if docker exec "${CONTAINER_NAME}" sh -lc \
      "PYTHONPATH=/code python3 -m app.tools.import_fingerprint --file '${FINGERPRINT_FILE}'"; then
      echo "✓ fingerprint sync completed"
      exit 0
    fi
  fi

  echo "[WARN] fingerprint sync attempt ${attempt}/${MAX_RETRY} failed, retry in ${SLEEP_SECONDS}s..."
  attempt=$((attempt + 1))
  sleep "${SLEEP_SECONDS}"
done

echo "[WARN] fingerprint sync failed after ${MAX_RETRY} attempts"
exit 0
