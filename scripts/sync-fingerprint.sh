#!/usr/bin/env bash
set -euo pipefail

# 将 /code/tools/finger.json 导入数据库，保证容器使用最新指纹。
# 用法:
#   ./scripts/sync-fingerprint.sh
#   ARL_WEB_CONTAINER_NAME=arl_web ./scripts/sync-fingerprint.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CONTAINER_NAME="${ARL_WEB_CONTAINER_NAME:-arl_web}"
FINGERPRINT_FILE="${ARL_FINGERPRINT_FILE:-/code/tools/finger.json}"
MAX_RETRY="${ARL_FINGERPRINT_SYNC_RETRY:-30}"
SLEEP_SECONDS="${ARL_FINGERPRINT_SYNC_INTERVAL:-2}"
# 默认延迟并降低导入优先级，减少与服务就绪阶段的资源竞争。
SYNC_DELAY_SECONDS="${ARL_FINGERPRINT_SYNC_DELAY_SECONDS:-90}"
IMPORT_NICE_LEVEL="${ARL_FINGERPRINT_SYNC_NICE_LEVEL:-19}"
HOST_FINGERPRINT_FILE="${ARL_HOST_FINGERPRINT_FILE:-${ROOT_DIR}/tools/finger.json}"
STATE_FILE="${ARL_FINGERPRINT_SYNC_STATE_FILE:-${ROOT_DIR}/ARL/docker/.fingerprint-sync.sha256}"
LOCK_DIR="${ARL_FINGERPRINT_SYNC_LOCK_DIR:-${ROOT_DIR}/ARL/docker/.fingerprint-sync.lock}"

calc_sha256() {
  local file_path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file_path}" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file_path}" | awk '{print $1}'
    return 0
  fi
  return 1
}

sanitize_non_negative_int() {
  local value="$1"
  local fallback="$2"
  if [[ "${value}" =~ ^[0-9]+$ ]]; then
    echo "${value}"
    return 0
  fi
  echo "${fallback}"
}

run_import_fingerprint() {
  if docker exec "${CONTAINER_NAME}" sh -lc "command -v nice >/dev/null 2>&1"; then
    echo "[INFO] importing fingerprint with low priority (nice=${IMPORT_NICE_LEVEL})"
    docker exec "${CONTAINER_NAME}" sh -lc \
      "env PYTHONPATH=/code nice -n ${IMPORT_NICE_LEVEL} python3 -m app.tools.import_fingerprint --file \"${FINGERPRINT_FILE}\""
    return $?
  fi

  echo "[INFO] nice command not found in container, importing with default priority"
  docker exec "${CONTAINER_NAME}" sh -lc \
    "PYTHONPATH=/code python3 -m app.tools.import_fingerprint --file \"${FINGERPRINT_FILE}\""
}

get_fingerprint_count() {
  local count
  count="$(docker exec "${CONTAINER_NAME}" sh -lc \
    "PYTHONPATH=/code python3 -c \"from app import utils; print(utils.conn_db('fingerprint').estimated_document_count())\"" \
    2>/dev/null || true)"
  if [[ "${count}" =~ ^[0-9]+$ ]]; then
    echo "${count}"
    return 0
  fi
  echo ""
  return 0
}

SYNC_DELAY_SECONDS="$(sanitize_non_negative_int "${SYNC_DELAY_SECONDS}" "90")"
IMPORT_NICE_LEVEL="$(sanitize_non_negative_int "${IMPORT_NICE_LEVEL}" "19")"
if [ "${IMPORT_NICE_LEVEL}" -gt 19 ]; then
  IMPORT_NICE_LEVEL=19
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[WARN] docker command not found, skip fingerprint sync"
  exit 0
fi

if [ ! -f "${HOST_FINGERPRINT_FILE}" ]; then
  echo "[WARN] host fingerprint file not found: ${HOST_FINGERPRINT_FILE}, skip sync"
  exit 0
fi

if ! docker ps --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
  echo "[WARN] container ${CONTAINER_NAME} is not running, skip fingerprint sync"
  exit 0
fi

mkdir -p "$(dirname "${STATE_FILE}")"
if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
  echo "[INFO] fingerprint sync already running, skip duplicate execution"
  exit 0
fi
trap 'rmdir "${LOCK_DIR}" >/dev/null 2>&1 || true' EXIT

current_hash=""
if current_hash="$(calc_sha256 "${HOST_FINGERPRINT_FILE}")"; then
  if [ -f "${STATE_FILE}" ]; then
    last_hash="$(tr -d '\r\n' < "${STATE_FILE}")"
    if [ -n "${last_hash}" ] && [ "${last_hash}" = "${current_hash}" ]; then
      finger_count="$(get_fingerprint_count)"
      if [ -n "${finger_count}" ] && [ "${finger_count}" -gt 0 ]; then
        echo "[INFO] fingerprint unchanged(hash=${current_hash}), current count=${finger_count}, skip sync"
        exit 0
      fi
    fi
  fi
else
  echo "[WARN] sha256 tool not found, will force sync"
fi

echo "Syncing fingerprint file into ${CONTAINER_NAME}..."
if [ "${SYNC_DELAY_SECONDS}" -gt 0 ]; then
  echo "[INFO] delay fingerprint sync ${SYNC_DELAY_SECONDS}s to avoid startup contention"
  sleep "${SYNC_DELAY_SECONDS}"
fi

attempt=1
while [ "${attempt}" -le "${MAX_RETRY}" ]; do
  if docker exec "${CONTAINER_NAME}" sh -lc "[ -f '${FINGERPRINT_FILE}' ]"; then
    if run_import_fingerprint; then
      if [ -n "${current_hash}" ]; then
        printf "%s" "${current_hash}" > "${STATE_FILE}"
      fi
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
