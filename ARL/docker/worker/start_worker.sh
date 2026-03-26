#!/usr/bin/env bash
#
# Worker 容器启动脚本
# - 读取 ARL 配置中的 Celery 队列并发参数
# - 启动 github、heavy、web 与主任务四个队列 worker
set -e

get_cfg_int() {
  local key="$1"
  local default_value="$2"
  local value

  value="$(PYTHONPATH=/code python3 - "$key" "$default_value" <<'PY' 2>/dev/null || true
import sys
from app.config import Config

cfg_key = sys.argv[1]
default_value = int(sys.argv[2])
value = getattr(Config, cfg_key, default_value)

try:
    value = int(value)
except Exception:
    value = default_value

if value <= 0:
    value = default_value

print(value)
PY
)"

  if [ -z "$value" ]; then
    value="$default_value"
  fi

  echo "$value"
}

ensure_python_runtime() {
  # 兼容历史镜像: pkg_resources 缺失会导致 celery/gunicorn 直接崩溃循环重启。
  if ! python3 -c "import pkg_resources" >/dev/null 2>&1; then
    echo "[WARN] pkg_resources missing, trying to repair setuptools..."
    pip3 install --no-cache-dir "setuptools<81" >/dev/null 2>&1 || true
  fi

  if ! python3 -c "import pkg_resources" >/dev/null 2>&1; then
    echo "[ERROR] pkg_resources still missing, abort startup."
    exit 1
  fi
}

recover_interrupted_tasks() {
  local output
output="$(PYTHONPATH=/code python3 - <<'PY' 2>/dev/null || true
from app import celerytask, utils

interrupted_result = utils.recover_interrupted_tasks_on_worker_start()
requeue_waiting_result = celerytask.requeue_orphan_waiting_tasks_on_worker_start()
orphan_waiting_result = celerytask.recover_orphan_waiting_tasks_on_worker_start()
task_count = int((interrupted_result or {}).get("task", 0) or 0)
github_count = int((interrupted_result or {}).get("github_task", 0) or 0)
requeue_task_count = int((requeue_waiting_result or {}).get("task", 0) or 0)
requeue_github_count = int((requeue_waiting_result or {}).get("github_task", 0) or 0)
orphan_task_count = int((orphan_waiting_result or {}).get("task", 0) or 0)
orphan_github_count = int((orphan_waiting_result or {}).get("github_task", 0) or 0)
print(
    "recover interrupted tasks task={} github_task={} requeue_waiting_task={} requeue_waiting_github_task={} orphan_waiting_task={} orphan_waiting_github_task={}".format(
        task_count,
        github_count,
        requeue_task_count,
        requeue_github_count,
        orphan_task_count,
        orphan_github_count,
    )
)
PY
)"

  if [ -n "$output" ]; then
    echo "$output"
  fi
}

should_run_startup_recovery() {
  local flag
  flag="$(echo "${ARL_WORKER_RECOVER_ON_BOOT:-1}" | tr '[:upper:]' '[:lower:]')"
  case "$flag" in
    0|false|no|off)
      return 1
      ;;
    *)
      return 0
      ;;
  esac
}

terminate_children() {
  local pids=("$@")
  local pid

  for pid in "${pids[@]}"; do
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done

  for pid in "${pids[@]}"; do
    if [ -n "$pid" ]; then
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
}

ensure_python_runtime

wait-for-it.sh -t 0 mongodb:27017
wait-for-it.sh -t 0 rabbitmq:5672
wait-for-it.sh -t 0 redis:6379
mkdir -p /code/app/tmp
LOG_FILE_PATH="${ARL_SCAN_LOG_FILE:-/code/logs/arl_worker.log}"
mkdir -p "$(dirname "${LOG_FILE_PATH}")"

if should_run_startup_recovery; then
  recover_interrupted_tasks
else
  echo "skip startup recovery because ARL_WORKER_RECOVER_ON_BOOT=${ARL_WORKER_RECOVER_ON_BOOT:-0}"
fi

GITHUB_CONCURRENCY="$(get_cfg_int CELERY_GITHUB_WORKER_CONCURRENCY 1)"
HEAVY_CONCURRENCY="$(get_cfg_int CELERY_HEAVY_WORKER_CONCURRENCY 1)"
WEB_CONCURRENCY="$(get_cfg_int CELERY_WEB_WORKER_CONCURRENCY 1)"
TASK_CONCURRENCY="$(get_cfg_int CELERY_TASK_WORKER_CONCURRENCY 2)"

echo "start celery github=${GITHUB_CONCURRENCY} heavy=${HEAVY_CONCURRENCY} web=${WEB_CONCURRENCY} task=${TASK_CONCURRENCY} log=${LOG_FILE_PATH}"

celery -A app.celerytask.celery worker \
  -l info \
  -Q arlgithub \
  -n arlgithub@%h \
  -c "${GITHUB_CONCURRENCY}" \
  -O fair \
  -f "${LOG_FILE_PATH}" &
GITHUB_PID=$!

celery -A app.celerytask.celery worker \
  -l info \
  -Q arlheavy \
  -n arlheavy@%h \
  -c "${HEAVY_CONCURRENCY}" \
  -O fair \
  -f "${LOG_FILE_PATH}" &
HEAVY_PID=$!

celery -A app.celerytask.celery worker \
  -l info \
  -Q arlweb \
  -n arlweb@%h \
  -c "${WEB_CONCURRENCY}" \
  -O fair \
  -f "${LOG_FILE_PATH}" &
WEB_PID=$!

celery -A app.celerytask.celery worker \
  -l info \
  -Q arltask \
  -n arltask@%h \
  -c "${TASK_CONCURRENCY}" \
  -O fair \
  -f "${LOG_FILE_PATH}" &
TASK_PID=$!

trap 'terminate_children "$GITHUB_PID" "$HEAVY_PID" "$WEB_PID" "$TASK_PID"; exit 143' TERM INT

while true; do
  for worker_info in \
    "arlgithub:${GITHUB_PID}" \
    "arlheavy:${HEAVY_PID}" \
    "arlweb:${WEB_PID}" \
    "arltask:${TASK_PID}"; do
    WORKER_NAME="${worker_info%%:*}"
    WORKER_PID="${worker_info##*:}"

    if kill -0 "${WORKER_PID}" >/dev/null 2>&1; then
      continue
    fi

    wait "${WORKER_PID}"
    EXIT_CODE=$?
    echo "[ERROR] celery worker ${WORKER_NAME} exited unexpectedly with code ${EXIT_CODE}, stopping sibling workers for container restart."
    terminate_children "$GITHUB_PID" "$HEAVY_PID" "$WEB_PID" "$TASK_PID"
    exit "${EXIT_CODE}"
  done

  sleep 2
done
