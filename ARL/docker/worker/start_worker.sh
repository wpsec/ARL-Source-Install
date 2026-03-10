#!/usr/bin/env bash
#
# Worker 容器启动脚本
# - 读取 ARL 配置中的 Celery 队列并发参数
# - 启动 github 与主任务两个队列 worker
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

ensure_python_runtime

wait-for-it.sh -t 60 mongodb:27017
wait-for-it.sh -t 60 rabbitmq:5672
wait-for-it.sh -t 60 redis:6379
mkdir -p /code/app/tmp

GITHUB_CONCURRENCY="$(get_cfg_int CELERY_GITHUB_WORKER_CONCURRENCY 1)"
TASK_CONCURRENCY="$(get_cfg_int CELERY_TASK_WORKER_CONCURRENCY 2)"

echo "start celery github=${GITHUB_CONCURRENCY} task=${TASK_CONCURRENCY}"

celery -A app.celerytask.celery worker \
  -l info \
  -Q arlgithub \
  -n arlgithub \
  -c "${GITHUB_CONCURRENCY}" \
  -O fair \
  -f arl_worker.log &

exec celery -A app.celerytask.celery worker \
  -l info \
  -Q arltask \
  -n arltask \
  -c "${TASK_CONCURRENCY}" \
  -O fair \
  -f arl_worker.log
