#!/usr/bin/env bash
#
# Web 容器启动脚本
# - 读取 ARL 配置中的运行并发参数
# - 等待依赖服务就绪后启动 gunicorn
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
  # 兼容历史镜像: 某些 pip/setuptools 组合会导致 pkg_resources 丢失，进而使 gunicorn/celery 启动失败。
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

echo "Starting gen_crt.sh..."
gen_crt.sh && echo "gen_crt.sh completed"

echo "Starting nginx..."
nginx
echo "nginx started successfully"

echo "Waiting for services..."
wait-for-it.sh -t 0 mongodb:27017
wait-for-it.sh -t 0 rabbitmq:5672
wait-for-it.sh -t 0 redis:6379

# 默认跳过启动阶段全量导入，避免与后台同步并发争抢资源。
IMPORT_FINGERPRINT_ON_BOOT="${ARL_WEB_IMPORT_FINGERPRINT_ON_BOOT:-0}"
case "${IMPORT_FINGERPRINT_ON_BOOT}" in
  1|true|TRUE|yes|YES|on|ON)
    if [ -f /code/tools/finger.json ]; then
      echo "Importing custom fingerprint rules during web startup..."
      if ! PYTHONPATH=/code python3 -m app.tools.import_fingerprint --file /code/tools/finger.json; then
        echo "Custom fingerprint import failed, continue startup"
      fi
    else
      echo "Custom fingerprint file not found, skip import"
    fi
    ;;
  *)
    echo "Skip fingerprint import during web startup, rely on async sync script"
    ;;
esac

WEB_GUNICORN_WORKERS="$(get_cfg_int WEB_GUNICORN_WORKERS 2)"
echo "Starting gunicorn workers=${WEB_GUNICORN_WORKERS}..."

exec gunicorn \
  -b 0.0.0.0:5003 \
  app.main:arl_app \
  -w "${WEB_GUNICORN_WORKERS}" \
  --timeout 300 \
  --graceful-timeout 300 \
  --access-logfile arl_web.log \
  --access-logformat '%({x-real-ip}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
