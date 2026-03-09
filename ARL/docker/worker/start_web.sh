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

  value="$(PYTHONPATH=/code python3.6 - "$key" "$default_value" <<'PY' 2>/dev/null || true
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

echo "Starting gen_crt.sh..."
gen_crt.sh && echo "gen_crt.sh completed"

echo "Starting nginx..."
if nginx; then
  echo "nginx started successfully"
else
  echo "nginx failed to start"
fi

echo "Waiting for services..."
wait-for-it.sh -t 60 mongodb:27017
wait-for-it.sh -t 60 rabbitmq:5672
wait-for-it.sh -t 60 redis:6379

if [ -f /code/tools/finger.json ]; then
  echo "Importing custom fingerprint rules..."
  if ! PYTHONPATH=/code python3.6 -m app.tools.import_fingerprint --file /code/tools/finger.json; then
    echo "Custom fingerprint import failed, continue startup"
  fi
else
  echo "Custom fingerprint file not found, skip import"
fi

WEB_GUNICORN_WORKERS="$(get_cfg_int WEB_GUNICORN_WORKERS 2)"
echo "Starting gunicorn workers=${WEB_GUNICORN_WORKERS}..."

exec gunicorn \
  -b 0.0.0.0:5003 \
  app.main:arl_app \
  -w "${WEB_GUNICORN_WORKERS}" \
  --access-logfile arl_web.log \
  --access-logformat '%({x-real-ip}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
