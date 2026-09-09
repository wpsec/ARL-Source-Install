#!/usr/bin/env bash
#
# Scheduler 容器启动脚本
# - 保留运行期配置校验
# - 上报 scheduler 容器进程数，供 web 汇总
set -e

wait-for-it.sh -t 0 mongodb:27017
wait-for-it.sh -t 0 rabbitmq:5672
wait-for-it.sh -t 0 redis:6379

PYTHONPATH=/code python3 -m app.tools.sync_runtime_config --quiet || {
  echo "[ERROR] scheduler runtime config sync failed"
  exit 1
}
PYTHONPATH=/code python3 -m app.tools.check_runtime_config \
  --runtime /code/app/config.yaml --quiet || {
  echo "[ERROR] scheduler runtime config security check failed"
  exit 1
}

mkdir -p "${ARL_PROCESS_MONITOR_DIR:-/run/arl-process-monitor}"
MONITOR_LOG="/tmp/arl_process_monitor_${ARL_PROCESS_MONITOR_INSTANCE:-scheduler}.log"
PYTHONPATH=/code python3 -m app.tools.system_monitor_process_reporter \
  >>"${MONITOR_LOG}" 2>&1 &
PROCESS_MONITOR_PID="$!"

SCHEDULER_PID=""
cleanup() {
  if [ -n "${PROCESS_MONITOR_PID}" ] && kill -0 "${PROCESS_MONITOR_PID}" >/dev/null 2>&1; then
    kill "${PROCESS_MONITOR_PID}" >/dev/null 2>&1 || true
    wait "${PROCESS_MONITOR_PID}" >/dev/null 2>&1 || true
  fi
}

terminate_scheduler() {
  if [ -n "${SCHEDULER_PID}" ] && kill -0 "${SCHEDULER_PID}" >/dev/null 2>&1; then
    kill "${SCHEDULER_PID}" >/dev/null 2>&1 || true
  fi
  exit 143
}

trap cleanup EXIT
trap terminate_scheduler TERM INT

python3 -m app.scheduler &
SCHEDULER_PID="$!"
wait "${SCHEDULER_PID}"
