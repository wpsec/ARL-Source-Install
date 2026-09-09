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

  # 与 start_web.sh 同源防御：取末行并做整数校验，即便上游 import 期有诊断
  # 写入 stdout，也不会把非数字灌进 celery 参数（降级方向=默认值）。
  value="$(printf '%s\n' "$value" | tail -n 1 | tr -d '[:space:]')"
  case "$value" in
    ''|*[!0-9]*) value="$default_value" ;;
  esac

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

log_wih_binary_runtime() {
  local configured_path="${ARL_WIH_BIN_PATH:-/usr/bin/wih}"
  local resolved_path=""
  local version_text=""

  if [ -n "$configured_path" ] && [ -x "$configured_path" ]; then
    resolved_path="$configured_path"
  elif command -v wih >/dev/null 2>&1; then
    resolved_path="$(command -v wih)"
  fi

  if [ -z "$resolved_path" ]; then
    echo "[WARN] wih binary not found during worker startup"
    return 0
  fi

  version_text="$("$resolved_path" --version 2>/dev/null | head -n 1 || true)"
  if [ -z "$version_text" ]; then
    version_text="unknown"
  fi

  echo "worker startup wih binary path=${resolved_path} version_text=${version_text}"
}

recover_interrupted_tasks() {
  local output
output="$(PYTHONPATH=/code python3 - <<'PY' 2>/dev/null || true
from app import celerytask, utils

recovery_guard = celerytask._collect_live_task_recovery_guard(
    timeout_sec=1.5,
    queue_names=celerytask._WAITING_ORPHAN_QUEUE_SET,
)
live_task_id_set = set(recovery_guard.get("task_id_set") or set())
inspect_ok = bool(recovery_guard.get("live_ok"))
inspect_trusted = bool(recovery_guard.get("trusted"))
inspect_reply_workers = int(recovery_guard.get("reply_worker_count", 0) or 0)
broker_consumer_total = int(recovery_guard.get("consumer_total", 0) or 0)
if inspect_trusted:
    interrupted_result = utils.recover_interrupted_tasks_on_worker_start(live_task_id_set=live_task_id_set)
else:
    interrupted_result = {
        "task": 0,
        "github_task": 0,
        "live_skip": 0,
    }
requeue_waiting_result = celerytask.requeue_orphan_waiting_tasks_on_worker_start()
orphan_waiting_result = celerytask.recover_orphan_waiting_tasks_on_worker_start()
orphan_domain_deep_result = celerytask.recover_orphan_domain_deep_tasks_on_worker_start()
task_count = int((interrupted_result or {}).get("task", 0) or 0)
github_count = int((interrupted_result or {}).get("github_task", 0) or 0)
live_skip = int((interrupted_result or {}).get("live_skip", 0) or 0)
requeue_task_count = int((requeue_waiting_result or {}).get("task", 0) or 0)
requeue_github_count = int((requeue_waiting_result or {}).get("github_task", 0) or 0)
orphan_task_count = int((orphan_waiting_result or {}).get("task", 0) or 0)
orphan_github_count = int((orphan_waiting_result or {}).get("github_task", 0) or 0)
orphan_domain_deep_requeued = int((orphan_domain_deep_result or {}).get("requeued", 0) or 0)
orphan_domain_deep_failed = int((orphan_domain_deep_result or {}).get("failed", 0) or 0)
print(
    "recover interrupted tasks inspect_ok={} inspect_trusted={} inspect_reply_workers={} broker_consumer_total={} task={} github_task={} live_skip={} requeue_waiting_task={} requeue_waiting_github_task={} orphan_waiting_task={} orphan_waiting_github_task={} orphan_domain_deep_requeued={} orphan_domain_deep_failed={}".format(
        int(inspect_ok),
        int(inspect_trusted),
        inspect_reply_workers,
        broker_consumer_total,
        task_count,
        github_count,
        live_skip,
        requeue_task_count,
        requeue_github_count,
        orphan_task_count,
        orphan_github_count,
        orphan_domain_deep_requeued,
        orphan_domain_deep_failed,
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

start_process_monitor() {
  local monitor_dir="${ARL_PROCESS_MONITOR_DIR:-/run/arl-process-monitor}"
  local monitor_instance="${ARL_PROCESS_MONITOR_INSTANCE:-unknown}"
  local monitor_log="/code/logs/arl_process_monitor_${monitor_instance}.log"

  mkdir -p "${monitor_dir}"
  PYTHONPATH=/code python3 -m app.tools.system_monitor_process_reporter \
    >>"${monitor_log}" 2>&1 &
  PROCESS_MONITOR_PID="$!"
  echo "started process monitor instance=${monitor_instance} pid=${PROCESS_MONITOR_PID}"
}

spawn_worker() {
  local worker_name="$1"
  local queue_name="$2"
  local concurrency="$3"

  celery -A app.celerytask.celery worker \
    -l info \
    -Q "${queue_name}" \
    -n "${worker_name}@%h" \
    -c "${concurrency}" \
    -O fair \
    -f "${LOG_FILE_PATH}" &
  LAST_SPAWNED_WORKER_PID="$!"
}

assign_spawned_worker_pid() {
  local target_var="$1"
  shift

  # 不能使用 PID="$(spawn_worker ...)" 这种命令替换来捕获后台 celery PID。
  # 在 bash 中，命令替换会等待子进程持有的管道关闭；而 celery 是长生命周期进程，
  # 会导致脚本卡在第一个 worker 上，后续 arlheavy/arlweb/arltask 根本不会启动。
  spawn_worker "$@"

  if [ -z "${LAST_SPAWNED_WORKER_PID:-}" ]; then
    echo "[ERROR] failed to capture spawned worker pid for $*"
    return 1
  fi

  printf -v "${target_var}" '%s' "${LAST_SPAWNED_WORKER_PID}"
}

assert_worker_stable() {
  local worker_name="$1"
  local worker_pid="$2"
  local stable_check_sec="${3:-2}"
  local elapsed=0

  while [ "${elapsed}" -lt "${stable_check_sec}" ]; do
    if ! kill -0 "${worker_pid}" >/dev/null 2>&1; then
      echo "[ERROR] celery worker ${worker_name} exited before startup stabilized pid=${worker_pid}"
      wait "${worker_pid}" >/dev/null 2>&1 || true
      return 1
    fi

    sleep 1
    elapsed=$((elapsed + 1))
  done

  return 0
}

check_worker_consumer_health() {
  local output
  local status

  if output="$(PYTHONPATH=/code python3 - <<'PY'
import socket

from app import celerytask

health = celerytask._inspect_worker_queue_health(
    {
        "arlgithub": "arlgithub",
        "arlheavy": "arlheavy",
        "arlweb": "arlweb",
        "arltask": "arltask",
    },
    hostname=socket.gethostname(),
    timeout_sec=1.5,
)
checks = health.get("checks") or {}
summary = " ".join(
    "{}={}".format(name, int(bool(item.get("healthy"))))
    for name, item in sorted(checks.items())
)
print(
    "worker consumer health inspect_ok={} healthy={} {}".format(
        int(bool(health.get("inspect_ok"))),
        int(bool(health.get("ok"))),
        summary,
    ).strip()
)
if not health.get("ok"):
    raise SystemExit(1)
PY
  )"; then
    [ -n "${output}" ] && echo "${output}"
    return 0
  fi

  status="$?"
  [ -n "${output}" ] && echo "${output}"
  return "${status}"
}

wait_for_worker_consumers() {
  local attempts=0

  # 启动后给 Celery 注册 pidbox/consumer 的时间，避免把正常启动竞态当成故障。
  while [ "${attempts}" -lt 15 ]; do
    if check_worker_consumer_health; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 2
  done

  echo "[ERROR] celery workers did not register all expected consumers"
  return 1
}

handle_worker_exit() {
  local worker_name="$1"
  local exit_code="$2"

  if [ "${exit_code}" -eq 0 ]; then
    echo "[WARN] celery worker ${worker_name} exited with code 0, respawning in-place to avoid restarting the whole container."
    return 0
  fi

  echo "[ERROR] celery worker ${worker_name} exited unexpectedly with code ${exit_code}, stopping sibling workers for container restart."
  return 1
}

ensure_python_runtime

echo "Syncing runtime config from template (missing keys only)..."
if ! PYTHONPATH=/code python3 -m app.tools.sync_runtime_config --quiet; then
  echo "[WARN] runtime config sync failed, continue startup with existing config"
fi
if ! PYTHONPATH=/code python3 -m app.tools.check_runtime_config \
  --runtime /code/app/config.yaml --quiet; then
  echo "[ERROR] runtime config security check failed, abort startup"
  exit 1
fi

wait-for-it.sh -t 0 mongodb:27017
wait-for-it.sh -t 0 rabbitmq:5672
wait-for-it.sh -t 0 redis:6379
mkdir -p /code/app/tmp
LOG_FILE_PATH="${ARL_SCAN_LOG_FILE:-/code/logs/arl_worker.log}"
mkdir -p "$(dirname "${LOG_FILE_PATH}")"
log_wih_binary_runtime

start_process_monitor

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

assign_spawned_worker_pid GITHUB_PID "arlgithub" "arlgithub" "${GITHUB_CONCURRENCY}"
assign_spawned_worker_pid HEAVY_PID "arlheavy" "arlheavy" "${HEAVY_CONCURRENCY}"
assign_spawned_worker_pid WEB_PID "arlweb" "arlweb" "${WEB_CONCURRENCY}"
assign_spawned_worker_pid TASK_PID "arltask" "arltask" "${TASK_CONCURRENCY}"
assert_worker_stable "arlgithub" "${GITHUB_PID}"
assert_worker_stable "arlheavy" "${HEAVY_PID}"
assert_worker_stable "arlweb" "${WEB_PID}"
assert_worker_stable "arltask" "${TASK_PID}"
if ! wait_for_worker_consumers; then
  terminate_children "${PROCESS_MONITOR_PID}" "${GITHUB_PID}" "${HEAVY_PID}" "${WEB_PID}" "${TASK_PID}"
  exit 1
fi

trap 'terminate_children "$PROCESS_MONITOR_PID" "$GITHUB_PID" "$HEAVY_PID" "$WEB_PID" "$TASK_PID"; exit 143' TERM INT

HEALTH_CHECK_TICKS=0
HEALTH_FAILURES=0

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

    if wait "${WORKER_PID}"; then
      EXIT_CODE=0
    else
      EXIT_CODE=$?
    fi

    if handle_worker_exit "${WORKER_NAME}" "${EXIT_CODE}"; then
      case "${WORKER_NAME}" in
        arlgithub)
          assign_spawned_worker_pid GITHUB_PID "arlgithub" "arlgithub" "${GITHUB_CONCURRENCY}"
          assert_worker_stable "arlgithub" "${GITHUB_PID}"
          ;;
        arlheavy)
          assign_spawned_worker_pid HEAVY_PID "arlheavy" "arlheavy" "${HEAVY_CONCURRENCY}"
          assert_worker_stable "arlheavy" "${HEAVY_PID}"
          ;;
        arlweb)
          assign_spawned_worker_pid WEB_PID "arlweb" "arlweb" "${WEB_CONCURRENCY}"
          assert_worker_stable "arlweb" "${WEB_PID}"
          ;;
        arltask)
          assign_spawned_worker_pid TASK_PID "arltask" "arltask" "${TASK_CONCURRENCY}"
          assert_worker_stable "arltask" "${TASK_PID}"
          ;;
      esac
      continue
    fi

    terminate_children "$PROCESS_MONITOR_PID" "$GITHUB_PID" "$HEAVY_PID" "$WEB_PID" "$TASK_PID"
    exit "${EXIT_CODE}"
  done

  HEALTH_CHECK_TICKS=$((HEALTH_CHECK_TICKS + 1))
  if [ "${HEALTH_CHECK_TICKS}" -ge 15 ]; then
    HEALTH_CHECK_TICKS=0
    if check_worker_consumer_health; then
      HEALTH_FAILURES=0
    else
      HEALTH_FAILURES=$((HEALTH_FAILURES + 1))
      echo "[WARN] celery consumer health check failed consecutive=${HEALTH_FAILURES}/3"
      if [ "${HEALTH_FAILURES}" -ge 3 ]; then
        echo "[ERROR] celery consumer health stayed unhealthy, stopping container for broker re-registration"
        terminate_children "$PROCESS_MONITOR_PID" "$GITHUB_PID" "$HEAVY_PID" "$WEB_PID" "$TASK_PID"
        exit 1
      fi
    fi
  fi

  sleep 2
done
