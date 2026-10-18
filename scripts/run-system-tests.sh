#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT}/ARL/docker/docker-compose.system-test.yml"
IMAGE="${ARL_TEST_RUNNER_IMAGE:-arl:local}"

if [[ ! -f "${ROOT}/.arl-system-test-snapshot" ]]; then
  echo "[ERROR] 仅允许在一次性测试快照中运行；缺少 .arl-system-test-snapshot 标记。" >&2
  exit 2
fi

if [[ ! -f "${COMPOSE_FILE}" || ! -f "${ROOT}/ARL/app/config.yaml.example" ]]; then
  echo "[ERROR] 隔离测试栈文件不完整。" >&2
  exit 2
fi

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "[ERROR] 测试运行镜像不可用：${IMAGE}" >&2
  exit 2
fi
for SIDE_CAR_IMAGE in mongo:7.0 redis:7-alpine rabbitmq:3.13-management-alpine; do
  if ! docker image inspect "${SIDE_CAR_IMAGE}" >/dev/null 2>&1; then
    echo "[ERROR] 离线测试镜像缺失：${SIDE_CAR_IMAGE}；脚本不会联网拉取。" >&2
    exit 2
  fi
done

COMMIT="$(head -n 1 "${ROOT}/.arl-system-test-snapshot" | tr -cd 'a-f0-9')"
SOURCE_SHA="$(sed -n '2p' "${ROOT}/.arl-system-test-snapshot")"
if [[ ! "${COMMIT}" =~ ^[a-f0-9]{7,40}$ ]]; then
  echo "[ERROR] 测试快照没有有效的 commit 标识。" >&2
  exit 2
fi
if [[ ! "${SOURCE_SHA}" =~ ^[a-f0-9]{64}$ ]]; then
  echo "[ERROR] 测试快照没有有效的源码归档摘要。" >&2
  exit 2
fi

PROJECT="arl-system-test-${COMMIT:0:8}-$(date -u +%Y%m%d%H%M%S)-$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
RABBIT_USER="arltest_$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
RABBIT_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
UI_USERNAME="arl_ui_$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
UI_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
WEB_PORT="$(python3 -c 'import socket; sock=socket.socket(); sock.bind(("127.0.0.1", 0)); print(sock.getsockname()[1]); sock.close()')"
export ARL_TEST_RABBIT_USER="${RABBIT_USER}"
export ARL_TEST_RABBIT_PASSWORD="${RABBIT_PASSWORD}"
export ARL_SYSTEM_TEST_UI_USERNAME="${UI_USERNAME}"
export ARL_SYSTEM_TEST_UI_PASSWORD="${UI_PASSWORD}"
export ARL_SYSTEM_TEST_WEB_PORT="${WEB_PORT}"
export ARL_TEST_RUNNER_IMAGE="${IMAGE}"
export ARL_TEST_SOURCE_DIR="${ROOT}"

REPORT_DIR="${ARL_TEST_REPORT_DIR:-/var/tmp/arl-system-test-reports}"
mkdir -p "${REPORT_DIR}"
REPORT="${REPORT_DIR}/${PROJECT}.log"
: > "${REPORT}"
IMAGE_ID="$(docker image inspect "${IMAGE}" --format '{{.Id}}')"
DOCKER_VERSION="$(docker version --format '{{.Server.Version}}')"
STATUS=0
CONFIG_PREPARED=1
STACK_READY=0
COMPOSE=(docker compose --progress quiet --project-name "${PROJECT}" --file "${COMPOSE_FILE}")

cleanup() {
  local exit_status=$?
  if [[ "${CONFIG_PREPARED}" -eq 1 ]]; then
    "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
    cp "${ROOT}/ARL/app/config.yaml.example" "${ROOT}/ARL/app/config.yaml" || true
    chmod 600 "${ROOT}/ARL/app/config.yaml" 2>/dev/null || true
    unset ARL_TEST_RABBIT_USER ARL_TEST_RABBIT_PASSWORD
  fi
  exit "${exit_status}"
}
trap cleanup EXIT

echo "[1/6] 生成短期隔离配置（凭据由本次运行随机生成，不写入命令行或日志）。"
docker run --pull=never --rm --network none \
  --volume "${ROOT}:/workspace" \
  --workdir /workspace \
  --env ARL_TEST_RABBIT_USER \
  --env ARL_TEST_RABBIT_PASSWORD \
  "${IMAGE}" \
  python3 /workspace/scripts/prepare_system_test_config.py "${PROJECT}" || STATUS=$?
if [[ "${STATUS}" -eq 0 ]]; then
  echo "[2/6] 启动仅含内部网络的临时测试服务。"
  if "${COMPOSE[@]}" up --pull never --detach --wait mongodb redis rabbitmq web target; then
    STACK_READY=1
  else
    STATUS=$?
  fi
fi

if [[ "${STACK_READY}" -eq 1 ]]; then
  echo "[3/6] 运行隔离 API、Celery、RabbitMQ、MongoDB、Redis 和靶场集成用例。"
  if "${COMPOSE[@]}" run --pull never --rm test-runner 2>&1 \
      | sed -e "s/${RABBIT_USER}/[REDACTED]/g" \
            -e "s/${RABBIT_PASSWORD}/[REDACTED]/g" \
            -e "s/${UI_USERNAME}/[REDACTED]/g" \
            -e "s/${UI_PASSWORD}/[REDACTED]/g" \
      | tee -a "${REPORT}" >/dev/null; then
    :
  else
    SYSTEM_TEST_STATUS=$?
    if [[ "${STATUS}" -eq 0 ]]; then
      STATUS="${SYSTEM_TEST_STATUS}"
    fi
  fi

  echo "[4/6] 每个 Python 测试模块在独立进程执行；统计失败并检查导入污染。"
  if "${COMPOSE[@]}" run --pull never --rm -e ARL_RUN_SYSTEM_TESTS=0 test-runner \
      python3 /workspace/scripts/check-test-hygiene.py 2>&1 \
      | sed -e "s/${RABBIT_USER}/[REDACTED]/g" \
            -e "s/${RABBIT_PASSWORD}/[REDACTED]/g" \
            -e "s/${UI_USERNAME}/[REDACTED]/g" \
            -e "s/${UI_PASSWORD}/[REDACTED]/g" \
      | tee -a "${REPORT}" >/dev/null; then
    :
  else
    HYGIENE_STATUS=$?
    if [[ "${STATUS}" -eq 0 ]]; then
      STATUS="${HYGIENE_STATUS}"
    fi
  fi
fi

if [[ "${STACK_READY}" -eq 1 && "${STATUS}" -eq 0 && "${ARL_RUN_SYSTEM_UI_E2E:-0}" == "1" ]]; then
  FRONTEND="${ROOT}/ARL/docker/frontend-src"
  if [[ ! -d "${FRONTEND}/node_modules" ]] || ! command -v npm >/dev/null 2>&1; then
    echo "[ERROR] 系统 UI E2E 需要已安装的前端依赖和 npm；测试脚本不会联网安装依赖。" >&2
    STATUS=2
  else
    echo "[5/6] 在隔离用户下执行真实 API、worker 与浏览器任务闭环。"
    if "${COMPOSE[@]}" run --pull never --rm test-runner \
        python3 /workspace/ARL/test/system_test_ui_user.py create 2>&1 \
        | sed -e "s/${RABBIT_USER}/[REDACTED]/g" \
              -e "s/${RABBIT_PASSWORD}/[REDACTED]/g" \
              -e "s/${UI_USERNAME}/[REDACTED]/g" \
              -e "s/${UI_PASSWORD}/[REDACTED]/g" \
        | tee -a "${REPORT}" >/dev/null; then
      if "${COMPOSE[@]}" up --pull never --detach --wait system-worker \
          | sed -e "s/${RABBIT_USER}/[REDACTED]/g" \
                -e "s/${RABBIT_PASSWORD}/[REDACTED]/g" \
          | tee -a "${REPORT}" >/dev/null; then
        UI_API_URL="http://127.0.0.1:${WEB_PORT}"
        if ! python3 - "${UI_API_URL}" >/dev/null 2>&1 <<'PY'
import sys
import urllib.request
with urllib.request.urlopen(sys.argv[1] + "/api/task/", timeout=3) as response:
    if response.status != 200:
        raise SystemExit(1)
PY
        then
          WEB_CONTAINER_ID="$("${COMPOSE[@]}" ps -q web)"
          WEB_CONTAINER_IP="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${WEB_CONTAINER_ID}")"
          UI_API_URL="http://${WEB_CONTAINER_IP}:5018"
          if ! python3 - "${UI_API_URL}" >/dev/null 2>&1 <<'PY'
import sys
import urllib.request
with urllib.request.urlopen(sys.argv[1] + "/api/task/", timeout=3) as response:
    if response.status != 200:
        raise SystemExit(1)
PY
          then
            echo "[ERROR] 测试机无法从宿主连接隔离 API 的 loopback 端口或容器地址。" >&2
            STATUS=1
          fi
        fi

        if [[ "${STATUS}" -eq 0 ]] && (cd "${FRONTEND}" && \
            PLAYWRIGHT_BROWSERS_PATH="${ROOT}/.pw-browsers" \
            ARL_SYSTEM_TEST_UI_API_URL="${UI_API_URL}" \
            ARL_SYSTEM_TEST_UI_USERNAME="${UI_USERNAME}" \
            ARL_SYSTEM_TEST_UI_PASSWORD="${UI_PASSWORD}" \
            npm run test:e2e -- --grep '@system') 2>&1 \
            | sed -e "s/${RABBIT_USER}/[REDACTED]/g" \
                  -e "s/${RABBIT_PASSWORD}/[REDACTED]/g" \
                  -e "s/${UI_USERNAME}/[REDACTED]/g" \
                  -e "s/${UI_PASSWORD}/[REDACTED]/g" \
            | tee -a "${REPORT}" >/dev/null; then
          :
        else
          STATUS=$?
        fi
      else
        STATUS=$?
      fi
    else
      STATUS=$?
    fi

    if [[ "${STATUS}" -ne 0 ]]; then
      "${COMPOSE[@]}" logs --no-color system-worker web 2>&1 \
        | sed -e "s/${RABBIT_USER}/[REDACTED]/g" \
              -e "s/${RABBIT_PASSWORD}/[REDACTED]/g" \
              -e "s/${UI_USERNAME}/[REDACTED]/g" \
              -e "s/${UI_PASSWORD}/[REDACTED]/g" \
        | tee -a "${REPORT}" >/dev/null || true
    fi

    "${COMPOSE[@]}" run --pull never --rm test-runner \
      python3 /workspace/ARL/test/system_test_ui_user.py delete >/dev/null 2>&1 || true
  fi
fi

echo "[6/6] 停止并移除本次 Compose 项目容器和内部网络。"
"${COMPOSE[@]}" down --remove-orphans || STATUS=$?

# 运行配置含短期 RabbitMQ 凭据；以无凭据模板覆盖临时快照中的副本。
cp "${ROOT}/ARL/app/config.yaml.example" "${ROOT}/ARL/app/config.yaml"
chmod 600 "${ROOT}/ARL/app/config.yaml"
unset ARL_TEST_RABBIT_USER ARL_TEST_RABBIT_PASSWORD
unset ARL_SYSTEM_TEST_UI_USERNAME ARL_SYSTEM_TEST_UI_PASSWORD ARL_SYSTEM_TEST_WEB_PORT
if [[ "${STATUS}" -eq 0 ]]; then
  CONFIG_PREPARED=0
fi

cat > "${REPORT_DIR}/${PROJECT}.md" <<EOF
# 隔离系统测试结果

- commit：${COMMIT}
- 源码归档 SHA-256：${SOURCE_SHA}
- 项目：${PROJECT}
- 执行主机：$(hostname)
- Docker Server：${DOCKER_VERSION}
- 测试镜像：${IMAGE_ID}
- 退出状态：${STATUS}
- 详细输出：\`${REPORT}\`
- 系统集成摘要：$(grep -E '^(Ran [0-9]+ tests?|OK$|FAILED)' "${REPORT}" | head -n 1 || true)
- 浏览器系统测试摘要：$(grep -E '^[[:space:]]+[0-9]+ passed' "${REPORT}" | tail -n 1 || true)
- Python 模块摘要：$(grep '^--- scanned=' "${REPORT}" | tail -n 1 || true)；$(grep '^--- test-totals ' "${REPORT}" | tail -n 1 || true)
- 网络：Docker internal network，无公网出口；仅含 MongoDB、Redis、RabbitMQ、API 与固定 HTTP fixture。
- 数据：MongoDB 使用 \`arl_system_test\`；Redis 使用 DB 13；RabbitMQ 使用独立 vhost；容器数据不挂载持久卷。
EOF

echo "[测试结果摘要]"
grep -E '^(Ran [0-9]+ tests?|OK$|FAILED|FAIL:|ERROR:|--- scanned=|--- test-totals )' "${REPORT}" | tail -n 40 || true

if [[ "${STATUS}" -ne 0 ]]; then
  echo "[FAILED] 系统测试失败，摘要：${REPORT_DIR}/${PROJECT}.md" >&2
  exit "${STATUS}"
fi

echo "[PASSED] 隔离系统测试通过，摘要：${REPORT_DIR}/${PROJECT}.md"
