#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${ARL_TEST_RUNNER_IMAGE:-arl:local}"
RUST_IMAGE="${ARL_RUST_TEST_RUNNER_IMAGE:-arl:system-test-runner}"
FRONTEND="${ROOT}/ARL/docker/frontend-src"
RUN_ID="$(date -u +%Y%m%d%H%M%S)-$$"
RUST_RESULT_DIR="${ARL_RUST_TEST_RESULT_DIR:-${TMPDIR:-/tmp}/arl-rust-test-${RUN_ID}}"
REPORT_DIR="${ARL_OFFLINE_TEST_REPORT_DIR:-/var/tmp/arl-offline-test-reports}"
REPORT="${REPORT_DIR}/${RUN_ID}.log"
SAFE_CONFIG_DIR="${TMPDIR:-/tmp}/arl-offline-config-${RUN_ID}"
COMMIT="$(head -n 1 "${ROOT}/.arl-system-test-snapshot" 2>/dev/null || true)"
SOURCE_SHA="$(sed -n '2p' "${ROOT}/.arl-system-test-snapshot" 2>/dev/null || true)"
RUST_CARGO_CACHE_DIR="${ARL_RUST_CARGO_CACHE_DIR:-/var/tmp/arl-rust-cargo-${COMMIT:0:8}}"

if [[ ! -f "${ROOT}/.arl-system-test-snapshot" ]]; then
  echo "[ERROR] 仅允许在一次性源码快照中运行；缺少 .arl-system-test-snapshot 标记。" >&2
  exit 2
fi
if [[ ! "${COMMIT}" =~ ^[a-f0-9]{7,40}$ || ! "${SOURCE_SHA}" =~ ^[a-f0-9]{64}$ ]]; then
  echo "[ERROR] 源码快照标记缺少有效 commit 或归档摘要。" >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1 || ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "[ERROR] Python/Rust 离线测试需要预装的隔离运行镜像：${IMAGE}" >&2
  exit 2
fi
if ! docker image inspect "${RUST_IMAGE}" >/dev/null 2>&1; then
  echo "[ERROR] Rust 离线测试需要预装工具链镜像：${RUST_IMAGE}" >&2
  exit 2
fi
if [[ ! -d "${RUST_CARGO_CACHE_DIR}/registry" ]]; then
  echo "[ERROR] Cargo 离线依赖缓存缺失：${RUST_CARGO_CACHE_DIR}/registry；请先用指定代理预取 Cargo.lock 依赖。" >&2
  exit 2
fi
if [[ ! -d "${FRONTEND}/node_modules" ]]; then
  echo "[ERROR] 前端依赖未安装；此离线入口不会访问包仓库安装依赖。" >&2
  exit 2
fi
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "[ERROR] 前端测试需要宿主 Node.js 及 npm；建议使用 Node 24.21.0。" >&2
  exit 2
fi
if ! node -e '
const [major, minor, patch] = process.versions.node.split(".").map(Number);
const supported = (major === 22 && (minor > 22 || (minor === 22 && patch >= 2)))
  || (major === 24 && (minor > 15 || (minor === 15 && patch >= 0)))
  || major >= 26;
if (!supported) process.exit(1);
'; then
  echo "[ERROR] 当前 Node.js 不满足前端依赖 engines；需要 22.22.2+、24.15.0+ 或 26+。" >&2
  exit 2
fi

mkdir -p "${REPORT_DIR}"
mkdir "${SAFE_CONFIG_DIR}"
cp "${ROOT}/ARL/app/config.yaml.example" "${SAFE_CONFIG_DIR}/config.yaml"
chmod 600 "${SAFE_CONFIG_DIR}/config.yaml"
exec > >(tee -a "${REPORT}") 2>&1
echo "report=${REPORT}"
echo "runner_image=${IMAGE}"
echo "rust_runner_image=${RUST_IMAGE}"
echo "snapshot_commit=${COMMIT}"
echo "snapshot_sha256=${SOURCE_SHA}"
trap 'status=$?; echo "offline_test_exit_status=${status}"' EXIT

echo "[1/5] Python 全量测试、隔离组件链路与测试卫生检查。"
ARL_RUN_SYSTEM_UI_E2E=1 bash "${ROOT}/scripts/run-system-tests.sh"

RUST_ARGS=(
  run --pull=never --rm --network none
  --volume "${ROOT}:/workspace:rw"
  --volume "${SAFE_CONFIG_DIR}/config.yaml:/workspace/ARL/app/config.yaml:rw"
  --workdir /workspace/ARL
  --env PYTHONPATH=/workspace/ARL:/workspace
  --env PYTHONDONTWRITEBYTECODE=1
  --env ARL_RUN_LEGACY_NETWORK_TESTS=0
  "${RUST_IMAGE}"
)

echo "[2/5] Rust crate 单测（读取只读 Cargo.lock 缓存，构建网络关闭）。"
mkdir -p "${RUST_RESULT_DIR}"
docker buildx build \
  --platform linux/amd64 \
  --network none \
  --pull=false \
  --build-arg "ARL_TEST_RUNNER_IMAGE=${RUST_IMAGE}" \
  --build-context "cargo_cache=${RUST_CARGO_CACHE_DIR}" \
  --file "${ROOT}/ARL/docker/Dockerfile.rust-test" \
  --output "type=local,dest=${RUST_RESULT_DIR}" \
  --progress plain \
  "${ROOT}/ARL/native/arl_accel"
if [[ ! -s "${RUST_RESULT_DIR}/rust-test-result" ]]; then
  echo "[ERROR] Rust 测试镜像没有导出成功标记。" >&2
  exit 1
fi

echo "[3/5] Rust 原生 smoke 与 Python/Rust 固定 corpus 一致性。"
docker "${RUST_ARGS[@]}" python3 /usr/local/share/arl/arl_accel_smoke_test.py
docker "${RUST_ARGS[@]}" python3 /workspace/ARL/app/tools/compare_rust_python_corpus.py \
  --input /workspace/ARL/test/data/rust_accel_golden_corpus.json --run-native --strict-order
docker "${RUST_ARGS[@]}" python3 /workspace/ARL/app/tools/compare_rust_python_corpus.py \
  --input /workspace/ARL/test/data/api_unified_rust_corpus.json --run-native --strict-order

echo "[4/5] 前端类型检查、Vitest 与 production build。"
(cd "${FRONTEND}" && npm run lint && npm test && npm run build)

echo "[5/5] Playwright 固定 API fixture；浏览器外网请求由用例拦截。"
(cd "${FRONTEND}" && PLAYWRIGHT_BROWSERS_PATH="${ROOT}/.pw-browsers" npm run test:e2e -- --grep-invert '@system')

echo "[PASSED] 离线测试入口完成。Rust 结果标记：${RUST_RESULT_DIR}/rust-test-result"
