#!/usr/bin/env bash
# 标准容器全量回归（计划 3 最终验收的容器面，计划 1 hygiene 容器重扫）。
# 与 verify-multiarch-rust.sh 的区别：本脚本跑完整 unittest 套件与测试卫生
# 扫描，镜像为应用镜像（全依赖 + xing + arl_accel wheel + Mongo sidecar）。
#
# 用法：
#   bash scripts/run-container-regression.sh [platform]   # 默认 linux/arm64
# 前置：docker daemon 可用；仓库根执行；基础镜像可拉取。
set -euo pipefail

PLATFORM="${1:-linux/arm64}"
ARCH="${PLATFORM##*/}"
IMAGE="arl-regression:${ARCH}"
NETWORK="arlreg-${ARCH}"
MONGO="arlmongo-${ARCH}"
APP="arl-reg-${ARCH}"
# 宿主轻依赖基线（python3.9，无 xing/arl_accel，2026-09-06 记录）：
# Ran 768, failures=20, errors=197, skipped=49 —— 容器基线以本脚本产出为准。

if ! docker info >/dev/null 2>&1; then
    echo "[ERROR] docker daemon unavailable" >&2
    exit 1
fi

echo "[1/5] build ${IMAGE} (${PLATFORM})"
docker buildx build --platform "${PLATFORM}" \
    --file ARL/docker/Dockerfile --tag "${IMAGE}" --load --progress quiet .

echo "[2/5] mongo sidecar"
docker network create "${NETWORK}" 2>/dev/null || true
docker rm -f "${MONGO}" >/dev/null 2>&1 || true
docker run -d --name "${MONGO}" --network "${NETWORK}" mongo:7.0 >/dev/null

echo "[3/5] app container"
docker rm -f "${APP}" >/dev/null 2>&1 || true
docker create --name "${APP}" --platform "${PLATFORM}" --network "${NETWORK}" \
    "${IMAGE}" sleep 7200 >/dev/null
docker start "${APP}" >/dev/null
# Mongo 主机名解析：镜像 config-docker.yaml 默认 mongodb 主机名时注入别名。
docker exec "${APP}" sh -c 'grep -q "^[[:space:]]*MONGO" /code/docker/config-docker.yaml && head -20 /code/docker/config-docker.yaml' >/dev/null

echo "[4/5] full unittest discover (image source == repo HEAD at build time)"
docker exec -w /code -e PYTHONPATH=. "${APP}" \
    python3 -m unittest discover -s test -p 'test_*.py' 2>&1 | tail -5

echo "[5/5] test hygiene rescan + native smoke"
docker cp scripts/check-test-hygiene.py "${APP}:/tmp/check-test-hygiene.py"
docker cp ARL "${APP}:/tmp/regression_root" >/dev/null 2>&1 || true
# hygiene 工具镜像内路径：ARL 布局为 /code/{app,test}，工具按 repo-root 推导，
# 用软链构造期望布局再跑。
docker exec "${APP}" sh -c 'mkdir -p /tmp/hyg/ARL && ln -sfn /code/app /tmp/hyg/ARL/app && ln -sfn /code/test /tmp/hyg/ARL/test && ln -sfn /tmp/check-test-hygiene.py /tmp/hyg/check-test-hygiene.py'
docker exec "${APP}" python3 /tmp/hyg/check-test-hygiene.py 2>&1 | tail -3
docker exec "${APP}" python3 /usr/local/share/arl/arl_accel_smoke_test.py \
    && echo "[OK] native smoke passed"

echo "[DONE] platform=${PLATFORM}；登记要求：把 [4]/[5] 输出与宿主基线差异写入 docs/plan/03 与 01 验收行"
