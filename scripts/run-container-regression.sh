#!/usr/bin/env bash
# 标准容器全量回归（计划 3 最终验收的容器面，计划 1 hygiene 容器重扫）。
# 与 verify-multiarch-rust.sh 的区别：本脚本跑完整 unittest 套件与测试卫生
# 扫描，镜像为应用镜像（全依赖 + xing + arl_accel wheel），并起 compose 等价
# sidecar（mongo auth + redis + rabbitmq，别名对齐 config-docker.yaml 主机名）。
#
# 用法：
#   bash scripts/run-container-regression.sh [platform] [arch-tag]
#     platform 默认 linux/arm64；arch-tag 用于产物文件名（默认取 platform 尾段）
# 产物：/tmp/arlreg-<tag>-discover.log、/tmp/arlreg-<tag>-hygiene.log
# 前置：docker daemon 可用；仓库根执行；基础镜像可拉取。
# sidecar 凭据仅为仓库模板默认值（config-docker.yaml），非真实生产秘密。
set -euo pipefail

PLATFORM="${1:-linux/arm64}"
ARCH="${PLATFORM##*/}"
TAG="${2:-${ARCH}}"
IMAGE="arl-regression:${TAG}"
NETWORK="arlreg-${TAG}"
MONGO="arlmongo-${TAG}"
REDIS="arlredis-${TAG}"
RABBIT="arlrabbit-${TAG}"
APP="arl-reg-${TAG}"
# 宿主轻依赖基线（python3.9，无 xing/arl_accel，2026-09-06 记录）：
# Ran 768, failures=20, errors=197, skipped=49 —— 容器基线以本脚本产出为准。

if ! docker info >/dev/null 2>&1; then
    echo "[ERROR] docker daemon unavailable" >&2
    exit 1
fi

echo "[1/6] build ${IMAGE} (${PLATFORM})"
docker buildx build --platform "${PLATFORM}" \
    --file ARL/docker/Dockerfile --tag "${IMAGE}" --load --progress quiet .

echo "[2/6] sidecars (mongo auth / redis / rabbitmq，别名=config-docker.yaml 主机名)"
docker network create "${NETWORK}" 2>/dev/null || true
docker rm -f "${MONGO}" "${REDIS}" "${RABBIT}" >/dev/null 2>&1 || true
docker run -d --name "${MONGO}" --network "${NETWORK}" --network-alias mongodb \
    -e MONGO_INITDB_ROOT_USERNAME=admin -e MONGO_INITDB_ROOT_PASSWORD=admin \
    mongo:7.0 >/dev/null
docker run -d --name "${REDIS}" --network "${NETWORK}" --network-alias redis \
    redis:7-alpine >/dev/null
docker run -d --name "${RABBIT}" --network "${NETWORK}" --network-alias rabbitmq \
    -e RABBITMQ_DEFAULT_USER=arl -e RABBITMQ_DEFAULT_PASS=arlpassword \
    -e RABBITMQ_DEFAULT_VHOST=arlv2host rabbitmq:3-management-alpine >/dev/null
# mongo 就绪探测（wire version 握手完成即返回）
for _ in $(seq 1 60); do
    if docker exec "${MONGO}" mongosh --quiet --eval 'db.adminCommand("ping")' \
        -u admin -p admin --authenticationDatabase admin >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

echo "[3/6] app container"
docker rm -f "${APP}" >/dev/null 2>&1 || true
docker create --name "${APP}" --platform "${PLATFORM}" --network "${NETWORK}" \
    "${IMAGE}" sleep 7200 >/dev/null
docker start "${APP}" >/dev/null

echo "[4/6] full unittest discover (image source == repo HEAD at build time)"
docker exec -w /code -e PYTHONPATH=. "${APP}" \
    sh -c 'python3 -m unittest discover -s test -p "test_*.py" > /tmp/discover.log 2>&1; tail -6 /tmp/discover.log'
docker cp "${APP}:/tmp/discover.log" "/tmp/arlreg-${TAG}-discover.log"
grep -cE "^(FAIL|ERROR):" "/tmp/arlreg-${TAG}-discover.log" || true

echo "[5/6] test hygiene rescan + native smoke"
docker cp scripts/check-test-hygiene.py "${APP}:/tmp/check-test-hygiene.py"
# hygiene 工具镜像内路径：ARL 布局为 /code/{app,test}，工具按 repo-root 推导，
# 用软链构造期望布局再跑（全量三态：polluted/clean/load-fail）。
docker exec "${APP}" sh -c 'mkdir -p /tmp/hyg/ARL && ln -sfn /code/app /tmp/hyg/ARL/app && ln -sfn /code/test /tmp/hyg/ARL/test && ln -sfn /tmp/check-test-hygiene.py /tmp/hyg/check-test-hygiene.py'
docker exec "${APP}" python3 /tmp/hyg/check-test-hygiene.py > "/tmp/arlreg-${TAG}-hygiene.log" 2>&1 || true
tail -4 "/tmp/arlreg-${TAG}-hygiene.log"
docker exec "${APP}" python3 /usr/local/share/arl/arl_accel_smoke_test.py \
    && echo "[OK] native smoke passed"
docker exec -w /code -e PYTHONPATH=. "${APP}" \
    python3 app/tools/compare_rust_python_corpus.py --input test/data/rust_accel_golden_corpus.json --run-native --strict-order | tail -3
docker exec -w /code -e PYTHONPATH=. "${APP}" \
    python3 app/tools/compare_rust_python_corpus.py --input test/data/api_unified_rust_corpus.json --run-native --strict-order | tail -3

echo "[6/6] 保留 ${APP}/${MONGO}/${REDIS}/${RABBIT} 供失败复查；下次运行自动重建"
echo "[DONE] platform=${PLATFORM}；产物：/tmp/arlreg-${TAG}-discover.log /tmp/arlreg-${TAG}-hygiene.log"
echo "登记要求：把 [4]/[5] 输出与宿主基线差异写入 docs/plan/03 与 01 验收行"
