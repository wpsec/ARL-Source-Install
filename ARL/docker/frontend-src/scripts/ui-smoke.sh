#!/usr/bin/env bash
# UI 双架构 smoke（计划 4）。设计口径：
# - UI 交付物是静态资源（JS/CSS/HTML），架构无关。双架构证据 = 同一份 dist 在
#   linux/amd64 与 linux/arm64 的 nginx 容器内服务，响应字节一致且资产哈希与
#   本地构建产物一致；默认路径离线可跑，不依赖 npm registry。
# - 浏览器弹窗/键盘行为：playwright 在场则真实 Chromium 验证（本地 dist 登录页
#   + 可选 UI_SMOKE_URL 在线环境的 Modal 链路）；不在场明确 SKIP，不伪造通过。
# - 跨架构“重建产物一致”需要容器内 npm ci（外网），不属默认路径。
#
# 用法（仓库根或任意目录）:
#   bash ARL/docker/frontend-src/scripts/ui-smoke.sh
# 环境开关:
#   UI_SMOKE_PLATFORMS   默认 "linux/amd64 linux/arm64"；置空则跳过容器阶段
#   UI_SMOKE_NGINX_IMAGE 默认 nginx:alpine（本地缺镜像默认 SKIP；PULL_OK=1 允许拉取）
#   UI_SMOKE_URL / UI_SMOKE_MODAL_TRIGGER  在线环境 Modal 验收（授权环境专用）
#   SKIP_BUILD=1  复用现有 dist（跳过 lint/test/build 前置阶段）
#   PULL_OK=1     允许 docker pull 缺失镜像
#   SUMMARY_DIR   证据 JSON 输出目录（默认 frontend-src/reports）
# 退出码: 0=非 SKIP 阶段全过; 1=任一阶段失败。
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORMS="${UI_SMOKE_PLATFORMS-linux/amd64 linux/arm64}"
NGINX_IMAGE="${UI_SMOKE_NGINX_IMAGE:-nginx:alpine}"
SUMMARY_DIR="${SUMMARY_DIR:-$SRC_DIR/reports}"
SKIP_BUILD="${SKIP_BUILD:-0}"
PULL_OK="${PULL_OK:-0}"

DIST_DIR="$SRC_DIR/dist"
SNAPSHOT_DIR="$SRC_DIR/../frontend"
MANIFEST="$SUMMARY_DIR/dist-manifest.txt"
RESULT_FILE="$SUMMARY_DIR/ui-smoke-result.txt"

declare -a PHASES=()
declare -a STATES=()

record() {
    PHASES+=("$1")
    STATES+=("$2")
    printf '[%s] %s\n' "$2" "$1"
}

fail_phase() {
    record "$1" "FAIL"
    printf '%s\n' "${PHASES[@]}" > "$RESULT_FILE"
    exit 1
}

docker_ok() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

hash256() {
    # macOS 有 shasum（BSD），精简 Linux 镜像可能只有 coreutils 的 sha256sum。
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

image_present() {
    [ -n "$(docker images -q "$1" 2>/dev/null)" ]
}

mkdir -p "$SUMMARY_DIR"

# ---------- 阶段 1: 构建链（lint + 单测 + 产物） ----------
if [ "$SKIP_BUILD" = "1" ]; then
    [ -f "$DIST_DIR/index.html" ] || fail_phase "SKIP_BUILD=1 但 dist 不存在"
    record "build(lint+test+dist)" "SKIP"
else
    command -v npm >/dev/null 2>&1 || fail_phase "npm 不可用"
    if [ ! -d "$SRC_DIR/node_modules" ]; then
        (cd "$SRC_DIR" && npm ci --silent) || fail_phase "npm ci 失败（离线环境需预装 node_modules）"
    fi
    (cd "$SRC_DIR" && npm run lint && npm test --silent && npm run build) \
        || fail_phase "lint/test/build 链失败"
    record "build(lint+test+dist)" "PASS"
fi

# ---------- 阶段 2: dist 清单与关键引用自洽 ----------
[ -f "$DIST_DIR/index.html" ] || fail_phase "dist/index.html 缺失"
(
    cd "$DIST_DIR"
    find . -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' \) | sort | while read -r f; do
        if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$f"; else sha256sum "$f"; fi
    done
) > "$MANIFEST" || fail_phase "dist 清单生成失败"

ASSET_REF="$(grep -o '/assets/[^"]*\.js' "$DIST_DIR/index.html" | head -n1 || true)"
[ -n "$ASSET_REF" ] || fail_phase "index.html 未引用入口 JS（构建产物异常）"
ASSET_PATH="$DIST_DIR$ASSET_REF"
[ -f "$ASSET_PATH" ] || fail_phase "index.html 引用的资产不存在: $ASSET_REF"
record "dist manifest + entry-asset 自洽" "PASS"

# ---------- 阶段 2b: 遗留静态入口与源码构建一致 ----------
# 当前生产 Dockerfile 从源码构建；worker/ARMWorker 等兼容入口仍直接复制
# docker/frontend。两套入口必须服务同一份 hash 资产，否则用户会看到旧 UI。
if [ -d "$SNAPSHOT_DIR" ]; then
    if ! diff -rq "$DIST_DIR" "$SNAPSHOT_DIR" >/dev/null; then
        fail_phase "docker/frontend 静态快照与 frontend-src/dist 不一致"
    fi
    record "docker/frontend 静态快照一致性" "PASS"
else
    record "docker/frontend 静态快照一致性" "SKIP(快照目录不存在)"
fi

# ---------- 阶段 3: 双架构容器 serve 一致性 ----------
if [ -z "$PLATFORMS" ]; then
    record "双架构容器 serve" "SKIP(未指定平台)"
elif ! docker_ok; then
    record "双架构容器 serve" "SKIP(docker 不可用)"
else
    SERVE_AVAILABLE=1
    if ! image_present "$NGINX_IMAGE"; then
        if [ "$PULL_OK" = "1" ]; then
            docker pull -q "$NGINX_IMAGE" || SERVE_AVAILABLE=0
        else
            SERVE_AVAILABLE=0
        fi
        if [ "$SERVE_AVAILABLE" = "0" ]; then
            record "双架构容器 serve" "SKIP(本地无 $NGINX_IMAGE 且不可拉取)"
        fi
    fi
    if [ "$SERVE_AVAILABLE" = "1" ]; then
        EXPECTED_INDEX="$SUMMARY_DIR/expected-index.html"
        cp "$DIST_DIR/index.html" "$EXPECTED_INDEX"
        EXPECTED_ASSET_SHA="$(hash256 "$ASSET_PATH")"
        BASE_PORT=18080
        REF_FILE=""
        OK=1
        declare -a CONTAINERS=()
        cleanup() {
            for c in "${CONTAINERS[@]:-}"; do
                [ -n "$c" ] && docker stop "$c" >/dev/null 2>&1 || true
            done
        }
        trap cleanup EXIT
        for platform in $PLATFORMS; do
            suffix="${platform##*/}"
            port=$((BASE_PORT + ${#CONTAINERS[@]}))
            name="arl-ui-smoke-$suffix-$$"
            if ! docker run -d --rm --platform "$platform" --name "$name" \
                -p "$port:80" \
                -v "$DIST_DIR:/usr/share/nginx/html:ro" \
                "$NGINX_IMAGE" >/dev/null 2>&1; then
                OK=0
                printf '[ERROR] %s 容器启动失败\n' "$platform" >&2
                break
            fi
            CONTAINERS+=("$name")
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                curl -sf -o /dev/null "http://127.0.0.1:$port/" && break
                sleep 0.5
            done
            serve_index="$SUMMARY_DIR/index-$suffix.html"
            serve_asset="$SUMMARY_DIR/asset-$suffix.js"
            curl -sf "http://127.0.0.1:$port/" -o "$serve_index" || { OK=0; break; }
            curl -sf "http://127.0.0.1:$port$ASSET_REF" -o "$serve_asset" || { OK=0; break; }
            cmp -s "$serve_index" "$EXPECTED_INDEX" || { OK=0; break; }
            served_sha="$(hash256 "$serve_asset")"
            [ "$served_sha" = "$EXPECTED_ASSET_SHA" ] || { OK=0; break; }
            if [ -z "$REF_FILE" ]; then
                REF_FILE="$serve_index"
            elif ! cmp -s "$REF_FILE" "$serve_index"; then
                OK=0
                break
            fi
        done
        cleanup
        if [ "$OK" = "1" ]; then
            record "双架构容器 serve($PLATFORMS)" "PASS"
        else
            fail_phase "双架构容器 serve 不一致或失败"
        fi
    fi
fi

# ---------- 阶段 4: 浏览器弹窗与键盘行为 ----------
BROWSER_SCRIPT="$SRC_DIR/scripts/ui-smoke-browser.mjs"
if ! command -v node >/dev/null 2>&1; then
    record "浏览器行为(playwright)" "SKIP(node 不可用)"
elif ! (cd "$SRC_DIR" && node --input-type=module -e "await import('playwright')" >/dev/null 2>&1); then
    record "浏览器行为(playwright)" "SKIP(playwright 未安装，不隐式拉包)"
else
    (cd "$SRC_DIR" && node "$BROWSER_SCRIPT")
    code=$?
    case "$code" in
        0) record "浏览器行为(playwright)" "PASS" ;;
        77) record "浏览器行为(playwright)" "SKIP(浏览器二进制缺失)" ;;
        *) fail_phase "浏览器行为验证失败(rc=$code)" ;;
    esac
fi

# ---------- 汇总 ----------
{
    printf '{"ts":"%s","dist_entry":"%s","phases":{\n' "$(date -u +%FT%TZ)" "$ASSET_REF"
    for i in "${!PHASES[@]}"; do
        printf '"%s":"%s"%s\n' "${PHASES[$i]}" "${STATES[$i]}" "$([ "$i" -lt $((${#PHASES[@]} - 1)) ] && echo , )"
    done
    printf '}}\n'
} > "$SUMMARY_DIR/ui-smoke-summary.json"

printf '[INFO] 证据目录: %s\n' "$SUMMARY_DIR"
printf '[INFO] 结果: '
joined=0
for state in "${STATES[@]}"; do
    case "$state" in
        FAIL*) joined=1 ;;
    esac
    printf '%s ' "$state"
done
printf '\n'
exit "$joined"
