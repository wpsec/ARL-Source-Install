#!/bin/bash
# 互联网资产自动化收集系统 Docker 开发构建脚本
# 支持完整构建和快速开发构建
#
# 用法:
#   ./quick-build.sh              # 快速构建（仅代码更新）
#   ./quick-build.sh full         # 完整构建（包括系统包和依赖）
#   ./quick-build.sh clean        # 清空缓存后完整构建
#   ./quick-build.sh frontend     # 更新前端文件到运行中的容器
#   ./quick-build.sh tag v1.0     # 构建并标记为 arl:v1.0

set -e

BUILD_MODE="${1:-quick}"
# 统一使用脚本绝对路径，避免在非项目根目录执行时找不到文件
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

DOCKERFILE_PATH="$ROOT_DIR/ARL/docker"
BUILD_CONTEXT="$ROOT_DIR"
# 与 docker-compose.yml 保持一致的默认镜像标签，避免 latest/local 不一致导致容器未加载新镜像
DEFAULT_IMAGE_TAG="arl:local"

# 前端热更新构建镜像：默认跟随 Dockerfile 首个 node 基础镜像，支持环境变量覆盖
resolve_frontend_node_image() {
    local dockerfile="$DOCKERFILE_PATH/Dockerfile"
    if [ -f "$dockerfile" ]; then
        local image=""
        image="$(awk '/^[[:space:]]*FROM[[:space:]]+node:/ {print $2; exit}' "$dockerfile")"
        if [ -n "$image" ]; then
            echo "$image"
            return 0
        fi
    fi
    echo "node:20.20.1-bookworm"
}

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 主机架构识别（用于 ARM 兼容提示）
HOST_ARCH="$(uname -m 2>/dev/null || echo unknown)"
NORMALIZED_HOST_ARCH="$HOST_ARCH"
case "$NORMALIZED_HOST_ARCH" in
    amd64)
        NORMALIZED_HOST_ARCH="x86_64"
        ;;
    arm64)
        NORMALIZED_HOST_ARCH="aarch64"
        ;;
esac
NON_X86_BUILD=0
if [ "$NORMALIZED_HOST_ARCH" != "x86_64" ]; then
    NON_X86_BUILD=1
fi

# 检测 Docker Compose 版本
detect_compose_version() {
    if docker compose version &>/dev/null 2>&1; then
        echo "docker compose"  # Docker Compose v2
    elif docker-compose --version &>/dev/null 2>&1; then
        echo "docker-compose"  # Docker Compose v1
    else
        echo "error"
    fi
}

COMPOSE_CMD=$(detect_compose_version)

if [ "$COMPOSE_CMD" = "error" ]; then
    echo -e "${RED}错误: 未找到 Docker Compose${NC}"
    exit 1
fi

# 统一加载环境变量（优先项目根 .env，其次 ARL/docker/.env）
load_compose_env() {
    local env_file=""
    if [ -f "$ROOT_DIR/.env" ]; then
        env_file="$ROOT_DIR/.env"
    elif [ -f "$DOCKERFILE_PATH/.env" ]; then
        env_file="$DOCKERFILE_PATH/.env"
    fi

    if [ -n "$env_file" ]; then
        set -a
        # shellcheck disable=SC1090
        . "$env_file"
        set +a
        echo -e "${GREEN}✓ 已加载环境变量: $env_file${NC}"
    else
        echo -e "${YELLOW}[WARN] 未找到 .env，使用 compose 默认值${NC}"
    fi
}

load_compose_env

# 前端 npm 源配置（可在 .env 中覆盖）
# 优先级：ARL_FRONTEND_NPM_REGISTRY > NPM_REGISTRY > 默认 npmmirror
FRONTEND_NPM_REGISTRY="${ARL_FRONTEND_NPM_REGISTRY:-${NPM_REGISTRY:-https://registry.npmmirror.com}}"
FRONTEND_NODE_IMAGE_DEFAULT="$(resolve_frontend_node_image)"
FRONTEND_NODE_IMAGE="${ARL_FRONTEND_BUILD_IMAGE:-$FRONTEND_NODE_IMAGE_DEFAULT}"
# 构建后端配置：有 buildx 时优先使用 buildx（可通过 DOCKER_BUILD_PREFER_BUILDX=0 关闭）
DOCKER_BUILD_PREFER_BUILDX="${DOCKER_BUILD_PREFER_BUILDX:-1}"

detect_build_backend() {
    if [ "$DOCKER_BUILD_PREFER_BUILDX" = "1" ] && docker buildx version >/dev/null 2>&1; then
        echo "buildx"
    else
        echo "classic"
    fi
}

BUILD_BACKEND="$(detect_build_backend)"

# 读取项目版本号（用于前端构建校验与构建日志）
read_project_version() {
    local version_file="$ROOT_DIR/ARL/version.txt"
    if [ ! -f "$version_file" ]; then
        echo "unknown"
        return 0
    fi
    tr -d '\r\n' < "$version_file"
}

# 显示构建模式
show_build_info() {
    local project_version
    project_version="$(read_project_version)"
    local git_commit="unknown"
    if command -v git >/dev/null 2>&1; then
        git_commit="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    fi

    echo -e "${GREEN}========================================${NC}"
    echo "互联网资产自动化收集系统 Docker 开发构建工具"
    echo -e "${GREEN}========================================${NC}"
    echo "构建模式: $1"
    echo "主机架构: $NORMALIZED_HOST_ARCH"
    echo "上下文: $BUILD_CONTEXT"
    echo "Compose: $COMPOSE_CMD"
    echo "Build后端: ${BUILD_BACKEND}"
    echo "NPM镜像: ${FRONTEND_NPM_REGISTRY}"
    echo "前端Node镜像: ${FRONTEND_NODE_IMAGE}"
    echo "项目版本: ${project_version}"
    echo "代码提交: ${git_commit}"
    echo ""

    if [ "$NON_X86_BUILD" -eq 1 ]; then
        echo -e "${YELLOW}[WARN] 检测到非 x86_64 环境，已启用 ARM 兼容模式${NC}"
        echo -e "${YELLOW}[WARN] 构建阶段会跳过 x86_64 专有工具检查(massdns/ncrack)，不会阻塞构建${NC}"
        echo ""
    fi
}

show_arch_runtime_notice() {
    if [ "$NON_X86_BUILD" -ne 1 ]; then
        return
    fi

    echo -e "${YELLOW}[WARN] ARM 兼容模式提示:${NC}"
    echo "  - 已跳过 x86_64 专有组件自检，系统可继续启动"
    echo "  - 涉及 massdns/ncrack 的功能会自动降级并记录告警"
    echo ""
}

sync_fingerprint_after_deploy() {
    local sync_script="$ROOT_DIR/scripts/sync-fingerprint.sh"
    if [ ! -x "$sync_script" ]; then
        echo -e "${YELLOW}[WARN] 未找到可执行的指纹同步脚本，跳过自动同步${NC}"
        return 0
    fi

    local log_dir="$ROOT_DIR/ARL/docker/logs"
    local log_file="$log_dir/fingerprint-sync.log"
    mkdir -p "$log_dir"
    (
        "$sync_script"
    ) >"$log_file" 2>&1 &
    echo -e "${GREEN}✓ 指纹同步已转为后台低优先级执行（延迟启动，日志: $log_file）${NC}"
}

run_docker_build() {
    local dockerfile="$1"
    local image_tag="$2"
    local no_cache="${3:-0}"

    local -a cmd
    if [ "$BUILD_BACKEND" = "buildx" ]; then
        cmd=(
            docker buildx build
            --load
            --pull=false
            -f "$dockerfile"
            -t "$image_tag"
            "$BUILD_CONTEXT"
            --build-arg BUILDKIT_INLINE_CACHE=1
            --build-arg "NPM_REGISTRY=$FRONTEND_NPM_REGISTRY"
        )
    else
        cmd=(
            docker build
            --pull=false
            -f "$dockerfile"
            -t "$image_tag"
            "$BUILD_CONTEXT"
            --build-arg BUILDKIT_INLINE_CACHE=1
            --build-arg "NPM_REGISTRY=$FRONTEND_NPM_REGISTRY"
        )
    fi

    if [ "$no_cache" = "1" ]; then
        cmd+=(--no-cache)
    fi

    "${cmd[@]}"
}

# 检查 tools 目录结构（适配新目录布局）
check_tools_layout() {
    local required_paths=(
        "tools/ncrack/ncrack"
        "tools/ncrack/ncrack-services"
        "tools/nuclei/nuclei-templates"
        "tools/GeoLite2/GeoLite2-ASN.mmdb"
        "tools/GeoLite2/GeoLite2-City.mmdb"
        "tools/wih/main.go"
        "tools/wih/go.mod"
        "tools/wih/config/rules.yml"
        "tools/dhparam.pem"
        "tools/finger.json"
    )

    local missing=()
    local path=""
    for path in "${required_paths[@]}"; do
        if [ ! -e "$ROOT_DIR/$path" ]; then
            missing+=("$path")
        fi
    done

    if ! compgen -G "$ROOT_DIR/tools/nuclei/nuclei_*_linux_amd64.zip" >/dev/null; then
        missing+=("tools/nuclei/nuclei_*_linux_amd64.zip")
    fi
    # Python 源码包（Dockerfile 需要至少一个本地包以通过 COPY）
    if ! compgen -G "$ROOT_DIR/tools/Python-*.tgz" >/dev/null; then
        missing+=("tools/Python-*.tgz")
    fi

    if [ "${#missing[@]}" -gt 0 ]; then
        echo -e "${RED}错误: tools 目录缺少以下必需文件/目录:${NC}"
        printf '  - %s\n' "${missing[@]}"
        echo ""
        echo "请确认你调整后的 tools 目录结构与 Dockerfile 保持一致后再构建。"
        return 1
    fi

    # Playwright 离线包（可选）
    if [ -d "$ROOT_DIR/tools/playwright/ms-playwright" ] || \
       compgen -G "$ROOT_DIR/tools/playwright/ms-playwright*.tar.gz" >/dev/null; then
        echo -e "${GREEN}✓ 检测到 Playwright 离线包，将优先离线安装${NC}"
    else
        echo -e "${YELLOW}[WARN] 未检测到 Playwright 离线包，将尝试在线下载 Chromium${NC}"
    fi
}

# 本地前端热更新：编译 frontend-src/dist，并同步到运行中容器。
# 镜像构建（quick/full/clean/tag）前端由 Dockerfile 多阶段构建完成。
build_frontend_dist_for_hot_update() {
    local src_dir="$ROOT_DIR/ARL/docker/frontend-src"
    local dist_dir="$src_dir/dist"
    local project_version
    project_version="$(read_project_version)"
    local use_local_npm=0

    if [ ! -d "$src_dir" ]; then
        echo -e "${RED}错误: 未找到 frontend-src 源码目录${NC}"
        return 1
    fi

    if command -v npm >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
        local node_major="0"
        node_major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
        if [ "$node_major" -ge 20 ]; then
            use_local_npm=1
        else
            echo -e "${YELLOW}[WARN] 检测到本机 Node 版本过低(node=$(node --version 2>/dev/null || echo unknown))，改用 ${FRONTEND_NODE_IMAGE} 构建${NC}"
        fi
    fi

    if [ "$use_local_npm" -eq 1 ]; then
        echo -e "${YELLOW}构建前端静态文件(frontend-src，本机 npm)...${NC}"
        (
            cd "$src_dir"
            npm config set registry "$FRONTEND_NPM_REGISTRY"
            if ! npm run build; then
                echo -e "${YELLOW}[WARN] 前端构建失败，尝试自动安装依赖后重试...${NC}"
                if [ -f "package-lock.json" ]; then
                    npm ci --no-audit --no-fund
                else
                    npm install --no-audit --no-fund
                fi
                npm run build
            fi
        )
    else
        echo -e "${YELLOW}[WARN] 未使用本机 npm，改用 Docker Node 环境构建 frontend-src...${NC}"
        if ! docker image inspect "$FRONTEND_NODE_IMAGE" >/dev/null 2>&1; then
            echo -e "${YELLOW}[WARN] 未检测到 Node 构建镜像，尝试拉取: $FRONTEND_NODE_IMAGE${NC}"
            docker pull "$FRONTEND_NODE_IMAGE"
        fi
        docker run --rm \
            -v "$src_dir:/workspace" \
            -v "$ROOT_DIR/ARL/version.txt:/version.txt:ro" \
            -e "npm_config_registry=$FRONTEND_NPM_REGISTRY" \
            -w /workspace \
            "$FRONTEND_NODE_IMAGE" \
            sh -lc 'if npm run build; then exit 0; fi; echo "[WARN] build failed, try install deps then rebuild..."; if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi; npm run build'
    fi

    if [ ! -f "$dist_dir/index.html" ] || [ ! -d "$dist_dir/assets" ]; then
        echo -e "${RED}错误: frontend-src 构建结果不完整（缺少 dist/index.html 或 dist/assets）${NC}"
        return 1
    fi

    if [ -n "$project_version" ] && [ "$project_version" != "unknown" ]; then
        if ! LC_ALL=C grep -R -F "$project_version" "$dist_dir/assets" >/dev/null 2>&1; then
            echo -e "${RED}错误: 前端构建产物未包含当前版本 ${project_version}${NC}"
            return 1
        fi
    fi

    return 0
}

# 构建镜像（含离线回退）
# 功能说明：先按常规 quick 方式构建；若因网络/鉴权失败，再尝试把 Dockerfile 中 FROM 镜像替换为本地镜像 ID 构建
build_image_with_offline_fallback() {
    local image_tag="$1"
    local dockerfile="$DOCKERFILE_PATH/Dockerfile"

    # 第一轮：常规快速构建（优先复用本地缓存）
    if run_docker_build "$dockerfile" "$image_tag" "0"; then
        return 0
    fi

    echo -e "${YELLOW}常规构建失败，尝试离线回退模式...${NC}"

    local from_images_text
    from_images_text="$(awk '/^[[:space:]]*FROM[[:space:]]+/ {print $2}' "$dockerfile")"
    if [ -z "$from_images_text" ]; then
        echo -e "${RED}错误: 无法解析 Dockerfile 的基础镜像${NC}"
        return 1
    fi

    local temp_dockerfile
    temp_dockerfile=$(mktemp)
    cp "$dockerfile" "$temp_dockerfile"

    local image=""
    local image_id=""
    local processed_images=""
    while IFS= read -r image; do
        [ -z "$image" ] && continue
        case " $processed_images " in
            *" $image "*) continue ;;
        esac
        processed_images="$processed_images $image"

        if ! docker image inspect "$image" >/dev/null 2>&1; then
            echo -e "${RED}错误: 本地不存在基础镜像 $image${NC}"
            echo "请先执行: docker pull $image"
            rm -f "$temp_dockerfile"
            return 1
        fi

        image_id=$(docker image inspect "$image" --format '{{.Id}}')
        if [ -z "$image_id" ]; then
            echo -e "${RED}错误: 无法获取本地镜像ID $image${NC}"
            rm -f "$temp_dockerfile"
            return 1
        fi

        # 仅替换 FROM 行中的镜像名称，保留 AS 别名
        perl -i -pe 's{^(\s*FROM\s+)\Q'"$image"'\E(\s|$)}{$1'"$image_id"'$2}i' "$temp_dockerfile"
    done <<EOF
$from_images_text
EOF

    echo -e "${YELLOW}离线回退: 使用本地基础镜像 ID 构建${NC}"
    if ! DOCKER_BUILDKIT=0 docker build --pull=false -f "$temp_dockerfile" -t "$image_tag" "$BUILD_CONTEXT" --build-arg BUILDKIT_INLINE_CACHE=1 --build-arg "NPM_REGISTRY=$FRONTEND_NPM_REGISTRY"; then
        rm -f "$temp_dockerfile"
        return 1
    fi

    rm -f "$temp_dockerfile"
    return 0
}

# 快速构建
# 功能说明：快速重建代码层，复用系统包缓存，构建统一镜像标签并强制重建容器
quick_build() {
    show_build_info "快速构建"
    echo -e "${YELLOW}提示: 只重建代码层，复用系统包缓存，前端由 Dockerfile 多阶段构建${NC}"
    echo ""
    check_tools_layout
    
    # 统一使用 docker build 生成镜像，避免 docker-compose(v1) 旧服务名导致构建失败
    build_image_with_offline_fallback "${DEFAULT_IMAGE_TAG}"
    
    echo -e "${GREEN}✓ 快速构建完成!${NC}"
    echo "构建的镜像: ${DEFAULT_IMAGE_TAG}"
    echo ""
    
    # 检查docker-compose.yml位置
    if [ ! -f "$DOCKERFILE_PATH/docker-compose.yml" ]; then
        echo -e "${RED}错误: 未找到docker-compose.yml${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}正在重启容器以使用新镜像...${NC}"
    cd "$DOCKERFILE_PATH"
    # 强制重建容器，确保使用刚构建的新镜像；
    # 同时重建 nginx，避免其继续使用旧的 arl_web 上游 IP 导致 502
    $COMPOSE_CMD up -d --force-recreate nginx web worker scheduler
    sync_fingerprint_after_deploy
    echo -e "${GREEN}✓ 容器重启完成!${NC}"
    echo ""
    show_arch_runtime_notice
    echo "构建和部署已完成，请在浏览器中强制刷新(Ctrl+Shift+R)查看效果"
}

# 完整构建
full_build() {
    show_build_info "完整构建 (15-30 分钟)"
    echo -e "${YELLOW}提示: 完整重建所有层（包含前端源码编译）${NC}"
    echo ""
    check_tools_layout
    
    run_docker_build "$DOCKERFILE_PATH/Dockerfile" "${DEFAULT_IMAGE_TAG}" "1"
    
    echo -e "${GREEN}✓ 完整构建完成!${NC}"
    echo "构建的镜像: ${DEFAULT_IMAGE_TAG}"
    echo ""
    show_arch_runtime_notice
}

# 清空缓存构建
clean_build() {
    show_build_info "清空缓存完整构建 (20-35 分钟)"
    echo -e "${YELLOW}提示: 删除所有构建缓存，从零开始（包含前端构建缓存）${NC}"
    echo ""
    check_tools_layout
    
    # 删除 dangling images
    docker builder prune -a -f
    
    run_docker_build "$DOCKERFILE_PATH/Dockerfile" "${DEFAULT_IMAGE_TAG}" "1"
    
    echo -e "${GREEN}✓ 清空缓存构建完成!${NC}"
    echo ""
    show_arch_runtime_notice
}

# 前端文件更新
frontend_update() {
    show_build_info "前端文件更新"
    echo -e "${YELLOW}提示: 构建 frontend-src/dist 并同步到运行中的容器${NC}"
    echo ""
    
    # 检查容器是否运行
    if ! docker ps --format 'table {{.Names}}' | grep -q "^arl_web$"; then
        echo -e "${RED}错误: arl_web 容器未运行${NC}"
        echo "请先启动容器: docker compose up -d"
        exit 1
    fi

    build_frontend_dist_for_hot_update
    
    echo "正在更新前端文件..."

    echo "初始化前端目录..."
    docker exec arl_web sh -c 'rm -rf /code/frontend/* && mkdir -p /code/frontend'
    echo "复制 dist 到容器..."
    docker cp "$ROOT_DIR/ARL/docker/frontend-src/dist/." arl_web:/code/frontend/
    
    # 重载 nginx
    echo "重载 nginx..."
    docker exec arl_web nginx -s reload
    
    echo -e "${GREEN}✓ 前端文件更新完成!${NC}"
    echo ""
    echo "请刷新浏览器查看更改效果"
}

# 标记版本
# 功能说明：基于最新代码快速构建，然后为镜像添加版本标签
tag_build() {
    if [ -z "$1" ]; then
        echo -e "${RED}错误: 未指定版本号${NC}"
        echo "用法: ./quick-build.sh tag <版本号>"
        echo "例子: ./quick-build.sh tag v1.0.0"
        return 1
    fi
    
    VERSION="$1"
    show_build_info "标记版本构建"
    echo -e "${YELLOW}提示: 快速构建后将 ${DEFAULT_IMAGE_TAG} 标记为 arl:$VERSION${NC}"
    echo ""
    check_tools_layout
    
    # tag 模式复用 quick 的离线回退逻辑，降低网络不稳定导致的失败
    build_image_with_offline_fallback "${DEFAULT_IMAGE_TAG}"
    
    # 添加版本标签
    echo -e "${YELLOW}正在标记镜像为 arl:$VERSION...${NC}"
    docker tag "${DEFAULT_IMAGE_TAG}" "arl:$VERSION"
    echo -e "${GREEN}✓ 版本标记完成!${NC}"
    echo ""
    echo "可用镜像:"
    echo "  - ${DEFAULT_IMAGE_TAG} (开发默认标签)"
    echo "  - arl:$VERSION (版本标签)"
    echo ""
    show_arch_runtime_notice
}

# 显示帮助
show_help() {
    echo "互联网资产自动化收集系统 Docker 构建工具"
    echo ""
    echo "用法: ./quick-build.sh [命令] [选项]"
    echo ""
    echo "命令:"
    echo "  quick [默认]      快速构建，更新代码并自动重启容器（2-5 分钟）"
    echo "  full              完整构建，包括系统包（15-30 分钟）"
    echo "  clean             清空缓存后完整构建（20-35 分钟）"
    echo "  frontend          更新前端文件到运行中的容器（即时生效）"
    echo "  tag <版本>        快速构建并标记版本"
    echo "  help              显示此帮助信息"
    echo ""
    echo "例子:"
    echo "  ./quick-build.sh quick         # 快速构建（推荐开发使用）"
    echo "  ./quick-build.sh full          # 完整构建"
    echo "  ./quick-build.sh frontend      # 更新前端文件"
    echo "  ./quick-build.sh tag v1.0.0    # 构建并标记为 v1.0.0"
    echo ""
    echo "说明:"
    echo "  - quick命令执行完成后，容器会自动重启并加载新镜像"
    echo "  - 快速构建会复用之前的系统包缓存，速度更快"
    echo "  - frontend命令只更新前端文件，无需重新构建Docker镜像"
}

# 主程序
case "$BUILD_MODE" in
    quick)
        quick_build
        ;;
    full)
        full_build
        ;;
    clean)
        clean_build
        ;;
    frontend)
        frontend_update
        ;;
    tag)
        tag_build "$2"
        ;;
    help)
        show_help
        ;;
    *)
        echo -e "${RED}错误: 未知的构建模式 '$BUILD_MODE'${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}构建脚本执行完成!${NC}"
