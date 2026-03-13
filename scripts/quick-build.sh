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

# 检查 tools 目录结构（适配新目录布局）
check_tools_layout() {
    local required_paths=(
        "tools/ncrack/ncrack"
        "tools/ncrack/ncrack-services"
        "tools/nuclei/nuclei-templates"
        "tools/GeoLite2/GeoLite2-ASN.mmdb"
        "tools/GeoLite2/GeoLite2-City.mmdb"
        "tools/wih/wih_linux_amd64"
        "tools/wih/wih_linux_arm64"
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

# 预构建前端静态文件（frontend-src -> ARL/docker/frontend）
# 说明：
# - quick/full/clean/tag 构建前都应调用，避免镜像继续打包旧前端资源
# - 不再回退使用仓库预构建静态文件，必须基于当前源码编译
build_frontend_with_local_npm() {
    local src_dir="$1"
    (
        cd "$src_dir"
        if npm run build; then
            return 0
        fi
        echo -e "${YELLOW}[WARN] 前端构建失败，尝试自动安装依赖后重试...${NC}"
        if [ -f "package-lock.json" ]; then
            npm ci --no-audit --no-fund
        else
            npm install --no-audit --no-fund
        fi
        npm run build
    )
}

build_frontend_with_docker_node() {
    local src_dir="$1"
    local node_image="${ARL_FRONTEND_BUILD_IMAGE:-node:20-alpine}"

    if ! docker image inspect "$node_image" >/dev/null 2>&1; then
        echo -e "${YELLOW}[WARN] 未检测到 Node 构建镜像，尝试拉取: $node_image${NC}"
        docker pull "$node_image"
    fi

    docker run --rm \
        -v "$src_dir:/workspace" \
        -w /workspace \
        "$node_image" \
        sh -lc 'if npm run build; then exit 0; fi; echo "[WARN] build failed, try install deps then rebuild..."; if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi; npm run build'
}

validate_frontend_dist_version() {
    local dist_assets_dir="$1"
    local expected_version="$2"
    if [ -z "$expected_version" ] || [ "$expected_version" = "unknown" ]; then
        echo -e "${YELLOW}[WARN] 未读取到 ARL/version.txt，跳过前端版本校验${NC}"
        return 0
    fi

    if LC_ALL=C grep -R -F "$expected_version" "$dist_assets_dir" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ 前端构建版本校验通过: ${expected_version}${NC}"
        return 0
    fi

    echo -e "${RED}错误: 前端构建产物未包含当前版本 ${expected_version}，疑似仍在使用旧代码${NC}"
    return 1
}

prepare_frontend_static() {
    local src_dir="$ROOT_DIR/ARL/docker/frontend-src"
    local dist_dir="$src_dir/dist"
    local static_dir="$ROOT_DIR/ARL/docker/frontend"
    local project_version
    project_version="$(read_project_version)"

    if [ ! -d "$src_dir" ]; then
        echo -e "${YELLOW}[WARN] 未找到 frontend-src，跳过前端构建${NC}"
        return 0
    fi

    if command -v npm >/dev/null 2>&1; then
        echo -e "${YELLOW}构建前端静态文件(frontend-src，本机 npm)...${NC}"
        build_frontend_with_local_npm "$src_dir"
    else
        echo -e "${YELLOW}[WARN] 未检测到 npm，改用 Docker Node 环境构建 frontend-src...${NC}"
        build_frontend_with_docker_node "$src_dir"
    fi

    if [ ! -f "$dist_dir/index.html" ] || [ ! -d "$dist_dir/assets" ]; then
        echo -e "${RED}错误: frontend-src 构建结果不完整（缺少 dist/index.html 或 dist/assets）${NC}"
        return 1
    fi

    validate_frontend_dist_version "$dist_dir/assets" "$project_version"

    # 清理旧静态资源，避免历史 hash 文件残留导致引用错乱
    rm -rf "$static_dir"
    mkdir -p "$static_dir"
    cp -a "$dist_dir/." "$static_dir/"
    echo -e "${GREEN}✓ 前端静态文件已同步到 ARL/docker/frontend${NC}"
    return 0
}

# 构建镜像（含离线回退）
# 功能说明：先按常规 quick 方式构建；若因网络/鉴权失败，再尝试使用本地基础镜像 ID 构建
build_image_with_offline_fallback() {
    local image_tag="$1"
    local dockerfile="$DOCKERFILE_PATH/Dockerfile"

    # 第一轮：常规快速构建（优先复用本地缓存）
    if docker build --pull=false -f "$dockerfile" -t "$image_tag" "$BUILD_CONTEXT" --build-arg BUILDKIT_INLINE_CACHE=1; then
        return 0
    fi

    echo -e "${YELLOW}常规构建失败，尝试离线回退模式...${NC}"

    local base_image
    base_image=$(awk '/^[[:space:]]*FROM[[:space:]]+/ {print $2; exit}' "$dockerfile")
    if [ -z "$base_image" ]; then
        echo -e "${RED}错误: 无法解析 Dockerfile 的基础镜像${NC}"
        return 1
    fi

    if ! docker image inspect "$base_image" >/dev/null 2>&1; then
        echo -e "${RED}错误: 本地不存在基础镜像 $base_image${NC}"
        echo "请先执行: docker pull $base_image"
        return 1
    fi

    local base_image_id
    base_image_id=$(docker image inspect "$base_image" --format '{{.Id}}')
    local temp_dockerfile
    temp_dockerfile=$(mktemp)

    # 用本地镜像 ID 替换第一条 FROM，尽量避免访问 Docker Hub 鉴权服务
    awk -v base="$base_image_id" '
      BEGIN { done=0 }
      {
        if (!done && $1=="FROM") {
          sub(/^FROM[[:space:]]+[^[:space:]]+/, "FROM " base)
          done=1
        }
        print
      }
    ' "$dockerfile" > "$temp_dockerfile"

    echo -e "${YELLOW}离线回退: 使用本地基础镜像 $base_image_id${NC}"
    if ! DOCKER_BUILDKIT=0 docker build --pull=false -f "$temp_dockerfile" -t "$image_tag" "$BUILD_CONTEXT" --build-arg BUILDKIT_INLINE_CACHE=1; then
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
    echo -e "${YELLOW}提示: 只重建代码层，复用系统包缓存，直接更新${DEFAULT_IMAGE_TAG}镜像${NC}"
    echo ""
    check_tools_layout
    prepare_frontend_static
    
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
    echo -e "${GREEN}✓ 容器重启完成!${NC}"
    echo ""
    show_arch_runtime_notice
    echo "构建和部署已完成，请在浏览器中强制刷新(Ctrl+Shift+R)查看效果"
}

# 完整构建
full_build() {
    show_build_info "完整构建 (15-30 分钟)"
    echo -e "${YELLOW}提示: 完整重建所有层，包括系统包和依赖${NC}"
    echo ""
    check_tools_layout
    prepare_frontend_static
    
    docker build -f "$DOCKERFILE_PATH/Dockerfile" -t "${DEFAULT_IMAGE_TAG}" "$BUILD_CONTEXT" --no-cache
    
    echo -e "${GREEN}✓ 完整构建完成!${NC}"
    echo "构建的镜像: ${DEFAULT_IMAGE_TAG}"
    echo ""
    show_arch_runtime_notice
}

# 清空缓存构建
clean_build() {
    show_build_info "清空缓存完整构建 (20-35 分钟)"
    echo -e "${YELLOW}提示: 删除所有构建缓存，从零开始${NC}"
    echo ""
    check_tools_layout
    prepare_frontend_static
    
    # 删除 dangling images
    docker builder prune -a -f
    
    docker build -f "$DOCKERFILE_PATH/Dockerfile" -t "${DEFAULT_IMAGE_TAG}" "$BUILD_CONTEXT" --no-cache
    
    echo -e "${GREEN}✓ 清空缓存构建完成!${NC}"
    echo ""
    show_arch_runtime_notice
}

# 前端文件更新
frontend_update() {
    show_build_info "前端文件更新"
    echo -e "${YELLOW}提示: 自动构建 frontend-src 并同步静态文件到运行中的容器${NC}"
    echo ""
    
    # 检查容器是否运行
    if ! docker ps --format 'table {{.Names}}' | grep -q "^arl_web$"; then
        echo -e "${RED}错误: arl_web 容器未运行${NC}"
        echo "请先启动容器: docker compose up -d"
        exit 1
    fi

    prepare_frontend_static
    
    echo "正在更新前端文件..."

    echo "初始化前端目录..."
    docker exec arl_web mkdir -p /code/frontend/js /code/frontend/css /code/frontend/assets
    # 避免旧 hash 资源残留导致页面仍引用旧文件
    docker exec arl_web sh -c 'rm -rf /code/frontend/assets/* /code/frontend/js/* /code/frontend/css/*'
    
    # 复制前端文件到容器
    echo "复制 JS 文件..."
    docker cp "ARL/docker/frontend/js/." arl_web:/code/frontend/js/ 2>/dev/null || true
    
    echo "复制 CSS 文件..."
    docker cp "ARL/docker/frontend/css/." arl_web:/code/frontend/css/ 2>/dev/null || true

    echo "复制 Assets 文件..."
    docker cp "ARL/docker/frontend/assets/." arl_web:/code/frontend/assets/ 2>/dev/null || true
    
    echo "复制 HTML 文件..."
    docker cp "ARL/docker/frontend/index.html" arl_web:/code/frontend/ 2>/dev/null || true
    
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
    prepare_frontend_static
    
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
