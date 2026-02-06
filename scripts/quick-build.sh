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
DOCKERFILE_PATH="ARL/docker"
BUILD_CONTEXT="."
# 与 docker-compose.yml 保持一致的默认镜像标签，避免 latest/local 不一致导致容器未加载新镜像
DEFAULT_IMAGE_TAG="arl:local"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# 显示构建模式
show_build_info() {
    echo -e "${GREEN}========================================${NC}"
    echo "互联网资产自动化收集系统 Docker 开发构建工具"
    echo -e "${GREEN}========================================${NC}"
    echo "构建模式: $1"
    echo "上下文: $BUILD_CONTEXT"
    echo "Compose: $COMPOSE_CMD"
    echo ""
}

# 快速构建
# 功能说明：快速重建代码层，复用系统包缓存，构建统一镜像标签并强制重建容器
quick_build() {
    show_build_info "快速构建"
    echo -e "${YELLOW}提示: 只重建代码层，复用系统包缓存，直接更新${DEFAULT_IMAGE_TAG}镜像${NC}"
    echo ""
    
    if [ "$COMPOSE_CMD" = "docker compose" ]; then
        # 从项目根目录直接构建统一镜像标签
        docker build -f "$DOCKERFILE_PATH/Dockerfile" -t "${DEFAULT_IMAGE_TAG}" . --build-arg BUILDKIT_INLINE_CACHE=1
    else
        cd "$DOCKERFILE_PATH"
        docker-compose build --force-rm arl_web
    fi
    
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
    echo "构建和部署已完成，请在浏览器中强制刷新(Ctrl+Shift+R)查看效果"
}

# 完整构建
full_build() {
    show_build_info "完整构建 (15-30 分钟)"
    echo -e "${YELLOW}提示: 完整重建所有层，包括系统包和依赖${NC}"
    echo ""
    
    if [ "$COMPOSE_CMD" = "docker compose" ]; then
        docker build -f "$DOCKERFILE_PATH/Dockerfile" -t "${DEFAULT_IMAGE_TAG}" . --no-cache
    else
        cd "$DOCKERFILE_PATH"
        docker-compose build --force-rm --no-cache
    fi
    
    echo -e "${GREEN}✓ 完整构建完成!${NC}"
    echo "构建的镜像: ${DEFAULT_IMAGE_TAG}"
}

# 清空缓存构建
clean_build() {
    show_build_info "清空缓存完整构建 (20-35 分钟)"
    echo -e "${YELLOW}提示: 删除所有构建缓存，从零开始${NC}"
    echo ""
    
    # 删除 dangling images
    docker builder prune -a -f
    
    if [ "$COMPOSE_CMD" = "docker compose" ]; then
        docker build -f "$DOCKERFILE_PATH/Dockerfile" -t "${DEFAULT_IMAGE_TAG}" . --no-cache
    else
        cd "$DOCKERFILE_PATH"
        docker-compose build --force-rm --no-cache
    fi
    
    echo -e "${GREEN}✓ 清空缓存构建完成!${NC}"
}

# 前端文件更新
frontend_update() {
    show_build_info "前端文件更新"
    echo -e "${YELLOW}提示: 只更新前端文件到运行中的容器${NC}"
    echo ""
    
    # 检查容器是否运行
    if ! docker ps --format 'table {{.Names}}' | grep -q "^arl_web$"; then
        echo -e "${RED}错误: arl_web 容器未运行${NC}"
        echo "请先启动容器: docker compose up -d"
        exit 1
    fi
    
    echo "正在更新前端文件..."
    
    # 复制前端文件到容器
    echo "复制 JS 文件..."
    docker cp "ARL/docker/frontend/js/." arl_web:/code/frontend/js/ 2>/dev/null || true
    
    echo "复制 CSS 文件..."
    docker cp "ARL/docker/frontend/css/." arl_web:/code/frontend/css/ 2>/dev/null || true
    
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
    
    # 执行快速构建
    if [ "$COMPOSE_CMD" = "docker compose" ]; then
        docker build -f "$DOCKERFILE_PATH/Dockerfile" -t "${DEFAULT_IMAGE_TAG}" . --build-arg BUILDKIT_INLINE_CACHE=1
    else
        cd "$DOCKERFILE_PATH"
        docker-compose build --force-rm arl_web
    fi
    
    # 添加版本标签
    echo -e "${YELLOW}正在标记镜像为 arl:$VERSION...${NC}"
    docker tag "${DEFAULT_IMAGE_TAG}" "arl:$VERSION"
    echo -e "${GREEN}✓ 版本标记完成!${NC}"
    echo ""
    echo "可用镜像:"
    echo "  - ${DEFAULT_IMAGE_TAG} (开发默认标签)"
    echo "  - arl:$VERSION (版本标签)"
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
