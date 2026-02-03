#!/bin/bash
# ARL Docker 开发构建脚本
# 支持完整构建和快速开发构建
#
# 用法:
#   ./quick-build.sh              # 快速构建（仅代码更新）
#   ./quick-build.sh full         # 完整构建（包括系统包和依赖）
#   ./quick-build.sh clean        # 清空缓存后完整构建
#   ./quick-build.sh tag v1.0     # 构建并标记为 arl:v1.0

set -e

BUILD_MODE="${1:-quick}"
DOCKERFILE_PATH="ARL/docker"
BUILD_CONTEXT="."

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
    echo "ARL Docker 开发构建工具"
    echo -e "${GREEN}========================================${NC}"
    echo "构建模式: $1"
    echo "上下文: $BUILD_CONTEXT"
    echo "Compose: $COMPOSE_CMD"
    echo ""
}

# 快速构建
quick_build() {
    show_build_info "快速构建"
    echo -e "${YELLOW}提示: 只重建代码层，复用系统包缓存${NC}"
    echo ""
    
    if [ "$COMPOSE_CMD" = "docker compose" ]; then
        # 从项目根目录构建，指定 Dockerfile.dev 和上下文
        docker build -f "$DOCKERFILE_PATH/Dockerfile.dev" -t arl:dev .
    else
        cd "$DOCKERFILE_PATH"
        docker-compose build --force-rm arl_web
    fi
    
    echo -e "${GREEN}✓ 快速构建完成!${NC}"
    echo "构建的镜像: arl:dev"
    echo ""
    echo "使用新镜像:"
    echo "  docker tag arl:dev arl:latest"
    echo "  docker compose up -d"
}

# 完整构建
full_build() {
    show_build_info "完整构建 (15-30 分钟)"
    echo -e "${YELLOW}提示: 完整重建所有层，包括系统包和依赖${NC}"
    echo ""
    
    if [ "$COMPOSE_CMD" = "docker compose" ]; then
        docker build -f "$DOCKERFILE_PATH/Dockerfile" -t arl:latest . --no-cache
    else
        cd "$DOCKERFILE_PATH"
        docker-compose build --force-rm --no-cache
    fi
    
    echo -e "${GREEN}✓ 完整构建完成!${NC}"
    echo "构建的镜像: arl:latest"
}

# 清空缓存构建
clean_build() {
    show_build_info "清空缓存完整构建 (20-35 分钟)"
    echo -e "${YELLOW}提示: 删除所有构建缓存，从零开始${NC}"
    echo ""
    
    # 删除 dangling images
    docker builder prune -a -f
    
    if [ "$COMPOSE_CMD" = "docker compose" ]; then
        docker build -f "$DOCKERFILE_PATH/Dockerfile" -t arl:latest . --no-cache
    else
        cd "$DOCKERFILE_PATH"
        docker-compose build --force-rm --no-cache
    fi
    
    echo -e "${GREEN}✓ 清空缓存构建完成!${NC}"
}

# 构建并标记版本
tag_build() {
    local tag="$1"
    if [ -z "$tag" ]; then
        echo -e "${RED}错误: 请指定版本标签 (例: v1.0)${NC}"
        exit 1
    fi
    
    show_build_info "快速构建并标记为 $tag"
    
    if [ "$COMPOSE_CMD" = "docker compose" ]; then
        docker build -f "$DOCKERFILE_PATH/Dockerfile.dev" -t "arl:$tag" .
    else
        docker build -f "$DOCKERFILE_PATH/Dockerfile" -t "arl:$tag" .
    fi
    
    echo -e "${GREEN}✓ 构建完成并标记为 arl:$tag!${NC}"
}

# 显示帮助
show_help() {
    echo "ARL Docker 构建工具"
    echo ""
    echo "用法: ./quick-build.sh [命令] [选项]"
    echo ""
    echo "命令:"
    echo "  quick [默认]      快速构建，仅更新代码（2-5 分钟）"
    echo "  full              完整构建，包括系统包（15-30 分钟）"
    echo "  clean             清空缓存后完整构建（20-35 分钟）"
    echo "  tag <版本>        快速构建并标记版本"
    echo "  help              显示此帮助信息"
    echo ""
    echo "例子:"
    echo "  ./quick-build.sh quick         # 快速构建"
    echo "  ./quick-build.sh full          # 完整构建"
    echo "  ./quick-build.sh tag v1.0.0    # 构建并标记为 v1.0.0"
    echo ""
    echo "构建后更新容器:"
    echo "  docker tag arl:dev arl:latest"
    echo "  docker compose up -d"
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
