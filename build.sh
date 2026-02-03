#!/bin/bash
set -e

# ARL Docker 镜像构建脚本

echo "========================================="
echo "ARL 本地镜像构建脚本"
echo "========================================="
echo ""

# 检查Docker是否安装
if ! command -v docker &> /dev/null; then
    echo " 错误: Docker未安装"
    exit 1
fi
echo "✓ Docker 已安装"

# 检查docker compose是否可用 (支持v2和v1)
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
    echo "✓ Docker Compose v2 可用"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    echo "✓ Docker Compose v1 可用"
else
    echo " 错误: Docker Compose 未安装"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"  # 脚本所在目录就是项目根目录
DOCKER_DIR="$PROJECT_ROOT/ARL/docker"

echo "✓ 项目目录: $PROJECT_ROOT"
echo "✓ Docker目录: $DOCKER_DIR"
echo ""

# 检查必要的文件和目录
echo "检查必要的文件和目录..."

if [ ! -f "$PROJECT_ROOT/ARL/docker/Dockerfile" ]; then
    echo " 错误: Dockerfile 不存在于 $PROJECT_ROOT/ARL/docker/"
    exit 1
fi
echo "✓ Dockerfile 存在"

if [ ! -d "$PROJECT_ROOT/ARL/app" ]; then
    echo " 错误: ARL/app 目录不存在"
    exit 1
fi
echo "✓ ARL源码目录存在"

if [ ! -d "$PROJECT_ROOT/tools" ]; then
    echo " 错误: tools 目录不存在"
    exit 1
fi
echo "✓ tools 工具目录存在"

# 检查离线工具文件
echo ""
echo "检查离线工具文件..."

REQUIRED_TOOLS=(
    "tools/GeoLite2-ASN.mmdb"
    "tools/GeoLite2-City.mmdb"
    "tools/ncrack"
    "tools/ncrack-services"
    "tools/dhparam.pem"
    "tools/wih_linux_amd64"
)

for tool in "${REQUIRED_TOOLS[@]}"; do
    if [ ! -f "$PROJECT_ROOT/$tool" ]; then
        echo "⚠ 警告: 未找到 $tool (但可以继续，某些功能可能不可用)"
    else
        echo "✓ $(basename $tool) 存在"
    fi
done

# 询问是否构建
echo ""
echo "准备构建镜像..."
echo "镜像名称: arl:local"
echo "基础镜像: Rocky Linux 8"
echo "使用: $COMPOSE_CMD"
read -p "是否继续? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "取消构建"
    exit 0
fi

# 开始构建
echo ""
echo "开始构建Docker镜像..."
echo "这可能需要几分钟，请耐心等待..."
echo ""

cd "$PROJECT_ROOT"

# 构建镜像
docker build \
    -t arl:local \
    -f "$DOCKER_DIR/Dockerfile" \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    .

BUILD_RESULT=$?

echo ""
if [ $BUILD_RESULT -eq 0 ]; then
    echo "========================================="
    echo "✓ 镜像构建成功!"
    echo "========================================="
    echo ""
    echo "镜像信息:"
    docker images arl:local
else
    echo "========================================="
    echo " 镜像构建失败"
    echo "========================================="
    exit 1
fi
