#!/bin/bash
set -e

# ARL 系统启动脚本

echo "========================================="
echo "ARL 系统启动脚本"
echo "========================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/ARL/docker"

# 检查docker compose (支持v2和v1)
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
    echo "✓ 使用 Docker Compose v2"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    echo "✓ 使用 Docker Compose v1"
else
    echo "❌ 错误: Docker Compose 未安装"
    exit 1
fi

# 创建必要的目录和Volume
echo "准备环境..."

cd "$DOCKER_DIR"

# 创建MongoDB数据卷
if ! docker volume ls | grep -q arl_db; then
    echo "创建 MongoDB 数据卷 (arl_db)..."
    docker volume create arl_db
else
    echo "✓ MongoDB 数据卷已存在"
fi

# 创建导出目录
if [ ! -d "exports" ]; then
    mkdir -p exports
    echo "✓ 创建导出目录"
fi

# 检查config文件
if [ ! -f "config-docker.yaml" ]; then
    echo "❌ 错误: config-docker.yaml 不存在"
    echo "请从 config-docker.yaml.example 复制并配置"
    exit 1
fi
echo "✓ 配置文件已准备"

# 启动服务
echo ""
echo "启动服务..."
echo ""

# 检查是否需要重新构建镜像
if ! docker images | grep -q "arl.*local"; then
    echo "未找到 arl:local 镜像，开始构建..."
    $COMPOSE_CMD build
elif [ "$1" == "rebuild" ]; then
    echo "开始重新构建镜像..."
    $COMPOSE_CMD build --no-cache
fi

$COMPOSE_CMD up -d

echo ""
echo "========================================="
echo "✓ 服务启动成功"
echo "========================================="
echo ""
echo "访问地址 (通过 Nginx 反向代理 + Basic Auth):"
echo "  Web: http://localhost (或 http://服务器IP)"
echo "  Basic Auth 用户名: admin"
echo "  Basic Auth 密码: admin123456"
echo ""
echo "后端直接访问 (仅本地可访问):"
echo "  HTTPS: https://localhost:5003"
echo ""
echo "快速开发环境（推荐）:"
echo "  使用 ./start.dev.sh 启动开发环境（Dockerfile.dev, 快速构建）"
echo "  修改代码后运行: ./quick-build.sh quick"
echo ""
echo "查看日志:"
echo "  $COMPOSE_CMD logs -f web"
echo "  $COMPOSE_CMD logs -f worker"
echo "  $COMPOSE_CMD logs -f scheduler"
echo ""
echo "停止服务:"
echo "  $COMPOSE_CMD down"
echo ""
echo "重新构建镜像（清除缓存）:"
echo "  ./start.sh rebuild"
echo ""
