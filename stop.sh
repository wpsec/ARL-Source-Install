#!/bin/bash
set -e

echo "========================================="
echo "ARL 系统停止脚本"
echo "========================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/ARL/docker"

if [ ! -d "$DOCKER_DIR" ]; then
    echo "错误: 未找到目录 $DOCKER_DIR"
    exit 1
fi

if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
    echo "使用 Docker Compose v2"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    echo "使用 Docker Compose v1"
else
    echo "错误: Docker Compose 未安装"
    exit 1
fi

cd "$DOCKER_DIR"

if [ ! -f "docker-compose.yml" ]; then
    echo "错误: 未找到 docker-compose.yml"
    exit 1
fi

echo "正在停止并移除 ARL 相关容器（保留数据卷）..."
$COMPOSE_CMD down --remove-orphans

echo ""
echo "========================================="
echo "ARL 系统已停止"
echo "========================================="
echo "提示: 数据卷未删除，可通过 ./start.sh 快速恢复启动。"
