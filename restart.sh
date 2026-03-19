#!/bin/bash
set -e

echo "========================================="
echo "ARL 系统重启脚本 (用于应用热更新配置)"
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

cd "$DOCKER_DIR"

# 可以接收可选的服务参数，如 ./restart.sh web (只重启web)
if [ $# -eq 0 ]; then
    echo "正在完整重启所有容器..."
    $COMPOSE_CMD restart
else
    echo "正在重启指定容器: $@"
    $COMPOSE_CMD restart "$@"
fi

echo ""
echo "========================================="
echo "✓ 重启指令执行完毕"
echo "========================================="
echo "查看日志:"
echo "  $COMPOSE_CMD logs -f web"
echo "  $COMPOSE_CMD logs -f worker"
echo "  $COMPOSE_CMD logs -f scheduler"
echo ""
