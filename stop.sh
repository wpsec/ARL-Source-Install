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

# 与 start.sh 对称：compose v1 会对 nginx 的 ${BASIC_AUTH_PASSWORD:?} 强制插值，
# 未加载 .env 时 down 直接报错；根目录优先、ARL/docker 回退。
ENV_FILE_ROOT="$SCRIPT_DIR/.env"
ENV_FILE_DOCKER="$DOCKER_DIR/.env"
ENV_FILE=""
if [ -f "$ENV_FILE_ROOT" ]; then
    ENV_FILE="$ENV_FILE_ROOT"
elif [ -f "$ENV_FILE_DOCKER" ]; then
    ENV_FILE="$ENV_FILE_DOCKER"
fi
if [ -n "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
fi

echo "正在停止并移除 ARL 相关容器（保留数据卷）..."
$COMPOSE_CMD down --remove-orphans

echo ""
echo "========================================="
echo "ARL 系统已停止"
echo "========================================="
echo "提示: 数据卷未删除，可通过 ./start.sh 快速恢复启动。"
