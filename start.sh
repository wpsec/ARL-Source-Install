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

BASIC_AUTH_USER="admin"
BASIC_AUTH_PASS="admin123456"
ARL_APP_USER="admin"
ARL_APP_PASS="arlpass"
ENV_FILE_ROOT="$SCRIPT_DIR/.env"
ENV_FILE_DOCKER="$DOCKER_DIR/.env"
ENV_FILE=""
if [ -f "$ENV_FILE_ROOT" ]; then
    ENV_FILE="$ENV_FILE_ROOT"
elif [ -f "$ENV_FILE_DOCKER" ]; then
    ENV_FILE="$ENV_FILE_DOCKER"
fi

if [ -n "$ENV_FILE" ]; then
    echo "✓ 加载环境变量: $ENV_FILE"
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
    BASIC_AUTH_USER=$(grep -E '^BASIC_AUTH_USERNAME=' "$ENV_FILE" | tail -n1 | cut -d= -f2- | tr -d '\r' || true)
    BASIC_AUTH_PASS=$(grep -E '^BASIC_AUTH_PASSWORD=' "$ENV_FILE" | tail -n1 | cut -d= -f2- | tr -d '\r' || true)
    ARL_APP_USER=$(grep -E '^ARL_APP_USERNAME=' "$ENV_FILE" | tail -n1 | cut -d= -f2- | tr -d '\r' || true)
    ARL_APP_PASS=$(grep -E '^ARL_APP_PASSWORD=' "$ENV_FILE" | tail -n1 | cut -d= -f2- | tr -d '\r' || true)
else
    echo "⚠ 未找到 .env，使用默认账号密码"
fi

[ -z "$BASIC_AUTH_USER" ] && BASIC_AUTH_USER="admin"
[ -z "$BASIC_AUTH_PASS" ] && BASIC_AUTH_PASS="admin123456"
[ -z "$ARL_APP_USER" ] && ARL_APP_USER="admin"
[ -z "$ARL_APP_PASS" ] && ARL_APP_PASS="arlpass"

WORKER_REPLICAS_RAW="${ARL_WORKER_REPLICAS:-2}"
if [ "$WORKER_REPLICAS_RAW" != "1" ] && [ "$WORKER_REPLICAS_RAW" != "2" ]; then
    echo "⚠ ARL_WORKER_REPLICAS=$WORKER_REPLICAS_RAW 无效，回退为 2"
    WORKER_REPLICAS_RAW="2"
fi
WORKER_REPLICAS="$WORKER_REPLICAS_RAW"

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

# 检查配置模板文件
if [ ! -f "config-docker.yaml" ]; then
    echo "❌ 错误: config-docker.yaml 不存在"
    echo "请从 config-docker.yaml.example 复制并配置"
    exit 1
fi

# 运行期配置与模板分离：
# - config-docker.yaml: 版本模板（随代码更新）
# - config-runtime.yaml: 用户实际运行配置（不进 git，避免升级覆盖）
if [ ! -f "config-runtime.yaml" ]; then
    cp "config-docker.yaml" "config-runtime.yaml"
    echo "✓ 首次启动：已从模板创建 config-runtime.yaml"
else
    echo "✓ 检测到 config-runtime.yaml，将复用用户运行配置"
fi
echo "✓ 配置文件已准备"

# 自动检查/补齐 PoC 文库，避免首次部署额外手工步骤
if [ -x "$SCRIPT_DIR/scripts/sync-poc-library.sh" ]; then
    if "$SCRIPT_DIR/scripts/sync-poc-library.sh"; then
        echo "✓ PoC 文库检查完成"
    else
        echo "❌ PoC 文库自动同步失败，请检查 .env 中的 ARL_POC_* 配置"
        exit 1
    fi
else
    echo "⚠ 未找到 PoC 文库同步脚本，跳过自动补齐"
fi

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

UP_SERVICES="nginx web worker_1 scheduler"
if [ "$WORKER_REPLICAS" = "2" ]; then
    UP_SERVICES="$UP_SERVICES worker_2"
fi

echo "✓ 本次部署 worker 副本数: $WORKER_REPLICAS (服务: $UP_SERVICES)"
$COMPOSE_CMD up -d $UP_SERVICES

# 启动后主动同步一次指纹，确保升级后运行中的容器使用最新 tools/finger.json
if [ -x "$SCRIPT_DIR/scripts/sync-fingerprint.sh" ]; then
    mkdir -p "$DOCKER_DIR/logs"
    (
        "$SCRIPT_DIR/scripts/sync-fingerprint.sh"
    ) >"$DOCKER_DIR/logs/fingerprint-sync.log" 2>&1 &
    echo "✓ 指纹同步已后台低优先级执行（延迟启动），日志: $DOCKER_DIR/logs/fingerprint-sync.log"
fi

echo ""
echo "========================================="
echo "✓ 服务启动成功"
echo "========================================="
echo ""
echo "访问地址 (通过 Nginx 反向代理 + Basic Auth):"
echo "  Web: http://localhost (或 http://服务器IP)"
echo "  Basic Auth 用户名: $BASIC_AUTH_USER"
echo "  Basic Auth 密码: $BASIC_AUTH_PASS"
echo ""
echo "ARL 应用登录账号:"
echo "  用户名: $ARL_APP_USER"
echo "  密码: $ARL_APP_PASS"
echo "  注: ARL_APP_* 仅在 Mongo 数据首次初始化时生效"
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
echo "  $COMPOSE_CMD logs -f worker_1"
if [ "$WORKER_REPLICAS" = "2" ]; then
    echo "  $COMPOSE_CMD logs -f worker_2"
fi
echo "  $COMPOSE_CMD logs -f scheduler"
echo ""
echo "停止服务:"
echo "  $COMPOSE_CMD down"
echo ""
echo "重新构建镜像（清除缓存）:"
echo "  ./start.sh rebuild"
echo ""
