#!/bin/bash
set -e

echo "========================================="
echo "ARL 系统重启脚本 (用于应用热更新配置)"
echo "========================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/ARL/docker"
ENV_FILE_ROOT="$SCRIPT_DIR/.env"
ENV_FILE_DOCKER="$DOCKER_DIR/.env"
ENV_FILE=""

sync_runtime_config_from_template() {
    local sync_script="$SCRIPT_DIR/ARL/app/tools/sync_runtime_config.py"
    local template_file="$DOCKER_DIR/config-docker.yaml"
    local runtime_file="$DOCKER_DIR/config-runtime.yaml"

    if [ ! -f "$sync_script" ]; then
        echo "⚠ 未找到配置同步脚本，跳过运行配置补齐"
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo "⚠ 未找到 python3，跳过运行配置补齐"
        return 0
    fi
    if ! python3 "$sync_script" --template "$template_file" --runtime "$runtime_file" --quiet; then
        echo "❌ 运行配置补齐失败，请先修复配置文件后重试"
        return 1
    fi

    echo "✓ 运行配置已完成缺失项补齐（保留用户现有值）"
    return 0
}

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

WORKER_REPLICAS_RAW="${ARL_WORKER_REPLICAS:-2}"
if [ "$WORKER_REPLICAS_RAW" != "1" ] && [ "$WORKER_REPLICAS_RAW" != "2" ]; then
    WORKER_REPLICAS_RAW="2"
fi
WORKER_REPLICAS="$WORKER_REPLICAS_RAW"

cd "$DOCKER_DIR"

# 与 start.sh 保持一致：确保运行期配置文件存在，避免升级后 compose 重建时报错
if [ ! -f "config-docker.yaml" ]; then
    echo "❌ 错误: config-docker.yaml 不存在"
    exit 1
fi

if [ ! -f "config-runtime.yaml" ]; then
    cp "config-docker.yaml" "config-runtime.yaml"
    echo "✓ 已自动创建 config-runtime.yaml（由模板复制）"
fi
sync_runtime_config_from_template

map_service_alias() {
    local service_name="$1"
    case "$service_name" in
        worker)
            echo "worker_1"
            ;;
        *)
            echo "$service_name"
            ;;
    esac
}

# 可以接收可选的服务参数，如 ./restart.sh web (只重启web)
if [ $# -eq 0 ]; then
    running_services="$($COMPOSE_CMD ps --services --status running | tr '\n' ' ' | xargs || true)"
    if [ -z "$running_services" ]; then
        running_services="nginx web worker_1 scheduler"
        if [ "$WORKER_REPLICAS" = "2" ]; then
            running_services="$running_services worker_2"
        fi
    fi
    echo "正在重启运行中的容器: $running_services"
    $COMPOSE_CMD restart $running_services
else
    mapped_services=""
    for service_name in "$@"; do
        mapped_name="$(map_service_alias "$service_name")"
        if [ "$mapped_name" != "$service_name" ]; then
            echo "✓ 兼容映射: $service_name -> $mapped_name"
        fi
        mapped_services="$mapped_services $mapped_name"
    done
    mapped_services="$(echo "$mapped_services" | xargs)"
    echo "正在重启指定容器: $mapped_services"
    $COMPOSE_CMD restart $mapped_services
fi

echo ""
echo "========================================="
echo "✓ 重启指令执行完毕"
echo "========================================="
echo "查看日志:"
echo "  $COMPOSE_CMD logs -f web"
echo "  $COMPOSE_CMD logs -f worker_1"
if [ "$WORKER_REPLICAS" = "2" ]; then
    echo "  $COMPOSE_CMD logs -f worker_2"
fi
echo "  $COMPOSE_CMD logs -f scheduler"
echo ""
