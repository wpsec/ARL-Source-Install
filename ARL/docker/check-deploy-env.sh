#!/usr/bin/env bash
# 部署 .env 预检（计划 1：Compose 启动前的必填配置显式检查）。
# 用法: check-deploy-env.sh [ENV文件路径]
#   不传参数时按 仓库根 .env → ARL/docker/.env 顺序探测。
# 规则:
#   1) .env 必须存在（本地文件，已被 Git 忽略，不入库）；
#   2) 凭据必填键必须齐全且非空；
#   3) <set-me> 占位值不允许启动；
#   4) 密码键命中仓库历史分发过或常见的弱口令值时只告警，不阻止启动；
#      密码强度建议不作为部署硬门禁。
# 输出约定: 问题一律走 stderr 且只列键名，绝不回显敏感键的值。
# 退出码: 0=通过; 1=存在任一问题; 2=用法错误。
set -u

REQUIRED_KEYS=(
    MONGO_INITDB_ROOT_USERNAME
    MONGO_INITDB_ROOT_PASSWORD
    ARL_APP_USERNAME
    ARL_APP_PASSWORD
    RABBITMQ_DEFAULT_USER
    RABBITMQ_DEFAULT_PASS
    BASIC_AUTH_PASSWORD
)

# 仅对密码类键做弱值检查；用户名（admin 等）不属于凭据机密。
PASSWORD_KEYS=(
    MONGO_INITDB_ROOT_PASSWORD
    ARL_APP_PASSWORD
    RABBITMQ_DEFAULT_PASS
    BASIC_AUTH_PASSWORD
)

# 曾经以默认值形式随仓库分发过、或属常见弱口令的值：出现只告警，不回显值。
WEAK_VALUES="admin admin123456 arlpass arlpassword password 123456 changeme"

PLACEHOLDER='<set-me>'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ "$#" -gt 1 ]; then
    printf '[ENV-CHECK] usage: %s [path-to-.env]\n' "$0" >&2
    exit 2
fi

ENV_FILE="${1:-}"
if [ -z "$ENV_FILE" ]; then
    if [ -f "$REPO_ROOT/.env" ]; then
        ENV_FILE="$REPO_ROOT/.env"
    elif [ -f "$SCRIPT_DIR/.env" ]; then
        ENV_FILE="$SCRIPT_DIR/.env"
    fi
fi

if [ -z "$ENV_FILE" ] || [ ! -f "$ENV_FILE" ]; then
    printf '[ENV-CHECK] 缺少 .env：请复制 %s 为 .env 并填入自设凭据（.env 仅本地存在，不入库）\n' \
        "$SCRIPT_DIR/.env.example" >&2
    exit 1
fi

fail=0
warn=0

env_get() {
    # 取键的最后一个赋值行（与 compose env-file 后写覆盖语义一致），去掉行尾 \r
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r' || true
}

is_password_key() {
    local candidate key
    candidate="$1"
    for key in "${PASSWORD_KEYS[@]}"; do
        [ "$key" = "$candidate" ] && return 0
    done
    return 1
}

is_weak_value() {
    local candidate value
    candidate="$1"
    for value in $WEAK_VALUES; do
        [ "$value" = "$candidate" ] && return 0
    done
    return 1
}

for key in "${REQUIRED_KEYS[@]}"; do
    value="$(env_get "$key")"
    if [ -z "$value" ]; then
        printf '[ENV-CHECK] 缺少必填配置或值为空: %s\n' "$key" >&2
        fail=1
        continue
    fi
    if [ "$value" = "$PLACEHOLDER" ]; then
        printf '[ENV-CHECK] 仍为占位值，请填入真实配置: %s\n' "$key" >&2
        fail=1
        continue
    fi
    if is_password_key "$key" && is_weak_value "$value"; then
        printf '[ENV-CHECK] WARNING: %s 使用弱口令或历史默认值，建议轮换（不阻止启动）\n' "$key" >&2
        warn=1
    fi
done

if [ "$fail" -ne 0 ]; then
    exit 1
fi

if [ "$warn" -ne 0 ]; then
    printf '[ENV-CHECK] OK: %s（必填键齐全、无占位；存在弱口令告警）\n' "$ENV_FILE"
else
    printf '[ENV-CHECK] OK: %s（必填键齐全、无占位）\n' "$ENV_FILE"
fi
exit 0
