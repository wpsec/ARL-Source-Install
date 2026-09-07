#!/bin/bash
# 重置 ARL 应用登录账号（arl 库 user 集合，应用层鉴权账号，非数据库认证用户）。
# 用法: ./resetpass.sh [用户名]
#   - 用户名缺省时取 .env 的 ARL_APP_USERNAME；
#   - 新密码：优先读 ARL_APP_PASSWORD 环境变量（非交互），否则交互隐式输入；
#   - MongoDB root 凭据：从 .env 的 MONGO_INITDB_ROOT_* 读取（与 start.sh 同源）。
# 凭据治理（计划 1）：不内置任何默认账号/密码，不回显密码明文。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/ARL/docker"

ENV_FILE=""
if [ -f "$SCRIPT_DIR/.env" ]; then
    ENV_FILE="$SCRIPT_DIR/.env"
elif [ -f "$DOCKER_DIR/.env" ]; then
    ENV_FILE="$DOCKER_DIR/.env"
else
    echo "[-] 未找到 .env（root 凭据与默认用户名依赖它）；请先按 .env.example 创建" >&2
    exit 1
fi

env_get() {
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$ENV_FILE" | tail -n1 | cut -d= -f2- | tr -d '\r' || true
}

MONGO_ROOT_USER="$(env_get MONGO_INITDB_ROOT_USERNAME)"
MONGO_ROOT_PASS="$(env_get MONGO_INITDB_ROOT_PASSWORD)"
if [ -z "$MONGO_ROOT_USER" ] || [ -z "$MONGO_ROOT_PASS" ]; then
    echo "[-] .env 缺少 MONGO_INITDB_ROOT_USERNAME/PASSWORD" >&2
    exit 1
fi

USERNAME="${1:-$(env_get ARL_APP_USERNAME)}"
if [ -z "$USERNAME" ]; then
    echo "[-] 未提供用户名（参数或 .env 的 ARL_APP_USERNAME）" >&2
    exit 1
fi

NEW_PASS="${ARL_APP_PASSWORD:-}"
if [ -z "$NEW_PASS" ]; then
    read -r -s -p "新密码（至少 8 位，不回显）: " NEW_PASS; echo
    read -r -s -p "再次输入确认: " NEW_PASS_CONFIRM; echo
    if [ "$NEW_PASS" != "$NEW_PASS_CONFIRM" ]; then
        echo "[-] 两次输入不一致" >&2
        exit 1
    fi
fi

if [ "${#NEW_PASS}" -lt 8 ]; then
    echo "[-] 密码长度不足 8 位，拒绝设置弱口令" >&2
    exit 1
fi
case "$NEW_PASS" in
    admin|arlpass|arlpassword|password|admin123|admin123456|123456|changeme)
        echo "[-] 命中已知弱口令/历史默认值，拒绝" >&2
        exit 1 ;;
esac

# 应用层口令 = md5(固定盐 + 明文)，与 ARL 登录校验及 mongo-init.js 同口径；
# 在宿主机用 openssl 计算，避免把明文传给容器进程参数。
HASHED="$(printf '%s' "arlsalt!@#${NEW_PASS}" | openssl dgst -md5 | awk '{print $NF}')"

echo "[*] 通过身份验证重置应用账号: $USERNAME"
docker exec -i arl_mongodb mongosh -u "$MONGO_ROOT_USER" -p "$MONGO_ROOT_PASS" \
    --authenticationDatabase admin arl --eval '
const username = args[0];
const hashed = args[1];
db.user.deleteMany({ username: username });
db.user.insertOne({ username: username, password: hashed });
print("[+] 已重置应用账号: " + username);
' "$USERNAME" "$HASHED"

echo "[!] 请同步更新 $ENV_FILE 中的 ARL_APP_PASSWORD（新卷初始化将沿用该值）"
