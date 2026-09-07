#!/usr/bin/env bash
# 首次安装内部凭据初始化（计划 1）。
# 用法: init-deploy-env.sh [目标 .env 路径]
#   缺省目标 = ARL/docker/.env，与 docker compose 的 project-directory 默认 env-file
#   路径一致（直接 `docker compose up` 与应用 `start.sh` 使用同一份文件）。
# 行为:
#   - .env 不存在时从 .env.example 创建（权限 600，本地文件不入库）；
#   - Mongo/RabbitMQ 内部凭据（含用户名）自动生成随机值，仅填充“缺失/空/占位”键，
#     已有值永不覆盖 → 幂等，可重复执行；
#   - Basic Auth 与 ARL 应用密码属用户填写项，不自动生成：
#       交互终端 → 隐式提示输入（只要求非空、非占位，不做复杂度强制）；
#       非交互   → 保留 <set-me>，由 check-deploy-env.sh 预检点名待填。
# 退出码: 0=完成（可能仍有用户待填键）; 1=环境错误。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"
ENV_TARGET="${1:-$SCRIPT_DIR/.env}"
PLACEHOLDER='<set-me>'

if [ ! -f "$ENV_EXAMPLE" ]; then
    printf '[INIT] 缺少模板: %s\n' "$ENV_EXAMPLE" >&2
    exit 1
fi

if [ ! -f "$ENV_TARGET" ]; then
    mkdir -p "$(dirname "$ENV_TARGET")"
    cp "$ENV_EXAMPLE" "$ENV_TARGET"
    printf '[INIT] 已从 .env.example 创建 %s\n' "$ENV_TARGET"
fi
chmod 600 "$ENV_TARGET"

gen_secret() {
    # 32 位十六进制随机（约 128 bit）；openssl 缺失时退到 python secrets。
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 16
    else
        python3 -c "import secrets; print(secrets.token_hex(16))"
    fi
}

get_val() {
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$ENV_TARGET" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r' || true
}

needs_fill() {
    case "$(get_val "$1")" in
        ''|"$PLACEHOLDER") return 0 ;;
        *) return 1 ;;
    esac
}

set_key() {
    # 键名只接受本脚本白名单常量；值经 ENVIRON 传递，避免 awk -v 对反斜杠的转义解释。
    local key="$1" value="$2"
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$ENV_TARGET"; then
        NEW_VALUE="$value" awk -v key="$key" '
            BEGIN { value = ENVIRON["NEW_VALUE"] }
            $0 ~ "^[[:space:]]*" key "[[:space:]]*=" { print key "=" value; next }
            { print }
        ' "$ENV_TARGET" > "$ENV_TARGET.tmp"
        mv "$ENV_TARGET.tmp" "$ENV_TARGET"
    else
        printf '%s=%s\n' "$key" "$value" >> "$ENV_TARGET"
    fi
}

# ---------- 内部凭据：自动生成（幂等） ----------
GENERATED=""
for key in MONGO_INITDB_ROOT_USERNAME MONGO_INITDB_ROOT_PASSWORD RABBITMQ_DEFAULT_USER RABBITMQ_DEFAULT_PASS; do
    if needs_fill "$key"; then
        case "$key" in
            MONGO_INITDB_ROOT_USERNAME) set_key "$key" "root_$(gen_secret | cut -c1-8)" ;;
            RABBITMQ_DEFAULT_USER)      set_key "$key" "arl_$(gen_secret | cut -c1-8)" ;;
            *)                          set_key "$key" "$(gen_secret)" ;;
        esac
        GENERATED="$GENERATED $key"
    fi
done

# ---------- 用户填写项：TTY 交互 / 非交互留占位 ----------
ask_user_secret() {
    local key="$1" label="$2" value=""
    if ! needs_fill "$key"; then
        return 0
    fi
    if [ ! -t 0 ]; then
        printf '[INIT] 非交互模式：%s 保留占位，请编辑 %s 填入（仅要求非空，无复杂度强制）\n' "$key" "$ENV_TARGET" >&2
        return 0
    fi
    # 只做空值/占位校验，不做强度校验（计划 1 第二轮口径）。
    while true; do
        if ! read -r -s -p "请输入 ${label}（不回显，无复杂度要求；Ctrl-D 跳过留待手填）: " value; then
            printf '\n[INIT] 跳过 %s，保留占位待手填\n' "$key"
            return 0
        fi
        printf '\n'
        if [ -n "$value" ] && [ "$value" != "$PLACEHOLDER" ]; then
            set_key "$key" "$value"
            printf '[INIT] 已写入 %s（值不回显）\n' "$key"
            return 0
        fi
        printf '[INIT] 不能为空或占位值，请重输\n' >&2
    done
}
ask_user_secret BASIC_AUTH_PASSWORD "Basic Auth 密码"
ask_user_secret ARL_APP_PASSWORD "ARL 应用登录密码（仅首次初始化卷生效）"

# awk+mv 重写会带入默认 umask 权限，收尾统一重申 600。
chmod 600 "$ENV_TARGET"
printf '[INIT] 目标文件: %s（权限 600）\n' "$ENV_TARGET"
if [ -n "$GENERATED" ]; then
    printf '[INIT] 已自动生成内部凭据:%s\n' "$GENERATED"
else
    printf '[INIT] 内部凭据键均已存在，保持不变（幂等）\n'
fi
printf '[INIT] 完成后由 check-deploy-env.sh 校验必填与占位；预检通过即可 ./start.sh\n'
