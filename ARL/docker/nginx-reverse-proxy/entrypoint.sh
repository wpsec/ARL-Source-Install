#!/bin/sh
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 获取环境变量
USERNAME=${BASIC_AUTH_USERNAME:-admin}
PASSWORD=${BASIC_AUTH_PASSWORD:-}
HTPASSWD_FILE="/etc/nginx/.htpasswd"

printf '%b\n' "${GREEN}=== ARL Nginx Reverse Proxy Startup ===${NC}"
printf '%b\n' "${YELLOW}Username: ${USERNAME}${NC}"

# 生成 .htpasswd 文件
if [ -z "$PASSWORD" ]; then
    printf '%b\n' "${RED}Error: BASIC_AUTH_PASSWORD environment variable is not set!${NC}"
    exit 1
fi

# 创建 .htpasswd 文件（使用 htpasswd 生成 bcrypt 密码哈希）
# 通过标准输入传递密码，避免密码出现在进程参数中。
if ! printf '%s\n' "$PASSWORD" | htpasswd -i -B -c "$HTPASSWD_FILE" "$USERNAME" > /dev/null 2>&1; then
    printf '%b\n' "${RED}✗ Failed to generate .htpasswd file${NC}"
    exit 1
fi

printf '%b\n' "${GREEN}✓ .htpasswd file generated successfully${NC}"
printf '%b\n' "${YELLOW}Auth file: $HTPASSWD_FILE${NC}"

# 设置正确的权限
chmod 644 "$HTPASSWD_FILE"

# 验证 nginx 配置
printf '%b\n' "${YELLOW}Validating nginx configuration...${NC}"
nginx -t
if [ $? -eq 0 ]; then
    printf '%b\n' "${GREEN}✓ Nginx configuration is valid${NC}"
else
    printf '%b\n' "${RED}✗ Nginx configuration validation failed${NC}"
    exit 1
fi

printf '%b\n' "${GREEN}✓ All checks passed, starting nginx...${NC}"

# 启动 nginx（传递命令行参数）
exec "$@"
