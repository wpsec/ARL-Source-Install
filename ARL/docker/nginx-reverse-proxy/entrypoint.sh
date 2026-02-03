#!/bin/bash
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 获取环境变量
USERNAME=${BASIC_AUTH_USERNAME:-admin}
PASSWORD=${BASIC_AUTH_PASSWORD:-admin123456}
HTPASSWD_FILE="/etc/nginx/.htpasswd"

echo -e "${GREEN}=== ARL Nginx Reverse Proxy Startup ===${NC}"
echo -e "${YELLOW}Username: $USERNAME${NC}"

# 生成 .htpasswd 文件
if [ -z "$PASSWORD" ]; then
    echo -e "${RED}Error: BASIC_AUTH_PASSWORD environment variable is not set!${NC}"
    exit 1
fi

# 创建 .htpasswd 文件（使用 htpasswd 生成 bcrypt 密码哈希）
# 注意：-b 表示从命令行读取密码，-B 表示使用 bcrypt 哈希
htpasswd -b -B -c "$HTPASSWD_FILE" "$USERNAME" "$PASSWORD" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ .htpasswd file generated successfully${NC}"
    echo -e "${YELLOW}Auth file: $HTPASSWD_FILE${NC}"
else
    echo -e "${RED}✗ Failed to generate .htpasswd file${NC}"
    exit 1
fi

# 设置正确的权限
chmod 644 "$HTPASSWD_FILE"

# 验证 nginx 配置
echo -e "${YELLOW}Validating nginx configuration...${NC}"
nginx -t
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Nginx configuration is valid${NC}"
else
    echo -e "${RED}✗ Nginx configuration validation failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ All checks passed, starting nginx...${NC}"

# 启动 nginx（传递命令行参数）
exec "$@"
