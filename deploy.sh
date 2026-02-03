#!/bin/bash

# ARL 系统完整部署脚本
# 用途：将本地文件同步到远程服务器

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 配置
REMOTE_USER="root"
REMOTE_HOST="192.168.246.130"
REMOTE_PATH="/root/arl/ARL-Source-Install"
LOCAL_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${GREEN}=== ARL 系统完整部署脚本 ===${NC}"
echo -e "${YELLOW}本地目录: $LOCAL_PATH${NC}"
echo -e "${YELLOW}远程目录: $REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH${NC}"

# 验证必要文件
echo -e "\n${YELLOW}检查必要文件...${NC}"

FILES_TO_CHECK=(
    "ARL/docker/Dockerfile"
    "ARL/docker/docker-compose.yml"
    "ARL/docker/nginx-reverse-proxy/Dockerfile"
    "ARL/docker/nginx-reverse-proxy/nginx.conf"
    "ARL/docker/nginx-reverse-proxy/entrypoint.sh"
    ".env.example"
)

for file in "${FILES_TO_CHECK[@]}"; do
    if [ -f "$LOCAL_PATH/$file" ]; then
        echo -e "${GREEN}✓ $file${NC}"
    else
        echo -e "${RED}✗ $file 不存在${NC}"
        exit 1
    fi
done

# 同步文件到远程
echo -e "\n${YELLOW}开始同步文件到远程服务器...${NC}"

# 1. 同步 Dockerfile
echo "  → 同步 ARL/docker/Dockerfile"
scp "$LOCAL_PATH/ARL/docker/Dockerfile" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/ARL/docker/Dockerfile"

# 2. 同步 docker-compose.yml
echo "  → 同步 ARL/docker/docker-compose.yml"
scp "$LOCAL_PATH/ARL/docker/docker-compose.yml" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/ARL/docker/docker-compose.yml"

# 3. 同步 nginx 反向代理相关文件
echo "  → 同步 nginx 反向代理文件"
mkdir -p "$LOCAL_PATH/ARL/docker/nginx-reverse-proxy" 2>/dev/null || true
scp "$LOCAL_PATH/ARL/docker/nginx-reverse-proxy/Dockerfile" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/ARL/docker/nginx-reverse-proxy/Dockerfile"
scp "$LOCAL_PATH/ARL/docker/nginx-reverse-proxy/nginx.conf" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/ARL/docker/nginx-reverse-proxy/nginx.conf"
scp "$LOCAL_PATH/ARL/docker/nginx-reverse-proxy/entrypoint.sh" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/ARL/docker/nginx-reverse-proxy/entrypoint.sh"
scp "$LOCAL_PATH/ARL/docker/nginx-reverse-proxy/README.md" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/ARL/docker/nginx-reverse-proxy/README.md"

# 4. 同步 .env.example
echo "  → 同步 .env.example"
scp "$LOCAL_PATH/.env.example" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/.env.example"

# 5. 同步 QUICKSTART.md
echo "  → 同步 QUICKSTART.md"
scp "$LOCAL_PATH/QUICKSTART.md" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/QUICKSTART.md"

echo -e "\n${GREEN}✓ 所有文件同步完成${NC}"

# 提示下一步
echo -e "\n${YELLOW}=== 下一步操作 ===${NC}"
echo "1. 连接到远程服务器："
echo "   ssh $REMOTE_USER@$REMOTE_HOST"
echo ""
echo "2. 进入项目目录："
echo "   cd $REMOTE_PATH"
echo ""
echo "3. 复制环境配置文件："
echo "   cp .env.example .env"
echo ""
echo "4. 编辑 .env 文件修改密码（可选）："
echo "   vi .env"
echo ""
echo "5. 启动系统："
echo "   cd ARL/docker"
echo "   docker-compose up -d --build"
echo ""
echo "6. 查看日志："
echo "   docker-compose logs -f"
echo ""
echo "7. 访问系统："
echo "   http://$REMOTE_HOST"
echo ""
echo -e "${GREEN}部署完成！${NC}"
