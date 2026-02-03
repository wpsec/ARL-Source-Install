#!/bin/bash
# ARL 错误诊断和修复脚本
# 用于诊断 eytax.com.cn 任务失败的根本原因

set -e

echo "🎯 ARL 任务错误诊断和修复工具"
echo "=========================================="
echo "时间: $(date)"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 1. 查询最新错误任务
echo -e "${BLUE}1️⃣ 查询最新的错误任务${NC}"
echo "=================================================="

TASK_INFO=$(docker exec arl_mongodb mongosh --quiet --eval "
use('arl');
var task = db.task.find({status: 'error', target: 'eytax.com.cn'}).sort({start_date: -1}).limit(1).toArray()[0];
if (task) {
  print('TASK_ID:' + task._id);
  print('START_TIME:' + task.start_date);
  print('END_TIME:' + task.end_date);
  print('ERROR_MSG:' + (task.error_msg || '无'));
  print('TASK_NAME:' + task.name);
} else {
  print('NO_TASK_FOUND');
}
" 2>/dev/null || echo "NO_TASK_FOUND")

if [[ "$TASK_INFO" == "NO_TASK_FOUND" ]]; then
  echo -e "${RED}❌ 未找到错误任务${NC}"
else
  echo "$TASK_INFO" | while IFS=':' read -r key value; do
    case $key in
      TASK_ID) echo -e "${GREEN}任务ID:${NC} $value" ;;
      START_TIME) echo -e "${GREEN}开始时间:${NC} $value" ;;
      END_TIME) echo -e "${GREEN}结束时间:${NC} $value" ;;
      ERROR_MSG) echo -e "${RED}错误信息:${NC} $value" ;;
      TASK_NAME) echo -e "${GREEN}任务名称:${NC} $value" ;;
    esac
  done
fi

echo ""

# 2. 系统资源检查
echo -e "${BLUE}2️⃣ 系统资源状态检查${NC}"
echo "=================================================="

echo -e "${YELLOW}内存使用:${NC}"
free -h | head -2

echo ""
echo -e "${YELLOW}容器资源使用:${NC}"
docker stats --no-stream --format "table {{.Container}}\t{{.MemUsage}}\t{{.CPUPerc}}"

echo ""

# 3. RabbitMQ状态检查
echo -e "${BLUE}3️⃣ RabbitMQ状态检查${NC}"
echo "=================================================="

echo -e "${YELLOW}RabbitMQ连接数:${NC}"
docker exec arl_rabbitmq rabbitmqctl list_connections | grep -c 'amqp' || echo "0"

echo -e "${YELLOW}RabbitMQ队列状态:${NC}"
docker exec arl_rabbitmq rabbitmqctl list_queues name messages | head -10

echo ""

# 4. Worker日志检查
echo -e "${BLUE}4️⃣ Worker服务日志${NC}"
echo "=================================================="

echo -e "${YELLOW}最近的ERROR日志:${NC}"
docker logs arl_worker 2>&1 | grep -i "error\|exception\|failed\|timeout" | tail -10 || echo "无ERROR日志"

echo ""
echo -e "${YELLOW}最近的日志输出:${NC}"
docker logs arl_worker 2>&1 | tail -15

echo ""

# 5. Web服务日志检查
echo -e "${BLUE}5️⃣ Web服务日志${NC}"
echo "=================================================="

echo -e "${YELLOW}Web服务最近的ERROR:${NC}"
docker logs arl_web 2>&1 | grep -i "error\|exception" | tail -5 || echo "无ERROR日志"

echo ""

# 6. 问题分析和建议
echo -e "${BLUE}6️⃣ 问题分析和修复建议${NC}"
echo "=================================================="

# 检查内存使用
AVAILABLE_MEM=$(free -h | awk 'NR==2 {print $7}' | sed 's/G.*//')
echo -e "${YELLOW}可用内存:${NC} ${AVAILABLE_MEM}GB"

if (( $(echo "$AVAILABLE_MEM < 1" | bc -l) )); then
  echo -e "${RED}⚠️ 可用内存不足 1GB!${NC}"
  echo "建议: 清理系统缓存或增加系统内存"
  echo ""
  echo "清理缓存命令:"
  echo "  sync && echo 3 > /proc/sys/vm/drop_caches"
  echo "  docker system prune -f"
fi

echo ""

# 7. 具体修复步骤
echo -e "${BLUE}7️⃣ 建议的修复步骤${NC}"
echo "=================================================="

echo -e "${YELLOW}步骤1: 清理系统缓存${NC}"
echo "  sudo sync && echo 3 > /proc/sys/vm/drop_caches"
echo ""

echo -e "${YELLOW}步骤2: 重启ARL服务${NC}"
echo "  docker restart arl_worker arl_scheduler arl_web"
echo "  sleep 20"
echo ""

echo -e "${YELLOW}步骤3: 验证服务状态${NC}"
echo "  docker ps"
echo "  docker logs arl_worker | tail -20"
echo ""

echo -e "${YELLOW}步骤4: 重新创建轻量级任务测试${NC}"
echo "  只启用以下模块:"
echo "  ✓ 域名查询插件"
echo "  ✓ 端口扫描 (轻量模式)"
echo "  ✓ 服务识别"
echo "  ✓ SSL证书"
echo "  ✓ 跳过CDN"
echo ""

echo -e "${YELLOW}步骤5: 如果轻量任务成功,逐步启用其他模块${NC}"
echo ""

# 8. 自动修复建议
echo -e "${BLUE}8️⃣ 自动执行修复${NC}"
echo "=================================================="

read -p "是否自动执行清理和重启? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo -e "${YELLOW}执行清理缓存...${NC}"
  sync && echo 3 > /proc/sys/vm/drop_caches
  
  echo -e "${YELLOW}重启ARL服务...${NC}"
  docker restart arl_worker arl_scheduler arl_web
  
  echo -e "${YELLOW}等待服务启动...${NC}"
  sleep 20
  
  echo -e "${GREEN}✅ 修复完成!${NC}"
  echo ""
  echo -e "${YELLOW}当前服务状态:${NC}"
  docker ps
else
  echo -e "${YELLOW}跳过自动修复${NC}"
fi

echo ""
echo -e "${BLUE}诊断和修复完成!${NC}"
echo "=========================================="