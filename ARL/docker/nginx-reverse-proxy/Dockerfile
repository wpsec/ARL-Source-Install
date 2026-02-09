FROM nginx:1.24-alpine

# 安装 apache2-utils（提供 htpasswd 工具）
RUN apk add --no-cache apache2-utils bash

# 复制 nginx 配置文件
COPY nginx.conf /etc/nginx/nginx.conf

# 复制启动脚本
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 设置默认用户名和密码环境变量
ENV BASIC_AUTH_USERNAME=admin
ENV BASIC_AUTH_PASSWORD=admin123456

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
