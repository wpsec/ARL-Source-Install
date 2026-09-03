FROM nginx:1.24-alpine

# 安装 apache2-utils（提供 htpasswd 工具）
RUN sed -i 's#https://dl-cdn.alpinelinux.org/alpine#https://mirrors.aliyun.com/alpine#g' /etc/apk/repositories \
    && apk add --no-cache apache2-utils

# 复制 nginx 配置文件
COPY nginx.conf /etc/nginx/nginx.conf

# 复制启动脚本
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
