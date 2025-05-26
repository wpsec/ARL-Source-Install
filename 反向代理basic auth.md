
# arl.conf
```
server {
    listen 80;
    server_name 0.0.0.0;

    location / {
        proxy_pass https://localhost:50031;  # 使用 HTTPS
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 关闭 SSL 证书验证（避免自签名证书问题）
        proxy_ssl_verify off;

        # 启用 Basic Auth
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
```

```
sudo apt update && sudo apt install nginx  # Ubuntu/Debian
sudo yum install nginx                     # CentOS/RHEL



sudo apt install apache2-utils  # 如果没有 htpasswd 先安装
sudo htpasswd -c /etc/nginx/.htpasswd wp  # wp 是用户名

sudo rm /etc/nginx/sites-enabled/default
sudo systemctl restart nginx
```
# docker-compose.yml 
```
services:
    web:
        image: tophant/arl:v2.6.1
        container_name: arl_web
        restart: unless-stopped
        depends_on:
          - mongodb
          - rabbitmq
        ports:
          #http 服务，默认不映射出来
          #- "5003:80"
          - "127.0.0.1:50031:443"
```