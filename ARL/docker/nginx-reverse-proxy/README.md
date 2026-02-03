# ARL Nginx 反向代理（含 Basic Auth）

## 功能说明

此反向代理容器提供：

- ✅ 基于 nginx 的反向代理
- ✅ HTTP Basic Auth 用户认证
- ✅ 支持 WebSocket 连接
- ✅ 自签名 SSL 证书支持
- ✅ 支持动态修改用户名和密码

## 快速开始

### 方法 1：修改环境变量（推荐）

在 `docker-compose.yml` 中配置环境变量：

```yaml
services:
  nginx:
    build:
      context: .
      dockerfile: ARL/docker/nginx-reverse-proxy/Dockerfile
    container_name: arl_nginx
    restart: unless-stopped
    ports:
      - "80:80"
    environment:
      BASIC_AUTH_USERNAME: admin
      BASIC_AUTH_PASSWORD: mypassword123
    depends_on:
      - arl_web
```

### 方法 2：使用 .env 文件

1. 复制模板文件：

   ```bash
   cp ARL/docker/nginx-reverse-proxy/.env.example .env
   ```

2. 编辑 `.env` 文件：

   ```bash
   BASIC_AUTH_USERNAME=admin
   BASIC_AUTH_PASSWORD=mypassword123
   ```

3. 在 `docker-compose.yml` 中引用：

   ```yaml
   services:
     nginx:
       environment:
         - BASIC_AUTH_USERNAME=${BASIC_AUTH_USERNAME}
         - BASIC_AUTH_PASSWORD=${BASIC_AUTH_PASSWORD}
   ```

4. 启动容器：
   ```bash
   docker-compose up -d
   ```

## 修改密码

### 方式 1：重新启动容器（推荐）

修改环境变量后重启：

```bash
docker-compose down
# 编辑 .env 或 docker-compose.yml 中的密码
docker-compose up -d
```

### 方式 2：在容器内修改

进入容器并重新生成密码：

```bash
docker exec arl_nginx htpasswd -b -B -c /etc/nginx/.htpasswd admin newpassword123
docker exec arl_nginx nginx -s reload
```

## 访问

- **地址**：`http://your-server-ip/`
- **用户名**：环境变量 `BASIC_AUTH_USERNAME`
- **密码**：环境变量 `BASIC_AUTH_PASSWORD`

## 健康检查

无需认证的健康检查端点：

```bash
curl http://your-server-ip/health
```

输出：`healthy`

## 常见问题

### Q: 如何禁用 Basic Auth？

编辑 `nginx.conf`，注释掉以下两行：

```nginx
# auth_basic "ARL Access Restricted";
# auth_basic_user_file /etc/nginx/.htpasswd;
```

然后重新构建镜像。

### Q: 如何添加多个用户？

进入容器手动添加：

```bash
# 追加新用户（不加 -c 参数）
docker exec arl_nginx htpasswd -b -B /etc/nginx/.htpasswd user2 password2
docker exec arl_nginx nginx -s reload
```

### Q: 后端是自签名证书怎么办？

nginx 已配置 `proxy_ssl_verify off;`，不验证后端 SSL 证书。

### Q: 如何查看访问日志？

```bash
docker logs arl_nginx
# 或
docker exec arl_nginx tail -f /var/log/nginx/access.log
```

## 架构图

```
Client
  ↓ (HTTP + Basic Auth)
Nginx Reverse Proxy (arl_nginx)
  ↓ (HTTPS)
ARL Web (arl_web:443)
```

## 安全建议

1. **强密码**：使用至少 12 个字符的复杂密码
2. **HTTPS**：在前面加一层 HTTPS（例如用 Caddy 或 Let's Encrypt）
3. **限制访问**：可在 nginx.conf 中限制 IP 访问
4. **定期更换密码**：每月或每季度更换一次

## 扩展配置

如需更复杂的 nginx 配置，编辑 `nginx.conf` 文件，修改后：

```bash
docker-compose up -d --build
```

重新构建镜像。
