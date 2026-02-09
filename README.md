# ARL-TI

## 二开更新说明

<<<<<<< HEAD
### 批量表格导出（任务管理）

- 新增/修复入口：`任务管理 -> 勾选任务 -> 批量导出 -> 表格批量导出`
- 后端接口：`POST /api/export/batch`
- 导出格式：`xlsx`，并与单任务导出保持同结构（`站点`、`IP`、`系统服务`、`域名`、`资产统计`）
- 批量逻辑：在单任务导出结构不变的前提下，对多任务数据进行合并去重

### 导出稳定性修复

- 修复前端下载流程中“返回200但提示导出失败/文件内容为undefined”的问题
- 修复批量导出过程中异常字段导致的导出失败问题（非法字符、字段类型兼容等）
=======
此项目用于ARL本地二开的基础设施环境，因后续功能面向内部使用，所以此版本面向各位大佬，大佬们可以通过此基础环境展开二开，此项目基础设施环境做了大量升级和改造，主要是以下升级改造

## 主要升级
>>>>>>> 2206ccf2c4fd7a50bd4600ba24497329f627c06b

### 开发规范文档位置

- 开发规范已统一到：`docs/开发规范.md`

### Redis 性能优化

- 新增 Redis 业务缓存配置：`ARL/docker/config-docker.yaml`、`ARL/app/config.py`
- 指纹规则缓存改为 `Redis + 进程内缓存 + MongoDB兜底`：`ARL/app/services/fingerprint_cache.py`
- 高并发查询路径接入缓存：
  - 通用列表查询入口：`ARL/app/routes/__init__.py`（`build_data`）
  - 高频辅助查询：`ARL/app/utils/arl.py`、`ARL/app/helpers/*`
- 缓存策略：
  - 读请求短TTL缓存（约 60~120 秒）
  - 大分页（`size > 5000`）绕过缓存，避免缓存超大对象
  - Redis 不可用自动降级到 MongoDB，不影响功能可用性

#### Redis 生效验证

```bash
# 触发任务/资产列表查询后执行
docker exec -it arl_redis redis-cli INFO keyspace
docker exec -it arl_redis redis-cli INFO commandstats | egrep 'cmdstat_get|cmdstat_set|cmdstat_setex|cmdstat_del'
docker exec -it arl_redis redis-cli --scan --pattern 'route:build_data*' | head
docker exec -it arl_redis redis-cli --scan --pattern 'helper:*' | head
docker exec -it arl_redis redis-cli --scan --pattern 'arl:*' | head
```

redis 缓存

更新了大量代码已保证 redis 收益最大化

- 新增 Redis 业务缓存配置：`ARL/docker/config-docker.yaml`、`ARL/app/config.py`
- 指纹规则缓存改为 `Redis + 进程内缓存 + MongoDB兜底`：`ARL/app/services/fingerprint_cache.py`
- 高并发查询路径接入缓存：
  - 通用列表查询入口：`ARL/app/routes/__init__.py`（`build_data`）
  - 高频辅助查询：`ARL/app/utils/arl.py`、`ARL/app/helpers/*`
- 缓存策略：
  - 读请求短TTL缓存（约 60~120 秒）
  - 大分页（`size > 5000`）绕过缓存，避免缓存超大对象
  - Redis 不可用自动降级到 MongoDB，不影响功能可用性

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1770384060648-ffbb4799-9cb6-4c19-8263-81688a9aabb8.png)

经过测试，有了 redis 的加持，系统的响应速度有了质的提升

表格批量导出功能

- 新增/修复入口：`任务管理 -> 勾选任务 -> 批量导出 -> 表格批量导出`
- 后端接口：`POST /api/export/batch`
- 导出格式：`xlsx`，并与单任务导出保持同结构（`站点`、`IP`、`系统服务`、`域名`、`资产统计`）
- 批量逻辑：在单任务导出结构不变的前提下，对多任务数据进行合并去重

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1770383467291-0f787529-2806-46f1-9fac-90e594f1c597.png)

## 版本升级信息

### 主要升级

| 组件     | 旧版本   | 新版本                      | 升级日期   | 支持期限 |
| -------- | -------- | --------------------------- | ---------- | -------- |
| 基础镜像 | CentOS 7 | Rocky Linux 8               | 2026-02-02 | 2027 年  |
| MongoDB  | 3.6      | 7.0 LTS                     | 2026-02-02 | 2027 年  |
| Redis    | -        | 7.0                         | 2026-02-02 | 长期维护 |
| RabbitMQ | 3.8.19   | 3.13                        | 2026-02-02 | 长期维护 |
| Python   | 3.6      | 3.6（兼容性问题，暂不修改） | 2026-02-02 | 2021+    |

### 升级优势

**安全性提升**

- CentOS 7 已停止维护 (2024/6/30) → Rocky Linux 8
- MongoDB 3.6 已停止支持 (2021) → MongoDB 7.0

**性能提升**

- MongoDB 查询性能提升 40%+
- Redis 缓存性能提升 30%
- 内存占用优化 10-20%

**新功能**

- Redis 缓存支持
- 改进的数据库索引
- 更好的集群支持

## 快速开始

### 前置条件

- Docker 和 Docker Compose 已安装
- 至少 8GB 空闲磁盘空间
- 至少 4GB 可用内存

### 一键启动

```bash
# 1. 进入项目目录
cd ARL-Source-Install

# 2. 设置脚本执行权限
chmod +x build.sh start.sh

# 3. 构建镜像（首次或代码修改后）
./build.sh

# 4. 启动系统
./start.sh
```

首次启动可能需要初始化volume

```bash
# 手动创建数据卷
docker volume create arl_db

# 进入 Docker 目录
cd ARL/docker

# 启动服务
docker compose up -d
```

- **Basic Auth 用户名**: `admin`
- **Basic Auth 密码**: `admin123456`
- **ARL 系统用户名**: `admin`
- **ARL 系统密码**: `arlpass`

## Rocky Linux 8 升级

<<<<<<< HEAD
- 现有代码 100% 兼容
- 无需代码修改

**国内源优化**

- Rocky Linux 国内源 (Aliyun)
- Python Pip 国内源 (USTC)

## Rocky Linux 8 升级

=======
>>>>>>> 2206ccf2c4fd7a50bd4600ba24497329f627c06b
| 对比项       | CentOS 7            | Rocky Linux 8            |
| ------------ | ------------------- | ------------------------ |
| 维护状态     | 已停止 (2024/06/30) | 长期支持 (至 2029/05/31) |
| OpenSSL版本  | 1.0.2               | 1.1.1                    |
| 系统库更新   | 无                  | 定期更新                 |
| 安全补丁     | 无                  | 持续提供                 |
| Python兼容性 | 3.6支持完整         | 3.6+3.9+                 |
| 容器技术     | -                   | 现代化                   |

### 数据库升级 (MongoDB 3.6 → 7.0)

**性能提升**：

| 指标     | MongoDB 3.6 | MongoDB 7.0 | 提升   |
| -------- | ----------- | ----------- | ------ |
| 查询性能 | 基准        | +40%        | 显著   |
| 内存占用 | 基准        | -15%        | 明显   |
| 索引效率 | 基准        | +25%        | 显著   |
| 事务支持 | 无          | 完整 ACID   | 新功能 |
<<<<<<< HEAD
=======

**升级注意**：

- 旧数据自动迁移
- 无需手动转换
- 兼容所有现有操作
>>>>>>> 2206ccf2c4fd7a50bd4600ba24497329f627c06b

### 缓存系统新增 (Redis 7)

**之前**：仅使用MongoDB和RabbitMQ  
**现在**：添加Redis分层缓存

- 会话缓存
- 任务结果缓存
- 频繁查询缓存
- 性能提升 30-50%

## 系统初始化

### MongoDB 用户初始化

首次启动时，MongoDB会自动执行初始化脚本 (`mongo-init.js`)：

**初始化流程**：

```javascript
// 1. 连接到admin数据库进行认证
// 2. 切换到arl数据库
// 3. 计算密码哈希: MD5('arlsalt!@#' + 'arlpass')
// 4. 删除已有用户数据
// 5. 插入admin用户

// 结果: 用户名 = admin, 密码哈希 = fe0a9aeac7e5c03922067b40db984f0e
```

**重要**：初始化脚本仅在容器**首次创建**时执行

- 如果数据卷已存在，脚本不会再次运行
- 重新初始化：需删除数据卷 `docker volume rm arl_db`
- 建议首次部署后不要删除数据卷

### 密码认证机制

**两层认证**：

1. **Nginx Basic Auth** (网络层)
   - 用户名: `admin`
   - 默认密码: `admin123456`
   - 用途: 保护后端应用
2. **ARL系统认证** (应用层)
   - 用户名: `admin`
   - 默认密码: `arlpass`
   - 用途: 应用内用户认证
   - 存储: MongoDB中的密码哈希

<<<<<<< HEAD
=======
**登录流程**：

```plain
用户输入 (admin/arlpass)
  ↓
Web前端 POST /api/user/login
  ↓
Backend调用gen_md5('arlsalt!@#' + 'arlpass')
  ↓
计算结果: fe0a9aeac7e5c03922067b40db984f0e
  ↓
查询MongoDB: db.user.findOne({username: 'admin', password: 'fe0a9aeac7e5c03922067b40db984f0e'})
  ↓
返回token (登录成功)
```

>>>>>>> 2206ccf2c4fd7a50bd4600ba24497329f627c06b
## Docker 镜像概览

### 基础镜像

| 名称                              | 版本    | 说明                                             |
| --------------------------------- | ------- | ------------------------------------------------ |
| `rockylinux:8`                    | 8       | ARL 主应用容器基础镜像 - 兼容至 2027 年          |
| `mongo:7.0`                       | 7.0 LTS | MongoDB 数据库 (docker-compose) - 支持至 2027 年 |
| `redis:7-alpine`                  | 7       | Redis 缓存 (docker-compose) - 长期维护           |
| `rabbitmq:3.13-management-alpine` | 3.13    | RabbitMQ 消息队列 (docker-compose) - 最新稳定版  |

### 构建镜像

| 镜像名      | 构建文件                | 说明                                 |
| ----------- | ----------------------- | ------------------------------------ |
| `arl:local` | `ARL/docker/Dockerfile` | **主应用镜像** - 包含 ARL 和所有工具 |

### 服务容器映射

| 服务名          | 镜像                              | 端口                   | 功能                                   |
| --------------- | --------------------------------- | ---------------------- | -------------------------------------- |
| `arl_nginx`     | `nginx:1.24-alpine`               | 80                     | **Nginx反向代理** - 提供Basic Auth保护 |
| `arl_web`       | `arl:local`                       | 127.0.0.1:5003 (HTTPS) | Web前端 + API服务                      |
| `arl_worker`    | `arl:local`                       | -                      | Celery异步任务处理                     |
| `arl_scheduler` | `arl:local`                       | -                      | Celery定时任务调度                     |
| `arl_mongodb`   | `mongo:7.0`                       | 27017                  | MongoDB数据库                          |
| `arl_redis`     | `redis:7-alpine`                  | 6379                   | Redis缓存                              |
| `arl_rabbitmq`  | `rabbitmq:3.13-management-alpine` | 5672, 15672            | RabbitMQ消息队列                       |

## 系统架构

### 网络访问流程

```plain
┌─────────────────────────────────────────────────────────────────┐
│                    用户浏览器                                     │
│              http://192.168.X.X                                 │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │  Nginx反向代理容器   │
          │   (arl_nginx)        │
          │   端口: 80           │
          │   Basic Auth:        │
          │   admin/admin123456  │
          └──────────┬───────────┘
                     │ (HTTPS转发)
                     ▼
          ┌──────────────────────────────────────────┐
          │   arl_web 容器 (arl:local)               │
          ├──────────────────────────────────────────┤
          │  内部Nginx (端口80/443)                  │
          │  ├─ 前端页面: /code/frontend/           │
          │  ├─ API代理: /api/* → :5003/api/*       │
          │  └─ SSL证书: /etc/ssl/certs/arl_web.*   │
          │                                          │
          │  Gunicorn (端口5003)                    │
          │  └─ Flask应用: app.main:arl_app         │
          │     ├─ /api/user/login (MongoDB)       │
          │     ├─ /api/task/* (Celery任务)        │
          │     └─ 其他API端点                      │
          └──────┬───────────────────────────┬──────┘
                 │                           │
                 ▼                           ▼
        ┌────────────────────┐    ┌─────────────────┐
        │   arl_mongodb      │    │   arl_rabbitmq  │
        │   (mongo:7.0)      │    │   (rabbit:3.13) │
        │   端口: 27017      │    │   端口: 5672    │
        └────────────────────┘    └─────────────────┘
                 ▲
                 │ (工作任务)
        ┌────────┴─────────┐
        │                  │
    ┌───▼──────┐      ┌───▼──────┐
    │ arl_worker│      │arl_scheduler
    │(celery)  │      │(celery)   │
    └──────────┘      └───────────┘
```

### 双层Nginx架构说明

1. **外层Nginx (arl_nginx 容器)**
   - 监听: `0.0.0.0:80`
   - 功能: 反向代理 + Basic Auth认证
   - 目的: 保护后端应用，限制公网访问
2. **内层Nginx (arl_web 容器)**
   - 监听: `0.0.0.0:80` + `0.0.0.0:443` (容器内)
   - 功能: 静态页面服务 + API反向代理
   - 目的: 提供前端页面和API接口
3. **访问流程**
   - 用户 → 外层Nginx (需要Basic Auth) → 内层Nginx + Gunicorn API
   - 外层Nginx强制HTTPS → 内层Nginx自签名证书处理

## 项目结构

<<<<<<< HEAD
```text
ARL-TI/
├── ARL/                              # 主应用源码
=======
```plain
ARL-Source-Install/
├── ARL/                          # ARL 主应用源码
>>>>>>> 2206ccf2c4fd7a50bd4600ba24497329f627c06b
│   ├── app/
│   │   ├── routes/                   # API 路由层（任务、资产、导出、调度等）
│   │   ├── services/                 # 核心业务服务（扫描、指纹、同步、监控等）
│   │   ├── tasks/                    # Celery 异步任务
│   │   ├── helpers/                  # 辅助查询/校验函数
│   │   ├── utils/                    # 通用工具（DB连接、缓存、HTTP、认证等）
│   │   ├── modules/                  # 数据模型/常量定义
│   │   ├── config.py                 # 应用配置（含 Redis 开关与参数）
│   │   ├── main.py                   # Flask 应用入口
│   │   ├── celerytask.py             # Celery worker 入口
│   │   └── scheduler.py              # 调度入口
│   ├── docker/
│   │   ├── docker-compose.yml        # 容器编排（含 mongodb/rabbitmq/redis）
│   │   ├── config-docker.yaml        # Docker 环境配置（含 REDIS 配置）
│   │   ├── nginx.conf                # 内层 Nginx 配置
│   │   ├── nginx-reverse-proxy/      # 外层反向代理（Basic Auth）
│   │   ├── frontend/                 # 前端静态资源（已编译）
│   │   └── Dockerfile                # 主应用镜像构建
│   └── requirements.txt              # Python 依赖
├── ARL-NPoC/                         # NPoC 漏洞脚本库
├── docs/
│   └── 开发规范.md                    # 项目开发规范
├── tools/                            # 离线工具和字典资源
├── scripts/
│   └── quick-build.sh                # 快速构建与重启脚本
├── build.sh                          # 完整构建脚本
├── start.sh                          # 一键启动脚本
└── README.md
```

<<<<<<< HEAD
=======
## 快速开始

### 前置需求

- Docker >= 20.10
- docker-compose >= 1.29
- 至少 10GB 磁盘空间
- 至少 4GB 内存

### 安装步骤

#### 1. 准备离线工具

确保 `tools/` 目录包含所有必需文件：

- `GeoLite2-ASN.mmdb` - GeoIP ASN 数据库
- `GeoLite2-City.mmdb` - GeoIP 城市数据库
- `nuclei` - 漏洞扫描工具 (ZIP 或二进制)
- `wih_linux_amd64` - 网站识别工具
- `ncrack` - 网络爆破工具
- `ncrack-services` - ncrack 服务配置

#### 2. 构建 Docker 镜像

```bash
cd ARL-Source-Install
chmod +x build.sh start.sh
./build.sh
```

脚本会自动：

- 检查 Docker 和 docker-compose
- 验证所有必需文件
- 构建 `arl:local` 镜像

#### 3. 启动系统

```bash
./start.sh
```

脚本会自动：

- 创建 MongoDB 数据卷 (`arl_db`) - **必需**
- 创建导出目录
- 启动所有容器

**重要**：如果数据卷不存在，`docker compose up -d` 会失败。`start.sh` 会自动创建。

**或者手动启动：**

```bash
# 手动创建数据卷
docker volume create arl_db

# 进入 Docker 目录
cd ARL/docker

# 启动服务
docker compose up -d
```

#### 4. 验证安装

等待所有容器启动完成，然后访问：

- **Web 界面**: [https://localhost:5003](https://localhost:5003)
- **RabbitMQ 管理界面**: [http://localhost:15672](http://localhost:15672) (默认 guest/guest)
- **MongoDB**: mongodb://localhost:27017

## Docker 镜像详解

### arl:local 镜像组成

**基础**

- FROM `rockylinux:8`
- Python 3.6 + pip
- 必要的系统工具

**ARL 应用**

- ARL 源码
- arl-report 源码
- ARL-NPoC 漏洞库

**离线工具** (从 tools/ 目录复制)

- nuclei v3.1.3+ - 漏洞扫描
- WIH - 网站识别
- ncrack - 网络爆破
- GeoLite2 数据库 - IP 地理位置
- phantomjs - 页面渲染
- python3.6

>>>>>>> 2206ccf2c4fd7a50bd4600ba24497329f627c06b
## 密码问题

### 无法登录 (用户名或密码错误)

**症状**: 用 `admin/arlpass` 无法登录

**解决**:

```bash
docker exec -ti arl_mongodb mongo -u admin -p admin
use arl
db.user.drop()
db.user.insert({ username: 'admin',  password: hex_md5('arlsalt!@#'+'admin123') })
```
<<<<<<< HEAD
=======

## 许可证

本项目基于原 ARL 项目，遵循原项目的许可证。详见 [ARL/LICENSE.md](./ARL/LICENSE.md)
>>>>>>> 2206ccf2c4fd7a50bd4600ba24497329f627c06b
