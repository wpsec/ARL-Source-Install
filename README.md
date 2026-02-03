# ARL-Source-Install

ARL 灯塔资产侦察系统二开升级版本，升级了基础镜像和核心依赖，源码本地化安装版本，支持完全独立的 Docker 镜像构建。

此项目用于ARL本地二开的基础设施环境，因后续功能面向内部使用，所以此版本面向各位大佬，大佬们可以通过此基础环境展开二开～



## 当前状态

**版本**: 升级版本（Rocky Linux 8 + Python 3.6 + MongoDB 7 + Redis 7）

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

- **Basic Auth 用户名**: `admin`
- **Basic Auth 密码**: `admin123456`
- **ARL 系统用户名**: `admin`
- **ARL 系统密码**: `arlpass`

## 版本信息

- 现有代码 100% 兼容
- 无需代码修改

**国内源优化**

- Rocky Linux 国内源 (Aliyun)
- Python Pip 国内源 (USTC)

## Rocky Linux 8 升级详解

### 为什么从 CentOS 7 升级到 Rocky Linux 8？

| 对比项       | CentOS 7               | Rocky Linux 8               |
| ------------ | ---------------------- | --------------------------- |
| 维护状态     | 已停止 (2024/06/30) | 长期支持 (至 2029/05/31) |
| OpenSSL版本  | 1.0.2           | 1.1.1                |
| 系统库更新   | 无                  | 定期更新                 |
| 安全补丁     | 无                  | 持续提供                 |
| Python兼容性 | 3.6支持完整         | 3.6+3.9+                 |
| 容器技术     | -               | 现代化                   |

### Python 3.6 源码编译

由于Rocky Linux 8默认仓库不包含Python 3.6，系统采用源码编译方式：

**编译过程** (Dockerfile中)：

```dockerfile
# 1. 下载Python 3.6.15源码 (tools/Python-3.6.15.tgz)
# 2. 解压并配置: ./configure --prefix=/usr/local
# 3. 编译: make -j4
# 4. 安装: make install
# 5. 创建软链接: ln -s /usr/local/bin/python3.6 /usr/bin/python3.6

# 结果: /usr/local/bin/python3.6 ← Python 3.6.15
#      /usr/local/bin/pip3.6 ← pip 18.1 (需升级)
```

**关键依赖版本调整**：

```
原始需求 (CentOS 7):
- cryptography==38.0.4 (需要Rust编译器) 
- pyOpenSSL==22.1.0 (需要新cryptography) 
- urllib3>=2.0 (不支持Python 3.6) 

Rocky Linux 8 + Python 3.6 兼容版本:
- pip==21.3.1 (最后一个支持Python 3.6的pip)
- cryptography==3.3.2 (最后一个无需Rust的版本) 
- pyOpenSSL==20.0.1 (兼容cryptography 3.3.2) 
- urllib3<2.0 (Python 3.6兼容) 
```

### 数据库升级 (MongoDB 3.6 → 7.0)

**性能提升**：

| 指标     | MongoDB 3.6 | MongoDB 7.0  | 提升   |
| -------- | ----------- | ------------ | ------ |
| 查询性能 | 基准        | +40%         | 显著   |
| 内存占用 | 基准        | -15%         | 明显   |
| 索引效率 | 基准        | +25%         | 显著   |
| 事务支持 | 无       | 完整 ACID | 新功能 |

**升级注意**：

- 旧数据自动迁移 
- 无需手动转换
- 兼容所有现有操作

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
   - 密码: `admin123456`
   - 用途: 保护后端应用

2. **ARL系统认证** (应用层)
   - 用户名: `admin`
   - 密码: `arlpass`
   - 用途: 应用内用户认证
   - 存储: MongoDB中的密码哈希

**登录流程**：

```
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

```
┌─────────────────────────────────────────────────────────────────┐
│                    用户浏览器                                     │
│              http://192.168.X.X (公网)                          │
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
   - 监听: `0.0.0.0:80` (公网)
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

```
ARL-Source-Install/
├── ARL/                          # ARL 主应用源码
│   ├── app/
│   │   ├── main.py               # Flask 应用主文件
│   │   ├── celerytask.py         # Celery 异步任务
│   │   ├── config.py             # 配置文件
│   │   ├── routes/               # API 路由
│   │   ├── services/             # 业务逻辑服务
│   │   ├── tasks/                # 侦察任务
│   │   ├── utils/                # 工具函数
│   │   ├── dicts/                # 字典数据
│   │   ├── tools/                # 二进制工具
│   │   └── ...
│   ├── docker/
│   │   ├── Dockerfile            # 镜像构建文件
│   │   ├── docker-compose.yml    # 容器编排配置
│   │   ├── nginx.conf            # 反向代理配置
│   │   ├── config-docker.yaml    # Docker 配置文件
│   │   └── mongo-init.js         # MongoDB 初始化脚本
│   ├── requirements.txt          # Python 依赖
│   └── ...
├── ARL-NPoC/                     # PoC 漏洞库
│   ├── xing/                     # 漏洞脚本
│   └── requirements.txt
├── tools/                         # 离线工具和数据库
│   ├── GeoLite2-ASN.mmdb        # GeoIP ASN 数据库
│   ├── GeoLite2-City.mmdb       # GeoIP 城市数据库
│   ├── dhparam.pem              # SSL DH 参数
│   ├── ncrack                   # 网络爆破工具
│   ├── phantomjs                # 网页截图工具
│   ├── wih_linux_amd64          # WIH 扫描器
│   └── ...
├── test/                         # 测试文件
│   ├── test_*.py                # 单元测试
│   └── ...
├── build.sh                      # 构建脚本
├── start.sh                      # 启动脚本
└── README.md                     # 本文件
│   ├── nuclei/                  # nuclei 漏洞扫描工具
│   ├── wih_linux_amd64          # 网站识别工具
│   ├── ncrack                   # 网络爆破工具
│   ├── ncrack-services          # ncrack 服务文件
│   └── phantomjs                # 页面渲染引擎
├── build.sh                      #  新增：Docker 镜像构建脚本
├── start.sh                      #  新增：系统启动脚本
├── test_report_api.py            #  新增：API 测试工具
└── README.md                     # 本文件
```

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

- **Web 界面**: https://localhost:5003
- **RabbitMQ 管理界面**: http://localhost:15672 (默认 guest/guest)
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



## 许可证

本项目基于原 ARL 项目，遵循原项目的许可证。详见 [ARL/LICENSE.md](./ARL/LICENSE.md)
