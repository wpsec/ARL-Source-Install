#!/bin/bash
set -e

echo "更新系统并安装依赖..."

# 安装必要的依赖
sudo apt-get update
sudo apt-get install -y gnupg curl

# 下载并添加 MongoDB GPG 密钥
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | \
    sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor

# 获取 Ubuntu 版本代号
UBUNTU_CODENAME=$(lsb_release -sc)

# 根据系统版本选择对应的 MongoDB 源
case "$UBUNTU_CODENAME" in
    noble | jammy | focal)
        MONGO_REPO_CODENAME="$UBUNTU_CODENAME"
        ;;
    *)
        echo "当前 Ubuntu 版本 ($UBUNTU_CODENAME) 未被支持，请手动配置 MongoDB 源。"
        exit 1
        ;;
esac

# 写入 MongoDB APT 源
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu $MONGO_REPO_CODENAME/mongodb-org/8.0 multiverse" | \
    sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list

# 更新软件包列表
sudo apt-get update -y

echo "MongoDB 8.0 APT 源已成功配置，当前使用的是 $MONGO_REPO_CODENAME 版本库。"

apt update && apt upgrade -y
apt install -y curl wget unzip git python3 python3-pip python3-dev gcc g++ make \
    nginx rabbitmq-server mongodb-org nmap

echo "检查 Python3 和 Pip..."
if ! command -v python3.6 &> /dev/null; then
    echo "未找到 Python3.6，使用默认 Python3..."
    ln -sf /usr/bin/python3 /usr/bin/python3.6
fi

if ! command -v pip3 &> /dev/null; then
    echo "安装 pip..."
    python3 -m ensurepip
    python3 -m pip install --upgrade pip -i https://pypi.mirrors.ustc.edu.cn/simple
fi

echo "安装 nuclei..."
if ! command -v nuclei &> /dev/null; then
    if [ -f "./tools/nuclei_2.9.15_linux_amd64.zip" ]; then
        echo "使用本地 tools/nuclei_2.9.15_linux_amd64.zip 文件..."
        unzip "./tools/nuclei_2.9.15_linux_amd64.zip" -d /usr/local/bin/
        chmod +x /usr/local/bin/nuclei
    else
        echo "未找到本地 nuclei 文件，请确保 tools/ 目录下有 nuclei_2.9.15_linux_amd64.zip"
        exit 1
    fi
fi

echo "配置并启动 MongoDB..."
systemctl enable mongod
systemctl start mongod

echo "配置并启动 RabbitMQ..."
systemctl enable rabbitmq-server
systemctl start rabbitmq-server

echo "安装 wih..."
if ! command -v wih &> /dev/null; then
    if [ -f "./tools/wih_linux_amd64" ]; then
        echo "使用本地 tools/wih_linux_amd64..."
        cp ./tools/wih_linux_amd64 /usr/bin/wih
        chmod +x /usr/bin/wih
    else
        echo "未找到 wih_linux_amd64，安装失败。"
        exit 1
    fi
    wih --version
fi

echo "安装 ncrack..."
if [ ! -f /usr/local/bin/ncrack ]; then
    if [ -f "./tools/ncrack" ]; then
        echo "使用本地 tools/ncrack..."
        cp ./tools/ncrack /usr/local/bin/ncrack
        chmod +x /usr/local/bin/ncrack
    else
        echo "未找到 ncrack，安装失败。"
        exit 1
    fi
fi

mkdir -p /usr/local/share/ncrack
if [ ! -f /usr/local/share/ncrack/ncrack-services ]; then
    if [ -f "./tools/ncrack-services" ]; then
        echo "使用本地 tools/ncrack-services..."
        cp ./tools/ncrack-services /usr/local/share/ncrack/ncrack-services
    else
        echo "未找到 ncrack-services，安装失败。"
        exit 1
    fi
fi

mkdir -p /data/GeoLite2
for db in GeoLite2-ASN.mmdb GeoLite2-City.mmdb; do
    if [ ! -f "/data/GeoLite2/$db" ]; then
        if [ -f "./tools/$db" ]; then
            echo "使用本地 tools/$db..."
            cp "./tools/$db" "/data/GeoLite2/$db"
        else
            echo "未找到 $db，安装失败。"
            exit 1
        fi
    fi
done

cd ARL-NPoC
echo "安装 PoC 依赖..."
pip3 install -r requirements.txt -i https://pypi.mirrors.ustc.edu.cn/simple
pip3 install -e . -i https://pypi.mirrors.ustc.edu.cn/simple
cd ../

cd ARL
if [ ! -f rabbitmq_user ]; then
    echo "添加 RabbitMQ 用户..."
    rabbitmqctl delete_user arl
    rabbitmqctl add_user arl arlpassword
    rabbitmqctl add_vhost arlv2host
    rabbitmqctl set_user_tags arl arltag
    rabbitmqctl set_permissions -p arlv2host arl ".*" ".*" ".*"
    mongosh 127.0.0.1:27017/arl ./docker/mongo-init.js
    touch rabbitmq_user
fi

echo "安装 ARL 依赖..."
pip3 install -r requirements.txt -i https://pypi.mirrors.ustc.edu.cn/simple
[ ! -f app/config.yaml ] && cp app/config.yaml.example app/config.yaml

[ ! -f /usr/bin/phantomjs ] && ln -s "$(pwd)/app/tools/phantomjs" /usr/bin/phantomjs

[ ! -f /etc/nginx/conf.d/arl.conf ] && cp misc/arl.conf /etc/nginx/conf.d/

if [ ! -f /etc/ssl/certs/dhparam.pem ]; then
    if [ -f "./tools/dhparam.pem" ]; then
        echo "使用本地 tools/dhparam.pem..."
        cp "./tools/dhparam.pem" /etc/ssl/certs/dhparam.pem
    else
        echo "未找到 dhparam.pem，安装失败。"
        exit 1
    fi
fi

echo "生成证书..."
./docker/worker/gen_crt.sh

echo "配置并启动 ARL 相关服务..."
for service in arl-web arl-worker arl-worker-github arl-scheduler; do
    [ ! -f "/etc/systemd/system/$service.service" ] && cp "misc/$service.service" /etc/systemd/system/
    systemctl enable $service
    systemctl start $service
done

systemctl enable nginx
systemctl start nginx

echo "安装完成！"
