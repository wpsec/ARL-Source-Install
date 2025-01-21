#!/bin/bash
set -e

echo "Downloading CentOS 7 repo file from Aliyun..."
curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo

# 检查 curl 命令是否成功
if [ $? -eq 0 ]; then
    echo "Repo file downloaded successfully."
else
    echo "Failed to download repo file. Please check your network connection."
    exit 1
fi

# 生成 yum 缓存
echo "Generating yum cache..."
yum makecache

# 检查 yum makecache 是否成功
if [ $? -eq 0 ]; then
    echo "Yum cache generated successfully."
else
    echo "Failed to generate yum cache. Please check your yum configuration."
    exit 1
fi

# 检查当前 SELinux 状态
echo "Current SELinux status:"
sestatus

# 修改 SELinux 配置文件，设置为禁用
echo "Disabling SELinux..."
sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config

# 提示用户需要重启系统
echo "SELinux has been disabled in the configuration file."
echo "You need to reboot the system for the changes to take effect."
echo "Run 'sudo reboot' to restart the system."

echo "cd /opt/"

mkdir -p /opt/
cd /opt/

tee /etc/yum.repos.d/mongodb-org-4.0.repo <<"EOF"
[mongodb-org-4.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/4.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-4.0.asc
EOF

echo "install dependencies ..."
yum install epel-release -y
yum install python36 mongodb-org-server mongodb-org-shell rabbitmq-server python36-devel gcc-c++ git \
 nginx  fontconfig wqy-microhei-fonts unzip wget vim net-tools -y

if [ ! -f /usr/bin/python3.6 ]; then
  echo "link python3.6"
  ln -s /usr/bin/python36 /usr/bin/python3.6
fi

if [ ! -f /usr/local/bin/pip3.6 ]; then
  echo "install  pip3.6"
  python3.6 -m ensurepip --default-pip
  python3.6 -m pip install --upgrade pip -i https://pypi.mirrors.ustc.edu.cn/simple
  pip3.6 --version
fi

if ! command -v nmap &> /dev/null
then
    echo "install nmap-7.91-1 ..."
    rpm -vhU https://nmap.org/dist/nmap-7.91-1.x86_64.rpm
fi


if ! command -v nuclei &> /dev/null
then
  echo "install nuclei_2.9.15 ..."
  
  # 使用本地的 nuclei_2.9.15_linux_amd64.zip 文件
  if [ -f /opt/tools/nuclei_2.9.15_linux_amd64.zip ]; then
    echo "Using local nuclei_2.9.15_linux_amd64.zip ..."
    cp /opt/tools/nuclei_2.9.15_linux_amd64.zip ./
  else
    echo "Local nuclei_2.9.15_linux_amd64.zip not found. Exiting."
    exit 1
  fi

  # 解压并安装
  unzip nuclei_2.9.15_linux_amd64.zip && mv nuclei /usr/bin/ && rm -f nuclei_2.9.15_linux_amd64.zip
  
  # 更新 nuclei 模板
  nuclei -ut
fi


if ! command -v wih &> /dev/null
then
  echo "install wih ..."

  # 使用本地的 wih_linux_amd64 文件
  if [ -f /opt/tools/wih_linux_amd64 ]; then
    echo "Using local wih_linux_amd64 ..."
    cp /opt/tools/wih_linux_amd64 /usr/bin/wih
    chmod +x /usr/bin/wih
  else
    echo "Local wih_linux_amd64 not found. Exiting."
    exit 1
  fi

  # 检查是否安装成功
  wih --version
fi


echo "start services ..."
systemctl enable mongod
systemctl start mongod
systemctl enable rabbitmq-server
systemctl start rabbitmq-server


# if [ ! -d ARL ]; then
#   echo "git clone ARL proj"
#   git clone https://github.com/TophantTechnology/ARL
# fi

# if [ ! -d "ARL-NPoC" ]; then
#   echo "git clone ARL-NPoC proj"
#   git clone https://github.com/1c3z/ARL-NPoC
# fi

cd ARL-NPoC
echo "install poc requirements ..."
pip3.6 install -r requirements.txt  -i https://pypi.mirrors.ustc.edu.cn/simple
pip3.6 install -e . -i https://pypi.mirrors.ustc.edu.cn/simple
cd ../

if [ ! -f /usr/local/bin/ncrack ]; then
  echo "install ncrack ..."

  # 使用本地的 ncrack 文件
  if [ -f /opt/tools/ncrack ]; then
    echo "Using local ncrack ..."
    cp /opt/tools/ncrack /usr/local/bin/ncrack
    chmod +x /usr/local/bin/ncrack
  else
    echo "Local ncrack not found. Exiting."
    exit 1
  fi
fi

mkdir -p /usr/local/share/ncrack
if [ ! -f /usr/local/share/ncrack/ncrack-services ]; then
  echo "install ncrack-services ..."

  # 使用本地的 ncrack-services 文件
  if [ -f /opt/tools/ncrack-services ]; then
    echo "Using local ncrack-services ..."
    mkdir -p /usr/local/share/ncrack  # 确保目标目录存在
    cp /opt/tools/ncrack-services /usr/local/share/ncrack/ncrack-services
  else
    echo "Local ncrack-services not found. Exiting."
    exit 1
  fi
fi

mkdir -p /data/GeoLite2

# 使用本地的 GeoLite2-ASN.mmdb 文件
if [ ! -f /data/GeoLite2/GeoLite2-ASN.mmdb ]; then
  echo "install GeoLite2-ASN.mmdb ..."
  if [ -f /opt/tools/GeoLite2-ASN.mmdb ]; then
    echo "Using local GeoLite2-ASN.mmdb ..."
    cp /opt/tools/GeoLite2-ASN.mmdb /data/GeoLite2/GeoLite2-ASN.mmdb
  else
    echo "Local GeoLite2-ASN.mmdb not found. Exiting."
    exit 1
  fi
fi

# 使用本地的 GeoLite2-City.mmdb 文件
if [ ! -f /data/GeoLite2/GeoLite2-City.mmdb ]; then
  echo "install GeoLite2-City.mmdb ..."
  if [ -f /opt/tools/GeoLite2-City.mmdb ]; then
    echo "Using local GeoLite2-City.mmdb ..."
    cp /opt/tools/GeoLite2-City.mmdb /data/GeoLite2/GeoLite2-City.mmdb
  else
    echo "Local GeoLite2-City.mmdb not found. Exiting."
    exit 1
  fi
fi

cd ARL

if [ ! -f rabbitmq_user ]; then
  echo "add rabbitmq user"
  rabbitmqctl add_user arl arlpassword
  rabbitmqctl add_vhost arlv2host
  rabbitmqctl set_user_tags arl arltag
  rabbitmqctl set_permissions -p arlv2host arl ".*" ".*" ".*"
  echo "init arl user"
  mongo 127.0.0.1:27017/arl docker/mongo-init.js
  touch rabbitmq_user
fi

echo "install arl requirements ..."
pip3.6 install -r requirements.txt -i https://pypi.mirrors.ustc.edu.cn/simple
if [ ! -f app/config.yaml ]; then
  echo "create config.yaml"
  cp app/config.yaml.example  app/config.yaml
fi

if [ ! -f /usr/bin/phantomjs ]; then
  echo "install phantomjs"
  ln -s `pwd`/app/tools/phantomjs  /usr/bin/phantomjs
fi

if [ ! -f /etc/nginx/conf.d/arl.conf ]; then
  echo "copy arl.conf"
  cp misc/arl.conf /etc/nginx/conf.d
fi



if [ ! -f /etc/ssl/certs/dhparam.pem ]; then
  echo "install dhparam.pem ..."

  # 使用本地的 dhparam.pem 文件
  if [ -f /opt/tools/dhparam.pem ]; then
    echo "Using local dhparam.pem ..."
    cp /opt/tools/dhparam.pem /etc/ssl/certs/dhparam.pem
  else
    echo "Local dhparam.pem not found. Exiting."
    exit 1
  fi
fi


echo "gen cert ..."
./docker/worker/gen_crt.sh


cd /opt/ARL/


if [ ! -f /etc/systemd/system/arl-web.service ]; then
  echo  "copy arl-web.service"
  cp misc/arl-web.service /etc/systemd/system/
fi

if [ ! -f /etc/systemd/system/arl-worker.service ]; then
  echo  "copy arl-worker.service"
  cp misc/arl-worker.service /etc/systemd/system/
fi


if [ ! -f /etc/systemd/system/arl-worker-github.service ]; then
  echo  "copy arl-worker-github.service"
  cp misc/arl-worker-github.service /etc/systemd/system/
fi

if [ ! -f /etc/systemd/system/arl-scheduler.service ]; then
  echo  "copy arl-scheduler.service"
  cp misc/arl-scheduler.service /etc/systemd/system/
fi

echo "start arl services ..."
systemctl enable arl-web
systemctl start arl-web
systemctl enable arl-worker
systemctl start arl-worker
systemctl enable arl-worker-github
systemctl start arl-worker-github
systemctl enable arl-scheduler
systemctl start arl-scheduler
systemctl enable nginx
systemctl start nginx
systemctl status arl-web
systemctl status arl-worker
systemctl status arl-worker-github
systemctl status arl-scheduler

echo "install done"

