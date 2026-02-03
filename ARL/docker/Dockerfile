FROM rockylinux:8

WORKDIR /code

# 1. 优化源配置：适配 Rocky 8 的仓库文件名
RUN sed -e 's|^mirrorlist=|#mirrorlist=|g' \
    -e 's|^#baseurl=http://dl.rockylinux.org/$contentdir|baseurl=https://mirrors.aliyun.com/rockylinux|g' \
    -i /etc/yum.repos.d/Rocky-*.repo

# 2. 配置 pip 源
RUN mkdir -p /root/.pip && \
    printf '[global]\nindex-url = https://pypi.mirrors.ustc.edu.cn/simple/\ntimeout = 120\n' > /root/.pip/pip.conf

# 3. 安装依赖：Rocky 8 的 openssl-devel 是 1.1.1 版本，支持 Python 3.6
RUN dnf install -y epel-release fontconfig && \
    dnf install -y gcc gcc-c++ make zlib-devel bzip2-devel openssl-devel sqlite-devel \
    readline-devel libffi-devel xz-devel nginx unzip wget findutils nmap && \
    dnf clean all

# 3.5. 编译安装 Python 3.6
COPY tools/Python-3.6.15.tgz /tmp/
RUN cd /tmp && \
    tar xzf Python-3.6.15.tgz && \
    cd Python-3.6.15 && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install && \
    ln -sf /usr/local/bin/python3.6 /usr/bin/python3 && \
    ln -sf /usr/local/bin/python3.6 /usr/bin/python3.6 && \
    ln -sf /usr/local/bin/pip3.6 /usr/bin/pip3 && \
    ln -sf /usr/local/bin/pip3.6 /usr/bin/pip3.6 && \
    rm -rf /tmp/Python-3.6.15*

# 4. 环境依赖安装 (利用缓存：先装依赖，再拷源码)
COPY ARL-NPoC/ /opt/ARL-NPoC/
COPY ARL/requirements.txt /code/requirements.txt
# Python 3.6 版本固定策略：
# 1. 升级 pip 到 21.3.1（最后支持 Python 3.6 的版本）
# 2. 固定 cryptography==3.3.2（最后一个不需要 Rust 编译器的版本）
# 3. 固定 urllib3<2.0 和 pyOpenSSL 兼容版本
RUN pip3.6 install --upgrade 'pip==21.3.1' && \
    pip3.6 install --no-cache-dir 'urllib3<2.0' 'cryptography==3.3.2' 'pyOpenSSL==20.0.1' && \
    pip3.6 install --no-cache-dir -r /code/requirements.txt
# 尝试安装 NPoC，失败不中断
RUN pip3.6 install --no-cache-dir -e /opt/ARL-NPoC/ || true
# 确保关键包已安装
RUN pip3.6 install --no-cache-dir psutil==5.7.2 flask pymongo celery || true
# 显示已安装的包
RUN echo "===== 已安装的关键包 =====" && pip3.6 list | grep -E "psutil|flask|pymongo|celery|urllib3" && echo "===== 包安装检查完毕 ====="

# 5. 复制业务文件与工具
COPY ARL/app/ app/
COPY ARL/test/ test/
COPY ARL/docker/frontend/ frontend/
COPY ARL/docker/nginx.conf /etc/nginx/nginx.conf
COPY ARL/docker/worker/*.sh /usr/bin/

# 6. 复制二进制工具（先创建目录，再复制，并设置正确权限）
RUN mkdir -p /data/GeoLite2 /usr/local/share/ncrack

COPY tools/ncrack /usr/local/bin/ncrack
COPY tools/ncrack-services /usr/local/share/ncrack/ncrack-services
COPY tools/nuclei_2.9.15_linux_amd64.zip /tmp/nuclei.zip
COPY tools/wih_linux_amd64 /usr/bin/wih
COPY tools/GeoLite2-* /data/GeoLite2/
COPY tools/dhparam.pem /etc/ssl/certs/dhparam.pem

# 设置二进制文件执行权限
RUN chmod +x /usr/local/bin/ncrack /usr/bin/wih

ENV LANG=en_US.UTF-8

# 7. 离线工具配置与清理
RUN ln -sf /code/app/tools/phantomjs /usr/bin/phantomjs && \
    cd /tmp && \
    unzip -q nuclei.zip nuclei && \
    mv nuclei /usr/bin/ && \
    rm -f nuclei.zip && \
    chmod +x /usr/bin/*.sh /usr/bin/nuclei

WORKDIR /code

# 8. 语法与环境自测
RUN echo "===== 检查关键模块 =====" && \
    python3.6 -c "import psutil; print('✓ psutil 已安装')" && \
    python3.6 -c "import flask; print('✓ flask 已安装')" && \
    python3.6 -c "import pymongo; print('✓ pymongo 已安装')" && \
    python3.6 -c "import celery; print('✓ celery 已安装')" && \
    cp app/config.yaml.example app/config.yaml && \
    echo "===== 所有关键模块检查通过 =====" && \
    echo "===== 检查关键工具 =====" && \
    nmap --version | head -2 && echo "✓ nmap 已安装" && \
    nuclei -version && echo "✓ nuclei 已安装" && \
    /usr/local/bin/ncrack --version | head -1 && echo "✓ ncrack 已安装" && \
    /usr/bin/wih -h | head -1 && echo "✓ wih 已安装" && \
    phantomjs --version && echo "✓ phantomjs 已安装" && \
    echo "===== 所有工具检查通过 ====="