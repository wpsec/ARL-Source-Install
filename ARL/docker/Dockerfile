FROM rockylinux:8

WORKDIR /code
ARG TARGETARCH
ARG PYTHON_VERSION=3.10.20

# 1. 优化源配置：适配 Rocky 8 的仓库文件名
RUN sed -e 's|^mirrorlist=|#mirrorlist=|g' \
    -e 's|^#baseurl=http://dl.rockylinux.org/$contentdir|baseurl=https://mirrors.aliyun.com/rockylinux|g' \
    -i /etc/yum.repos.d/Rocky-*.repo

# 2. 配置 pip 源
RUN mkdir -p /root/.pip && \
    printf '[global]\nindex-url = https://pypi.mirrors.ustc.edu.cn/simple/\ntimeout = 120\n' > /root/.pip/pip.conf

# 3. 安装依赖（包含 Playwright Chromium 运行时库）
RUN dnf install -y epel-release fontconfig && \
    dnf install -y gcc gcc-c++ make zlib-devel bzip2-devel openssl-devel sqlite-devel \
    readline-devel libffi-devel xz-devel nginx unzip wget findutils nmap \
    alsa-lib atk at-spi2-atk cairo cups-libs gtk3 libdrm mesa-libgbm \
    libX11 libXcomposite libXcursor libXdamage libXext libXi libXrandr \
    libXScrnSaver libXtst nss nspr pango xorg-x11-fonts-Type1 xorg-x11-fonts-misc && \
    dnf clean all

# 3.5. 编译安装 Python 3.10
# - 优先使用本地 tools/Python-${PYTHON_VERSION}.tgz（离线构建）
# - 本地不存在时，自动从公共镜像下载源码包
COPY tools/Python-*.tgz /tmp/
RUN set -e; \
    PYTHON_TGZ="/tmp/Python-${PYTHON_VERSION}.tgz"; \
    if [ ! -f "${PYTHON_TGZ}" ]; then \
      for URL in \
        "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" \
        "https://mirrors.huaweicloud.com/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" \
        "https://mirrors.aliyun.com/python-release/source/Python-${PYTHON_VERSION}.tgz"; do \
        echo "try download ${URL}"; \
        if wget -q -O "${PYTHON_TGZ}" "${URL}"; then \
          echo "download python source success: ${URL}"; \
          break; \
        fi; \
      done; \
    fi; \
    test -s "${PYTHON_TGZ}" || (echo "[ERROR] Python source package not found: ${PYTHON_TGZ}" && exit 1); \
    cd /tmp && \
    tar xzf "Python-${PYTHON_VERSION}.tgz" && \
    cd "Python-${PYTHON_VERSION}" && \
    ./configure --prefix=/usr/local --with-ensurepip=install && \
    make -j"$(nproc)" && \
    make install && \
    ln -sf /usr/local/bin/python3.10 /usr/bin/python3 && \
    ln -sf /usr/local/bin/python3.10 /usr/bin/python3.10 && \
    ln -sf /usr/local/bin/pip3.10 /usr/bin/pip3 && \
    ln -sf /usr/local/bin/pip3.10 /usr/bin/pip3.10 && \
    python3 --version && \
    pip3 --version && \
    rm -rf "/tmp/Python-${PYTHON_VERSION}" "/tmp/Python-${PYTHON_VERSION}.tgz"

# 4. 环境依赖安装 (利用缓存：先装依赖，再拷源码)
COPY ARL-NPoC/ /opt/ARL-NPoC/
COPY ARL/requirements.txt /code/requirements.txt
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN pip3 install --upgrade pip setuptools wheel && \
    pip3 install --no-cache-dir -r /code/requirements.txt
# 尝试安装 NPoC，失败不中断
RUN pip3 install --no-cache-dir -e /opt/ARL-NPoC/ || true
# NPoC 的 setup.py 未声明 install_requires，显式安装插件运行时依赖
RUN pip3 install --no-cache-dir \
    dnslib==0.9.16 \
    pycryptodomex==3.16.0 \
    requests_ntlm==1.1.0
# 确保关键包已安装
RUN pip3 install --no-cache-dir psutil flask pymongo celery || true
# Playwright 浏览器（下载失败不阻塞构建，运行时可按需回退）
RUN python3 -m playwright install chromium || \
    echo "[WARN] playwright browser install failed, screenshot will fallback when unavailable"
# 显示已安装的包
RUN echo "===== 已安装的关键包 =====" && pip3 list | grep -E "psutil|flask|pymongo|celery|urllib3|playwright" && echo "===== 包安装检查完毕 ====="

# 5. 复制业务文件与工具
COPY ARL/app/ app/
COPY ARL/test/ test/
COPY ARL/docker/frontend/ frontend/
COPY ARL/docker/nginx.conf /etc/nginx/nginx.conf
COPY ARL/docker/worker/*.sh /usr/bin/

# 6. 复制二进制工具（先创建目录，再复制，并设置正确权限）
RUN mkdir -p /data/GeoLite2 /usr/local/share/ncrack

COPY tools/ncrack/ncrack /usr/local/bin/ncrack
COPY tools/ncrack/ncrack-services /usr/local/share/ncrack/ncrack-services
COPY tools/nuclei/nuclei_*_linux_amd64.zip /tmp/
COPY tools/nuclei/nuclei-templates/ /code/tools/nuclei-templates/
COPY tools/finger.json /code/tools/finger.json
COPY tools/wih/ /tmp/wih/
COPY tools/GeoLite2/GeoLite2-* /data/GeoLite2/
COPY tools/dhparam.pem /etc/ssl/certs/dhparam.pem

# 根据架构安装 WIH，并设置可执行权限
RUN set -e; \
    ARCH="${TARGETARCH:-$(uname -m)}"; \
    case "$ARCH" in \
      amd64|x86_64) WIH_BIN="wih_linux_amd64" ;; \
      arm64|aarch64) WIH_BIN="wih_linux_arm64" ;; \
      *) echo "[ERROR] unsupported arch for wih: $ARCH"; exit 1 ;; \
    esac; \
    cp "/tmp/wih/${WIH_BIN}" /usr/bin/wih && \
    chmod +x /usr/local/bin/ncrack /usr/bin/wih && \
    rm -rf /tmp/wih

ENV LANG=en_US.UTF-8

# 7. 离线工具配置与清理
RUN ln -sf /code/app/tools/phantomjs /usr/bin/phantomjs && \
    NUCLEI_ZIP=$(ls -1 /tmp/nuclei_*_linux_amd64.zip | head -n 1) && \
    unzip -q "${NUCLEI_ZIP}" nuclei && \
    mv nuclei /usr/bin/ && \
    rm -f /tmp/nuclei_*_linux_amd64.zip && \
    chmod +x /usr/bin/*.sh /usr/bin/nuclei

WORKDIR /code

# 8. 语法与环境自测
# 说明：
# - ncrack/massdns 当前仓库仅提供 x86_64 预编译二进制
# - WIH 已支持 x86_64 / aarch64 双架构
RUN echo "===== 检查关键模块 =====" && \
    python3 -c "import psutil; print('✓ psutil 已安装')" && \
    python3 -c "import flask; print('✓ flask 已安装')" && \
    python3 -c "import pymongo; print('✓ pymongo 已安装')" && \
    python3 -c "import celery; print('✓ celery 已安装')" && \
    python3 -c "import dnslib; print('✓ dnslib 已安装')" && \
    python3 -c "from Cryptodome.Cipher import AES; print('✓ pycryptodomex 已安装')" && \
    python3 -c "from requests_ntlm import HttpNtlmAuth; print('✓ requests_ntlm 已安装')" && \
    python3 -c "import playwright; print('✓ playwright 已安装')" && \
    cp app/config.yaml.example app/config.yaml && \
    echo "===== 所有关键模块检查通过 =====" && \
    echo "===== 检查关键工具 =====" && \
    nmap --version | head -2 && echo "✓ nmap 已安装" && \
    nuclei -version && echo "✓ nuclei 已安装" && \
    /usr/bin/wih -h >/tmp/wih_check.txt 2>&1 && head -1 /tmp/wih_check.txt && echo "✓ wih 已安装" && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
      if /code/app/tools/massdns --help >/tmp/massdns_check.txt 2>&1; then \
        head -1 /tmp/massdns_check.txt && echo "✓ massdns 已安装"; \
      else \
        echo "[WARN] massdns 自检失败，运行时将按降级策略处理"; \
      fi; \
      /usr/local/bin/ncrack --version >/tmp/ncrack_check.txt 2>&1 && head -1 /tmp/ncrack_check.txt && echo "✓ ncrack 已安装"; \
      if phantomjs --version >/tmp/phantom_check.txt 2>&1; then head -1 /tmp/phantom_check.txt && echo "✓ phantomjs 已安装(兼容兜底)"; else echo "[WARN] phantomjs 自检失败，仅影响 legacy 兼容路径"; fi; \
    else \
      echo "[WARN] 当前架构: $ARCH，跳过 x86_64 专有工具检查(massdns/ncrack)"; \
    fi && \
    echo "===== 所有工具检查通过 ====="
