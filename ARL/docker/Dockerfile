FROM node:20.20.1-bookworm AS frontend_builder

WORKDIR /frontend
ARG NPM_REGISTRY=https://registry.npmmirror.com

# 安装前端依赖（含 node-gyp 所需编译工具）
COPY ARL/docker/frontend-src/package*.json ./
RUN set -eux; \
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; \
    if command -v apt-get >/dev/null 2>&1; then \
      for SOURCE_LIST in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do \
        if [ -f "${SOURCE_LIST}" ]; then \
          sed -i \
            -e 's|deb.debian.org/debian-security|mirrors.aliyun.com/debian-security|g' \
            -e 's|security.debian.org/debian-security|mirrors.aliyun.com/debian-security|g' \
            -e 's|deb.debian.org/debian|mirrors.aliyun.com/debian|g' \
            "${SOURCE_LIST}"; \
        fi; \
      done; \
      apt-get -o Acquire::Retries=5 update; \
      apt-get -o Acquire::Retries=5 install -y --no-install-recommends python3 make g++; \
      rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
      apk add --no-cache python3 make g++; \
    else \
      echo "[ERROR] unsupported package manager in frontend_builder"; \
      exit 127; \
    fi; \
    command -v node >/dev/null 2>&1 || (echo "[ERROR] node command not found" && exit 127); \
    npm_exec() { \
      if command -v npm >/dev/null 2>&1; then \
        if npm "$@"; then return 0; fi; \
        rc="$?"; \
        if [ "${rc}" -ne 127 ]; then return "${rc}"; fi; \
        echo "[WARN] npm command returned 127, fallback to npm-cli.js"; \
      fi; \
      for cli in /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/lib/node_modules/npm/bin/npm-cli.js /usr/share/nodejs/npm/bin/npm-cli.js; do \
        if [ -f "${cli}" ]; then \
          if node "${cli}" "$@"; then return 0; fi; \
          rc="$?"; \
          if [ "${rc}" -ne 127 ]; then return "${rc}"; fi; \
        fi; \
      done; \
      if command -v corepack >/dev/null 2>&1; then \
        if corepack npm "$@"; then return 0; fi; \
        rc="$?"; \
        if [ "${rc}" -ne 127 ]; then return "${rc}"; fi; \
      fi; \
      echo "[ERROR] npm command not found"; \
      return 127; \
    }; \
    node --version; \
    npm_exec --version; \
    npm_exec config set registry "${NPM_REGISTRY}"; \
    npm_exec config set fetch-retries 5; \
    npm_exec config set fetch-retry-mintimeout 20000; \
    npm_exec config set fetch-retry-maxtimeout 120000; \
    # 生产镜像构建强制可复现：lock 缺失直接失败（回退 npm install 会让依赖漂移进镜像）
    if [ ! -f package-lock.json ]; then \
      echo "[ERROR] frontend-src/package-lock.json missing; production build must run npm ci" >&2; \
      exit 1; \
    fi; \
    npm_exec ci --no-audit --no-fund

# 前端构建会读取 ../../version.txt，这里映射到 /version.txt
COPY ARL/version.txt /version.txt
COPY ARL/docker/frontend-src/ ./
RUN set -eux; \
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; \
    npm_run_build() { \
      if command -v npm >/dev/null 2>&1; then \
        if npm run build; then return 0; fi; \
        rc="$?"; \
        if [ "${rc}" -ne 127 ]; then return "${rc}"; fi; \
      fi; \
      for cli in /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/lib/node_modules/npm/bin/npm-cli.js /usr/share/nodejs/npm/bin/npm-cli.js; do \
        if [ -f "${cli}" ]; then \
          if node "${cli}" run build; then return 0; fi; \
          rc="$?"; \
          if [ "${rc}" -ne 127 ]; then return "${rc}"; fi; \
        fi; \
      done; \
      if command -v corepack >/dev/null 2>&1; then \
        corepack npm run build; \
        return "$?"; \
      fi; \
      echo "[ERROR] npm build command not found"; \
      return 127; \
    }; \
    npm_run_build; \
    test -f /frontend/dist/index.html; \
    test -d /frontend/dist/assets

FROM rockylinux:8

WORKDIR /code
ARG TARGETARCH
ARG NPM_REGISTRY=https://registry.npmmirror.com
ARG PYTHON_VERSION=3.10.20
ARG GO_VERSION=1.22.4
ARG RUST_VERSION=1.85.1
ARG MATURIN_VERSION=1.8.6
ARG NCRACK_VERSION=0.7
ARG NUCLEI_VERSION=3.7.0
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV LANG=en_US.UTF-8

COPY tools/ncrack/ /tmp/ncrack-offline/

# 配置 Rocky/EPEL 与 pip 镜像源，并安装系统依赖
RUN set -eux; \
    sed -e 's|^mirrorlist=|#mirrorlist=|g' \
        -e 's|^#baseurl=http://dl.rockylinux.org/$contentdir|baseurl=https://mirrors.aliyun.com/rockylinux|g' \
        -i /etc/yum.repos.d/Rocky-*.repo; \
    mkdir -p /root/.pip; \
    printf '[global]\nindex-url = https://pypi.mirrors.ustc.edu.cn/simple/\ntimeout = 120\n' > /root/.pip/pip.conf; \
    dnf install -y epel-release; \
    sed -e 's|^metalink=|#metalink=|g' \
        -e 's|^mirrorlist=|#mirrorlist=|g' \
        -e 's|^#baseurl=http://download.example/pub/epel|baseurl=https://mirrors.ustc.edu.cn/epel|g' \
        -e 's|^#baseurl=https://download.example/pub/epel|baseurl=https://mirrors.ustc.edu.cn/epel|g' \
        -i /etc/yum.repos.d/epel*.repo; \
    dnf clean all; \
    dnf install -y \
      fontconfig gcc gcc-c++ make git zlib-devel bzip2-devel openssl-devel sqlite-devel \
      readline-devel libffi-devel xz-devel nginx unzip wget findutils nmap \
      alsa-lib atk at-spi2-atk cairo cups-libs gtk3 libdrm mesa-libgbm \
      libX11 libXcomposite libXcursor libXdamage libXext libXi libXrandr \
      libXScrnSaver libXtst nss nspr pango xorg-x11-fonts-Type1 xorg-x11-fonts-misc; \
    dnf clean all

# Rust 官方工具链以 xz 压缩包提供；单独安装解包工具以保持系统依赖层缓存稳定。
RUN set -eux; \
    dnf install -y xz; \
    dnf clean all

COPY --from=frontend_builder /usr/local/bin/node /usr/local/bin/node
COPY --from=frontend_builder /usr/local/lib/node_modules/ /usr/local/lib/node_modules/
RUN set -eux; \
    ln -sf /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm; \
    ln -sf /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx; \
    node --version; \
    npm --version; \
    npx --version

# 编译安装 ncrack，避免预编译二进制与当前 OpenSSL 运行时不兼容
RUN set -eux; \
    NCRACK_TGZ="/tmp/ncrack-${NCRACK_VERSION}.tar.gz"; \
    OFFLINE_NCRACK_TGZ="/tmp/ncrack-offline/ncrack-${NCRACK_VERSION}.tar.gz"; \
    if [ -s "${OFFLINE_NCRACK_TGZ}" ]; then \
      echo "use offline ncrack source package: ${OFFLINE_NCRACK_TGZ}"; \
      cp "${OFFLINE_NCRACK_TGZ}" "${NCRACK_TGZ}"; \
    fi; \
    if [ ! -s "${NCRACK_TGZ}" ]; then \
      for URL in \
        "https://nmap.org/ncrack/dist/ncrack-${NCRACK_VERSION}.tar.gz" \
        "https://nmap.org/svn/ncrack/ncrack-${NCRACK_VERSION}.tar.gz"; do \
        echo "try download ${URL}"; \
        wget -q --timeout=30 --tries=1 --no-check-certificate -O "${NCRACK_TGZ}" "${URL}" && break || true; \
      done; \
    fi; \
    test -s "${NCRACK_TGZ}" || (echo "[ERROR] ncrack source package not found: ${NCRACK_TGZ}" && exit 1); \
    cd /tmp; \
    tar -xzf "ncrack-${NCRACK_VERSION}.tar.gz"; \
    cd "ncrack-${NCRACK_VERSION}"; \
    ./configure; \
    make -j"$(nproc)"; \
    ./ncrack -V >/dev/null; \
    install -m 0755 ncrack /usr/local/bin/ncrack; \
    install -d /usr/local/share/ncrack; \
    install -m 0644 ncrack-services /usr/local/share/ncrack/ncrack-services; \
    rm -rf "/tmp/ncrack-${NCRACK_VERSION}" "/tmp/ncrack-${NCRACK_VERSION}.tar.gz" /tmp/ncrack-offline

# 编译安装 Python（优先离线包，失败再走在线下载）
COPY tools/Python-*.tgz /tmp/
# Go 工具链离线包（amd64，可选；arm64 仍走在线下载回退）
COPY tools/go1.22.4.linux-amd64.tar.gz /tmp/
RUN set -eux; \
    PYTHON_TGZ="/tmp/Python-${PYTHON_VERSION}.tgz"; \
    if [ ! -s "${PYTHON_TGZ}" ]; then \
      for URL in \
        "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" \
        "https://mirrors.huaweicloud.com/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" \
        "https://mirrors.aliyun.com/python-release/source/Python-${PYTHON_VERSION}.tgz"; do \
        echo "try download ${URL}"; \
        wget -q --timeout=30 --tries=1 -O "${PYTHON_TGZ}" "${URL}" && break || true; \
      done; \
    fi; \
    test -s "${PYTHON_TGZ}" || (echo "[ERROR] Python source package not found: ${PYTHON_TGZ}" && exit 1); \
    cd /tmp; \
    tar xzf "Python-${PYTHON_VERSION}.tgz"; \
    cd "Python-${PYTHON_VERSION}"; \
    ./configure --prefix=/usr/local --with-ensurepip=install; \
    make -j"$(nproc)"; \
    make install; \
    ln -sf /usr/local/bin/python3.10 /usr/bin/python3; \
    ln -sf /usr/local/bin/python3.10 /usr/bin/python3.10; \
    ln -sf /usr/local/bin/pip3.10 /usr/bin/pip3; \
    ln -sf /usr/local/bin/pip3.10 /usr/bin/pip3.10; \
    python3 --version; \
    pip3 --version; \
    rm -rf "/tmp/Python-${PYTHON_VERSION}" "/tmp/Python-${PYTHON_VERSION}.tgz"

COPY ARL-NPoC/ /opt/ARL-NPoC/
COPY ARL/requirements.txt /code/requirements.txt
COPY ARL/native/arl_accel/ /code/native/arl_accel/
COPY tools/playwright/ /tmp/playwright-offline/
# 安装 Python 依赖，并安装 Playwright 浏览器（离线优先）
RUN set -eux; \
    pip3 install --upgrade "pip<24.1" "setuptools<81" wheel; \
    pip3 install --no-cache-dir -r /code/requirements.txt; \
    pip3 install --no-cache-dir -e /opt/ARL-NPoC/; \
    python3 -c 'import xing' >/dev/null 2>&1 || { echo '[ERROR] ARL-NPoC xing import validation failed'; exit 1; }; \
    pip3 install --no-cache-dir dnslib==0.9.16 pycryptodomex==3.16.0 requests_ntlm==1.1.0; \
    OFFLINE_DIR="/tmp/playwright-offline"; \
    ARCH="${TARGETARCH:-$(uname -m)}"; \
    case "$ARCH" in \
      amd64|x86_64) PW_ARCH="amd64" ;; \
      arm64|aarch64) PW_ARCH="arm64" ;; \
      *) PW_ARCH="$ARCH" ;; \
    esac; \
    mkdir -p "${PLAYWRIGHT_BROWSERS_PATH}"; \
    extract_playwright_tar() { \
      TAR_FILE="$1"; \
      TMP_PW_DIR="/tmp/ms-playwright-extract"; \
      rm -rf "${TMP_PW_DIR}" && mkdir -p "${TMP_PW_DIR}"; \
      tar -xzf "${TAR_FILE}" -C "${TMP_PW_DIR}"; \
      if [ -d "${TMP_PW_DIR}/ms-playwright" ]; then \
        cp -a "${TMP_PW_DIR}/ms-playwright/." "${PLAYWRIGHT_BROWSERS_PATH}/"; \
      else \
        cp -a "${TMP_PW_DIR}/." "${PLAYWRIGHT_BROWSERS_PATH}/"; \
      fi; \
      rm -rf "${TMP_PW_DIR}"; \
    }; \
    if [ -d "${OFFLINE_DIR}/ms-playwright" ] && [ -n "$(ls -A "${OFFLINE_DIR}/ms-playwright" 2>/dev/null)" ]; then \
      cp -a "${OFFLINE_DIR}/ms-playwright/." "${PLAYWRIGHT_BROWSERS_PATH}/"; \
    elif [ -f "${OFFLINE_DIR}/ms-playwright-${PW_ARCH}.tar.gz" ]; then \
      extract_playwright_tar "${OFFLINE_DIR}/ms-playwright-${PW_ARCH}.tar.gz"; \
    elif [ -f "${OFFLINE_DIR}/ms-playwright.tar.gz" ]; then \
      extract_playwright_tar "${OFFLINE_DIR}/ms-playwright.tar.gz"; \
    else \
      PLAYWRIGHT_DOWNLOAD_HOST=https://cdn.npmmirror.com/binaries/playwright \
        python3 -m playwright install chromium || \
      echo "[WARN] playwright browser install failed, screenshot will fallback when unavailable"; \
    fi

# 与 ncrack/python/go 同规：tools/rust/ 下有离线包则优先使用（国内网络
# 对 static.rust-lang.org 不稳，镜像站 rust-static 路径全部 404/假 200）。
# BuildKit bind mount：离线包只进构建过程，不作为 174MB 层烘进镜像。
# 在与生产运行时相同的 Rocky/glibc 基线中构建 abi3 wheel，避免构建机 glibc 版本高于运行时。
RUN --mount=type=bind,src=tools/rust,dst=/tmp/rust-offline set -eux; \
    ARCH="${TARGETARCH:-$(uname -m)}"; \
    case "$ARCH" in \
      amd64|x86_64) RUST_ARCH="x86_64-unknown-linux-gnu" ;; \
      arm64|aarch64) RUST_ARCH="aarch64-unknown-linux-gnu" ;; \
      *) echo "[ERROR] unsupported arch for rust/arl_accel build: $ARCH"; exit 1 ;; \
    esac; \
    RUST_TARBALL="/tmp/rust-${RUST_VERSION}-${RUST_ARCH}.tar.xz"; \
    if [ -s "/tmp/rust-offline/rust-${RUST_VERSION}-${RUST_ARCH}.tar.xz" ]; then \
      echo "use offline rust toolchain"; \
      cp "/tmp/rust-offline/rust-${RUST_VERSION}-${RUST_ARCH}.tar.xz" "${RUST_TARBALL}"; \
    else \
      for URL in \
        "https://static.rust-lang.org/dist/rust-${RUST_VERSION}-${RUST_ARCH}.tar.xz" \
        "https://mirrors.huaweicloud.com/rust-static/${RUST_VERSION}/rust-${RUST_VERSION}-${RUST_ARCH}.tar.xz"; do \
        echo "try download ${URL}"; \
        wget -q --timeout=60 --tries=1 -O "${RUST_TARBALL}" "${URL}" && break || true; \
      done; \
    fi; \
    xz -t "${RUST_TARBALL}" 2>/dev/null || { echo "[ERROR] rust tarball corrupt or HTML error page"; rm -f "${RUST_TARBALL}"; exit 1; }; \
    test -s "${RUST_TARBALL}" || (echo "[ERROR] Rust toolchain package not found: ${RUST_TARBALL}" && exit 1); \
    cd /tmp; \
    RUST_DIR="rust-${RUST_VERSION}-${RUST_ARCH}"; \
    tar -xJf "${RUST_TARBALL}" \
      --exclude="${RUST_DIR}/rust-docs" \
      --exclude="${RUST_DIR}/rust-docs-json-preview" \
      --exclude="${RUST_DIR}/rust-analysis-${RUST_ARCH}" \
      --exclude="${RUST_DIR}/clippy-preview" \
      --exclude="${RUST_DIR}/rustfmt-preview" \
      --exclude="${RUST_DIR}/rls-preview" \
      --exclude="${RUST_DIR}/rust-analyzer-preview" \
      --exclude="${RUST_DIR}/llvm-tools-preview" \
      --exclude="${RUST_DIR}/llvm-bitcode-linker-preview"; \
    "./${RUST_DIR}/install.sh" --prefix=/usr/local --disable-ldconfig \
      --components="rustc,cargo,rust-std-${RUST_ARCH}"; \
    rustc --version; \
    cargo --version; \
    pip3 install --no-cache-dir "maturin==${MATURIN_VERSION}"; \
    cd /code/native/arl_accel; \
    python3 -m maturin build --release --strip --compatibility manylinux_2_28 --interpreter python3; \
    pip3 install --no-cache-dir target/wheels/arl_accel-*.whl; \
    python3 /code/native/arl_accel/smoke_test.py; \
    cd /code; \
    rm -rf "/tmp/rust-${RUST_VERSION}-${RUST_ARCH}" "${RUST_TARBALL}" /root/.cargo /root/.rustup /code/native/arl_accel

COPY ARL/app/ app/
COPY ARL/docker/config-docker.yaml /code/docker/config-docker.yaml

# MassDNS 必须在目标架构内编译；仓库中的历史二进制仅作为源码安装兼容文件，不能直接进入多架构镜像。
ARG MASSDNS_COMMIT=6bfa47197d78e68b79041d494e280174cb2d6ae1
RUN set -eux; \
    MASSDNS_SRC="/tmp/massdns"; \
    timeout 180 git clone --depth 1 https://github.com/blechschmidt/massdns.git "${MASSDNS_SRC}"; \
    git -C "${MASSDNS_SRC}" checkout --detach "${MASSDNS_COMMIT}"; \
    make -C "${MASSDNS_SRC}"; \
    install -m 0755 "${MASSDNS_SRC}/bin/massdns" /code/app/tools/massdns; \
    /code/app/tools/massdns --version; \
    rm -rf "${MASSDNS_SRC}"

RUN mkdir -p /usr/local/share/arl
COPY ARL/native/arl_accel/smoke_test.py /usr/local/share/arl/arl_accel_smoke_test.py
COPY ARL/test/ test/
COPY --from=0 /frontend/dist/ frontend/
COPY ARL/docker/nginx.conf /etc/nginx/nginx.conf
COPY ARL/docker/worker/*.sh /usr/bin/

COPY tools/nuclei/nuclei_*_linux_*.zip /tmp/
COPY tools/nuclei/nuclei-templates/ /code/tools/nuclei-templates/
COPY tools/afrog/ /code/tools/afrog/
COPY tools/finger.json /code/tools/finger.json
COPY tools/wih/ /code/tools/wih/
COPY tools/GeoLite2/GeoLite2-* /data/GeoLite2/
COPY tools/dhparam.pem /etc/ssl/certs/dhparam.pem

# 安装源码版 WIH，解压 Nuclei，并执行基础自检
RUN set -eux; \
    ARCH="${TARGETARCH:-$(uname -m)}"; \
    case "$ARCH" in \
      amd64|x86_64) GO_ARCH="amd64" ;; \
      arm64|aarch64) GO_ARCH="arm64" ;; \
      *) echo "[ERROR] unsupported arch for go/wih build: $ARCH"; exit 1 ;; \
    esac; \
    GO_TGZ="/tmp/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"; \
    if [ -s "${GO_TGZ}" ]; then \
      echo "use offline go toolchain: ${GO_TGZ}"; \
    fi; \
    if [ ! -s "${GO_TGZ}" ]; then \
      for URL in \
        "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" \
        "https://dl.google.com/go/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" \
        "https://mirrors.aliyun.com/golang/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"; do \
        echo "try download ${URL}"; \
        wget -q --timeout=30 --tries=1 -O "${GO_TGZ}" "${URL}" && break || true; \
      done; \
    fi; \
    test -s "${GO_TGZ}" || (echo "[ERROR] go toolchain package not found: ${GO_TGZ}" && exit 1); \
    rm -rf /usr/local/go; \
    tar -C /usr/local -xzf "${GO_TGZ}"; \
    export PATH="/usr/local/go/bin:${PATH}"; \
    export GOPROXY="https://goproxy.cn,direct"; \
    go version; \
    cd /code/tools/wih; \
    GOOS=linux GOARCH="${GO_ARCH}" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /usr/bin/wih .; \
    node --version; \
    npm --version; \
    npm config set registry "${NPM_REGISTRY}"; \
    export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1; \
    if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi; \
    node -e "require('playwright'); console.log('node-playwright-ok')"; \
    mkdir -p /usr/local/share/arl; \
    rm -rf /usr/local/share/arl/wih; \
    cp -a /code/tools/wih /usr/local/share/arl/wih; \
    test -f /usr/local/share/arl/wih/config/rules.yml; \
    cd /code; \
    rm -rf /usr/local/go /root/go /tmp/go-build "${GO_TGZ}"; \
    ln -sf /code/app/tools/phantomjs /usr/bin/phantomjs; \
    case "$ARCH" in \
      amd64|x86_64) NUCLEI_ARCH="amd64" ;; \
      arm64|aarch64) NUCLEI_ARCH="arm64" ;; \
      *) echo "[ERROR] unsupported arch for nuclei build: $ARCH"; exit 1 ;; \
    esac; \
    NUCLEI_ZIP="/tmp/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip"; \
    if [ ! -s "$NUCLEI_ZIP" ]; then \
      for URL in \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" \
        "https://mirror.ghproxy.com/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip"; do \
        echo "try download ${URL}"; \
        wget -q --timeout=30 --tries=1 --no-check-certificate -O "$NUCLEI_ZIP" "$URL" && break || true; \
      done; \
    fi; \
    test -s "$NUCLEI_ZIP" || (echo "[ERROR] nuclei package not found: $NUCLEI_ZIP" && exit 1); \
    unzip -q "${NUCLEI_ZIP}" nuclei; \
    mv nuclei /usr/bin/; \
    rm -f /tmp/nuclei_*.zip; \
    chmod +x /usr/local/bin/ncrack /usr/bin/wih /usr/bin/*.sh /usr/bin/nuclei; \
    cp app/config.yaml.example app/config.yaml; \
    python3 -c "import psutil, flask, pymongo, celery, dnslib, playwright"; \
    python3 -c "from Cryptodome.Cipher import AES"; \
    python3 -c "from requests_ntlm import HttpNtlmAuth"; \
    ncrack -V >/dev/null; \
    nmap --version >/dev/null; \
    nuclei -version >/dev/null; \
    test -x /usr/bin/wih
