# Playwright 离线包说明

为了避免构建阶段联网下载 Chromium 过慢，可以提前准备离线包并放到本目录。

## 支持的离线格式（按优先级）

1. `ms-playwright/` 目录（推荐）
2. `ms-playwright-<arch>.tar.gz`（例如 `ms-playwright-amd64.tar.gz`、`ms-playwright-arm64.tar.gz`）
3. `ms-playwright.tar.gz`（通用）

> `<arch>` 对应构建架构：`amd64` 或 `arm64`。

## 如何生成离线包（推荐）

推荐按 `tools/wih` 中锁定的 Node 版 `Playwright` 生成离线包，这样 Docker 构建时前置离线浏览器目录能同时满足 `WIH` runtime，后续 `npm ci` 阶段不会再次触发浏览器下载。

如果宿主机已经安装 `node/npm`，在项目根目录执行：

```bash
cd tools/wih
npm ci --ignore-scripts --no-audit --no-fund
rm -rf /tmp/ms-playwright
export PLAYWRIGHT_BROWSERS_PATH=/tmp/ms-playwright
npx playwright install chromium

# amd64 示例
tar -czf ../playwright/ms-playwright-amd64.tar.gz -C /tmp ms-playwright
```

如果宿主机没有 `npm`，推荐直接使用 Docker 的 Node 镜像生成，仍然在项目根目录执行，代理地址自行调整：

```bash
docker run --rm \
  -v "$PWD":/repo \
  -w /repo/tools/wih \
  -e PLAYWRIGHT_BROWSERS_PATH=/tmp/ms-playwright \
  node:20.20.1-bookworm \
  bash -lc 'export https_proxy=http://192.168.10.107:7897 http_proxy=http://192.168.10.107:7897 all_proxy=socks5://192.168.10.107:7897 && npm ci --ignore-scripts --no-audit --no-fund && rm -rf /tmp/ms-playwright && npx playwright install chromium && tar -czf /repo/tools/playwright/ms-playwright-amd64.tar.gz -C /tmp ms-playwright'
```

如果只按 Python 版 `playwright` 生成离线包，也能被 Dockerfile 解压使用；但当 Python 版与 `tools/wih/package-lock.json` 中的 Node 版 `playwright` 版本不一致时，浏览器 revision 可能不同，`WIH` runtime 运行时可能找不到对应 Chromium。

## 构建行为

- 构建时会优先使用本目录离线包。
- 若未找到离线包，才会回退到在线下载 `playwright chromium`。
- 在线下载失败不会中断构建，运行时会按代码逻辑回退到 PhantomJS。
- `tools/wih` 的 Node 依赖安装阶段会设置 `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`，不会再次执行 `npx playwright install chromium`。
