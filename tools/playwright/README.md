# Playwright 离线包说明

为了避免构建阶段联网下载 Chromium 过慢，可以提前准备离线包并放到本目录。

## 支持的离线格式（按优先级）

1. `ms-playwright/` 目录（推荐）
2. `ms-playwright-<arch>.tar.gz`（例如 `ms-playwright-amd64.tar.gz`、`ms-playwright-arm64.tar.gz`）
3. `ms-playwright.tar.gz`（通用）

> `<arch>` 对应构建架构：`amd64` 或 `arm64`。

## 如何生成离线包

在一台可以正常下载 Playwright 浏览器的 Linux 机器上执行：

```bash
python3 -m pip install "playwright>=1.40"
export PLAYWRIGHT_BROWSERS_PATH=/tmp/ms-playwright
python3 -m playwright install chromium

# amd64 示例
tar -czf ms-playwright-amd64.tar.gz -C /tmp ms-playwright
```

然后把 `ms-playwright-amd64.tar.gz`（或 `arm64` 对应包）复制到当前目录。

## 构建行为

- 构建时会优先使用本目录离线包。
- 若未找到离线包，才会回退到在线下载 `playwright chromium`。
- 在线下载失败不会中断构建，运行时会按代码逻辑回退到 PhantomJS。
