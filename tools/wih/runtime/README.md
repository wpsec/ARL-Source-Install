# WIH Runtime Driver 契约

本文档说明 `WIH` 运行时参数采集链路与 external driver 的接入协议。

## 1. 目标

`WIH` 本体只负责：

- CLI 参数解析
- 预算控制
- 结果归一化
- 同 host 过滤
- 输出结构化 `endpoint / parameter`

真正的浏览器运行时采集器可以作为外部 driver 单独实现，例如：

- `Playwright + CDP`
- `Puppeteer`
- 自研浏览器自动化脚本

当前仓库也已经内置一版最小 `Playwright` driver：

- [playwright_driver.js](/Users/eric.sy.wu/Documents/Github/newui/ARL-Source-Install/tools/wih/runtime/playwright_driver.js)

它的定位是：

- 为 `WIH` 提供最小真实浏览器运行时采集能力
- 优先覆盖页面加载期请求与少量低风险交互
- 仍然把结果归一化、过滤和结构化输出留给 `WIH` 主链路

## 2. 启用方式

默认情况下，`WIH` 已启用内置 `Playwright` 运行时采集。

等价默认值为：

- `--runtime-enable=true`
- `--runtime-driver=playwright`
- `--runtime-max-pages=8`
- `--runtime-max-actions=20`
- `--runtime-max-requests=120`

如果你只是正常执行：

```bash
./wih -t https://example.com
```

并且本地具备 `node + playwright`，就会直接尝试运行内置 driver。

若需显式指定，也可以继续这样写：

```bash
./wih -t https://example.com \
  --runtime-enable \
  --runtime-driver playwright
```

若要继续接入自定义 external driver：

```bash
./wih -t https://example.com \
  --runtime-enable \
  --runtime-driver external \
  --runtime-command "python3 tools/wih/runtime/external_driver_example.py"
```

使用内置 `playwright` 驱动前，需要本地具备：

- `node`
- `playwright`
- 对应浏览器运行依赖

推荐在 `tools/wih` 目录执行：

```bash
cd tools/wih
npm install
npx playwright install chromium
```

说明：

- 内置 driver 使用的是 Node 版 `Playwright`
- 仅安装 Python 版 `playwright` 不会满足 `require('playwright')`
- 当前只要求 `chromium`，不需要额外下载全部浏览器

若 `playwright` 已安装但 `node` 不在默认路径，可通过 `--runtime-command` 覆盖调用命令。

若运行环境缺失，`WIH` 会提醒并自动退回静态扫描。

## 3. 输入协议

`WIH` 会通过 `stdin` 向 runtime driver 发送 JSON：

```json
{
  "target_url": "https://example.com",
  "default_headers": {
    "User-Agent": "Mozilla/5.0 ...",
    "Accept": "application/json, text/plain, */*"
  },
  "max_pages": 8,
  "max_actions": 20,
  "max_requests": 120,
  "follow_redirect": false,
  "timeout_sec": 20
}
```

字段含义：

- `target_url`
  当前单站点扫描目标
- `default_headers`
  建议 external driver 复用的默认请求头
- `max_pages`
  页面探索预算
- `max_actions`
  交互预算
- `max_requests`
  请求采集预算
- `follow_redirect`
  是否跟随重定向
- `timeout_sec`
  单次 external driver 总超时

## 4. 输出协议

runtime driver 通过 `stdout` 返回 JSON：

```json
{
  "endpoints": [
    {
      "endpoint_id": "optional",
      "url": "https://example.com/api/search",
      "method": "POST",
      "content_type": "application/json",
      "body_kind": "json",
      "trigger_context": {
        "page": "https://example.com/search",
        "event": "click",
        "dom_hint": "button.search"
      },
      "request_template": {
        "headers": {
          "Content-Type": "application/json"
        },
        "query": {
          "scene": "web"
        },
        "body": {
          "keyword": "<value>",
          "pageNo": "<value>"
        }
      }
    }
  ],
  "parameters": [
    {
      "endpoint_id": "optional",
      "param_name": "keyword",
      "location": "body",
      "param_type": "string",
      "example": "test"
    }
  ]
}
```

`stdin` 请求体还支持：

- `default_headers`
  - 会作为 Playwright context 的默认请求头附加到运行时请求
- `proxy_url`
  - 若存在，会在浏览器启动时作为代理配置使用

## 5. 内置 Playwright driver 当前行为

当前仓库自带的 `playwright_driver.js` 为 MVP 实现，已覆盖：

- `window.fetch`
- `XMLHttpRequest.open/send/setRequestHeader`
- `navigator.sendBeacon`
- `WebSocket`
- `Playwright page.on('request')` 网络请求观测
- `URLSearchParams`
- `FormData`
- `JSON / GraphQL body` 的基础解析
- 同 host 页面浅层探索

同时会执行少量低风险交互：

- 搜索类输入框填充
- `select` 切换
- 低风险 `GET/搜索表单` 提交
- `tab` 切换
- 搜索/筛选/下一页/更多 这类弱副作用按钮点击

页面探索策略当前为：

- 先访问当前目标页
- 再从页面里的 `a[href] / iframe[src] / GET form action` 中提取同 host 候选页
- 按 `max_pages` 预算做浅层顺序探索
- 每页仅执行预算内的低风险交互，不做明显高副作用动作

endpoint 去重当前也不再只按“完整 URL 值”处理，而是更偏向“接口面”维度：

- `method`
- `origin + path`
- `query 参数键集合`
- `body 参数键集合`
- `body_kind`

这样像分页、筛选值变化这类请求，不会轻易把同一接口面拆成大量近似重复记录。

当前 runtime 输出也会开始补齐：

- `endpoint.page_url`
- `parameter.source=runtime`
- `parameter.source_detail.page_url`
- `parameter.occurrence_count`

默认仍然会避免：

- `submit/save/delete/update/upload/pay` 等明显高副作用动作
- 跨 host 请求采集

## 6. 当前主链路会自动补的内容

runtime driver 不需要完全理解 `WIH` 的内部模型。

当前 `WIH` 主链路会自动补：

- `endpoint_id`
- `method`
- `protocol`
- `source_types=runtime_hook`
- `body_kind / content_type`
- `request_template`
- `request_packet`
- `parameter.location`
- `parameter.param_type`
- `parameter.example/default`
- `is_pii`
- `entropy`

## 7. 当前主链路会自动做的过滤

runtime driver 返回的结果不会被无条件信任。

`WIH` 会继续执行：

- 同 host 过滤
- endpoint 去重
- parameter 去重
- endpoint_id 映射
- request template 规范化

也就是说：

- external driver 只需要尽量把真实运行时观测到的基础信息吐出来
- 结果标准化和最终输出仍由 `WIH` 完成

## 8. 示例脚本

仓库中提供了一个最小可运行示例：

- [external_driver_example.py](/Users/eric.sy.wu/Documents/Github/newui/ARL-Source-Install/tools/wih/runtime/external_driver_example.py)
- [playwright_driver.js](/Users/eric.sy.wu/Documents/Github/newui/ARL-Source-Install/tools/wih/runtime/playwright_driver.js)

其中：

- `external_driver_example.py` 不实现真实浏览器 Hook，只演示：
  - 读取 `stdin` JSON
  - 构造最小 runtime 结果
  - 输出 `stdout` JSON
- `playwright_driver.js` 则提供一版最小真实浏览器实现，适合本地已有 `Playwright` 环境时直接试跑

后续若需要更强的登录态、复杂单页应用、更多交互策略，仍建议继续基于当前契约替换或扩展浏览器驱动实现。
