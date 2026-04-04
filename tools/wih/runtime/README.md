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

## 2. 启用方式

```bash
./wih -t https://example.com \
  --runtime-enable \
  --runtime-driver external \
  --runtime-command "python3 tools/wih/runtime/external_driver_example.py"
```

## 3. 输入协议

`WIH` 会通过 `stdin` 向 external driver 发送 JSON：

```json
{
  "target_url": "https://example.com",
  "default_headers": {
    "User-Agent": "Mozilla/5.0 ...",
    "Accept": "application/json, text/plain, */*"
  },
  "max_pages": 3,
  "max_actions": 8,
  "max_requests": 40,
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

external driver 通过 `stdout` 返回 JSON：

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

## 5. 当前主链路会自动补的内容

external driver 不需要完全理解 `WIH` 的内部模型。

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

## 6. 当前主链路会自动做的过滤

external driver 返回的结果不会被无条件信任。

`WIH` 会继续执行：

- 同 host 过滤
- endpoint 去重
- parameter 去重
- endpoint_id 映射
- request template 规范化

也就是说：

- external driver 只需要尽量把真实运行时观测到的基础信息吐出来
- 结果标准化和最终输出仍由 `WIH` 完成

## 7. 示例脚本

仓库中提供了一个最小可运行示例：

- [external_driver_example.py](/Users/eric.sy.wu/Documents/Github/newui/ARL-Source-Install/tools/wih/runtime/external_driver_example.py)

这个脚本不实现真实浏览器 Hook，只演示：

- 读取 `stdin` JSON
- 构造最小 runtime 结果
- 输出 `stdout` JSON

后续可以直接替换成真实的浏览器驱动实现。
