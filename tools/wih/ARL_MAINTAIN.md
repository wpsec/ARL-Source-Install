# ARL Maintained WIH

本目录为 ARL 自维护的 `wih` 源码版本，目标是保持与 ARL 现有调用协议兼容，同时支持后续规则与功能的可持续演进。

## 兼容约定

当前实现兼容 ARL 调用参数：

- `-r, --rule-config`
- `-J, --output-json`
- `-o, --output`
- `-t, --target`
- `--concurrency`
- `--concurrency-per-site`
- `--log-level`
- `--disable-ak-sk-output`
- `--proxy`
- `--version`

输出 JSON 行协议与 ARL `InfoHunter.dump_result()` 对齐：

```json
{
  "target": "https://example.com",
  "records": [
    {
      "id": "rule_id",
      "content": "...",
      "source": "https://example.com",
      "tag": "",
      "hash": 123
    }
  ]
}
```

## 规则模板

- 默认模板：`tools/wih/config/rules.yml`
- ARL 默认规则路径：`Config.WIH_RULE_PATH`（已默认指向上述路径）

## 降噪约定

- `email` 规则需要尽量避免将静态资源文件名误识别成邮箱，例如 `avatar@2x.png`、`logo@2x-xxxx.png`
- `path` 规则优先保留“可拼接、可探测、接近真实业务路由”的路径线索，避免把 JS 代码片段、外部主机样式伪路径、静态资源路径大量带入结果与 `path_url` 探测
- 当调整 `tools/wih/config/rules.yml` 时，应同步维护 `tools/wih/util/rules_embed.yaml`，确保规则文件缺失或加载失败时的 embedded fallback 与主规则模板行为一致
- ARL 在 `ARL/app/services/infoHunter.py` 的 `InfoHunter.dump_result()` 侧还会做一层解析期兜底过滤，因此规则收紧应以“减少无效匹配和无效探测”为主，避免把所有噪声控制都堆到后处理
