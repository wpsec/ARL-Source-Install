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
