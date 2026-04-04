#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WIH external runtime driver 最小示例。

说明：
- 从 stdin 读取 runtime 请求 JSON
- 向 stdout 返回 endpoints / parameters JSON
- 仅作为接入契约示例，不提供真实浏览器 Hook 能力

推荐后续替换为：
- Playwright + CDP
- Puppeteer
- 自研浏览器自动化驱动
"""

import json
import sys
from urllib.parse import urlparse


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        json.dump({"endpoints": [], "parameters": []}, sys.stdout, ensure_ascii=False)
        return

    try:
        payload = json.loads(raw)
    except Exception:
        json.dump({"endpoints": [], "parameters": []}, sys.stdout, ensure_ascii=False)
        return

    target_url = str(payload.get("target_url") or "").strip()
    if not target_url:
        json.dump({"endpoints": [], "parameters": []}, sys.stdout, ensure_ascii=False)
        return

    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        json.dump({"endpoints": [], "parameters": []}, sys.stdout, ensure_ascii=False)
        return

    endpoint_url = f"{parsed.scheme}://{parsed.netloc}/runtime/example"
    result = {
        "endpoints": [
            {
                "endpoint_id": "external-demo-endpoint",
                "url": endpoint_url,
                "method": "POST",
                "content_type": "application/json",
                "body_kind": "json",
                "trigger_context": {
                    "page": target_url,
                    "event": "runtime_example",
                    "dom_hint": "external_driver_example",
                },
                "request_template": {
                    "body": {
                        "keyword": "<value>",
                        "pageNo": "<value>",
                    }
                },
            }
        ],
        "parameters": [
            {
                "endpoint_id": "external-demo-endpoint",
                "param_name": "keyword",
                "location": "body",
                "example": "test",
            },
            {
                "endpoint_id": "external-demo-endpoint",
                "param_name": "pageNo",
                "location": "body",
                "example": "1",
            },
        ],
    }
    json.dump(result, sys.stdout, ensure_ascii=False)


if __name__ == "__main__":
    main()
