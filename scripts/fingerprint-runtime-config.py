#!/usr/bin/env python3
"""生成运行配置的非敏感指纹输入，只输出 allowlist 字段。"""

import argparse
import json
import sys
from pathlib import Path

import yaml


SAFE_KEYS = frozenset(
    {
        "API_UNIFIED_ENABLE",
        "API_UNIFIED_FALLBACK_ENABLE",
        "API_DOCUMENT_MAX_TARGETS",
        "API_DOCUMENT_MAX_SIZE_BYTES",
        "API_DOCUMENT_MAX_DEPTH",
        "API_DOCUMENT_MAX_REF_COUNT",
        "API_EXTERNAL_REF_ENABLE",
        "GRAPHQL_SCHEMA_ENABLE",
        "GRAPHQL_SCHEMA_MAX_SIZE_BYTES",
        "GRAPHQL_SCHEMA_MAX_DEPTH",
        "GRAPHQL_SCHEMA_SUMMARY_MAX_BYTES",
        "WSDL_PARSE_ENABLE",
        "WSDL_MAX_SIZE_BYTES",
        "API_ENDPOINT_PROBE_MAX_TARGETS",
        "API_ENDPOINT_CLAIM_LEASE_SEC",
        "RUST_ACCEL_ENABLE",
        "RUST_ACCEL_FALLBACK_ENABLE",
        "RUST_ACCEL_API_UNIFIED_MODE",
        "RUST_ACCEL_API_UNIFIED_RUST_STAGES",
        "WIH_TOTAL_BUDGET_SEC",
        "WIH_CONCURRENCY",
        "WIH_CONCURRENCY_PER_SITE",
        "WIH_MAX_BATCH_SIZE",
        "WIH_PERIODIC_REUSE_ENABLE",
        "WIH_ADAPTIVE_RUNTIME_ENABLE",
        "WIH_RUNTIME_ENABLE",
        "WIH_RUNTIME_DRIVER",
        "WIH_RUNTIME_MAX_PAGES",
        "WIH_RUNTIME_MAX_ACTIONS",
        "WIH_RUNTIME_MAX_REQUESTS",
        "URLFINDER_SENSITIVE_ENABLE",
        "URLFINDER_SENSITIVE_MAX_TARGETS",
        "URLFINDER_SENSITIVE_INCLUDE_JS",
        "URLFINDER_URL_PROBE_ENABLE",
        "URLFINDER_URL_PROBE_MAX_TARGETS",
        "URLFINDER_URL_PROBE_CONCURRENCY",
        "PORT_SCAN_TARGET_BATCH_SIZE",
        "PORT_SCAN_BATCH_CONCURRENCY",
        "PORT_SCAN_BATCH_TIMEOUT_SEC",
        "TASK_FINALIZER_DRAIN_ROUNDS",
        "TASK_FINALIZER_PENDING_MAX",
        "LEDGER_DEGRADED_THRESHOLD",
    }
)


def flatten_allowlisted(value, path=()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from flatten_allowlisted(item, path + (str(key),))
    elif path and path[-1] in SAFE_KEYS:
        yield ".".join(path), value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()

    try:
        with args.config.open(encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
    except (OSError, yaml.YAMLError) as exc:
        print("读取配置失败: {}".format(exc), file=sys.stderr)
        return 2

    if not isinstance(document, dict):
        print("配置顶层必须是对象", file=sys.stderr)
        return 2

    values = {
        key: value for key, value in flatten_allowlisted(document)
    }
    print(
        json.dumps(
            {"schema_version": 1, "values": values},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
