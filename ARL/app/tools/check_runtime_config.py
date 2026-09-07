#!/usr/bin/env python3
"""运行期配置安全预检。

该检查只输出配置路径和字段名，不输出任何敏感值；部署凭据仍由 .env
提供，运行配置文件只承载非凭据模板和用户本地的 provider 配置。
"""
import argparse
import os
import re
import stat
import sys
from pathlib import Path

import yaml


EMBEDDED_CREDENTIAL_URL = re.compile(r"^[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@", re.I)
PROTECTED_URL_PATHS = (
    ("MONGO", "URI"),
    ("CELERY", "BROKER_URL"),
)


def _get_path(document, path):
    current = document
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _has_embedded_credentials(value):
    return isinstance(value, str) and bool(EMBEDDED_CREDENTIAL_URL.search(value.strip()))


def validate_runtime_config(runtime_path, template_path=None, fix_permissions=False):
    runtime = Path(runtime_path).expanduser()
    if not runtime.is_file():
        return ["runtime config file missing"], []
    if runtime.is_symlink():
        return ["runtime config must not be a symlink"], []
    runtime = runtime.resolve()

    failures = []
    warnings = []
    try:
        document = yaml.safe_load(runtime.read_text(encoding="utf-8")) or {}
    except Exception:
        return ["runtime config YAML cannot be parsed"], []
    if not isinstance(document, dict):
        return ["runtime config root must be a mapping"], []

    for path in PROTECTED_URL_PATHS:
        if _has_embedded_credentials(_get_path(document, path)):
            failures.append("embedded credentials in {}".format(".".join(path)))

    mode = stat.S_IMODE(runtime.stat().st_mode)
    if mode & 0o077:
        if fix_permissions:
            try:
                os.chmod(runtime, mode & 0o700)
            except OSError:
                failures.append("runtime config permissions must be owner-only")
        else:
            failures.append("runtime config permissions must be owner-only")

    if template_path:
        template = Path(template_path).expanduser()
        try:
            template_document = yaml.safe_load(template.read_text(encoding="utf-8")) or {}
        except Exception:
            failures.append("runtime config template YAML cannot be parsed")
        else:
            for path in PROTECTED_URL_PATHS:
                if _has_embedded_credentials(_get_path(template_document, path)):
                    failures.append("embedded credentials in template {}".format(".".join(path)))

    return failures, warnings


def main():
    parser = argparse.ArgumentParser(description="检查运行期配置的凭据边界和文件权限")
    parser.add_argument("--runtime", required=True, help="运行期配置文件路径")
    parser.add_argument("--template", default="", help="版本配置模板路径")
    parser.add_argument("--fix-permissions", action="store_true", help="将运行配置收敛为 owner-only")
    parser.add_argument("--quiet", action="store_true", help="通过时不输出摘要")
    args = parser.parse_args()

    failures, warnings = validate_runtime_config(
        args.runtime,
        template_path=args.template or None,
        fix_permissions=args.fix_permissions,
    )
    if failures:
        for failure in failures:
            print("[RUNTIME-CONFIG-CHECK] {}".format(failure), file=sys.stderr)
        return 1
    if not args.quiet:
        print("[RUNTIME-CONFIG-CHECK] OK: runtime file and credential boundary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
