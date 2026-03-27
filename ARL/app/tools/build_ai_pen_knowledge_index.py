#!/usr/bin/env python3
"""
构建 AI 渗透测试知识索引（面向 tools/poc 三类语料）。

用途：
1. 将 tools/poc/POC、tools/poc/vulhub、tools/poc/PoC-in-GitHub 的文件路径与文本片段做轻量分词；
2. 生成 token -> 来源/样例路径索引，供 AI 渗透测试阶段快速检索参考；
3. 输出到 ARL/docker/ai/sop/ai_pen_knowledge_index.json（可自定义）。
"""

import argparse
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path


TOKEN_STOPWORDS = {
    "http", "https", "www", "com", "org", "net", "cn",
    "cve", "cnvd", "cnnvd", "poc", "exploit", "vuln", "vulnerability",
    "test", "testing", "demo", "example", "readme", "docs", "document",
    "json", "yaml", "yml", "txt", "md", "markdown",
    "api", "app", "service", "server", "client", "request", "response",
    "漏洞", "测试", "脚本", "利用", "示例", "说明", "文档",
}

ALLOWED_SUFFIX = {
    ".md", ".markdown", ".txt", ".yaml", ".yml", ".json",
    ".py", ".sh", ".http", ".js", ".ts", ".xml", ".ini", ".conf",
}

GENERIC_HEADINGS = {
    "fofa", "favicon", "poc", "exp", "描述", "漏洞描述", "说明", "参考", "复现", "利用", "影响范围",
    "修复建议", "复测", "payload", "请求包", "response", "proof", "demo",
}

VULN_TYPE_PATTERNS = {
    "api_doc": (r"swagger", r"openapi", r"api[ -]?docs", r"postman", r"接口文档"),
    "auth_bypass": (r"登录绕过", r"认证绕过", r"未授权", r"鉴权绕过", r"身份验证绕过", r"authentication bypass"),
    "cmdi": (r"命令执行", r"rce", r"remote code execution", r"command execution", r"代码执行"),
    "file_read": (r"任意文件读取", r"文件读取", r"目录遍历", r"download", r"file read", r"traversal"),
    "file_upload": (r"任意文件上传", r"文件上传", r"upload"),
    "idor": (r"越权", r"idor", r"任意用户", r"权限绕过"),
    "info_leak": (r"信息泄露", r"敏感信息泄露", r"账号密码泄露", r"password leak", r"disclosure"),
    "jwt": (r"jwt", r"json web token"),
    "sqli": (r"sql注入", r"sqli", r"sql injection"),
    "ssrf": (r"ssrf", r"服务端请求伪造"),
    "weak_password": (r"弱口令", r"default login", r"default credential"),
    "websocket": (r"websocket", r"socket\.io", r"sockjs"),
    "xss": (r"xss", r"cross[- ]site scripting"),
    "xxe": (r"xxe", r"xml external entity", r"外部实体注入"),
}


def resolve_repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current.parent] + list(current.parents):
        if not (parent / "tools").is_dir():
            continue
        if (parent / "ARL").is_dir():
            return parent
        if (parent / "app").is_dir() and (parent / "docker").is_dir():
            return parent
    if len(current.parents) >= 4:
        return current.parents[3]
    return Path.cwd()


def resolve_path(path_text: str, default_path: Path) -> Path:
    text = str(path_text or "").strip()
    if not text:
        return default_path
    path = Path(text).expanduser()
    if path.is_absolute():
        return path
    return (Path.cwd() / path).resolve()


def default_source_paths(repo_root: Path):
    base = repo_root / "tools" / "poc"
    return {
        "poc_library": base / "POC",
        "vulhub": base / "vulhub",
        "poc_in_github": base / "PoC-in-GitHub",
    }


def default_output_path(repo_root: Path) -> Path:
    candidates = [
        repo_root / "ARL" / "docker" / "ai" / "sop" / "ai_pen_knowledge_index.json",
        repo_root / "docker" / "ai" / "sop" / "ai_pen_knowledge_index.json",
    ]
    for candidate in candidates:
        if candidate.parent.exists() or candidate.parent.parent.exists():
            return candidate
    return repo_root / "ai_pen_knowledge_index.json"


def normalize_token(value: str) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9_]+", "", text)
    if len(text) < 3:
        return ""
    if text.isdigit():
        return ""
    if text in TOKEN_STOPWORDS:
        return ""
    return text[:64]


def normalize_label(value: str, max_len: int = 96) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:max_len]


def extract_tokens(text: str, max_tokens=120):
    token_list = []
    seen = set()
    raw = str(text or "").lower()
    if not raw:
        return token_list
    for item in re.split(r"[^a-z0-9_]+", raw):
        token = normalize_token(item)
        if not token or token in seen:
            continue
        seen.add(token)
        token_list.append(token)
        if len(token_list) >= max_tokens:
            break
    return token_list


def safe_read_text(file_path: Path, max_read_bytes: int):
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_read_bytes)
    except Exception:
        return ""


def extract_markdown_title(text: str, fallback: str = "") -> str:
    content = str(text or "")
    match = re.search(r"^\s*#\s+(.+?)\s*$", content, flags=re.M)
    if match:
        return normalize_label(match.group(1), 120)
    return normalize_label(fallback, 120)


def detect_vuln_types(text: str, max_items: int = 6):
    content = str(text or "").lower()
    result = []
    for vuln_type, patterns in VULN_TYPE_PATTERNS.items():
        if any(re.search(pattern, content, flags=re.I) for pattern in patterns):
            result.append(vuln_type)
            if len(result) >= max_items:
                break
    return result


def extract_entry_paths(text: str, max_items: int = 6):
    content = str(text or "")
    result = []
    seen = set()

    def append_item(raw_value: str):
        value = normalize_label(raw_value, 180)
        if not value or value in seen:
            return
        seen.add(value)
        result.append(value)

    for match in re.finditer(r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+([^\s]+)", content, flags=re.I):
        append_item(match.group(1))
        if len(result) >= max_items:
            return result

    for match in re.finditer(r"https?://[^\s\"'<>`]{4,2048}", content, flags=re.I):
        raw = str(match.group(0) or "").strip()
        try:
            from urllib.parse import urlsplit
            parsed = urlsplit(raw)
            append_item(parsed.path + (("?"+parsed.query) if parsed.query else ""))
        except Exception:
            append_item(raw)
        if len(result) >= max_items:
            return result

    return result


def extract_verify_actions(text: str, max_items: int = 4):
    content = str(text or "")
    result = []
    seen = set()

    for match in re.finditer(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", content, flags=re.M):
        heading = normalize_label(match.group(1), 80).lower()
        if not heading or heading in GENERIC_HEADINGS or heading in seen:
            continue
        seen.add(heading)
        result.append(heading)
        if len(result) >= max_items:
            return result

    for match in re.finditer(r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+([^\s]+)", content, flags=re.I):
        action = normalize_label("{} {}".format(str(match.group(0) or "").split()[0].upper(), match.group(1)), 120)
        if action and action not in seen:
            seen.add(action)
            result.append(action)
        if len(result) >= max_items:
            return result
    return result


def build_record_ref(source_id: str, source_root: Path, file_path: Path, text: str):
    try:
        rel_path = str(file_path.relative_to(source_root)).replace("\\", "/")
    except Exception:
        rel_path = str(file_path)

    rel_parts = Path(rel_path).parts
    parent_name = normalize_label(file_path.parent.name, 64)
    group_name = normalize_label(rel_parts[0] if rel_parts else "", 64)
    title = extract_markdown_title(text, fallback=file_path.stem)
    vuln_types = detect_vuln_types("{}\n{}".format(rel_path, text))
    entry_paths = extract_entry_paths(text)
    verify_actions = extract_verify_actions(text)
    product_labels = [item for item in [parent_name, group_name] if item]

    return {
        "source": source_id,
        "path": rel_path,
        "title": title,
        "product_labels": product_labels[:3],
        "vuln_types": vuln_types[:6],
        "entry_paths": entry_paths[:6],
        "verify_actions": verify_actions[:4],
    }


def iter_candidate_files(root_dir: Path):
    if not root_dir.is_dir():
        return []
    files = []
    for file_path in root_dir.rglob("*"):
        if not file_path.is_file():
            continue
        if ".git" in file_path.parts:
            continue
        files.append(file_path)
    files.sort()
    return files


def build_index(
    source_paths: dict,
    max_files_per_source: int = 20000,
    max_read_bytes: int = 65536,
    min_token_count: int = 2,
    max_index_tokens: int = 8000,
    max_samples_per_token: int = 8,
):
    token_index = {}
    source_stats = []

    for source_id, source_path in source_paths.items():
        source_path = Path(source_path)
        files = iter_candidate_files(source_path)
        indexed_files = 0

        for file_path in files:
            if indexed_files >= max_files_per_source:
                break

            indexed_files += 1
            rel_path = str(file_path.relative_to(source_path)).replace("\\", "/")
            suffix = file_path.suffix.lower()
            token_pool = set()

            # 路径分词
            token_pool.update(extract_tokens(rel_path, max_tokens=60))
            token_pool.update(extract_tokens(file_path.stem, max_tokens=30))

            # 文本分词（仅常见文本文件，且仅读取前 N 字节）
            text = ""
            if suffix in ALLOWED_SUFFIX:
                text = safe_read_text(file_path, max_read_bytes=max_read_bytes)
                if text:
                    token_pool.update(extract_tokens(text, max_tokens=120))

            record_ref = build_record_ref(source_id, source_path, file_path, text)

            for token in token_pool:
                bucket = token_index.get(token)
                if bucket is None:
                    bucket = {
                        "count": 0,
                        "sources": defaultdict(int),
                        "samples": [],
                        "product_labels": defaultdict(int),
                        "vuln_types": defaultdict(int),
                        "entry_paths": [],
                        "verify_actions": [],
                        "record_refs": [],
                    }
                    token_index[token] = bucket

                bucket["count"] += 1
                bucket["sources"][source_id] += 1
                if len(bucket["samples"]) < max_samples_per_token:
                    bucket["samples"].append("{}:{}".format(source_id, rel_path))
                for label in record_ref.get("product_labels", []):
                    label_text = normalize_label(label, 64)
                    if label_text:
                        bucket["product_labels"][label_text] += 1
                for vuln_type in record_ref.get("vuln_types", []):
                    vuln_text = normalize_label(vuln_type, 32)
                    if vuln_text:
                        bucket["vuln_types"][vuln_text] += 1
                for entry_path in record_ref.get("entry_paths", []):
                    entry_text = normalize_label(entry_path, 180)
                    if entry_text and entry_text not in bucket["entry_paths"] and len(bucket["entry_paths"]) < 6:
                        bucket["entry_paths"].append(entry_text)
                for verify_action in record_ref.get("verify_actions", []):
                    action_text = normalize_label(verify_action, 120)
                    if action_text and action_text not in bucket["verify_actions"] and len(bucket["verify_actions"]) < 4:
                        bucket["verify_actions"].append(action_text)
                if len(bucket["record_refs"]) < 4:
                    bucket["record_refs"].append(record_ref)

        source_stats.append(
            {
                "id": source_id,
                "path": str(source_path),
                "exists": source_path.is_dir(),
                "file_count": len(files),
                "indexed_file_count": indexed_files,
            }
        )

    # 裁剪 token 数量，保证索引可读且可加载
    filtered = [
        (token, item)
        for token, item in token_index.items()
        if int(item.get("count", 0)) >= min_token_count
    ]
    filtered.sort(key=lambda pair: (-int(pair[1].get("count", 0)), pair[0]))
    filtered = filtered[:max_index_tokens]

    normalized_token_index = {}
    for token, item in filtered:
        source_counter = item.get("sources", {})
        normalized_sources = {
            key: int(value)
            for key, value in sorted(source_counter.items(), key=lambda kv: kv[0])
            if int(value) > 0
        }
        normalized_token_index[token] = {
            "count": int(item.get("count", 0)),
            "sources": normalized_sources,
            "samples": list(item.get("samples", [])),
            "product_labels": [
                {"name": key, "count": int(value)}
                for key, value in sorted(
                    (item.get("product_labels") or {}).items(),
                    key=lambda kv: (-int(kv[1] or 0), kv[0]),
                )[:8]
                if key
            ],
            "vuln_types": [
                {"name": key, "count": int(value)}
                for key, value in sorted(
                    (item.get("vuln_types") or {}).items(),
                    key=lambda kv: (-int(kv[1] or 0), kv[0]),
                )[:8]
                if key
            ],
            "entry_paths": list(item.get("entry_paths", []))[:6],
            "verify_actions": list(item.get("verify_actions", []))[:4],
            "record_refs": list(item.get("record_refs", []))[:4],
        }

    summary = {
        "token_count": len(normalized_token_index),
        "source_count": len(source_stats),
        "total_indexed_files": sum(int(item.get("indexed_file_count", 0)) for item in source_stats),
    }

    return {
        "version": "ai_pen_knowledge_index_v1",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "sources": source_stats,
        "token_index": normalized_token_index,
    }


def main():
    repo_root = resolve_repo_root()
    source_defaults = default_source_paths(repo_root)
    output_default = default_output_path(repo_root)

    parser = argparse.ArgumentParser(description="构建 AI 渗透测试知识索引")
    parser.add_argument("--poc-library-dir", default=str(source_defaults["poc_library"]), help="tools/poc/POC 路径")
    parser.add_argument("--vulhub-dir", default=str(source_defaults["vulhub"]), help="tools/poc/vulhub 路径")
    parser.add_argument("--poc-in-github-dir", default=str(source_defaults["poc_in_github"]), help="tools/poc/PoC-in-GitHub 路径")
    parser.add_argument("--output", default=str(output_default), help="输出 JSON 路径")
    parser.add_argument("--max-files-per-source", type=int, default=20000, help="每个来源最多索引文件数")
    parser.add_argument("--max-read-bytes", type=int, default=65536, help="单文件最多读取字节数")
    parser.add_argument("--min-token-count", type=int, default=2, help="最小 token 计数阈值")
    parser.add_argument("--max-index-tokens", type=int, default=8000, help="索引最大 token 数")
    args = parser.parse_args()

    source_paths = {
        "poc_library": resolve_path(args.poc_library_dir, source_defaults["poc_library"]),
        "vulhub": resolve_path(args.vulhub_dir, source_defaults["vulhub"]),
        "poc_in_github": resolve_path(args.poc_in_github_dir, source_defaults["poc_in_github"]),
    }

    output_path = resolve_path(args.output, output_default)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    result = build_index(
        source_paths=source_paths,
        max_files_per_source=max(1, int(args.max_files_per_source)),
        max_read_bytes=max(2048, int(args.max_read_bytes)),
        min_token_count=max(1, int(args.min_token_count)),
        max_index_tokens=max(500, int(args.max_index_tokens)),
    )

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("saved ai pen knowledge index -> {}".format(output_path))
    print("summary:", json.dumps(result.get("summary", {}), ensure_ascii=False))


if __name__ == "__main__":
    main()
