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
            if suffix in ALLOWED_SUFFIX:
                text = safe_read_text(file_path, max_read_bytes=max_read_bytes)
                if text:
                    token_pool.update(extract_tokens(text, max_tokens=120))

            for token in token_pool:
                bucket = token_index.get(token)
                if bucket is None:
                    bucket = {
                        "count": 0,
                        "sources": defaultdict(int),
                        "samples": [],
                    }
                    token_index[token] = bucket

                bucket["count"] += 1
                bucket["sources"][source_id] += 1
                if len(bucket["samples"]) < max_samples_per_token:
                    bucket["samples"].append("{}:{}".format(source_id, rel_path))

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
