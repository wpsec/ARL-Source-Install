#!/usr/bin/env python3
"""
构建 AI-POC 索引文件。

用途：
1. 扫描 nuclei 模板库，生成 token -> tags 映射；
2. 扫描 afrog PoC 库，生成 token -> keywords 映射；
3. 输出 JSON 索引，供 AI-POC 预匹配阶段加载使用。
"""

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml


TOKEN_STOPWORDS = {
    "www", "http", "https", "com", "org", "net", "cn",
    "api", "app", "web", "server", "system", "platform", "service",
    "default", "login", "admin", "panel", "console", "dashboard",
    "disclosure", "detect", "detection", "info", "information",
    "vulnerability", "vuln", "exposure", "unauthorized", "misconfig",
    "cve", "cnvd", "cnnvd", "rce", "xss", "sqli", "lfi", "rfi", "ssrf",
    "poc", "template", "scan", "scanner",
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
    # 兜底：ARL/app/tools/build_poc_index.py -> 回到仓库根
    if len(current.parents) >= 4:
        return current.parents[3]
    return Path.cwd()


def default_nuclei_dir(repo_root: Path) -> Path:
    candidates = [
        repo_root / "tools" / "nuclei" / "nuclei-templates",
        repo_root / "tools" / "nuclei-templates",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


def default_afrog_dir(repo_root: Path) -> Path:
    candidates = [
        repo_root / "tools" / "afrog" / "afrog-pocs",
        repo_root / "tools" / "afrog-pocs",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


def default_output_path(repo_root: Path) -> Path:
    candidates = [
        repo_root / "ARL" / "docker" / "ai" / "sop" / "poc_index.json",
        repo_root / "docker" / "ai" / "sop" / "poc_index.json",
        repo_root / "ARL" / "docker" / "ai" / "poc-index" / "poc_index.json",
        repo_root / "docker" / "ai" / "poc-index" / "poc_index.json",
    ]
    for candidate in candidates:
        parent = candidate.parent
        if parent.is_dir() or parent.parent.is_dir():
            return candidate
    return repo_root / "poc_index.json"


def resolve_path(path_text: str, default_path: Path) -> Path:
    text = str(path_text or "").strip()
    if not text:
        return default_path
    path = Path(text).expanduser()
    if path.is_absolute():
        return path
    return (Path.cwd() / path).resolve()


def normalize_tag(value: str) -> str:
    text = re.sub(r"[^a-z0-9._-]", "", str(value or "").strip().lower())
    if not text:
        return ""
    return text[:48]


def normalize_keyword(value: str) -> str:
    text = str(value or "").strip().replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip(" ,;|")
    text = text.replace('"', "").replace("'", "").replace("`", "")
    if not re.search(r"[A-Za-z0-9\u4e00-\u9fff]", text):
        return ""
    return text[:80]


def normalize_token(value: str) -> str:
    text = re.sub(r"[^a-z0-9._-]", "", str(value or "").strip().lower())
    if len(text) < 2 or text.isdigit() or text in TOKEN_STOPWORDS:
        return ""
    return text[:64]


def dedupe_keep_order(values):
    result = []
    seen = set()
    for value in values:
        key = str(value or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(str(value).strip())
    return result


def parse_tag_list(value):
    tags = []
    if isinstance(value, str):
        items = re.split(r"[,\s]+", value)
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = []
    for item in items:
        tag = normalize_tag(item)
        if tag:
            tags.append(tag)
    return dedupe_keep_order(tags)


def extract_ascii_tokens(text: str, max_tokens=120):
    tokens = []
    seen = set()
    raw_text = str(text or "").strip().lower()
    if not raw_text:
        return tokens

    for item in re.split(r"[^a-z0-9]+", raw_text):
        token = str(item or "").strip()
        if len(token) < 2 or token.isdigit() or token in TOKEN_STOPWORDS:
            continue
        if token in seen:
            continue
        seen.add(token)
        tokens.append(token)
        if len(tokens) >= max_tokens:
            break
    return tokens


def iter_yaml_files(root_dir: Path):
    if not root_dir.is_dir():
        return []
    files = []
    for file_path in root_dir.rglob("*"):
        if not file_path.is_file():
            continue
        suffix = file_path.suffix.lower()
        if suffix not in {".yaml", ".yml"}:
            continue
        files.append(file_path)
    return sorted(files)


def load_yaml_file(file_path: Path):
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)
    except Exception:
        return {}
    if isinstance(data, dict):
        return data
    return {}


def update_set_map(set_map, key: str, values, max_per_key=80):
    if not key:
        return
    bucket = set_map[key]
    for value in values:
        if len(bucket) >= max_per_key:
            break
        if value:
            bucket.add(value)


def extract_quoted_phrases(text: str, max_items=12):
    raw = str(text or "")
    if not raw:
        return []
    matches = []
    for pattern in [r'"([^"\n]{2,100})"', r"'([^'\n]{2,100})'"]:
        matches.extend(re.findall(pattern, raw))

    keywords = []
    for item in matches:
        keyword = normalize_keyword(item)
        if not keyword:
            continue
        lower_keyword = keyword.lower()
        if lower_keyword in TOKEN_STOPWORDS:
            continue
        keywords.append(keyword)
        if len(keywords) >= max_items:
            break
    return dedupe_keep_order(keywords)


def extract_kv_hints(text: str, max_items=16):
    raw = str(text or "")
    if not raw:
        return []

    pattern = re.compile(
        r'(?i)\b(?:app|product|vendor|title|framework|body|fofa(?:-query)?|hunter(?:-query)?|zoomeye|quake)'
        r'\s*[:=]{1,2}\s*(?:"([^"\n]{2,120})"|\'([^\'\n]{2,120})\'|([A-Za-z0-9\u4e00-\u9fff._/\-]{2,80}))'
    )

    results = []
    for match in pattern.finditer(raw):
        value = match.group(1) or match.group(2) or match.group(3) or ""
        keyword = normalize_keyword(value)
        if keyword:
            results.append(keyword)
        if len(results) >= max_items:
            break
    return dedupe_keep_order(results)


def build_nuclei_index(nuclei_dir: Path, with_reverse_map=False):
    token_to_tags = defaultdict(set)
    tag_to_templates = defaultdict(set)
    severity_counter = Counter()
    template_count = 0
    parsed_files = 0

    for file_path in iter_yaml_files(nuclei_dir):
        parsed_files += 1
        data = load_yaml_file(file_path)
        if not data:
            continue

        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        template_id = str(data.get("id", "")).strip()
        name = str(info.get("name", "")).strip()
        description = str(info.get("description", "")).strip()
        author = str(info.get("author", "")).strip()
        severity = normalize_tag(info.get("severity", ""))
        if severity:
            severity_counter[severity] += 1

        tags = parse_tag_list(info.get("tags"))
        if not tags:
            tags = parse_tag_list(template_id)

        if not tags:
            continue

        try:
            relative_path = str(file_path.relative_to(nuclei_dir)).replace("\\", "/")
        except Exception:
            relative_path = file_path.name

        token_parts = [template_id, name, description, author, relative_path, severity, " ".join(tags)]
        metadata = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}
        for key in ["fofa-query", "shodan-query", "google-query", "product", "vendor"]:
            value = metadata.get(key)
            if value is not None:
                token_parts.append(str(value))

        tokens = set(extract_ascii_tokens(" ".join(token_parts), max_tokens=140))
        for raw_value in [template_id] + tags:
            token = normalize_token(raw_value)
            if token:
                tokens.add(token)
            compact_token = normalize_token(str(raw_value).replace("-", "").replace("_", "").replace(".", ""))
            if compact_token:
                tokens.add(compact_token)

        for token in tokens:
            update_set_map(token_to_tags, token, tags, max_per_key=80)

        for tag in tags:
            update_set_map(tag_to_templates, tag, [relative_path], max_per_key=120)

        template_count += 1

    result = {
        "template_count": template_count,
        "parsed_files": parsed_files,
        "token_to_tags": {k: sorted(list(v)) for k, v in sorted(token_to_tags.items()) if v},
        "severity_count": dict(sorted(severity_counter.items())),
    }
    if with_reverse_map:
        result["tag_to_templates"] = {k: sorted(list(v)) for k, v in sorted(tag_to_templates.items()) if v}
    return result


def build_afrog_index(afrog_dir: Path, with_reverse_map=False):
    token_to_keywords = defaultdict(set)
    keyword_to_pocs = defaultdict(set)
    severity_counter = Counter()
    poc_count = 0
    parsed_files = 0

    for file_path in iter_yaml_files(afrog_dir):
        parsed_files += 1
        data = load_yaml_file(file_path)
        if not data:
            continue

        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        poc_id = str(data.get("id", "")).strip() or file_path.stem
        name = str(info.get("name", "")).strip()
        description = str(info.get("description", "")).strip()
        severity = normalize_tag(info.get("severity", ""))
        if severity:
            severity_counter[severity] += 1

        try:
            relative_path = str(file_path.relative_to(afrog_dir)).replace("\\", "/")
        except Exception:
            relative_path = file_path.name

        keywords = []
        keywords.extend(extract_kv_hints(description))
        keywords.extend(extract_quoted_phrases(description))
        if name:
            keywords.append(name)
        if poc_id:
            keywords.append(poc_id.replace("-", " ").replace("_", " "))

        normalized_keywords = []
        for item in keywords:
            keyword = normalize_keyword(item)
            if keyword:
                normalized_keywords.append(keyword)
        normalized_keywords = dedupe_keep_order(normalized_keywords)[:16]
        if not normalized_keywords:
            fallback_keyword = normalize_keyword(poc_id)
            if fallback_keyword:
                normalized_keywords = [fallback_keyword]

        token_parts = [poc_id, name, description, relative_path, severity, " ".join(normalized_keywords)]
        tokens = set(extract_ascii_tokens(" ".join(token_parts), max_tokens=140))
        for raw_value in [poc_id] + normalized_keywords:
            token = normalize_token(raw_value)
            if token:
                tokens.add(token)
            compact_token = normalize_token(str(raw_value).replace("-", "").replace("_", "").replace(".", ""))
            if compact_token:
                tokens.add(compact_token)

        for token in tokens:
            update_set_map(token_to_keywords, token, normalized_keywords, max_per_key=80)
        for keyword in normalized_keywords:
            update_set_map(keyword_to_pocs, keyword, [poc_id], max_per_key=120)

        poc_count += 1

    result = {
        "poc_count": poc_count,
        "parsed_files": parsed_files,
        "token_to_keywords": {k: sorted(list(v)) for k, v in sorted(token_to_keywords.items()) if v},
        "severity_count": dict(sorted(severity_counter.items())),
    }
    if with_reverse_map:
        result["keyword_to_pocs"] = {k: sorted(list(v)) for k, v in sorted(keyword_to_pocs.items()) if v}
    return result


def build_index(nuclei_dir: Path, afrog_dir: Path, with_reverse_map=False):
    nuclei_index = build_nuclei_index(nuclei_dir, with_reverse_map=with_reverse_map)
    afrog_index = build_afrog_index(afrog_dir, with_reverse_map=with_reverse_map)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "version": 1,
        "generated_at": generated_at,
        "meta": {
            "nuclei_dir": str(nuclei_dir),
            "afrog_dir": str(afrog_dir),
            "with_reverse_map": bool(with_reverse_map),
        },
        "nuclei": nuclei_index,
        "afrog": afrog_index,
    }


def main():
    repo_root = resolve_repo_root()
    parser = argparse.ArgumentParser(description="Build AI-POC index from nuclei/afrog template libraries.")
    parser.add_argument("--nuclei-dir", default="", help="nuclei 模板目录")
    parser.add_argument("--afrog-dir", default="", help="afrog poc 目录")
    parser.add_argument("--output", default="", help="输出索引 JSON 文件路径")
    parser.add_argument("--with-reverse-map", action="store_true", help="附带 tag_to_templates / keyword_to_pocs 反向映射")
    parser.add_argument("--quiet", action="store_true", help="静默输出")
    args = parser.parse_args()

    nuclei_dir = resolve_path(args.nuclei_dir, default_nuclei_dir(repo_root))
    afrog_dir = resolve_path(args.afrog_dir, default_afrog_dir(repo_root))
    output_path = resolve_path(args.output, default_output_path(repo_root))

    if not nuclei_dir.is_dir():
        raise SystemExit("nuclei dir not found: {}".format(nuclei_dir))
    if not afrog_dir.is_dir():
        raise SystemExit("afrog dir not found: {}".format(afrog_dir))

    index_data = build_index(
        nuclei_dir=nuclei_dir,
        afrog_dir=afrog_dir,
        with_reverse_map=bool(args.with_reverse_map),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(index_data, f, ensure_ascii=False, indent=2)

    if not args.quiet:
        nuclei_data = index_data.get("nuclei", {})
        afrog_data = index_data.get("afrog", {})
        print("[AI-POC] index generated: {}".format(output_path))
        print(
            "[AI-POC] nuclei templates:{} tokens:{} tags:{}".format(
                int(nuclei_data.get("template_count", 0) or 0),
                len(nuclei_data.get("token_to_tags", {}) or {}),
                len(nuclei_data.get("tag_to_templates", {}) or {}),
            )
        )
        print(
            "[AI-POC] afrog pocs:{} tokens:{} keywords:{}".format(
                int(afrog_data.get("poc_count", 0) or 0),
                len(afrog_data.get("token_to_keywords", {}) or {}),
                len(afrog_data.get("keyword_to_pocs", {}) or {}),
            )
        )


if __name__ == "__main__":
    main()
