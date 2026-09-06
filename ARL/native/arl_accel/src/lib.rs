use percent_encoding::percent_decode_str;
#[cfg(not(test))]
use pyo3::prelude::*;
#[cfg(not(test))]
use pyo3::types::PyModule;
#[cfg(not(test))]
use pyo3::wrap_pyfunction;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use url::Url;

type ExtractedRecord = (String, String, String, String, usize);
type PageInput = (String, String, String, usize, bool);

static JS_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#"(?i)https?://[^\s"'<>`]{3,2048}\.js(?:\?[^\s"'<>`]*)?"#).expect("valid JS URL regex"),
        Regex::new(r#"(?i)(?:src|href)\s*=\s*["']\s*([^"']+?\.js(?:\?[^"']*)?)\s*["']"#)
            .expect("valid JS attribute regex"),
        Regex::new(r#"(?i)["'`]\s*((?:\/\/|\/|\./|\.\./)?[^\s"'<>`]{2,2048}\.js(?:\?[^\s"'<>`]*)?)\s*["'`]"#)
            .expect("valid quoted JS regex"),
    ]
});

static URL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#"(?i)https?://[^\s"'<>`]{4,2048}"#).expect("valid absolute URL regex"),
        Regex::new(r#"(?i)["'`]\s*((?:\/|\./|\.\./)[^\s"'<>`]{2,2048})\s*["'`]"#)
            .expect("valid relative URL regex"),
        Regex::new(r#"(?i)["'`]\s*((?:api|auth|oauth|rest|v[0-9]+)[^\s"'<>`]{1,2048})\s*["'`]"#)
            .expect("valid API path regex"),
    ]
});

static ROUTE_METHOD_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\|(get|post|put|delete|patch|options|head|connect|trace)$")
        .expect("valid route method regex")
});

static HTML_LINK_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#"(?is)<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>"#)
            .expect("valid HTML anchor regex"),
        Regex::new(r#"(?is)<iframe\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>"#)
            .expect("valid HTML iframe regex"),
    ]
});
static HTML_SCRIPT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>"#)
        .expect("valid HTML script regex")
});
static HTML_FORM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form\s*>"#).expect("valid HTML form regex")
});
static HTML_ACTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\baction\s*=\s*["']([^"']+)["']"#).expect("valid HTML action regex")
});
static HTML_METHOD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\bmethod\s*=\s*["']([^"']+)["']"#).expect("valid HTML method regex")
});
static HTML_FIELD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>"#)
        .expect("valid HTML field regex")
});
static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b"#)
        .expect("valid domain regex")
});
static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)https?://[^\s"'<>\x60]{4,2048}"#).expect("valid URL regex"));
static JS_ENDPOINT_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#"(?i)https?://[^\s"'<>\x60]{4,2048}"#)
            .expect("valid JS absolute endpoint regex"),
        Regex::new(r#"['"\x60]\s*((?:\/\/|\/|\./|\.\./)[^\s'"\x60<>]{2,2048})\s*['"\x60]"#)
            .expect("valid JS relative endpoint regex"),
        Regex::new(
            r#"['"\x60]\s*((?:(?:api|auth|oauth|rest|graphql|rpc|v[0-9]+|service|services|module|modules)[^\s'"\x60<>]{2,2048}))\s*['"\x60]"#,
        )
        .expect("valid JS prefixed endpoint regex"),
        Regex::new(
            r#"(?i)(?:fetch|axios(?:\.[a-z]+)?|baseurl|endpoint|request|url)\s*[:=,(]\s*['"\x60]([^\s'"\x60<>]{2,2048})\s*['"\x60]"#,
        )
        .expect("valid JS contextual endpoint regex"),
    ]
});

const JS_BLACK_KEYWORDS: &[&str] = &["www.w3.org", "example.com", "javascript:", "data:"];
const URL_BLACK_KEYWORDS: &[&str] = &[
    "www.w3.org",
    "example.com",
    "javascript:",
    "data:",
    "location.href",
    "application/x-www-form-urlencoded",
    "*#__pure__*",
];
const STATIC_SUFFIXES: &[&str] = &[
    ".css", ".scss", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".vue", ".ts", ".woff",
    ".woff2", ".ttf", ".map",
];
const JS_SUFFIXES: &[&str] = &[".js", ".mjs"];
const NOISE_SINGLE_SEGMENTS: &[&str] = &[
    "head", "body", "html", "script", "style", "meta", "link", "title",
];

const SENSITIVE_PATH_KEYWORDS: &[&str] = &[
    "api", "ajax", "admin", "auth", "login", "logout", "upload", "download", "export", "import",
    "graphql", "search", "query", "config", "report", "token", "user", "account", "order",
    "payment", "invoice",
];
const CRITICAL_PATH_KEYWORDS: &[&str] = &[
    "admin", "export", "upload", "download", "report", "graphql", "config", "token",
];

fn clean_candidate(value: &str) -> String {
    // F6（第 11 批）：legacy 提取面 trim 语义与 Python 基线 `.strip()` 对齐——
    // Python 把 U+001C-001F 当空白而 Rust `trim()` 不是（对抗审查 P2-1 实证），
    // 凡镜像 Python `.strip()` 的判定点一律走 py_strip。
    let mut text = py_strip(value)
        .trim_matches(|character: char| "\"'`;,()[]{}".contains(character))
        .to_string();
    if text.is_empty() {
        return text;
    }

    text = text.replace("\\/", "/");
    text = text
        .replace("%3A", ":")
        .replace("%2F", "/")
        .replace("%3a", ":")
        .replace("%2f", "/");
    let decoded = percent_decode_str(&text).decode_utf8_lossy();
    py_strip(&decoded).to_string()
}

fn extract_host(value: &str) -> Option<String> {
    let parsed = Url::parse(value)
        .or_else(|_| Url::parse(&format!("https://{}", py_strip(value))))
        .ok()?;
    parsed
        .host_str()
        .map(|host| py_strip(host).to_lowercase().trim_end_matches('.').to_string())
}

fn allowed_host_set(sites: &[String]) -> HashSet<String> {
    sites.iter().filter_map(|site| extract_host(site)).collect()
}

fn strip_route_method_suffix(path: &str) -> String {
    ROUTE_METHOD_SUFFIX.replace(py_strip(path), "").to_string()
}

fn has_route_template_markers(path: &str) -> bool {
    if path.contains('|')
        || path.contains('{')
        || path.contains('}')
        || path.contains('<')
        || path.contains('>')
        || path.contains('[')
        || path.contains(']')
        || path.contains("${")
    {
        return true;
    }

    path.split('/').any(|segment| {
        let segment = py_strip(segment);
        segment.starts_with(':') || segment.contains('*')
    })
}

fn is_noise_single_segment_path(path: &str) -> bool {
    let normalized = py_strip(path).trim_matches('/');
    if normalized.is_empty() || normalized.contains('/') || normalized.contains('.') {
        return false;
    }
    NOISE_SINGLE_SEGMENTS.contains(&normalized.to_lowercase().as_str())
}

fn is_js_resource_path(path: &str) -> bool {
    let lower_path = py_strip(path).to_lowercase();
    JS_SUFFIXES
        .iter()
        .any(|suffix| lower_path.ends_with(suffix))
}

fn is_non_js_static_resource_path(path: &str) -> bool {
    let lower_path = py_strip(path).to_lowercase();
    STATIC_SUFFIXES
        .iter()
        .any(|suffix| lower_path.ends_with(suffix))
}

fn strip_url_annotation(value: &str) -> String {
    let text = py_strip(value);
    if !text.contains(" (") || !text.ends_with(')') {
        return text.to_string();
    }
    let prefix = text
        .rsplit_once(" (")
        .map(|item| py_strip(item.0))
        .unwrap_or(text);
    if Url::parse(prefix)
        .ok()
        .map(|parsed| {
            (parsed.scheme() == "http" || parsed.scheme() == "https") && parsed.host_str().is_some()
        })
        .unwrap_or(false)
    {
        return prefix.to_string();
    }
    text.to_string()
}

fn is_js_url(value: &str) -> bool {
    let lower = py_strip(value).to_lowercase();
    if lower.is_empty() {
        return false;
    }
    if lower.contains(".js") {
        return true;
    }
    Url::parse(&lower)
        .ok()
        .map(|parsed| parsed.path().to_lowercase().ends_with(".js"))
        .unwrap_or(false)
}

fn normalize_url(base_url: &str, value: &str, allowed_hosts: &HashSet<String>) -> Option<String> {
    let candidate = clean_candidate(value);
    if candidate.is_empty() {
        return None;
    }

    let candidate_scheme = candidate.to_ascii_lowercase();
    let mut parsed =
        if candidate_scheme.starts_with("http://") || candidate_scheme.starts_with("https://") {
            Url::parse(&candidate).ok()?
        } else if candidate.starts_with("//") {
            let scheme = Url::parse(base_url)
                .ok()
                .map(|base| base.scheme().to_string())
                .unwrap_or_else(|| "https".to_string());
            Url::parse(&format!("{}:{}", scheme, candidate)).ok()?
        } else {
            Url::parse(base_url).ok()?.join(&candidate).ok()?
        };

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    let host = parsed
        .host_str()
        .map(|host| py_strip(host).to_lowercase().trim_end_matches('.').to_string())
        .unwrap_or_default();
    if host.is_empty() || (!allowed_hosts.is_empty() && !allowed_hosts.contains(&host)) {
        return None;
    }

    let normalized_path = strip_route_method_suffix(parsed.path());
    if has_route_template_markers(&normalized_path)
        || is_noise_single_segment_path(&normalized_path)
    {
        return None;
    }
    if normalized_path != parsed.path() {
        parsed.set_path(&normalized_path);
    }
    parsed.set_fragment(None);
    Some(parsed.to_string())
}

fn normalize_page_url(
    base_url: &str,
    value: &str,
    allowed_hosts: &HashSet<String>,
    allow_js: bool,
) -> Option<String> {
    let normalized = normalize_url(base_url, value, allowed_hosts)?;
    let parsed = Url::parse(&normalized).ok()?;
    let path = parsed.path();
    if is_non_js_static_resource_path(path) || (!allow_js && is_js_resource_path(path)) {
        return None;
    }
    Some(normalized)
}

fn safe_site(value: &str) -> String {
    let parsed = match Url::parse(value) {
        Ok(parsed) => parsed,
        Err(_) => return String::new(),
    };
    let host = match parsed.host_str() {
        Some(host) if !host.is_empty() => host,
        _ => return String::new(),
    };
    let formatted_host = if host.contains(':') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    match parsed.port() {
        Some(port) => format!("{}://{}:{}", parsed.scheme(), formatted_host, port),
        None => format!("{}://{}", parsed.scheme(), formatted_host),
    }
}

fn is_blocked_url(value: &str, for_js: bool) -> bool {
    let lower = value.to_lowercase();
    let keywords = if for_js {
        JS_BLACK_KEYWORDS
    } else {
        URL_BLACK_KEYWORDS
    };
    if keywords.iter().any(|keyword| lower.contains(keyword)) {
        return true;
    }
    if for_js {
        return false;
    }
    let path = Url::parse(&lower)
        .ok()
        .map(|parsed| parsed.path().to_string())
        .unwrap_or_default();
    is_non_js_static_resource_path(&path)
}

fn append_page_record(
    records: &mut Vec<ExtractedRecord>,
    record_seen: &mut HashSet<(String, String, String, String)>,
    record_type: &str,
    content: &str,
    source: &str,
    site: &str,
    next_depth: usize,
) {
    if py_strip(content).is_empty() || py_strip(site).is_empty() {
        return;
    }
    append_record(
        records,
        record_seen,
        record_type,
        content,
        source,
        site,
        next_depth,
    );
}

fn extract_scope_domains_core(
    text: &str,
    allowed_flds: &HashSet<String>,
    exclude_hosts: &HashSet<String>,
) -> Vec<String> {
    if text.is_empty() || allowed_flds.is_empty() {
        return Vec::new();
    }

    let mut candidates = HashSet::new();
    for item in DOMAIN_RE.find_iter(text) {
        candidates.insert(
            py_strip(item.as_str())
                .to_lowercase()
                .trim_end_matches('.')
                .to_string(),
        );
    }
    for item in URL_RE.find_iter(text) {
        if let Some(host) = extract_host(item.as_str()) {
            candidates.insert(host);
        }
    }

    let mut results = Vec::new();
    for candidate in candidates {
        if candidate.is_empty() || exclude_hosts.contains(&candidate) {
            continue;
        }
        let labels: Vec<&str> = candidate.split('.').collect();
        if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
            continue;
        }
        let in_scope = allowed_flds
            .iter()
            .any(|fld| candidate == *fld || candidate.ends_with(&format!(".{}", fld)));
        if in_scope {
            results.push(candidate);
        }
    }
    results.sort();
    results
}

fn pattern_tokens(text: &str, pattern: &Regex) -> Vec<String> {
    pattern
        .captures_iter(text)
        .filter_map(|captures| captures.get(1).or_else(|| captures.get(0)))
        .map(|capture| py_strip(capture.as_str()).to_string())
        .filter(|token| !token.is_empty())
        .collect()
}

fn append_record(
    records: &mut Vec<ExtractedRecord>,
    record_seen: &mut HashSet<(String, String, String, String)>,
    record_type: &str,
    content: &str,
    source: &str,
    site: &str,
    next_depth: usize,
) -> bool {
    let fingerprint = (
        record_type.to_string(),
        content.to_string(),
        source.to_string(),
        site.to_string(),
    );
    if !record_seen.insert(fingerprint) {
        return false;
    }
    records.push((
        record_type.to_string(),
        content.to_string(),
        source.to_string(),
        site.to_string(),
        next_depth,
    ));
    true
}

fn process_page(
    base_url: &str,
    text: &str,
    source_url: &str,
    depth: usize,
    is_js_page: bool,
    allowed_hosts: &HashSet<String>,
    allow_js: bool,
    max_url_records: usize,
    max_js_files: usize,
    max_js_depth: usize,
    records: &mut Vec<ExtractedRecord>,
    js_seen: &mut HashSet<String>,
    record_seen: &mut HashSet<(String, String, String, String)>,
) {
    if text.is_empty() {
        return;
    }

    let js_source = if is_js_page && !source_url.is_empty() {
        source_url
    } else {
        base_url
    };
    if allow_js && (!is_js_page || depth < max_js_depth) {
        for pattern in JS_PATTERNS.iter() {
            for raw in pattern_tokens(text, pattern) {
                let Some(normalized) = normalize_url(base_url, &raw, allowed_hosts) else {
                    continue;
                };
                if !is_js_url(&normalized)
                    || is_blocked_url(&normalized, true)
                    || !js_seen.insert(normalized.clone())
                {
                    continue;
                }
                if js_seen.len() > max_js_files {
                    js_seen.remove(&normalized);
                    break;
                }
                let next_depth = if is_js_page { depth + 1 } else { 1 };
                append_record(
                    records,
                    record_seen,
                    "urlfinder_js",
                    &normalized,
                    js_source,
                    &safe_site(&normalized),
                    next_depth,
                );
            }
        }
    }

    if is_js_page && depth >= max_js_depth {
        return;
    }

    for pattern in URL_PATTERNS.iter() {
        for raw in pattern_tokens(text, pattern) {
            let Some(normalized) = normalize_url(base_url, &raw, allowed_hosts) else {
                continue;
            };
            if is_js_url(&normalized) || is_blocked_url(&normalized, false) {
                continue;
            }
            // Python 端以已接受的唯一记录数控制 URL 上限；重复候选不能提前消耗预算。
            if records.len() >= max_url_records {
                return;
            }
            append_record(
                records,
                record_seen,
                "urlfinder_url",
                &normalized,
                base_url,
                &safe_site(&normalized),
                0,
            );
        }
    }
}

fn extract_urlfinder_candidates_core(
    pages: Vec<(String, String, String, usize, bool)>,
    allowed_hosts: Vec<String>,
    allow_js: bool,
    max_url_records: usize,
    max_js_files: usize,
    max_js_depth: usize,
) -> Vec<ExtractedRecord> {
    let allowed_hosts: HashSet<String> = allowed_hosts
        .into_iter()
        .map(|host| host.to_lowercase())
        .collect();
    let max_url_records = max_url_records.max(1);
    let max_js_files = max_js_files.max(1);
    let max_js_depth = max_js_depth.max(1);
    let mut records = Vec::new();
    let mut js_seen = HashSet::new();
    let mut record_seen = HashSet::new();

    for (base_url, text, source_url, depth, is_js_page) in pages {
        process_page(
            &base_url,
            &text,
            &source_url,
            depth,
            is_js_page,
            &allowed_hosts,
            allow_js,
            max_url_records,
            max_js_files,
            max_js_depth,
            &mut records,
            &mut js_seen,
            &mut record_seen,
        );
    }
    records
}

fn extract_html_candidates_core(
    pages: Vec<PageInput>,
    allowed_hosts: Vec<String>,
    allowed_flds: Vec<String>,
    exclude_hosts: Vec<String>,
) -> Vec<ExtractedRecord> {
    let allowed_hosts: HashSet<String> = allowed_hosts
        .into_iter()
        .map(|host| py_strip(&host).to_lowercase())
        .filter(|host| !host.is_empty())
        .collect();
    let allowed_flds: HashSet<String> = allowed_flds
        .into_iter()
        .map(|fld| py_strip(&fld).to_lowercase())
        .filter(|fld| !fld.is_empty())
        .collect();
    let exclude_hosts: HashSet<String> = exclude_hosts
        .into_iter()
        .map(|host| py_strip(&host).to_lowercase())
        .filter(|host| !host.is_empty())
        .collect();
    let mut records = Vec::new();
    let mut record_seen = HashSet::new();

    for (base_url, text, _source_url, depth, _is_js_page) in pages {
        if py_strip(&text).is_empty() {
            continue;
        }
        let source_site = safe_site(&base_url);
        let next_depth = depth + 1;

        for pattern in HTML_LINK_PATTERNS.iter() {
            for captures in pattern.captures_iter(&text) {
                let Some(raw) = captures.get(1) else { continue };
                let Some(normalized) =
                    normalize_page_url(&base_url, raw.as_str(), &allowed_hosts, false)
                else {
                    continue;
                };
                let site = safe_site(&normalized);
                append_page_record(
                    &mut records,
                    &mut record_seen,
                    "page_link",
                    &normalized,
                    &base_url,
                    &site,
                    next_depth,
                );
                append_page_record(
                    &mut records,
                    &mut record_seen,
                    "urlfinder_url",
                    &normalized,
                    &base_url,
                    &site,
                    0,
                );
            }
        }

        for captures in HTML_FORM_RE.captures_iter(&text) {
            let attrs = captures
                .get(1)
                .map(|item| item.as_str())
                .unwrap_or_default();
            let body = captures
                .get(2)
                .map(|item| item.as_str())
                .unwrap_or_default();
            let raw_action = HTML_ACTION_RE
                .captures(attrs)
                .and_then(|item| item.get(1))
                .map(|item| item.as_str())
                .unwrap_or(&base_url);
            let Some(normalized) = normalize_page_url(&base_url, raw_action, &allowed_hosts, false)
            else {
                continue;
            };
            let method = HTML_METHOD_RE
                .captures(attrs)
                .and_then(|item| item.get(1))
                .map(|item| py_strip(item.as_str()).to_uppercase())
                .filter(|item| !item.is_empty())
                .unwrap_or_else(|| "GET".to_string());
            let mut field_names = HashSet::new();
            for field in HTML_FIELD_RE.captures_iter(body) {
                if let Some(name) = field.get(1) {
                    let name = py_strip(name.as_str());
                    if !name.is_empty() {
                        field_names.insert(name.to_string());
                    }
                }
            }
            let mut field_names: Vec<String> = field_names.into_iter().collect();
            field_names.sort();
            field_names.truncate(12);
            let form_summary = if field_names.is_empty() {
                format!("{} {}", method, normalized)
            } else {
                format!("{} {} [{}]", method, normalized, field_names.join(","))
            };
            let page_site = safe_site(&base_url);
            append_page_record(
                &mut records,
                &mut record_seen,
                "page_form",
                &form_summary,
                &base_url,
                &page_site,
                0,
            );
            append_page_record(
                &mut records,
                &mut record_seen,
                "urlfinder_url",
                &normalized,
                &base_url,
                &page_site,
                0,
            );
        }

        for captures in HTML_SCRIPT_RE.captures_iter(&text) {
            let Some(raw) = captures.get(1) else { continue };
            let Some(normalized) =
                normalize_page_url(&base_url, raw.as_str(), &allowed_hosts, true)
            else {
                continue;
            };
            if !is_js_url(&normalized) {
                continue;
            }
            let site = safe_site(&normalized);
            append_page_record(
                &mut records,
                &mut record_seen,
                "urlfinder_js",
                &normalized,
                &base_url,
                &site,
                0,
            );
        }

        let page_host = extract_host(&base_url).unwrap_or_default();
        let mut page_excludes = exclude_hosts.clone();
        if !page_host.is_empty() {
            page_excludes.insert(page_host);
        }
        for domain in extract_scope_domains_core(&text, &allowed_flds, &page_excludes) {
            append_page_record(
                &mut records,
                &mut record_seen,
                "domain",
                &domain,
                &base_url,
                &source_site,
                0,
            );
        }
    }
    records
}

fn is_api_doc_candidate(value: &str) -> bool {
    // 第 10 批（计划 6 §9.3/余留项）：与 Python 统一面 `_TYPE_HINT_KEYWORDS`
    // 的关键词集合同口径（含第 7 批 wsdl、第 8 批 graphql/graphiql）。
    // 只影响 api_doc_url 记录发射面；legacy 请求面（ApiDocScanner._DOC_KEYWORDS）
    // 维持四 token 不变，flag-off 的文档扫描行为零变化。
    let lower = value.to_lowercase();
    [
        "swagger",
        "openapi",
        "api-docs",
        "postman",
        "wsdl",
        "graphql",
        "graphiql",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn extract_js_endpoint_candidates_core(
    pages: Vec<PageInput>,
    allowed_hosts: Vec<String>,
    max_records: usize,
) -> Vec<ExtractedRecord> {
    let allowed_hosts: HashSet<String> = allowed_hosts
        .into_iter()
        .map(|host| py_strip(&host).to_lowercase())
        .filter(|host| !host.is_empty())
        .collect();
    let mut records = Vec::new();
    let mut record_seen = HashSet::new();
    let max_records = max_records.max(1);

    for (base_url, text, _source_url, _depth, _is_js_page) in pages {
        if py_strip(&text).is_empty() {
            continue;
        }
        for pattern in JS_ENDPOINT_PATTERNS.iter() {
            for raw in pattern_tokens(&text, pattern) {
                let Some(normalized) = normalize_page_url(&base_url, &raw, &allowed_hosts, false)
                else {
                    continue;
                };
                let site = safe_site(&normalized);
                let record_type = if is_api_doc_candidate(&normalized) {
                    "api_doc_url"
                } else {
                    "urlfinder_url"
                };
                append_page_record(
                    &mut records,
                    &mut record_seen,
                    record_type,
                    &normalized,
                    &base_url,
                    &site,
                    0,
                );
                if record_type == "api_doc_url" {
                    append_page_record(
                        &mut records,
                        &mut record_seen,
                        "urlfinder_url",
                        &normalized,
                        &base_url,
                        &site,
                        0,
                    );
                }
                if records.len() >= max_records {
                    return records;
                }
            }
        }
    }
    records
}

fn normalize_sensitive_candidate(
    raw_url: &str,
    allowed_hosts: &HashSet<String>,
    allow_js: bool,
) -> Option<String> {
    let cleaned = strip_url_annotation(raw_url);
    let normalized = normalize_url(&cleaned, &cleaned, allowed_hosts)?;
    let parsed = Url::parse(&normalized).ok()?;
    let path = parsed.path();
    if is_non_js_static_resource_path(path) || (!allow_js && is_js_resource_path(path)) {
        return None;
    }
    Some(normalized)
}

fn score_candidate(normalized_url: &str, record_type: &str, source: &str) -> i32 {
    let parsed = match Url::parse(normalized_url) {
        Ok(parsed) => parsed,
        Err(_) => return 0,
    };
    let path_text = parsed.path().to_lowercase();
    let query_text = parsed.query().unwrap_or_default().to_lowercase();
    let record_type_text = record_type.to_lowercase();
    let source_host = extract_host(source).unwrap_or_default();
    let target_host = extract_host(normalized_url).unwrap_or_default();

    let mut score = 10;
    score += if is_js_url(normalized_url) { 4 } else { 6 };
    if !query_text.is_empty() {
        score += 4;
    }
    if !source_host.is_empty() && source_host == target_host {
        score += 2;
    }
    if record_type_text.contains("urlfinder_js") {
        score += 2;
    }
    if record_type_text.contains("urlfinder_url") {
        score += 3;
    }
    score += SENSITIVE_PATH_KEYWORDS
        .iter()
        .filter(|keyword| path_text.contains(**keyword))
        .count() as i32
        * 3;
    score += CRITICAL_PATH_KEYWORDS
        .iter()
        .filter(|keyword| path_text.contains(**keyword))
        .count() as i32
        * 2;
    if path_text.matches('/').count() >= 3 {
        score += 2;
    }
    if ["id=", "token=", "kw=", "keyword=", "page=", "size="]
        .iter()
        .any(|token| query_text.contains(token))
    {
        score += 3;
    }
    score
}

fn rank_sensitive_targets_core(
    records: Vec<(String, String, String, String)>,
    sites: Vec<String>,
    blocked_hosts: Vec<String>,
    include_js: bool,
    max_targets: usize,
) -> Vec<(String, i32)> {
    let allowed_hosts = allowed_host_set(&sites);
    let blocked_hosts: HashSet<String> = blocked_hosts
        .into_iter()
        .map(|host| host.to_lowercase())
        .collect();
    let mut target_scores: HashMap<String, i32> = HashMap::new();

    for (record_type, content, source, _site) in records {
        let record_type = py_strip(&record_type).to_lowercase();
        if !record_type.starts_with("urlfinder_") {
            continue;
        }
        for candidate in [content, source.clone()] {
            let Some(normalized) =
                normalize_sensitive_candidate(&candidate, &allowed_hosts, include_js)
            else {
                continue;
            };
            let Some(host) = extract_host(&normalized) else {
                continue;
            };
            if blocked_hosts.contains(&host) || (!include_js && is_js_url(&normalized)) {
                continue;
            }
            let score = score_candidate(&normalized, &record_type, &source);
            target_scores
                .entry(normalized)
                .and_modify(|previous| *previous = (*previous).max(score))
                .or_insert(score);
        }
    }

    let mut targets: Vec<(String, i32)> = target_scores.into_iter().collect();
    targets.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    targets.truncate(max_targets.max(1));
    targets
}

// ---------------------------------------------------------------------------
// 第 10 批：统一 API 面纯数据批量函数（计划 6 §9.3 第三阶段）。
//
// py_strip：对齐 CPython `str.strip()` 的空白集——Python 把 U+001C-001F
// （FS/GS/RS/US）当空白而 Rust `char::is_whitespace`（White_Space 属性）不是
// （对抗审查 P2-1 差分 fuzz 实证）。凡参与"与 Python 基线逐字节相等"契约的
// trim 必须走本函数；U+0085/U+00A0 两侧同判（is_whitespace 覆盖）。
// ---------------------------------------------------------------------------

fn py_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}
// 语义事实源 = CPython 3.10 urllib.parse.urlsplit + discovery_context.normalize_url，
// 仅覆盖 Python 适配器预检放行的"安全子集"；子集外输入原样返回（与 Python
// 基线不可解析分支一致），跨版本行为漂移由 adapter shadow 双跑与 golden 门禁拦截。
// ---------------------------------------------------------------------------

fn ascii_lowercase_host(host: &str) -> String {
    host.to_ascii_lowercase().trim_end_matches('.').to_string()
}

/// 与 Python `int(port, 10)` 在"纯数字"输入下等价；越界/溢出返回 None。
fn parse_safe_port(port: &str) -> Option<u32> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse::<u32>().ok().filter(|value| *value <= 65535)
}

/// `normalize_url`（discovery_context）的安全子集移植。
///
/// 前置假设（由 Python adapter 预检保证，Rust 侧防御性复检）：
/// - 调用方已做 `str.strip()`；
/// - scheme 为小写 `http`/`https`，netloc 为纯 ASCII 且无方括号；
/// - 全串不含 \t \r \n（CPython urlsplit 会先整串删除它们）。
/// 子集外返回原文；行为分歧由 shadow 双跑计数暴露。
fn normalize_url_unified(value: &str) -> String {
    let text = py_strip(value);
    if text.is_empty() {
        return String::new();
    }
    if text.contains(['\t', '\r', '\n']) {
        return py_strip(value).to_string();
    }
    let (scheme, tail) = if let Some(rest) = text.strip_prefix("http://") {
        ("http", rest)
    } else if let Some(rest) = text.strip_prefix("https://") {
        ("https", rest)
    } else {
        return py_strip(value).to_string();
    };
    // _splitnetloc：netloc 结束于最早的 '/' '?' '#'。
    let netloc_end = tail
        .find(['/', '?', '#'])
        .unwrap_or(tail.len());
    let (netloc, rest) = (&tail[..netloc_end], &tail[netloc_end..]);
    if netloc.is_empty()
        || !netloc.is_ascii()
        || netloc.contains(['[', ']'])
        || netloc
            .chars()
            .any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
    {
        return py_strip(value).to_string();
    }
    // _hostinfo：rpartition('@') 去 userinfo；首个 ':' 分 host/port。
    let hostinfo = match netloc.rsplit_once('@') {
        Some((_, after)) => after,
        None => netloc,
    };
    let (host, port_part) = match hostinfo.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (hostinfo, None),
    };
    let host = ascii_lowercase_host(host);
    if host.is_empty() {
        return py_strip(value).to_string();
    }
    // port 属性语义：空串→None；纯数字且 0-65535；0 为 falsy→不保留；
    // http:80 / https:443 为默认端口→去除；其余以十进制整数重渲染。
    let port: u32 = match port_part {
        None => 0,
        Some("") => 0,
        Some(raw) => match parse_safe_port(raw) {
            Some(parsed) => parsed,
            None => return py_strip(value).to_string(),
        },
    };
    let mut netloc_out = host;
    if port != 0 && !((scheme == "http" && port == 80) || (scheme == "https" && port == 443)) {
        netloc_out.push(':');
        netloc_out.push_str(&port.to_string());
    }
    // rest：先切 fragment（丢弃），再切 query（原样保留）。
    let (before_frag, _fragment) = match rest.split_once('#') {
        Some((left, frag)) => (left, frag),
        None => (rest, ""),
    };
    let (path, query) = match before_frag.split_once('?') {
        Some((path, query)) => (path, query),
        None => (before_frag, ""),
    };
    let path_out = if path.is_empty() { "/" } else { path };
    let mut out = String::with_capacity(text.len() + 2);
    out.push_str(scheme);
    out.push_str("://");
    out.push_str(&netloc_out);
    out.push_str(path_out);
    if !query.is_empty() {
        out.push('?');
        out.push_str(query);
    }
    out
}

fn canonical_method_unified(method: &str) -> String {
    // py_strip 对齐 Python str.strip()（\x1c-\x1f 亦为空白，P2-1）。
    let text = py_strip(method).to_ascii_uppercase();
    const METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];
    if METHODS.contains(&text.as_str()) {
        text
    } else {
        "GET".to_string()
    }
}

/// 与 Python `_TYPE_HINT_KEYWORDS`（api_candidate_registry）顺序与映射冻结一致。
fn document_type_hint_unified(url: &str) -> &'static str {
    const HINTS: [(&str, &str); 7] = [
        ("postman", "postman"),
        ("openapi", "openapi"),
        ("swagger", "swagger"),
        ("api-docs", "swagger"),
        ("wsdl", "wsdl"),
        ("graphql", "graphql"),
        ("graphiql", "graphql"),
    ];
    let lowered = py_strip(url).to_lowercase();
    for (keyword, hint) in HINTS {
        if lowered.contains(keyword) {
            return hint;
        }
    }
    "unknown"
}

/// Endpoint 记录按键分组 + sources 合并（§9.3 第 3/4 条的纯数据面）。
///
/// 键 = (url, method, api_type, path_template)（digest 前的规范化字段全等，
/// 与 Registry `scoped_idempotency_key` 分组语义一致）；组按首现顺序输出，
/// sources = 组内非空 strip 后的去重集合按字典序（对齐 `add_source`+`sorted`）。
fn dedupe_endpoint_records_core(
    records: &[(String, String, String, String, String)],
) -> Vec<(usize, Vec<String>)> {
    // 借用键（Review efficiency-6）：records 生命周期覆盖全函数，键与来源
    // 集合只存 &str，逐条 12 次 String clone 归零；输出序 = 首现序（order
    // 记录键引用），sources 码点序 = UTF-8 字节序 = CPython sorted() 口径。
    let mut order: Vec<(&str, &str, &str, &str)> = Vec::new();
    let mut groups: HashMap<(&str, &str, &str, &str), (usize, HashSet<&str>)> = HashMap::new();
    for (index, (url, method, api_type, path_template, source)) in records.iter().enumerate() {
        let key = (
            url.as_str(),
            method.as_str(),
            api_type.as_str(),
            path_template.as_str(),
        );
        let entry = groups.entry(key).or_insert_with(|| {
            order.push(key);
            (index, HashSet::new())
        });
        let cleaned = py_strip(source);
        if !cleaned.is_empty() {
            entry.1.insert(cleaned);
        }
    }
    order
        .into_iter()
        .map(|key| {
            let (first_index, sources) = &groups[&key];
            let mut merged: Vec<String> = sources
                .iter()
                .map(|source| (*source).to_string())
                .collect();
            merged.sort();
            (*first_index, merged)
        })
        .collect()
}

#[cfg(not(test))]
#[pyfunction]
fn unified_normalize_urls(values: Vec<String>) -> PyResult<Vec<String>> {
    Ok(values.iter().map(|item| normalize_url_unified(item)).collect())
}

#[cfg(not(test))]
#[pyfunction]
fn unified_canonical_methods(values: Vec<String>) -> PyResult<Vec<String>> {
    Ok(values
        .iter()
        .map(|item| canonical_method_unified(item))
        .collect())
}

#[cfg(not(test))]
#[pyfunction]
fn unified_document_type_hints(values: Vec<String>) -> PyResult<Vec<String>> {
    Ok(values
        .iter()
        .map(|item| document_type_hint_unified(item).to_string())
        .collect())
}

#[cfg(not(test))]
#[pyfunction]
fn unified_dedupe_endpoints(
    records: Vec<(String, String, String, String, String)>,
) -> PyResult<Vec<(usize, Vec<String>)>> {
    Ok(dedupe_endpoint_records_core(&records))
}

#[cfg(not(test))]
#[pyfunction]
fn extract_urlfinder_candidates(
    pages: Vec<(String, String, String, usize, bool)>,
    allowed_hosts: Vec<String>,
    allow_js: bool,
    max_url_records: usize,
    max_js_files: usize,
    max_js_depth: usize,
) -> PyResult<Vec<ExtractedRecord>> {
    Ok(extract_urlfinder_candidates_core(
        pages,
        allowed_hosts,
        allow_js,
        max_url_records,
        max_js_files,
        max_js_depth,
    ))
}

#[cfg(not(test))]
#[pyfunction]
fn rank_sensitive_targets(
    records: Vec<(String, String, String, String)>,
    sites: Vec<String>,
    blocked_hosts: Vec<String>,
    include_js: bool,
    max_targets: usize,
) -> PyResult<Vec<(String, i32)>> {
    Ok(rank_sensitive_targets_core(
        records,
        sites,
        blocked_hosts,
        include_js,
        max_targets,
    ))
}

#[cfg(not(test))]
#[pyfunction]
fn extract_html_candidates(
    pages: Vec<PageInput>,
    allowed_hosts: Vec<String>,
    allowed_flds: Vec<String>,
    exclude_hosts: Vec<String>,
) -> PyResult<Vec<ExtractedRecord>> {
    Ok(extract_html_candidates_core(
        pages,
        allowed_hosts,
        allowed_flds,
        exclude_hosts,
    ))
}

#[cfg(not(test))]
#[pyfunction]
fn extract_js_endpoint_candidates(
    pages: Vec<PageInput>,
    allowed_hosts: Vec<String>,
    max_records: usize,
) -> PyResult<Vec<ExtractedRecord>> {
    Ok(extract_js_endpoint_candidates_core(
        pages,
        allowed_hosts,
        max_records,
    ))
}

#[cfg(not(test))]
#[pymodule]
fn arl_accel(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_urlfinder_candidates, m)?)?;
    m.add_function(wrap_pyfunction!(rank_sensitive_targets, m)?)?;
    m.add_function(wrap_pyfunction!(extract_html_candidates, m)?)?;
    m.add_function(wrap_pyfunction!(extract_js_endpoint_candidates, m)?)?;
    m.add_function(wrap_pyfunction!(unified_normalize_urls, m)?)?;
    m.add_function(wrap_pyfunction!(unified_canonical_methods, m)?)?;
    m.add_function(wrap_pyfunction!(unified_document_type_hints, m)?)?;
    m.add_function(wrap_pyfunction!(unified_dedupe_endpoints, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_relative_and_route_candidates() {
        let hosts = HashSet::from(["example.test".to_string()]);
        assert_eq!(
            normalize_url(
                "https://example.test/app/index.html",
                "../api/users|get#fragment",
                &hosts,
            )
            .as_deref(),
            Some("https://example.test/api/users")
        );
    }

    #[test]
    fn filters_cross_domain_candidates() {
        let hosts = HashSet::from(["example.test".to_string()]);
        assert!(normalize_url("https://example.test/", "https://other.test/api", &hosts).is_none());
    }

    #[test]
    fn extracts_relative_protocol_relative_and_recursive_js_candidates() {
        let first_page = r#"
            <script src="/static/app.js"></script>
            <a href="/api/users">users</a>
            <a href="//example.test/admin">admin</a>
            <a href="https://other.test/should-not-cross-scope">external</a>
            <a href="https://:invalid/bad">malformed</a>
        "#;
        let child_page = r#"const next = './child.js'; const endpoint = '../api/orders?id=1';"#;
        let records = extract_urlfinder_candidates_core(
            vec![
                (
                    "https://example.test/app/index.html".to_string(),
                    first_page.to_string(),
                    "https://example.test/app/index.html".to_string(),
                    0,
                    false,
                ),
                (
                    "https://example.test/static/app.js".to_string(),
                    child_page.to_string(),
                    "https://example.test/app/index.html".to_string(),
                    1,
                    true,
                ),
            ],
            vec!["example.test".to_string()],
            true,
            20,
            20,
            2,
        );

        let js_url_record = records
            .iter()
            .find(|item| item.1 == "https://example.test/api/orders?id=1")
            .expect("recursive JS URL should be extracted");
        assert_eq!(js_url_record.2, "https://example.test/static/app.js");

        let contents: HashSet<String> = records.into_iter().map(|item| item.1).collect();
        assert!(contents.contains("https://example.test/static/app.js"));
        assert!(contents.contains("https://example.test/api/users"));
        assert!(contents.contains("https://example.test/admin"));
        assert!(contents.contains("https://example.test/api/orders?id=1"));
        assert!(!contents.iter().any(|item| item.contains("other.test")));
        assert!(!contents.iter().any(|item| item.contains("invalid")));
    }

    #[test]
    fn deduplicates_before_url_record_limit() {
        let records = extract_urlfinder_candidates_core(
            vec![(
                "https://example.test/index.html".to_string(),
                r#"<a href="/api/a"></a><a href="/api/a"></a><a href="/api/b"></a>"#.to_string(),
                "https://example.test/index.html".to_string(),
                0,
                false,
            )],
            vec!["example.test".to_string()],
            true,
            2,
            20,
            2,
        );

        let contents: HashSet<String> = records.into_iter().map(|item| item.1).collect();
        assert!(contents.contains("https://example.test/api/a"));
        assert!(contents.contains("https://example.test/api/b"));
    }

    #[test]
    fn accepts_uppercase_http_scheme() {
        let records = extract_urlfinder_candidates_core(
            vec![(
                "https://example.test/index.html".to_string(),
                "HTTP://example.test/api/up".to_string(),
                "https://example.test/index.html".to_string(),
                0,
                false,
            )],
            vec!["example.test".to_string()],
            true,
            20,
            20,
            2,
        );

        assert!(records
            .iter()
            .any(|item| item.1 == "http://example.test/api/up"));
    }

    #[test]
    fn filters_static_files_and_url_annotations_for_sensitive_targets() {
        let targets = rank_sensitive_targets_core(
            vec![
                (
                    "urlfinder_url".to_string(),
                    "https://example.test/static/logo.png".to_string(),
                    "https://example.test/app.js".to_string(),
                    "https://example.test".to_string(),
                ),
                (
                    "urlfinder_url".to_string(),
                    "https://example.test/admin/export?id=1 (status=200)".to_string(),
                    "https://example.test/app.js".to_string(),
                    "https://example.test".to_string(),
                ),
                (
                    "urlfinder_url".to_string(),
                    "https://other.test/admin".to_string(),
                    "https://example.test/app.js".to_string(),
                    "https://example.test".to_string(),
                ),
            ],
            vec!["https://example.test".to_string()],
            Vec::new(),
            true,
            10,
        );

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].0, "https://example.test/admin/export?id=1");
        assert_eq!(targets[1].0, "https://example.test/app.js");
    }

    #[test]
    fn ranks_sensitive_targets_deterministically() {
        let score = score_candidate(
            "https://example.test/admin/export?id=1",
            "urlfinder_url",
            "https://example.test/",
        );
        assert!(score > 20);
    }

    #[test]
    fn extracts_html_links_forms_scripts_and_scoped_domains() {
        let html = r#"
            <a href="/admin">admin</a>
            <iframe src="//example.test/frame"></iframe>
            <form action="/login" method="post">
                <input name="username">
                <input name="password">
            </form>
            <script src="/static/app.js"></script>
            <span>api.example.test</span>
            <span>other.test</span>
        "#;
        let records = extract_html_candidates_core(
            vec![(
                "https://example.test/index.html".to_string(),
                html.to_string(),
                "https://example.test/index.html".to_string(),
                0,
                false,
            )],
            vec!["example.test".to_string()],
            vec!["example.test".to_string()],
            vec!["example.test".to_string()],
        );

        assert!(records
            .iter()
            .any(|record| record.0 == "page_link" && record.1 == "https://example.test/admin"));
        assert!(records.iter().any(|record| {
            record.0 == "page_form"
                && record
                    .1
                    .contains("POST https://example.test/login [password,username]")
        }));
        assert!(records.iter().any(|record| {
            record.0 == "urlfinder_js" && record.1 == "https://example.test/static/app.js"
        }));
        assert!(records
            .iter()
            .any(|record| record.0 == "domain" && record.1 == "api.example.test"));
        assert!(!records.iter().any(|record| record.1 == "other.test"));
    }

    #[test]
    fn unified_normalize_matches_python_safe_subset() {
        // 期望值全部来自 CPython 3.10 normalize_url 实测（golden 见 corpus fixture）。
        let cases = [
            ("https://Example.test/Path?x=1#frag", "https://example.test/Path?x=1"),
            ("http://example.test:80/a", "http://example.test/a"),
            ("https://example.test:443", "https://example.test/"),
            ("http://example.test:8080/a?b=2#z", "http://example.test:8080/a?b=2"),
            ("https://example.test", "https://example.test/"),
            ("https://example.test?a=b", "https://example.test/?a=b"),
            ("https://user:pw@example.test/x", "https://example.test/x"),
            ("https://a.b:080/x", "https://a.b:80/x"),
            ("https://a.b:0/x", "https://a.b/x"),
            ("https://a.b:/x", "https://a.b/x"),
            ("https://a.b:99999/x", "https://a.b:99999/x"),
            ("https://a.b:abc/x", "https://a.b:abc/x"),
            ("https://example.test./x", "https://example.test/x"),
            ("https://a.b/a%2Fb?c=%3Cd#e", "https://a.b/a%2Fb?c=%3Cd"),
            ("https://a.b/a?b=1#?c", "https://a.b/a?b=1"),
            ("", ""),
            ("HTTPS://a.b/x", "HTTPS://a.b/x"),
            ("ftp://a.b/x", "ftp://a.b/x"),
            ("/rel/path", "/rel/path"),
            ("https://a.b\tc/x", "https://a.b\tc/x"),
            ("https://[::1]:8080/x", "https://[::1]:8080/x"),
            ("https://:8080/x", "https://:8080/x"),
        ];
        for (input, expected) in cases {
            assert_eq!(normalize_url_unified(input), expected, "input: {}", input);
        }
    }

    #[test]
    fn unified_canonical_methods_align() {
        assert_eq!(canonical_method_unified(" get "), "GET");
        assert_eq!(canonical_method_unified("POST"), "POST");
        assert_eq!(canonical_method_unified("weird"), "GET");
        assert_eq!(canonical_method_unified(""), "GET");
        assert_eq!(canonical_method_unified("TRACE"), "GET");
    }

    #[test]
    fn unified_document_type_hints_align() {
        assert_eq!(document_type_hint_unified("https://a.b/v3/API-DOCS"), "swagger");
        assert_eq!(document_type_hint_unified("https://a.b/openapi.json"), "openapi");
        assert_eq!(document_type_hint_unified("https://a.b/x?y=postman"), "postman");
        assert_eq!(document_type_hint_unified("https://a.b/s?singleWsdl"), "wsdl");
        assert_eq!(document_type_hint_unified("https://a.b/GraphiQL"), "graphql");
        // 顺序即优先级：postman 先于 openapi。
        assert_eq!(
            document_type_hint_unified("https://a.b/openapi.postman.json"),
            "postman"
        );
        assert_eq!(document_type_hint_unified("https://a.b/api/users"), "unknown");
    }

    #[test]
    fn unified_dedupe_merges_sources_in_first_seen_order() {
        let records: Vec<(String, String, String, String, String)> = [
            ("https://a.b/u", "GET", "rest", "", "js"),
            ("https://a.b/u", "POST", "rest", "", "doc"),
            ("https://a.b/u", "GET", "rest", "", "browser"),
            ("https://a.b/u", "GET", "graphql", "", ""),
            ("https://a.b/u", "GET", "rest", "/v1", "page"),
        ]
        .into_iter()
        .map(|(a, b, c, d, e)| {
            (
                a.to_string(),
                b.to_string(),
                c.to_string(),
                d.to_string(),
                e.to_string(),
            )
        })
        .collect();
        let merged = dedupe_endpoint_records_core(&records);
        assert_eq!(merged.len(), 4);
        assert_eq!(merged[0].0, 0);
        assert_eq!(merged[0].1, vec!["browser".to_string(), "js".to_string()]);
        assert_eq!(merged[1].0, 1);
        assert_eq!(merged[2].0, 3);
        assert!(merged[2].1.is_empty());
        assert_eq!(merged[3].0, 4);
    }

    #[test]
    fn py_strip_matches_cpython_whitespace_set() {
        // CPython str.strip() 把 U+001C-001F 当空白，Rust trim() 不是（P2-1）。
        assert_eq!(py_strip("\u{1c}abc\u{1d}"), "abc");
        assert_eq!(py_strip(" \t\n\u{1c}\u{1f}x\u{85}\u{a0}"), "x");
        assert_eq!(py_strip("\u{1c}"), "");
        assert_eq!(py_strip("a\u{200b}b"), "a\u{200b}b"); // ZWSP 两侧都非空白
    }

    #[test]
    fn dedupe_source_trim_follows_python_whitespace() {
        let records = vec![
            ("u".to_string(), "GET".to_string(), "rest".to_string(), String::new(),
             "\u{1c}abc".to_string()),
            ("u".to_string(), "GET".to_string(), "rest".to_string(), String::new(),
             "\u{1c}".to_string()),
        ];
        let merged = dedupe_endpoint_records_core(&records);
        // \u{1c}abc 归一为 "abc"（与 Python strip 一致），纯 \u{1c} 剔除。
        assert_eq!(merged, vec![(0, vec!["abc".to_string()])]);
    }

    // F6（第 11 批）：legacy 提取面 trim 语义钉——以下行为点对齐 Python
    // `str.strip()`（U+001C-001F 为空白），防再引入 Rust `trim()` 偏差。

    #[test]
    fn legacy_clean_candidate_follows_python_whitespace() {
        assert_eq!(clean_candidate("\u{1c}/api/users\u{1d}"), "/api/users");
        assert_eq!(clean_candidate("\u{1c}\u{1e}"), "");
        // 先空白后引号的次序与 Python `_clean_candidate`（strip→strip(chars)→unquote→strip）一致：
        // 引号内的控制字符由末次 strip 收敛。
        assert_eq!(clean_candidate("\"\u{1c}foo\""), "foo");
    }

    #[test]
    fn legacy_host_and_js_url_helpers_follow_python_whitespace() {
        assert_eq!(
            extract_host("\u{1c}https://example.test/\u{1d}").as_deref(),
            Some("example.test")
        );
        assert!(is_js_url("https://example.test/a.js\u{1c}"));
        assert!(!is_js_url("\u{1c}\u{1d}"));
        assert_eq!(strip_route_method_suffix("\u{1c}/a|GET\u{1d}"), "/a");
    }

    #[test]
    fn legacy_pattern_tokens_follow_python_whitespace() {
        // 捕获组字符类不排除 C0 控制符：token 内含尾随 \u{1d} 时，
        // Python `_extract_by_patterns` 的 strip() 会收敛，Rust trim() 不会——
        // 该分歧会沿 normalize_url 固化成 percent-encoded 路径差异（F6 实证面）。
        assert_eq!(
            pattern_tokens("fetch('/api/v1/users\u{1d}');", &URL_PATTERNS[1]),
            vec!["/api/v1/users".to_string()]
        );
    }

    #[test]
    fn legacy_empty_control_only_records_are_dropped() {
        let mut records: Vec<ExtractedRecord> = Vec::new();
        let mut seen = HashSet::new();
        append_page_record(
            &mut records,
            &mut seen,
            "page_link",
            "\u{1c}",
            "https://example.test/src",
            "https://example.test",
            0,
        );
        // Python 基线在 token 层 strip 后为空即不产出；Rust 面同判。
        assert!(records.is_empty());
    }

    #[test]
    fn legacy_rank_record_type_follows_python_whitespace() {
        let records = vec![(
            "\u{1c}urlfinder_url".to_string(),
            "https://example.test/api/users\u{1d}".to_string(),
            "https://example.test/page.html".to_string(),
            "https://example.test".to_string(),
        )];
        let targets = rank_sensitive_targets_core(
            records,
            vec!["https://example.test".to_string()],
            vec![],
            false,
            10,
        );
        assert!(
            targets
                .iter()
                .any(|(target, _)| target == "https://example.test/api/users"),
            "record_type 前导 \\u{{1c}} 不得吞掉排序输入（Python recordType.strip() 语义）: {targets:?}"
        );
    }

    #[test]
    fn api_doc_keywords_align_with_unified_type_hints() {
        // 第 10 批口径钉：Rust 面必须覆盖统一面 _TYPE_HINT_KEYWORDS 全部关键词；
        // 非文档形态不误报。Python 镜像钉见 ARL/test/test_rust_accel.py。
        for url in [
            "https://example.test/swagger.json",
            "https://example.test/openapi.yaml",
            "https://example.test/v3/api-docs",
            "https://example.test/collection.postman.json",
            "https://example.test/service?singleWsdl",
            "https://example.test/graphql",
            "https://example.test/graphiql",
        ] {
            assert!(is_api_doc_candidate(url), "{} should be doc candidate", url);
        }
        assert!(!is_api_doc_candidate("https://example.test/api/users"));
        assert!(!is_api_doc_candidate("https://example.test/static/app.js"));
    }

    #[test]
    fn extracts_js_endpoint_and_api_doc_candidates_in_batch() {
        assert!(URL_PATTERNS[1].is_match("fetch('/api/v1/users');"));
        assert!(JS_ENDPOINT_PATTERNS[1].is_match("fetch('/api/v1/users');"));
        assert_eq!(
            normalize_page_url(
                "https://example.test/static/app.js",
                "/api/v1/users",
                &HashSet::from(["example.test".to_string()]),
                false,
            )
            .as_deref(),
            Some("https://example.test/api/v1/users")
        );
        let records = extract_js_endpoint_candidates_core(
            vec![(
                "https://example.test/static/app.js".to_string(),
                r#"fetch('/api/v1/users'); const docs='/v3/api-docs';"#.to_string(),
                "https://example.test/static/app.js".to_string(),
                0,
                true,
            )],
            vec!["example.test".to_string()],
            100,
        );

        assert!(records.iter().any(|record| {
            record.0 == "urlfinder_url" && record.1 == "https://example.test/api/v1/users"
        }));
        assert!(records.iter().any(|record| {
            record.0 == "api_doc_url" && record.1 == "https://example.test/v3/api-docs"
        }));
    }
}
