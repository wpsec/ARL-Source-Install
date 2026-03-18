# coding: utf-8
"""
TLS/SSL 合规基线判定工具。

功能说明：
- 统一判定 SSL/TLS 协议与加密套件是否符合 ARL 当前导出基线
- 生成可直接写入报告的“不合规项”与“修复建议”
- 为扫描结果持久化和导出复用同一套规则，避免口径漂移

基线原则：
- 协议仅允许 TLSv1.2 / TLSv1.3
- TLS 1.2 优先 ECDHE + AEAD（AES-GCM / CHACHA20，必要时 AES-CCM）
- TLS 1.3 允许 RFC 8446 标准套件
- 禁用 RC4 / 3DES / DES / MD5 / NULL / EXPORT / 匿名套件 / 静态 RSA
- DHE 若保留，DH 参数至少 2048 位
"""

import re

TLS_POLICY_VERSION = "2026.03"
TLS_POLICY_NAME = "ARL TLS 基线"
TLS_GUIDE_PATH = "docs/ssl_tls_cipher_compliance_baseline.md"

_ALLOWED_PROTOCOLS = {"TLSV1.2", "TLSV1.3"}
_LEGACY_PROTOCOLS = {"SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1"}
_TLS13_BASELINE_SUITES = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
}
_TLS12_AEAD_MARKERS = (
    "_AES_128_GCM_",
    "_AES_256_GCM_",
    "_CHACHA20_POLY1305_",
    "_AES_128_CCM_",
    "_AES_128_CCM_8_",
    "_AES_256_CCM_",
    "_AES_256_CCM_8_",
)
_REMEDIATION_CIPHER_LIST = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305"
)


def _safe_text(value):
    """
    将任意值安全归一化为字符串。
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").strip()
    return str(value).strip()


def normalize_tls_protocol_name(name):
    """
    统一协议名称格式，便于规则判定与展示。
    """
    value = _safe_text(name).replace(" ", "")
    if not value:
        return ""

    lower = value.lower()
    if lower.startswith("tlsv"):
        return "TLSv{}".format(value[4:])
    if lower.startswith("sslv"):
        return "SSLv{}".format(value[4:])
    return value


def normalize_cipher_suite_name(name):
    """
    归一化套件名称，去除 nmap 附加参数并兼容 TLS 1.3 旧命名。
    """
    value = _safe_text(name)
    if not value:
        return ""

    value = re.sub(r"\s+\([^)]*\)", "", value).strip().upper()
    value = value.replace(" ", "")
    if value.startswith("TLS_AKE_WITH_"):
        value = "TLS_" + value[len("TLS_AKE_WITH_"):]
    return value


def _extract_dh_bits(name):
    """
    从套件展示文本中提取 DH 位数，如 "(dh 1024)" 或 "(ffdhe2048)"。
    """
    text = _safe_text(name)
    if not text:
        return 0

    for pattern in [
        r"\(\s*dh\s+(\d{3,5})\s*\)",
        r"\(\s*ffdhe(\d{3,5})\s*\)",
        r"\bffdhe(\d{3,5})\b",
    ]:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            try:
                return int(match.group(1))
            except Exception:
                return 0
    return 0


def _suite_display(protocol, raw_name):
    """
    拼装报告展示文本。
    """
    protocol = normalize_tls_protocol_name(protocol)
    name = _safe_text(raw_name)
    if protocol:
        return "[{}] {}".format(protocol, name)
    return name


def _new_compliance_result():
    """
    构造默认合规结果结构。
    """
    return {
        "policy_name": TLS_POLICY_NAME,
        "policy_version": TLS_POLICY_VERSION,
        "guide_path": TLS_GUIDE_PATH,
        "has_issue": False,
        "issue_codes": [],
        "issues": [],
        "non_compliant_text": "",
        "remediation_text": "",
        "summary": "未发现不合规项",
    }


def _append_issue(issue_map, key, item_type, display, code, reason):
    """
    以“同一项合并多原因”的方式累计问题。
    """
    if not display or not code or not reason:
        return

    issue = issue_map.get(key)
    if not issue:
        issue = {
            "type": item_type,
            "display": display,
            "codes": [],
            "reasons": [],
        }
        issue_map[key] = issue

    if code not in issue["codes"]:
        issue["codes"].append(code)
    if reason not in issue["reasons"]:
        issue["reasons"].append(reason)


def _has_any_token(name, tokens):
    """
    判断套件名中是否包含任一关键字。
    """
    for token in tokens:
        if token in name:
            return True
    return False


def _is_tls12_baseline_suite(base_name, dh_bits):
    """
    判定 TLS 1.2 套件是否符合当前基线。
    """
    if not base_name:
        return False

    if base_name.startswith(("TLS_ECDHE_RSA_WITH_", "TLS_ECDHE_ECDSA_WITH_")):
        return _has_any_token(base_name, _TLS12_AEAD_MARKERS)

    if base_name.startswith("TLS_DHE_RSA_WITH_"):
        return dh_bits >= 2048 and _has_any_token(base_name, _TLS12_AEAD_MARKERS)

    return False


def _sort_issues(issues):
    """
    协议问题优先，其次按展示文本稳定排序。
    """
    def sort_key(item):
        issue_type = _safe_text(item.get("type"))
        display = _safe_text(item.get("display"))
        return (0 if issue_type == "protocol" else 1, display)

    return sorted(issues, key=sort_key)


def _build_non_compliant_text(issues):
    """
    生成导出报告中的不合规项文本。
    """
    lines = []
    for item in issues:
        display = _safe_text(item.get("display"))
        reasons = [_safe_text(reason) for reason in item.get("reasons", []) if _safe_text(reason)]
        if not display:
            continue
        if reasons:
            lines.append("{} -> {}".format(display, "；".join(reasons)))
        else:
            lines.append(display)
    return "\r\n".join(lines)


def _build_remediation_text(issue_codes):
    """
    基于问题类型拼装常规部署与 K8s 部署修复建议。
    """
    codes = set(issue_codes or [])
    if not codes:
        return ""

    actions = []
    if "legacy_protocol" in codes or "unknown_protocol" in codes:
        actions.append("协议加固：仅启用 TLSv1.2/TLSv1.3，关闭 SSLv2/SSLv3/TLSv1.0/TLSv1.1。")
    if {
        "weak_block_cipher",
        "weak_hash",
        "null_or_export_cipher",
        "anonymous_cipher",
        "cbc_mode",
        "no_forward_secrecy",
        "not_in_baseline",
    } & codes:
        actions.append(
            "套件加固：仅保留 ECDHE + AEAD 套件，优先 AES-GCM/CHACHA20；禁用 RC4/3DES/DES/MD5/NULL/EXPORT/CBC/静态 RSA。"
        )
    if "weak_dh_param" in codes:
        actions.append("密钥交换加固：如需保留 DHE，请使用 FFDHE2048 或更高参数，优先 X25519 / secp256r1 等 ECDHE 曲线。")

    actions.append(
        "常规部署：Nginx 使用 `ssl_protocols TLSv1.2 TLSv1.3;`、`ssl_ciphers {}`；Apache 使用 `SSLProtocol -all +TLSv1.2 +TLSv1.3`、`SSLCipherSuite {}`。".format(
            _REMEDIATION_CIPHER_LIST,
            _REMEDIATION_CIPHER_LIST,
        )
    )
    actions.append(
        "K8s 集群：在 ingress-nginx ConfigMap 或 Ingress 注解中设置 `ssl-protocols: TLSv1.2 TLSv1.3`、`ssl-ciphers: {}`；如保留 DHE，在 ConfigMap 中通过 `ssl-dh-param: <namespace>/<secret>` 下发 2048 位以上 DH 参数。".format(
            _REMEDIATION_CIPHER_LIST
        )
    )
    actions.append("详细规范与示例见 `{}`。".format(TLS_GUIDE_PATH))

    return "\r\n".join(actions)


def analyze_ssl_security_compliance(ssl_security):
    """
    分析 ssl_security 字段并输出统一的 TLS 合规结果。
    """
    result = _new_compliance_result()
    if not isinstance(ssl_security, dict):
        return result

    issue_map = {}

    protocol_names = []
    protocols = ssl_security.get("protocols", [])
    if isinstance(protocols, list):
        for item in protocols:
            name = item.get("name", "") if isinstance(item, dict) else item
            protocol = normalize_tls_protocol_name(name)
            if protocol:
                protocol_names.append(protocol)

    if not protocol_names and isinstance(ssl_security.get("protocol_names"), list):
        for name in ssl_security.get("protocol_names", []):
            protocol = normalize_tls_protocol_name(name)
            if protocol:
                protocol_names.append(protocol)

    for protocol in sorted(set(protocol_names)):
        upper_protocol = protocol.upper()
        display = "[协议] {}".format(protocol)
        if upper_protocol in _LEGACY_PROTOCOLS:
            _append_issue(
                issue_map,
                "protocol:{}".format(protocol),
                "protocol",
                display,
                "legacy_protocol",
                "旧版协议已淘汰，应仅保留 TLSv1.2/TLSv1.3",
            )
        elif upper_protocol not in _ALLOWED_PROTOCOLS:
            _append_issue(
                issue_map,
                "protocol:{}".format(protocol),
                "protocol",
                display,
                "unknown_protocol",
                "不在当前 TLS 基线允许范围内",
            )

    cipher_suites = ssl_security.get("cipher_suites", [])
    if isinstance(cipher_suites, list):
        for item in cipher_suites:
            if not isinstance(item, dict):
                continue

            protocol = normalize_tls_protocol_name(item.get("protocol", ""))
            raw_name = _safe_text(item.get("name", ""))
            base_name = normalize_cipher_suite_name(raw_name)
            if not base_name:
                continue

            dh_bits = _extract_dh_bits(raw_name)
            display = _suite_display(protocol, raw_name)
            issue_key = "cipher:{}:{}".format(protocol, display)

            if _has_any_token(base_name, ("_NULL_", "EXPORT", "_EXPORT_")):
                _append_issue(
                    issue_map,
                    issue_key,
                    "cipher",
                    display,
                    "null_or_export_cipher",
                    "包含 NULL/EXPORT 套件，属于高风险配置",
                )
            if _has_any_token(base_name, ("_ADH_", "_AECDH_", "_ANON_")):
                _append_issue(
                    issue_map,
                    issue_key,
                    "cipher",
                    display,
                    "anonymous_cipher",
                    "匿名套件缺少可靠身份认证，不应启用",
                )
            if _has_any_token(base_name, ("RC4", "3DES", "_DES_")):
                _append_issue(
                    issue_map,
                    issue_key,
                    "cipher",
                    display,
                    "weak_block_cipher",
                    "使用 RC4/3DES/DES 等弱加密算法",
                )
            if "MD5" in base_name:
                _append_issue(
                    issue_map,
                    issue_key,
                    "cipher",
                    display,
                    "weak_hash",
                    "使用 MD5 摘要算法，不符合当前基线",
                )
            if base_name.startswith("TLS_RSA_WITH_") or base_name.startswith(("TLS_DH_", "TLS_ECDH_")):
                _append_issue(
                    issue_map,
                    issue_key,
                    "cipher",
                    display,
                    "no_forward_secrecy",
                    "静态密钥交换不提供前向保密",
                )
            if "_CBC_" in base_name:
                _append_issue(
                    issue_map,
                    issue_key,
                    "cipher",
                    display,
                    "cbc_mode",
                    "CBC 套件不在当前互联网 TLS 加固基线内",
                )
            if base_name.startswith("TLS_DHE_") and dh_bits and dh_bits < 2048:
                _append_issue(
                    issue_map,
                    issue_key,
                    "cipher",
                    display,
                    "weak_dh_param",
                    "DHE 参数仅 {} 位，低于 2048 位基线".format(dh_bits),
                )

            has_specific_issue = issue_key in issue_map
            upper_protocol = protocol.upper()
            if upper_protocol == "TLSV1.3":
                if base_name not in _TLS13_BASELINE_SUITES and not has_specific_issue:
                    _append_issue(
                        issue_map,
                        issue_key,
                        "cipher",
                        display,
                        "not_in_baseline",
                        "不属于 TLS 1.3 推荐标准套件",
                    )
            elif upper_protocol == "TLSV1.2":
                if not _is_tls12_baseline_suite(base_name, dh_bits) and not has_specific_issue:
                    _append_issue(
                        issue_map,
                        issue_key,
                        "cipher",
                        display,
                        "not_in_baseline",
                        "不属于 TLS 1.2 推荐套件基线",
                    )

    issues = _sort_issues(list(issue_map.values()))
    issue_codes = sorted(
        {
            _safe_text(code)
            for issue in issues
            for code in issue.get("codes", [])
            if _safe_text(code)
        }
    )

    result["issues"] = issues
    result["issue_codes"] = issue_codes
    result["has_issue"] = bool(issues)
    result["non_compliant_text"] = _build_non_compliant_text(issues)
    result["remediation_text"] = _build_remediation_text(issue_codes)
    if issues:
        result["summary"] = "发现 {} 项 TLS 不合规内容".format(len(issues))
    return result


def get_ssl_security_compliance(ssl_security):
    """
    优先复用已持久化的合规分析，缺失时即时重新计算。
    """
    if isinstance(ssl_security, dict):
        compliance = ssl_security.get("compliance")
        if (
            isinstance(compliance, dict)
            and _safe_text(compliance.get("policy_version")) == TLS_POLICY_VERSION
        ):
            return compliance
    return analyze_ssl_security_compliance(ssl_security)
