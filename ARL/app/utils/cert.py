"""
证书处理工具
"""
import ssl
import OpenSSL
import socket
import shutil
import subprocess
import re
import ipaddress
from collections import Counter
from datetime import datetime

socket.setdefaulttimeout(6)


def _safe_text(value):
    """
    将各种输入安全转为字符串，避免后续拼接异常。
    """
    if value is None:
        return ""
    return str(value).strip()


def _is_ip_address(value):
    """
    判断输入是否是 IP 地址（v4/v6）。
    """
    text = _safe_text(value)
    if not text:
        return False

    try:
        ipaddress.ip_address(text)
        return True
    except Exception:
        return False


def _normalize_server_hostname(value):
    """
    归一化 SNI 主机名，IP/空值返回空字符串。
    """
    hostname = _safe_text(value).strip(".").lower()
    if not hostname:
        return ""
    if _is_ip_address(hostname):
        return ""
    return hostname


def _normalize_hash_text(value):
    """
    归一化哈希文本，仅保留十六进制字符。
    """
    return re.sub(r"[^0-9a-fA-F]", "", _safe_text(value)).lower()


def _normalize_cert_time_text(value):
    """
    统一证书时间文本格式（优先空格分隔）。
    """
    text = _safe_text(value)
    if not text:
        return ""
    return text.replace("T", " ")


def _extract_dn_attr(dn_text, attr_name):
    """
    从形如 key=value/key=value 的 DN 文本提取属性。
    """
    text = _safe_text(dn_text)
    if not text:
        return ""

    pattern = re.compile(r"(?:^|/)\s*{}\s*=\s*([^/]+)".format(re.escape(attr_name)), re.IGNORECASE)
    match = pattern.search(text)
    if not match:
        return ""
    return _safe_text(match.group(1))


def _extract_dns_patterns_from_cert(cert_obj):
    """
    从证书对象提取可匹配域名模式（CN + SAN DNS）。
    """
    if not isinstance(cert_obj, dict):
        return []

    patterns = []
    seen = set()

    def _append(pattern):
        text = _safe_text(pattern).lower().rstrip(".")
        if not text:
            return
        if text.startswith("*."):
            text = "*.{}".format(text[2:].strip())
        if text in seen:
            return
        seen.add(text)
        patterns.append(text)

    subject = cert_obj.get("subject", {})
    if isinstance(subject, dict):
        _append(subject.get("common_name", ""))

    extensions = cert_obj.get("extensions", {})
    if isinstance(extensions, dict):
        san_text = _safe_text(extensions.get("subjectAltName", ""))
        for raw in san_text.split(","):
            item = _safe_text(raw)
            if not item:
                continue
            if ":" in item:
                prefix, value = item.split(":", 1)
                if _safe_text(prefix).lower() != "dns":
                    continue
                _append(value)
            else:
                _append(item)

    return patterns


def _match_hostname_pattern(pattern, hostname):
    """
    证书域名模式匹配：支持精确和单级通配符。
    """
    pattern = _safe_text(pattern).lower().rstrip(".")
    hostname = _safe_text(hostname).lower().rstrip(".")
    if not pattern or not hostname:
        return False

    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not suffix:
            return False
        if hostname == suffix:
            return False
        if not hostname.endswith(".{}".format(suffix)):
            return False
        left = hostname[:-(len(suffix) + 1)]
        return bool(left) and "." not in left

    return hostname == pattern


def _cert_matches_server_hostname(cert_obj, server_hostname):
    """
    判断证书是否命中指定 server_hostname。
    """
    hostname = _normalize_server_hostname(server_hostname)
    if not hostname:
        return False

    patterns = _extract_dns_patterns_from_cert(cert_obj)
    for pattern in patterns:
        if _match_hostname_pattern(pattern, hostname):
            return True
    return False


def _looks_like_default_or_fake_cert(cert_obj):
    """
    识别常见默认证书/假证书特征。
    """
    if not isinstance(cert_obj, dict):
        return False

    texts = [
        _safe_text(cert_obj.get("subject_dn", "")).lower(),
        _safe_text(cert_obj.get("issuer_dn", "")).lower(),
    ]

    subject = cert_obj.get("subject", {})
    if isinstance(subject, dict):
        texts.append(_safe_text(subject.get("common_name", "")).lower())

    extensions = cert_obj.get("extensions", {})
    if isinstance(extensions, dict):
        texts.append(_safe_text(extensions.get("subjectAltName", "")).lower())

    joined = " ".join([x for x in texts if x])
    if not joined:
        return False

    hit_keywords = [
        "kubernetes ingress controller fake certificate",
        "ingress.local",
        "acme co",
        "fake certificate",
    ]
    for keyword in hit_keywords:
        if keyword in joined:
            return True
    return False


def _should_probe_nmap_ssl_cert(parsed_cert, server_hostname=""):
    """
    仅在“疑似不准/可疑”场景触发 nmap ssl-cert，平衡准确性与性能。
    """
    if not isinstance(parsed_cert, dict) or not parsed_cert:
        return True

    if _looks_like_default_or_fake_cert(parsed_cert):
        return True

    normalized_sni = _normalize_server_hostname(server_hostname)
    if normalized_sni and not _cert_matches_server_hostname(parsed_cert, normalized_sni):
        return True

    return False


def _fetch_server_certificate(connect_host, port, server_hostname=""):
    """
    获取远端证书 PEM：
    - 支持 connect_host 与 server_hostname 分离（SNI）
    - 失败时回退 ssl.get_server_certificate
    """
    connect_host = _safe_text(connect_host)
    if not connect_host:
        return ""

    try:
        port = int(port)
    except Exception:
        return ""

    if port <= 0:
        return ""

    normalized_sni = _normalize_server_hostname(server_hostname)
    if not normalized_sni and not _is_ip_address(connect_host):
        normalized_sni = _normalize_server_hostname(connect_host)

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((connect_host, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=normalized_sni or None) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)
                if cert_der:
                    return ssl.DER_cert_to_PEM_cert(cert_der)
    except Exception:
        pass

    try:
        return ssl.get_server_certificate((connect_host, port))
    except Exception:
        return ""


def _normalize_protocol_name(name):
    """
    统一协议名称格式，便于展示与导出聚合。
    """
    value = _safe_text(name).replace(" ", "")
    if not value:
        return ""

    lower = value.lower()
    if lower.startswith("tlsv"):
        suffix = value[4:]
        return "TLSv{}".format(suffix)
    if lower.startswith("sslv"):
        suffix = value[4:]
        return "SSLv{}".format(suffix)
    return value


def _parse_cipher_line(line):
    """
    解析 nmap ssl-enum-ciphers 中的单行套件信息。

    样例：
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A
    """
    text = _safe_text(line)
    if not text:
        return "", ""

    strength = ""
    cipher_name = text

    if " - " in text:
        left, right = text.rsplit(" - ", 1)
        right = _safe_text(right).upper()
        if right in {"A", "B", "C", "D", "E", "F"}:
            cipher_name = _safe_text(left)
            strength = right

    return cipher_name, strength


def _parse_ssl_enum_ciphers_output(raw_text):
    """
    解析 nmap ssl-enum-ciphers 原始输出，提取协议/套件/强度。
    """
    if not _safe_text(raw_text):
        return {}

    protocol_pattern = re.compile(r"^(SSLv[0-9.]+|TLSv[0-9.]+)\s*:\s*$", re.IGNORECASE)
    protocol_map = {}
    cipher_suites = []
    current_protocol = ""
    in_cipher_block = False
    least_strength = ""

    for raw_line in raw_text.splitlines():
        line = _safe_text(raw_line)
        if not line:
            continue

        # nmap 脚本输出以 | / |_ 开头，先统一清洗。
        line = line.lstrip("|").lstrip("_").strip()
        if not line:
            continue

        low = line.lower()
        if low.startswith("ssl-enum-ciphers"):
            continue

        protocol_match = protocol_pattern.match(line)
        if protocol_match:
            current_protocol = _normalize_protocol_name(protocol_match.group(1))
            if current_protocol and current_protocol not in protocol_map:
                protocol_map[current_protocol] = {
                    "name": current_protocol,
                    "supported": True,
                    "cipher_count": 0,
                }
            in_cipher_block = False
            continue

        if low.startswith("ciphers:"):
            in_cipher_block = bool(current_protocol)
            continue

        if low.startswith("compressors:") or low.startswith("compressor:"):
            in_cipher_block = False
            continue

        if low.startswith("cipher preference"):
            in_cipher_block = False
            continue

        if low.startswith("least strength"):
            _, _, right = line.partition(":")
            least_strength = _safe_text(right).upper()
            continue

        if not in_cipher_block or not current_protocol:
            continue

        cipher_name, strength = _parse_cipher_line(line)
        if not cipher_name:
            continue

        cipher_suites.append(
            {
                "protocol": current_protocol,
                "name": cipher_name,
                "strength": strength,
            }
        )
        protocol_map[current_protocol]["cipher_count"] += 1

    if not protocol_map and not cipher_suites and not least_strength:
        return {}

    protocol_names = sorted(protocol_map.keys())
    strength_counter = Counter(
        [item.get("strength", "") for item in cipher_suites if _safe_text(item.get("strength", ""))]
    )
    ecdhe_count = 0
    for item in cipher_suites:
        name = _safe_text(item.get("name", "")).upper()
        if "ECDHE" in name:
            ecdhe_count += 1

    strength_stat = {}
    for key in sorted(strength_counter.keys()):
        strength_stat[key] = strength_counter[key]

    return {
        "source": "nmap_ssl_enum_ciphers",
        "scan_time": str(datetime.utcnow()),
        "protocols": [protocol_map[name] for name in protocol_names],
        "protocol_names": protocol_names,
        "cipher_suites": cipher_suites,
        "cipher_total": len(cipher_suites),
        "ecdhe_count": ecdhe_count,
        "strength_stat": strength_stat,
        "least_strength": least_strength,
    }


def _scan_ssl_security_with_nmap(host, port, server_hostname=""):
    """
    调用 nmap ssl-enum-ciphers 脚本扫描协议与加密套件。
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return {}

    try:
        port = int(port)
    except Exception:
        return {}

    normalized_sni = _normalize_server_hostname(server_hostname)

    cmd = [
        nmap_bin,
        "-n",
        "-Pn",
        "--max-retries",
        "1",
        "--host-timeout",
        "20s",
        "--script-timeout",
        "15s",
        "-p",
        str(port),
        "--script",
        "ssl-enum-ciphers",
    ]
    if normalized_sni:
        cmd.extend(["--script-args", "tls.servername={}".format(normalized_sni)])
    cmd.append(str(host))

    try:
        # nmap 在目标无响应时可能返回非0，但 stdout 仍有可解析信息，因此不使用 check=True。
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=28,
            check=False,
        )
        parsed = _parse_ssl_enum_ciphers_output(result.stdout or "")
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _parse_ssl_cert_output_with_nmap(raw_text):
    """
    解析 nmap ssl-cert 输出，提取基础证书信息。
    """
    if not _safe_text(raw_text):
        return {}

    subject_dn = ""
    issuer_dn = ""
    san_text = ""
    signature_algorithm = ""
    not_before = ""
    not_after = ""
    md5 = ""
    sha1 = ""
    sha256 = ""

    for raw_line in raw_text.splitlines():
        line = _safe_text(raw_line)
        if not line:
            continue

        line = line.lstrip("|").lstrip("_").strip()
        if not line:
            continue

        if line.lower().startswith("ssl-cert:"):
            line = _safe_text(line.split(":", 1)[1])
            if not line:
                continue

        if line.startswith("Subject:"):
            subject_dn = _safe_text(line.split(":", 1)[1])
            continue
        if line.startswith("Issuer:"):
            issuer_dn = _safe_text(line.split(":", 1)[1])
            continue
        if line.startswith("Subject Alternative Name:"):
            san_text = _safe_text(line.split(":", 1)[1])
            continue
        if line.startswith("Signature Algorithm:"):
            signature_algorithm = _safe_text(line.split(":", 1)[1])
            continue
        if line.startswith("Not valid before:"):
            not_before = _normalize_cert_time_text(line.split(":", 1)[1])
            continue
        if line.startswith("Not valid after:"):
            not_after = _normalize_cert_time_text(line.split(":", 1)[1])
            continue
        if line.startswith("MD5:"):
            md5 = _normalize_hash_text(line.split(":", 1)[1])
            continue
        if line.startswith("SHA-1:"):
            sha1 = _normalize_hash_text(line.split(":", 1)[1])
            continue
        if line.startswith("SHA-256:"):
            sha256 = _normalize_hash_text(line.split(":", 1)[1])
            continue

    if not subject_dn and not issuer_dn and not sha256 and not sha1 and not md5:
        return {}

    validity = {
        "start": not_before,
        "end": not_after,
        "expired": "",
    }
    if not_after:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                validity["expired"] = datetime.utcnow() > datetime.strptime(not_after, fmt)
                break
            except Exception:
                continue

    subject_common_name = _extract_dn_attr(subject_dn, "commonName")
    issuer_common_name = _extract_dn_attr(issuer_dn, "commonName")

    return {
        "source": "nmap_ssl_cert",
        "scan_time": str(datetime.utcnow()),
        "subject_dn": subject_dn,
        "issuer_dn": issuer_dn,
        "signature_algorithm": signature_algorithm,
        "validity": validity,
        "extensions": {"subjectAltName": san_text},
        "subject": {
            "common_name": subject_common_name,
        },
        "issuer": {
            "common_name": issuer_common_name,
        },
        "fingerprint": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
        },
    }


def _scan_ssl_cert_with_nmap(host, port, server_hostname=""):
    """
    调用 nmap ssl-cert 脚本抓取证书，用于二次校验/兜底。
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return {}

    try:
        port = int(port)
    except Exception:
        return {}

    normalized_sni = _normalize_server_hostname(server_hostname)

    cmd = [
        nmap_bin,
        "-n",
        "-Pn",
        "--max-retries",
        "1",
        "--host-timeout",
        "20s",
        "--script-timeout",
        "15s",
        "-p",
        str(port),
        "-v",
        "--script",
        "ssl-cert",
    ]
    if normalized_sni:
        cmd.extend(["--script-args", "tls.servername={}".format(normalized_sni)])
    cmd.append(str(host))

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=28,
            check=False,
        )
        parsed = _parse_ssl_cert_output_with_nmap(result.stdout or "")
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _get_cert_fingerprint_sha256(cert_obj):
    """
    获取证书 SHA-256 指纹（不存在则返回空字符串）。
    """
    if not isinstance(cert_obj, dict):
        return ""
    fingerprint = cert_obj.get("fingerprint", {})
    if not isinstance(fingerprint, dict):
        return ""
    return _normalize_hash_text(fingerprint.get("sha256", ""))


def _merge_nmap_cert_into_parsed(parsed_cert, nmap_cert):
    """
    将 nmap ssl-cert 结果合并到 parse_certs 结构，优先覆盖关键身份字段。
    """
    if not isinstance(parsed_cert, dict):
        parsed_cert = {}
    if not isinstance(nmap_cert, dict) or not nmap_cert:
        return parsed_cert

    merged = dict(parsed_cert)
    merged["cert_source"] = "python_ssl+nmap_ssl_cert"

    if _safe_text(nmap_cert.get("subject_dn", "")):
        merged["subject_dn"] = _safe_text(nmap_cert.get("subject_dn", ""))
    if _safe_text(nmap_cert.get("issuer_dn", "")):
        merged["issuer_dn"] = _safe_text(nmap_cert.get("issuer_dn", ""))
    if _safe_text(nmap_cert.get("signature_algorithm", "")):
        merged["signature_algorithm"] = _safe_text(nmap_cert.get("signature_algorithm", ""))

    nmap_validity = nmap_cert.get("validity", {})
    if isinstance(nmap_validity, dict):
        validity = merged.get("validity", {}) if isinstance(merged.get("validity"), dict) else {}
        for key in ["start", "end", "expired"]:
            if nmap_validity.get(key) not in [None, ""]:
                validity[key] = nmap_validity.get(key)
        merged["validity"] = validity

    nmap_ext = nmap_cert.get("extensions", {})
    if isinstance(nmap_ext, dict):
        extensions = merged.get("extensions", {}) if isinstance(merged.get("extensions"), dict) else {}
        san_text = _safe_text(nmap_ext.get("subjectAltName", ""))
        if san_text:
            extensions["subjectAltName"] = san_text
        merged["extensions"] = extensions

    nmap_subject = nmap_cert.get("subject", {})
    if isinstance(nmap_subject, dict):
        subject = merged.get("subject", {}) if isinstance(merged.get("subject"), dict) else {}
        common_name = _safe_text(nmap_subject.get("common_name", ""))
        if common_name:
            subject["common_name"] = common_name
        merged["subject"] = subject

    nmap_issuer = nmap_cert.get("issuer", {})
    if isinstance(nmap_issuer, dict):
        issuer = merged.get("issuer", {}) if isinstance(merged.get("issuer"), dict) else {}
        common_name = _safe_text(nmap_issuer.get("common_name", ""))
        if common_name:
            issuer["common_name"] = common_name
        merged["issuer"] = issuer

    nmap_fingerprint = nmap_cert.get("fingerprint", {})
    if isinstance(nmap_fingerprint, dict):
        fingerprint = merged.get("fingerprint", {}) if isinstance(merged.get("fingerprint"), dict) else {}
        for key in ["md5", "sha1", "sha256"]:
            value = _normalize_hash_text(nmap_fingerprint.get(key, ""))
            if value:
                fingerprint[key] = value
        merged["fingerprint"] = fingerprint

    return merged


def parse_certs(certs):
    result = {}
    ospj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certs)

    subject = ospj.get_subject()
    subject_dn = "C={C}, CN={CN}".format(C=subject.C,CN=subject.CN)
    if subject.O:
        subject_dn += " ,O={O}".format(O = subject.O)

    issuer = ospj.get_issuer()
    issuser_obj = {}
    issuser_obj['country'] = issuer.C
    issuser_obj['province'] = issuer.ST
    issuser_obj['locality'] = issuer.L
    issuser_obj['organizational'] = issuer.O
    issuser_obj['organizational_unit'] = issuer.OU
    issuser_obj['common_name'] = issuer.CN
    issuser_obj['email'] = issuer.emailAddress

    issuer_dn = "C={C}, O={O}, OU={OU}, CN={CN}".format(C=issuer.CN, O=issuer.O, OU=issuer.OU, CN=issuer.CN)

    signature_algorithm = bytes.decode(ospj.get_signature_algorithm()) # 返回证书使用的签名算法
    serial_number = ospj.get_serial_number() # 证书序列号
    validity_obj = {}
    start_date = str(datetime.strptime(ospj.get_notBefore().decode("UTF-8"), '%Y%m%d%H%M%SZ'))
    end_date = str(datetime.strptime(ospj.get_notAfter().decode("UTF-8"), '%Y%m%d%H%M%SZ'))

    validity_obj['start'] = start_date
    validity_obj['end'] = end_date
    validity_obj['expired'] = ospj.has_expired()

    version = ospj.get_version() + 1


    subject_key_info = {}
    subject_key_info['key_algorithm'] = signature_algorithm
    subject_key_info['public_key'] = {}
    subject_key_info['public_key']['length'] = ospj.get_pubkey().bits()
    subject_key_info['public_key']['key'] = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, ospj.get_pubkey()).decode("utf-8")

    subject_obj = {}
    subject_obj['country'] =  subject.C
    subject_obj['province'] = subject.ST
    subject_obj['locality'] = subject.L
    subject_obj['organizational'] = subject.O
    subject_obj['organizational_unit'] = subject.OU
    subject_obj['common_name'] = subject.CN
    subject_obj['email'] = subject.emailAddress

    fingerprint_obj = {}
    fingerprint_obj['sha1'] = bytes.decode(ospj.digest('sha1')).replace(":", "").lower()
    fingerprint_obj['sha256'] = bytes.decode(ospj.digest('sha256')).replace(":", "").lower()
    fingerprint_obj['md5'] = bytes.decode(ospj.digest('md5')).replace(":", "").lower()

    extensions = {}
    exn_num = 0
    while exn_num < ospj.get_extension_count():
        ext_name = bytes.decode(ospj.get_extension(exn_num).get_short_name())
        ext_val = str(ospj.get_extension(exn_num))
        extensions[ext_name] = ext_val
        exn_num += 1

    result['subject_dn'] = subject_dn
    result['issuer'] = issuser_obj
    result['signature_algorithm'] = signature_algorithm
    result['serial_number'] = str(serial_number) # 转换为 str模式 MongoDB can only handle up to 8-byte ints
    result['validity'] = validity_obj
    result['issuer_dn'] = issuer_dn
    result['version'] = version
    result['extensions'] = extensions
    #这个太长了，省点
    #result['subject_key_info'] = subject_key_info
    result['subject'] = subject_obj
    result['fingerprint'] = fingerprint_obj

    return result



def get_cert(host, port, server_hostname=""):
    from . import get_logger
    from .tls_policy import analyze_ssl_security_compliance

    logger = get_logger()
    try:
        normalized_sni = _normalize_server_hostname(server_hostname)
        certs = _fetch_server_certificate(connect_host=host, port=port, server_hostname=normalized_sni)
        if not certs and normalized_sni:
            # SNI 失败时回退无 SNI，避免漏采
            certs = _fetch_server_certificate(connect_host=host, port=port, server_hostname="")

        parsed_cert = {}
        if certs:
            try:
                parsed_cert = parse_certs(certs)
                if isinstance(parsed_cert, dict) and parsed_cert:
                    parsed_cert["cert_source"] = "python_ssl"
            except Exception as parse_err:
                logger.debug("parse cert by python ssl error {}:{} {}".format(host, port, parse_err))
                parsed_cert = {}

        nmap_cert = {}
        if _should_probe_nmap_ssl_cert(parsed_cert, normalized_sni):
            nmap_cert = _scan_ssl_cert_with_nmap(host, port, server_hostname=normalized_sni)
            if not nmap_cert and normalized_sni:
                nmap_cert = _scan_ssl_cert_with_nmap(host, port, server_hostname="")

        if nmap_cert:
            if not parsed_cert:
                parsed_cert = nmap_cert
                parsed_cert["cert_source"] = "nmap_ssl_cert"
            else:
                parsed_match = _cert_matches_server_hostname(parsed_cert, normalized_sni) if normalized_sni else False
                nmap_match = _cert_matches_server_hostname(nmap_cert, normalized_sni) if normalized_sni else False
                parsed_fake = _looks_like_default_or_fake_cert(parsed_cert)
                nmap_fake = _looks_like_default_or_fake_cert(nmap_cert)
                parsed_sha256 = _get_cert_fingerprint_sha256(parsed_cert)
                nmap_sha256 = _get_cert_fingerprint_sha256(nmap_cert)

                should_merge = False
                if nmap_match and not parsed_match:
                    should_merge = True
                elif parsed_fake and not nmap_fake:
                    should_merge = True
                elif not parsed_sha256 and nmap_sha256:
                    should_merge = True

                if should_merge:
                    parsed_cert = _merge_nmap_cert_into_parsed(parsed_cert, nmap_cert)

        if not parsed_cert:
            return {}

        ssl_security = _scan_ssl_security_with_nmap(host, port, server_hostname=normalized_sni)
        if not ssl_security and normalized_sni:
            ssl_security = _scan_ssl_security_with_nmap(host, port, server_hostname="")
        if ssl_security:
            # 证书扫描阶段直接附带 TLS 合规判定，供导出与后续审计复用。
            ssl_security["compliance"] = analyze_ssl_security_compliance(ssl_security)
            parsed_cert["ssl_security"] = ssl_security
        return parsed_cert
    except Exception as e:
        logger.debug("get cert error {}:{} {}".format(host,port, e))
        return {}



