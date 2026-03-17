"""
域名处理和验证工具
"""
import tld
from urllib.parse import urlparse
from app.config import Config

blackdomain_list = None
blackhexie_list = None


def _normalize_host_text(value):
    """
    规范化原始主机文本：
    - 去空白/尾点
    - 支持 URL 提取 hostname
    - 支持 host:port 去端口
    """
    text = str(value or "").strip().lower().rstrip(".")
    if not text:
        return ""

    if "://" in text:
        try:
            text = str(urlparse(text).hostname or "").strip().lower().rstrip(".")
        except Exception:
            text = ""

    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()

    if ":" in text and text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
        if str(port_text).isdigit():
            text = host.strip()

    return text


def normalize_domain(domain, remove_wildcard=True):
    """
    归一化域名为 ASCII（IDNA/Punycode）格式。

    返回:
        str: 归一化后的域名；失败时返回空字符串
    """
    text = _normalize_host_text(domain)
    if not text:
        return ""

    if remove_wildcard and text.startswith("*."):
        text = text[2:].strip(".")

    if not text:
        return ""

    labels = []
    for raw_label in text.split("."):
        label = str(raw_label or "").strip()
        if not label:
            return ""
        try:
            label_ascii = label.encode("idna").decode("ascii").lower()
        except Exception:
            return ""
        if not label_ascii:
            return ""
        labels.append(label_ascii)

    return ".".join(labels).strip(".")


def normalize_fuzz_domain(domain):
    """
    归一化包含 {fuzz} 占位符的域名。
    """
    text = _normalize_host_text(domain)
    if "{fuzz}" not in text:
        return ""

    wildcard_prefix = ""
    if text.startswith("*."):
        wildcard_prefix = "*."
        text = text[2:].strip(".")

    placeholder = "arlfuzzplaceholder"
    replaced = text.replace("{fuzz}", placeholder)
    normalized = normalize_domain(replaced, remove_wildcard=False)
    if normalized and placeholder in normalized:
        normalized = normalized.replace(placeholder, "{fuzz}")
    else:
        # 回退方案：逐标签编码，尽量保持 {fuzz} 原样。
        labels = []
        for raw_label in text.split("."):
            label = str(raw_label or "").strip()
            if not label:
                return ""

            if "{fuzz}" not in label:
                try:
                    labels.append(label.encode("idna").decode("ascii").lower())
                except Exception:
                    return ""
                continue

            parts = label.split("{fuzz}")
            label_builder = []
            for idx, part in enumerate(parts):
                if part:
                    try:
                        label_builder.append(part.encode("idna").decode("ascii").lower())
                    except Exception:
                        return ""
                if idx != len(parts) - 1:
                    label_builder.append("{fuzz}")

            label_normalized = "".join(label_builder)
            if not label_normalized:
                return ""
            labels.append(label_normalized)

        normalized = ".".join(labels).strip(".")

    if not normalized:
        return ""

    if wildcard_prefix:
        normalized = wildcard_prefix + normalized

    return normalized


def check_domain_black(domain):
    from app.utils import get_logger
    logger = get_logger()

    domain = normalize_domain(domain)
    if not domain:
        return False

    global blackdomain_list
    global blackhexie_list
    if blackdomain_list is None:
        with open(Config.black_domain_path) as f:
            blackdomain_list = []
            for line in f.readlines():
                item = str(line or "").strip()
                if not item:
                    continue
                item = normalize_domain(item) or item.lower().rstrip(".")
                blackdomain_list.append(item)

    for item in blackdomain_list:
        item = item.strip()
        if item and domain.endswith(item):
            return True

    if blackhexie_list is None:
        with open(Config.black_hexie_path) as f:
            blackhexie_list = f.readlines()

    try:
        for item in blackhexie_list:
            item = item.strip()
            _, _, subdomain = tld.parse_tld(domain, fix_protocol=True, fail_silently=True)
            if subdomain and item and item.strip() in subdomain:
                return True
    except Exception as e:
        logger.warning("Error on: {}, {}".format(domain, e))
        return True

    return False


def is_forbidden_domain(domain):
    domain = normalize_domain(domain)
    if not domain:
        return False

    for f_domain in Config.FORBIDDEN_DOMAINS:
        f_domain = normalize_domain(f_domain)
        if not f_domain:
            continue

        if domain.endswith("." + f_domain):
            return True
        if domain == f_domain:
            return True

    return False


def is_valid_domain(domain):
    from app.utils import domain_parsed
    domain = normalize_domain(domain)
    if not domain:
        return False

    if "." not in domain:
        return False

    invalid_chars = "!@#$%&*():_\\"
    for c in invalid_chars:
        if c in domain:
            return False

    # 不允许下发特殊二级域名
    if domain in ["com.cn", "gov.cn", "edu.cn"]:
        return False

    if domain_parsed(domain):
        return True

    return False


def is_valid_fuzz_domain(domain):
    from app.utils import domain_parsed
    domain = normalize_fuzz_domain(domain)
    if not domain:
        return False

    if "{fuzz}" not in domain:
        return False

    domain = domain.replace("{fuzz}", "12fuzz12")
    parsed = domain_parsed(domain)
    if not parsed:
        return False

    if "12fuzz12" in parsed['fld']:
        return False

    return True


def is_in_scope(src_domain, target_domain):
    from app.utils import get_fld

    src_domain = normalize_domain(src_domain)
    target_domain = normalize_domain(target_domain)
    if not src_domain or not target_domain:
        return False

    fld1 = get_fld(src_domain)
    fld2 = get_fld(target_domain)

    if not fld1 or not fld2:
        return False

    if fld1 != fld2:
        return False

    if src_domain == target_domain:
        return True

    return src_domain.endswith("."+target_domain)


def is_in_scopes(domain, scopes):
    for target_scope in scopes:
        if is_in_scope(domain, target_scope):
            return True

    return False


def cut_first_name(domain):
    """将子域名剔除前面一节名称"""
    domain = normalize_domain(domain)
    if not domain:
        return

    domain_parts, non_zero_i, _ = tld.utils.process_url(domain, fix_protocol=True, fail_silently=True)
    if not domain_parts:
        return

    if non_zero_i == 1:
        return

    item = ".".join(domain_parts[1:])
    return item
