"""计划5：指纹规则纯函数公共层（零运行时依赖，生成器/服务层/测试共用）。

存在理由：统一生成脚本必须可在无 xing/celery/Mongo 的环境独立运行
（`python3 -m app.tools.build_unified_fingerprints`），而 `app.services.*` 包
eager import 链会拉起 NPoC 依赖；置信度/解析函数只允许一份实现（05 §零.1），
故下沉到本模块由双方 import，运行时经 kscan_fingerprint/fingerprint_cache 原别名 re-export 兼容。
"""
import re

def unquote_string(value):
    value = str(value).strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    value = value.replace("\\\\", "\\")
    value = value.replace('\\"', '"')
    return value
def split_logic_expression(expression):
    """
    在双引号之外按 && / || 拆分表达式。
    """
    tokens = []
    operators = []
    buf = []
    in_quotes = False
    escaped = False
    i = 0
    while i < len(expression):
        ch = expression[i]

        if in_quotes and ch == "\\" and not escaped:
            escaped = True
            buf.append(ch)
            i += 1
            continue

        if ch == '"' and not escaped:
            in_quotes = not in_quotes

        if not in_quotes and i + 1 < len(expression):
            op = expression[i:i + 2]
            if op in ("&&", "||"):
                token = "".join(buf).strip()
                if token:
                    tokens.append(token)
                operators.append(op)
                buf = []
                i += 2
                escaped = False
                continue

        buf.append(ch)
        escaped = False
        i += 1

    token = "".join(buf).strip()
    if token:
        tokens.append(token)

    return tokens, operators
def extract_literal_from_regex(pattern, min_len=4):
    """
    将部分正则回退为稳定字面量，减少规则浪费。
    """
    text = unquote_string(pattern)
    text = text.replace("\\/", "/")
    text = text.replace("\\.", ".")
    text = text.replace("\\-", "-")
    text = text.replace("\\_", "_")
    text = text.replace("\\ ", " ")
    text = re.sub(r"\\x[0-9a-fA-F]{2}", " ", text)
    text = re.sub(r"\[[^\]]*\]", " ", text)
    text = re.sub(r"[\^\$\(\)\{\}\|\?\*\+]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    candidates = re.findall(r"[A-Za-z0-9_\-./\u4e00-\u9fa5]{%d,}" % int(min_len), text)
    if not candidates:
        return ""

    stopwords = {
        "server", "title", "set-cookie", "cookie", "content", "http", "https", "www",
        "meta", "body", "header", "location", "version",
    }
    candidates = [x for x in candidates if x.lower() not in stopwords]
    if not candidates:
        return ""

    candidates.sort(key=lambda x: len(x), reverse=True)
    return candidates[0]
def safe_int(value, default_value=0):
    try:
        return int(value)
    except Exception:
        return default_value
def extract_human_rule_fields(human_rule):
    """
    提取 human_rule 中出现过的字段，用于结果打分和说明
    """
    rule_text = str(human_rule or "")
    ordered_fields = []
    for field_name in ("icon_hash", "header", "title", "response", "url", "body"):
        if re.search(r'(^|[\s!(]){}(\s*(~=|==|!=|=))'.format(re.escape(field_name)), rule_text):
            ordered_fields.append(field_name)
    return ordered_fields
def estimate_human_rule_confidence(human_rule):
    """
    基于规则特征粗略估算识别置信度
    """
    fields = set(extract_human_rule_fields(human_rule))
    fragment_count = max(str(human_rule or "").count("||") + str(human_rule or "").count("&&") + 1, 1)

    if "icon_hash" in fields:
        base_score = 95
    elif "header" in fields and ({"body", "title", "response", "url"} & fields):
        base_score = 90
    elif "response" in fields:
        base_score = 86
    elif "header" in fields:
        base_score = 82
    elif "title" in fields:
        base_score = 78
    elif "url" in fields:
        base_score = 76
    elif "body" in fields:
        base_score = 72
    else:
        base_score = 70

    bonus = min(max(fragment_count - 1, 0) * 2, 8)
    return min(base_score + bonus, 98)
