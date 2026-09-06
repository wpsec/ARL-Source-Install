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

# ---------------------------------------------------------------------------
# human_rule 解析 / 序列化 / 合并键（架构 Review 轮 2：运行时与构建脚本解耦）。
#
# 原驻 app/tools/build_unified_fingerprints，被 site_fingerprint_registry 运行时
# import——生产导入链挂上构建脚本模块即耦合（05 §零.1 单一实现约束下的唯一
# 合规落点即本零依赖公共层）。构建模块保持原名 re-export，审计面不变。
# ---------------------------------------------------------------------------

SUPPORTED_FIELDS = {"body", "header", "title", "response", "url", "icon_hash"}
SUPPORTED_OPS = {"contains", "equals", "not_equals", "regex"}

COND_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*(~=|==|!=|=)\s*("([^"\\]|\\.)*"|-?\d+)\s*$')


def human_rule_unquote(raw: str) -> str:
    if raw.startswith('"') and raw.endswith('"'):
        inner = raw[1:-1]
        return inner.replace('\\\\', '\x00').replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r').replace('\x00', '\\')
    return raw


def human_rule_quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'


# != 保留生产布尔语义（整串不等）——not-contains 意图升级属行为变更，第3阶段带对照决策。


OP_TO_CANON = {"=": "contains", "==": "equals", "!=": "not_equals", "~=": "regex"}
CANON_TO_OP = {v: k for k, v in OP_TO_CANON.items()}


def has_boolean_parentheses(expression: str) -> bool:
    """引号外出现 ( ) 即判不可解析（现行源 0 处；防御未来源引入歧义语法）。"""
    in_quotes = False
    escaped = False
    for ch in expression:
        if in_quotes:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quotes = False
            continue
        if ch == '"':
            in_quotes = True
        elif ch in "()":
            return True
    return False


def parse_human_rule(expression: str):
    """human_rule → ({"any":[{"all":[cond]}], "excludes":[]}, problems)。

    problems 非空即整条拒绝（括号语法/非法条件/不支持字段一律不猜语义）。
    """
    if has_boolean_parentheses(expression):
        return None, ["parentheses_not_supported"]
    tokens, operators = split_logic_expression(expression)
    groups = [[]]
    for index, token in enumerate(tokens):
        if index > 0 and operators[index - 1] == "||":
            groups.append([])
        groups[-1].append(token)

    any_branches, problems = [], []
    for group in groups:
        conds = []
        for part in group:
            m = COND_RE.match(part.strip())
            if not m:
                problems.append("unparsable_condition")
                continue
            field, op, raw = m.group(1), m.group(2), m.group(3)
            field = field.lower()
            if field not in SUPPORTED_FIELDS:
                problems.append("unsupported_field:" + field)
                continue
            conds.append({"field": field, "operator": OP_TO_CANON[op], "value": human_rule_unquote(raw)})
        if conds:
            any_branches.append({"all": conds})
    if problems:
        return None, problems
    if not any_branches:
        return None, ["no_valid_condition"]
    return {"any": any_branches, "excludes": []}, []


def to_human_rule(match: dict) -> str:
    """canonical match → 确定性 human_rule 文本（分支/条件稳定序）。"""
    def ser_cond(c):
        return "{}{}{}".format(c["field"], CANON_TO_OP[c["operator"]], human_rule_quote(c["value"]))

    branches = []
    for branch in match.get("any", []):
        conds = sorted(ser_cond(c) for c in branch.get("all", []))
        if conds:
            branches.append(" && ".join(conds))
    branches = sorted(set(branches))
    text = " || ".join(branches)
    for ex in sorted(ser_cond(c) for c in match.get("excludes", [])):
        text = "{} || {}".format(text, ex) if text else ex
    return text




def merge_key(name: str) -> str:
    """合并键：casefold + 去首尾空白 + 内部连续空白并一。标点不清理（A-B 与 AB 是不同产品）。"""
    return re.sub(r"\s+", " ", str(name).strip()).casefold()
