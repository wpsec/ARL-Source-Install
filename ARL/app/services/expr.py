"""
表达式解析和验证
"""
from app.utils import get_logger
from pyparsing import CaselessLiteral, Word, alphas,\
    nums, QuotedString, Group,ParserElement, infixNotation, opAssoc, ParseException

ParserElement.enablePackrat()


logger = get_logger()

# 定义操作符
equals = CaselessLiteral("=")
contains = CaselessLiteral("==")
not_contains = CaselessLiteral("!=")
and_op = CaselessLiteral("&&")
or_op = CaselessLiteral("||")
not_op = CaselessLiteral("!")

# 定义变量和值的语法
variable = Word(alphas + "_")

integer = Word(nums)

escape_char = "\\"
quoted_string = QuotedString('"', escChar=escape_char, unquoteResults=False)


value = quoted_string | integer


# 定义表达式语法
bool_expr = infixNotation(
    Group(variable + equals + value) |
    Group(variable + contains + value) |
    Group(variable + not_contains + value) |
    Group(not_op + variable),
    [
        (not_op, 1, opAssoc.RIGHT),
        (and_op, 2, opAssoc.LEFT),
        (or_op, 2, opAssoc.LEFT),
    ]
)


# 定义操作符
operators = {
    '==': lambda x, y: x == y,
    '!=': lambda x, y: x != y,
    '=': lambda x, y: x in y,
    '!': lambda x: not x,
    '&&': lambda x, y: x and y,
    '||': lambda x, y: x or y
}


# 对双引号包裹的字符串进行 unquote
def unquote_string(s):
    # 去掉引号
    s = s[1:-1]

    # 处理转义字符
    s = s.replace('\\\\', '\\')
    s = s.replace('\\n', '\n')
    s = s.replace('\\t', '\t')
    s = s.replace('\\r', '\r')
    s = s.replace('\\"', '"')

    return s


# 解析表达式
def parse_expression(expression):
    result = bool_expr.parseString(expression, parseAll=True)
    return result.as_list()


#  递归求值
def evaluate_expression(parsed, variables):
    if isinstance(parsed, str):
        if parsed in variables:
            return variables[parsed]
        elif parsed.startswith('"'):
            return unquote_string(parsed)
        else:
            raise ValueError(f"Unknown variable: {parsed}")

    if parsed is None:
        raise ValueError("empty expression tree")

    if len(parsed) == 1:
        return evaluate_expression(parsed[0], variables)
    if len(parsed) == 2:
        # 前缀 not：['!', operand]；其余偶数长度均为畸形树
        if parsed[0] != "!":
            raise ValueError(f"malformed expression tree: even-length node {len(parsed)}")
        return operators[parsed[0]](evaluate_expression(parsed[1], variables))
    if len(parsed) % 2 == 0:
        raise ValueError(f"malformed expression tree: even-length node {len(parsed)}")

    # pyparsing infixNotation 对连续同级运算产出扁平列表 [a, op, b, op, c...]。
    # 旧实现只处理长度 1/2/3，≥3 运算数（如 6 分支 || 规则，长度 11）隐式返回 None，
    # 生产里这类规则永远不命中且无告警（计划5 第2阶段核出的真实缺陷，golden 已锁定）。
    # 修复后按左折叠求值；二元条件 [field, op, value] 参数序保持 (value, variable) 不变。
    acc = evaluate_expression(parsed[0], variables)
    index = 1
    while index < len(parsed):
        op = parsed[index]
        operand = evaluate_expression(parsed[index + 1], variables)
        if op == "||":
            acc = bool(acc) or bool(operand)
        elif op == "&&":
            acc = bool(acc) and bool(operand)
        else:
            acc = operators[op](operand, acc)
        index += 2
    return acc


def evaluate(expression, variables):
    parsed = parse_expression(expression)
    return evaluate_expression(parsed, variables)


def _check_expression(expression):
    variables = {
        'body': "",
        'header': "",
        'title': "",
        'icon_hash': "",
        'response': "",
        'url': "",
    }
    try:
        return evaluate(expression, variables)
    except ParseException as e:
        raise ValueError(f"Invalid expression: {expression}  exception: {e}")
    except Exception as e:
        raise ValueError(f"Error evaluating expression: {expression} exception: {e}")


def check_expression(expression):
    try:
        _check_expression(expression)
        return True
    except ValueError as e:
        logger.error(e)
        # import traceback
        # traceback.print_exception(type(e), e, e.__traceback__)
        return False


def check_expression_with_error(expression):
    try:
        _check_expression(expression)
        return True, None,
    except ValueError as e:
        return False, e
