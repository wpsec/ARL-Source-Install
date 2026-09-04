"""计划5：expr 求值器行为锁定（≥3 操作数扁平树修复 + 优先级 + != 现状语义）。

!= 按运行时字面语义锁定为"整串不等"（kscan 源作者意图是"不含"——62 条规则受影响，
是否改为 not-contains 属行为变更，计划5 第3阶段带标注对照另行决策，禁止顺手改）。
"""
import importlib.util
import pathlib
import sys
import types
import unittest

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]


class _Quiet:
    def __getattr__(self, _name):
        return lambda *a, **k: None


def _load_expr():
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = [str(ROOT_DIR / "app")]
    sys.modules.setdefault("app", app_pkg)
    utils_pkg = types.ModuleType("app.utils")
    utils_pkg.get_logger = lambda *a, **k: _Quiet()
    sys.modules.setdefault("app.utils", utils_pkg)
    spec = importlib.util.spec_from_file_location("expr_under_test", ROOT_DIR / "app" / "services" / "expr.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EXPR = _load_expr()

VARS = {
    "body": "<html>hi</html>",
    "header": "Server: Apache",
    "title": "t",
    "response": "x",
    "icon_hash": "0",
    "url": "u",
}


class ExprEvaluationTest(unittest.TestCase):
    def ev(self, text):
        return EXPR.evaluate_expression(EXPR.parse_expression(text), dict(VARS))

    def test_single_condition(self):
        self.assertTrue(self.ev('body="hi"'))
        self.assertFalse(self.ev('body="nope"'))

    def test_three_branch_or_hits(self):
        # 修复前：长度 5 隐式返回 None（永不命中）。修复后按布尔语义真评估。
        self.assertTrue(bool(self.ev('body="nope" || title="t2" || body="hi"')))
        self.assertFalse(bool(self.ev('body="nope" || title="t2" || body="zz"')))

    def test_six_branch_or_flat_tree(self):
        text = " || ".join('body="miss%d"' % i for i in range(5)) + ' || body="hi"'
        self.assertTrue(bool(self.ev(text)))

    def test_and_precedence_over_or(self):
        self.assertTrue(bool(self.ev('body="hi" && title="t" || body="zz"')))
        self.assertFalse(bool(self.ev('body="hi" && title="zz" || body="zz"')))

    def test_not_equals_current_semantics_locked(self):
        # 现状：!= 是"整串不等"比较（不是 not-contains；对页面 body 几乎恒真）。
        # 行为变更需第3阶段带标注对照决策，此处锁定现状。
        self.assertFalse(bool(self.ev('body!="<html>hi</html>"')))  # 整串相等 → 不等为假
        self.assertTrue(bool(self.ev('body="<html>hi</html>"')))
        self.assertTrue(bool(self.ev('body!="hi"')))  # 整串 ≠ "hi" → 真（证明它不是 not-contains）

    def test_malformed_even_tree_raises(self):
        with self.assertRaises(ValueError):
            EXPR.evaluate_expression(["a", "||"], dict(VARS))


if __name__ == "__main__":
    unittest.main()
