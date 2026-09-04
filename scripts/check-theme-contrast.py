#!/usr/bin/env python3
"""daisy 主题 WCAG AA 对比度验收（docs/04 Phase 1 验收项，数值入 docs/03 批次记录）。

直接解析 index.css：品牌变量块 = 值唯一来源，daisy 主题块 = token 映射，
避免脚本内复制色值造成三方漂移。primary-content 等按"配对反推"校验。
"""
import re
import sys
from pathlib import Path

CSS = Path(__file__).resolve().parent.parent / "ARL/docker/frontend-src/src/index.css"

# 校验对：(前景 token, 背景 token, 场景, 最低比值)
PAIRS = [
    ("color-base-content", "color-base-100", "正文/页面底", 4.5),
    ("color-base-content", "color-base-200", "正文/卡片面", 4.5),
    ("muted", "color-base-100", "次要文字/页面底", 4.5),
    ("muted", "color-base-200", "次要文字/卡片面", 4.5),
    ("color-primary-content", "color-primary", "主按钮配对", 4.5),
    ("color-secondary-content", "color-secondary", "次按钮配对", 4.5),
    ("color-accent-content", "color-accent", "强调配对", 4.5),
    ("color-warning-content", "color-warning", "warning 配对", 4.5),
    ("color-error-content", "color-error", "error 配对", 4.5),
    ("color-success-content", "color-success", "success 配对", 4.5),
    ("color-warning", "color-base-200", "warning 色作大字/图标", 3.0),
    ("color-error", "color-base-200", "error 色作大字/图标", 3.0),
]


def parse_brand_vars(src: str) -> dict:
    """{theme_or_root: {--brand-x: '#hex'}}"""
    blocks = {}
    for m in re.finditer(r":root\s*\{(.*?)\}", src, re.S):
        blocks["root"] = dict(re.findall(r"(--brand-[a-z-]+):\s*([^;]+);", m.group(1)))
    for m in re.finditer(r"\[data-theme='([a-z]+)'\]\s*\{(.*?)\}", src, re.S):
        blocks[m.group(1)] = dict(re.findall(r"(--brand-[a-z-]+):\s*([^;]+);", m.group(2)))
    return blocks


def parse_daisy_themes(src: str) -> dict:
    """{theme: {token: value}}，token 含 --color-* 等。"""
    themes = {}
    for m in re.finditer(r'@plugin "daisyui/theme"\s*\{(.*?)\}', src, re.S):
        body = m.group(1)
        name = re.search(r'name:\s*"?([a-z-]+)"?;', body)
        if not name:
            continue
        tokens = dict(re.findall(r"^\s*(--[a-z0-9-]+):\s*\"([^\"]+)\";", body, re.M))
        themes[name.group(1)] = tokens
    return themes


def resolve(value: str, brand: dict) -> str:
    seen = set()
    while True:
        m = re.fullmatch(r"var\((--[a-z-]+)\)", value.strip())
        if not m or m.group(1) in seen:
            return value.strip()
        seen.add(m.group(1))
        if m.group(1) not in brand:
            raise KeyError(f"未定义品牌变量 {m.group(1)}")
        value = brand[m.group(1)]


def lum(hex_color: str) -> float:
    h = hex_color.strip().lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    def lin(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def ratio(fg: str, bg: str) -> float:
    l1, l2 = lum(fg), lum(bg)
    hi, lo = max(l1, l2), min(l1, l2)
    return (hi + 0.05) / (lo + 0.05)


def main():
    src = CSS.read_text(encoding="utf-8")
    brand_blocks = parse_brand_vars(src)
    themes = parse_daisy_themes(src)
    theme_names = ["brand", "midnight", "slate", "nord", "titanium", "sandstone"]
    failures = []
    print(f"{'theme':<10} {'场景':<22} {'fg':<8} {'bg':<8} {'ratio':>6} 要求  结果")
    for t in theme_names:
        brand = dict(brand_blocks.get("root", {}))
        brand.update(brand_blocks.get(t, {}))
        tokens = themes.get(t, {})
        if not tokens:
            failures.append(f"{t}: daisy 主题块缺失")
            continue
        tokens = {k.lstrip("-"): v for k, v in tokens.items()}
        tokens["muted"] = brand.get("--brand-text-muted", "#888888")
        for fg_tok, bg_tok, scene, need in PAIRS:
            if fg_tok not in tokens or bg_tok not in tokens:
                failures.append(f"{t}: token 缺失 {fg_tok}/{bg_tok}")
                continue
            fg = resolve(tokens[fg_tok], brand)
            bg = resolve(tokens[bg_tok], brand)
            try:
                r = ratio(fg, bg)
            except Exception as e:
                failures.append(f"{t}: {scene} 解析失败 {e}")
                continue
            ok = r >= need
            if not ok:
                failures.append(f"{t} {scene}: {fg} on {bg} = {r:.2f} < {need}")
            print(f"{t:<10} {scene:<22} {fg:<8} {bg:<8} {r:>6.2f} {need:>4.1f}  {'PASS' if ok else 'FAIL'}")
    print()
    if failures:
        print("FAILURES:")
        for f in failures:
            print(" -", f)
        sys.exit(1)
    print("ALL PASS")


if __name__ == "__main__":
    main()
