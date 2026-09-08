"""主题对比度门禁解析器回归。"""

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT.parent / "scripts" / "check-theme-contrast.py"
SPEC = importlib.util.spec_from_file_location("theme_contrast_gate", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ThemeContrastGateTest(unittest.TestCase):
    def test_parses_daisyui5_unquoted_tokens_for_all_themes(self):
        source = MODULE.CSS.read_text(encoding="utf-8")
        themes = MODULE.parse_daisy_themes(source)
        self.assertEqual(
            {"brand", "midnight", "slate", "nord", "titanium", "sandstone"},
            set(themes),
        )
        for tokens in themes.values():
            self.assertEqual("var(--brand-bg)", tokens["--color-base-100"])
            self.assertIn("--color-primary-content", tokens)

    def test_theme_gate_has_no_contrast_failures(self):
        source = MODULE.CSS.read_text(encoding="utf-8")
        brands = MODULE.parse_brand_vars(source)
        themes = MODULE.parse_daisy_themes(source)
        for theme, tokens in themes.items():
            brand = dict(brands["root"])
            brand.update(brands.get(theme, {}))
            values = {key.lstrip("-"): value for key, value in tokens.items()}
            values["muted"] = brand["--brand-text-muted"]
            for foreground, background, _scene, minimum in MODULE.PAIRS:
                fg = MODULE.resolve(values[foreground], brand)
                bg = MODULE.resolve(values[background], brand)
                self.assertGreaterEqual(
                    MODULE.ratio(fg, bg),
                    minimum,
                    "{}: {} on {}".format(theme, foreground, background),
                )


if __name__ == "__main__":
    unittest.main()
