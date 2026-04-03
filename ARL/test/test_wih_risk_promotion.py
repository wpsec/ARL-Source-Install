import unittest
from types import SimpleNamespace

try:
    from app.services.commonTask import WebSiteFetch
except Exception:
    from test.test_ai_pen_js_context import WebSiteFetch


class TestWihRiskPromotion(unittest.TestCase):
    def setUp(self):
        self.task = WebSiteFetch.__new__(WebSiteFetch)

    def test_generic_url_carrier_records_are_not_promoted_by_keyword_only(self):
        self.assertFalse(
            self.task._should_promote_wih_to_risk(
                SimpleNamespace(recordType="urlfinder_js", content="http://demo.example.com/iToken.js")
            )
        )
        self.assertFalse(
            self.task._should_promote_wih_to_risk(
                SimpleNamespace(recordType="path", content="/password/passwordFound';")
            )
        )

    def test_explicit_secret_rule_types_still_promote(self):
        self.assertTrue(
            self.task._should_promote_wih_to_risk(
                SimpleNamespace(recordType="openai_api_key", content="OPENAI_API_KEY=sk-123456789012345678901234567890123456789012345678")
            )
        )
        self.assertTrue(
            self.task._should_promote_wih_to_risk(
                SimpleNamespace(recordType="secret_key", content='secret_key="demo-secret"')
            )
        )

    def test_js_placeholder_password_record_is_not_promoted(self):
        record = SimpleNamespace(
            recordType="password",
            content='password:"password"',
            source="https://example.com/static/app.js",
        )
        self.assertFalse(self.task._should_promote_wih_to_risk(record))
        self.assertFalse(self.task._is_sensitive_wih_record("password", 'password:"password"', source=record.source))

    def test_js_debug_secret_record_is_not_promoted(self):
        record = SimpleNamespace(
            recordType="secret_key",
            content='token=")&&(SYNO.Debug("',
            source="https://example.com/webman/sds/dist/dsm.common.bundle.js",
        )
        self.assertFalse(self.task._should_promote_wih_to_risk(record))
        self.assertFalse(self.task._is_sensitive_wih_record("secret_key", 'token=")&&(SYNO.Debug("', source=record.source))


if __name__ == "__main__":
    unittest.main()
