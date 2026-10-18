import unittest
from unittest.mock import patch

from app.services import finger_db_cache, finger_db_identify, have_human_rule_from_db
from app.services.fingerprint import FingerPrint


class TestExpression(unittest.TestCase):
    def test_finger_db_identify_uses_cached_rules(self):
        rules = [
            FingerPrint("FixtureApp", 'icon_hash=="116323821"', sources=["fixture"]),
            FingerPrint("OtherApp", 'icon_hash=="2062026853"', sources=["fixture"]),
        ]
        variables = {"icon_hash": "116323821"}

        with patch.object(finger_db_cache, "get_data", return_value=rules):
            results = finger_db_identify(variables)

        self.assertEqual(["FixtureApp"], results)

    def test_have_human_rule_from_db_checks_exact_rule(self):
        stored_rules = {
            'icon_hash="116323821"',
            'icon_hash="2062026853"',
        }

        def find_one(query):
            return {"human_rule": query["human_rule"]} if query["human_rule"] in stored_rules else None

        with patch("app.services.fingerprint_cache.conn_db") as connection:
            connection.return_value.find_one.side_effect = find_one

            self.assertTrue(have_human_rule_from_db('icon_hash="116323821"'))
            self.assertTrue(have_human_rule_from_db('icon_hash="2062026853"'))
            self.assertFalse(have_human_rule_from_db('body="test" || icon_hash=="11111111"'))

        self.assertEqual(3, connection.return_value.find_one.call_count)


if __name__ == "__main__":
    unittest.main()
