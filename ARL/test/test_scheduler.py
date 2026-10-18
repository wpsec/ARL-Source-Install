import unittest
from unittest.mock import Mock, patch

import app.helpers.scheduler as scheduler
from app.helpers.scheduler import have_same_site_update_monitor


class TestScheduler(unittest.TestCase):
    def test_have_same_site_update_monitor(self):
        collection = Mock()
        collection.find_one.return_value = {"scope_id": "fixture-scope"}
        with patch.object(scheduler.utils, "conn_db", return_value=collection):
            data = have_same_site_update_monitor("fixture-scope")
        self.assertTrue(data)
        collection.find_one.assert_called_once_with({
            "scope_id": "fixture-scope",
            "scope_type": "site_update_monitor",
        })


if __name__ == '__main__':
    unittest.main()
