import unittest
from unittest.mock import Mock, patch

import app.utils.github_task as github_task
from app.utils.github_task import github_cron_run


class TestGithubCronRun(unittest.TestCase):
    def test_github_cron_dispatch_and_schedule_update(self):
        item = {
            "_id": "0123456789abcdef01234567",
            "name": "fixture monitor",
            "keyword": "fixture-keyword",
            "run_number": 2,
            "cron": "0 * * * *",
        }
        collection = Mock()

        with patch.object(github_task, "submit_github_task") as submit, \
                patch.object(github_task, "CronTab") as cron_tab, \
                patch.object(github_task.utils, "conn_db", return_value=collection), \
                patch.object(github_task.utils, "curr_date", return_value="fixture-date"), \
                patch.object(github_task.utils, "time2date", return_value="fixture-next-date"), \
                patch.object(github_task.time, "time", return_value=1_800_000_000):
            cron_tab.return_value.next.return_value = 300
            github_cron_run(item)

        submit.assert_called_once()
        self.assertEqual(3, item["run_number"])
        self.assertEqual("fixture-date", item["last_run_date"])
        self.assertEqual("fixture-next-date", item["next_run_date"])
        collection.find_one_and_replace.assert_called_once()


if __name__ == '__main__':
    unittest.main()
