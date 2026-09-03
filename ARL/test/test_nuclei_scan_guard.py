"""Nuclei 模板预校验与同目标/profile 重复执行收敛的回归测试。"""

import os
import shutil
import tempfile
import unittest

try:
    from app.services.nuclei_scan import NucleiScan
except Exception:
    NucleiScan = None


def _make_scanner(template_files=None):
    scanner = NucleiScan(["https://example.test"], scan_profile={})
    tmp_dir = None
    if template_files is not None:
        tmp_dir = tempfile.mkdtemp(prefix="nuclei_preflight_")
        template_dir = os.path.join(tmp_dir, "tpl")
        os.makedirs(template_dir)
        for name, content in template_files.items():
            with open(os.path.join(template_dir, name), "w", encoding="utf-8") as f:
                f.write(content)
        scanner.nuclei_template_dir = template_dir
    return scanner, tmp_dir


@unittest.skipIf(NucleiScan is None, "运行依赖未安装，跳过 Nuclei 守卫回归")
class TestNucleiTemplatePreflight(unittest.TestCase):
    def test_counts_broken_and_missing_id(self):
        scanner, tmp_dir = _make_scanner({
            "good.yaml": "id: sample\ninfo:\n  severity: info\n",
            "broken.yaml": "id: x\n  bad indent: [\n",
            "noid.yaml": "info:\n  severity: info\n",
        })
        try:
            scanner._preflight_templates()
            metrics = scanner.scan_metrics
            self.assertEqual(3, metrics["template_preflight_scanned"])
            self.assertEqual(1, metrics["template_preflight_broken"])
            self.assertEqual(1, metrics["template_preflight_missing_id"])
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_multidoc_template_not_marked_broken(self):
        scanner, tmp_dir = _make_scanner({
            "multi.yaml": "---\nid: one\n---\nid: two\n",
        })
        try:
            scanner._preflight_templates()
            metrics = scanner.scan_metrics
            self.assertEqual(1, metrics["template_preflight_scanned"])
            self.assertEqual(0, metrics["template_preflight_broken"])
            self.assertEqual(0, metrics["template_preflight_missing_id"])
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)


@unittest.skipIf(NucleiScan is None, "运行依赖未安装")
class TestNucleiBatchDedup(unittest.TestCase):
    def test_duplicate_successful_batch_skipped(self):
        scanner, _ = _make_scanner()
        stages = []

        def fake_run(**kwargs):
            stages.append(kwargs.get("stage"))
            return {"returncode": 0, "stdout": "", "stderr": "", "result_size": 0}

        scanner._run_nuclei_command = fake_run
        batch = {"targets": ["https://a.test"], "tags": "tomcat", "auto_scan": False, "batch_type": "fingerprint"}

        scanner.exec_nuclei(dict(batch), 1)
        second = scanner.exec_nuclei(dict(batch), 2)

        self.assertEqual(1, len(stages))
        self.assertEqual(1, scanner.scan_metrics["duplicate_batch_skipped"])
        self.assertEqual("skipped_duplicate_batch", second.get("stderr"))

    def test_failed_batch_can_retry(self):
        scanner, _ = _make_scanner()
        outcomes = iter([
            {"returncode": 1, "stdout": "", "stderr": "boom", "result_size": 0},
            {"returncode": 0, "stdout": "", "stderr": "", "result_size": 0},
        ])
        calls = []

        def fake_run(**kwargs):
            calls.append(kwargs.get("stage"))
            return next(outcomes)

        scanner._run_nuclei_command = fake_run
        batch = {"targets": ["https://a.test"], "tags": "tomcat", "auto_scan": False, "batch_type": "fingerprint"}

        scanner.exec_nuclei(dict(batch), 1)
        scanner.exec_nuclei(dict(batch), 2)

        self.assertEqual(2, len(calls))
        self.assertEqual(0, scanner.scan_metrics["duplicate_batch_skipped"])

    def test_different_tags_or_targets_not_skipped(self):
        scanner, _ = _make_scanner()
        calls = []

        def fake_run(**kwargs):
            calls.append(kwargs.get("stage"))
            return {"returncode": 0, "stdout": "", "stderr": "", "result_size": 0}

        scanner._run_nuclei_command = fake_run
        scanner.exec_nuclei(
            {"targets": ["https://a.test"], "tags": "tomcat", "auto_scan": False, "batch_type": "fingerprint"}, 1
        )
        scanner.exec_nuclei(
            {"targets": ["https://a.test"], "tags": "nginx", "auto_scan": False, "batch_type": "fingerprint"}, 2
        )
        scanner.exec_nuclei(
            {"targets": ["https://b.test"], "tags": "tomcat", "auto_scan": False, "batch_type": "fingerprint"}, 3
        )

        self.assertEqual(3, len(calls))
        self.assertEqual(0, scanner.scan_metrics["duplicate_batch_skipped"])


if __name__ == "__main__":
    unittest.main()
