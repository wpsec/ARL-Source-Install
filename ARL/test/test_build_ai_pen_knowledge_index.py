import importlib.util
import pathlib
import tempfile
import unittest


def _load_script_module():
    module_name = "build_ai_pen_knowledge_index_test_module"
    script_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "tools" / "build_ai_pen_knowledge_index.py"
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


script_module = _load_script_module()


class TestBuildAiPenKnowledgeIndex(unittest.TestCase):
    def test_detect_vuln_types_and_entry_paths(self):
        text = """
        # 科荣AIO系统接口UtilServlet存在代码执行漏洞
        ## poc
        POST /UtilServlet HTTP/1.1
        Host: 127.0.0.1
        """
        vuln_types = script_module.detect_vuln_types(text)
        entry_paths = script_module.extract_entry_paths(text)
        actions = script_module.extract_verify_actions(text)

        self.assertIn("cmdi", vuln_types)
        self.assertIn("/UtilServlet", entry_paths)
        self.assertTrue(any("post /utilservlet" in item.lower() for item in actions))

    def test_build_index_outputs_structured_fields(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            poc_dir = root / "POC" / "wpoc" / "科荣AIO"
            poc_dir.mkdir(parents=True, exist_ok=True)
            sample_file = poc_dir / "科荣AIO管理系统endTime参数存在SQL注入漏洞.md"
            sample_file.write_text(
                "# 科荣AIO管理系统endTime参数存在SQL注入漏洞\n\n"
                "GET /moffice?op=showWorkPlanList&type=1&beginTime=1&endTime=1* HTTP/1.1\n",
                encoding="utf-8",
            )

            result = script_module.build_index(
                source_paths={"poc_library": root / "POC"},
                max_files_per_source=50,
                max_read_bytes=8192,
                min_token_count=1,
                max_index_tokens=200,
                max_samples_per_token=4,
            )

            token_index = result.get("token_index", {})
            matched = token_index.get("kerongaio") or token_index.get("endtime") or {}
            self.assertTrue(token_index)
            self.assertIn("record_refs", matched)
            self.assertIn("vuln_types", matched)
            self.assertIn("entry_paths", matched)
            self.assertIn("verify_actions", matched)


if __name__ == "__main__":
    unittest.main()
