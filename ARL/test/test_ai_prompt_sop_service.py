"""AI SOP 文件服务回归测试。"""

import tempfile
import unittest
from pathlib import Path

from app.services.ai_prompt_sop_service import AIPromptSopService


class TestAIPromptSopService(unittest.TestCase):
    def _service(self, root):
        return AIPromptSopService(
            project_root=root,
            template_file_map={"prompt-1": "ai/sop/prompt-1.yaml"},
        )

    def test_yaml_upload_and_atomic_persistence_keep_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            service = self._service(root)
            parsed = service.parse_uploaded(
                "id: prompt-1\nname: 测试\nscene: demo\ncontent: 内容\n".encode("utf-8")
            )
            self.assertEqual("prompt-1", parsed["id"])
            self.assertEqual("内容", parsed["content"])

            persisted = service.persist_templates([parsed], [])
            self.assertEqual("ai/sop/prompt-1.yaml", persisted[0]["file"])
            payload = service.load_payload(persisted[0]["file"])
            self.assertEqual("测试", payload["name"])
            self.assertEqual("内容", payload["content"])

    def test_path_escape_and_empty_content_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            service = self._service(Path(temp_dir))
            self.assertEqual({}, service.load_payload("../../../../outside.yaml"))
            with self.assertRaises(ValueError):
                service.write_content("../../../../outside.yaml", "内容")
            with self.assertRaises(ValueError):
                service.parse_uploaded(b"content: ''\n")


if __name__ == "__main__":
    unittest.main()
