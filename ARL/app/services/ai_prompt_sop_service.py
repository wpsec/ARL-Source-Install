"""AI SOP 文件服务。

SOP 文件属于配置域的持久化资源；路径校验、YAML 解析和原子写入集中在这里，
避免 API route 同时承担文件格式和配置合并职责。
"""

from datetime import datetime
from pathlib import Path
import errno
import json
import os
import tempfile

import yaml


class AIPromptSopService(object):
    """负责 AI 提示词/SOP 文件的安全读写和上传解析。"""

    def __init__(self, project_root, template_file_map, logger=None):
        self.project_root = Path(project_root).resolve()
        self.prompt_sop_dir = self.project_root / "docker" / "ai" / "sop"
        self.template_file_map = dict(template_file_map or {})
        self.logger = logger

    @staticmethod
    def _normalize_file_ref(raw_file_ref):
        return str(raw_file_ref or "").strip().replace("\\", "/")

    def _is_within_project_root(self, path_obj):
        try:
            Path(path_obj).resolve().relative_to(self.project_root)
            return True
        except Exception:
            return False

    def resolve_path(self, raw_file_ref):
        file_ref = self._normalize_file_ref(raw_file_ref)
        if not file_ref:
            return "", None

        file_path = Path(file_ref)
        if file_path.is_absolute():
            resolved = file_path.resolve()
        elif file_ref.startswith("docker/"):
            resolved = (self.project_root / file_ref).resolve()
        elif file_ref.startswith("ai/"):
            resolved = (self.project_root / "docker" / file_ref).resolve()
        else:
            resolved = (self.prompt_sop_dir / file_ref).resolve()
        return file_ref, resolved

    @staticmethod
    def _extract_content(value):
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, (int, float)):
            return str(value).strip()
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            try:
                return json.dumps(value, ensure_ascii=False).strip()
            except Exception:
                return str(value).strip()
        return str(value).strip()

    def load_payload(self, raw_file_ref):
        file_ref, resolved = self.resolve_path(raw_file_ref)
        if not file_ref or resolved is None:
            return {}
        if not self._is_within_project_root(resolved):
            if self.logger:
                self.logger.warning("skip loading ai prompt template outside project root: %s", file_ref)
            return {}
        if not resolved.exists() or not resolved.is_file():
            return {}

        try:
            text = resolved.read_text(encoding="utf-8")
        except Exception as exc:
            if self.logger:
                self.logger.warning("load ai prompt template failed: %s (%s)", file_ref, exc)
            return {}

        payload = {"file": file_ref}
        if resolved.suffix.lower() in (".yaml", ".yml"):
            try:
                loaded = yaml.safe_load(text)
            except Exception as exc:
                if self.logger:
                    self.logger.warning("parse ai sop yaml failed: %s (%s)", file_ref, exc)
                loaded = None

            if isinstance(loaded, dict):
                for key in ("id", "name", "scene", "updated_at"):
                    value = str(loaded.get(key) or "").strip()
                    if value:
                        payload[key] = value
                content = self._extract_content(
                    loaded.get("content")
                    if loaded.get("content") is not None
                    else loaded.get("prompt")
                )
                if not content:
                    content = self._extract_content(loaded.get("sop"))
                payload["content"] = content
                return payload
            if isinstance(loaded, str):
                payload["content"] = loaded.strip()
                return payload

        payload["content"] = text.strip()
        return payload

    def read_content(self, raw_file_ref):
        return str(self.load_payload(raw_file_ref).get("content") or "").strip()

    def resolve_template_file(self, prompt_id, raw_file_ref=""):
        file_ref = self._normalize_file_ref(raw_file_ref)
        if file_ref:
            return file_ref
        return str(self.template_file_map.get(str(prompt_id or "").strip()) or "").strip()

    def _atomic_write_text(self, resolved, text):
        resolved.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                delete=False,
                dir=str(resolved.parent),
                suffix=".tmp",
                encoding="utf-8",
            ) as tmp_file:
                tmp_file.write(text)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
                tmp_path = Path(tmp_file.name)
            tmp_path.replace(resolved)
        except OSError as exc:
            if exc.errno not in (errno.EBUSY, errno.EXDEV, errno.EPERM):
                raise
            if self.logger:
                self.logger.warning(
                    "atomic ai sop replace failed, fallback to direct write: %s",
                    exc,
                )
            with resolved.open("w", encoding="utf-8") as file_obj:
                file_obj.write(text)
                file_obj.flush()
                os.fsync(file_obj.fileno())
        finally:
            if tmp_path and tmp_path.exists():
                tmp_path.unlink()

    def write_content(self, raw_file_ref, content, prompt_meta=None):
        file_ref, resolved = self.resolve_path(raw_file_ref)
        prompt_text = str(content or "").strip()
        if not file_ref or resolved is None or not prompt_text:
            return False
        if not self._is_within_project_root(resolved):
            raise ValueError("提示词文件路径超出项目目录")

        suffix = resolved.suffix.lower()
        if suffix in (".yaml", ".yml"):
            meta = prompt_meta if isinstance(prompt_meta, dict) else {}
            existing_payload = self.load_payload(file_ref)
            now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            yaml_obj = {}
            for key in ("id", "name", "scene"):
                value = str(meta.get(key) or existing_payload.get(key) or "").strip()
                if value:
                    yaml_obj[key] = value
            yaml_obj["updated_at"] = str(meta.get("updated_at") or now_text).strip() or now_text
            yaml_obj["content"] = prompt_text
            yaml_text = yaml.safe_dump(
                yaml_obj,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
        else:
            yaml_text = prompt_text + "\n"

        self._atomic_write_text(resolved, yaml_text)
        return True

    def parse_uploaded(self, file_bytes):
        if not file_bytes:
            raise ValueError("上传文件为空")
        if len(file_bytes) > 512 * 1024:
            raise ValueError("SOP 文件过大（最大 512KB）")
        try:
            text = file_bytes.decode("utf-8")
        except Exception as exc:
            raise ValueError("SOP 文件必须为 UTF-8 编码") from exc
        if not text.strip():
            raise ValueError("SOP 文件内容为空")

        try:
            loaded = yaml.safe_load(text)
        except Exception as exc:
            raise ValueError("SOP YAML 格式错误：{}".format(exc)) from exc

        parsed = {}
        if isinstance(loaded, dict):
            for key in ("id", "name", "scene", "updated_at"):
                parsed[key] = str(loaded.get(key) or "").strip()
            content = self._extract_content(
                loaded.get("content")
                if loaded.get("content") is not None
                else loaded.get("prompt")
            )
            if not content:
                content = self._extract_content(loaded.get("sop"))
            parsed["content"] = content
        elif isinstance(loaded, str):
            parsed["content"] = loaded.strip()
        else:
            parsed["content"] = text.strip()

        parsed["content"] = str(parsed.get("content") or "").strip()
        if not parsed["content"]:
            raise ValueError("SOP YAML 缺少 content 字段或内容为空")
        return parsed

    def persist_templates(self, prompt_templates, existing_templates):
        existing_map = {}
        if isinstance(existing_templates, list):
            for item in existing_templates:
                if not isinstance(item, dict):
                    continue
                template_id = str(item.get("id") or "").strip()
                if template_id:
                    existing_map[template_id] = dict(item)

        persisted = []
        for item in prompt_templates or []:
            if not isinstance(item, dict):
                continue
            prompt_id = str(item.get("id") or "").strip()
            if not prompt_id:
                continue
            existing_item = existing_map.get(prompt_id) or {}
            content = str(item.get("content") or "").strip()
            file_ref = self.resolve_template_file(
                prompt_id,
                item.get("file") or existing_item.get("file"),
            )
            persisted_item = {
                "id": prompt_id,
                "name": str(item.get("name") or prompt_id).strip(),
                "scene": str(item.get("scene") or "ai_report_export").strip(),
                "updated_at": str(item.get("updated_at") or "").strip(),
            }
            file_saved = False
            if file_ref:
                try:
                    if content:
                        self.write_content(file_ref, content, prompt_meta=item)
                    persisted_item["file"] = file_ref
                    file_saved = True
                except Exception as exc:
                    if self.logger:
                        self.logger.warning(
                            "persist ai prompt template to file failed: %s (%s)",
                            file_ref,
                            exc,
                        )
            if not file_saved:
                persisted_item["content"] = content
            persisted.append(persisted_item)
        return persisted
