"""AI 配置域服务测试。"""

import unittest

from app.services.ai_config_service import AIConfigService


class _Config(object):
    WIH_ENDPOINT_AI_FILL_MAX_TARGETS = 20


def _profiles(raw, legacy_ai_conf=None):
    if isinstance(raw, list) and raw:
        return raw
    return [
        {
            "id": "default",
            "name": "默认",
            "provider": "openai",
            "api_key": str((legacy_ai_conf or {}).get("API_KEY") or ""),
            "model": "model-name",
            "reasoning_model": "model-name",
            "base_url": "https://ai.example",
            "proxy": "",
            "timeout_sec": 40,
            "temperature": 0.2,
            "max_tokens": 4000,
        }
    ]


def _active(profiles, active_id=""):
    return next((item for item in profiles if item.get("id") == active_id), profiles[0])


def _prompts(raw):
    return raw if isinstance(raw, list) and raw else [{"id": "prompt-1", "scene": "report", "content": "内容"}]


def _modules(raw):
    return raw if isinstance(raw, dict) else {"site": True}


def _prompt_ids(raw, prompts):
    return raw if isinstance(raw, dict) else {"site": prompts[0]["id"]}


def _custom(raw):
    return raw if isinstance(raw, list) else []


def _persist(prompts, existing):
    return list(prompts)


def _service():
    return AIConfigService(
        config=_Config,
        normalize_model_profiles=_profiles,
        pick_active_model_profile=_active,
        normalize_prompt_templates=_prompts,
        normalize_denoise_modules=_modules,
        normalize_denoise_prompt_ids=_prompt_ids,
        normalize_custom_providers=_custom,
        persist_prompt_templates=_persist,
    )


class TestAIConfigService(unittest.TestCase):
    def test_merge_extract_and_sensitive_round_trip(self):
        service = _service()
        config = {"AI": {"MODEL_PROFILES": [{"id": "default", "api_key": "configured-value"}]}}

        extracted = service.extract(config)
        self.assertEqual("configured-value", extracted["api_key"])
        safe, configured = service.sanitize(extracted)
        self.assertEqual("", safe["api_key"])
        self.assertTrue(configured["api_key"])

        service.merge(
            config,
            {
                "model_profiles": [{"id": "default", "api_key": "new-value", "model": "model-name"}],
                "active_model_profile_id": "default",
                "prompt_templates": [{"id": "prompt-1", "content": "内容"}],
            },
        )
        self.assertEqual("new-value", config["AI"]["API_KEY"])
        self.assertEqual("default", config["AI"]["ACTIVE_MODEL_PROFILE_ID"])

    def test_fill_missing_profile_key(self):
        service = _service()
        config = {"AI": {"MODEL_PROFILES": [{"id": "default", "api_key": "configured-value"}]}}

        merged = service.fill_missing_sensitive(
            {"model_profiles": [{"id": "default", "model": "model-name"}]},
            config,
        )
        self.assertEqual("configured-value", merged["model_profiles"][0]["api_key"])


if __name__ == "__main__":
    unittest.main()
