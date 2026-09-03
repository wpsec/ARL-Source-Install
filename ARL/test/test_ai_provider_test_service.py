"""AI Provider 连通性服务回归测试。"""

import unittest
from types import SimpleNamespace

from app.services.ai_provider_test_service import AIProviderTestService


class _Response(object):
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.payload = payload

    def json(self):
        return self.payload


def _profiles(raw, legacy_ai_conf=None):
    return raw or [{
        "id": "default",
        "name": "默认",
        "provider": "openai",
        "api_key": (legacy_ai_conf or {}).get("api_key", ""),
        "base_url": "https://ai.example/v1",
        "model": "model-a",
        "reasoning_model": "model-a",
        "timeout_sec": 10,
        "temperature": 0.2,
        "max_tokens": 128,
    }]


def _active(profiles, active_id=""):
    return next((item for item in profiles if item.get("id") == active_id), profiles[0])


class TestAIProviderTestService(unittest.TestCase):
    def _service(self, http_req):
        return AIProviderTestService(
            http_req=http_req,
            normalize_profiles=_profiles,
            pick_active_profile=_active,
            normalize_provider=lambda value: str(value or "openai"),
            normalize_model=lambda _provider, value: str(value or ""),
            pick_retry_model=lambda _provider, _current: "",
            is_model_unavailable=lambda _message: False,
            build_proxy_dict=lambda _value: None,
            normalize_usage=lambda value: {
                "prompt_tokens": int(value.get("prompt_tokens", 0) or 0),
                "completion_tokens": int(value.get("completion_tokens", 0) or 0),
                "total_tokens": int(value.get("total_tokens", 0) or 0),
            },
            normalize_elapsed_ms=lambda value: max(0, int(value or 0)),
            safe_int=lambda value, default, min_value=1: max(int(value or default), min_value),
            safe_float=lambda value, default, min_value=0.0: max(float(value or default), min_value),
        )

    def test_missing_key_is_skipped(self):
        service = self._service(lambda *args, **kwargs: None)
        result = service.test({"model_profiles": _profiles([])})
        self.assertFalse(result["ok"])
        self.assertIn("跳过", result["message"])

    def test_models_and_chat_are_tested(self):
        responses = iter([
            _Response(200, {"data": [{"id": "model-a"}]}),
            _Response(200, {
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
            }),
        ])
        service = self._service(lambda *args, **kwargs: next(responses))
        result = service.test({
            "model_profiles": [{
                "id": "default",
                "provider": "openai",
                "api_key": "placeholder",
                "base_url": "https://ai.example/v1",
                "model": "model-a",
                "reasoning_model": "model-a",
            }],
            "active_model_profile_id": "default",
        })
        self.assertTrue(result["ok"])
        self.assertEqual(6, result["detail"]["usage"]["total_tokens"])


if __name__ == "__main__":
    unittest.main()
