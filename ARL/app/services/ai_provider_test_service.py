"""AI Provider 连通性测试服务。

配置 API 只负责读取、合并和返回结果；模型发现、最小对话验证、模型回退和
用量记录在本服务中保持一致，避免请求细节继续堆积在 route 模块。
"""

from datetime import datetime
import time

from app.utils.log_safety import safe_error_text


class AIProviderTestService(object):
    """执行一次 AI 配置的最小真实链路测试。"""

    def __init__(
        self,
        http_req,
        normalize_profiles,
        pick_active_profile,
        normalize_provider,
        normalize_model,
        pick_retry_model,
        is_model_unavailable,
        build_proxy_dict,
        normalize_usage,
        normalize_elapsed_ms,
        safe_int,
        safe_float,
        usage_logger=None,
        logger=None,
    ):
        self.http_req = http_req
        self.normalize_profiles = normalize_profiles
        self.pick_active_profile = pick_active_profile
        self.normalize_provider = normalize_provider
        self.normalize_model = normalize_model
        self.pick_retry_model = pick_retry_model
        self.is_model_unavailable = is_model_unavailable
        self.build_proxy_dict = build_proxy_dict
        self.normalize_usage = normalize_usage
        self.normalize_elapsed_ms = normalize_elapsed_ms
        self.safe_int = safe_int
        self.safe_float = safe_float
        self.usage_logger = usage_logger
        self.logger = logger

    @staticmethod
    def _extract_reply_text(chat_payload):
        choices = chat_payload.get("choices", []) if isinstance(chat_payload, dict) else []
        message_obj = choices[0].get("message") if isinstance(choices, list) and choices else {}
        if not isinstance(message_obj, dict):
            return "（接口已响应，但返回内容为空）"
        content_obj = message_obj.get("content")
        if isinstance(content_obj, str):
            return content_obj.strip() or "（接口已响应，但返回内容为空）"
        if isinstance(content_obj, list):
            parts = []
            for fragment in content_obj:
                if not isinstance(fragment, dict) or fragment.get("type") != "text":
                    continue
                text_value = str(fragment.get("text") or "").strip()
                if text_value:
                    parts.append(text_value)
            return "\n".join(parts).strip() or "（接口已响应，但返回内容为空）"
        return "（接口已响应，但返回内容为空）"

    def test(self, ai_config):
        if not isinstance(ai_config, dict):
            raise ValueError("ai_config 必须为对象")

        profiles = self.normalize_profiles(
            ai_config.get("model_profiles"),
            legacy_ai_conf=ai_config,
        )
        active_id = str(ai_config.get("active_model_profile_id") or "").strip()
        active_profile = self.pick_active_profile(profiles, active_id)
        provider_id = self.normalize_provider(active_profile.get("provider") or "openai")
        base_url = str(active_profile.get("base_url") or "").strip()
        api_key = str(active_profile.get("api_key") or "").strip()
        proxy_url = str(
            active_profile.get("proxy")
            or ai_config.get("proxy_url")
            or ai_config.get("proxy")
            or ""
        ).strip()
        proxies = self.build_proxy_dict(proxy_url)
        model_name = self.normalize_model(provider_id, active_profile.get("model"))
        reasoning_model = self.normalize_model(
            provider_id,
            active_profile.get("reasoning_model")
            or ai_config.get("reasoning_model")
            or model_name,
        )
        profile_name = str(active_profile.get("name") or active_profile.get("id") or "").strip()
        timeout_sec = self.safe_int(active_profile.get("timeout_sec"), 40, min_value=5)
        request_delay_ms = min(
            30000,
            self.safe_int(ai_config.get("request_delay_ms"), 0, min_value=0),
        )
        request_text = "你好呀～"
        request_started_at = time.perf_counter()

        def sleep_before_request():
            if request_delay_ms > 0:
                time.sleep(float(request_delay_ms) / 1000.0)

        def build_result(ok, message, detail, status="", usage=None, error_message="", elapsed_ms=0):
            detail_value = detail if isinstance(detail, dict) else {}
            status_value = str(status or "").strip().lower()
            if status_value not in ("ok", "error", "skipped"):
                status_value = "ok" if ok else "error"
            elapsed_value = self.normalize_elapsed_ms(elapsed_ms)
            if elapsed_value <= 0 and status_value in ("ok", "error"):
                elapsed_value = self.normalize_elapsed_ms(
                    int((time.perf_counter() - request_started_at) * 1000.0)
                )
            error_value = safe_error_text(error_message or (message if status_value == "error" else ""))
            result = {
                "ok": bool(ok),
                "message": str(message or ""),
                "provider": provider_id,
                "detail": detail_value,
                "tested_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            if callable(self.usage_logger):
                self.usage_logger(
                    scene="ai_config_test",
                    provider=provider_id,
                    model=str(detail_value.get("model") or model_name),
                    profile=str(detail_value.get("profile") or profile_name),
                    status=status_value,
                    request_text=str(detail_value.get("request_text") or request_text),
                    reply_text=str(detail_value.get("reply_text") or ""),
                    error_message=error_value,
                    elapsed_ms=elapsed_value,
                    usage=usage,
                    meta={
                        "base_url": base_url,
                        "model_count": self.safe_int(detail_value.get("model_count"), 0, min_value=0),
                    },
                )
            return result

        common_detail = {
            "model": model_name,
            "reasoning_model": reasoning_model,
            "profile": profile_name,
            "request_text": request_text,
            "reply_text": "",
        }
        if not api_key:
            return build_result(False, "未配置 API Key，已跳过连通性测试", common_detail, status="skipped")
        if not base_url:
            return build_result(False, "未配置 Base URL，已跳过连通性测试", common_detail, status="skipped")

        headers = {
            "Authorization": "Bearer {}".format(api_key),
            "Content-Type": "application/json",
        }
        request_options = {"headers": headers, "timeout": (8, timeout_sec)}
        if proxies:
            request_options["proxies"] = proxies

        try:
            models_conn = self.http_req(
                "{}/models".format(base_url.rstrip("/")),
                "get",
                **request_options
            )
            status_code = int(getattr(models_conn, "status_code", 0) or 0)
            try:
                models_payload = models_conn.json() if models_conn is not None else {}
            except Exception:
                models_payload = {}
            if status_code != 200:
                error_message = ""
                if isinstance(models_payload, dict):
                    error_obj = models_payload.get("error")
                    if isinstance(error_obj, dict):
                        error_message = str(error_obj.get("message") or "")
                    error_message = error_message or str(models_payload.get("message") or "")
                error_message = error_message or "HTTP {}".format(status_code)
                detail = dict(common_detail)
                detail.update({"status_code": status_code, "base_url": base_url})
                return build_result(
                    False,
                    "AI 测试失败：{}".format(safe_error_text(error_message)),
                    detail,
                    status="error",
                    error_message=error_message,
                )

            models = models_payload.get("data", []) if isinstance(models_payload, dict) else []
            model_count = len(models) if isinstance(models, list) else 0
            first_model = ""
            if isinstance(models, list) and models and isinstance(models[0], dict):
                first_model = str(models[0].get("id") or "").strip()
            chat_url = "{}/chat/completions".format(base_url.rstrip("/"))

            def run_chat(test_type, preferred_model, allow_retry=True):
                preferred = str(preferred_model or "").strip()
                test_model = preferred or first_model
                result = {
                    "type": str(test_type or "").strip(),
                    "configured_model": preferred,
                    "model": test_model,
                    "profile": profile_name,
                    "request_text": request_text,
                    "reply_text": "",
                    "status": "error",
                    "ok": False,
                    "message": "",
                    "status_code": 0,
                    "usage": self.normalize_usage({}),
                }
                if not test_model:
                    result["message"] = "未发现可用模型"
                    return result

                body = {
                    "model": test_model,
                    "temperature": min(
                        max(self.safe_float(active_profile.get("temperature"), 0.2, min_value=0.0), 0.0),
                        1.0,
                    ),
                    "max_tokens": max(
                        64,
                        min(self.safe_int(active_profile.get("max_tokens"), 128, min_value=32), 512),
                    ),
                    "messages": [{"role": "user", "content": request_text}],
                }
                chat_options = {"headers": headers, "json": body, "timeout": (8, timeout_sec)}
                if proxies:
                    chat_options["proxies"] = proxies
                sleep_before_request()
                conn = self.http_req(chat_url, "post", **chat_options)
                result["status_code"] = int(getattr(conn, "status_code", 0) or 0)
                try:
                    payload = conn.json() if conn is not None else {}
                except Exception:
                    payload = {}
                if result["status_code"] == 200:
                    result["status"] = "ok"
                    result["ok"] = True
                    result["usage"] = self.normalize_usage(
                        payload.get("usage") if isinstance(payload, dict) else {}
                    )
                    result["reply_text"] = self._extract_reply_text(payload)
                    result["message"] = "ok"
                    return result

                error_message = ""
                if isinstance(payload, dict):
                    error_obj = payload.get("error")
                    if isinstance(error_obj, dict):
                        error_message = str(error_obj.get("message") or "").strip()
                    error_message = error_message or str(payload.get("message") or "").strip()
                error_message = error_message or "HTTP {}".format(result["status_code"])
                retry_model = self.pick_retry_model(provider_id, test_model) if allow_retry and self.is_model_unavailable(error_message) else ""
                if retry_model:
                    retry_body = dict(body)
                    retry_body["model"] = retry_model
                    retry_options = {"headers": headers, "json": retry_body, "timeout": (8, timeout_sec)}
                    if proxies:
                        retry_options["proxies"] = proxies
                    sleep_before_request()
                    retry_conn = self.http_req(chat_url, "post", **retry_options)
                    result["status_code"] = int(getattr(retry_conn, "status_code", 0) or 0)
                    try:
                        retry_payload = retry_conn.json() if retry_conn is not None else {}
                    except Exception:
                        retry_payload = {}
                    if result["status_code"] == 200:
                        result["status"] = "ok"
                        result["ok"] = True
                        result["model"] = retry_model
                        result["usage"] = self.normalize_usage(
                            retry_payload.get("usage") if isinstance(retry_payload, dict) else {}
                        )
                        result["reply_text"] = self._extract_reply_text(retry_payload)
                        result["message"] = "模型已从 {} 自动切换为 {}".format(test_model, retry_model)
                        return result
                    retry_error = ""
                    if isinstance(retry_payload, dict):
                        retry_obj = retry_payload.get("error")
                        if isinstance(retry_obj, dict):
                            retry_error = str(retry_obj.get("message") or "").strip()
                        retry_error = retry_error or str(retry_payload.get("message") or "").strip()
                    error_message = retry_error or "HTTP {}".format(result["status_code"])
                if not allow_retry and self.is_model_unavailable(error_message):
                    result["message"] = "{}（已禁用自动切换模型，请确认当前模型可用）".format(error_message)
                else:
                    result["message"] = safe_error_text(error_message)
                return result

            analysis = run_chat("analysis", model_name, allow_retry=True)
            reasoning_reference = reasoning_model or model_name
            same_model = bool(reasoning_reference and model_name and reasoning_reference == model_name)
            if same_model:
                reasoning = dict(analysis)
                reasoning["type"] = "reasoning"
                reasoning["configured_model"] = reasoning_reference
                reasoning["message"] = "思考模型与分析模型相同，复用测试结果"
            else:
                reasoning = run_chat("reasoning", reasoning_reference, allow_retry=False)

            total_usage = self.normalize_usage({
                "prompt_tokens": self.safe_int(analysis.get("usage", {}).get("prompt_tokens"), 0, min_value=0)
                + self.safe_int(reasoning.get("usage", {}).get("prompt_tokens"), 0, min_value=0),
                "completion_tokens": self.safe_int(analysis.get("usage", {}).get("completion_tokens"), 0, min_value=0)
                + self.safe_int(reasoning.get("usage", {}).get("completion_tokens"), 0, min_value=0),
                "total_tokens": self.safe_int(analysis.get("usage", {}).get("total_tokens"), 0, min_value=0)
                + self.safe_int(reasoning.get("usage", {}).get("total_tokens"), 0, min_value=0),
            })
            all_ok = bool(analysis.get("ok")) and bool(reasoning.get("ok"))
            failed = []
            if not analysis.get("ok"):
                failed.append("分析模型({})".format(analysis.get("message") or "unknown_error"))
            if not reasoning.get("ok"):
                failed.append("思考模型({})".format(reasoning.get("message") or "unknown_error"))
            summary = (
                "AI 测试成功（分析模型与思考模型相同，已完成连通性测试）"
                if all_ok and same_model
                else "AI 测试成功（分析模型 + 思考模型）"
                if all_ok
                else "AI 测试失败：{}".format("；".join(failed)[:240])
            )
            detail = {
                "base_url": base_url,
                "model_count": model_count,
                "first_model": first_model,
                "model": str(analysis.get("model") or model_name),
                "reasoning_model": str(reasoning.get("model") or reasoning_reference),
                "profile": profile_name,
                "request_text": request_text,
                "reply_text": str(analysis.get("reply_text") or ""),
                "usage": total_usage,
                "analysis_test": analysis,
                "reasoning_test": reasoning,
            }
            return build_result(
                all_ok,
                summary,
                detail,
                status="ok" if all_ok else "error",
                usage=total_usage,
                error_message="；".join(failed)[:300],
            )
        except Exception as exc:
            error_text = safe_error_text(exc)
            detail = dict(common_detail)
            detail["base_url"] = base_url
            return build_result(
                False,
                "AI 测试失败：{}".format(error_text),
                detail,
                status="error",
                error_message=error_text,
            )
