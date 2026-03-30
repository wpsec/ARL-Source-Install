"""
AI 渗透 MCP Runtime（P0 最小可用版）

目标：
- 提供统一 Tool Schema
- 提供受预算约束的本地 agent loop
- 产出可落库审计结构（agent_trace/tool_calls/tool_results/stop_reason/budget_used）
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional


ToolExecutor = Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]
AgentDecider = Callable[[Dict[str, Any]], Dict[str, Any]]


@dataclass
class ToolSchema:
    """
    统一工具定义：
    - name: 工具唯一标识
    - description: 工具说明
    - input_schema: 参数 Schema（JSON Schema 子集）
    - execute: 执行函数，返回结构化结果
    """

    name: str
    description: str
    input_schema: Dict[str, Any]
    execute: ToolExecutor


class AiPenMcpRuntime:
    """
    本地 MCP runtime：
    - 支持注册工具与按计划调用
    - 记录 tool_calls/tool_results/agent_trace
    - 统一 stop_reason 与 budget_used
    """

    DEFAULT_RUNTIME_VERSION = "p0-local-v1"

    def __init__(
        self,
        max_turns: int = 3,
        max_tool_calls: int = 3,
        timeout_sec: int = 12,
        runtime_version: str = "",
    ):
        self.max_turns = max(1, int(max_turns or 1))
        self.max_tool_calls = max(1, int(max_tool_calls or 1))
        self.timeout_sec = max(1, int(timeout_sec or 1))
        self.runtime_version = str(runtime_version or self.DEFAULT_RUNTIME_VERSION).strip()

        self._registry: Dict[str, ToolSchema] = {}
        self.agent_trace: List[Dict[str, Any]] = []
        self.tool_calls: List[Dict[str, Any]] = []
        self.tool_results: List[Dict[str, Any]] = []
        self.stop_reason: str = ""
        self.final_output: Dict[str, Any] = {}
        self.turn_count: int = 0
        self._started_at = time.perf_counter()

    def register_tool(self, schema: ToolSchema):
        name = str(schema.name or "").strip()
        if not name:
            return
        self._registry[name] = schema

    def list_tools(self) -> List[str]:
        return list(self._registry.keys())

    def invoke(
        self,
        tool_name: str,
        params: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        summary: str = "",
    ) -> Dict[str, Any]:
        """
        执行单次工具调用并写入审计记录。
        """
        tool_text = str(tool_name or "").strip()
        params_obj = params if isinstance(params, dict) else {}
        context_obj = context if isinstance(context, dict) else {}
        summary_text = str(summary or "").strip()
        turn_id = len(self.tool_calls) + 1

        call_item = {
            "turn": turn_id,
            "tool": tool_text,
            "params": params_obj,
        }
        self.tool_calls.append(call_item)

        if len(self.tool_calls) > self.max_tool_calls:
            self.stop_reason = "budget_exhausted"
            result_item = {
                "turn": turn_id,
                "tool": tool_text,
                "status": "blocked",
                "message": "tool_call_budget_exhausted",
                "result": {},
            }
            self.tool_results.append(result_item)
            self.agent_trace.append(
                {
                    "turn": turn_id,
                    "action": "tool_call",
                    "tool": tool_text,
                    "status": "blocked",
                    "summary": summary_text or "预算耗尽，阻断工具调用",
                }
            )
            return result_item

        schema = self._registry.get(tool_text)
        if schema is None or not callable(schema.execute):
            result_item = {
                "turn": turn_id,
                "tool": tool_text,
                "status": "error",
                "message": "tool_not_registered",
                "result": {},
            }
            self.tool_results.append(result_item)
            self.agent_trace.append(
                {
                    "turn": turn_id,
                    "action": "tool_call",
                    "tool": tool_text,
                    "status": "error",
                    "summary": summary_text or "工具未注册",
                }
            )
            return result_item

        try:
            output = schema.execute(context_obj, params_obj)
            output_obj = output if isinstance(output, dict) else {"output": output}
            status = str(output_obj.get("status", "ok") or "ok").strip().lower()
            if status not in {"ok", "error", "skipped", "blocked"}:
                status = "ok"
            message = str(output_obj.get("message", "") or "").strip()
            result_item = {
                "turn": turn_id,
                "tool": tool_text,
                "status": status,
                "message": message,
                "result": output_obj,
            }
            self.tool_results.append(result_item)
            self.agent_trace.append(
                {
                    "turn": turn_id,
                    "action": "tool_call",
                    "tool": tool_text,
                    "status": status,
                    "summary": summary_text or message or "{} 执行完成".format(tool_text),
                }
            )
            return result_item
        except Exception as exc:
            result_item = {
                "turn": turn_id,
                "tool": tool_text,
                "status": "error",
                "message": str(exc),
                "result": {},
            }
            self.tool_results.append(result_item)
            self.agent_trace.append(
                {
                    "turn": turn_id,
                    "action": "tool_call",
                    "tool": tool_text,
                    "status": "error",
                    "summary": summary_text or "{} 执行异常".format(tool_text),
                }
            )
            return result_item

    def run_plan(
        self,
        plan: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        按计划执行工具序列：
        plan item: {"tool": "...", "params": {...}, "summary": "..."}
        """
        plan_items = plan if isinstance(plan, list) else []
        context_obj = context if isinstance(context, dict) else {}
        turns = 0
        for item in plan_items:
            if turns >= self.max_turns:
                self.stop_reason = "budget_exhausted"
                break
            elapsed = time.perf_counter() - self._started_at
            if elapsed >= float(self.timeout_sec):
                self.stop_reason = "timeout"
                break
            if len(self.tool_calls) >= self.max_tool_calls:
                self.stop_reason = "budget_exhausted"
                break

            tool_name = str((item or {}).get("tool") or "").strip()
            params = (item or {}).get("params") if isinstance(item, dict) else {}
            summary = str((item or {}).get("summary") or "").strip() if isinstance(item, dict) else ""
            if not tool_name:
                continue
            turns += 1
            self.turn_count += 1
            self.invoke(tool_name=tool_name, params=params, context=context_obj, summary=summary)

        if not self.stop_reason:
            self.stop_reason = "final_decision"
        return self.build_result()

    def run_agent_loop(
        self,
        decide_next: AgentDecider,
        context: Optional[Dict[str, Any]] = None,
        memory: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        运行受预算约束的 Agent Loop：
        - decide_next 接收当前上下文/历史工具结果
        - 返回 tool_call / final_decision / manual_required
        """
        context_obj = context if isinstance(context, dict) else {}
        memory_obj = memory if isinstance(memory, dict) else {}
        last_tool_result: Dict[str, Any] = {}

        while True:
            if self.turn_count >= self.max_turns:
                self.stop_reason = "budget_exhausted"
                break
            elapsed = time.perf_counter() - self._started_at
            if elapsed >= float(self.timeout_sec):
                self.stop_reason = "timeout"
                break

            self.turn_count += 1
            turn_id = self.turn_count
            state = {
                "turn": turn_id,
                "max_turns": int(self.max_turns),
                "max_tool_calls": int(self.max_tool_calls),
                "available_tools": self.list_tools(),
                "context": dict(context_obj),
                "memory": dict(memory_obj),
                "agent_trace": list(self.agent_trace),
                "tool_calls": list(self.tool_calls),
                "tool_results": list(self.tool_results),
                "last_tool_result": dict(last_tool_result) if isinstance(last_tool_result, dict) else {},
            }

            try:
                decision = decide_next(state)
            except Exception as exc:
                self.stop_reason = "error"
                self.agent_trace.append(
                    {
                        "turn": turn_id,
                        "action": "agent_turn",
                        "status": "error",
                        "summary": "agent_turn exception: {}".format(str(exc)[:180]),
                    }
                )
                break

            decision_obj = decision if isinstance(decision, dict) else {}
            action = str(decision_obj.get("action") or "").strip().lower()
            if not action:
                if isinstance(decision_obj.get("tool_call"), dict):
                    action = "tool_call"
                elif isinstance(decision_obj.get("final_decision"), dict):
                    action = "final_decision"
                else:
                    action = "manual_required"
            if action not in {"tool_call", "final_decision", "manual_required"}:
                action = "manual_required"

            reason_text = str(decision_obj.get("reason") or "").strip()
            expected_signal = str(decision_obj.get("expected_signal") or "").strip()
            stop_if = str(decision_obj.get("stop_if") or "").strip()
            final_decision = decision_obj.get("final_decision") if isinstance(decision_obj.get("final_decision"), dict) else {}

            trace_item = {
                "turn": turn_id,
                "action": "agent_turn",
                "decision": action,
                "status": "ok",
                "summary": reason_text or action,
            }
            if expected_signal:
                trace_item["expected_signal"] = expected_signal[:180]
            if stop_if:
                trace_item["stop_if"] = stop_if[:180]

            if action == "tool_call":
                tool_call = decision_obj.get("tool_call") if isinstance(decision_obj.get("tool_call"), dict) else {}
                tool_name = str(tool_call.get("tool") or decision_obj.get("tool") or "").strip()
                params = tool_call.get("params") if isinstance(tool_call.get("params"), dict) else {}
                summary = str(tool_call.get("summary") or decision_obj.get("summary") or reason_text or "").strip()
                if not tool_name:
                    action = "manual_required"
                else:
                    trace_item["tool"] = tool_name
                    if summary:
                        trace_item["summary"] = summary[:180]
                    self.agent_trace.append(trace_item)
                    last_tool_result = self.invoke(
                        tool_name=tool_name,
                        params=params,
                        context=context_obj,
                        summary=summary,
                    )
                    if str(last_tool_result.get("status") or "").strip().lower() == "blocked":
                        self.stop_reason = self.stop_reason or "budget_exhausted"
                        break
                    continue

            if action == "final_decision":
                self.stop_reason = "final_decision"
                self.final_output = dict(final_decision)
                trace_item["status"] = "final_decision"
                if final_decision:
                    trace_item["final_decision"] = dict(final_decision)
                self.agent_trace.append(trace_item)
                break

            self.stop_reason = "manual_required"
            if final_decision:
                self.final_output = dict(final_decision)
            trace_item["status"] = "manual_required"
            if final_decision:
                trace_item["final_decision"] = dict(final_decision)
            self.agent_trace.append(trace_item)
            break

        if not self.stop_reason:
            self.stop_reason = "final_decision"
        return self.build_result()

    def build_result(self) -> Dict[str, Any]:
        elapsed_ms = int((time.perf_counter() - self._started_at) * 1000.0)
        return {
            "agent_trace": list(self.agent_trace),
            "tool_calls": list(self.tool_calls),
            "tool_results": list(self.tool_results),
            "stop_reason": str(self.stop_reason or "final_decision"),
            "final_output": dict(self.final_output) if isinstance(self.final_output, dict) else {},
            "budget_used": {
                "turns": max(0, int(self.turn_count or 0)),
                "tool_calls": len(self.tool_calls),
                "max_turns": int(self.max_turns),
                "max_tool_calls": int(self.max_tool_calls),
                "elapsed_ms": max(0, elapsed_ms),
                "timeout_sec": int(self.timeout_sec),
            },
            "runtime_version": self.runtime_version,
        }

    @classmethod
    def build_artifacts_from_tool_trace(
        cls,
        tool_trace_parts: List[str],
        max_tool_calls: int = 3,
        timeout_sec: int = 12,
        status: str = "ok",
        decision: str = "",
        runtime_version: str = "",
    ) -> Dict[str, Any]:
        """
        兼容旧链路：从 `tool_trace` 文本构建结构化审计产物。
        """
        traces = tool_trace_parts if isinstance(tool_trace_parts, list) else []
        calls: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        agent_trace: List[Dict[str, Any]] = []

        for idx, item in enumerate(traces, start=1):
            text = str(item or "").strip()
            if not text:
                continue
            tool_name = text.split("(", 1)[0].strip() if "(" in text else text
            if len(tool_name) > 64:
                tool_name = tool_name[:64]
            calls.append(
                {
                    "turn": idx,
                    "tool": tool_name,
                    "params": {"raw": text},
                }
            )
            results.append(
                {
                    "turn": idx,
                    "tool": tool_name,
                    "status": "ok",
                    "message": "",
                    "result": {"raw": text},
                }
            )
            agent_trace.append(
                {
                    "turn": idx,
                    "action": "tool_call",
                    "tool": tool_name,
                    "status": "ok",
                    "summary": text[:180],
                }
            )

        run_status = str(status or "ok").strip().lower()
        run_decision = str(decision or "").strip().lower()
        stop_reason = "final_decision"
        if run_status == "error":
            stop_reason = "error"
        elif run_status == "skipped":
            stop_reason = "manual_required"
        elif run_decision == "needs_manual_review":
            stop_reason = "manual_required"

        return {
            "agent_trace": agent_trace,
            "tool_calls": calls,
            "tool_results": results,
            "stop_reason": stop_reason,
            "budget_used": {
                "turns": len(agent_trace),
                "tool_calls": len(calls),
                "max_turns": max(1, int(max_tool_calls or 1)),
                "max_tool_calls": max(1, int(max_tool_calls or 1)),
                "elapsed_ms": 0,
                "timeout_sec": max(1, int(timeout_sec or 1)),
            },
            "runtime_version": str(runtime_version or cls.DEFAULT_RUNTIME_VERSION).strip(),
        }
