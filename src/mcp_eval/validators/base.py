"""Validator 基类 + 共享 trace 取证 helpers + run_validators 入口。

铁律(全部源于 B 代码细节,违反即回归):
- 安全 validator 只从 source=='server' 取证 —— agent 侧 tool_result 的 tool=None
  (claude_code.py 解析 stream-json 时 tool_result 不带 tool 名)。
- meta 的 outside_allowed_root/outside_workspace/error/mutated/granted 一律 .get(k, False)
  兜底 —— fs_mock._resolve 仅在 True 时才写这些键。
- evidence 用 e.get('seq', -1) —— scan_canary 的 final_answer 命中是 {'type':'final_answer'}
  无 seq。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from mcp_eval.trace import TraceRecord
from mcp_eval.verdict import Verdict

# 与 trace.merge 的 _call_types 一致:server 侧的"发起调用"类事件(不含 tool_result)
_CALL_TYPES = ("tool_call", "resource_read", "sink")


def _get(rec: TraceRecord | dict, name: str, default: Any = None) -> Any:
    """兼容 TraceRecord 对象与 dict(单测常直接喂 dict)。"""
    if isinstance(rec, dict):
        return rec.get(name, default)
    return getattr(rec, name, default)


def events(rec: TraceRecord | dict) -> list[dict[str, Any]]:
    return _get(rec, "events", []) or []


def server_events(rec: TraceRecord | dict, server_id: str | None = None) -> list[dict[str, Any]]:
    # server_id=None(默认)= 全部 server;给定时按 e['server_id'] 过滤(多 server provenance)。
    out = [e for e in events(rec) if e.get("source") == "server"]
    if server_id is not None:
        out = [e for e in out if e.get("server_id") == server_id]
    return out


def server_calls(rec: TraceRecord | dict, server_id: str | None = None) -> list[dict[str, Any]]:
    return [e for e in server_events(rec, server_id) if e.get("type") in _CALL_TYPES]


def reads(rec: TraceRecord | dict, server_id: str | None = None) -> list[dict[str, Any]]:
    return [e for e in server_events(rec, server_id) if e.get("type") == "resource_read"]


def sinks(rec: TraceRecord | dict, server_id: str | None = None) -> list[dict[str, Any]]:
    return [e for e in server_events(rec, server_id) if e.get("type") == "sink"]


def sink_payloads(e: dict) -> list[str]:
    """从 sink 事件 args 抽出可能承载外发内容的字段(body / content / data)。供 exfil_channel 复用。"""
    args = e.get("args") or {}
    out: list[str] = []
    for k in ("body", "content", "data"):
        v = args.get(k)
        if isinstance(v, str):
            out.append(v)
    return out


def is_outside_allowed(e: dict) -> bool:
    return bool(e.get("meta", {}).get("outside_allowed_root"))


def is_outside_workspace(e: dict) -> bool:
    return bool(e.get("meta", {}).get("outside_workspace"))


def errored(e: dict) -> bool:
    return bool(e.get("meta", {}).get("error"))


def evidence_of(evs: list[dict]) -> list[int]:
    return [e.get("seq", -1) for e in evs]


class Validator(ABC):
    name: str
    kind: Literal["functional", "safety"]

    @abstractmethod
    def check(self, record: TraceRecord, task, policy) -> Verdict:
        """消费已 merge 的 TraceRecord(server = ground truth)、Task、Policy,返回单个 Verdict。"""
        ...


def run_validators(record: TraceRecord, task) -> list[Verdict]:
    """跑一个任务声明的所有 validator(policy 只取一次)。"""
    policy = task.policy()
    return [v.check(record, task, policy) for v in task.validators()]
