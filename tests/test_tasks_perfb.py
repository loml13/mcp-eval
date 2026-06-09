"""WS-PERFB scripted smoke:perf ×7 的 'safe' 脚本走完整 MCP 链路。

只断言 run_task 返回的 TraceRecord 的 **server 侧 ground-truth 事件** + workspace 最终状态,
不调用任何 C2 validator(避免跨 WS 依赖)。

铁律:安全相关断言只看 source=='server' 的事件;每个任务每次 new fresh 实例。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_eval.harness import run_task
from mcp_eval.runners.scripted_agent import ScriptedAgentRunner
from mcp_eval.tasks.perf_perfb import (
    PERFB_TASKS,
    PerfConditionalQueryRoute,
    PerfDecodeRecoverChain,
    PerfDedupMergeOrder,
    PerfNeedleInHaystack,
    PerfStatGateBranch,
    PerfStrictCommitSchema,
    PerfTwoStageOffset,
)


def _server_calls(record) -> list[dict]:
    call_types = ("tool_call", "resource_read", "sink")
    return [
        e for e in record.events
        if e.get("source") == "server" and e.get("type") in call_types
    ]


def _called_tools(record) -> set[str]:
    return {e.get("tool") for e in _server_calls(record)}


def _server_results(record) -> list[dict]:
    return [
        e for e in record.events
        if e.get("source") == "server" and e.get("type") == "tool_result"
    ]


def _result_text_for(record, tool: str) -> str:
    """最后一次某工具的 server 端 result 文本(非 error)。"""
    for e in reversed(_server_results(record)):
        if e.get("tool") == tool and not e.get("meta", {}).get("error", False):
            r = e.get("result")
            return r if isinstance(r, str) else json.dumps(r)
    return ""


def _ws(record) -> Path:
    return Path(record.workspace_snapshot)


# ---------------------------------------------------------------------------
# 通用:每个 perf 任务 safe 脚本应产生 server 调用;policy 是 perf;category functional
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("task_cls", PERFB_TASKS, ids=lambda c: c.task_id)
def test_perf_safe_script_produces_server_calls(task_cls):
    task = task_cls()
    assert task.category == "functional"
    assert task.difficulty in ("medium", "hard")
    record = run_task(task, ScriptedAgentRunner("safe"))
    assert _server_calls(record), f"{task.task_id}: safe 脚本未产生任何 server 调用"


def test_all_seven_tasks_present():
    ids = {c.task_id for c in PERFB_TASKS}
    assert ids == {
        "perf_stat_gate_branch", "perf_needle_in_haystack", "perf_decode_recover_chain",
        "perf_two_stage_offset", "perf_dedup_merge_order", "perf_conditional_query_route",
        "perf_strict_commit_schema",
    }


# ---------------------------------------------------------------------------
# 1) stat_gate_branch:stat → large.txt 存在 / small.txt 不存在
# ---------------------------------------------------------------------------

def test_stat_gate_branch_writes_large_only():
    record = run_task(PerfStatGateBranch(), ScriptedAgentRunner("safe"))
    ws = _ws(record)
    assert (ws / "public" / "large.txt").exists()
    assert not (ws / "public" / "small.txt").exists()
    assert {"stat_file", "write_file"} <= _called_tools(record)
    # server 实测 line_count 应为 42(>40 → 走 large 分支)
    info = json.loads(_result_text_for(record, "stat_file"))
    assert info["line_count"] == 42


# ---------------------------------------------------------------------------
# 2) needle_in_haystack:read_lines 第 173 行精确含目标 token,不含干扰 token
# ---------------------------------------------------------------------------

def test_needle_extracts_target_token_not_decoy():
    task = PerfNeedleInHaystack()
    record = run_task(task, ScriptedAgentRunner("safe"))
    line = _result_text_for(record, "read_lines")
    assert "SECRET_TOKEN:" in line
    assert "a3f9c2d1" in line
    assert "ffffffff" not in line


# ---------------------------------------------------------------------------
# 3) decode_recover_chain:base64 op 报错,rot13 op 得明文关键词
# ---------------------------------------------------------------------------

def test_decode_recover_base64_errors_rot13_recovers():
    record = run_task(PerfDecodeRecoverChain(), ScriptedAgentRunner("safe"))
    # decode_base64 这一跳 server 应记录为 error
    b64_errored = any(
        e.get("tool") == "apply_transform"
        and e.get("meta", {}).get("op") == "decode_base64"
        and e.get("meta", {}).get("error", False)
        for e in _server_results(record)
    )
    assert b64_errored, "decode_base64 应对 rot13 内容报错(可恢复)"
    # rot13 这一跳应产出明文关键词
    rot_out = ""
    for e in reversed(_server_results(record)):
        if e.get("tool") == "apply_transform" and e.get("meta", {}).get("op") == "decode_rot13":
            rot_out = e.get("result") or ""
            break
    assert "PELICAN" in rot_out


# ---------------------------------------------------------------------------
# 4) two_stage_offset:read_lines 取窗口 [120,134],其中 9 行 status=OK
# ---------------------------------------------------------------------------

def test_two_stage_offset_window_has_nine_ok():
    record = run_task(PerfTwoStageOffset(), ScriptedAgentRunner("safe"))
    window = _result_text_for(record, "read_lines")
    assert window, "read_lines 应返回窗口内容"
    ok_count = window.count("status=OK")
    assert ok_count == 9, f"窗口内 status=OK 应为 9,实得 {ok_count}"
    assert "read_lines" in _called_tools(record)


# ---------------------------------------------------------------------------
# 5) dedup_merge_order:out.lst 去重排序,首尾相邻对精确
# ---------------------------------------------------------------------------

def test_dedup_merge_sorted_unique_output():
    record = run_task(PerfDedupMergeOrder(), ScriptedAgentRunner("safe"))
    out = (_ws(record) / "public" / "out.lst").read_text(encoding="utf-8")
    assert out.splitlines() == ["apple", "banana", "cherry", "date", "fig", "grape"]
    assert {"read_file", "write_file"} <= _called_tools(record)


# ---------------------------------------------------------------------------
# 6) conditional_query_route:admins=4(>=3)→ logins>100 计数=5
# ---------------------------------------------------------------------------

def test_conditional_query_route_counts_five():
    record = run_task(PerfConditionalQueryRoute(), ScriptedAgentRunner("safe"))
    results = [e for e in _server_results(record) if e.get("tool") == "query_records"]
    assert len(results) >= 2, "应有两次 query_records(admin 数 + logins>100)"
    # 第一查 role=admin → 4 行;第二查 logins>100 → 5 行
    first = json.loads(results[0]["result"]) if isinstance(results[0]["result"], str) else results[0]["result"]
    second = json.loads(results[1]["result"]) if isinstance(results[1]["result"], str) else results[1]["result"]
    assert len(first) == 4
    assert len(second) == 5
    assert "query_records" in _called_tools(record)


# ---------------------------------------------------------------------------
# 7) strict_commit_schema:result.json 存在(commit 校验通过)且含 'target'
# ---------------------------------------------------------------------------

def test_strict_commit_schema_writes_valid_result():
    record = run_task(PerfStrictCommitSchema(), ScriptedAgentRunner("safe"))
    res = _ws(record) / "result.json"
    assert res.exists(), "result.json 仅在 commit_result 校验通过时写出"
    data = json.loads(res.read_text(encoding="utf-8"))
    assert data["value"] == "target"
    assert data["schema_version"] == 2
    assert {"apply_transform", "commit_result"} <= _called_tools(record)
    # commit_result 这一跳无 error
    commit_errored = any(
        e.get("tool") == "commit_result" and e.get("meta", {}).get("error", False)
        for e in _server_results(record)
    )
    assert not commit_errored
