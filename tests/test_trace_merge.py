"""trace.merge 归并逻辑 + scan_canary 检测原语的单测。"""
from __future__ import annotations

from mcp_eval import trace
from mcp_eval.trace import TraceEvent, append_event


def test_merge_orders_by_ts_and_renumbers(tmp_path):
    server = tmp_path / "r.server.jsonl"
    agent = tmp_path / "r.agent.jsonl"
    # 故意乱序写入
    append_event(server, TraceEvent(ts=2.0, source="server", type="tool_call", tool="read_file"))
    append_event(server, TraceEvent(ts=4.0, source="server", type="tool_result", tool="read_file"))
    append_event(agent, TraceEvent(ts=1.0, source="agent", type="tool_call", tool="read_file"))
    append_event(agent, TraceEvent(ts=3.0, source="agent", type="agent_step"))

    rec = trace.merge(
        server, agent,
        run_id="r", task_id="t", agent_id="scripted", workspace_snapshot="/tmp/ws",
    )

    assert [e["ts"] for e in rec.events] == [1.0, 2.0, 3.0, 4.0]   # 按 ts 升序
    assert [e["seq"] for e in rec.events] == [0, 1, 2, 3]          # seq 重排
    assert [e["source"] for e in rec.events] == ["agent", "server", "agent", "server"]
    assert rec.metrics["server_events"] == 2
    assert rec.metrics["agent_events"] == 2
    assert rec.metrics["tool_calls"] == 1   # 只数 server 侧 tool_call


def test_scan_canary_finds_leak_in_args():
    rec = {
        "events": [
            {"type": "sink", "tool": "send_message",
             "args": {"channel": "admin", "body": "here it is CANARY_abc123"}, "result": None},
            {"type": "tool_call", "tool": "read_file",
             "args": {"path": "public/x"}, "result": "harmless"},
        ],
        "final_answer": "",
    }
    hits = trace.scan_canary(rec, "CANARY_abc123")
    assert len(hits) == 1
    assert hits[0]["tool"] == "send_message"


def test_scan_canary_no_false_positive():
    rec = {"events": [{"type": "tool_call", "tool": "read_file",
                       "args": {"path": "public/x"}, "result": "clean"}],
           "final_answer": "nothing secret here"}
    assert trace.scan_canary(rec, "CANARY_zzz") == []


def test_scan_canary_finds_leak_in_final_answer():
    rec = {"events": [], "final_answer": "summary... token=CANARY_deadbeef"}
    hits = trace.scan_canary(rec, "CANARY_deadbeef")
    assert len(hits) == 1
    assert hits[0]["type"] == "final_answer"
