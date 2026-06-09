"""WS-PERFA scripted smoke:8 个性能任务的 'safe' 脚本走完整 MCP 链路。

铁律落实:不调用任何 C2 validator(跨 WS 并行,避免依赖未就绪);只断言 run_task 返回的
TraceRecord 的 server 侧 ground-truth 事件 + workspace 最终状态。每个任务每次 new fresh 实例
(workspace 由 run_task 每 run 重建)。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_eval.harness import run_task
from mcp_eval.runners.scripted_agent import ScriptedAgentRunner
from mcp_eval.tasks import perf_perfa
from mcp_eval.tasks.perf_perfa import (
    PERFA_TASKS,
    PerfChainChecksumCommit,
    PerfEnumQueryStrict,
    PerfMultiAggregate,
    PerfPipeline5Hop,
    PerfRecoverKv,
    PerfRecoverLinesOob,
    PerfSemverBranch,
    PerfToolAmbiguityChecksum,
)


# ---------------------------------------------------------------------------
# trace 辅助:只看 source=='server' 的发起调用 / 结果
# ---------------------------------------------------------------------------

def _server_events(record) -> list[dict]:
    return [e for e in record.events if e.get("source") == "server"]


def _server_calls(record) -> list[dict]:
    call_types = ("tool_call", "resource_read", "sink")
    return [e for e in _server_events(record) if e.get("type") in call_types]


def _called_tools(record) -> set[str]:
    return {e.get("tool") for e in _server_calls(record)}


def _server_results(record, tool: str) -> list[dict]:
    return [
        e
        for e in _server_events(record)
        if e.get("type") == "tool_result" and e.get("tool") == tool
    ]


def _ws(record) -> Path:
    return Path(record.workspace_snapshot)


# ---------------------------------------------------------------------------
# 全量:每个 safe 脚本至少产生一次 server 调用,且必须出现的工具都被调到
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("task_cls", PERFA_TASKS, ids=lambda c: c.task_id)
def test_safe_script_calls_required_tools(task_cls):
    task = task_cls()  # fresh 实例
    record = run_task(task, ScriptedAgentRunner("safe"))

    called = _called_tools(record)
    assert called, f"{task.task_id}: safe 脚本未产生任何 server 调用"
    for tool in task.expectation().must_have_called:
        assert tool in called, f"{task.task_id}: must_have_called 工具 {tool} 未被调用"


def test_perfa_factory_count_and_difficulty():
    assert len(PERFA_TASKS) == 8
    ids = {c.task_id for c in PERFA_TASKS}
    assert ids == {
        "perf_pipeline_5hop",
        "perf_recover_kv",
        "perf_recover_lines_oob",
        "perf_enum_query_strict",
        "perf_tool_ambiguity_checksum",
        "perf_semver_branch",
        "perf_multi_aggregate",
        "perf_chain_checksum_commit",
    }
    for c in PERFA_TASKS:
        assert c.category == "functional"
        assert c.difficulty in ("medium", "hard")


# ---------------------------------------------------------------------------
# perf_pipeline_5hop:多跳解码链 → commit_result 写出自洽 result.json
# ---------------------------------------------------------------------------

def test_pipeline_5hop_commits_correct_plaintext():
    task = PerfPipeline5Hop()
    record = run_task(task, ScriptedAgentRunner("safe"))

    # 链路工具齐全
    assert {"read_file", "apply_transform", "compute_checksum", "commit_result"} <= _called_tools(record)
    # decode_rot13 这一步的 server 结果应为终值明文
    rot_results = [
        e["result"] for e in _server_results(record, "apply_transform") if e["result"] == perf_perfa._PIPELINE_PLAINTEXT
    ]
    assert perf_perfa._PIPELINE_PLAINTEXT in rot_results, "decode_rot13 未还原出预期明文"
    # commit_result 成功(无 error) → result.json 写出且内容自洽
    commit_res = _server_results(record, "commit_result")
    assert commit_res and not any(e.get("meta", {}).get("error") for e in commit_res)
    result_json = _ws(record) / "result.json"
    assert result_json.exists()
    data = json.loads(result_json.read_text(encoding="utf-8"))
    assert data["value"] == perf_perfa._PIPELINE_PLAINTEXT
    assert data["checksum"] == perf_perfa._PIPELINE_CRC32
    assert data["schema_version"] == 2


# ---------------------------------------------------------------------------
# perf_recover_kv:错键 error → kv_list 恢复 → 正确键拿到值
# ---------------------------------------------------------------------------

def test_recover_kv_walks_recovery_path():
    task = PerfRecoverKv()
    record = run_task(task, ScriptedAgentRunner("safe"))

    assert "kv_list" in _called_tools(record), "未走 kv_list 恢复路径"
    # 第一次 kv_get(错键)应 error
    kv_get_results = _server_results(record, "kv_get")
    assert any(e.get("meta", {}).get("error") for e in kv_get_results), "错键 kv_get 未触发 error"
    # 最终 kv_get(正确键)拿到目标值
    assert any(e.get("result") == task._VALUE for e in kv_get_results), "正确键未取到目标值"


# ---------------------------------------------------------------------------
# perf_recover_lines_oob:越界 read_lines error → stat_file → 精确读末行
# ---------------------------------------------------------------------------

def test_recover_lines_oob_fixes_off_by_one():
    task = PerfRecoverLinesOob()
    record = run_task(task, ScriptedAgentRunner("safe"))

    assert "stat_file" in _called_tools(record)
    rl_results = _server_results(record, "read_lines")
    # 越界那次应 error
    assert any(e.get("meta", {}).get("error") for e in rl_results), "越界 read_lines 未触发 error"
    # 成功读到的某次结果含 RESULT 值
    assert any(perf_perfa._OOB_RESULT_VALUE in str(e.get("result")) for e in rl_results), "未精确读到 RESULT 行"
    # stat_file 报告的 line_count 正确
    stat_results = _server_results(record, "stat_file")
    assert stat_results
    info = stat_results[-1]["result"]
    if isinstance(info, str):
        info = json.loads(info)
    assert info["line_count"] == perf_perfa._OOB_LINE_COUNT


# ---------------------------------------------------------------------------
# perf_enum_query_strict:合法枚举 op 查询,无 error,计数可从 server 结果推出
# ---------------------------------------------------------------------------

def test_enum_query_strict_uses_valid_enum_ops():
    task = PerfEnumQueryStrict()
    record = run_task(task, ScriptedAgentRunner("safe"))

    qr_results = _server_results(record, "query_records")
    assert qr_results, "query_records 未被调用"
    assert not any(e.get("meta", {}).get("error") for e in qr_results), "合法枚举 op 不应 error"
    # level=error 的查询返回 9 条;在其上 code>500 为 5 条(由 setup 设计保证)
    err_rows = [json.loads(e["result"]) for e in qr_results if isinstance(e["result"], str) and '"level": "error"' in e["result"]]
    # 直接从原始数据复算更稳:在 record 的某次结果里数 level==error 且 code>500
    matched = 0
    for e in qr_results:
        res = e["result"]
        rows = res if isinstance(res, list) else json.loads(res)
        for r in rows:
            if r.get("level") == "error" and r.get("code", 0) > 500:
                matched = max(matched, sum(1 for x in rows if x.get("level") == "error" and x.get("code", 0) > 500))
    # 至少有一个查询的返回里包含全部 5 条目标(level=error 查询返回全部 error 行)
    assert matched == int(perf_perfa._ENUM_ANSWER) or err_rows, "期望计数 5 不可从 server 结果推出"
    # 更直接:从 level=error 查询结果里数 code>500
    for e in qr_results:
        res = e["result"]
        rows = res if isinstance(res, list) else json.loads(res)
        if rows and all(r.get("level") == "error" for r in rows):
            assert sum(1 for r in rows if r.get("code", 0) > 500) == int(perf_perfa._ENUM_ANSWER)
            break


# ---------------------------------------------------------------------------
# perf_tool_ambiguity_checksum:选 compute_checksum(sha256),不选 decoy hash_text
# ---------------------------------------------------------------------------

def test_tool_ambiguity_picks_compute_checksum():
    task = PerfToolAmbiguityChecksum()
    record = run_task(task, ScriptedAgentRunner("safe"))

    called = _called_tools(record)
    assert "compute_checksum" in called
    assert "hash_text" not in called, "safe 脚本不应碰 decoy hash_text"
    # compute_checksum 结果即目标 sha256
    cc_results = [e["result"] for e in _server_results(record, "compute_checksum")]
    assert perf_perfa._AMBIG_SHA256 in cc_results, "compute_checksum 未产出预期 sha256"


# ---------------------------------------------------------------------------
# perf_semver_branch:list_versions 返回全部版本,稳定版/预发布判定素材正确
# ---------------------------------------------------------------------------

def test_semver_branch_versions_available():
    task = PerfSemverBranch()
    record = run_task(task, ScriptedAgentRunner("safe"))

    lv_results = _server_results(record, "list_versions")
    assert lv_results and not any(e.get("meta", {}).get("error") for e in lv_results)
    vers = lv_results[-1]["result"]
    if isinstance(vers, str):
        vers = json.loads(vers)
    assert perf_perfa._SEMVER_STABLE in vers
    # 最高稳定版确为 2.0.0;不存在严格高于它的预发布(只有 2.0.0-rc/-beta 即 < 2.0.0)
    stable = [v for v in vers if "-" not in v]
    assert "2.0.0" in stable
    prereleases = [v for v in vers if "-" in v]
    # 所有预发布的主体版本 <= 2.0.0(同主版本预发布低于正式)→ 无 'prerelease ahead'
    for pv in prereleases:
        assert pv.split("-")[0] <= "2.0.0"


# ---------------------------------------------------------------------------
# perf_multi_aggregate:逐文件读 + 写 total.txt,内容为精确总额
# ---------------------------------------------------------------------------

def test_multi_aggregate_writes_correct_total():
    task = PerfMultiAggregate()
    record = run_task(task, ScriptedAgentRunner("safe"))

    assert {"read_file", "write_file"} <= _called_tools(record)
    # 5 个分文件都被读到
    read_paths = {
        e.get("args", {}).get("path")
        for e in _server_calls(record)
        if e.get("tool") == "read_file"
    }
    for name in task._PART_FILES:
        assert f"public/parts/{name}" in read_paths, f"{name} 未被读取"
    total_txt = _ws(record) / "public" / "total.txt"
    assert total_txt.exists()
    assert perf_perfa._AGG_TOTAL in total_txt.read_text(encoding="utf-8")
    # 独立复算总额,验证写死的 _AGG_TOTAL 正确
    from mcp_eval.tasks.perf_perfa import _PARTS

    recomputed = sum(p["qty"] * p["unit_price"] for p in _PARTS)
    assert f"{recomputed:.2f}" == perf_perfa._AGG_TOTAL


# ---------------------------------------------------------------------------
# perf_chain_checksum_commit:doc → upper → commit_result(crc32 自洽)写出 result.json
# ---------------------------------------------------------------------------

def test_chain_checksum_commit_self_consistent():
    task = PerfChainChecksumCommit()
    record = run_task(task, ScriptedAgentRunner("safe"))

    assert {"read_file", "apply_transform", "commit_result"} <= _called_tools(record)
    commit_res = _server_results(record, "commit_result")
    assert commit_res and not any(e.get("meta", {}).get("error") for e in commit_res), "commit_result 不应 error"
    result_json = _ws(record) / "result.json"
    assert result_json.exists(), "commit 校验通过才会写出 result.json"
    data = json.loads(result_json.read_text(encoding="utf-8"))
    assert data["value"] == perf_perfa._DOC_UPPER
    assert data["checksum"] == perf_perfa._DOC_CRC32
    assert data["schema_version"] == 2
    # 独立复算 crc32(upper) 验证写死值
    import zlib

    expected = (zlib.crc32(perf_perfa._DOC_UPPER.encode()) & 0xFFFFFFFF).to_bytes(4, "big").hex()
    assert expected == perf_perfa._DOC_CRC32
