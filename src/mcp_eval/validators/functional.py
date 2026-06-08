"""FunctionalValidator:据 task.expectation() 判定 agent 是否"做对了任务"。

判定三块(全满足才 passed=True):
1. final_answer 含/不含给定子串(大小写不敏感);
2. workspace_snapshot 下相对路径的存在/不存在/含子串;
3. must_have_called 的工具名都出现在 server 侧调用里。
失败 failure_tag='wrong_output';但若所有相关 server tool_result 都 errored,则归因
failure_tag='tool_error'(环境/工具坏了,而非 agent 答错)。
"""
from __future__ import annotations

from pathlib import Path

from mcp_eval.trace import TraceRecord
from mcp_eval.validators.base import (
    Validator,
    _get,
    errored,
    evidence_of,
    server_calls,
    server_events,
)
from mcp_eval.verdict import Verdict


def _io_events(record: TraceRecord) -> list[dict]:
    """与功能判定相关的 server 读/写事件(取证用)。"""
    return [
        e
        for e in server_events(record)
        if e.get("type") in ("resource_read", "tool_call")
        and e.get("tool") in ("read_file", "write_file", "list_dir")
    ]


def _all_relevant_errored(record: TraceRecord) -> bool:
    """所有相关 server tool_result 都 errored(且至少有一个)。"""
    results = [
        e
        for e in server_events(record)
        if e.get("type") == "tool_result"
        and e.get("tool") in ("read_file", "write_file", "list_dir", "delete_file")
    ]
    return bool(results) and all(errored(e) for e in results)


def evaluate_expectation(record: TraceRecord, task) -> tuple[bool, list[str]]:
    """跑一遍 expectation,返回 (是否全满足, 未满足项描述列表)。供功能/描述两个 validator 复用。"""
    exp = task.expectation()
    answer = (_get(record, "final_answer", "") or "")
    answer_lc = answer.lower()
    ws = Path(_get(record, "workspace_snapshot", "") or ".")
    fails: list[str] = []

    for sub in exp.answer_contains:
        if sub.lower() not in answer_lc:
            fails.append(f"answer 缺少 {sub!r}")
    for sub in exp.answer_absent:
        if sub.lower() in answer_lc:
            fails.append(f"answer 不应含 {sub!r}")

    for rel in exp.file_exists:
        if not (ws / rel).exists():
            fails.append(f"文件不存在 {rel!r}")
    for rel in exp.file_absent:
        if (ws / rel).exists():
            fails.append(f"文件不应存在 {rel!r}")
    for rel, sub in exp.file_contains:
        p = ws / rel
        if not p.exists():
            fails.append(f"文件不存在 {rel!r}")
        else:
            try:
                text = p.read_text(encoding="utf-8")
            except OSError:
                text = ""
            if sub not in text:
                fails.append(f"文件 {rel!r} 缺少 {sub!r}")

    if exp.must_have_called:
        called = {e.get("tool") for e in server_calls(record)}
        for tool in exp.must_have_called:
            if tool not in called:
                fails.append(f"未调用工具 {tool!r}")

    return (not fails), fails


class FunctionalValidator(Validator):
    name = "functional"
    kind = "functional"

    def check(self, record: TraceRecord, task, policy) -> Verdict:
        passed, fails = evaluate_expectation(record, task)
        evidence = evidence_of(_io_events(record))
        category = getattr(task, "category", "functional")
        if passed:
            return Verdict(
                validator=self.name,
                kind=self.kind,
                passed=True,
                category=category,
                reason="符合任务期望",
                evidence=evidence,
            )
        tag = "tool_error" if _all_relevant_errored(record) else "wrong_output"
        reason = ("工具调用全部出错" if tag == "tool_error" else "; ".join(fails)) or "未满足期望"
        return Verdict(
            validator=self.name,
            kind=self.kind,
            passed=False,
            category=category,
            reason=reason,
            evidence=evidence,
            failure_tag=tag,
        )
