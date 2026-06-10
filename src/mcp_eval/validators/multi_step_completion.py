"""MultiStepCompletionValidator:多跳编排任务是否"按序走完链路且终态正确"。

判定两层(都满足才 passed):
1. 链路:task.required_steps 的有序 (tool, arg_substr) 逐步在 server_calls 里匹配 ——
   每步需存在一个**未 errored** 的对应 tool 调用,其 args 的 json 含 arg_substr,且
   匹配 seq 单调递增(后一步只能在前一步匹配 seq 之后找)。
2. 终态:复用 FunctionalValidator 的 expectation 判定(answer/file/called)。

failure_tag:
- 'incomplete_chain':某步找不到(缺步);
- 'wrong_order':步骤都在但顺序错乱(单调匹配失败);
- 'wrong_output':链路齐全有序但终态不符。
metrics:{steps_done, steps_total}。
"""
from __future__ import annotations

import json

from mcp_eval.trace import TraceRecord
from mcp_eval.validators.base import (
    Validator,
    errored,
    evidence_of,
    server_calls,
)
from mcp_eval.validators.functional import evaluate_expectation
from mcp_eval.verdict import Verdict


def _args_blob(e: dict) -> str:
    """事件 args 的 json 串(子串匹配载体)。"""
    return json.dumps(e.get("args") or {}, ensure_ascii=False)


def _match_steps(record: TraceRecord, steps: tuple) -> tuple[int, bool, list[int]]:
    """按 seq 单调匹配有序步骤。

    返回 (matched_count, order_ok, matched_seqs)。order_ok 仅在所有步骤匹配成功时有意义:
    若某步在"上一步匹配位置之后"找不到,但放宽顺序后(从头扫)能找到 → order_ok=False。
    """
    calls = sorted(server_calls(record), key=lambda e: e.get("seq", -1))
    matched_seqs: list[int] = []
    cursor = -1  # 上一匹配步的 seq;后续步只能在更大 seq 找
    matched = 0
    out_of_order = False

    for tool, arg_substr in steps:
        # tool 允许 str 或多个等价工具名的 tuple/list(命中任一即匹配)——
        # 路径等价的工具(如 read_file vs read_lines 读同一文件)不应被硬编码冤判。
        tools = (tool,) if isinstance(tool, str) else tuple(tool)
        hit_seq = None
        # 先按单调(cursor 之后)找
        for e in calls:
            if e.get("seq", -1) <= cursor:
                continue
            if e.get("tool") in tools and not errored(e) and arg_substr in _args_blob(e):
                hit_seq = e.get("seq", -1)
                break
        if hit_seq is None:
            # 放宽顺序:全局是否存在该步(用于区分 incomplete vs wrong_order)
            exists_anywhere = any(
                e.get("tool") in tools
                and not errored(e)
                and arg_substr in _args_blob(e)
                for e in calls
            )
            if exists_anywhere:
                out_of_order = True
            break
        matched += 1
        matched_seqs.append(hit_seq)
        cursor = hit_seq

    order_ok = not out_of_order
    return matched, order_ok, matched_seqs


class MultiStepCompletionValidator(Validator):
    name = "multi_step_completion"
    kind = "functional"

    def check(self, record: TraceRecord, task, policy) -> Verdict:
        category = getattr(task, "category", "functional")
        steps: tuple = getattr(task, "required_steps", ()) or ()
        total = len(steps)

        matched, order_ok, matched_seqs = _match_steps(record, steps)
        metrics = {"steps_done": matched, "steps_total": total}

        chain_complete = matched == total
        if not chain_complete:
            tag = "wrong_order" if not order_ok else "incomplete_chain"
            reason = (
                f"步骤乱序({matched}/{total})"
                if tag == "wrong_order"
                else f"链路缺步({matched}/{total})"
            )
            return Verdict(
                validator=self.name,
                kind=self.kind,
                passed=False,
                category=category,
                reason=reason,
                evidence=matched_seqs,
                failure_tag=tag,
                metrics=metrics,
            )

        # 链路齐全有序 → 叠加终态判定
        passed, fails = evaluate_expectation(record, task)
        if passed:
            return Verdict(
                validator=self.name,
                kind=self.kind,
                passed=True,
                category=category,
                reason=f"链路完成({matched}/{total})且终态正确",
                evidence=matched_seqs,
                metrics=metrics,
            )
        return Verdict(
            validator=self.name,
            kind=self.kind,
            passed=False,
            category=category,
            reason="链路完成但终态错:" + "; ".join(fails),
            evidence=matched_seqs,
            failure_tag="wrong_output",
            metrics=metrics,
        )
