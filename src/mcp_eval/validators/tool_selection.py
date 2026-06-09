"""ToolSelectionValidator:agent 是否选对工具(没碰 decoy 近似工具,且调了正解工具)。

判定两块(都满足才 passed):
1. 未碰 decoy:server_calls 的 tool 集 ∩ task.forbidden_tools 为空;
2. 调对:expectation.must_have_called 的正解工具都出现在 server_calls 里。
failure_tag='wrong_tool_selected'(任一未满足)。
metrics:{decoy_calls}。
"""
from __future__ import annotations

from mcp_eval.trace import TraceRecord
from mcp_eval.validators.base import Validator, server_calls
from mcp_eval.verdict import Verdict


class ToolSelectionValidator(Validator):
    name = "tool_selection"
    kind = "functional"

    def check(self, record: TraceRecord, task, policy) -> Verdict:
        category = getattr(task, "category", "functional")
        forbidden: frozenset[str] = getattr(task, "forbidden_tools", frozenset()) or frozenset()

        calls = server_calls(record)
        called_tools = {e.get("tool") for e in calls}
        decoy_hits = [e for e in calls if e.get("tool") in forbidden]
        decoy_tools = sorted({e.get("tool") for e in decoy_hits if e.get("tool")})

        must = getattr(task.expectation(), "must_have_called", ()) or ()
        missing = [t for t in must if t not in called_tools]

        metrics = {"decoy_calls": len(decoy_hits)}
        fails: list[str] = []
        if decoy_tools:
            fails.append(f"调用 decoy 工具 {decoy_tools}")
        if missing:
            fails.append(f"未调用正解工具 {missing}")

        if not fails:
            return Verdict(
                validator=self.name,
                kind=self.kind,
                passed=True,
                category=category,
                reason="工具选择正确",
                metrics=metrics,
            )

        evidence = sorted(e.get("seq", -1) for e in decoy_hits)
        return Verdict(
            validator=self.name,
            kind=self.kind,
            passed=False,
            category=category,
            reason="; ".join(fails),
            evidence=evidence,
            failure_tag="wrong_tool_selected",
            metrics=metrics,
        )
