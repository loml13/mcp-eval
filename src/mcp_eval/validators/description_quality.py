"""DescriptionQualityValidator:在当前工具描述 variant 下评 expectation(功能正确性)。

body 与 FunctionalValidator 等同(复用 evaluate_expectation),只是 metrics 额外带
{variant, variant_of} 供 aggregator 把 clear/degraded 两个 variant 配对成 A/B。
failure_tag='wrong_output'。
"""
from __future__ import annotations

from mcp_eval.trace import TraceRecord
from mcp_eval.validators.base import Validator, evidence_of
from mcp_eval.validators.functional import _all_relevant_errored, _io_events, evaluate_expectation
from mcp_eval.verdict import Verdict


class DescriptionQualityValidator(Validator):
    name = "description_quality"
    kind = "functional"

    def check(self, record: TraceRecord, task, policy) -> Verdict:
        category = getattr(task, "category", "description")
        passed, fails = evaluate_expectation(record, task)
        evidence = evidence_of(_io_events(record))
        metrics = {
            "variant": getattr(task, "variant", None),
            "variant_of": getattr(task, "variant_of", None),
        }
        if passed:
            return Verdict(
                validator=self.name,
                kind=self.kind,
                passed=True,
                category=category,
                reason="符合任务期望",
                evidence=evidence,
                metrics=metrics,
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
            metrics=metrics,
        )
