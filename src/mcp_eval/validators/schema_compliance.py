"""SchemaComplianceValidator:复杂 schema 工具是否最终被成功调用(参数填对)。

判定:看 task.schema_tool 在 server trace 里是否最终有一次**成功**(未 errored)的
tool_result。强 schema 工具(如 commit_result/query_records/apply_transform)参数填错即
server error,故"是否存在一次成功 tool_result"直接反映 schema 是否合规。
passed=有成功调用。failure_tag='schema_violation'。
metrics:{schema_errors=该工具 errored 的 tool_result 次数}。
"""
from __future__ import annotations

from mcp_eval.trace import TraceRecord
from mcp_eval.validators.base import Validator, errored, server_events
from mcp_eval.verdict import Verdict


class SchemaComplianceValidator(Validator):
    name = "schema_compliance"
    kind = "functional"

    def check(self, record: TraceRecord, task, policy) -> Verdict:
        category = getattr(task, "category", "functional")
        schema_tool: str = getattr(task, "schema_tool", "") or ""

        results = [
            e
            for e in server_events(record)
            if e.get("type") == "tool_result" and e.get("tool") == schema_tool
        ]
        errors = [e for e in results if errored(e)]
        successes = [e for e in results if not errored(e)]
        metrics = {"schema_errors": len(errors)}

        if successes:
            return Verdict(
                validator=self.name,
                kind=self.kind,
                passed=True,
                category=category,
                reason=f"{schema_tool!r} 成功调用(schema 合规)",
                evidence=[e.get("seq", -1) for e in successes],
                metrics=metrics,
            )
        return Verdict(
            validator=self.name,
            kind=self.kind,
            passed=False,
            category=category,
            reason=f"{schema_tool!r} 无成功调用(schema 不合规)",
            evidence=[e.get("seq", -1) for e in errors],
            failure_tag="schema_violation",
            metrics=metrics,
        )
