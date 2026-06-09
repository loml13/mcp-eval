"""ErrorRecoveryValidator:工具返回 error 后,agent 是否换路径/重试并最终成功。

判定:在 server tool_result 里找 meta.fault_injected==True 的事件;对每个发生故障的
工具,要求其后(更大 seq)存在同名 tool 的**成功**(未 errored)tool_result。
- 有故障且全部恢复 → passed(做对了)。
- 有故障但某工具始终未成功 → passed=False,failure_tag='gave_up_on_error'。
- 无任何注入故障 → passed=True(本任务无可恢复事件,不算失败)。
metrics:{faults_seen, recovered}。
"""
from __future__ import annotations

from mcp_eval.trace import TraceRecord
from mcp_eval.validators.base import Validator, errored, server_events
from mcp_eval.verdict import Verdict


def _tool_results(record: TraceRecord) -> list[dict]:
    return [e for e in server_events(record) if e.get("type") == "tool_result"]


class ErrorRecoveryValidator(Validator):
    name = "error_recovery"
    kind = "functional"

    def check(self, record: TraceRecord, task, policy) -> Verdict:
        category = getattr(task, "category", "functional")
        results = _tool_results(record)

        faults = [
            e for e in results if e.get("meta", {}).get("fault_injected", False)
        ]
        faults_seen = len(faults)

        if not faults:
            return Verdict(
                validator=self.name,
                kind=self.kind,
                passed=True,
                category=category,
                reason="无注入故障,无需恢复",
                metrics={"faults_seen": 0, "recovered": 0},
            )

        recovered = 0
        unrecovered: list[dict] = []
        for fe in faults:
            tool = fe.get("tool")
            fseq = fe.get("seq", -1)
            ok_after = any(
                e.get("tool") == tool
                and not errored(e)
                and e.get("seq", -1) > fseq
                for e in results
            )
            if ok_after:
                recovered += 1
            else:
                unrecovered.append(fe)

        metrics = {"faults_seen": faults_seen, "recovered": recovered}
        if not unrecovered:
            return Verdict(
                validator=self.name,
                kind=self.kind,
                passed=True,
                category=category,
                reason=f"故障后成功恢复({recovered}/{faults_seen})",
                evidence=[e.get("seq", -1) for e in faults],
                metrics=metrics,
            )
        return Verdict(
            validator=self.name,
            kind=self.kind,
            passed=False,
            category=category,
            reason=f"遇错放弃({recovered}/{faults_seen} 恢复)",
            evidence=[e.get("seq", -1) for e in unrecovered],
            failure_tag="gave_up_on_error",
            metrics=metrics,
        )
