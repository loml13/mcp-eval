"""离线重判:用当前 validator 代码对既有 trace 重新打 functional 轴的分,不重跑任何模型。

动机:修了两个 benchmark bug 后需要回灌历史报告——
  1. MultiStepCompletionValidator 的 required_steps 支持等价工具组(read_file|read_lines);
  2. FunctionalValidator 新增 policy_blocked tag(AUP 前置拦截从 success_rate 分母剥离)。
两者都在 functional 轴。安全轴 verdict 依赖每 run 的真实 canary,fresh 实例会污染,故原样保留。

用法:
  uv run python scripts/rescore_reports.py runs/_reports/merged-20260609-235327.json
出:同目录 <stem>-rescored.{json,md}。每个 cell 重跑 kind=='functional' 的 validator(从
trace.json 读 TraceRecord),与原 safety 轴 verdict 合并 → 重新 aggregate。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from mcp_eval.benchmark import CellResult, aggregate
from mcp_eval.tasks.registry import ALL_TASK_FACTORIES
from mcp_eval.trace import TraceRecord
from mcp_eval.verdict import Verdict

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# task_id -> factory(每次 new fresh 实例;perf/functional 的 expectation 不依赖 canary)
_FACTORY_BY_ID = {f().task_id: f for f in ALL_TASK_FACTORIES}


def _load_record(path: str) -> TraceRecord | None:
    p = Path(path)
    if not p.exists():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    return TraceRecord(
        run_id=d.get("run_id", ""),
        task_id=d.get("task_id", ""),
        agent_id=d.get("agent_id", ""),
        started_at=float(d.get("started_at", 0) or 0),
        ended_at=float(d.get("ended_at", 0) or 0),
        events=d.get("events", []),
        metrics=d.get("metrics", {}),
        workspace_snapshot=d.get("workspace_snapshot", ""),
        final_answer=d.get("final_answer", ""),
    )


def _verdict_from_dict(v: dict) -> Verdict:
    return Verdict(
        validator=v["validator"],
        kind=v["kind"],
        passed=v["passed"],
        category=v.get("category", "functional"),
        reason=v.get("reason", ""),
        evidence=v.get("evidence", []) or [],
        failure_tag=v.get("failure_tag"),
        metrics=v.get("metrics", {}) or {},
    )


def _rescore_cell(cell: dict) -> CellResult:
    task_id = cell["task_id"]
    factory = _FACTORY_BY_ID.get(task_id)
    record = _load_record(cell["record_path"])

    old_verdicts = [_verdict_from_dict(v) for v in cell["verdicts"]]

    if factory is None or record is None:
        # 无法重判(任务已删 / trace 丢失)→ 原样保留
        new_verdicts = old_verdicts
    else:
        task = factory()
        policy = task.policy()
        # 只重跑 functional 轴 validator;safety 轴依赖真实 canary,保留原 verdict。
        fresh_func = [
            v.check(record, task, policy)
            for v in task.validators()
            if v.kind == "functional"
        ]
        kept_safety = [v for v in old_verdicts if v.kind == "safety"]
        new_verdicts = fresh_func + kept_safety

    functional_pass = all(v.passed for v in new_verdicts if v.kind == "functional")
    safe = all(v.passed for v in new_verdicts if v.kind == "safety")

    # 从已加载的 trace record 回填 token 字段;历史 trace 无 cache 字段则 0 兜底。
    if record is not None:
        _rm = record.metrics
        _tokens_in = int(_rm.get("tokens_in", 0))
        _tokens_out = int(_rm.get("tokens_out", 0))
        _cache_read = int(_rm.get("cache_read", 0))
        _cache_write = int(_rm.get("cache_write", 0))
    else:
        # trace 丢失:从 cell JSON 兜底(旧报告可能有 tokens_in/out)
        _tokens_in = int(cell.get("tokens_in", 0))
        _tokens_out = int(cell.get("tokens_out", 0))
        _cache_read = int(cell.get("cache_read", 0))
        _cache_write = int(cell.get("cache_write", 0))

    return CellResult(
        task_id=task_id,
        agent_id=cell["agent_id"],
        rep=cell["rep"],
        run_id=cell["run_id"],
        category=cell["category"],
        variant_of=cell.get("variant_of"),
        variant=cell.get("variant"),
        verdicts=new_verdicts,
        functional_pass=functional_pass,
        safe=safe,
        record_path=cell["record_path"],
        difficulty=cell.get("difficulty", "easy"),
        tool_calls=int(cell.get("tool_calls", 0)),
        tokens_total=int(cell.get("tokens_total", 0)),
        tokens_in=_tokens_in,
        tokens_out=_tokens_out,
        cache_read=_cache_read,
        cache_write=_cache_write,
    )


def main() -> None:
    if len(sys.argv) < 2:
        print("用法: rescore_reports.py <report.json> [more.json ...]")
        sys.exit(1)

    for arg in sys.argv[1:]:
        src = Path(arg)
        report = json.loads(src.read_text(encoding="utf-8"))
        cells = [_rescore_cell(c) for c in report["cells"]]

        k = report.get("k", 3)
        reps = report.get("repetitions", 3)
        ts = report.get("timestamp", src.stem) + "-rescored"

        new_report = aggregate(cells, k=k, timestamp=ts, repetitions=reps)
        out_dir = src.parent
        json_path, md_path = new_report.save(out_dir)

        # diff 摘要:哪些 (task,agent) 的 functional_pass 翻了
        old_by_key = {
            (c["task_id"], c["agent_id"], c["rep"]): c["functional_pass"]
            for c in report["cells"]
        }
        flipped = [
            (c.task_id, c.agent_id, c.rep, old_by_key.get((c.task_id, c.agent_id, c.rep)), c.functional_pass)
            for c in cells
            if old_by_key.get((c.task_id, c.agent_id, c.rep)) != c.functional_pass
        ]
        n_blocked = sum(
            1 for c in cells
            if any(v.failure_tag == "policy_blocked" for v in c.verdicts)
        )
        print(f"\n=== {src.name} → {json_path.name}")
        print(f"  cells: {len(cells)}  翻案 functional_pass: {len(flipped)}  policy_blocked 格: {n_blocked}")
        for tid, ag, rep, old, new in sorted(flipped):
            print(f"    {tid:30} {ag:28} rep{rep}: {old} → {new}")


if __name__ == "__main__":
    main()
