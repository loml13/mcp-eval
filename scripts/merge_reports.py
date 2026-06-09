"""把多份 benchmark report JSON 合并成一张统一 leaderboard。

用途:增量加被测模型时不必重跑已测模型 —— 各模型(或各批)单独跑出 report(配
`run_benchmark.py --no-scripted` 出纯单模型 report),再 merge 成 N 模型大矩阵。
按 `run_id` 去重(每次 run 全局唯一),重建 cells 后走 benchmark 的同一套 `aggregate`,
所以 leaderboard / 难度分层 / Attack×Model / failure taxonomy 与原生跑出来口径完全一致。

用法:
  uv run python scripts/merge_reports.py runs/_reports/A.json runs/_reports/B.json [...]
  # 输出 runs/_reports/merged-<ts>.{json,md}
"""
from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path

from mcp_eval.benchmark import CellResult, aggregate
from mcp_eval.verdict import Verdict

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _verdict_from_dict(d: dict) -> Verdict:
    return Verdict(
        validator=d["validator"],
        kind=d["kind"],
        passed=d["passed"],
        category=d["category"],
        reason=d.get("reason", ""),
        evidence=list(d.get("evidence", [])),
        failure_tag=d.get("failure_tag"),
        metrics=dict(d.get("metrics", {})),
    )


def _cell_from_dict(d: dict) -> CellResult:
    return CellResult(
        task_id=d["task_id"],
        agent_id=d["agent_id"],
        rep=d["rep"],
        run_id=d["run_id"],
        category=d["category"],
        variant_of=d.get("variant_of"),
        variant=d.get("variant"),
        verdicts=[_verdict_from_dict(v) for v in d.get("verdicts", [])],
        functional_pass=d["functional_pass"],
        safe=d["safe"],
        record_path=d.get("record_path", ""),
        difficulty=d.get("difficulty", "easy"),
        # 效率信号 + 安全判定都依赖这两个字段:_cell_safe 要求 tool_calls>0(无 server 活动
        # 算未抵御),漏掉 → safety_pass^k 与 Efficiency 两节全归零。
        tool_calls=d.get("tool_calls", 0),
        tokens_total=d.get("tokens_total", 0),
    )


_LIMIT_MARKERS = ("session limit", "hit your")


def _is_contaminated(cd: dict) -> bool:
    """配额限流污染:cell 的 trace 里出现 `You've hit your session limit` 这类提示 ——
    被测 agent 撞 Max 池上限,`claude -p` 把限流文案当答案返回,该 cell 非真实表现,丢弃。
    补跑的干净 cell(新 run_id)会自然顶上。仅 Claude 系可能命中,其余读不到也无妨。"""
    rp = cd.get("record_path", "")
    if not rp or not Path(rp).exists():
        return False
    try:
        rec = json.loads(Path(rp).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    blob = " ".join(str(e.get("result", "")) for e in rec.get("events", [])).lower()
    return any(m in blob for m in _LIMIT_MARKERS)


def _infer_k(cells: list[CellResult]) -> int:
    """k = 任一 (agent, task) 的最大重复次数(pass^k 的 k)。"""
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for c in cells:
        counts[(c.agent_id, c.task_id)] += 1
    return max(counts.values(), default=1)


def _select_cells(loaded: list[tuple[str, list[dict]]]) -> tuple[list[CellResult], dict[str, int]]:
    """选择最终参与聚合的 cell。

    per-(agent, task) 后来者覆盖:补跑报告(靠后传入)整体替换基线里的同一格。
    若 winner 格自身含配额污染,丢弃整格而不是只丢污染 rep,避免剩余 2/3 被当作
    pass^k 完整通过。
    """
    winner: dict[tuple[str, str], int] = {}
    for idx, (_p, cds) in enumerate(loaded):
        for cd in cds:
            winner[(cd["agent_id"], cd["task_id"])] = idx

    by_winning_group: dict[tuple[int, str, str], list[dict]] = defaultdict(list)
    superseded = 0
    for idx, (_p, cds) in enumerate(loaded):
        for cd in cds:
            key = (cd["agent_id"], cd["task_id"])
            if winner[key] != idx:
                superseded += 1
                continue
            by_winning_group[(idx, cd["agent_id"], cd["task_id"])].append(cd)

    cells: list[CellResult] = []
    seen: set[str] = set()
    dropped_contaminated_cells = 0
    dropped_incomplete_groups = 0
    for (_idx, _agent, _task), group in by_winning_group.items():
        clean_group: list[dict] = []
        group_seen: set[str] = set()
        group_has_contamination = False
        for cd in group:
            rid = cd.get("run_id")
            if rid and (rid in seen or rid in group_seen):
                continue
            if rid:
                group_seen.add(rid)
            if _is_contaminated(cd):
                group_has_contamination = True
                dropped_contaminated_cells += 1
                continue
            clean_group.append(cd)

        if group_has_contamination:
            dropped_incomplete_groups += 1
            continue

        for cd in clean_group:
            rid = cd.get("run_id")
            if rid:
                seen.add(rid)
            cells.append(_cell_from_dict(cd))

    stats = {
        "superseded": superseded,
        "dropped_contaminated_cells": dropped_contaminated_cells,
        "dropped_incomplete_groups": dropped_incomplete_groups,
    }
    return cells, stats


def main() -> None:
    paths = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not paths:
        print("用法: merge_reports.py <report1.json> <report2.json> ...")
        sys.exit(1)

    # 各报告先全部读进来。
    loaded = [(p, json.loads(Path(p).read_text(encoding="utf-8")).get("cells", []))
              for p in paths]

    cells, stats = _select_cells(loaded)
    if any(stats.values()):
        print(
            f"整格替换 {stats['superseded']} 个旧 cell(补跑覆盖),"
            f"另因污染丢弃 {stats['dropped_incomplete_groups']} 个不完整格"
            f"({stats['dropped_contaminated_cells']} 个污染 cell)"
        )

    if not cells:
        print("没有可合并的 cell")
        sys.exit(1)

    k = _infer_k(cells)
    ts = "merged-" + time.strftime("%Y%m%d-%H%M%S")
    # runners=None → agent 顺序按 cell 首次出现序(各报告依传入顺序拼接)。
    report = aggregate(cells, k=k, runners=None, timestamp=ts, repetitions=k)

    out_dir = PROJECT_ROOT / "runs" / "_reports"
    json_path, md_path = report.save(out_dir)
    print(report.to_markdown())
    print(f"\n合并 {len(paths)} 份报告 → {len(cells)} cells / {report.n_agents} agents (k={k})")
    print(f"落盘:\n  {json_path}\n  {md_path}")


if __name__ == "__main__":
    main()
