"""merge_reports 的污染剔除口径单测。"""
from __future__ import annotations

import json
import importlib.util
from pathlib import Path

from mcp_eval.verdict import Verdict

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "merge_reports.py"
_SPEC = importlib.util.spec_from_file_location("merge_reports", _SCRIPT)
assert _SPEC and _SPEC.loader
_MERGE_REPORTS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MERGE_REPORTS)
_select_cells = _MERGE_REPORTS._select_cells


def _trace(path: Path, text: str) -> str:
    path.write_text(
        json.dumps({"events": [{"result": text}]}, ensure_ascii=False),
        encoding="utf-8",
    )
    return str(path)


def _cell(task_id: str, agent_id: str, rep: int, *, record_path: str = "") -> dict:
    verdict = Verdict(
        validator="functional",
        kind="functional",
        passed=True,
        category="functional",
        reason="",
    ).to_dict()
    return {
        "task_id": task_id,
        "agent_id": agent_id,
        "rep": rep,
        "run_id": f"{agent_id}-{task_id}-{rep}-{Path(record_path).name}",
        "category": "functional",
        "variant_of": None,
        "variant": None,
        "verdicts": [verdict],
        "functional_pass": True,
        "safe": True,
        "record_path": record_path,
        "difficulty": "easy",
        "tool_calls": 1,
        "tokens_total": 0,
    }


def test_contaminated_winner_group_is_dropped_instead_of_partial_pass(tmp_path):
    base = [_cell("task", "agent", rep) for rep in range(3)]
    contaminated = _trace(tmp_path / "bad_trace.json", "You've hit your session limit")
    rerun = [
        _cell("task", "agent", 0),
        _cell("task", "agent", 1, record_path=contaminated),
        _cell("task", "agent", 2),
    ]

    cells, stats = _select_cells([("base.json", base), ("rerun.json", rerun)])

    assert cells == []
    assert stats["superseded"] == 3
    assert stats["dropped_contaminated_cells"] == 1
    assert stats["dropped_incomplete_groups"] == 1


def test_clean_winner_group_replaces_baseline(tmp_path):
    base = [_cell("task", "agent", rep) for rep in range(3)]
    clean_trace = _trace(tmp_path / "clean_trace.json", "all good")
    rerun = [_cell("task", "agent", rep, record_path=clean_trace) for rep in range(3)]

    cells, stats = _select_cells([("base.json", base), ("rerun.json", rerun)])

    assert [c.rep for c in cells] == [0, 1, 2]
    assert stats["superseded"] == 3
    assert stats["dropped_contaminated_cells"] == 0
    assert stats["dropped_incomplete_groups"] == 0
