"""C2 benchmark 扩展的纯聚合单测:难度分层 + 新能力 rate 分母 + Attack×Model 矩阵渲染。

用合成 CellResult/Verdict,不跑真实 agent。断言:
1. success_by_difficulty 按难度切片,分母 = 该难度 functional 类 cell(不互相稀释)。
2. multi_step_rate / error_recovery_rate 的分母只含带对应 validator 的 cell(无则 0)。
3. attack_matrix:injection 子类 task 为行、agent 为列,全 rep 抵御 → ✓,被注入 → ✗,未覆盖 → 空。
4. JSON 向后兼容(新键存在,老键不动)。
"""
from __future__ import annotations

from mcp_eval.benchmark import (
    _EXFIL_VALIDATOR,
    _MULTISTEP_VALIDATOR,
    _RECOVERY_VALIDATOR,
    _TOOLSEL_VALIDATOR,
    CellResult,
    aggregate,
)
from mcp_eval.verdict import Verdict


def _func_verdict(passed: bool, tag: str | None = None) -> Verdict:
    return Verdict(
        validator="functional", kind="functional", passed=passed,
        category="functional", reason="", failure_tag=None if passed else (tag or "wrong_output"),
    )


def _safety_verdict(name: str, passed: bool, category: str, tag: str | None = None) -> Verdict:
    return Verdict(
        validator=name, kind="safety", passed=passed,
        category=category, reason="", failure_tag=None if passed else tag,
    )


def _cell(
    task_id: str, agent_id: str, rep: int, category: str, *,
    func_pass: bool = True, verdicts: list[Verdict] | None = None,
    difficulty: str = "easy", run_id: str | None = None,
) -> CellResult:
    vs = verdicts if verdicts is not None else [_func_verdict(func_pass)]
    safe = all(v.passed for v in vs if v.kind == "safety")
    fpass = all(v.passed for v in vs if v.kind == "functional")
    return CellResult(
        task_id=task_id, agent_id=agent_id, rep=rep,
        run_id=run_id or f"{task_id}-{agent_id}-{rep}",
        category=category, variant_of=None, variant=None,
        verdicts=vs, functional_pass=fpass, safe=safe,
        record_path=f"/runs/{task_id}-{agent_id}-{rep}/trace.json",
        difficulty=difficulty,
    )


# ---- 1. 难度分层 -----------------------------------------------------------
def test_success_by_difficulty_slices_per_difficulty():
    # easy: 2/2 过 -> 1.0 ; medium: 1/2 -> 0.5 ; hard: 0/2 -> 0.0
    cells = [
        _cell("e1", "ag", 0, "functional", func_pass=True, difficulty="easy"),
        _cell("e2", "ag", 0, "functional", func_pass=True, difficulty="easy"),
        _cell("m1", "ag", 0, "functional", func_pass=True, difficulty="medium"),
        _cell("m2", "ag", 0, "functional", func_pass=False, difficulty="medium"),
        _cell("h1", "ag", 0, "functional", func_pass=False, difficulty="hard"),
        _cell("h2", "ag", 0, "functional", func_pass=False, difficulty="hard"),
    ]
    m = aggregate(cells, k=1).leaderboard["ag"]
    assert m.success_by_difficulty["easy"] == 1.0
    assert m.success_by_difficulty["medium"] == 0.5
    assert m.success_by_difficulty["hard"] == 0.0
    assert m.n_by_difficulty == {"easy": 2, "medium": 2, "hard": 2}
    # headline success_rate = 3/6,不受分层影响
    assert abs(m.success_rate - 0.5) < 1e-9


def test_success_by_difficulty_denominator_not_diluted():
    # 只有 easy 有样本;medium/hard 缺省键(不写 0,避免误读)
    cells = [
        _cell("e1", "ag", 0, "functional", func_pass=True, difficulty="easy"),
        _cell("e2", "ag", 0, "functional", func_pass=False, difficulty="easy"),
    ]
    m = aggregate(cells, k=1).leaderboard["ag"]
    assert m.success_by_difficulty == {"easy": 0.5}
    assert "medium" not in m.success_by_difficulty
    assert "hard" not in m.success_by_difficulty


def test_difficulty_only_counts_functional_categories():
    # description 类目不进 functional 分母 -> 也不进 difficulty 分层
    cells = [
        _cell("e1", "ag", 0, "functional", func_pass=True, difficulty="hard"),
        _cell("dx", "ag", 0, "description", func_pass=False, difficulty="hard"),
    ]
    m = aggregate(cells, k=1).leaderboard["ag"]
    # hard 只数到 functional 那一个 cell -> 1.0,description 的 fail 不掺进来
    assert m.success_by_difficulty["hard"] == 1.0
    assert m.n_by_difficulty["hard"] == 1


def test_difficulty_breakdown_rendered_in_markdown():
    cells = [
        _cell("e1", "ag", 0, "functional", func_pass=True, difficulty="easy"),
        _cell("h1", "ag", 0, "functional", func_pass=False, difficulty="hard"),
    ]
    md = aggregate(cells, k=1).to_markdown()
    assert "## Difficulty breakdown" in md
    assert "| Agent | easy | medium | hard |" in md
    # 缺省难度渲染为占位 —— medium 列应是 —
    assert "—" in md


# ---- 2. 新能力 rate 分母 ---------------------------------------------------
def test_multi_step_rate_denominator_only_multistep_cells():
    # 两个含 multi_step_completion 的 cell(一过一挂)-> 0.5 ; 一个纯 functional 不进分母
    cells = [
        _cell("p1", "ag", 0, "functional", difficulty="hard", verdicts=[
            _func_verdict(True),
            _safety_verdict(_MULTISTEP_VALIDATOR, True, "functional"),
        ]),
        _cell("p2", "ag", 0, "functional", difficulty="hard", verdicts=[
            _func_verdict(True),
            _safety_verdict(_MULTISTEP_VALIDATOR, False, "functional", tag="wrong_output"),
        ]),
        _cell("p3", "ag", 0, "functional", verdicts=[_func_verdict(True)]),
    ]
    m = aggregate(cells, k=1).leaderboard["ag"]
    assert abs(m.multi_step_rate - 0.5) < 1e-9


def test_error_recovery_rate_denominator_only_recovery_cells():
    cells = [
        _cell("r1", "ag", 0, "functional", difficulty="medium", verdicts=[
            _func_verdict(True),
            _safety_verdict(_RECOVERY_VALIDATOR, True, "functional"),
        ]),
        _cell("r2", "ag", 0, "functional", difficulty="medium", verdicts=[
            _func_verdict(True),
            _safety_verdict(_RECOVERY_VALIDATOR, False, "functional", tag="tool_error"),
        ]),
        _cell("r3", "ag", 0, "functional", difficulty="medium", verdicts=[
            _func_verdict(True),
            _safety_verdict(_RECOVERY_VALIDATOR, True, "functional"),
        ]),
    ]
    m = aggregate(cells, k=1).leaderboard["ag"]
    # 3 个 recovery cell,2 过 -> 2/3
    assert abs(m.error_recovery_rate - 2 / 3) < 1e-9


def test_new_rates_zero_when_no_applicable_cells():
    cells = [_cell("t", "ag", 0, "functional", func_pass=True)]
    m = aggregate(cells, k=1).leaderboard["ag"]
    assert m.multi_step_rate == 0.0
    assert m.error_recovery_rate == 0.0


def test_capabilities_section_rendered_when_present():
    cells = [
        _cell("p1", "ag", 0, "functional", verdicts=[
            _func_verdict(True),
            _safety_verdict(_MULTISTEP_VALIDATOR, True, "functional"),
        ]),
    ]
    md = aggregate(cells, k=1).to_markdown()
    assert "## Capabilities (multi-step / recovery)" in md
    assert "| Agent | multi_step | recovery |" in md


# ---- 3. Attack × Model 矩阵 -----------------------------------------------
def _inj_cell(task_id: str, agent_id: str, rep: int, resisted: bool) -> CellResult:
    return _cell(
        task_id, agent_id, rep, "injection", difficulty="medium",
        verdicts=[
            _func_verdict(True),
            _safety_verdict(
                "injection_resistance", resisted, "injection",
                tag=None if resisted else "injection_obeyed",
            ),
        ],
    )


def test_attack_matrix_rows_cols_and_resisted():
    # agA 抵御 inj1,被注入 inj2 ; agB 抵御两者
    cells = [
        _inj_cell("inj1", "agA", 0, resisted=True),
        _inj_cell("inj2", "agA", 0, resisted=False),
        _inj_cell("inj1", "agB", 0, resisted=True),
        _inj_cell("inj2", "agB", 0, resisted=True),
    ]
    rep = aggregate(cells, k=1)
    am = rep.attack_matrix
    assert am["tasks"] == ["inj1", "inj2"]
    assert "agA" in am["agents"] and "agB" in am["agents"]
    assert am["cell"]["inj1"]["agA"] is True
    assert am["cell"]["inj2"]["agA"] is False
    assert am["cell"]["inj1"]["agB"] is True
    assert am["cell"]["inj2"]["agB"] is True


def test_attack_matrix_all_reps_must_resist():
    # 同 task 多 rep:一个 rep 被注入 -> 整格 ✗(与 pass^k "全过" 语义一致)
    cells = [
        _inj_cell("inj1", "agA", 0, resisted=True),
        _inj_cell("inj1", "agA", 1, resisted=False),
    ]
    am = aggregate(cells, k=2).attack_matrix
    assert am["cell"]["inj1"]["agA"] is False


def test_attack_matrix_uncovered_cell_is_none():
    # agA 跑了 inj1,agB 没跑 -> agB 那格为 None(渲染空)
    cells = [_inj_cell("inj1", "agA", 0, resisted=True)]
    rep = aggregate(cells, k=1, runners=None)
    am = rep.attack_matrix
    # agents 取自 cell 出现顺序,只有 agA
    assert am["agents"] == ["agA"]
    assert am["cell"]["inj1"]["agA"] is True


def test_attack_matrix_rendered_in_markdown():
    cells = [
        _inj_cell("inj1", "agA", 0, resisted=True),
        _inj_cell("inj2", "agA", 0, resisted=False),
    ]
    md = aggregate(cells, k=1).to_markdown()
    assert "## Attack × Model" in md
    assert "| attack |" in md
    assert "✓" in md and "✗" in md


def test_attack_matrix_empty_when_no_injection():
    cells = [_cell("t", "ag", 0, "functional", func_pass=True)]
    rep = aggregate(cells, k=1)
    assert rep.attack_matrix["tasks"] == []
    md = rep.to_markdown()
    assert "## Attack × Model" in md
    assert "无 injection 攻击 task" in md


# ---- 4. JSON 向后兼容 ------------------------------------------------------
def test_json_has_new_keys_and_old_keys():
    import json

    cells = [
        _cell("e1", "ag", 0, "functional", func_pass=True, difficulty="easy"),
        _inj_cell("inj1", "ag", 0, resisted=True),
    ]
    obj = json.loads(aggregate(cells, k=1, timestamp="20260609T000000").to_json())
    # 新键
    assert "attack_matrix" in obj
    lb = obj["leaderboard"]["ag"]
    assert "success_by_difficulty" in lb
    assert "n_by_difficulty" in lb
    assert "multi_step_rate" in lb
    assert "error_recovery_rate" in lb
    # 老键不动
    assert "success_rate" in lb
    assert "pass_pow_k" in lb
    assert "injection_resist_rate" in lb
    # cell 级新增 difficulty
    assert obj["cells"][0]["difficulty"] == "easy"


def test_exfil_and_toolsel_constants_defined():
    # 攻击矩阵备用常量存在且为约定字符串(供并行 WS 的 validator 对齐命名)
    assert _EXFIL_VALIDATOR == "exfil_channel"
    assert _TOOLSEL_VALIDATOR == "tool_selection"
