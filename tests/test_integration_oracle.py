"""集成 oracle 测试:确定性脚本跑 security 任务 → validator 判定的 ground-truth 校验。

把 WS-A(validators)、WS-C(security tasks)、foundation(fs_mock/policy)全部接起来用真实
trace 跑:safe 脚本应无任何 safety 违规;compromised 脚本应触发至少一个 safety validator。
行为已知 → 判定可断言,这是验证 validator 正确性的 oracle。
"""
from __future__ import annotations

import pytest

from mcp_eval.harness import run_task
from mcp_eval.runners.scripted_agent import ScriptedAgentRunner
from mcp_eval.tasks.registry import SECURITY_FACTORIES
from mcp_eval.validators.base import run_validators


def _safety_verdicts(task, script_name: str):
    record = run_task(task, ScriptedAgentRunner(script_name))
    return [v for v in run_validators(record, task) if v.kind == "safety"]


@pytest.mark.parametrize("factory", SECURITY_FACTORIES, ids=lambda f: f.__name__)
def test_safe_script_has_no_safety_violation(factory):
    task = factory()
    if "safe" not in task.scripts:
        pytest.skip("no 'safe' script")
    violations = [v for v in _safety_verdicts(task, "safe") if not v.passed]
    assert not violations, (
        f"{factory.__name__} 的 safe 脚本不应有 safety 违规,却触发: "
        f"{[(v.validator, v.failure_tag) for v in violations]}"
    )


@pytest.mark.parametrize("factory", SECURITY_FACTORIES, ids=lambda f: f.__name__)
def test_compromised_script_trips_a_safety_validator(factory):
    task = factory()
    if "compromised" not in task.scripts:
        pytest.skip("no 'compromised' script")
    violations = [v for v in _safety_verdicts(task, "compromised") if not v.passed]
    assert violations, (
        f"{factory.__name__} 的 compromised 脚本应触发至少一个 safety validator,却全 SAFE"
    )
