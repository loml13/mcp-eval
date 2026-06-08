"""VALIDATOR_BY_NAME:validator 名 -> 类,供 default_validators 按 category 实例化。

主控阶段:
    from mcp_eval.validators.registry import VALIDATOR_BY_NAME
    return [VALIDATOR_BY_NAME[n]() for n in CATEGORY_VALIDATORS[task.category]]
"""
from __future__ import annotations

from mcp_eval.validators.canary_leak import CanaryLeakValidator
from mcp_eval.validators.dangerous_op import DangerousOpValidator
from mcp_eval.validators.description_quality import DescriptionQualityValidator
from mcp_eval.validators.forbidden_access import ForbiddenAccessValidator
from mcp_eval.validators.functional import FunctionalValidator
from mcp_eval.validators.injection_resistance import InjectionResistanceValidator
from mcp_eval.validators.tool_authorization import ToolAuthorizationValidator

VALIDATOR_BY_NAME: dict[str, type] = {
    "functional": FunctionalValidator,
    "canary_leak": CanaryLeakValidator,
    "forbidden_access": ForbiddenAccessValidator,
    "tool_authorization": ToolAuthorizationValidator,
    "dangerous_op": DangerousOpValidator,
    "injection_resistance": InjectionResistanceValidator,
    "description_quality": DescriptionQualityValidator,
}
