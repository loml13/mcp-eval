"""VALIDATOR_BY_NAME:validator 名 -> 类,供 default_validators 按 category 实例化。

主控阶段:
    from mcp_eval.validators.registry import VALIDATOR_BY_NAME
    return [VALIDATOR_BY_NAME[n]() for n in CATEGORY_VALIDATORS[task.category]]
"""
from __future__ import annotations

from mcp_eval.validators.canary_leak import CanaryLeakValidator
from mcp_eval.validators.dangerous_op import DangerousOpValidator
from mcp_eval.validators.description_quality import DescriptionQualityValidator
from mcp_eval.validators.error_recovery import ErrorRecoveryValidator
from mcp_eval.validators.exfil_channel import ExfilChannelValidator
from mcp_eval.validators.forbidden_access import ForbiddenAccessValidator
from mcp_eval.validators.functional import FunctionalValidator
from mcp_eval.validators.injection_resistance import InjectionResistanceValidator
from mcp_eval.validators.multi_step_completion import MultiStepCompletionValidator
from mcp_eval.validators.schema_compliance import SchemaComplianceValidator
from mcp_eval.validators.tool_authorization import ToolAuthorizationValidator
from mcp_eval.validators.tool_selection import ToolSelectionValidator

VALIDATOR_BY_NAME: dict[str, type] = {
    "functional": FunctionalValidator,
    "canary_leak": CanaryLeakValidator,
    "forbidden_access": ForbiddenAccessValidator,
    "tool_authorization": ToolAuthorizationValidator,
    "dangerous_op": DangerousOpValidator,
    "injection_resistance": InjectionResistanceValidator,
    "description_quality": DescriptionQualityValidator,
    "multi_step_completion": MultiStepCompletionValidator,
    "error_recovery": ErrorRecoveryValidator,
    "tool_selection": ToolSelectionValidator,
    "exfil_channel": ExfilChannelValidator,
    "schema_compliance": SchemaComplianceValidator,
}
