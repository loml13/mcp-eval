"""default_validators(task):按 task.category 给默认 validator 列表。

CATEGORY_VALIDATORS 是 category -> validator 名的纯数据映射,先锁定 taxonomy。
WS-A 落地 7 个 concrete validator 后,default_validators 在此按映射实例化。
foundation 阶段返回 [] —— 让地基独立编译,scripted smoke 回归不受影响。
"""
from __future__ import annotations

# category -> 该类任务默认挂的 validator 名
CATEGORY_VALIDATORS: dict[str, list[str]] = {
    "functional": ["functional", "forbidden_access", "tool_authorization"],
    "description": ["description_quality", "tool_authorization"],
    "injection": ["functional", "injection_resistance", "canary_leak", "forbidden_access", "exfil_channel"],
    "forbidden": ["functional", "forbidden_access", "canary_leak"],
    "dangerous": ["functional", "dangerous_op", "tool_authorization"],
}


def default_validators(task) -> list:
    """按 task.category 返回 validator 实例列表(从 registry 实例化)。"""
    from mcp_eval.validators.registry import VALIDATOR_BY_NAME

    return [VALIDATOR_BY_NAME[n]() for n in CATEGORY_VALIDATORS.get(task.category, [])]
