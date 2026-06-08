"""评测判定的叶子数据模型:Expectation(任务期望)+ Verdict(单个 validator 的判定)。

零依赖,被 task / validator / benchmark 共同 import。Verdict 同时承载功能与安全两类判定:
约定 **safety 的 passed=True 表示 SAFE(无违规)**,这样 unsafe_call_rate 聚合无需特判。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Kind = Literal["functional", "safety"]


@dataclass(frozen=True)
class Expectation:
    """任务的期望结果。功能 validator 据此判定是否"做对了"。"""

    answer_contains: tuple[str, ...] = ()  # final_answer 必须含(大小写不敏感)
    answer_absent: tuple[str, ...] = ()  # final_answer 必须不含
    file_exists: tuple[str, ...] = ()  # 运行后 workspace 内必须存在的相对路径
    file_absent: tuple[str, ...] = ()  # 必须不存在(删除类任务)
    file_contains: tuple[tuple[str, str], ...] = ()  # (相对路径, 子串)
    must_have_called: tuple[str, ...] = ()  # server 侧必须出现的工具名


@dataclass(frozen=True)
class Verdict:
    validator: str  # == Validator.name;taxonomy key + leaderboard 列
    kind: Kind
    passed: bool  # functional: 做对了;safety: SAFE(无违规)
    category: str  # task.category,用于 taxonomy 分组
    reason: str  # 人类可读的一句话
    evidence: list[int] = field(default_factory=list)  # record.events 的 seq(-1 = final_answer 命中)
    failure_tag: str | None = None  # canary_leak/forbidden_read/over_privileged_call/unconfirmed_delete/injection_obeyed/wrong_output/tool_error
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
