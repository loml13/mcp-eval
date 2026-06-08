"""Task 抽象基类:保留 B 的精确契约(task_id/prompt/setup_workspace/scripts/canary),
叠加 C1 声明式层(category/policy/expectation/validators/variant/server_extra_env)。

BenchmarkRunner 接收 zero-arg 工厂 Callable[[], Task];每个 rep new 一个 Task,确保每次
fresh canary + 干净 workspace(run_task 内部已每 run 建新 workspace,唯一陷阱是复用 Task 实例)。
"""
from __future__ import annotations

import secrets
from abc import ABC, abstractmethod
from pathlib import Path

from mcp_eval.policy import Policy
from mcp_eval.verdict import Expectation

CATEGORIES = ("functional", "description", "injection", "forbidden", "dangerous")


class Task(ABC):
    task_id: str  # 唯一 -> TraceRecord.task_id + 矩阵 key
    category: str  # CATEGORIES 之一;驱动默认 validators + taxonomy
    prompt: str  # 交给 ClaudeCodeRunner(claude -p)
    canary: str = ""  # '' = 无秘密;canary 任务在 __init__ 里设
    variant_of: str | None = None  # description A/B 配对 key
    variant: str | None = None  # 'clear' | 'degraded'

    @abstractmethod
    def setup_workspace(self, ws: Path) -> None:
        """与 run_task 调用的契约一致:在 ws 下铺初始状态。"""
        ...

    @abstractmethod
    def policy(self) -> Policy:
        ...

    def expectation(self) -> Expectation:
        return Expectation()

    def validators(self) -> list:
        from mcp_eval.validators import default_validators

        return default_validators(self)

    def server_extra_env(self) -> dict[str, str]:
        """description A/B hook:返回注入 mock server 的额外 env(如 MCP_EVAL_DESC_VARIANT)。"""
        return {}

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        return {}

    @staticmethod
    def _new_canary() -> str:
        return "CANARY_" + secrets.token_hex(8)
