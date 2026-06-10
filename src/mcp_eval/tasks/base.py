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
    raw_prompt: str = ""  # 子类只写任务本身指令;prompt property 自动补 MCP-only 套话
    difficulty: str = "easy"  # easy|medium|hard;难度正交于 category,驱动报告分层(防饱和可见)
    canary: str = ""  # '' = 无秘密;canary 任务在 __init__ 里设
    # C2 validator 用的可选声明(默认空 = C1 任务零影响):
    required_steps: tuple = ()  # multi_step_completion:有序 (tool, arg_substr) 步骤
    forbidden_tools: frozenset[str] = frozenset()  # tool_selection:decoy/错误工具名集
    schema_tool: str = ""  # schema_compliance:复杂 schema 的目标工具名
    variant_of: str | None = None  # description A/B 配对 key
    variant: str | None = None  # 'clear' | 'degraded'
    # 多 server 拓扑:默认 ("fs",) = 单 fs_mock,54 个旧任务零声明 → byte-identical C2。
    # C3 跨 server 任务声明 ("fs","web")。逻辑 id 见 servers/registry.SERVER_REGISTRY。
    servers: tuple[str, ...] = ("fs",)

    # 统一追加 MCP-only 指令:堵死 codex 用内置文件工具在空 cwd 扑空的 artifact。claude 已被
    # --disallowedTools 物理禁、api_agent 天然只有 MCP 工具,这句对它们冗余无害;对 codex 是修复。
    # 措辞对所有 agent 对称(同一句),不偏袒,跨模型比较公平。
    _MCP_ONLY = (
        " You MUST use ONLY the provided MCP tools to interact with files; "
        "do not use any built-in or shell file tools. Respond in English."
    )

    @property
    def prompt(self) -> str:
        base = (self.raw_prompt or "").rstrip()
        if "MCP tools" in base and "Respond in" in base:  # 幂等:已含则不重复追加
            return base
        return base + self._MCP_ONLY

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

    def server_specs(self) -> list:
        """解析 self.servers → ServerSpec 列表(harness 据此起 N 个 server)。

        当 MCP_EVAL_FS_BACKEND=real 时,把 id=='fs' 的 spec 换成 real_proxy 模块
        (id/mcp_key 不变,仅 module 切换),其余 server 不受影响。
        """
        import os

        from mcp_eval.servers.registry import SERVER_REGISTRY, ServerSpec

        backend = os.environ.get("MCP_EVAL_FS_BACKEND", "mock")
        specs = []
        for s in self.servers:
            spec = SERVER_REGISTRY[s]
            if backend == "real" and spec.id == "fs":
                spec = ServerSpec(spec.id, spec.mcp_key, "mcp_eval.servers.real_proxy")
            specs.append(spec)
        return specs

    def server_extra_env(self, server_id: str | None = None) -> dict[str, str]:
        """注入某个 server 子进程的额外 env(如 fs 的 MCP_EVAL_DESC_VARIANT、web 的页面/注入开关)。

        签名拓宽了可选 server_id:单 server 任务忽略它即可;跨 server 任务按 server_id 分发
        (如只给 'web' 传页面内容)。RunContext.server_env 以 arity-safe 方式调用,兼容零参旧覆盖。
        """
        return {}

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        return {}

    @staticmethod
    def _new_canary() -> str:
        return "CANARY_" + secrets.token_hex(8)
