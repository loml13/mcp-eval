"""被测 agent 的统一接入抽象。

每个 runner 把一个被测 agent(脚本化 / Claude Code / 未来 Codex)接到指定的 mock MCP
server 上跑一个 task,写出 agent 侧事件 JSONL,并返回 final answer 文本。server 侧事件由
mock server 自己写到 ctx.server_jsonl,harness 负责归并两层。
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunContext:
    run_id: str
    task: object  # tasks 里的 Task;用 object 避免循环 import
    workspace: Path  # 临时 workspace 根(含 public/ private/)
    trace_dir: Path  # 事件 JSONL 输出目录
    project_root: Path  # mcp-eval 项目根

    @property
    def agent_jsonl(self) -> Path:
        return self.trace_dir / f"{self.run_id}.agent.jsonl"

    @property
    def server_jsonl(self) -> Path:
        return self.trace_dir / f"{self.run_id}.server.jsonl"

    def server_env(self) -> dict[str, str]:
        """注入给 mock server 子进程的环境变量(server 据此定位 workspace 与 trace 输出)。

        合并 task.server_extra_env()(如 description A/B 的 MCP_EVAL_DESC_VARIANT)——单点
        chokepoint,两个 runner(scripted 经 full_server_env,claude_code 经 mcp_config env)都走这里。
        """
        extra_fn = getattr(self.task, "server_extra_env", None)
        extra = extra_fn() if callable(extra_fn) else {}
        return {
            "MCP_EVAL_WORKSPACE": str(self.workspace),
            "MCP_EVAL_TRACE_DIR": str(self.trace_dir),
            "MCP_EVAL_RUN_ID": self.run_id,
            **(extra or {}),
        }

    def full_server_env(self) -> dict[str, str]:
        """完整子进程环境:继承当前环境 + 注入 MCP_EVAL_*。"""
        return {**os.environ, **self.server_env()}


class AgentRunner(ABC):
    agent_id: str

    @abstractmethod
    def run(self, ctx: RunContext) -> str:
        """跑 agent,写 agent 侧事件到 ctx.agent_jsonl,返回 final answer 文本。"""
        ...
