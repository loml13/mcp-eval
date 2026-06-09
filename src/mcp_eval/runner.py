"""被测 agent 的统一接入抽象。

每个 runner 把一个被测 agent(脚本化 / Claude Code / 未来 Codex)接到指定的 mock MCP
server 上跑一个 task,写出 agent 侧事件 JSONL,并返回 final answer 文本。server 侧事件由
mock server 自己写到 ctx.server_jsonl,harness 负责归并两层。
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from mcp_eval.servers.registry import SERVER_REGISTRY


def _default_fs_spec() -> list:
    return [SERVER_REGISTRY["fs"]]


@dataclass
class RunContext:
    run_id: str
    task: object  # tasks 里的 Task;用 object 避免循环 import
    workspace: Path  # 临时 workspace 根(含 public/ private/)
    trace_dir: Path  # 事件 JSONL 输出目录
    project_root: Path  # mcp-eval 项目根
    # 多 server 拓扑;harness 从 task.server_specs() 注入。默认单 fs → byte-identical C2。
    server_specs: list = field(default_factory=_default_fs_spec)

    @property
    def agent_jsonl(self) -> Path:
        return self.trace_dir / f"{self.run_id}.agent.jsonl"

    @property
    def server_ids(self) -> list[str]:
        return [s.id for s in self.server_specs]

    def _server_jsonl_path(self, sid: str) -> Path:
        # 单 fs:沿用旧 .server.jsonl 文件名(back-compat 命门);多 server:按 id 命名空间。
        if self.server_ids == ["fs"]:
            return self.trace_dir / f"{self.run_id}.server.jsonl"
        return self.trace_dir / f"{self.run_id}.server.{sid}.jsonl"

    @property
    def server_jsonls(self) -> dict[str, Path]:
        """{server_id: jsonl 路径};harness 传给 trace.merge 做多源归并。"""
        return {s.id: self._server_jsonl_path(s.id) for s in self.server_specs}

    @property
    def server_jsonl(self) -> Path:
        """LEGACY:任何读 ctx.server_jsonl 的旧代码/测试仍拿到 fs 路径。"""
        return self._server_jsonl_path("fs")

    def server_env(self, server_id: str = "fs") -> dict[str, str]:
        """注入某个 server 子进程的环境变量。

        合并 task.server_extra_env(server_id)(arity-safe:兼容零参旧覆盖)。**单 fs 守卫**:
        当拓扑恰为 ["fs"] 时省略 MCP_EVAL_SERVER_ID/SERVER_JSONL 两键,让 fs_mock 回落到默认
        (SERVER_ID="fs" + 旧 .server.jsonl 路径),保证 54 旧任务的 server 端 byte-identical。
        """
        extra_fn = getattr(self.task, "server_extra_env", None)
        extra: dict = {}
        if callable(extra_fn):
            try:
                extra = extra_fn(server_id)  # 新签名:按 server_id 分发
            except TypeError:
                extra = extra_fn()  # 零参旧覆盖
        env = {
            "MCP_EVAL_WORKSPACE": str(self.workspace),
            "MCP_EVAL_TRACE_DIR": str(self.trace_dir),
            "MCP_EVAL_RUN_ID": self.run_id,
            **(extra or {}),
        }
        if self.server_ids != ["fs"]:
            env["MCP_EVAL_SERVER_ID"] = server_id
            env["MCP_EVAL_SERVER_JSONL"] = str(self._server_jsonl_path(server_id))
        return env

    def full_server_env(self, server_id: str = "fs") -> dict[str, str]:
        """完整子进程环境:继承当前环境 + 注入 MCP_EVAL_*。"""
        return {**os.environ, **self.server_env(server_id)}


class AgentRunner(ABC):
    agent_id: str

    @abstractmethod
    def run(self, ctx: RunContext) -> str:
        """跑 agent,写 agent 侧事件到 ctx.agent_jsonl,返回 final answer 文本。"""
        ...
