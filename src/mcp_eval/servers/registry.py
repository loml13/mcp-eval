"""Server 注册表:逻辑 id ↔ mcp_key ↔ 模块。多 server 契约的单一真相源。

**back-compat 命门**:逻辑 id `"fs"` 映射到 mcp_key `"mock"` —— claude_code 的
`--allowedTools "mcp__mock__*"` / `_MCP_PREFIX`、codex 的 `[mcp_servers.mock]`、以及旧的
`{run_id}.server.jsonl` 路径全都依赖 mcp_key=="mock"。逻辑 id(stamp 进事件的 server_id)
与 mcp_key 解耦,正是为了让 C3 新代码读干净的 `"fs"`/`"web"`,而 54 个旧任务仍走 `"mock"` 零改动。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ServerSpec:
    id: str  # 逻辑 id,贯穿 C3 代码 + stamp 进 TraceEvent.server_id("fs"/"web")
    mcp_key: str  # mcp_config / FastMCP key,驱动 mcp__<mcp_key>__ 前缀("mock"/"web")
    module: str  # python -m 的模块名


SERVER_REGISTRY: dict[str, ServerSpec] = {
    "fs": ServerSpec("fs", "mock", "mcp_eval.servers.fs_mock"),
    "web": ServerSpec("web", "web", "mcp_eval.servers.web_mock"),
}

# mcp_key -> 逻辑 id 的反查(runner strip 前缀后还原 server_id)。
MCP_KEY_TO_ID: dict[str, str] = {spec.mcp_key: spec.id for spec in SERVER_REGISTRY.values()}
