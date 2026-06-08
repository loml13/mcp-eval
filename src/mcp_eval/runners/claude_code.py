"""ClaudeCodeRunner:用 `claude -p ... --output-format stream-json` 把真实 Claude Code
接到 mock server 上跑,逐行解析 stream-json 事件转成 agent 侧 TraceEvent。

强制只走 MCP:--strict-mcp-config + --allowedTools 'mcp__mock__*' + --disallowedTools 禁内置,
让被测 agent 只能通过 mock MCP server 操作环境,保证 server 侧 trace 完整。
"""
from __future__ import annotations

import json
import subprocess
import sys

from mcp_eval.runner import AgentRunner, RunContext
from mcp_eval.trace import TraceEvent, append_event, now

# 禁掉所有会操作环境的内置工具,强制 agent 只能通过 mock MCP server 操作环境。
# 注意:不要把 ToolSearch 加进来 —— 在 deferred-tools 模式下它是 agent 加载
# mcp__mock__* 工具 schema 的入口,禁了会导致 MCP 工具根本调不出来
# (实测 Claude 先 ToolSearch 找到 mcp__mock__read_file,再 call 它)。
_BUILTIN_DENY = (
    "Bash Edit Read Write Glob Grep WebFetch WebSearch "
    "NotebookEdit Task TodoWrite MultiEdit"
)
_MCP_PREFIX = "mcp__mock__"


class ClaudeCodeRunner(AgentRunner):
    agent_id = "claude-code"

    def run(self, ctx: RunContext) -> str:
        mcp_config = self._write_mcp_config(ctx)
        cmd = [
            "claude", "-p", ctx.task.prompt,
            "--output-format", "stream-json", "--verbose",
            "--mcp-config", str(mcp_config),
            "--strict-mcp-config",
            "--allowedTools", "mcp__mock__*",
            "--disallowedTools", _BUILTIN_DENY,
            "--permission-mode", "bypassPermissions",
            "--add-dir", str(ctx.workspace),
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(ctx.workspace),
        )
        final = ""
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            got = self._handle(ctx, ev)
            if got is not None:
                final = got
        proc.wait()
        if proc.returncode != 0:
            err = proc.stderr.read() if proc.stderr else ""
            self._emit(ctx, "agent_step", None, None, None,
                       {"error": True, "returncode": proc.returncode, "stderr": err[:800]})
        return final

    def _write_mcp_config(self, ctx: RunContext):
        cfg = {
            "mcpServers": {
                "mock": {
                    "command": sys.executable,
                    "args": ["-m", "mcp_eval.servers.fs_mock"],
                    "env": ctx.server_env(),
                }
            }
        }
        path = ctx.trace_dir / "mcp_config.json"
        path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _handle(self, ctx: RunContext, ev: dict) -> str | None:
        et = ev.get("type")
        if et == "assistant":
            msg = ev.get("message", {})
            for block in msg.get("content", []) or []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    name = (block.get("name") or "").removeprefix(_MCP_PREFIX)
                    self._emit(ctx, "tool_call", name, block.get("input"), None,
                               {"raw_name": block.get("name"), "tool_use_id": block.get("id")})
            usage = msg.get("usage") or {}
            if usage:
                self._emit(ctx, "usage", None, None, None, {
                    "tokens_in": usage.get("input_tokens", 0),
                    "tokens_out": usage.get("output_tokens", 0),
                })
        elif et == "user":
            msg = ev.get("message", {})
            for block in msg.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    self._emit(ctx, "tool_result", None,
                               {"tool_use_id": block.get("tool_use_id")},
                               _block_text(block.get("content")), {})
        elif et == "result":
            final = ev.get("result", "") or ""
            self._emit(ctx, "agent_step", None, None, final, {"final": True})
            return final
        return None

    @staticmethod
    def _emit(ctx: RunContext, type_: str, tool, args, result, meta=None) -> None:
        append_event(
            ctx.agent_jsonl,
            TraceEvent(ts=now(), source="agent", type=type_, tool=tool, args=args, result=result, meta=meta or {}),
        )


def _block_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for c in content:
            if isinstance(c, dict):
                out.append(c.get("text") or json.dumps(c, ensure_ascii=False))
            else:
                out.append(str(c))
        return "\n".join(out)
    return str(content)
