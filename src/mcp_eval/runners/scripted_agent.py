"""确定性被测 agent:按 task 提供的固定动作脚本依次调用 MCP 工具。

行为完全可预测 → 用来验证 trace 捕获机制本身正确(server 侧应记录到的每一条都能精确断言)。
走真实的 MCP client → stdio → fs_mock 全链路。

脚本里的 args 值若为 "$LAST_RESULT",会被上一步工具返回替换 —— 用于模拟「读到 canary 再
转发出去」的泄漏链,而无需硬编码 canary 值。
"""
from __future__ import annotations

import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_eval.runner import AgentRunner, RunContext
from mcp_eval.trace import TraceEvent, append_event, now

PLACEHOLDER = "$LAST_RESULT"


class ScriptedAgentRunner(AgentRunner):
    agent_id = "scripted"

    def __init__(self, script_name: str = "safe") -> None:
        self.script_name = script_name

    def run(self, ctx: RunContext) -> str:
        return asyncio.run(self._run(ctx))

    async def _run(self, ctx: RunContext) -> str:
        actions = ctx.task.scripts.get(self.script_name, [])  # 缺该脚本 -> no-op,矩阵不中断
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_eval.servers.fs_mock"],
            env=ctx.full_server_env(),
        )
        last_result = ""
        transcript: list[str] = []
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for tool, raw_args in actions:
                    args = {
                        k: (last_result if v == PLACEHOLDER else v)
                        for k, v in raw_args.items()
                    }
                    self._emit(ctx, "tool_call", tool, args, None)
                    res = await session.call_tool(tool, args)
                    text = _result_text(res)
                    self._emit(ctx, "tool_result", tool, args, text)
                    transcript.append(f"{tool}({args}) -> {text[:80]}")
                    last_result = text
        final = "\n".join(transcript)
        self._emit(ctx, "agent_step", None, None, final, {"final": True})
        return final

    @staticmethod
    def _emit(ctx: RunContext, type_: str, tool, args, result, meta=None) -> None:
        append_event(
            ctx.agent_jsonl,
            TraceEvent(ts=now(), source="agent", type=type_, tool=tool, args=args, result=result, meta=meta or {}),
        )


def _result_text(res) -> str:
    parts = []
    for c in getattr(res, "content", None) or []:
        parts.append(getattr(c, "text", None) or str(c))
    return "\n".join(parts)
