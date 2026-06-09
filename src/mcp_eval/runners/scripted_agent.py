"""确定性被测 agent:按 task 提供的固定动作脚本依次调用 MCP 工具。

行为完全可预测 → 用来验证 trace 捕获机制本身正确(server 侧应记录到的每一条都能精确断言)。
走真实的 MCP client → stdio → fs_mock(多 server 时再加 web_mock)全链路。

脚本里的 args 值若为 "$LAST_RESULT",会被上一步工具返回替换 —— 用于模拟「读到 canary 再
转发出去」的泄漏链,而无需硬编码 canary 值。

脚本动作的 tool 可裸名(→ 默认 fs 会话),也可 mcp__<key>__<tool> 显式前缀(→ 路由到对应
server)。这让 safe/compromised oracle 脚本能确定性地横跨 fs+web。单 server 时只有一个会话、
全走裸名,与 C2 byte-identical(命门)。
"""
from __future__ import annotations

import asyncio
import contextlib
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
        multi = len(ctx.server_specs) > 1
        last_result = ""
        transcript: list[str] = []
        async with contextlib.AsyncExitStack() as stack:
            # 每 spec 一个独立 stdio 会话;单 fs 时只有一个,行为同 C2。
            sessions: dict[str, ClientSession] = {}
            for spec in ctx.server_specs:
                params = StdioServerParameters(
                    command=sys.executable,
                    args=["-m", spec.module],
                    env=ctx.full_server_env(spec.id),
                )
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                sessions[spec.id] = session
            await asyncio.gather(*(s.initialize() for s in sessions.values()))

            # 裸名路由表:{裸名: (session, server_id)}。第一个(fs)优先,撞名时保留 fs →
            # 撞名工具必须用 mcp__<key>__<tool> 前缀显式指定。前缀表:{暴露名: (session, 裸名, server_id)}。
            default_map: dict[str, tuple[ClientSession, str]] = {}
            prefixed_map: dict[str, tuple[ClientSession, str, str]] = {}
            for spec in ctx.server_specs:
                session = sessions[spec.id]
                listed = await session.list_tools()
                for t in listed.tools:
                    default_map.setdefault(t.name, (session, spec.id))
                    prefixed_map[f"mcp__{spec.mcp_key}__{t.name}"] = (session, t.name, spec.id)

            for tool, raw_args in actions:
                args = {
                    k: (last_result if v == PLACEHOLDER else v)
                    for k, v in raw_args.items()
                }
                session, bare, sid = self._route(tool, sessions, default_map, prefixed_map, ctx)
                meta = {"server_id": sid} if multi else None
                self._emit(ctx, "tool_call", bare, args, None, meta)
                res = await session.call_tool(bare, args)
                text = _result_text(res)
                self._emit(ctx, "tool_result", bare, args, text, meta)
                transcript.append(f"{bare}({args}) -> {text[:80]}")
                last_result = text
        final = "\n".join(transcript)
        self._emit(ctx, "agent_step", None, None, final, {"final": True})
        return final

    @staticmethod
    def _route(tool, sessions, default_map, prefixed_map, ctx) -> tuple[ClientSession, str, str]:
        """把脚本 tool 名解析成 (session, 裸名, server_id)。前缀名走 prefixed_map,
        裸名走 default_map(撞名落 fs);都查不到则回落到第一个 server,裸名原样调用。"""
        if tool in prefixed_map:
            return prefixed_map[tool]
        if tool in default_map:
            session, sid = default_map[tool]
            return session, tool, sid
        sid = ctx.server_ids[0]
        return sessions[sid], tool, sid

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
