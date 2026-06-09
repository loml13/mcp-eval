"""ApiAgentRunner:用 OpenAI 兼容 API(deepseek / 小米 / 任意 OpenAI 兼容端点)驱动一个最小
tool-calling agent,接到 mock MCP server 上跑。

兑现 B 阶段 plan 的「真·API baseline」扩展位。天然只走 MCP —— agent 只有我们经 MCP 暴露的
工具,没有任何内置工具,比 claude 还干净(无需 disallow)。把模型的 function-calling 一一映射到
mock server 的 MCP 工具,server 侧照常记 ground-truth trace。
"""
from __future__ import annotations

import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_eval.runner import AgentRunner, RunContext
from mcp_eval.trace import TraceEvent, append_event, now


class ApiAgentRunner(AgentRunner):
    agent_id = "api"

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        api_key: str,
        label: str | None = None,
        max_steps: int = 10,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.max_steps = max_steps
        self.agent_id = label or f"api({model})"

    def run(self, ctx: RunContext) -> str:
        return asyncio.run(self._run(ctx))

    async def _run(self, ctx: RunContext) -> str:
        from openai import AsyncOpenAI

        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_eval.servers.fs_mock"],
            env=ctx.full_server_env(),
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                tools = [self._to_openai_tool(t) for t in listed.tools]
                async with AsyncOpenAI(base_url=self.base_url, api_key=self.api_key) as client:
                    messages: list[dict] = [{"role": "user", "content": ctx.task.prompt}]
                    final = ""
                    for _ in range(self.max_steps):
                        try:
                            resp = await client.chat.completions.create(
                                model=self.model, messages=messages, tools=tools
                            )
                        except Exception as e:  # noqa: BLE001 - API/网络错误如实记进 trace
                            self._emit(ctx, "agent_step", None, None, None,
                                       {"error": True, "detail": str(e)[:300]})
                            return final
                        msg = resp.choices[0].message
                        usage = getattr(resp, "usage", None)
                        if usage:
                            self._emit(ctx, "usage", None, None, None, {
                                "tokens_in": getattr(usage, "prompt_tokens", 0) or 0,
                                "tokens_out": getattr(usage, "completion_tokens", 0) or 0,
                            })
                        if msg.tool_calls:
                            messages.append({
                                "role": "assistant",
                                "content": msg.content,
                                "tool_calls": [{
                                    "id": tc.id,
                                    "type": "function",
                                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                                } for tc in msg.tool_calls],
                            })
                            for tc in msg.tool_calls:
                                try:
                                    args = json.loads(tc.function.arguments or "{}")
                                except json.JSONDecodeError:
                                    args = {}
                                self._emit(ctx, "tool_call", tc.function.name, args, None)
                                res = await session.call_tool(tc.function.name, args)
                                text = _result_text(res)
                                self._emit(ctx, "tool_result", tc.function.name, args, text)
                                messages.append({"role": "tool", "tool_call_id": tc.id, "content": text})
                        else:
                            final = msg.content or ""
                            break
                    self._emit(ctx, "agent_step", None, None, final, {"final": True})
                    return final

    @staticmethod
    def _to_openai_tool(t) -> dict:
        return {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.inputSchema or {"type": "object", "properties": {}},
            },
        }

    @staticmethod
    def _emit(ctx: RunContext, type_: str, tool, args, result, meta=None) -> None:
        append_event(ctx.agent_jsonl, TraceEvent(
            ts=now(), source="agent", type=type_, tool=tool, args=args, result=result, meta=meta or {}))


def _result_text(res) -> str:
    parts = []
    for c in getattr(res, "content", None) or []:
        parts.append(getattr(c, "text", None) or str(c))
    return "\n".join(parts)
