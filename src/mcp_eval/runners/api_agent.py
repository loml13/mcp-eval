"""ApiAgentRunner:用 OpenAI 兼容 API(deepseek / 小米 / 任意 OpenAI 兼容端点)驱动一个最小
tool-calling agent,接到 mock MCP server 上跑。

兑现 B 阶段 plan 的「真·API baseline」扩展位。天然只走 MCP —— agent 只有我们经 MCP 暴露的
工具,没有任何内置工具,比 claude 还干净(无需 disallow)。把模型的 function-calling 一一映射到
mock server 的 MCP 工具,server 侧照常记 ground-truth trace。

多 server(C3):用 AsyncExitStack 同时开 N 个 stdio 会话(每 spec 一个)。单 server 时仍走
裸工具名 + 单会话,与 C2 byte-identical(命门);多 server 时强制把暴露名命名空间化为
mcp__<mcp_key>__<tool>(否则两个 server 各有一个同名 search 会在 OpenAI 扁平工具表里互相覆盖),
靠 route map 把暴露名路由回 (session, 裸名, server_id)。
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import re
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
        max_steps: int = 14,
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

        multi = len(ctx.server_specs) > 1
        async with contextlib.AsyncExitStack() as stack:
            # 每个 spec 开一个独立 stdio 会话;单 fs 时只有一个,行为同 C2。
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

            # 构建模型可见工具表 + 路由表。单 server:裸名(命门);多 server:命名空间化。
            tools: list[dict] = []
            route: dict[str, tuple[ClientSession, str, str]] = {}  # 暴露名 -> (session, 裸名, server_id)
            for spec in ctx.server_specs:
                session = sessions[spec.id]
                listed = await session.list_tools()
                for t in listed.tools:
                    exposed = f"mcp__{spec.mcp_key}__{t.name}" if multi else t.name
                    tools.append(self._to_openai_tool(t, exposed))
                    route[exposed] = (session, t.name, spec.id)

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
                        assistant_msg: dict = {
                            "role": "assistant",
                            "content": msg.content,
                            "tool_calls": [{
                                "id": tc.id,
                                "type": "function",
                                "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                            } for tc in msg.tool_calls],
                        }
                        # 推理模型(如 kimi-k2.6)开 thinking 时,要求回传的 assistant 工具调用
                        # 消息必须带 reasoning_content,否则下一轮请求 400;非推理模型该字段为
                        # None → 不加,行为不变(deepseek/mimo/qwen 不受影响)。
                        reasoning = getattr(msg, "reasoning_content", None)
                        if reasoning is None and getattr(msg, "model_extra", None):
                            reasoning = msg.model_extra.get("reasoning_content")
                        if reasoning is not None:
                            assistant_msg["reasoning_content"] = reasoning
                        messages.append(assistant_msg)
                        for tc in msg.tool_calls:
                            try:
                                args = json.loads(tc.function.arguments or "{}")
                            except json.JSONDecodeError:
                                args = {}
                            # 按暴露名路由回具体 session;单 server 时暴露名即裸名。
                            session, bare, sid = route.get(
                                tc.function.name, (sessions[ctx.server_ids[0]], tc.function.name, ctx.server_ids[0]))
                            meta = {"server_id": sid} if multi else None
                            self._emit(ctx, "tool_call", bare, args, None, meta)
                            res = await session.call_tool(bare, args)
                            text = _result_text(res)
                            self._emit(ctx, "tool_result", bare, args, text, meta)
                            messages.append({"role": "tool", "tool_call_id": tc.id, "content": text})
                    else:
                        final = _strip_think(msg.content or "")
                        break
                self._emit(ctx, "agent_step", None, None, final, {"final": True})
                return final

    @staticmethod
    def _to_openai_tool(t, name: str) -> dict:
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": t.description or "",
                "parameters": t.inputSchema or {"type": "object", "properties": {}},
            },
        }

    @staticmethod
    def _emit(ctx: RunContext, type_: str, tool, args, result, meta=None) -> None:
        append_event(ctx.agent_jsonl, TraceEvent(
            ts=now(), source="agent", type=type_, tool=tool, args=args, result=result, meta=meta or {}))


_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def _strip_think(text: str) -> str:
    """剥离内联思考块。MiniMax-M 系把推理写进 content 的 <think>...</think>;
    其它推理模型(kimi/glm)思考在独立 reasoning_content 里、本就不进 final。为跨模型
    公平,final answer 只留模型真正的可见回答。无 think 标签的模型为 no-op。"""
    text = _THINK_RE.sub("", text)
    idx = text.find("<think>")  # 未闭合(被 max_steps/截断打断):从 <think> 起全丢
    if idx != -1:
        text = text[:idx]
    return text.strip()


def _result_text(res) -> str:
    parts = []
    for c in getattr(res, "content", None) or []:
        parts.append(getattr(c, "text", None) or str(c))
    return "\n".join(parts)
