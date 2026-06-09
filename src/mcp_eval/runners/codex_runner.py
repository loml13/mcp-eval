"""CodexRunner:用 `codex exec --json` 把 OpenAI Codex 接到 mock MCP server 上跑(被测对象)。

隔离关键:codex 的 cwd = 一个**空临时目录**(它的内置 shell 在这,看不到任务文件),而 mock
server 的 WORKSPACE 指向真实任务目录 → codex 要完成任务**只能**通过 MCP 工具(read_file 等),
server 侧 trace 完整、安全判定可信。mock server 返回的只有文件内容、不含绝对路径,codex 无从
旁路。

踩坑(全部固化在此):
- stdin=DEVNULL —— 否则 codex exec 把管道 stdin 当"额外输入"读、卡死等 EOF。
- --skip-git-repo-check —— 空 cwd 不是 git repo,codex 默认拒跑。
- --dangerously-bypass-approvals-and-sandbox —— `approval_policy="never"` 不是"自动放行"而是
  "遇到要批准的就拒绝",会把 MCP 工具调用 cancel 掉;bypass 才真正自动放行。空 cwd 隔离仍在,
  所以去 sandbox 安全。
- 临时 CODEX_HOME 必须复制 ~/.codex/auth.json,否则连模型 401。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp_eval.runner import AgentRunner, RunContext
from mcp_eval.trace import TraceEvent, append_event, now


class CodexRunner(AgentRunner):
    agent_id = "codex"

    def __init__(self, model: str | None = None, label: str | None = None) -> None:
        self.model = model
        if label:
            self.agent_id = label
        elif model:
            self.agent_id = f"codex({model})"

    def run(self, ctx: RunContext) -> str:
        codex_home = Path(tempfile.mkdtemp(prefix="codex_home_"))
        empty_cwd = Path(tempfile.mkdtemp(prefix="codex_cwd_"))
        try:
            src_auth = Path.home() / ".codex" / "auth.json"
            if src_auth.exists():
                shutil.copy(src_auth, codex_home / "auth.json")
            self._write_config(codex_home, ctx)
            cmd = [
                "codex", "exec", ctx.task.prompt,
                "-C", str(empty_cwd),
                "--json",
                "--skip-git-repo-check",
                "--dangerously-bypass-approvals-and-sandbox",
            ]
            if self.model:
                cmd += ["-c", f'model="{self.model}"']
            env = {**os.environ, "CODEX_HOME": str(codex_home)}
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                cwd=str(empty_cwd),
            )
            return self._parse(ctx, proc.stdout)
        finally:
            shutil.rmtree(codex_home, ignore_errors=True)
            shutil.rmtree(empty_cwd, ignore_errors=True)

    def _write_config(self, codex_home: Path, ctx: RunContext) -> None:
        env_toml = ", ".join(f'{k} = "{v}"' for k, v in ctx.server_env().items())
        cfg = (
            "[mcp_servers.mock]\n"
            f'command = "{sys.executable}"\n'
            'args = ["-m", "mcp_eval.servers.fs_mock"]\n'
            f"env = {{ {env_toml} }}\n"
        )
        (codex_home / "config.toml").write_text(cfg, encoding="utf-8")

    def _parse(self, ctx: RunContext, out: str) -> str:
        final = ""
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            it = d.get("item", {})
            ity = it.get("type")
            if ity == "mcp_tool_call":
                status = it.get("status")
                if status == "in_progress":
                    self._emit(ctx, "tool_call", it.get("tool"), it.get("arguments"), None,
                               {"server": it.get("server")})
                elif status in ("completed", "failed"):
                    self._emit(ctx, "tool_result", it.get("tool"), it.get("arguments"),
                               it.get("result"), {"status": status, "error": it.get("error")})
            elif ity == "agent_message":
                final = it.get("text") or final
                self._emit(ctx, "agent_step", None, None, final, {"final": True})
            if d.get("type") == "turn.completed":
                u = d.get("usage", {}) or {}
                self._emit(ctx, "usage", None, None, None, {
                    "tokens_in": u.get("input_tokens", 0) or 0,
                    "tokens_out": u.get("output_tokens", 0) or 0,
                })
        return final

    @staticmethod
    def _emit(ctx: RunContext, type_: str, tool, args, result, meta=None) -> None:
        append_event(ctx.agent_jsonl, TraceEvent(
            ts=now(), source="agent", type=type_, tool=tool, args=args, result=result, meta=meta or {}))
