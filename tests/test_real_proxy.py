"""real_proxy 的单测(不依赖 Node/npx)。

下游替身:以 fs_mock 充当下游 server(通过 MCP_EVAL_REAL_CMD/ARGS 覆盖)。
proxy 进程与 fake 下游均通过 asyncio subprocess stdio 启动。

覆盖:
  - resolve_meta 纯函数(workspace 内/外、allowed_root 内/外、逃逸)
  - ALIAS_UP2DOWN / ALIAS_DOWN2UP 正反查
  - proxy 起动 + list_tools:包含 list_dir/read_file/write_file/search/stat_file/
    send_message/request_confirmation;不含 read_text_file/directory_tree 等
  - call read_file 经 proxy → fs_mock 返回真实内容,SERVER_JSONL 有 resource_read
    (tool=="read_file") + meta 含 resolved/outside_allowed_root 字段
  - send_message 经 proxy emit sink 事件
  - INJECT_TOOLDESC 命中时 list_tools 含 register_access decoy
  - fault 注入:transient(首次 ERROR,再次 OK)/ persistent(恒 ERROR)
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from contextlib import AsyncExitStack
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_eval.servers._fsutil import resolve_meta
from mcp_eval.trace import read_jsonl


# ─────────────────────────── resolve_meta 纯函数 ────────────────────────────

class TestResolveMeta:
    """_fsutil.resolve_meta 与 fs_mock._resolve 行为一致。"""

    def setup_method(self):
        self._td = tempfile.TemporaryDirectory()
        self.ws = Path(self._td.name).resolve()
        self.ar = self.ws / "public"
        self.ar.mkdir(parents=True, exist_ok=True)

    def teardown_method(self):
        self._td.cleanup()

    def test_inside_both(self):
        """public/ 内:无任何越界 flag。"""
        _, meta = resolve_meta(self.ws, self.ar, "public/a.txt")
        assert meta["requested"] == "public/a.txt"
        assert "outside_workspace" not in meta
        assert "outside_allowed_root" not in meta

    def test_inside_workspace_outside_allowed(self):
        """workspace 内但 allowed_root 外(private/)。"""
        _, meta = resolve_meta(self.ws, self.ar, "private/b.txt")
        assert "outside_workspace" not in meta
        assert meta.get("outside_allowed_root") is True

    def test_outside_workspace(self):
        """路径逃出 workspace。"""
        _, meta = resolve_meta(self.ws, self.ar, "../../../etc/passwd")
        assert meta.get("outside_workspace") is True
        assert meta.get("outside_allowed_root") is True

    def test_workspace_root_itself(self):
        """workspace 根目录自身不触发 outside_workspace。"""
        _, meta = resolve_meta(self.ws, self.ar, ".")
        assert "outside_workspace" not in meta

    def test_resolved_field(self):
        """resolved 字段存在且为字符串。"""
        _, meta = resolve_meta(self.ws, self.ar, "foo.txt")
        assert isinstance(meta["resolved"], str)
        assert meta["resolved"].endswith("foo.txt")

    def test_symlink_escape(self):
        """符号链接逃逸:链接指向 workspace 外 → outside_workspace=True。"""
        link = self.ws / "escape_link"
        link.symlink_to("/etc")  # /etc 肯定在 workspace 外
        _, meta = resolve_meta(self.ws, self.ar, "escape_link/passwd")
        assert meta.get("outside_workspace") is True


# ─────────────────────────── ALIAS 表纯函数 ────────────────────────────────

def test_alias_up2down():
    from mcp_eval.servers.real_proxy import ALIAS_UP2DOWN
    assert ALIAS_UP2DOWN["list_dir"] == "list_directory"
    assert ALIAS_UP2DOWN["read_file"] == "read_file"
    assert ALIAS_UP2DOWN["write_file"] == "write_file"
    assert ALIAS_UP2DOWN["search"] == "search_files"
    assert ALIAS_UP2DOWN["stat_file"] == "get_file_info"


def test_alias_down2up():
    from mcp_eval.servers.real_proxy import ALIAS_DOWN2UP
    assert ALIAS_DOWN2UP["list_directory"] == "list_dir"
    assert ALIAS_DOWN2UP["read_file"] == "read_file"
    assert ALIAS_DOWN2UP["write_file"] == "write_file"
    assert ALIAS_DOWN2UP["search_files"] == "search"
    assert ALIAS_DOWN2UP["get_file_info"] == "stat_file"


def test_alias_invertible():
    """UP2DOWN 与 DOWN2UP 互为逆。"""
    from mcp_eval.servers.real_proxy import ALIAS_DOWN2UP, ALIAS_UP2DOWN
    for up, down in ALIAS_UP2DOWN.items():
        assert ALIAS_DOWN2UP[down] == up


# ─────────────────────────── proxy 集成测试 helpers ────────────────────────

def _base_env(ws: Path, trace_dir: Path, run_id: str, extra: dict | None = None) -> dict:
    """构造 proxy 子进程 env。"""
    env = {
        **os.environ,
        "MCP_EVAL_WORKSPACE": str(ws),
        "MCP_EVAL_TRACE_DIR": str(trace_dir),
        "MCP_EVAL_RUN_ID": run_id,
        # proxy 用 fs_mock 当下游替身(不需要 Node)
        "MCP_EVAL_REAL_CMD": sys.executable,
        "MCP_EVAL_REAL_ARGS": "-m mcp_eval.servers.fs_mock",
        # 清除注入 env
        "MCP_EVAL_INJECT_TOOLDESC": "",
        "MCP_EVAL_FAULT_PATHS": "",
        "MCP_EVAL_FAULT_MODE": "transient",
    }
    if extra:
        env.update(extra)
    return env


async def _run_proxy(env: dict, coro):
    """启动 proxy,在 session 上执行 coro(接收 session 参数),返回结果。"""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_eval.servers.real_proxy"],
        env=env,
    )
    async with AsyncExitStack() as stack:
        read, write = await stack.enter_async_context(stdio_client(params))
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        return await coro(session)


def run(coro):
    """同步执行异步函数(测试辅助)。每次用新 event loop 避免跨测试 loop 复用问题。"""
    return asyncio.run(coro)


# ─────────────────────────── proxy 集成测试 ────────────────────────────────

@pytest.fixture()
def proxy_setup(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "public").mkdir()
    (ws / "private").mkdir()
    (ws / "public" / "hello.txt").write_text("hello world\n", encoding="utf-8")
    (ws / "private" / "secret.txt").write_text("TOP SECRET\n", encoding="utf-8")

    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    run_id = "test_run_001"

    return {
        "ws": ws,
        "trace_dir": trace_dir,
        "run_id": run_id,
        "server_jsonl": trace_dir / f"{run_id}.server.jsonl",
        "base_env": _base_env(ws, trace_dir, run_id),
    }


def test_list_tools_contains_expected(proxy_setup):
    """agent 视角 list_tools 含预期工具,不含旁路工具。"""
    env = proxy_setup["base_env"]

    async def _check(session):
        return await session.list_tools()

    result = run(_run_proxy(env, _check))
    names = {t.name for t in result.tools}

    expected = {"list_dir", "read_file", "write_file", "search", "stat_file",
                "send_message", "request_confirmation"}
    assert expected.issubset(names), f"缺少工具: {expected - names}"

    forbidden = {"read_text_file", "directory_tree", "list_directory_with_sizes",
                 "read_multiple_files", "read_media_file", "edit_file",
                 "create_directory", "move_file", "list_allowed_directories"}
    exposed = forbidden & names
    assert not exposed, f"不应暴露的工具被暴露: {exposed}"


def test_read_file_forwarded(proxy_setup):
    """read_file 经 proxy 转发到 fs_mock,返回真实内容并 emit resource_read 事件。"""
    env = proxy_setup["base_env"]
    server_jsonl = proxy_setup["server_jsonl"]

    async def _check(session):
        return await session.call_tool("read_file", {"path": "public/hello.txt"})

    res = run(_run_proxy(env, _check))
    text = "\n".join(getattr(c, "text", "") for c in res.content)
    assert "hello world" in text, f"内容不符: {text!r}"

    events = read_jsonl(server_jsonl)
    read_evts = [e for e in events
                 if e.get("type") == "resource_read" and e.get("tool") == "read_file"]
    assert read_evts, "缺少 resource_read 事件"
    meta = read_evts[0].get("meta", {})
    assert "resolved" in meta
    assert "outside_workspace" not in meta


def test_read_file_private_meta(proxy_setup):
    """读 private/ 文件时 meta 含 outside_allowed_root=True。"""
    env = proxy_setup["base_env"]
    server_jsonl = proxy_setup["server_jsonl"]

    async def _check(session):
        return await session.call_tool("read_file", {"path": "private/secret.txt"})

    run(_run_proxy(env, _check))

    events = read_jsonl(server_jsonl)
    read_evts = [e for e in events
                 if e.get("type") == "resource_read" and e.get("tool") == "read_file"]
    assert read_evts, "缺少 resource_read 事件"
    meta = read_evts[0].get("meta", {})
    assert meta.get("outside_allowed_root") is True, f"meta={meta}"


def test_send_message_emits_sink(proxy_setup):
    """send_message 经 proxy emit sink 事件。"""
    env = proxy_setup["base_env"]
    server_jsonl = proxy_setup["server_jsonl"]

    async def _check(session):
        return await session.call_tool("send_message", {"channel": "c1", "body": "hi"})

    res = run(_run_proxy(env, _check))
    text = "\n".join(getattr(c, "text", "") for c in res.content)
    assert text.strip() == "sent"

    events = read_jsonl(server_jsonl)
    sinks = [e for e in events
             if e.get("type") == "sink" and e.get("tool") == "send_message"]
    assert sinks, "缺少 sink 事件"
    assert sinks[0]["args"]["channel"] == "c1"
    assert sinks[0]["args"]["body"] == "hi"


def test_inject_tooldesc_adds_decoy(proxy_setup):
    """INJECT_TOOLDESC 设置时 list_tools 包含 register_access decoy。"""
    env = {**proxy_setup["base_env"], "MCP_EVAL_INJECT_TOOLDESC": "register"}

    async def _check(session):
        return await session.list_tools()

    result = run(_run_proxy(env, _check))
    names = {t.name for t in result.tools}
    assert "register_access" in names, f"缺少 register_access,实际: {names}"


def test_inject_tooldesc_unset_no_decoy(proxy_setup):
    """INJECT_TOOLDESC 未设置时 list_tools 不包含 register_access。"""
    env = proxy_setup["base_env"]

    async def _check(session):
        return await session.list_tools()

    result = run(_run_proxy(env, _check))
    names = {t.name for t in result.tools}
    assert "register_access" not in names


def test_fault_transient(proxy_setup):
    """transient fault:第一次 ERROR,第二次返回真实内容。"""
    env = {
        **proxy_setup["base_env"],
        "MCP_EVAL_FAULT_PATHS": "public/hello.txt",
        "MCP_EVAL_FAULT_MODE": "transient",
    }

    results: list[str] = []

    async def _check(session):
        r1 = await session.call_tool("read_file", {"path": "public/hello.txt"})
        r2 = await session.call_tool("read_file", {"path": "public/hello.txt"})
        return r1, r2

    r1, r2 = run(_run_proxy(env, _check))
    t1 = "\n".join(getattr(c, "text", "") for c in r1.content)
    t2 = "\n".join(getattr(c, "text", "") for c in r2.content)
    assert "ERROR" in t1, f"第一次应为 ERROR,实际: {t1!r}"
    assert "ERROR" not in t2, f"第二次应成功,实际: {t2!r}"


def test_fault_persistent(proxy_setup):
    """persistent fault:两次均 ERROR。"""
    env = {
        **proxy_setup["base_env"],
        "MCP_EVAL_FAULT_PATHS": "public/hello.txt",
        "MCP_EVAL_FAULT_MODE": "persistent",
    }

    async def _check(session):
        r1 = await session.call_tool("read_file", {"path": "public/hello.txt"})
        r2 = await session.call_tool("read_file", {"path": "public/hello.txt"})
        return r1, r2

    r1, r2 = run(_run_proxy(env, _check))
    t1 = "\n".join(getattr(c, "text", "") for c in r1.content)
    t2 = "\n".join(getattr(c, "text", "") for c in r2.content)
    assert "ERROR" in t1
    assert "ERROR" in t2


def test_request_confirmation(proxy_setup):
    """request_confirmation 返回 granted 且 emit tool_call/tool_result。"""
    env = proxy_setup["base_env"]
    server_jsonl = proxy_setup["server_jsonl"]

    async def _check(session):
        return await session.call_tool(
            "request_confirmation", {"action": "delete", "target": "public/hello.txt"}
        )

    res = run(_run_proxy(env, _check))
    text = "\n".join(getattr(c, "text", "") for c in res.content)
    assert text.strip() == "granted"

    events = read_jsonl(server_jsonl)
    rc_evts = [e for e in events if e.get("tool") == "request_confirmation"]
    assert len(rc_evts) >= 2, f"期望 >=2 个事件,实际: {len(rc_evts)}"
    meta = rc_evts[0].get("meta", {})
    assert meta.get("granted") is True
