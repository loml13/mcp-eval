"""mock vs real server-filesystem 后端对照脚本。

对指定任务子集 × 指定 runner,分别在 MCP_EVAL_FS_BACKEND=mock 和 =real 下各跑,
产出对照表:task_id | mock(functional/safe) | real(functional/safe) | 一致?

用法:
  uv run python scripts/compare_backends.py \\
      --tasks fb_absolute_path,fb_read_private,inj_b64_encoded \\
      --model sonnet --reps 1

  # 若无 API key,用 scripted runner:
  uv run python scripts/compare_backends.py \\
      --tasks fb_absolute_path,fb_read_private \\
      --scripted --reps 1

  # 无 Node / npx:用 --dry-run 只测 proxy 起动链路(下游=fs_mock)
  uv run python scripts/compare_backends.py \\
      --tasks fb_absolute_path --scripted --reps 1 --dry-run
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mcp_eval.harness import run_task
from mcp_eval.runners.scripted_agent import ScriptedAgentRunner
from mcp_eval.tasks.registry import ALL_TASK_FACTORIES
from mcp_eval.validators.base import run_validators


def _arg(flag: str, default: str | None = None) -> str | None:
    if flag in sys.argv:
        i = sys.argv.index(flag)
        return sys.argv[i + 1] if i + 1 < len(sys.argv) else default
    return default


def _run_backend(factories, runner, backend: str) -> dict[str, dict]:
    """在指定 backend 下跑所有任务,返回 {task_id: {functional, safe}}。"""
    os.environ["MCP_EVAL_FS_BACKEND"] = backend
    results: dict[str, dict] = {}
    for factory in factories:
        task = factory()
        try:
            record = run_task(task, runner)
            verds = run_validators(record, task)
            functional = all(v.passed for v in verds if v.kind == "functional")
            safe = all(v.passed for v in verds if v.kind == "safety")
        except Exception as e:  # noqa: BLE001
            print(f"  [WARN] {task.task_id} on {backend} failed: {e}")
            functional = False
            safe = False
        results[task.task_id] = {"functional": functional, "safe": safe}
    return results


def _sym(b: bool) -> str:
    return "PASS" if b else "FAIL"


def main() -> None:
    tasks_arg = _arg("--tasks", "fb_absolute_path,fb_read_private,inj_b64_encoded")
    reps = int(_arg("--reps", "1"))
    model = _arg("--model")
    scripted = "--scripted" in sys.argv
    dry_run = "--dry-run" in sys.argv

    want = {t.strip() for t in (tasks_arg or "").split(",") if t.strip()}
    factories = [f for f in ALL_TASK_FACTORIES if f().task_id in want]
    if not factories:
        print(f"没有找到任务:{want}")
        sys.exit(1)

    print(f"任务子集: {[f().task_id for f in factories]}")
    print(f"reps={reps}, model={'scripted' if scripted else model or 'default'}")

    # dry-run:把真实 server 命令换成 fs_mock(用于 Node 不可用时验链路)
    if dry_run:
        print("[dry-run] 下游使用 fs_mock 替代真实 server-filesystem")
        os.environ["MCP_EVAL_REAL_CMD"] = sys.executable
        os.environ["MCP_EVAL_REAL_ARGS"] = "-m mcp_eval.servers.fs_mock"

    # 构建 runner
    if scripted:
        runner = ScriptedAgentRunner("safe")
    elif model:
        from mcp_eval.runners.claude_code import ClaudeCodeRunner
        runner = ClaudeCodeRunner(model=model)
    else:
        from mcp_eval.runners.claude_code import ClaudeCodeRunner
        runner = ClaudeCodeRunner()

    print("\n--- mock backend ---")
    mock_results = {}
    real_results = {}

    for _ in range(reps):
        r = _run_backend(factories, runner, "mock")
        for tid, v in r.items():
            if tid not in mock_results:
                mock_results[tid] = v
            else:
                # reps>1 时取 AND(保守:任一 rep 失败则算失败)
                mock_results[tid]["functional"] = mock_results[tid]["functional"] and v["functional"]
                mock_results[tid]["safe"] = mock_results[tid]["safe"] and v["safe"]

    print("\n--- real backend ---")
    for _ in range(reps):
        r = _run_backend(factories, runner, "real")
        for tid, v in r.items():
            if tid not in real_results:
                real_results[tid] = v
            else:
                real_results[tid]["functional"] = real_results[tid]["functional"] and v["functional"]
                real_results[tid]["safe"] = real_results[tid]["safe"] and v["safe"]

    # 输出 Markdown 对照表
    header = "| task_id | mock functional | mock safe | real functional | real safe | 一致? |"
    sep    = "|---------|-----------------|-----------|-----------------|-----------|-------|"
    print(f"\n{header}")
    print(sep)

    consistent = 0
    total = 0
    for tid in sorted({*mock_results, *real_results}):
        m = mock_results.get(tid, {})
        r = real_results.get(tid, {})
        mf = _sym(m.get("functional", False))
        ms = _sym(m.get("safe", False))
        rf = _sym(r.get("functional", False))
        rs = _sym(r.get("safe", False))
        agree = (m.get("functional") == r.get("functional") and m.get("safe") == r.get("safe"))
        flag = "YES" if agree else "NO"
        if agree:
            consistent += 1
        total += 1
        print(f"| {tid} | {mf} | {ms} | {rf} | {rs} | {flag} |")

    pct = f"{consistent/total*100:.0f}%" if total else "N/A"
    print(f"\n方向一致率: {consistent}/{total} = {pct}")

    # 恢复 env
    os.environ.pop("MCP_EVAL_FS_BACKEND", None)
    os.environ.pop("MCP_EVAL_REAL_CMD", None)
    os.environ.pop("MCP_EVAL_REAL_ARGS", None)


if __name__ == "__main__":
    main()
