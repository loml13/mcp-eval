"""跑 C1 benchmark 矩阵,出 leaderboard + failure taxonomy 报告。

用法:
  uv run python scripts/run_benchmark.py --no-claude          # 仅 scripted(快、不花额度)
  uv run python scripts/run_benchmark.py --reps 1 --k-claude 1  # 含真实 claude-code
  uv run python scripts/run_benchmark.py --category injection   # 只跑某类
  uv run python scripts/run_benchmark.py --model sonnet --model opus  # 多 Claude 模型同台
  DEEPSEEK_KEY=... uv run python scripts/run_benchmark.py --no-claude \
      --api deepseek,https://api.deepseek.com,deepseek-v4-pro    # OpenAI 兼容 API(key 从 DEEPSEEK_KEY env)

增量加模型(不重跑已测):单模型跑 + --no-scripted 出独立 report,再 merge_reports.py 合并:
  KIMI_KEY=... uv run python scripts/run_benchmark.py --no-claude --no-scripted \
      --api kimi,https://api.moonshot.cn/v1,kimi-k2.6
  uv run python scripts/merge_reports.py runs/_reports/A.json runs/_reports/B.json
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from mcp_eval.benchmark import BenchmarkRunner
from mcp_eval.runners.claude_code import ClaudeCodeRunner
from mcp_eval.runners.scripted_agent import ScriptedAgentRunner
from mcp_eval.tasks.registry import ALL_TASK_FACTORIES

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _arg(flag: str, default: str | None = None) -> str | None:
    if flag in sys.argv:
        i = sys.argv.index(flag)
        return sys.argv[i + 1] if i + 1 < len(sys.argv) else default
    return default


def _args_multi(flag: str) -> list[str]:
    return [sys.argv[i + 1] for i, a in enumerate(sys.argv)
            if a == flag and i + 1 < len(sys.argv)]


def main() -> None:
    reps = int(_arg("--reps", "1"))
    k_claude = int(_arg("--k-claude", "1"))
    no_claude = "--no-claude" in sys.argv
    no_scripted = "--no-scripted" in sys.argv
    category = _arg("--category")
    # --fs-backend mock|real:切换 fs server 实现(mock=默认,real=真实 server-filesystem proxy)
    fs_backend = _arg("--fs-backend", "mock")
    os.environ["MCP_EVAL_FS_BACKEND"] = fs_backend
    # --model 可重复:多个 Claude 模型同台(如 --model sonnet --model opus)。
    claude_models = _args_multi("--model")

    factories = ALL_TASK_FACTORIES
    if category:
        factories = [f for f in factories if getattr(f, "category", None) == category
                     or getattr(f(), "category", None) == category]
    # --tasks t1,t2,... 定点跑指定 task_id(补跑被污染/失败的子集;新 run_id,merge 时替换旧 cell)。
    tasks_arg = _arg("--tasks")
    if tasks_arg:
        want = {t.strip() for t in tasks_arg.split(",") if t.strip()}
        factories = [f for f in factories if f().task_id in want]

    # scripted 是确定性上下界锚点;增量加模型(单模型跑后 merge)时用 --no-scripted 跳过。
    runners: list = [] if no_scripted else [ScriptedAgentRunner("safe")]
    per_runner_k: dict[str, int] = {}
    if not no_claude:
        # 无 --model → 退化为单个走 CLI 默认模型的 ClaudeCodeRunner(向后兼容)。
        for m in (claude_models or [None]):
            claude = ClaudeCodeRunner(model=m)
            runners.append(claude)
            per_runner_k[claude.agent_id] = k_claude

    # codex 被测对象:--codex(空 cwd 隔离 + 复制 auth,见 CodexRunner)
    if "--codex" in sys.argv:
        from mcp_eval.runners.codex_runner import CodexRunner
        cdx = CodexRunner()
        runners.append(cdx)
        per_runner_k[cdx.agent_id] = k_claude

    # OpenAI 兼容 API 模型:--api label,base_url,model(可重复);key 从环境变量 <LABEL>_KEY 读
    for spec in _args_multi("--api"):
        label, base, api_model = (s.strip() for s in spec.split(",", 2))
        key = os.environ.get(f"{label.upper()}_KEY", "")
        if not key:
            print(f"warn: 环境变量 {label.upper()}_KEY 未设,跳过 {label}")
            continue
        from mcp_eval.runners.api_agent import ApiAgentRunner
        api_runner = ApiAgentRunner(model=api_model, base_url=base, api_key=key, label=label)
        runners.append(api_runner)
        per_runner_k[api_runner.agent_id] = k_claude

    if not runners:
        print("没有可跑的 runner(--no-claude + --no-scripted 且未指定 --api/--codex)")
        sys.exit(1)

    bench = BenchmarkRunner(factories, runners, repetitions=reps, per_runner_k=per_runner_k)
    ts = _arg("--out") or time.strftime("%Y%m%d-%H%M%S")  # --out 自定报告名(并行跑避免撞名)
    print(f"跑 {len(factories)} 任务 × {len(runners)} agent  (scripted reps={reps}"
          f"{'' if no_claude else f', claude k={k_claude}'}) ...")
    report = bench.run(timestamp=ts)

    out_dir = PROJECT_ROOT / "runs" / "_reports"
    json_path, md_path = report.save(out_dir)
    print("\n" + report.to_markdown())
    print(f"\n报告已落盘:\n  {json_path}\n  {md_path}")


if __name__ == "__main__":
    main()
