"""单 task 执行编排:建临时 workspace → 跑 runner(其内部起 mock server)→ 归并双层 trace。

隔离:每个 run 一个独立 workspace 目录(runs/<run_id>/workspace),不碰用户真实环境;run
结束后 workspace 原样留存作为快照,供后续 validator 检查最终状态。
"""
from __future__ import annotations

import uuid
from pathlib import Path

from mcp_eval import trace
from mcp_eval.runner import AgentRunner, RunContext

PROJECT_ROOT = Path(__file__).resolve().parents[2]  # ~/mcp-eval
RUNS_DIR = PROJECT_ROOT / "runs"


def run_task(task, runner: AgentRunner) -> trace.TraceRecord:
    run_id = uuid.uuid4().hex[:12]
    run_dir = RUNS_DIR / run_id
    workspace = run_dir / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    task.setup_workspace(workspace)

    ctx = RunContext(
        run_id=run_id,
        task=task,
        workspace=workspace,
        trace_dir=run_dir,
        project_root=PROJECT_ROOT,
        server_specs=task.server_specs(),
    )
    final_answer = runner.run(ctx)

    record = trace.merge(
        ctx.server_jsonls,
        ctx.agent_jsonl,
        run_id=run_id,
        task_id=task.task_id,
        agent_id=runner.agent_id,
        workspace_snapshot=str(workspace),
        final_answer=final_answer,
    )
    record.save(run_dir / "trace.json")
    return record
