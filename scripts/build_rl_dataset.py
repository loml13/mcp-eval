"""
Track E v0 — RL 数据集构建器 (借 Toolathlon 自带 evaluation 标签当 reward)

数据来源:
  Toolathlon-Trajectories (hkust-nlp/Toolathlon-Trajectories, CC-BY-4.0)
  17 个模型在 108 个长程 MCP 任务上的执行轨迹。

许可说明:
  原始数据集采用 CC-BY-4.0 协议。本脚本生成的派生数据集继承该协议,
  使用时须保留出处声明。

Track E 说明:
  v0: 直接使用 Toolathlon 数据集中的 evaluation 字段作为 reward 标签。
      后续版本将替换为 mcp-eval validator 给分。
  产出三份文件:
    - rollouts.jsonl    统一 rollout schema (所有有效记录)
    - preference_pairs.jsonl  DPO 偏好对 (pass × fail 笛卡尔积)
    - sft.jsonl         SFT best-of-N (每 task cost 最低的 pass)
    - stats.json        数据集统计

用法:
    uv run python scripts/build_rl_dataset.py [--in-dir DIR] [--out-dir DIR]
                                               [--max-pairs-per-task N]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# 解析工具
# ---------------------------------------------------------------------------

def _maybe_parse(v):
    """若 v 是 str 则 json.loads,否则原样返回。double-parse 用。"""
    if isinstance(v, str):
        return json.loads(v)
    return v


def parse_record(raw: dict) -> dict | None:
    """
    解析一条原始 record,返回统一 rollout dict;
    遇到以下情况返回 None(调用方统计后跳过):
      - messages 为 None 或解析失败
      - 必要字段缺失
    """
    # --- messages ---
    try:
        messages = _maybe_parse(raw.get("messages"))
    except (json.JSONDecodeError, TypeError):
        messages = None
    if not messages:          # None 或空 list 均跳过
        return None

    # --- task_status ---
    try:
        task_status = _maybe_parse(raw.get("task_status"))
    except (json.JSONDecodeError, TypeError):
        task_status = None
    evaluation: bool | None = task_status.get("evaluation") if task_status else None

    # --- tool_calls (工具定义清单) ---
    try:
        tc_raw = _maybe_parse(raw.get("tool_calls"))
        tools: list = tc_raw.get("tools", []) if tc_raw else []
    except (json.JSONDecodeError, TypeError):
        tools = []

    # --- agent_cost ---
    try:
        cost_raw = _maybe_parse(raw.get("agent_cost"))
        cost: float = float(cost_raw.get("total_cost", 0.0)) if cost_raw else 0.0
    except (json.JSONDecodeError, TypeError, ValueError):
        cost = 0.0

    # --- key_stats ---
    try:
        ks = _maybe_parse(raw.get("key_stats"))
        turns: int = int(ks.get("total_turns", 0)) if ks else 0
        n_tool_calls: int = int(ks.get("tool_calls", 0)) if ks else 0
    except (json.JSONDecodeError, TypeError, ValueError):
        turns = 0
        n_tool_calls = 0

    # --- model / run 从 modelname_run 拆分 ---
    modelname_run: str = raw.get("modelname_run", "")
    if "_" in modelname_run:
        # 尾部 _<run号> 拆分,run 号可能多位数
        parts = modelname_run.rsplit("_", 1)
        model_name = parts[0]
        try:
            run = int(parts[1])
        except ValueError:
            run = 0
    else:
        model_name = modelname_run
        run = 0

    return {
        "task_name": raw.get("task_name", ""),
        "model": model_name,
        "run": run,
        "evaluation": evaluation,
        "cost": cost,
        "turns": turns,
        "n_tool_calls": n_tool_calls,
        "messages": messages,
        "tools": tools,
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def build_dataset(
    in_dir: Path,
    out_dir: Path,
    max_pairs_per_task: int = 20,
) -> dict:
    """
    读取 in_dir/*.jsonl → 解析 → 输出 rollouts / preference_pairs / sft。
    返回 stats dict。
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- 读取 & 解析 ----
    jsonl_files = sorted(in_dir.glob("*.jsonl"))
    if not jsonl_files:
        print(f"[警告] {in_dir} 下未找到任何 *.jsonl 文件", file=sys.stderr)

    total_raw = 0
    parse_errors = 0      # json.loads 失败
    skipped_none_msg = 0  # messages 为 None
    rollouts: list[dict] = []

    for fpath in jsonl_files:
        with open(fpath, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                total_raw += 1
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    parse_errors += 1
                    print(
                        f"[跳过] {fpath.name}:{lineno} JSON 解析失败: {exc}",
                        file=sys.stderr,
                    )
                    continue
                result = parse_record(raw)
                if result is None:
                    skipped_none_msg += 1
                    print(
                        f"[跳过] {fpath.name}:{lineno} task={raw.get('task_name','')} "
                        f"messages=None/空",
                        file=sys.stderr,
                    )
                    continue
                rollouts.append(result)

    # ---- 写 rollouts.jsonl ----
    rollouts_path = out_dir / "rollouts.jsonl"
    with open(rollouts_path, "w", encoding="utf-8") as f:
        for r in rollouts:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # ---- 统计 pass/fail/None 分布 ----
    n_pass = sum(1 for r in rollouts if r["evaluation"] is True)
    n_fail = sum(1 for r in rollouts if r["evaluation"] is False)
    n_eval_none = sum(1 for r in rollouts if r["evaluation"] is None)

    # ---- 每模型 pass 率 ----
    model_pass: dict[str, int] = defaultdict(int)
    model_total: dict[str, int] = defaultdict(int)
    for r in rollouts:
        model_total[r["model"]] += 1
        if r["evaluation"] is True:
            model_pass[r["model"]] += 1
    model_pass_rate = {
        m: round(model_pass[m] / model_total[m], 4) if model_total[m] else 0.0
        for m in model_total
    }

    # ---- 按 task 分组 ----
    task_pass: dict[str, list[dict]] = defaultdict(list)
    task_fail: dict[str, list[dict]] = defaultdict(list)
    all_tasks: set[str] = set()
    for r in rollouts:
        all_tasks.add(r["task_name"])
        if r["evaluation"] is True:
            task_pass[r["task_name"]].append(r)
        elif r["evaluation"] is False:
            task_fail[r["task_name"]].append(r)

    tasks_with_pass = set(task_pass.keys())
    tasks_all_fail = all_tasks - tasks_with_pass
    coverage = round(len(tasks_with_pass) / len(all_tasks), 4) if all_tasks else 0.0

    # ---- DPO 偏好对 ----
    pairs: list[dict] = []
    total_pairs_discarded = 0
    tasks_no_pair = 0

    for task_name in sorted(all_tasks):
        passes = task_pass.get(task_name, [])
        fails = task_fail.get(task_name, [])
        if not passes or not fails:
            tasks_no_pair += 1
            continue

        # 找 prompt:第一条 user message + tools schema (用 pass 记录的,各 pass 共享同一 task)
        first_pass = passes[0]
        user_msgs = [m for m in first_pass["messages"] if m.get("role") == "user"]
        prompt_msg = user_msgs[0]["content"] if user_msgs else ""
        tools_schema = first_pass["tools"]

        # 笛卡尔积
        cart: list[tuple[dict, dict]] = []
        for p in passes:
            for fl in fails:
                cart.append((p, fl))

        if len(cart) > max_pairs_per_task:
            discarded = len(cart) - max_pairs_per_task
            total_pairs_discarded += discarded
            print(
                f"[截断] task={task_name}: 笛卡尔积 {len(cart)} 对,"
                f" 保留 {max_pairs_per_task},丢弃 {discarded}",
                file=sys.stderr,
            )
            cart = cart[:max_pairs_per_task]

        for p, fl in cart:
            pairs.append(
                {
                    "task_name": task_name,
                    "prompt": {
                        "user_message": prompt_msg,
                        "tools": tools_schema,
                    },
                    "chosen": p["messages"],
                    "rejected": fl["messages"],
                    "chosen_model": p["model"],
                    "rejected_model": fl["model"],
                    "chosen_cost": p["cost"],
                    "rejected_cost": fl["cost"],
                }
            )

    pairs_path = out_dir / "preference_pairs.jsonl"
    with open(pairs_path, "w", encoding="utf-8") as f:
        for pair in pairs:
            f.write(json.dumps(pair, ensure_ascii=False) + "\n")

    # ---- SFT best-of-N (cost 最低的 pass) ----
    sft: list[dict] = []
    for task_name in sorted(tasks_with_pass):
        passes = task_pass[task_name]
        best = min(passes, key=lambda r: r["cost"])
        sft.append(
            {
                "task_name": task_name,
                "model": best["model"],
                "messages": best["messages"],
                "cost": best["cost"],
            }
        )

    sft_path = out_dir / "sft.jsonl"
    with open(sft_path, "w", encoding="utf-8") as f:
        for s in sft:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    # ---- 统计汇总 ----
    overall_pass_rate = round(n_pass / len(rollouts), 4) if rollouts else 0.0
    stats = {
        "source": "hkust-nlp/Toolathlon-Trajectories (CC-BY-4.0)",
        "track": "Track E v0",
        "input_files": [str(p) for p in jsonl_files],
        "total_raw_lines": total_raw,
        "parse_errors": parse_errors,
        "skipped_none_messages": skipped_none_msg,
        "total_rollouts": len(rollouts),
        "evaluation_distribution": {
            "pass": n_pass,
            "fail": n_fail,
            "none": n_eval_none,
        },
        "overall_pass_rate": overall_pass_rate,
        "label_skew_warning": (
            f"pass 稀疏: {n_pass}/{len(rollouts)} = {overall_pass_rate:.1%}; "
            f"全 fail 的 task(出不了偏好对): {len(tasks_all_fail)}/{len(all_tasks)}"
        ),
        "model_pass_rate": model_pass_rate,
        "tasks": {
            "total": len(all_tasks),
            "with_pass": len(tasks_with_pass),
            "all_fail_no_pair": len(tasks_all_fail),
            "coverage": coverage,
        },
        "preference_pairs": {
            "total": len(pairs),
            "discarded_by_truncation": total_pairs_discarded,
            "max_pairs_per_task": max_pairs_per_task,
        },
        "sft_samples": len(sft),
    }

    stats_path = out_dir / "stats.json"
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    return stats


def print_stats(stats: dict) -> None:
    """打印关键统计到 stdout。"""
    ev = stats["evaluation_distribution"]
    t = stats["tasks"]
    pp = stats["preference_pairs"]
    print("=" * 60)
    print("Track E v0 — RL 数据集构建完成")
    print("=" * 60)
    print(f"输入文件数:     {len(stats['input_files'])}")
    print(f"原始行数:       {stats['total_raw_lines']}")
    print(f"JSON 解析失败:  {stats['parse_errors']}")
    print(f"messages=None 跳过: {stats['skipped_none_messages']}")
    print(f"有效 rollout:   {stats['total_rollouts']}")
    print(f"  pass:  {ev['pass']}  fail: {ev['fail']}  eval=None: {ev['none']}")
    print(f"  总体 pass 率: {stats['overall_pass_rate']:.1%}")
    print(f"[!] {stats['label_skew_warning']}")
    print()
    print("每模型 pass 率:")
    for m, r in sorted(stats["model_pass_rate"].items()):
        print(f"  {m}: {r:.1%}")
    print()
    print(f"Task 覆盖率:    {t['with_pass']}/{t['total']} = {t['coverage']:.1%}")
    print(f"  全 fail(无偏好对): {t['all_fail_no_pair']} tasks")
    print(f"DPO 偏好对:     {pp['total']}  (截断丢弃 {pp['discarded_by_truncation']})")
    print(f"SFT 样本数:     {stats['sft_samples']}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="构建 Track E v0 RL 数据集 (Toolathlon-Trajectories → rollouts/DPO/SFT)"
    )
    parser.add_argument(
        "--in-dir",
        type=Path,
        default=Path("data/toolathlon_trajectories"),
        help="输入 *.jsonl 目录 (默认 data/toolathlon_trajectories)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("data/rl"),
        help="输出目录 (默认 data/rl)",
    )
    parser.add_argument(
        "--max-pairs-per-task",
        type=int,
        default=20,
        help="每个 task 最多保留的偏好对数量 (默认 20)",
    )
    args = parser.parse_args()

    stats = build_dataset(
        in_dir=args.in_dir,
        out_dir=args.out_dir,
        max_pairs_per_task=args.max_pairs_per_task,
    )
    print_stats(stats)


if __name__ == "__main__":
    main()
