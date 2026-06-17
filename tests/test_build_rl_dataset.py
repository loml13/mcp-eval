"""tests/test_build_rl_dataset.py — Track E v0 RL 数据集构建器的单元测试。

Fixture 说明:
  使用 inline 构造的 3 条 record,字段值均为「嵌套 JSON 字符串」以还原真实格式:
    record_pass   — evaluation=True,  messages 正常
    record_fail   — evaluation=False, messages 正常
    record_no_msg — messages 字段为 JSON null(→ 解析后 None),应被跳过
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# 把 scripts/ 加入 sys.path,不依赖 package install
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from build_rl_dataset import build_dataset, parse_record  # noqa: E402


# ---------------------------------------------------------------------------
# 辅助:构造 record 的原始字段(嵌套 JSON 字符串)
# ---------------------------------------------------------------------------

TOOLS_DEF = [
    {
        "type": "function",
        "function": {
            "name": "mock_tool",
            "description": "A mock tool",
            "parameters": {"type": "object", "properties": {}},
        },
    }
]

MESSAGES_PASS = [
    {"role": "user", "content": "Do task A"},
    {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "c1",
                "type": "function",
                "function": {"name": "mock_tool", "arguments": "{}"},
            }
        ],
    },
    {"role": "tool", "tool_call_id": "c1", "content": "result_A"},
    {"role": "assistant", "content": "Done with task A."},
]

MESSAGES_FAIL = [
    {"role": "user", "content": "Do task A"},
    {"role": "assistant", "content": "I failed."},
]


def _make_record(
    model_run: str,
    task: str,
    evaluation,
    messages,
    cost: float = 0.05,
    turns: int = 4,
    n_tc: int = 1,
) -> dict:
    """构造一条原始 record,模拟真实格式(嵌套 JSON 字符串)。"""
    task_status_val = json.dumps(
        {"preprocess": "done", "running": "done", "evaluation": evaluation}
    )
    messages_val = json.dumps(messages, ensure_ascii=False) if messages is not None else json.dumps(None)
    tool_calls_val = json.dumps({"tools": TOOLS_DEF, "tool_choice": "auto"})
    key_stats_val = json.dumps(
        {"interaction_turns": 1, "tool_calls": n_tc, "total_turns": turns, "total_messages": turns + 2}
    )
    agent_cost_val = json.dumps({"total_cost": cost, "total_input_tokens": 1000, "total_output_tokens": 100, "total_requests": 2})

    return {
        "modelname_run": model_run,
        "task_name": task,
        "task_status": task_status_val,
        "config": {},
        "request_id": "req-001",
        "initial_run_time": "2024-01-01T00:00:00",
        "completion_time": "2024-01-01T00:01:00",
        "tool_calls": tool_calls_val,
        "messages": messages_val,
        "key_stats": key_stats_val,
        "agent_cost": agent_cost_val,
    }


# 3 条 fixture records
RECORD_PASS = _make_record("model-A_1", "task_alpha", True, MESSAGES_PASS, cost=0.10)
RECORD_FAIL = _make_record("model-B_2", "task_alpha", False, MESSAGES_FAIL, cost=0.05)
RECORD_NO_MSG = _make_record("model-C_1", "task_beta", True, None, cost=0.20)


# ---------------------------------------------------------------------------
# Fixture:tmp 输入目录
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_in_dir(tmp_path: Path) -> Path:
    """写 3 条 records 到 tmp_path/input/test.jsonl。"""
    in_dir = tmp_path / "input"
    in_dir.mkdir()
    with open(in_dir / "test.jsonl", "w", encoding="utf-8") as f:
        for rec in [RECORD_PASS, RECORD_FAIL, RECORD_NO_MSG]:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return in_dir


@pytest.fixture()
def tmp_out_dir(tmp_path: Path) -> Path:
    return tmp_path / "output"


# ---------------------------------------------------------------------------
# 测试 1: double-parse 正确
# ---------------------------------------------------------------------------

class TestDoubleParse:
    def test_evaluation_parsed_correctly(self):
        r = parse_record(RECORD_PASS)
        assert r is not None
        assert r["evaluation"] is True

    def test_cost_parsed(self):
        r = parse_record(RECORD_PASS)
        assert abs(r["cost"] - 0.10) < 1e-9

    def test_turns_parsed(self):
        r = parse_record(RECORD_PASS)
        assert r["turns"] == 4

    def test_n_tool_calls_parsed(self):
        r = parse_record(RECORD_PASS)
        assert r["n_tool_calls"] == 1

    def test_tools_list_parsed(self):
        r = parse_record(RECORD_PASS)
        assert isinstance(r["tools"], list)
        assert len(r["tools"]) == 1
        assert r["tools"][0]["function"]["name"] == "mock_tool"

    def test_messages_is_list(self):
        r = parse_record(RECORD_PASS)
        assert isinstance(r["messages"], list)
        assert r["messages"][0]["role"] == "user"

    def test_model_run_split(self):
        r = parse_record(RECORD_PASS)
        assert r["model"] == "model-A"
        assert r["run"] == 1

    def test_model_run_split_multidigit(self):
        rec = _make_record("gpt-4o-mini_42", "t", True, MESSAGES_PASS)
        r = parse_record(rec)
        assert r["model"] == "gpt-4o-mini"
        assert r["run"] == 42


# ---------------------------------------------------------------------------
# 测试 2: None messages 被跳过
# ---------------------------------------------------------------------------

class TestSkipNoneMessages:
    def test_parse_record_returns_none(self):
        result = parse_record(RECORD_NO_MSG)
        assert result is None

    def test_rollout_count_excludes_none_msg(self, tmp_in_dir, tmp_out_dir):
        stats = build_dataset(tmp_in_dir, tmp_out_dir)
        assert stats["total_rollouts"] == 2   # PASS + FAIL only
        assert stats["skipped_none_messages"] == 1

    def test_rollouts_jsonl_count(self, tmp_in_dir, tmp_out_dir):
        build_dataset(tmp_in_dir, tmp_out_dir)
        lines = (tmp_out_dir / "rollouts.jsonl").read_text().strip().splitlines()
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# 测试 3: pass×fail 偏好对配对正确
# ---------------------------------------------------------------------------

class TestPreferencePairs:
    def test_one_pair_produced(self, tmp_in_dir, tmp_out_dir):
        stats = build_dataset(tmp_in_dir, tmp_out_dir)
        assert stats["preference_pairs"]["total"] == 1

    def test_chosen_is_pass(self, tmp_in_dir, tmp_out_dir):
        build_dataset(tmp_in_dir, tmp_out_dir)
        with open(tmp_out_dir / "preference_pairs.jsonl") as f:
            pair = json.loads(f.readline())
        # chosen 应来自 pass record: messages 更长
        assert pair["chosen_model"] == "model-A"
        assert pair["rejected_model"] == "model-B"
        # chosen messages 应包含 tool 调用
        roles = [m["role"] for m in pair["chosen"]]
        assert "tool" in roles

    def test_pair_has_prompt(self, tmp_in_dir, tmp_out_dir):
        build_dataset(tmp_in_dir, tmp_out_dir)
        with open(tmp_out_dir / "preference_pairs.jsonl") as f:
            pair = json.loads(f.readline())
        assert "user_message" in pair["prompt"]
        assert pair["prompt"]["user_message"] == "Do task A"

    def test_task_name_in_pair(self, tmp_in_dir, tmp_out_dir):
        build_dataset(tmp_in_dir, tmp_out_dir)
        with open(tmp_out_dir / "preference_pairs.jsonl") as f:
            pair = json.loads(f.readline())
        assert pair["task_name"] == "task_alpha"


# ---------------------------------------------------------------------------
# 测试 4: max-pairs-per-task 截断生效
# ---------------------------------------------------------------------------

class TestMaxPairsPerTask:
    @pytest.fixture()
    def many_records_dir(self, tmp_path: Path) -> Path:
        """构造 1 pass + 5 fail → 笛卡尔积 5 对,但 max=3 截断到 3。"""
        in_dir = tmp_path / "many_in"
        in_dir.mkdir()
        records = [_make_record("model-A_1", "task_z", True, MESSAGES_PASS, cost=0.1)]
        for i in range(5):
            records.append(
                _make_record(f"model-F{i}_1", "task_z", False, MESSAGES_FAIL, cost=0.05 * i)
            )
        with open(in_dir / "many.jsonl", "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        return in_dir

    def test_truncation_applied(self, many_records_dir, tmp_path):
        out = tmp_path / "many_out"
        stats = build_dataset(many_records_dir, out, max_pairs_per_task=3)
        assert stats["preference_pairs"]["total"] == 3

    def test_discarded_count(self, many_records_dir, tmp_path):
        out = tmp_path / "many_out2"
        stats = build_dataset(many_records_dir, out, max_pairs_per_task=3)
        assert stats["preference_pairs"]["discarded_by_truncation"] == 2

    def test_no_truncation_when_within_limit(self, many_records_dir, tmp_path):
        out = tmp_path / "many_out3"
        stats = build_dataset(many_records_dir, out, max_pairs_per_task=10)
        assert stats["preference_pairs"]["total"] == 5
        assert stats["preference_pairs"]["discarded_by_truncation"] == 0


# ---------------------------------------------------------------------------
# 测试 5: SFT 选 cost 最低的 pass
# ---------------------------------------------------------------------------

class TestSFT:
    @pytest.fixture()
    def multi_pass_dir(self, tmp_path: Path) -> Path:
        """同一 task 3 条 pass,cost 各不同,期望选最低的。"""
        in_dir = tmp_path / "sft_in"
        in_dir.mkdir()
        records = [
            _make_record("model-A_1", "task_x", True, MESSAGES_PASS, cost=0.30),
            _make_record("model-B_1", "task_x", True, MESSAGES_PASS, cost=0.05),  # cheapest
            _make_record("model-C_1", "task_x", True, MESSAGES_PASS, cost=0.15),
        ]
        with open(in_dir / "sft.jsonl", "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        return in_dir

    def test_sft_selects_cheapest(self, multi_pass_dir, tmp_path):
        out = tmp_path / "sft_out"
        stats = build_dataset(multi_pass_dir, out)
        assert stats["sft_samples"] == 1
        with open(out / "sft.jsonl") as f:
            entry = json.loads(f.readline())
        assert abs(entry["cost"] - 0.05) < 1e-9
        assert entry["model"] == "model-B"

    def test_sft_one_per_task(self, tmp_in_dir, tmp_out_dir):
        """task_alpha 有 1 pass,task_beta messages=None 被跳过 → SFT=1。"""
        stats = build_dataset(tmp_in_dir, tmp_out_dir)
        assert stats["sft_samples"] == 1

    def test_no_sft_for_all_fail_task(self, tmp_path):
        in_dir = tmp_path / "all_fail_in"
        in_dir.mkdir()
        records = [_make_record("model-A_1", "task_only_fail", False, MESSAGES_FAIL)]
        with open(in_dir / "af.jsonl", "w") as f:
            f.write(json.dumps(records[0]) + "\n")
        out = tmp_path / "all_fail_out"
        stats = build_dataset(in_dir, out)
        assert stats["sft_samples"] == 0


# ---------------------------------------------------------------------------
# 测试 6: stats.json 结构完整性
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_json_written(self, tmp_in_dir, tmp_out_dir):
        build_dataset(tmp_in_dir, tmp_out_dir)
        assert (tmp_out_dir / "stats.json").exists()

    def test_stats_has_required_keys(self, tmp_in_dir, tmp_out_dir):
        stats = build_dataset(tmp_in_dir, tmp_out_dir)
        for key in [
            "total_raw_lines", "parse_errors", "skipped_none_messages",
            "total_rollouts", "evaluation_distribution",
            "overall_pass_rate", "label_skew_warning",
            "model_pass_rate", "tasks", "preference_pairs", "sft_samples",
        ]:
            assert key in stats, f"缺少 key: {key}"

    def test_evaluation_distribution(self, tmp_in_dir, tmp_out_dir):
        stats = build_dataset(tmp_in_dir, tmp_out_dir)
        ev = stats["evaluation_distribution"]
        assert ev["pass"] == 1
        assert ev["fail"] == 1
        assert ev["none"] == 0

    def test_coverage_ratio(self, tmp_in_dir, tmp_out_dir):
        stats = build_dataset(tmp_in_dir, tmp_out_dir)
        t = stats["tasks"]
        # task_alpha 有 pass; task_beta 的 record 被跳过(messages=None) → task_beta 不计入 all_tasks
        assert t["with_pass"] == 1
        assert t["total"] == 1
        assert abs(t["coverage"] - 1.0) < 1e-9
