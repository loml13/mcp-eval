"""tests/test_pricing.py — pricing.price_key + estimate_cost_usd 的覆盖测试。

覆盖:
1. price_key:全部 agent_id 形态(claude-code(...)/claude-opus/api(...)/codex(...)/codex/scripted/未知)
2. estimate_cost_usd:Claude 缓存分档算术;非 Claude 退化(cache_*=0);None key → None 传播
"""
from __future__ import annotations

import pytest

from mcp_eval.pricing import PRICING, ModelPrice, estimate_cost_usd, price_key


# ---- price_key:agent_id 形态全覆盖 ----------------------------------------

class TestPriceKey:
    def test_short_name_claude_opus(self):
        assert price_key("claude-opus") == "claude-opus"

    def test_short_name_claude_sonnet(self):
        assert price_key("claude-sonnet") == "claude-sonnet"

    def test_short_name_deepseek(self):
        assert price_key("deepseek-v4-pro") == "deepseek-v4-pro"

    def test_claude_code_opus_with_version(self):
        """claude-code(opus 4.8) → claude-opus"""
        assert price_key("claude-code(opus 4.8)") == "claude-opus"

    def test_claude_code_opus_short(self):
        """claude-code(opus) → claude-opus"""
        assert price_key("claude-code(opus)") == "claude-opus"

    def test_claude_code_sonnet(self):
        """claude-code(sonnet) → claude-sonnet"""
        assert price_key("claude-code(sonnet)") == "claude-sonnet"

    def test_claude_code_sonnet_with_version(self):
        """claude-code(claude-sonnet-4-5) → claude-sonnet"""
        assert price_key("claude-code(claude-sonnet-4-5)") == "claude-sonnet"

    def test_api_deepseek(self):
        """api(deepseek-v4-pro) → deepseek-v4-pro"""
        assert price_key("api(deepseek-v4-pro)") == "deepseek-v4-pro"

    def test_api_qwen(self):
        """api(qwen3.7-max) → qwen3.7-max"""
        assert price_key("api(qwen3.7-max)") == "qwen3.7-max"

    def test_api_mimo(self):
        """api(mimo-v2.5-pro) → mimo-v2.5-pro"""
        assert price_key("api(mimo-v2.5-pro)") == "mimo-v2.5-pro"

    def test_api_glm(self):
        """api(glm-5.1) → glm-5.1"""
        assert price_key("api(glm-5.1)") == "glm-5.1"

    def test_api_kimi(self):
        """api(kimi-k2.6) → kimi-k2.6"""
        assert price_key("api(kimi-k2.6)") == "kimi-k2.6"

    def test_api_minimax(self):
        """api(MiniMax-M3) → MiniMax-M3"""
        assert price_key("api(MiniMax-M3)") == "MiniMax-M3"

    def test_codex_with_model(self):
        """codex(gpt-5.5) → gpt-5.5"""
        assert price_key("codex(gpt-5.5)") == "gpt-5.5"

    def test_codex_bare(self):
        """裸 codex(无括号) → gpt-5.5(Codex 后端固定)"""
        assert price_key("codex") == "gpt-5.5"

    def test_real_short_api_labels(self):
        """C3 报告里 API 模型的实际 agent_id 是短 label(--api <label> 直接用),
        非全名。映射必须覆盖这些真实 label,否则 cost 列全 '—'(本次 review 逮到的 bug)。"""
        assert price_key("glm") == "glm-5.1"
        assert price_key("qwen") == "qwen3.7-max"
        assert price_key("kimi") == "kimi-k2.6"
        assert price_key("minimax") == "MiniMax-M3"
        assert price_key("mimo") == "mimo-v2.5-pro"
        assert price_key("deepseek") == "deepseek-v4-pro"

    def test_scripted_returns_none(self):
        assert price_key("scripted") is None

    def test_unknown_string_returns_none(self):
        assert price_key("some-unknown-model-xyz") is None

    def test_empty_string_returns_none(self):
        assert price_key("") is None

    def test_all_pricing_keys_resolvable(self):
        """PRICING 里每个 key 自身就能命中 price_key(自洽校验)。"""
        for key in PRICING:
            assert price_key(key) == key, f"PRICING key {key!r} 无法被 price_key 解析"


# ---- estimate_cost_usd:算术正确性 ------------------------------------------

class TestEstimateCostUsd:
    def test_none_key_returns_none(self):
        """无 key → None,不填 0"""
        result = estimate_cost_usd(None, 1000, 500)
        assert result is None

    def test_unknown_key_returns_none(self):
        """未知 key → None"""
        result = estimate_cost_usd("nonexistent-model", 1000, 500)
        assert result is None

    def test_claude_sonnet_no_cache(self):
        """claude-sonnet,无 cache:cost = in/1M*3.0 + out/1M*15.0"""
        mp = PRICING["claude-sonnet"]
        tokens_in = 100_000
        tokens_out = 20_000
        expected = tokens_in / 1_000_000 * mp.input + tokens_out / 1_000_000 * mp.output
        result = estimate_cost_usd("claude-sonnet", tokens_in, tokens_out)
        assert result is not None
        assert abs(result - expected) < 1e-9

    def test_claude_opus_with_cache(self):
        """claude-opus 带 cache_read + cache_write,分档算术全正确。"""
        mp = PRICING["claude-opus"]
        tokens_in = 50_000
        tokens_out = 10_000
        cache_read = 200_000
        cache_write = 30_000
        expected = (
            tokens_in   / 1_000_000 * mp.input
            + tokens_out  / 1_000_000 * mp.output
            + cache_read  / 1_000_000 * mp.cache_read
            + cache_write / 1_000_000 * mp.cache_write
        )
        result = estimate_cost_usd("claude-opus", tokens_in, tokens_out, cache_read, cache_write)
        assert result is not None
        assert abs(result - expected) < 1e-9

    def test_claude_cache_cheaper_than_no_cache(self):
        """cache_read 价格低于 input 价格:有 cache 读时总 cost 应小于全量 input 计算。"""
        mp = PRICING["claude-sonnet"]
        assert mp.cache_read < mp.input, "cache_read 应比 input 便宜(定价文件需核查)"
        # 有 cache_read,无新 input
        cost_cached = estimate_cost_usd("claude-sonnet", 0, 10_000, cache_read=100_000)
        cost_full = estimate_cost_usd("claude-sonnet", 100_000, 10_000)
        assert cost_cached < cost_full

    def test_non_claude_cache_ignored(self):
        """非 Claude 模型 cache_* 定价为 0,传入也无效。"""
        mp = PRICING["deepseek-v4-pro"]
        assert mp.cache_read == 0.0 and mp.cache_write == 0.0
        cost_no_cache = estimate_cost_usd("deepseek-v4-pro", 100_000, 50_000)
        cost_with_cache = estimate_cost_usd("deepseek-v4-pro", 100_000, 50_000, 10_000, 5_000)
        assert cost_no_cache is not None
        assert abs(cost_no_cache - cost_with_cache) < 1e-9

    def test_zero_tokens_returns_zero(self):
        """全零 token → cost = 0.0(不是 None)"""
        result = estimate_cost_usd("claude-sonnet", 0, 0, 0, 0)
        assert result == 0.0

    def test_gpt_55_basic(self):
        """gpt-5.5 基础算术"""
        mp = PRICING["gpt-5.5"]
        tokens_in = 80_000
        tokens_out = 15_000
        expected = tokens_in / 1_000_000 * mp.input + tokens_out / 1_000_000 * mp.output
        result = estimate_cost_usd("gpt-5.5", tokens_in, tokens_out)
        assert result is not None
        assert abs(result - expected) < 1e-9

    def test_all_cn_models_have_positive_prices(self):
        """CN 模型不留 0 真价(架构师约定)。"""
        cn_models = ["qwen3.7-max", "mimo-v2.5-pro", "glm-5.1", "kimi-k2.6",
                     "MiniMax-M3", "deepseek-v4-pro"]
        for key in cn_models:
            mp = PRICING[key]
            assert mp.input > 0, f"{key} input 价格为 0"
            assert mp.output > 0, f"{key} output 价格为 0"

    def test_cost_scales_linearly(self):
        """成本与 token 数线性:token 翻倍 → cost 翻倍。"""
        key = "claude-sonnet"
        c1 = estimate_cost_usd(key, 10_000, 5_000)
        c2 = estimate_cost_usd(key, 20_000, 10_000)
        assert c1 is not None and c2 is not None
        assert abs(c2 - 2 * c1) < 1e-9
