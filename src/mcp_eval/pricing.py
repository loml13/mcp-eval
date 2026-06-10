"""模型定价单一真相源 —— 用于估算 USD cost/task。

价格快照日期: 2026-06
来源: 各厂商官网估算(Anthropic/OpenAI/各 CN 厂商公开价格页)
CN 模型 RMB→USD 按固定 FX = 7.20
口径声明:
  - tokens_in / tokens_out 均为每 1M token 的 USD 价格
  - cache_read / cache_write 仅 Claude 系列有效(Anthropic prompt caching 分档)
  - 非 Claude 模型 cache_read=cache_write=0 → 退化为 in*input_price + out*output_price
  - 这些价格是估算占位,生产评测前请核准最新官网定价

警告: 这些是 2026-06 估算值,模型价格随时会调整。
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ModelPrice:
    """USD per 1M tokens 的单价。"""
    input: float   # 普通 input token 单价
    output: float  # output token 单价
    cache_read: float = 0.0   # Anthropic 缓存读 ~0.1× input
    cache_write: float = 0.0  # Anthropic 缓存写 ~1.25× input


# FX 汇率:RMB → USD(固定估算)
_FX_RMB_TO_USD = 1.0 / 7.20


# 规范化定价键 -> 单价
# 价格单位: USD / 1M tokens
PRICING: dict[str, ModelPrice] = {
    # ---- Anthropic Claude ----
    # 来源: anthropic.com/pricing(估算,2026-06)
    "claude-opus": ModelPrice(
        input=15.0,
        output=75.0,
        cache_read=1.50,    # ~0.10× input
        cache_write=18.75,  # ~1.25× input
    ),
    "claude-sonnet": ModelPrice(
        input=3.0,
        output=15.0,
        cache_read=0.30,    # ~0.10× input
        cache_write=3.75,   # ~1.25× input
    ),
    # ---- OpenAI (Codex 后端) ----
    # 来源: openai.com/pricing(估算,2026-06)
    "gpt-5.5": ModelPrice(
        input=5.0,
        output=20.0,
    ),
    # ---- CN 模型(RMB 官网价 ÷ FX 7.20 转 USD) ----
    # Qwen3.7-Max: 阿里云 DashScope 官网估算
    "qwen3.7-max": ModelPrice(
        input=round(2.8 * _FX_RMB_TO_USD, 4),   # ¥2.8 / 1M → ~$0.389
        output=round(11.2 * _FX_RMB_TO_USD, 4),  # ¥11.2 / 1M → ~$1.556
    ),
    # Mimo v2.5 Pro: ModelBest 官网估算
    "mimo-v2.5-pro": ModelPrice(
        input=round(4.0 * _FX_RMB_TO_USD, 4),    # ¥4.0 / 1M → ~$0.556
        output=round(16.0 * _FX_RMB_TO_USD, 4),  # ¥16.0 / 1M → ~$2.222
    ),
    # GLM-5.1: 智谱 AI 官网估算
    "glm-5.1": ModelPrice(
        input=round(5.0 * _FX_RMB_TO_USD, 4),    # ¥5.0 / 1M → ~$0.694
        output=round(20.0 * _FX_RMB_TO_USD, 4),  # ¥20.0 / 1M → ~$2.778
    ),
    # Kimi k2.6: Moonshot AI 官网估算
    "kimi-k2.6": ModelPrice(
        input=round(4.0 * _FX_RMB_TO_USD, 4),    # ¥4.0 / 1M → ~$0.556
        output=round(16.0 * _FX_RMB_TO_USD, 4),  # ¥16.0 / 1M → ~$2.222
    ),
    # MiniMax-M3: MiniMax 官网估算
    "MiniMax-M3": ModelPrice(
        input=round(3.5 * _FX_RMB_TO_USD, 4),    # ¥3.5 / 1M → ~$0.486
        output=round(14.0 * _FX_RMB_TO_USD, 4),  # ¥14.0 / 1M → ~$1.944
    ),
    # DeepSeek-v4-Pro: DeepSeek 官网估算
    "deepseek-v4-pro": ModelPrice(
        input=round(2.0 * _FX_RMB_TO_USD, 4),    # ¥2.0 / 1M → ~$0.278
        output=round(8.0 * _FX_RMB_TO_USD, 4),   # ¥8.0 / 1M → ~$1.111
    ),
}

# 真实运行时的短 label(--api <label> 直接用,见 run_benchmark.py;merge 后的报告里也是短名)
# → PRICING 键。精确/前缀匹配,先于全名子串匹配。这是 C3 报告里 agent_id 的实际形态。
_LABEL_ALIASES: dict[str, str] = {
    "glm": "glm-5.1",
    "qwen": "qwen3.7-max",
    "kimi": "kimi-k2.6",
    "minimax": "MiniMax-M3",
    "mimo": "mimo-v2.5-pro",
    "deepseek": "deepseek-v4-pro",
    "opus": "claude-opus",
    "sonnet": "claude-sonnet",
}

# agent_id 内层 model 子串 → PRICING key 的映射(子串匹配,最长优先)
_INNER_ALIASES: list[tuple[str, str]] = [
    ("opus",          "claude-opus"),
    ("sonnet",        "claude-sonnet"),
    ("gpt-5.5",       "gpt-5.5"),
    ("qwen3.7-max",   "qwen3.7-max"),
    ("mimo-v2.5-pro", "mimo-v2.5-pro"),
    ("glm-5.1",       "glm-5.1"),
    ("kimi-k2.6",     "kimi-k2.6"),
    ("MiniMax-M3",    "MiniMax-M3"),
    ("minimax-m3",    "MiniMax-M3"),
    ("deepseek-v4-pro", "deepseek-v4-pro"),
]

# 剥 runner 外壳的正则:claude-code(...)、api(...)、codex(...)
_WRAPPER_RE = re.compile(r"^(?:claude-code|api|codex)\((.+)\)$", re.IGNORECASE)


def price_key(agent_id: str) -> str | None:
    """agent_id → PRICING 键。

    支持形态:
      - 'claude-opus' / 'claude-sonnet' / 'codex' / ... → 直接命中 PRICING
      - 'claude-code(opus 4.8)' / 'claude-code(sonnet)' → 剥壳取内层
      - 'api(deepseek-v4-pro)' / 'codex(gpt-5.5)' → 剥壳取内层
      - 'codex'(无括号) → 'gpt-5.5'(Codex 后端固定 gpt-5.5)
      - 'scripted' / 未知 → None
    """
    if not agent_id:
        return None

    # 1. 短名直接命中 PRICING(含大小写原样)
    if agent_id in PRICING:
        return agent_id

    # 2. 特殊:裸 'codex'(无括号)
    if agent_id.lower() == "codex":
        return "gpt-5.5"

    # 3. 剥 runner 外壳取内层 model 字符串
    m = _WRAPPER_RE.match(agent_id)
    if m:
        inner = m.group(1).strip()
    else:
        # 4. 无外壳但也不在 PRICING —— 对内层做子串匹配(容错短名如 'claude-sonnet')
        inner = agent_id

    # 内层直接命中
    if inner in PRICING:
        return inner

    inner_lower = inner.lower()
    # 短 label 精确或前缀匹配(glm / qwen / deepseek ... 以及 claude-code(opus) 内层 'opus')
    for short, key in _LABEL_ALIASES.items():
        if inner_lower == short or inner_lower.startswith(short):
            return key
    # 全名子串匹配(claude-code(opus 4.8) 内层含 'opus'、api(qwen3.7-max) 内层含全名等)
    for substr, key in _INNER_ALIASES:
        if substr.lower() in inner_lower:
            return key

    return None


def estimate_cost_usd(
    key: str | None,
    tokens_in: int,
    tokens_out: int,
    cache_read: int = 0,
    cache_write: int = 0,
) -> float | None:
    """估算 USD 成本。

    无 key → None(报告渲染 '—',绝不填 0 假装已知)。
    成本 = 非缓存 input*input_price + output*output_price
           + cache_read*cache_read_price + cache_write*cache_write_price
    各项 token / 1e6 * 单价(USD/1M)。
    非 Claude 模型 cache_read=cache_write=0 → 自然退化为 in*input + out*output。
    """
    if key is None:
        return None
    mp = PRICING.get(key)
    if mp is None:
        return None

    cost = (
        tokens_in   / 1_000_000 * mp.input
        + tokens_out  / 1_000_000 * mp.output
        + cache_read  / 1_000_000 * mp.cache_read
        + cache_write / 1_000_000 * mp.cache_write
    )
    return cost
