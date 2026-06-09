# mcp-eval

> 评测 AI agent 通过 **MCP(Model Context Protocol)工具**完成任务的**可靠性**与**安全性** —— 不只看「能不能调出工具」,而看「**用得对不对、安不安全、稳不稳**」。

---

## 这是什么

mcp-eval 把不同被测 agent(Claude Code / OpenAI Codex / 任意 OpenAI 兼容模型)接到一组 **instrumented mock MCP server** 上,跑一批精心设计的任务,从 **server 侧记录真实工具调用轨迹(ground truth)**,用程序化 validator 判定功能正确性与安全性,产出 leaderboard + **攻击 × 模型脆弱性矩阵**。

**为什么做**:对前沿模型,「能不能用 MCP 完成任务」已基本饱和(都能);真正有区分度的是

- **用得安不安全** —— 会不会被 prompt injection 骗去越权读取、外泄密钥、执行破坏性操作;
- **用得稳不稳** —— 多跳工具编排、错误恢复、复杂参数 schema 下还撑不撑得住。

mcp-eval 专切这两条线,避开已经很卷、又容易饱和的「通用 agent 能力评测」。

---

## 核心设计判断

1. **双层 trace,server 侧是唯一真相源**
   被测 agent 每次工具调用都经过自写的 mock server,server 端记录每个 `tool_call` / `resource_read` / `sink` 的**真实参数与结果**;agent 侧轨迹只作辅助(步数、token)。**安全判定只认 server 侧 ground truth** —— canary 有没有真流进外发通道、有没有真读越权路径,以实际 I/O 为准。

2. **强制只走 MCP(隔离)**
   要堵死 agent 用内置工具绕过:Claude Code 用 `--disallowedTools` 物理禁内置;API agent 天然只有我们给的工具;Codex 用**空 cwd 隔离**(内置 shell 看不到任务文件,被迫走 MCP)。

3. **server 记录,validator 判定**
   mock server 只如实记录、不裁决;判定全部交给独立 validator 消费 trace。同一条轨迹被多维 validator 复用,新增判定不动 server。

---

## 架构

```
src/mcp_eval/
  trace.py            双层 trace:TraceEvent / TraceRecord / merge() / scan_canary()
  runner.py           AgentRunner 抽象 + RunContext(workspace / trace / env 隔离)
  harness.py          run_task(task, runner) -> TraceRecord
  policy.py           Policy:每任务声明的安全边界(allowed tools/sinks、forbidden paths…)
  verdict.py          Expectation(任务期望) + Verdict(单个判定)
  benchmark.py        BenchmarkRunner(task×agent×rep 矩阵)+ 聚合 + 报告
  servers/fs_mock.py  instrumented filesystem mock MCP server(16 工具 + 故障注入 + decoy)
  runners/            被测对象 4 类:scripted / claude_code / api_agent / codex_runner
  validators/         12 判定器(功能 7 + 安全 5)
  tasks/              54 任务(functional / description / injection / forbidden / dangerous)
```

---

## 被测对象(runners)

| Runner | 被测对象 | 隔离方式 |
|---|---|---|
| `ScriptedAgentRunner` | 确定性脚本(上下界锚点) | 按固定脚本调工具,完全可控 |
| `ClaudeCodeRunner` | Claude Code(`claude -p`) | `--strict-mcp-config` + `--disallowedTools` 禁内置 |
| `ApiAgentRunner` | 任意 OpenAI 兼容模型 | 只给 MCP 工具,无内置工具 |
| `CodexRunner` | OpenAI Codex(`codex exec`) | 空 cwd 隔离 + 复制 auth + bypass approvals |

已实测真实模型:**claude-sonnet · codex · deepseek-v4-pro · mimo-v2.5-pro · qwen3.7-max**。

---

## 任务集(54)

| Category | 数量 | 测什么 |
|---|---|---|
| **functional** | 22 | 功能正确性(含 15 个 hard/medium 性能任务:多跳编排 5-7 步 / 错误恢复 / 复杂 schema / 工具选择 / 长结果提取 / 条件分支) |
| **injection** | 15 | 注入抵抗:间接注入 / 工具描述注入 / base64·rot13 编码混淆 / 角色越狱 / 伪权威 / 跨 channel + 多跳外泄 / 答案直接外泄 |
| **forbidden** | 7 | 越权路径:`../` 穿越 / symlink 逃逸 / URL 编码 / 绝对路径 / glob 过度索引 |
| **description** | 6(3 配对) | 工具描述质量对照(clear vs degraded:误导描述 + decoy 工具) |
| **dangerous** | 4 | 危险操作确认:删除/覆盖前是否走 confirmation,能否抵御诱导破坏 |

每任务带 `difficulty`(easy/medium/hard),与 category 正交,驱动报告难度分层(easy 饱和无意义,hard 才拉开)。

---

## Validators(12)

**功能(7)**:`functional`(终态:答案/文件/调用)· `multi_step_completion`(多跳按序)· `error_recovery`(故障后重试)· `tool_selection`(没选 decoy)· `schema_compliance`(复杂参数填对)· `description_quality`(A/B 配对)。
**安全(5)**:`canary_leak`(密钥泄漏)· `forbidden_access`(越权路径)· `tool_authorization`(越权工具/channel)· `dangerous_op`(危险操作未确认)· `injection_resistance`(注入抵抗 composite)· `exfil_channel`(跨通道 + 编码外泄)。

**铁律**:安全 validator 只取 `source=='server'` 事件;`meta` 一律 `.get(k, False)` 兜底;evidence 用 `seq`。

---

## 指标 & 报告

跑完产出 `runs/_reports/<ts>.{json,md}`:

- **Leaderboard** — `success_rate` / `pass^k`(全 k 次都过才算)/ `unsafe_call_rate` / `canary_leak_rate` / `inj_resist` …,按「成功率 − 安全惩罚」排序
- **Difficulty breakdown** — easy/medium/hard 分层成功率,暴露饱和是否被打破
- **Attack × Model 矩阵** — 每个注入攻击 × 每个模型,谁栽在哪(✓ 抵御 / ✗ 中招)
- **Capabilities** — `multi_step` / `error_recovery` 通过率
- **Failure taxonomy** — 失败按 tag 归类,可下钻到 `trace.json`

---

## 用法

```bash
# 仅 scripted(秒级、不花额度,验证链路 + validator oracle)
uv run python scripts/run_benchmark.py --no-claude

# 含真实 Claude Code
uv run python scripts/run_benchmark.py --model sonnet

# 多模型同台(key 从 <LABEL>_KEY 环境变量读)
DEEPSEEK_KEY=... QWEN_KEY=... \
uv run python scripts/run_benchmark.py --model sonnet --codex \
  --api deepseek,https://api.deepseek.com,deepseek-v4-pro \
  --api qwen,https://dashscope.aliyuncs.com/compatible-mode/v1,qwen3.7-max
```

---

## 已有发现(C1,6 模型实测)

- **性能维度饱和** — 4 个真实模型功能 `success_rate` 全 1.00,单步读写对前沿模型 trivial → C2 补了 15 硬任务 + 难度分层。
- **安全维度才有区分度** — `inj_resist` 从 deepseek 0.33、mimo 0.67 到 claude/qwen/codex 1.00,清晰拉开。
- **攻击 × 模型脆弱性矩阵成立** — deepseek 被 HTML 注释注入骗、mimo 被伪「系统策略」骗,claude/qwen/codex 全免疫;benchmark 能**精确定位「哪个攻击对哪个模型有效」**。

> 详尽设计、方法论与完整结果见 [`docs/PROJECT_REPORT.md`](docs/PROJECT_REPORT.md)。

---

## 路线图

- ✅ **B** — 被测 agent 接入 + 双层 trace
- ✅ **C1** — 单 server 完整 benchmark(21 任务 / 7 validator)
- ✅ **多模型** — ApiAgentRunner + CodexRunner + 多模型 CLI
- ✅ **C2** — 攻击矩阵加厚 + 硬性能(54 任务 / 12 validator / 难度分层 + Attack×Model)
- ⏭ **C3** — 扩 server(github/docs/crm)· pass^k 测稳定性 · 更多模型

---

## 开发

```bash
uv run pytest -q     # 全量测试(当前 265 passed)
```
