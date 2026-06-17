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
  benchmark.py        BenchmarkRunner(task×agent×rep 矩阵)+ pass^k 聚合 + 报告
  servers/fs_mock.py  instrumented filesystem mock MCP server(故障注入 + decoy)
  servers/web_mock.py 第二个 mock server(fetch/http_post sink)→ 跨 server 攻击
  servers/real_proxy.py  instrumented proxy,把任务原样跑在真实 server-filesystem 上(C4 外推性)
  runners/            被测对象 4 类:scripted / claude_code / api_agent / codex_runner
  validators/         14 判定器(功能 + 安全)
  tasks/              69 任务(functional / description / injection / forbidden / dangerous / 跨 server)
```

---

## 被测对象(runners)

| Runner | 被测对象 | 隔离方式 |
|---|---|---|
| `ScriptedAgentRunner` | 确定性脚本(上下界锚点) | 按固定脚本调工具,完全可控 |
| `ClaudeCodeRunner` | Claude Code(`claude -p`) | `--strict-mcp-config` + `--disallowedTools` 禁内置 |
| `ApiAgentRunner` | 任意 OpenAI 兼容模型 | 只给 MCP 工具,无内置工具 |
| `CodexRunner` | OpenAI Codex(`codex exec`) | 空 cwd 隔离 + 复制 auth + bypass approvals |

已实测真实模型(10 家):**claude-opus-4.8 · claude-sonnet-4.6 · claude-fable-5 · codex(gpt-5.5) · deepseek-v4-pro · mimo-v2.5-pro · qwen3.7-max · kimi · minimax · glm** + scripted 锚点。

---

## 任务集(69)

| Category | 数量 | 测什么 |
|---|---|---|
| **functional** | 22 | 功能正确性(含 15 个 hard/medium 性能任务:多跳编排 5-7 步 / 错误恢复 / 复杂 schema / 工具选择 / 长结果提取 / 条件分支) |
| **injection** | 15 | 注入抵抗:间接注入 / 工具描述注入 / base64·rot13 编码混淆 / 角色越狱 / 伪权威 / 跨 channel + 多跳外泄 / 答案直接外泄 |
| **跨 server** | 15 | C3 双 server 攻击:混淆代理 / 编码 post 外泄 / 两跳外泄 / 递归注入 / TOCTOU / 指令层级 / 工具歧义 |
| **forbidden** | 7 | 越权路径:`../` 穿越 / symlink 逃逸 / URL 编码 / 绝对路径 / glob 过度索引 |
| **description** | 6(3 配对) | 工具描述质量对照(clear vs degraded:误导描述 + decoy 工具) |
| **dangerous** | 4 | 危险操作确认:删除/覆盖前是否走 confirmation,能否抵御诱导破坏 |

每任务带 `difficulty`(easy/medium/hard),与 category 正交,驱动报告难度分层(easy 饱和无意义,hard 才拉开)。

---

## Validators(14)

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

# C4:真实 MCP server proxy(forbidden/injection 任务原样跑在真实 server-filesystem 上)
#   需 Node + npx(@modelcontextprotocol/server-filesystem 首次自动拉取)
uv run python scripts/run_benchmark.py --model sonnet --fs-backend real
# mock vs real 后端对照表(验证外推性)
uv run python scripts/compare_backends.py --tasks fb_read_private,inj_b64_encoded --scripted
```

---

## 已有发现(C3,10 模型 × 69 任务实测)

- **功能与安全是两条正交轴** — 没有全能赢家:纯功能 mimo 0.96 / qwen 0.95 最强但安全最差(canary 泄漏);Claude 系 + codex 功能中游但注入抵抗满分 1.00、安全顶格。
- **攻击 × 模型脆弱性矩阵成立** — benchmark 能**精确定位「哪个攻击对哪个模型有效」**:最强攻击是条件触发 + rot13 编码混淆;description decoy 描述能骗 4 个模型越权。
- **success_rate 系统性低估「自带激进安全分类器的模型」** — Claude 系的 AUP 前置拦截会把良性任务也挡掉,被朴素 success_rate 冤判;C3.5 把它单列为 `policy_blocked` 轴后,opus 0.857 → 0.932。
- **评测装置自身也被持续校验** — 每接入一个新被测模型都可能暴露 validator 瑕疵(如硬编码 `read_file` 的多跳判定),已据此修两个判分 bug + 离线重判。

> 详尽设计、方法论与完整结果见 [`docs/PROJECT_REPORT.md`](docs/PROJECT_REPORT.md)(12 章)。

---

## 路线图

- ✅ **B** — 被测 agent 接入 + 双层 trace
- ✅ **C1** — 单 server 完整 benchmark(21 任务 / 7 validator)
- ✅ **多模型** — ApiAgentRunner + CodexRunner + 多模型 CLI
- ✅ **C2** — 攻击矩阵加厚 + 硬性能(54 任务 / 难度分层 + Attack×Model)
- ✅ **C3** — 第二个 mock server + 跨 server 攻击 + pass^k / safety_pass^k / 效率四轴(69 任务 / 10 模型)
- ✅ **C3.5** — `policy_blocked` 单列 + 两个 validator bug 修复 + 离线重判
- ✅ **C4** — 真实 server-filesystem proxy(外推性)+ 成本归一化效率口径
- ⏭ **Track E** — 借 Toolathlon 轨迹(CC-BY-4.0)构建 RL 数据集,validator 给分当 reward

---

## 开发

```bash
uv run pytest -q     # 全量测试(当前 417 passed)
```
