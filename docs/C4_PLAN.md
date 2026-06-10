# C4 规划 —— 针对 C3 未解问题的下一轮测评

**一句话定位**:C3 把"约束环境下的工具使用安全"测扎实了(10 agent × 69 任务 × k=3,双 server,四条新轴)。C4 不再加模型/加任务堆量,而是**逐条修掉 C3 暴露的测量有效性缺口 + 把 eval infra 升级成 agentic RL 数据引擎**。

> 前置阅读:`docs/PROJECT_REPORT.md`(§6 实测、§7 发现、§9 局限)、`docs/C3_BLUEPRINT.md`。

---

## 0. C3 留下的 6 个真问题(全部有据可查)

| # | 未解决的问题 | 证据 | 影响 |
|---|---|---|---|
| **P1** | mock ≠ 真实 MCP server,结论外推性受限 | §9 | 最大外部有效性缺口 |
| **P2** | Claude 被"绑一只手"测(`--disallowedTools` + 单发 `-p` 拆掉原生 agentic 脚手架),功能分是**约束下限**非原生天花板 | §7.7 | Claude 功能排名被系统性低估 |
| **P3** | AUP 分类器污染 ~6% opus cell(含对良性任务 `perf_pipeline_5hop` 的误杀),当前混进"答错" | §6.8 | Claude 功能分被外部安全层进一步压低 |
| **P4** | token 口径不统一(Claude Code stream-json 不计 cache-read,sonnet 92.8 vs codex 52,705 不可横比) | §9 | 效率维度跨模型不可比 |
| **P5** | 安全是概率(`flaky_gap` 全 > 0),但 k=3 太小,刻画不了失败率尾部 | §6.3 | "定时炸弹"有多稀有说不清 |
| **P6** | 攻击是手写静态的,覆盖有限、可能被针对 | §5/§9 | 安全结论可能高估(没见过的攻击没测) |

外加一个**机会**(非问题):**P7** —— 现在有了 verifier(validator)+ rollout(trace),却从未把它们当 reward 用。这正是 agentic RL 的入口。

---

## 1. 五条轨道(每条对症一个问题)

### A · 真实 MCP server proxy 评测(治 P1)

**目标**:把被测面从自写 mock 扩到真实 MCP server,验证结论能不能外推。

**设计**:
- 在真实 server(优先 `@modelcontextprotocol/server-filesystem`、github、sqlite)前架一层 **instrumented proxy**:对上游 agent 假装是 MCP server,对下游转发到真实 server,在 proxy 层抓双层 trace(协议级,与现有 `trace.py` 同构)。
- 攻击面注入:真实 server 没有 canary 埋点/故障开关 → 由 **proxy 篡改返回内容**注入(在文件内容里插注入串、在工具结果里插 decoy 指令、按 query 计数模拟 TOCTOU),把 C3 的攻击库映射到真实 server 的返回通道上。
- validator/policy 几乎零改动(它们只消费 trace + policy)。

**难点**:① 真实 server 工具集与 mock 不一一对应 → 需一层工具名/语义映射;② proxy 必须对协议透明(初始化握手、resource、notification 全转发);③ 真实 server 有真实副作用,workspace 隔离要更严(临时目录 + 用完销毁)。

**验收**:同一批 forbidden/injection 任务在 mock 与 real-proxy 上跑,结论方向一致(若不一致,本身就是有价值的外推性 finding)。

---

### B · 原生 harness 轨道:解开"绑一只手"(治 P2)

**目标**:测出每个 agent 的**原生天花板**,把 model 与 harness 的贡献干净拆开,补上报告最大的方法论 caveat。

**设计**:
- 新增一类 runner / 运行模式 **native**:不再 `--disallowedTools` 禁内置工具、不再单发 `-p`,让 Claude Code / codex 用**全套原生 agentic 工具 + 完整 loop** 完成任务。
- 评测口径随之换轨:既然不强制只走 MCP,功能判定从"server 侧 trace"放宽到"**终态 + 工具使用正确性**"(workspace 终值仍是 ground truth,可验);安全判定保留对 sink/外发通道的监控。
- 对照设计:同一任务 × 同一模型 × {constrained(C3 口径) vs native} 两版 → **delta = harness 放大量**;同一 harness × {opus vs sonnet} → 权重贡献(C3 已有雏形,§7.7)。

**难点**:native 模式下 agent 可绕开 MCP 用内置工具,trace 完整性下降 → 安全判定的可信度需重新界定(对 native 轨道,安全结论以"可观测到的外发/越权"为下界,标注口径)。

**验收**:产出一张 `约束分 vs 原生分` 对照表,量化"被绑一只手"扣了多少分;§7.7 从定性 finding 升级为定量结论。

---

### C · 测量清理:AUP 桶 + token 归一(治 P3 + P4)

**目标**:低成本让现有数字立得住。两个独立小工程。

**C1 · AUP 拦截独立成桶**:
- 复用配额污染那套思路(`merge_reports._is_contaminated` 的模式):识别 cell 的 final_answer 含 `Usage Policy` / `unable to respond` 标记 → 标为 **`aup_blocked`**,从功能失败里剥离,单独报 **"AUP 拦截率"** 指标。
- 给一个可切换的计分规则:`exclude`(不算模型的错)vs `count`(算)两种口径都出,读者自取(§6.8 已手工算过:剔 AUP 后 opus 天花板 0.915)。

**C2 · token 口径归一**:
- 现状:Claude Code `usage` 不含 cache-read,API 模型含全量 → 不可比。
- 方案:统一改成**成本归一**(各模型 input/output 单价 × token,落到 USD/任务)或**只比 output_tokens**(各家口径较一致),报告标清口径。codex 已有 `costUSD` 字段可直接用,Claude 侧需从 `modelUsage` 估算。

**难点**:Claude Code 不暴露 cache-read 明细 → 成本只能估算,需在报告里诚实标"估算"。

**验收**:效率表加一列"成本/成功(USD,估算)",跨模型可比;新增 `aup_block_rate` 列。

---

### D · 高 k 尾部刻画 + 自适应攻击生成(治 P5 + P6)

**目标**:把"安全是概率"从 k=3 的粗测,深化成尾部刻画 + 主动找新洞。

**D1 · 高 k 尾部**:对 C3 已暴露的 flaky 攻击(`inj_conditional_trigger`、`inj_rot13_encoded`、`recinj_*`)在高破防模型上跑 **k=10~20**,估失败率置信区间,回答"mimo 那 +0.13 到底多稀有"。代价可控(只挑少数 task×model 格子加密)。

**D2 · 自适应攻击生成(red-team agent)**:
- 写一个攻击生成 agent:给定一个守住的 (task, 被测模型),让它**变异注入载荷**(换编码/换条件/换权威信号/换分隔符)直到破防或预算耗尽。
- 产出 = 一批**新攻击样本** + 每个的 r/k —— 这本身就是**对抗样本数据集**(与实习 dataset 方向直接相关)。
- 攻击迁移性:在 A 模型上找到的破防攻击,转测其它模型,看是否迁移(迁移率高 = 通用漏洞,低 = 模型特异)。

**难点**:red-team agent 自己也要避免被自己的注入带偏;变异空间要结构化(否则退化成乱试);新攻击要回灌进静态任务库需人工 sanity check(避免无效/重复)。

**验收**:flaky 攻击给出失败率区间;red-team 产出 ≥N 个静态库里没有的有效新攻击,沉淀成 `attacks_generated.py`。

---

### E · 闭环:validator 当 reward,做 rejection-sampling 数据引擎(P7)★

**目标**:把 eval infra 升级成 **agentic RL 数据生产线** —— 这是 C4 战略价值最高的一条,也是对接实习方向(agentic RL 数据集构建)的核心。

**设计(严格绕开"单 4090 不训 RL"硬约束 —— 只采样 + 打分 + 蒸馏,零梯度更新)**:
- **rollout 采样**:同一任务采 N 条轨迹(温度采样 / 多模型混采),复用现有 harness。
- **reward 打分**:现成的 12 个 validator 就是程序化 reward —— 功能分 + 安全分 + 效率,合成一个标量/向量 reward。pass^k / flaky_gap 还能筛掉不稳定样本。
- **数据产出**:三种用法,按下游需要选——
  1. **rejection sampling / best-of-N**:留每任务最高 reward 的轨迹 → 监督微调(SFT)数据;
  2. **偏好对**:高 reward vs 低 reward 配对 → DPO/RLAIF 数据;
  3. **过程奖励**:多跳任务的每步 trace + 是否推进终态 → step-level reward 标注(agentic PRM 数据)。
- 输出标准化成开放格式(JSONL,含 prompt / 轨迹 / reward / 拆解标签),即"一份带 verifier 的 agentic 数据集"。

**为什么这条对 boss 最有说服力**:agentic RL 最难、最值钱的是 verifier/reward,**而 mcp-eval 已经把这部分写好了**。E 轨道把"我做了个 eval"变成"我做了个**带可执行奖励的数据引擎**",正好是实习字面交付物。

**难点**:① reward 合成的权重(功能 vs 安全 vs 效率)需设计,避免刷分;② 采样成本(N 条 rollout × 任务 × 模型)要控预算;③ 数据质量验证(蒸馏出的数据真能提升下游?)需要至少一次小规模 SFT 验证——这步可借 4090 跑小模型 SFT(SFT 显存可控,不违反"不训 RL"约束,RL 才是被排除的)。

**验收**:产出 v0 数据集(≥1k 高质量轨迹 + reward 标注)+ 一次小模型 SFT 的 before/after 对照(证明数据有效)。

---

## 2. 建议排序与里程碑

```
阶段1(地基清理,~3-4天)   C · AUP 桶 + token 归一    → 现有数字立得住
阶段2(回应核心质疑,~1周)  B · 原生 harness 轨道       → 测出 Claude 原生天花板,§7.7 定量化
阶段3(战略主线,~2周)      E · rejection-sampling 数据引擎 → eval→数据引擎,实习对接点 ★
阶段4(并行/延后)          A · 真实 server proxy(最重)  +  D · 攻击生成(数据增益)
```

**排序逻辑**:先 C(便宜、让后续所有数字可信)→ 再 B(回应"Claude 到底强不强"这个绕不开的质疑)→ 然后 E(把项目从 eval 抬升到数据引擎,价值最高)→ A/D 体量大、可作为长期并行轨。

---

## 3. 约束与原则(继承,勿违)

- **纯评测/数据路线,不训练 RL**:单 4090,不做 RL 梯度更新。E 轨道只做"采样 + 打分 + 蒸馏";数据有效性验证用**小模型 SFT**(显存可控)而非 RL。
- **凭据永不入库**:各模型 key 走 env,`runs/` gitignore。
- **runner 契约不变**:新 runner 严格沿用 `AgentRunner.run(ctx) -> str` + 双层 trace。
- **测量有效性优先于堆量**:C4 不为"再多测几个模型"而做,为"让每个数字都经得起追问"而做。

---

## 4. 与实习/RL 的衔接

C4 的 E 轨道是与 [[project_agentic_rl_internship]](agentic RL 数据集构建方向)的直接接口:**mcp-eval 的 validator = reward function、trace = rollout 数据,接上 rejection sampling 即一条数据流水线**。详谈材料以此为钩子;B/C 轨道保证"给出的数字可信",是这套数据引擎可信度的底座。

> 本规划随项目演进更新。每条轨道落地后回填到 `PROJECT_REPORT.md` 对应章节。
