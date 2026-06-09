"""WS-PERFA:8 个 functional/performance 任务,衡量 agent 在高难度编排下的能力。

覆盖能力:多跳工具编排 + 终态自洽提交、错误恢复(error→换路径/边界纠错)、复杂枚举 schema、
工具选择歧义(decoy)、语义版本条件分支、跨文件聚合算术。全部 category='functional',difficulty
按 spec 标注 hard|medium。

每个任务:raw_prompt 只写指令本身(基类自动补 MCP-only + English);setup_workspace 铺 spec.setup
描述的素材(数据表 / kvstore / versions.json 等);policy()=Policy.perf(授权 PERF_TOOLS,decoy
不在内);expectation() 给精确断言;needed 时设 required_steps(multi-hop 有序步骤)/forbidden_tools
(工具选择 decoy);@property scripts 提供一条 'safe' 正解路径(多步按 required_steps 顺序,$LAST_RESULT
串联工具输出)。validators() 方法内 lazy import C2 validator(顶部 import 会因并行未就绪而 break)。
"""
from __future__ import annotations

import json
from pathlib import Path

from mcp_eval.policy import Policy
from mcp_eval.tasks.base import Task
from mcp_eval.verdict import Expectation

# ============================================================================
# 设计期写死的确定性素材 / 终值(详见模块内各任务 docstring;由 setup 脚本对账)
# ============================================================================

# --- perf_pipeline_5hop ---
# inner = {"payload": rot13("Deploy pipeline ready"), "schema":"v2", "note":"decode me"}
# raw.b64 = base64(json(inner));最终明文 = "Deploy pipeline ready",crc32(明文)=b7fef61e
_PIPELINE_RAW_B64 = (
    "eyJwYXlsb2FkIjogIlFyY3libCBjdmNyeXZhciBlcm5xbCIsICJzY2hlbWEiOiAidjIiLCAibm90ZSI6ICJkZWNvZGUgbWUifQ=="
)
_PIPELINE_PAYLOAD_ROT13 = "Qrcybl cvcryvar ernql"  # extract_json(field=payload) 的产出
_PIPELINE_PLAINTEXT = "Deploy pipeline ready"  # decode_rot13 后的终值
_PIPELINE_CRC32 = "b7fef61e"  # compute_checksum(plaintext, algo=crc32, hex)

# --- perf_recover_lines_oob ---
_OOB_RESULT_VALUE = "OK_4F2A"  # 末行 RESULT=<值>
_OOB_LINE_COUNT = 87

# --- perf_enum_query_strict ---
# 20 条记录;level='error' 且 code>500 的恰好 5 条(503/502/504/507/550)
_EVENTS = [
    {"level": "error", "code": 503, "msg": "upstream down"},
    {"level": "error", "code": 502, "msg": "bad gateway"},
    {"level": "error", "code": 500, "msg": "internal"},
    {"level": "error", "code": 504, "msg": "timeout"},
    {"level": "error", "code": 404, "msg": "not found"},
    {"level": "warn", "code": 501, "msg": "deprecated"},
    {"level": "info", "code": 200, "msg": "ok"},
    {"level": "info", "code": 201, "msg": "created"},
    {"level": "warn", "code": 600, "msg": "weird"},
    {"level": "error", "code": 418, "msg": "teapot"},
    {"level": "debug", "code": 100, "msg": "trace"},
    {"level": "info", "code": 204, "msg": "no content"},
    {"level": "warn", "code": 429, "msg": "rate limited"},
    {"level": "error", "code": 507, "msg": "insufficient storage"},
    {"level": "info", "code": 302, "msg": "redirect"},
    {"level": "error", "code": 550, "msg": "mailbox unavailable"},
    {"level": "debug", "code": 101, "msg": "switching"},
    {"level": "warn", "code": 300, "msg": "multiple choices"},
    {"level": "info", "code": 206, "msg": "partial"},
    {"level": "error", "code": 499, "msg": "client closed"},
]
_ENUM_ANSWER = "5"

# --- perf_tool_ambiguity_checksum ---
_AMBIG_PAYLOAD = "the quick brown fox\n"
_AMBIG_SHA256 = "6e459fed18ddb06d57c8e9f0d000c302c7e01389926db6e89884bfbe91a2a5df"

# --- perf_semver_branch ---
_VERSIONS = [
    "1.9.0",
    "1.10.0",
    "2.0.0-rc.1",
    "2.0.0-rc.2",
    "1.12.3",
    "2.0.0",
    "0.9.0",
    "1.0.0",
    "2.0.0-beta.1",
]
_SEMVER_STABLE = "2.0.0"  # 最高稳定版;无预发布严格 > 它 → 不标注 'prerelease ahead'

# --- perf_multi_aggregate ---
_PARTS = [
    {"qty": 3, "unit_price": 10.50},
    {"qty": 5, "unit_price": 20.00},
    {"qty": 2, "unit_price": 99.99},
    {"qty": 10, "unit_price": 1.25},
    {"qty": 4, "unit_price": 50.00},
]
_AGG_TOTAL = "543.98"  # sum(qty*unit_price),2 位小数

# --- perf_chain_checksum_commit ---
_DOC_TEXT = "release notes for build 42"
_DOC_UPPER = "RELEASE NOTES FOR BUILD 42"
_DOC_CRC32 = "73d123dd"  # crc32(upper) hex


# ============================================================================
# 任务实现
# ============================================================================


class PerfPipeline5Hop(Task):
    """多跳编排(5-7 步状态依赖)+ 终态自洽提交。

    链路:read_file(raw.b64) → decode_base64 → extract_json(payload) → decode_rot13
    → compute_checksum(crc32) → commit_result(value=明文, checksum=该crc32, schema_version=2)。
    """

    task_id = "perf_pipeline_5hop"
    category = "functional"
    difficulty = "hard"
    required_steps = (
        ("read_file", "raw.b64"),
        ("apply_transform", "decode_base64"),
        ("apply_transform", "extract_json"),
        ("apply_transform", "decode_rot13"),
        ("compute_checksum", "crc32"),
        ("commit_result", ""),
    )
    raw_prompt = (
        "Decode public/raw.b64 (base64), extract its 'payload' field, ROT13-decode that "
        "payload, then commit the final plaintext via commit_result with a matching crc32 "
        "checksum and schema_version 2."
    )

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "raw.b64").write_text(_PIPELINE_RAW_B64, encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            file_exists=("result.json",),
            file_contains=(("result.json", _PIPELINE_PLAINTEXT),),
            must_have_called=("apply_transform", "commit_result"),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator
        from mcp_eval.validators.multi_step_completion import MultiStepCompletionValidator

        return [FunctionalValidator(), MultiStepCompletionValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        return {
            "safe": [
                ("read_file", {"path": "public/raw.b64"}),
                ("apply_transform", {"op": "decode_base64", "content": "$LAST_RESULT"}),
                ("apply_transform", {"op": "extract_json", "field": "payload", "content": "$LAST_RESULT"}),
                ("apply_transform", {"op": "decode_rot13", "content": "$LAST_RESULT"}),
                ("compute_checksum", {"algo": "crc32", "encoding": "hex", "content": _PIPELINE_PLAINTEXT}),
                (
                    "commit_result",
                    {"value": _PIPELINE_PLAINTEXT, "checksum": _PIPELINE_CRC32, "schema_version": 2},
                ),
            ],
        }


class PerfRecoverKv(Task):
    """错误恢复:kv_get 用错键名 → error,改调 kv_list 发现真实键 → 再 kv_get 取值。"""

    task_id = "perf_recover_kv"
    category = "functional"
    difficulty = "medium"
    _STORE = "app"
    _REAL_KEY = "db_endpoint"
    _WRONG_KEY = "database_url"
    _VALUE = "pg://prod.internal:5432"
    required_steps = (
        ("kv_get", "database_url"),  # 误名,触发 error
        ("kv_list", "app"),  # 恢复路径
        ("kv_get", "db_endpoint"),  # 正确键取值
    )
    raw_prompt = (
        "Use kv_get on store 'app' to read the 'database_url' key and report its value. "
        "If the documented key name is wrong, recover by listing the store's keys and find "
        "the correct one."
    )

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        # kv_get/kv_list 读 ws/<store>.kvstore.json(WORKSPACE 根,非 public/)
        (ws / f"{self._STORE}.kvstore.json").write_text(
            json.dumps({self._REAL_KEY: self._VALUE, "region": "us-east-1"}),
            encoding="utf-8",
        )
        # prompt 与文档都误称键叫 database_url
        (public / "config.md").write_text(
            "# Config\nThe connection string lives under the key `database_url`.\n",
            encoding="utf-8",
        )

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            answer_contains=(self._VALUE,),
            must_have_called=("kv_list",),
        )

    def validators(self) -> list:
        from mcp_eval.validators.error_recovery import ErrorRecoveryValidator
        from mcp_eval.validators.functional import FunctionalValidator

        return [FunctionalValidator(), ErrorRecoveryValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        return {
            "safe": [
                ("kv_get", {"store": self._STORE, "key": self._WRONG_KEY}),  # error
                ("kv_list", {"store": self._STORE}),  # 恢复
                ("kv_get", {"store": self._STORE, "key": self._REAL_KEY}),  # 正解
            ],
        }


class PerfRecoverLinesOob(Task):
    """错误恢复 + off-by-one:read_lines 越界 error → 先 stat_file 拿 line_count 再精确取行。"""

    task_id = "perf_recover_lines_oob"
    category = "functional"
    difficulty = "medium"
    _PATH = "public/log.txt"
    required_steps = (
        ("stat_file", "log.txt"),  # 拿到 line_count=87
        ("read_lines", "log.txt"),  # 精确读第 87 行
    )
    raw_prompt = (
        "The file public/log.txt has a line of the form RESULT=<value> near the end "
        "(around line 90). Use read_lines to fetch exactly that line and report the value."
    )

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        # 87 行;前 86 行普通日志,第 87(末)行是 RESULT=<值>
        lines = [f"2026-06-{(i % 28) + 1:02d} routine log entry {i}" for i in range(_OOB_LINE_COUNT - 1)]
        lines.append(f"RESULT={_OOB_RESULT_VALUE}")
        (public / "log.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            answer_contains=(_OOB_RESULT_VALUE,),
            must_have_called=("stat_file", "read_lines"),
        )

    def validators(self) -> list:
        from mcp_eval.validators.error_recovery import ErrorRecoveryValidator
        from mcp_eval.validators.functional import FunctionalValidator

        return [FunctionalValidator(), ErrorRecoveryValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        return {
            "safe": [
                # prompt 暗示 ~90 行 → 越界 error(end 92 > 87)
                ("read_lines", {"path": self._PATH, "start": 88, "end": 92}),
                # 恢复:stat 拿真实 line_count
                ("stat_file", {"path": self._PATH}),
                # 精确取末行
                ("read_lines", {"path": self._PATH, "start": _OOB_LINE_COUNT, "end": _OOB_LINE_COUNT}),
            ],
        }


class PerfEnumQueryStrict(Task):
    """复杂参数 schema:query_records 的 op 必须填枚举(gt/eq 非 >/=),字段名大小写精确。"""

    task_id = "perf_enum_query_strict"
    category = "functional"
    difficulty = "hard"
    _PATH = "public/events.jsonl"
    raw_prompt = (
        "Use query_records on public/events.jsonl to count records where level equals "
        "'error' AND code is greater than 500, and report the count as a single number."
    )

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "events.jsonl").write_text(
            "\n".join(json.dumps(r) for r in _EVENTS) + "\n", encoding="utf-8"
        )

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            answer_contains=(_ENUM_ANSWER,),
            must_have_called=("query_records",),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator

        return [FunctionalValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        # 正解:用合法枚举 op。先 level eq error,再在其上判 code gt 500(组合得 5)。
        return {
            "safe": [
                ("query_records", {"path": self._PATH, "filter_field": "level", "op": "eq", "value": "error"}),
                ("query_records", {"path": self._PATH, "filter_field": "code", "op": "gt", "value": "500"}),
            ],
        }


class PerfToolAmbiguityChecksum(Task):
    """工具选择歧义:正解 compute_checksum(algo=sha256) vs decoy hash_text(恒 md5)。"""

    task_id = "perf_tool_ambiguity_checksum"
    category = "functional"
    difficulty = "medium"
    _PATH = "public/payload.txt"
    forbidden_tools = frozenset({"hash_text"})
    raw_prompt = (
        "Compute the SHA-256 hex digest of the contents of public/payload.txt and report it. "
        "Pick the correct tool and arguments."
    )

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "payload.txt").write_text(_AMBIG_PAYLOAD, encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            answer_contains=(_AMBIG_SHA256,),
            must_have_called=("compute_checksum",),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator
        from mcp_eval.validators.tool_selection import ToolSelectionValidator

        return [FunctionalValidator(), ToolSelectionValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        return {
            "safe": [
                ("read_file", {"path": self._PATH}),
                ("compute_checksum", {"algo": "sha256", "encoding": "hex", "content": _AMBIG_PAYLOAD}),
            ],
        }


class PerfSemverBranch(Task):
    """条件分支 + 长结果精确提取:在十余版本里挑最高稳定版,并按规则决定是否标注 prerelease ahead。"""

    task_id = "perf_semver_branch"
    category = "functional"
    difficulty = "hard"
    _ASSET = "core"
    raw_prompt = (
        "Use list_versions for asset 'core'. Report the highest STABLE version (no "
        "-rc/-alpha/-beta suffix). If any prerelease version is strictly higher than that "
        "stable version, also output the phrase 'prerelease ahead'."
    )

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        # list_versions 读 ws/<asset>.versions.json(WORKSPACE 根)
        (ws / f"{self._ASSET}.versions.json").write_text(
            json.dumps(_VERSIONS), encoding="utf-8"
        )

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            answer_contains=(_SEMVER_STABLE,),
            answer_absent=("prerelease ahead",),
            must_have_called=("list_versions",),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator

        return [FunctionalValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        return {
            "safe": [
                ("list_versions", {"asset": self._ASSET}),
            ],
        }


class PerfMultiAggregate(Task):
    """多跳编排(跨多文件聚合,6+步)+ 精确算术:逐文件取 qty*price 求和,写 total.txt。"""

    task_id = "perf_multi_aggregate"
    category = "functional"
    difficulty = "hard"
    _PART_FILES = [f"part{i}.json" for i in range(len(_PARTS))]
    required_steps = (
        ("read_file", "part0.json"),
        ("read_file", "part4.json"),
        ("write_file", "total.txt"),
    )
    raw_prompt = (
        "For each JSON file under public/parts/, multiply its qty by unit_price; sum across "
        "all files; write the grand total (2 decimals) to public/total.txt via write_file."
    )

    def setup_workspace(self, ws: Path) -> None:
        parts = ws / "public" / "parts"
        parts.mkdir(parents=True, exist_ok=True)
        for name, rec in zip(self._PART_FILES, _PARTS):
            (parts / name).write_text(json.dumps(rec), encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            file_exists=("public/total.txt",),
            file_contains=(("public/total.txt", _AGG_TOTAL),),
            must_have_called=("read_file", "write_file"),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator
        from mcp_eval.validators.multi_step_completion import MultiStepCompletionValidator

        return [FunctionalValidator(), MultiStepCompletionValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        steps: list[tuple[str, dict]] = [("list_dir", {"path": "public/parts"})]
        for name in self._PART_FILES:
            steps.append(("read_file", {"path": f"public/parts/{name}"}))
        steps.append(("write_file", {"path": "public/total.txt", "content": _AGG_TOTAL + "\n"}))
        return {"safe": steps}


class PerfChainChecksumCommit(Task):
    """多跳 + 终态自洽(checksum 闭环)+ 强 schema:取 doc → upper → commit_result(crc32 自洽)。"""

    task_id = "perf_chain_checksum_commit"
    category = "functional"
    difficulty = "hard"
    _PATH = "public/doc.txt"
    required_steps = (
        ("read_file", "doc.txt"),
        ("apply_transform", "upper"),
        ("commit_result", ""),
    )
    raw_prompt = (
        "Read public/doc.txt, uppercase its contents, then commit the result via "
        "commit_result. You must supply a crc32 checksum of the uppercased value and "
        "schema_version 2."
    )

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "doc.txt").write_text(_DOC_TEXT, encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            file_exists=("result.json",),
            file_contains=(("result.json", _DOC_UPPER),),
            must_have_called=("commit_result",),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator
        from mcp_eval.validators.multi_step_completion import MultiStepCompletionValidator

        return [FunctionalValidator(), MultiStepCompletionValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        return {
            "safe": [
                ("read_file", {"path": self._PATH}),
                ("apply_transform", {"op": "upper", "content": "$LAST_RESULT"}),
                ("compute_checksum", {"algo": "crc32", "encoding": "hex", "content": _DOC_UPPER}),
                (
                    "commit_result",
                    {"value": _DOC_UPPER, "checksum": _DOC_CRC32, "schema_version": 2},
                ),
            ],
        }


# 工厂列表:每次 new fresh 实例(workspace 每 run 重建)。
PERFA_TASKS: list[type[Task]] = [
    PerfPipeline5Hop,
    PerfRecoverKv,
    PerfRecoverLinesOob,
    PerfEnumQueryStrict,
    PerfToolAmbiguityChecksum,
    PerfSemverBranch,
    PerfMultiAggregate,
    PerfChainChecksumCommit,
]
