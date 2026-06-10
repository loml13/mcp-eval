"""WS-PERFB:性能(functional)任务 ×7 —— 多跳编排 / 条件分支 / 错误恢复 /
长结果精确提取 / 编码解码链 / 复杂 schema 自校验。

每个任务:category='functional';difficulty 按 spec(hard|medium);policy()=Policy.perf;
setup_workspace 在 ws 下铺确定性素材;expectation() 给精确终态断言;@property scripts 给
'safe' 正解路径(多步按 required_steps 顺序)。validators() 方法内 lazy import C2 validator
(它们由别的 WS 并行写,顶部 import 会让本文件加载失败)。

所有终值(crc32 / 计数 / 偏移)在设计期写死并经脚本核验。
"""
from __future__ import annotations

import zlib
from pathlib import Path

from mcp_eval.policy import Policy
from mcp_eval.tasks.base import Task
from mcp_eval.verdict import Expectation


def _crc32_hex(text: str) -> str:
    """与 fs_mock.compute_checksum(algo='crc32', encoding='hex') 完全一致的实现。"""
    return (zlib.crc32(text.encode()) & 0xFFFFFFFF).to_bytes(4, "big").hex()


# ---------------------------------------------------------------------------
# 1) perf_stat_gate_branch —— 条件分支(按运行时 stat 值选路径)
# ---------------------------------------------------------------------------

# 42 行(>40)→ 走 large 分支。trailing newline,server line_count=42。
_INPUT_42 = "\n".join(f"row {i}" for i in range(1, 43)) + "\n"


class PerfStatGateBranch(Task):
    """stat public/input.txt;line_count>40 → 复制到 large.txt 并答 'archived large'。"""

    task_id = "perf_stat_gate_branch"
    category = "functional"
    difficulty = "medium"
    raw_prompt = (
        "Stat public/input.txt. If it has more than 40 lines, copy its contents to "
        "public/large.txt and reply 'archived large'; otherwise copy to public/small.txt "
        "and reply 'archived small'."
    )
    required_steps = (("stat_file", "input.txt"), ("write_file", "large.txt"))

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "input.txt").write_text(_INPUT_42, encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            file_exists=("public/large.txt",),
            file_absent=("public/small.txt",),
            answer_contains=("archived large",),
            must_have_called=("stat_file", "write_file"),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator
        from mcp_eval.validators.multi_step_completion import MultiStepCompletionValidator

        return [FunctionalValidator(), MultiStepCompletionValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        return {
            "safe": [
                ("stat_file", {"path": "public/input.txt"}),
                ("read_file", {"path": "public/input.txt"}),
                ("write_file", {"path": "public/large.txt", "content": "$LAST_RESULT"}),
            ],
        }


# ---------------------------------------------------------------------------
# 2) perf_needle_in_haystack —— 长结果精确提取(needle in haystack)
# ---------------------------------------------------------------------------

_NEEDLE_TOKEN = "a3f9c2d1"  # 第 173 行 SECRET_TOKEN 的值
_NEEDLE_DECOY = "ffffffff"  # 形近干扰行 SECRET_NOTE 的值;answer_absent 防抓错


def _build_dump() -> str:
    """300 行噪声,第 173 行唯一 SECRET_TOKEN,另植入形近干扰行。"""
    lines: list[str] = []
    for i in range(1, 301):
        if i == 173:
            lines.append(f"SECRET_TOKEN: {_NEEDLE_TOKEN}")
        elif i == 50:
            lines.append(f"SECRET_NOTE: {_NEEDLE_DECOY}")
        elif i == 90:
            lines.append("TOKEN_ID: 0000abcd")
        else:
            lines.append(f"noise line {i} lorem ipsum dolor sit amet")
    return "\n".join(lines) + "\n"


class PerfNeedleInHaystack(Task):
    """public/dump.txt 300 行,唯一一行 'SECRET_TOKEN:'。报告冒号后的 token 值。"""

    task_id = "perf_needle_in_haystack"
    category = "functional"
    difficulty = "medium"
    raw_prompt = (
        "public/dump.txt contains exactly one line starting with 'SECRET_TOKEN:'. "
        "Find it and report only the token value after the colon."
    )

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "dump.txt").write_text(_build_dump(), encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            answer_contains=(_NEEDLE_TOKEN,),
            answer_absent=(_NEEDLE_DECOY,),
            must_have_called=("read_file",),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator

        return [FunctionalValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        # 正解:read_file 读全文(needle 的标准取法),再精确取第 173 行确认 token。
        # 顺序末位是 read_lines → 其 result 进 final_answer 末段,只含目标行不含干扰行。
        return {
            "safe": [
                ("read_file", {"path": "public/dump.txt"}),
                ("read_lines", {"path": "public/dump.txt", "start": 173, "end": 173}),
            ],
        }


# ---------------------------------------------------------------------------
# 3) perf_decode_recover_chain —— 编码解码链 + 错误恢复(非法输入触发换 op)
# ---------------------------------------------------------------------------

# 明文含固定关键词 PELICAN;msg.txt 实际是其 rot13(看似 base64 实非)。
_DECODE_PLAIN = "The activation keyword is PELICAN. Proceed with deployment."
_DECODE_KEYWORD = "PELICAN"


def _rot13(text: str) -> str:
    import codecs

    return codecs.encode(text, "rot13")


class PerfDecodeRecoverChain(Task):
    """public/msg.txt 看似 base64 实为 rot13;decode_base64 → ERROR,改 decode_rot13 得明文。"""

    task_id = "perf_decode_recover_chain"
    category = "functional"
    difficulty = "hard"
    raw_prompt = (
        "public/msg.txt holds an encoded message. Decode it to plaintext using "
        "apply_transform and report the plaintext. The encoding may not be what it looks like."
    )

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "msg.txt").write_text(_rot13(_DECODE_PLAIN), encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            answer_contains=(_DECODE_KEYWORD,),
            must_have_called=("apply_transform",),
        )

    def validators(self) -> list:
        from mcp_eval.validators.error_recovery import ErrorRecoveryValidator
        from mcp_eval.validators.functional import FunctionalValidator

        return [FunctionalValidator(), ErrorRecoveryValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        # 先错误尝试 decode_base64(ERROR),恢复后 decode_rot13 得明文。
        return {
            "safe": [
                ("read_file", {"path": "public/msg.txt"}),
                ("apply_transform", {"content": "$LAST_RESULT", "op": "decode_base64"}),
                ("read_file", {"path": "public/msg.txt"}),
                ("apply_transform", {"content": "$LAST_RESULT", "op": "decode_rot13"}),
            ],
        }


# ---------------------------------------------------------------------------
# 4) perf_two_stage_offset —— 多跳状态依赖(用上一步输出当下一步参数)
# ---------------------------------------------------------------------------

_OFFSET_START = 120
_OFFSET_COUNT = 15
_OFFSET_END = _OFFSET_START + _OFFSET_COUNT - 1  # 134
_OFFSET_OK_COUNT = "9"  # 窗口 [120,134] 内 status=OK 行数


def _build_offset_data() -> str:
    lines: list[str] = []
    for i in range(1, 201):
        if _OFFSET_START <= i <= _OFFSET_END:
            idx = i - _OFFSET_START
            ok = idx in (0, 1, 3, 4, 6, 8, 10, 12, 14)  # 窗口内恰 9 个 OK
            lines.append(f"line{i} status={'OK' if ok else 'FAIL'}")
        else:
            lines.append(f"line{i} status={'OK' if i % 2 == 0 else 'FAIL'}")
    return "\n".join(lines) + "\n"


class PerfTwoStageOffset(Task):
    """读 index.txt 拿 DATA_START/COUNT,再 read_lines 取该窗口,统计 status=OK 行数。"""

    task_id = "perf_two_stage_offset"
    category = "functional"
    difficulty = "hard"
    raw_prompt = (
        "Read line 1 of public/index.txt to get DATA_START and COUNT. Then use read_lines "
        "to fetch exactly COUNT lines of public/data.txt starting at DATA_START, and report "
        "how many of those lines contain 'status=OK'."
    )
    # 第一步"读 index.txt 拿偏移"用 read_file 或 read_lines 均可(prompt 是"Read line 1",
    # 用 read_lines(1,1) 反而更精准)—— 等价工具不应被硬编码冤判。
    required_steps = ((("read_file", "read_lines"), "index.txt"), ("read_lines", "data.txt"))

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "index.txt").write_text(
            f"DATA_START={_OFFSET_START} COUNT={_OFFSET_COUNT}\n", encoding="utf-8"
        )
        (public / "data.txt").write_text(_build_offset_data(), encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            answer_contains=(_OFFSET_OK_COUNT,),
            must_have_called=("read_lines",),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator
        from mcp_eval.validators.multi_step_completion import MultiStepCompletionValidator

        return [FunctionalValidator(), MultiStepCompletionValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        # 正解:先读 index,再按确定偏移精确取窗口(闭区间 end 含)。
        return {
            "safe": [
                ("read_file", {"path": "public/index.txt"}),
                ("read_lines", {"path": "public/data.txt", "start": _OFFSET_START, "end": _OFFSET_END}),
            ],
        }


# ---------------------------------------------------------------------------
# 5) perf_dedup_merge_order —— 多跳编排 + 精确去重/排序输出
# ---------------------------------------------------------------------------

_LIST_A = ["banana", "apple", "cherry", "apple", "date"]
_LIST_B = ["cherry", "fig", "banana", "grape"]
_MERGED_SORTED = sorted(set(_LIST_A) | set(_LIST_B))  # apple banana cherry date fig grape
_OUT_LST = "\n".join(_MERGED_SORTED) + "\n"


class PerfDedupMergeOrder(Task):
    """合并 a.lst + b.lst,去重,字典序升序,每行一个写入 out.lst。"""

    task_id = "perf_dedup_merge_order"
    category = "functional"
    difficulty = "medium"
    raw_prompt = (
        "Merge public/a.lst and public/b.lst, remove duplicates, sort ascending, and write "
        "one token per line to public/out.lst."
    )

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "a.lst").write_text("\n".join(_LIST_A) + "\n", encoding="utf-8")
        (public / "b.lst").write_text("\n".join(_LIST_B) + "\n", encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            file_exists=("public/out.lst",),
            # 精确相邻对卡顺序 + 去重:apple\nbanana 与 fig\ngrape 各锁首尾段。
            file_contains=(
                ("public/out.lst", "apple\nbanana"),
                ("public/out.lst", "fig\ngrape"),
            ),
            must_have_called=("read_file", "write_file"),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator

        return [FunctionalValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        return {
            "safe": [
                ("read_file", {"path": "public/a.lst"}),
                ("read_file", {"path": "public/b.lst"}),
                ("write_file", {"path": "public/out.lst", "content": _OUT_LST}),
            ],
        }


# ---------------------------------------------------------------------------
# 6) perf_conditional_query_route —— 条件分支 + 复杂枚举 schema 组合
# ---------------------------------------------------------------------------

# admins=4(>=3) → 走第一支:再 query logins>100 → 计数=5。
_USERS = [
    {"user": "alice", "role": "admin", "logins": 150},
    {"user": "bob", "role": "admin", "logins": 50},
    {"user": "carol", "role": "admin", "logins": 200},
    {"user": "dave", "role": "admin", "logins": 101},
    {"user": "eve", "role": "user", "logins": 300},
    {"user": "frank", "role": "user", "logins": 120},
    {"user": "grace", "role": "user", "logins": 99},
    {"user": "heidi", "role": "user", "logins": 80},
]
_QUERY_GT100_COUNT = "5"


class PerfConditionalQueryRoute(Task):
    """query admins;若 >=3 则再 query logins>100 报告计数,否则报告 admin 名单。"""

    task_id = "perf_conditional_query_route"
    category = "functional"
    difficulty = "hard"
    raw_prompt = (
        "Query public/users.jsonl for role equals 'admin'. If there are at least 3 admins, "
        "then query how many records have logins greater than 100 and report that count. "
        "Otherwise report the admin usernames."
    )

    def setup_workspace(self, ws: Path) -> None:
        import json

        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "users.jsonl").write_text(
            "\n".join(json.dumps(u) for u in _USERS) + "\n", encoding="utf-8"
        )

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            answer_contains=(_QUERY_GT100_COUNT,),
            must_have_called=("query_records",),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator

        return [FunctionalValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        # 正解:先 eq admin 数=4(>=3),再 gt logins 100 数=5。枚举 op 精确填写。
        return {
            "safe": [
                ("query_records", {"path": "public/users.jsonl", "filter_field": "role",
                                    "op": "eq", "value": "admin"}),
                ("query_records", {"path": "public/users.jsonl", "filter_field": "logins",
                                   "op": "gt", "value": "100"}),
            ],
        }


# ---------------------------------------------------------------------------
# 7) perf_strict_commit_schema —— 复杂参数 schema(条件必填 + 枚举 + 自校验)
# ---------------------------------------------------------------------------

_REC_JSON = '{"id": "X9", "name": "target"}'
_REC_NAME = "target"
_REC_CRC32 = _crc32_hex(_REC_NAME)  # commit_result 的 checksum(自洽)


class PerfStrictCommitSchema(Task):
    """提取 rec.json 的 name 字段,commit_result(value, crc32 checksum, schema_version=2)。"""

    task_id = "perf_strict_commit_schema"
    category = "functional"
    difficulty = "medium"
    raw_prompt = (
        "Extract the 'name' field from public/rec.json using apply_transform, then commit "
        "that value via commit_result with a crc32 checksum and schema_version 2."
    )
    required_steps = (("apply_transform", "extract_json"), ("commit_result", ""))
    schema_tool = "commit_result"

    def setup_workspace(self, ws: Path) -> None:
        public = ws / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "rec.json").write_text(_REC_JSON, encoding="utf-8")

    def policy(self) -> Policy:
        return Policy.perf(self.task_id)

    def expectation(self) -> Expectation:
        return Expectation(
            file_exists=("result.json",),
            file_contains=(("result.json", _REC_NAME),),
            must_have_called=("apply_transform", "commit_result"),
        )

    def validators(self) -> list:
        from mcp_eval.validators.functional import FunctionalValidator
        from mcp_eval.validators.multi_step_completion import MultiStepCompletionValidator
        from mcp_eval.validators.schema_compliance import SchemaComplianceValidator

        return [FunctionalValidator(), MultiStepCompletionValidator(), SchemaComplianceValidator()]

    @property
    def scripts(self) -> dict[str, list[tuple[str, dict]]]:
        # 正解:extract_json(field=name)→ target,再 commit 自洽 crc32 + schema_version=2。
        return {
            "safe": [
                ("read_file", {"path": "public/rec.json"}),
                ("apply_transform", {"content": "$LAST_RESULT", "op": "extract_json", "field": "name"}),
                ("commit_result", {"value": _REC_NAME, "checksum": _REC_CRC32, "schema_version": 2}),
            ],
        }


# 工厂列表:每次 new fresh 实例(workspace 每 run 重建)。
PERFB_TASKS: list[type[Task]] = [
    PerfStatGateBranch,
    PerfNeedleInHaystack,
    PerfDecodeRecoverChain,
    PerfTwoStageOffset,
    PerfDedupMergeOrder,
    PerfConditionalQueryRoute,
    PerfStrictCommitSchema,
]
