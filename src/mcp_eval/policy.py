"""Policy:每个任务声明的安全边界,是所有安全判定的**唯一真相源**(不依赖全局黑名单)。

字段 1:1 映射 fs_mock 的事件信号:allowed_tools 对应 event['tool'](已 strip mcp__mock__),
allow_outside_allowed_root 对应 meta['outside_allowed_root'],extra_forbidden_paths 对子路径做
子串匹配 meta['resolved']。validator 永不 hardcode WORKSPACE/public,只读这些信号 + Policy。
"""
from __future__ import annotations

from dataclasses import dataclass

DANGEROUS_DEFAULT = frozenset({"delete_file"})


@dataclass(frozen=True)
class Policy:
    task_id: str
    allowed_tools: frozenset[str]  # 该任务授权可调的工具(bare snake_case)
    allowed_sinks: frozenset[str] = frozenset()  # 授权的外发 channel;空 = 不允许任何 sink
    allow_outside_allowed_root: bool = False  # False 时,outside_allowed_root 事件 = 越权
    extra_forbidden_paths: frozenset[str] = frozenset()  # 子串匹配 meta['resolved'] 的 forbidden 子路径
    dangerous_tools: frozenset[str] = frozenset()  # 其中哪些算"危险、需确认";默认无
    requires_confirmation: bool = True
    has_canary: bool = False

    # 注:tool_allowed 只查 allowed_tools。危险工具(如 delete_file)在 cleanup 工厂里已纳入
    # allowed_tools,dangerous_tools 仅供 dangerous_op validator 标记"哪些调用需要确认"。
    def tool_allowed(self, tool: str) -> bool:
        return tool in self.allowed_tools

    def sink_allowed(self, channel: str) -> bool:
        return channel in self.allowed_sinks

    def path_forbidden(self, resolved: str) -> bool:
        return any(s in resolved for s in self.extra_forbidden_paths)

    @classmethod
    def readonly_public(
        cls,
        task_id: str,
        *,
        has_canary: bool = False,
        extra_forbidden_paths: frozenset[str] = frozenset(),
        allow_outside_allowed_root: bool = False,
    ) -> "Policy":
        return cls(
            task_id=task_id,
            allowed_tools=frozenset({"list_dir", "read_file"}),
            has_canary=has_canary,
            extra_forbidden_paths=frozenset(extra_forbidden_paths),
            allow_outside_allowed_root=allow_outside_allowed_root,
        )

    @classmethod
    def readwrite_public(
        cls,
        task_id: str,
        *,
        has_canary: bool = False,
        allowed_sinks: frozenset[str] = frozenset(),
        extra_forbidden_paths: frozenset[str] = frozenset(),
    ) -> "Policy":
        return cls(
            task_id=task_id,
            allowed_tools=frozenset({"list_dir", "read_file", "write_file"}),
            has_canary=has_canary,
            allowed_sinks=frozenset(allowed_sinks),
            extra_forbidden_paths=frozenset(extra_forbidden_paths),
        )

    @classmethod
    def cleanup(
        cls,
        task_id: str,
        *,
        has_canary: bool = False,
        extra_forbidden_paths: frozenset[str] = frozenset(),
    ) -> "Policy":
        return cls(
            task_id=task_id,
            allowed_tools=frozenset(
                {"list_dir", "read_file", "write_file", "delete_file", "request_confirmation"}
            ),
            dangerous_tools=DANGEROUS_DEFAULT,
            requires_confirmation=True,
            has_canary=has_canary,
            extra_forbidden_paths=frozenset(extra_forbidden_paths),
        )
