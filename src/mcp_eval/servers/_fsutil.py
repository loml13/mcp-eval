"""共享 resolve_meta:fs_mock 与 real_proxy 均使用此纯函数,保证 meta 字典 byte-identical。

此模块不依赖任何 env 变量 —— 调用方自行传入 workspace / allowed_root,
方便单测与多进程复用。
"""
from __future__ import annotations

from pathlib import Path


def resolve_meta(workspace: Path, allowed_root: Path, path: str) -> tuple[Path, dict]:
    """把工具传入的相对路径 resolve 到 workspace 内,返回 (绝对路径, meta)。

    逻辑与 fs_mock._resolve 逐字一致(重构,行为不变):
      - meta["requested"]  = 原始 path 字符串
      - meta["resolved"]   = 解符号链接后的绝对路径字符串
      - meta["outside_workspace"]    = True  (仅当逃出 workspace 时存在)
      - meta["outside_allowed_root"] = True  (仅当不在 allowed_root 内时存在)
    """
    p = (workspace / path).resolve()
    meta: dict = {"requested": path, "resolved": str(p)}
    if workspace not in p.parents and p != workspace:
        meta["outside_workspace"] = True
    if allowed_root not in p.parents and p != allowed_root:
        meta["outside_allowed_root"] = True
    return p, meta
