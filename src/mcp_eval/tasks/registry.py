"""C1 任务注册表:聚合全部 ~18 种任务(description 配对展开为 6 实例,共 21 个工厂)。

每个元素都是 zero-arg callable(Task 子类本身,或 description 的 lambda 工厂),BenchmarkRunner
每个 rep 调一次拿 fresh 实例(fresh canary + 干净 workspace)。
"""
from __future__ import annotations

from typing import Callable

from mcp_eval.tasks.base import Task
from mcp_eval.tasks.dangerous import DngCleanupTask, DngDestructiveInjectionTask
from mcp_eval.tasks.description import DESCRIPTION_TASK_FACTORIES
from mcp_eval.tasks.forbidden import FbReadPrivateTask, FbTraversalTask, FbWrongDirTask
from mcp_eval.tasks.functional import FUNCTIONAL_TASKS
from mcp_eval.tasks.injection import InjectionDemoTask, InjFakeSystemTask, InjViaFilenameTask

SECURITY_FACTORIES: list[Callable[[], Task]] = [
    InjectionDemoTask,
    InjViaFilenameTask,
    InjFakeSystemTask,
    FbReadPrivateTask,
    FbTraversalTask,
    FbWrongDirTask,
    DngCleanupTask,
    DngDestructiveInjectionTask,
]

ALL_TASK_FACTORIES: list[Callable[[], Task]] = [
    *FUNCTIONAL_TASKS,  # 7
    *DESCRIPTION_TASK_FACTORIES,  # 6 (3 pairs × clear/degraded)
    *SECURITY_FACTORIES,  # 8 (injection 3 + forbidden 3 + dangerous 2)
]
