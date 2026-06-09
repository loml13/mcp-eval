"""任务注册表:C1(21)+ C2(33)= 54 个任务工厂。

每个元素都是 zero-arg callable(Task 子类或 lambda 工厂),BenchmarkRunner 每 rep 调一次拿
fresh 实例(fresh canary + 干净 workspace)。
"""
from __future__ import annotations

from typing import Callable

from mcp_eval.tasks.attacks_inj import INJ_TASKS
from mcp_eval.tasks.attacks_other import OTHER_TASKS
from mcp_eval.tasks.base import Task
from mcp_eval.tasks.dangerous import DngCleanupTask, DngDestructiveInjectionTask
from mcp_eval.tasks.description import DESCRIPTION_TASK_FACTORIES
from mcp_eval.tasks.forbidden import FbReadPrivateTask, FbTraversalTask, FbWrongDirTask
from mcp_eval.tasks.functional import FUNCTIONAL_TASKS
from mcp_eval.tasks.injection import InjectionDemoTask, InjFakeSystemTask, InjViaFilenameTask
from mcp_eval.tasks.perf_perfa import PERFA_TASKS
from mcp_eval.tasks.perf_perfb import PERFB_TASKS

# C1 security(8):3 injection + 3 forbidden + 2 dangerous
_C1_SECURITY: list[Callable[[], Task]] = [
    InjectionDemoTask, InjViaFilenameTask, InjFakeSystemTask,
    FbReadPrivateTask, FbTraversalTask, FbWrongDirTask,
    DngCleanupTask, DngDestructiveInjectionTask,
]
# C2 攻击(18):inj 12 + fb/dng 6
C2_ATTACK_FACTORIES: list[Callable[[], Task]] = [*INJ_TASKS, *OTHER_TASKS]
# C2 性能(15):hard/medium 多跳/错误恢复/复杂schema/工具选择/长结果
C2_PERF_FACTORIES: list[Callable[[], Task]] = [*PERFA_TASKS, *PERFB_TASKS]

# 安全轴(26):C1 security 8 + C2 攻击 18
SECURITY_FACTORIES: list[Callable[[], Task]] = [*_C1_SECURITY, *C2_ATTACK_FACTORIES]

# 全量(54):functional 7 + description 6 + C1 security 8 + C2 攻击 18 + C2 性能 15
ALL_TASK_FACTORIES: list[Callable[[], Task]] = [
    *FUNCTIONAL_TASKS,
    *DESCRIPTION_TASK_FACTORIES,
    *_C1_SECURITY,
    *C2_ATTACK_FACTORIES,
    *C2_PERF_FACTORIES,
]
