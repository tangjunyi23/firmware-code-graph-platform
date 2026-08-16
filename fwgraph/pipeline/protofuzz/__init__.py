"""工控/物联网协议模糊测试（M-ICS-1）。

黑盒网络协议 fuzz：协议模板变异 → 发送 → 监视器判定 → 故障复播定位。
测试对象为存活设备（真机/仿真环境），与固件静态分析互补。
"""

from . import engine, monitors, protocols
from .runner import (build_report, get_run, list_runs, run_dir, start_run,
                     stop_run)

__all__ = [
    "engine", "monitors", "protocols",
    "start_run", "get_run", "list_runs", "stop_run", "run_dir",
    "build_report",
]
