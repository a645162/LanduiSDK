"""GUI 公共小工具：线程池任务 + 错误提示。"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal
from PySide6.QtWidgets import QMessageBox, QWidget


class _Signals(QObject):
    done = Signal(object)
    error = Signal(str)


class Task(QRunnable):
    """把阻塞的 requests 调用丢到线程池。"""

    def __init__(self, fn: Callable[[], Any]):
        super().__init__()
        self.fn = fn
        self.signals = _Signals()

    def run(self) -> None:
        try:
            result = self.fn()
        except Exception as exc:  # noqa: BLE001 - 把异常带回 UI 线程
            try:
                self.signals.error.emit(f"{type(exc).__name__}: {exc}")
            except RuntimeError:  # 窗口已关闭，信号源没了
                pass
            return
        try:
            self.signals.done.emit(result)
        except RuntimeError:
            pass


def run_async(parent: QObject, fn: Callable[[], Any], ok: Callable, err: Callable) -> None:
    """在线程池跑 fn，结果回主线程；任务对象挂在 parent 上防止被 GC。"""
    task = Task(fn)
    task.signals.done.connect(ok)
    task.signals.error.connect(err)

    keep: list[Task] = getattr(parent, "_bg_tasks", None)
    if keep is None:
        keep = []
        parent._bg_tasks = keep  # type: ignore[attr-defined]
    keep.append(task)

    def _cleanup(*_: Any) -> None:
        try:
            keep.remove(task)
        except ValueError:
            pass

    task.signals.done.connect(_cleanup)
    task.signals.error.connect(_cleanup)
    QThreadPool.globalInstance().start(task)


def err_box(parent: QWidget, exc: str) -> None:
    QMessageBox.critical(parent, "出错了", exc)


def is_auth_error(text: str) -> bool:
    return "登录" in text or "NotLoggedIn" in text
