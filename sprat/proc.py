"""Cancellable subprocess execution.

Stages call `run_cmd` instead of subprocess.run so a running test can be stopped: the whole
process tree is killed (npx -> node, schemathesis workers, docker client).
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class Cancelled(Exception):
    """Raised inside a stage when the user stopped the run."""


def check(cfg) -> None:
    ev = getattr(cfg, "cancel", None)
    if ev is not None and ev.is_set():
        raise Cancelled()


def progress(cfg, stage: str, msg: str, op: str = "", done: int | None = None, total: int | None = None,
             level: str = "info") -> None:
    """Report live activity (shown in the web UI while a run is going). No-op without a listener."""
    cb = getattr(cfg, "on_progress", None)
    if cb is not None:
        cb({"stage": stage, "msg": msg, "op": op, "done": done, "total": total, "level": level})


class Tail:
    """Read lines appended to a file by another process, without touching that process's handle."""

    def __init__(self, path: Path):
        self.path, self.pos, self.buf = Path(path), 0, b""

    def lines(self, final: bool = False) -> list[str]:
        """`final`: the writer has exited, so a last line without a newline is complete too."""
        try:
            with open(self.path, "rb") as f:
                f.seek(self.pos)
                data = f.read()
                self.pos = f.tell()
        except OSError:
            data = b""
        self.buf += data
        *complete, self.buf = self.buf.split(b"\n")
        if final and self.buf:
            complete.append(self.buf)
            self.buf = b""
        return [c.decode("utf-8", "replace").rstrip("\r") for c in complete]


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str


def _kill_tree(p: subprocess.Popen) -> None:
    if p.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()


def run_cmd(cmd: list[str], *, cancel: threading.Event | None = None, timeout: float = 3600,
            env: dict | None = None, on_cancel: Callable[[], None] | None = None,
            on_tick: Callable[[list[str]], None] | None = None) -> Result:
    """Run a command; `on_tick(new_stdout_lines)` is called about 4x a second while it runs."""
    # Output goes to files, not pipes, so a chatty process can't block on a full pipe. Separate
    # read handles (Tail) are used for live output: an inherited handle shares its file position
    # with the child, so seeking it would corrupt the child's writes.
    tmp = Path(tempfile.mkdtemp(prefix="sprat-"))
    out_path, err_path = tmp / "stdout", tmp / "stderr"
    try:
        with open(out_path, "wb") as out, open(err_path, "wb") as err:
            kw = {"start_new_session": True} if sys.platform != "win32" else {}
            p = subprocess.Popen(cmd, stdout=out, stderr=err, stdin=subprocess.DEVNULL, env=env, **kw)
            tail, tail_err = Tail(out_path), Tail(err_path)  # some tools (ZAP) log progress to stderr
            deadline = time.time() + timeout
            while p.poll() is None:
                if cancel is not None and cancel.is_set():
                    _kill_tree(p)
                    if on_cancel:
                        on_cancel()
                    raise Cancelled()
                if time.time() > deadline:
                    _kill_tree(p)
                    raise subprocess.TimeoutExpired(cmd, timeout)
                if on_tick:
                    on_tick(tail.lines() + tail_err.lines())
                time.sleep(0.25)
            if on_tick:
                on_tick(tail.lines(final=True) + tail_err.lines(final=True))
        return Result(p.returncode, out_path.read_bytes().decode("utf-8", "replace"),
                      err_path.read_bytes().decode("utf-8", "replace"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
